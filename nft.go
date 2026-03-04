package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

type policySet struct {
	macSet *nftables.Set
}

type NFTManager struct {
	mu     sync.Mutex
	conn   *nftables.Conn
	cfg    *Config
	table  *nftables.Table
	chains map[string]*nftables.Chain // keyed by interface name
	sets   map[string]*policySet      // keyed by policy name
}

func NewNFTManager(cfg *Config) (*NFTManager, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("connect nftables: %w", err)
	}

	m := &NFTManager{
		conn:   conn,
		cfg:    cfg,
		chains: make(map[string]*nftables.Chain),
		sets:   make(map[string]*policySet),
	}

	if err := m.setup(); err != nil {
		return nil, err
	}

	return m, nil
}

func (m *NFTManager) setup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Look for existing table (netdev family)
	tables, err := m.conn.ListTables()
	if err != nil {
		return fmt.Errorf("list tables: %w", err)
	}

	for _, t := range tables {
		if t.Name == m.cfg.TableName && t.Family == nftables.TableFamilyNetdev {
			m.table = t
			break
		}
	}

	if m.table == nil {
		if !m.cfg.CreateTable {
			return fmt.Errorf("table %q not found and create_table is false", m.cfg.TableName)
		}
		m.table = m.conn.AddTable(&nftables.Table{
			Name:   m.cfg.TableName,
			Family: nftables.TableFamilyNetdev,
		})
	}

	// Look for existing chains (one per interface)
	chains, err := m.conn.ListChains()
	if err != nil {
		return fmt.Errorf("list chains: %w", err)
	}

	for _, iface := range m.cfg.LanInterfaces {
		chainName := m.cfg.ChainName + "_" + iface
		for _, c := range chains {
			if c.Table.Name == m.cfg.TableName && c.Name == chainName {
				m.chains[iface] = c
				break
			}
		}
		if m.chains[iface] == nil {
			prio := nftables.ChainPriority(m.cfg.ChainPriority)
			chainType := nftables.ChainTypeFilter
			policy := nftables.ChainPolicyAccept
			ifaceCopy := iface

			m.chains[iface] = m.conn.AddChain(&nftables.Chain{
				Name:     chainName,
				Table:    m.table,
				Type:     chainType,
				Hooknum:  nftables.ChainHookIngress,
				Priority: &prio,
				Policy:   &policy,
				Device:   ifaceCopy,
			})
		}
	}

	// Create MAC sets for each policy
	for _, p := range m.cfg.Policies {
		ps, err := m.ensurePolicySet(p)
		if err != nil {
			return fmt.Errorf("ensure set for policy %q: %w", p.Name, err)
		}
		m.sets[p.Name] = ps
	}

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("flush setup: %w", err)
	}

	// Re-fetch sets to get kernel-assigned IDs
	allSets, err := m.conn.GetSets(m.table)
	if err != nil {
		return fmt.Errorf("get sets after flush: %w", err)
	}
	for _, p := range m.cfg.Policies {
		macName := "wlt_" + p.Name + "_mac"
		ps := m.sets[p.Name]
		for _, s := range allSets {
			if s.Name == macName {
				ps.macSet = s
				break
			}
		}
	}

	// Add rules (after flush so sets have correct IDs)
	for _, p := range m.cfg.Policies {
		ps := m.sets[p.Name]
		for _, iface := range m.cfg.LanInterfaces {
			chain := m.chains[iface]
			if err := m.ensurePolicyRule(p, ps, chain); err != nil {
				return fmt.Errorf("ensure rule for policy %q on %s: %w", p.Name, iface, err)
			}
		}
	}

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("flush rules: %w", err)
	}

	return nil
}

func (m *NFTManager) ensurePolicySet(p Policy) (*policySet, error) {
	macName := "wlt_" + p.Name + "_mac"

	sets, err := m.conn.GetSets(m.table)
	if err != nil {
		sets = nil
	}

	ps := &policySet{}
	for _, s := range sets {
		if s.Name == macName {
			ps.macSet = s
			break
		}
	}

	if ps.macSet == nil {
		ps.macSet = &nftables.Set{
			Table:   m.table,
			Name:    macName,
			KeyType: nftables.TypeEtherAddr,
		}
		if err := m.conn.AddSet(ps.macSet, nil); err != nil {
			return nil, fmt.Errorf("add mac set: %w", err)
		}
	}

	return ps, nil
}

func markBytes(mark uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, mark)
	return b
}

func (m *NFTManager) ensurePolicyRule(p Policy, ps *policySet, chain *nftables.Chain) error {
	rules, err := m.conn.GetRules(m.table, chain)
	if err != nil {
		return fmt.Errorf("get rules: %w", err)
	}

	ruleKey := "wlt:" + p.Name + ":mac:" + chain.Name
	for _, r := range rules {
		if string(r.UserData) == ruleKey {
			return nil
		}
	}

	m.conn.AddRule(&nftables.Rule{
		Table:    m.table,
		Chain:    chain,
		UserData: []byte(ruleKey),
		Exprs: []expr.Any{
			// ether saddr (src MAC at byte 6, 6 bytes)
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseLLHeader,
				Offset:       6,
				Len:          6,
			},
			// lookup in MAC set
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        ps.macSet.Name,
				SetID:          ps.macSet.ID,
			},
			// meta mark set <mark>
			&expr.Immediate{Register: 1, Data: markBytes(p.Mark)},
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true},
		},
	})

	return nil
}

// SetDevicePolicy moves a MAC from the old policy set to the new policy set.
func (m *NFTManager) SetDevicePolicy(mac net.HardwareAddr, oldPolicyName, newPolicyName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	elem := nftables.SetElement{Key: []byte(mac)}

	// Remove from old set
	if oldPolicyName != "" && oldPolicyName != newPolicyName {
		if oldPS, ok := m.sets[oldPolicyName]; ok {
			m.conn.SetDeleteElements(oldPS.macSet, []nftables.SetElement{elem})
		}
	}

	// Add to new set
	newPS, ok := m.sets[newPolicyName]
	if !ok {
		return fmt.Errorf("policy %q not found in nft sets", newPolicyName)
	}
	if err := m.conn.SetAddElements(newPS.macSet, []nftables.SetElement{elem}); err != nil {
		return fmt.Errorf("add mac element: %w", err)
	}

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("flush set changes: %w", err)
	}

	return nil
}

// RebuildFromState populates nft MAC sets from persisted state.
func (m *NFTManager) RebuildFromState(state *State) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, dev := range state.All() {
		ps, ok := m.sets[dev.Policy]
		if !ok {
			continue
		}

		mac, err := net.ParseMAC(dev.MAC)
		if err != nil {
			continue
		}

		if err := m.conn.SetAddElements(ps.macSet, []nftables.SetElement{{Key: []byte(mac)}}); err != nil {
			return fmt.Errorf("add mac element for %s: %w", dev.MAC, err)
		}
	}

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("flush rebuild: %w", err)
	}

	return nil
}

// Cleanup flushes all managed MAC set elements.
func (m *NFTManager) Cleanup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, ps := range m.sets {
		elems, err := m.conn.GetSetElements(ps.macSet)
		if err == nil && len(elems) > 0 {
			m.conn.SetDeleteElements(ps.macSet, elems)
		}
	}

	if err := m.conn.Flush(); err != nil {
		return fmt.Errorf("flush cleanup: %w", err)
	}

	return nil
}
