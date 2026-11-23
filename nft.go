package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// ruleTag identifies a rule wlt owns. The mark is part of the tag so that a
// changed mark in the config replaces the old rule instead of being ignored.
const ruleTagPrefix = "wlt:v2:"

// NFTManager owns the wlt netdev table: its per-interface ingress chains, one
// MAC set per policy, and one marking rule per (policy, chain).
//
// Sync makes the kernel match the desired state (config + device state) and is
// safe to call at any time; it only sends a batch when something differs, and
// that batch is applied atomically by the kernel. It is what recovers the table
// after `nft flush ruleset` followed by re-applying /etc/nftables.conf.
type NFTManager struct {
	mu      sync.Mutex
	cfg     *Config
	desired func() map[string][]net.HardwareAddr // policy name -> MACs
	logf    func(string, ...any)

	// newConn and ifaceExists are swappable for tests.
	newConn     func() (nftConn, error)
	ifaceExists func(name string) bool
}

// nftConn is the subset of *nftables.Conn the manager uses.
type nftConn interface {
	ListTablesOfFamily(nftables.TableFamily) ([]*nftables.Table, error)
	ListChainsOfTableFamily(nftables.TableFamily) ([]*nftables.Chain, error)
	GetSets(*nftables.Table) ([]*nftables.Set, error)
	GetSetElements(*nftables.Set) ([]nftables.SetElement, error)
	GetRules(*nftables.Table, *nftables.Chain) ([]*nftables.Rule, error)
	AddTable(*nftables.Table) *nftables.Table
	DelTable(*nftables.Table)
	AddChain(*nftables.Chain) *nftables.Chain
	AddSet(*nftables.Set, []nftables.SetElement) error
	DelSet(*nftables.Set)
	SetAddElements(*nftables.Set, []nftables.SetElement) error
	SetDeleteElements(*nftables.Set, []nftables.SetElement) error
	AddRule(*nftables.Rule) *nftables.Rule
	DelRule(*nftables.Rule) error
	Flush() error
}

func NewNFTManager(cfg *Config, desired func() map[string][]net.HardwareAddr) *NFTManager {
	return &NFTManager{
		cfg:     cfg,
		desired: desired,
		logf:    log.Printf,
		newConn: func() (nftConn, error) { return nftables.New() },
		ifaceExists: func(name string) bool {
			_, err := net.InterfaceByName(name)
			return err == nil
		},
	}
}

// DesiredFromState maps every device in state to its policy's MAC set.
// Devices whose policy no longer exists in the config fall back to the
// default policy, so they keep being marked.
func DesiredFromState(cfg *Config, state *State) func() map[string][]net.HardwareAddr {
	return func() map[string][]net.HardwareAddr {
		out := make(map[string][]net.HardwareAddr, len(cfg.Policies))
		for _, dev := range state.All() {
			mac, err := net.ParseMAC(dev.MAC)
			if err != nil || len(mac) != 6 {
				continue
			}
			policy := dev.Policy
			if cfg.PolicyByName(policy) == nil {
				policy = cfg.DefaultPolicy
			}
			out[policy] = append(out[policy], mac)
		}
		return out
	}
}

func setName(policy string) string { return "wlt_" + policy + "_mac" }

func (m *NFTManager) chainName(iface string) string { return m.cfg.ChainName + "_" + iface }

func ruleTag(p Policy) string { return fmt.Sprintf("%s%s:%d", ruleTagPrefix, p.Name, p.Mark) }

func isOwnedSetName(name string) bool {
	return strings.HasPrefix(name, "wlt_") && strings.HasSuffix(name, "_mac")
}

func markBytes(mark uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, mark)
	return b
}

func markRuleExprs(set *nftables.Set, mark uint32) []expr.Any {
	return []expr.Any{
		// ether saddr
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseLLHeader, Offset: 6, Len: 6},
		&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID},
		&expr.Immediate{Register: 1, Data: markBytes(mark)},
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true},
	}
}

// SyncResult reports what Sync changed.
type SyncResult struct {
	Changes       []string
	MissingIfaces []string
}

// Sync reconciles the kernel ruleset with the desired state in one atomic batch.
func (m *NFTManager) Sync() (SyncResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.syncLocked()
}

func (m *NFTManager) syncLocked() (SyncResult, error) {
	var res SyncResult
	conn, err := m.newConn()
	if err != nil {
		return res, fmt.Errorf("connect nftables: %w", err)
	}

	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyNetdev)
	if err != nil {
		return res, fmt.Errorf("list tables: %w", err)
	}
	table := &nftables.Table{Name: m.cfg.TableName, Family: nftables.TableFamilyNetdev}
	tableExists := false
	for _, t := range tables {
		if t.Name == m.cfg.TableName {
			tableExists = true
			break
		}
	}
	if !tableExists {
		if !m.cfg.CreateTable {
			return res, fmt.Errorf("table netdev %q not found and create_table is false", m.cfg.TableName)
		}
		conn.AddTable(table)
		res.Changes = append(res.Changes, "add table "+table.Name)
	}

	// Existing objects (only when the table already exists).
	existingChains := map[string]*nftables.Chain{}
	existingSets := map[string]*nftables.Set{}
	if tableExists {
		chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyNetdev)
		if err != nil {
			return res, fmt.Errorf("list chains: %w", err)
		}
		for _, c := range chains {
			if c.Table != nil && c.Table.Name == m.cfg.TableName {
				existingChains[c.Name] = c
			}
		}
		sets, err := conn.GetSets(table)
		if err != nil {
			return res, fmt.Errorf("list sets: %w", err)
		}
		for _, s := range sets {
			existingSets[s.Name] = s
		}
	}

	// Chains: one ingress chain per LAN interface that currently exists.
	// A netdev chain cannot be created for a missing device, and one missing
	// interface must not block the others; the reconciler retries when the
	// link appears.
	type chainInfo struct {
		chain *nftables.Chain
		isNew bool
	}
	var chains []chainInfo
	for _, iface := range m.cfg.LanInterfaces {
		name := m.chainName(iface)
		if c, ok := existingChains[name]; ok {
			chains = append(chains, chainInfo{chain: c})
			continue
		}
		if !m.ifaceExists(iface) {
			res.MissingIfaces = append(res.MissingIfaces, iface)
			continue
		}
		prio := nftables.ChainPriority(m.cfg.ChainPriority)
		policy := nftables.ChainPolicyAccept
		c := conn.AddChain(&nftables.Chain{
			Name:     name,
			Table:    table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookIngress,
			Priority: &prio,
			Policy:   &policy,
			Device:   iface,
		})
		chains = append(chains, chainInfo{chain: c, isNew: true})
		res.Changes = append(res.Changes, "add chain "+name)
	}

	// Sets and their elements.
	desired := m.desired()
	policySets := map[string]*nftables.Set{}
	for _, p := range m.cfg.Policies {
		name := setName(p.Name)
		want := uniqueMACs(desired[p.Name])
		if s, ok := existingSets[name]; ok {
			s.Table = table
			policySets[p.Name] = s
			have, err := conn.GetSetElements(s)
			if err != nil {
				return res, fmt.Errorf("list elements of %s: %w", name, err)
			}
			add, del := diffElements(want, have)
			if len(del) > 0 {
				if err := conn.SetDeleteElements(s, del); err != nil {
					return res, fmt.Errorf("delete elements from %s: %w", name, err)
				}
				res.Changes = append(res.Changes, fmt.Sprintf("remove %d element(s) from %s", len(del), name))
			}
			if len(add) > 0 {
				if err := conn.SetAddElements(s, add); err != nil {
					return res, fmt.Errorf("add elements to %s: %w", name, err)
				}
				res.Changes = append(res.Changes, fmt.Sprintf("add %d element(s) to %s", len(add), name))
			}
			continue
		}
		s := &nftables.Set{Table: table, Name: name, KeyType: nftables.TypeEtherAddr}
		if err := conn.AddSet(s, toElements(want)); err != nil {
			return res, fmt.Errorf("add set %s: %w", name, err)
		}
		policySets[p.Name] = s
		res.Changes = append(res.Changes, fmt.Sprintf("add set %s with %d element(s)", name, len(want)))
	}

	// Rules: exactly one tagged rule per policy in every chain.
	wantTags := map[string]Policy{}
	for _, p := range m.cfg.Policies {
		wantTags[ruleTag(p)] = p
	}
	for _, ci := range chains {
		present := map[string]bool{}
		if !ci.isNew {
			rules, err := conn.GetRules(table, ci.chain)
			if err != nil {
				return res, fmt.Errorf("list rules of %s: %w", ci.chain.Name, err)
			}
			for _, r := range rules {
				tag := string(r.UserData)
				if _, ok := wantTags[tag]; ok && !present[tag] {
					present[tag] = true
					continue
				}
				// Stale (old tag format, changed mark, removed policy),
				// duplicate, or foreign rule in a chain wlt owns.
				r.Table = table
				r.Chain = ci.chain
				if err := conn.DelRule(r); err != nil {
					return res, fmt.Errorf("delete stale rule in %s: %w", ci.chain.Name, err)
				}
				res.Changes = append(res.Changes, fmt.Sprintf("delete stale rule %q in %s", tag, ci.chain.Name))
			}
		}
		for _, p := range m.cfg.Policies {
			tag := ruleTag(p)
			if present[tag] {
				continue
			}
			conn.AddRule(&nftables.Rule{
				Table:    table,
				Chain:    ci.chain,
				UserData: []byte(tag),
				Exprs:    markRuleExprs(policySets[p.Name], p.Mark),
			})
			res.Changes = append(res.Changes, fmt.Sprintf("add rule %s in %s", p.Name, ci.chain.Name))
		}
	}

	// Sets of policies removed from the config (their rules are gone now).
	for name, s := range existingSets {
		if !isOwnedSetName(name) {
			continue
		}
		known := false
		for _, p := range m.cfg.Policies {
			if setName(p.Name) == name {
				known = true
				break
			}
		}
		if !known {
			s.Table = table
			conn.DelSet(s)
			res.Changes = append(res.Changes, "delete set "+name)
		}
	}

	if len(res.Changes) == 0 {
		return res, nil
	}
	if err := conn.Flush(); err != nil {
		return res, fmt.Errorf("apply nftables batch (%s): %w", strings.Join(res.Changes, "; "), err)
	}
	return res, nil
}

// SetDevicePolicy moves a MAC into newPolicy's set and out of every other
// policy set, in one batch. It does not fail when the MAC is absent from the
// old set (which is the normal case after the table was rebuilt).
func (m *NFTManager) SetDevicePolicy(mac net.HardwareAddr, oldPolicyName, newPolicyName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cfg.PolicyByName(newPolicyName) == nil {
		return fmt.Errorf("policy %q not found", newPolicyName)
	}
	conn, err := m.newConn()
	if err != nil {
		return fmt.Errorf("connect nftables: %w", err)
	}
	table := &nftables.Table{Name: m.cfg.TableName, Family: nftables.TableFamilyNetdev}
	sets, err := conn.GetSets(table)
	if err != nil {
		// Table is gone (e.g. ruleset flushed); rebuild everything.
		_, serr := m.syncLocked()
		return serr
	}
	byName := map[string]*nftables.Set{}
	for _, s := range sets {
		s.Table = table
		byName[s.Name] = s
	}
	if byName[setName(newPolicyName)] == nil {
		_, serr := m.syncLocked()
		return serr
	}

	elem := []nftables.SetElement{{Key: []byte(mac)}}
	changed := false
	for _, p := range m.cfg.Policies {
		s := byName[setName(p.Name)]
		if s == nil {
			continue
		}
		have, err := conn.GetSetElements(s)
		if err != nil {
			return fmt.Errorf("list elements of %s: %w", s.Name, err)
		}
		in := containsMAC(have, mac)
		switch {
		case p.Name == newPolicyName && !in:
			if err := conn.SetAddElements(s, elem); err != nil {
				return err
			}
			changed = true
		case p.Name != newPolicyName && in:
			if err := conn.SetDeleteElements(s, elem); err != nil {
				return err
			}
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("apply policy change: %w", err)
	}
	return nil
}

// Cleanup removes what wlt installed: the whole table when wlt created it,
// otherwise just the set elements (so traffic is no longer marked).
func (m *NFTManager) Cleanup() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	conn, err := m.newConn()
	if err != nil {
		return err
	}
	table := &nftables.Table{Name: m.cfg.TableName, Family: nftables.TableFamilyNetdev}
	if m.cfg.CreateTable {
		tables, err := conn.ListTablesOfFamily(nftables.TableFamilyNetdev)
		if err != nil {
			return err
		}
		for _, t := range tables {
			if t.Name == table.Name {
				conn.DelTable(table)
				return conn.Flush()
			}
		}
		return nil
	}
	sets, err := conn.GetSets(table)
	if err != nil {
		return err
	}
	for _, s := range sets {
		if !isOwnedSetName(s.Name) {
			continue
		}
		s.Table = table
		elems, err := conn.GetSetElements(s)
		if err == nil && len(elems) > 0 {
			if err := conn.SetDeleteElements(s, elems); err != nil {
				return err
			}
		}
	}
	return conn.Flush()
}

func uniqueMACs(in []net.HardwareAddr) []net.HardwareAddr {
	seen := map[string]bool{}
	out := make([]net.HardwareAddr, 0, len(in))
	for _, mac := range in {
		k := string(mac)
		if len(mac) != 6 || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, mac)
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i], out[j]) < 0 })
	return out
}

func toElements(macs []net.HardwareAddr) []nftables.SetElement {
	out := make([]nftables.SetElement, 0, len(macs))
	for _, mac := range macs {
		out = append(out, nftables.SetElement{Key: []byte(mac)})
	}
	return out
}

func containsMAC(elems []nftables.SetElement, mac net.HardwareAddr) bool {
	for _, e := range elems {
		if bytes.Equal(e.Key, mac) {
			return true
		}
	}
	return false
}

// diffElements returns the elements to add and to delete so that `have`
// becomes `want`.
func diffElements(want []net.HardwareAddr, have []nftables.SetElement) (add, del []nftables.SetElement) {
	wantSet := map[string]bool{}
	for _, mac := range want {
		wantSet[string(mac)] = true
	}
	haveSet := map[string]bool{}
	for _, e := range have {
		k := string(e.Key)
		haveSet[k] = true
		if !wantSet[k] {
			del = append(del, nftables.SetElement{Key: append([]byte(nil), e.Key...)})
		}
	}
	for _, mac := range want {
		if !haveSet[string(mac)] {
			add = append(add, nftables.SetElement{Key: []byte(mac)})
		}
	}
	return add, del
}
