package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

type Reconciler struct {
	cfg      *Config
	interval time.Duration
	logFn    func(string, ...any)
	conn     *nftables.Conn
}

func DefaultReconciler(cfg *Config) *Reconciler {
	return &Reconciler{
		cfg:      cfg,
		interval: 30 * time.Second,
		logFn:    log.Printf,
		conn:     nil,
	}
}

func (r *Reconciler) Reconcile(ctx context.Context) error {
	r.logFn("Starting reconciliation cycle")
	defer r.logFn("Completed reconciliation cycle")

	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("connect nftables: %w", err)
	}
	r.conn = conn

	// List all tables in netdev family
	tables, err := conn.ListTables()
	if err != nil {
		return fmt.Errorf("list tables: %w", err)
	}

	// Ensure wlt table exists
	var wltTable *nftables.Table
	for _, t := range tables {
		if t.Name == r.cfg.TableName && t.Family == nftables.TableFamilyNetdev {
			wltTable = t
			break
		}
	}

	if wltTable == nil {
		if !r.cfg.CreateTable {
			return fmt.Errorf("table %q not found and create_table is false", r.cfg.TableName)
		}
		r.logFn("Creating table %q", r.cfg.TableName)
		wltTable = conn.AddTable(&nftables.Table{
			Name:   r.cfg.TableName,
			Family: nftables.TableFamilyNetdev,
		})
		conn.Flush()
		r.logFn("Table %q created", r.cfg.TableName)
	}

	// Re-fetch table to ensure we have the reference
	for _, t := range tables {
		if t.Name == r.cfg.TableName && t.Family == nftables.TableFamilyNetdev && t == nil {
			wltTable = t
			break
		}
	}

	// Ensure chains exist for each LAN interface
	chains, err := conn.ListChains()
	if err != nil {
		return fmt.Errorf("list chains: %w", err)
	}

	for _, iface := range r.cfg.LanInterfaces {
		chainName := r.cfg.ChainName + "_" + iface
		var existingChain *nftables.Chain

		// Check if chain exists
		for _, c := range chains {
			if c.Table.Name == r.cfg.TableName && c.Name == chainName {
				existingChain = c
				break
			}
		}

		if existingChain == nil {
			r.logFn("Creating chain %q for interface %q", chainName, iface)
			prio := nftables.ChainPriority(r.cfg.ChainPriority)
			chainType := nftables.ChainTypeFilter
			policy := nftables.ChainPolicyAccept
			ifaceCopy := iface

			conn.AddChain(&nftables.Chain{
				Name:     chainName,
				Table:    wltTable,
				Type:     chainType,
				Hooknum:  nftables.ChainHookIngress,
				Priority: &prio,
				Policy:   &policy,
				Device:   ifaceCopy,
			})
			r.logFn("Chain %q created for interface %q", chainName, iface)
		}
	}
	conn.Flush()

	// Ensure MAC sets exist for each policy
	allSets, err := conn.GetSets(wltTable)
	if err != nil {
		return fmt.Errorf("get sets: %w", err)
	}

	existingSets := make(map[string]bool)
	for _, s := range allSets {
		existingSets[s.Name] = true
	}

	for _, p := range r.cfg.Policies {
		macName := "wlt_" + p.Name + "_mac"
		if !existingSets[macName] {
			r.logFn("Creating set %q for policy %q", macName, p.Name)
			conn.AddSet(&nftables.Set{
				Table:   wltTable,
				Name:    macName,
				KeyType: nftables.TypeEtherAddr,
			}, nil)
			r.logFn("Set %q created for policy %q", macName, p.Name)
			existingSets[macName] = true
		}
	}
	conn.Flush()

	// Re-fetch sets to get kernel-assigned IDs
	allSets, err = conn.GetSets(wltTable)
	if err != nil {
		return fmt.Errorf("get sets after flush: %w", err)
	}

	// Build set mapping
	setMap := make(map[string]*nftables.Set)
	for _, s := range allSets {
		setMap[s.Name] = s
	}

	// Ensure rules exist for each policy+interface combo
	for _, p := range r.cfg.Policies {
		macSet := setMap["wlt_"+p.Name+"_mac"]
		if macSet == nil {
			r.logFn("Warning: MAC set not found for policy %q", p.Name)
			continue
		}

		for _, iface := range r.cfg.LanInterfaces {
			chainName := r.cfg.ChainName + "_" + iface
			var chain *nftables.Chain
			for _, c := range chains {
				if c.Name == chainName && c.Table.Name == r.cfg.TableName {
					chain = c
					break
				}
			}
			if chain == nil {
				r.logFn("Warning: Chain %q not found for interface %q", chainName, iface)
				continue
			}

			// Check if rule already exists by getting rules for this chain
			chainRules, err := r.conn.GetRules(wltTable, chain)
			if err != nil {
				r.logFn("Warning: Could not get rules for chain %q: %v", chainName, err)
				continue
			}

			ruleKey := "wlt:" + p.Name + ":mac:" + chain.Name
			ruleExists := false
			for _, rule := range chainRules {
				if string(rule.UserData) == ruleKey {
					ruleExists = true
					break
				}
			}

			if !ruleExists {
				r.logFn("Adding rule for policy %q on chain %q", p.Name, chain.Name)
				r.conn.AddRule(&nftables.Rule{
					Table:    wltTable,
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
							SetName:        macSet.Name,
							SetID:          macSet.ID,
						},
						// meta mark set <mark>
						&expr.Immediate{Register: 1, Data: markBytes(p.Mark)},
						&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true},
					},
				})
				r.logFn("Rule added for policy %q on chain %q", p.Name, chain.Name)
			}
		}
	}

	conn.Flush()
	r.logFn("Reconciliation completed successfully")
	return nil
}

func (r *Reconciler) Start(ctx context.Context) error {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	r.logFn("Starting reconciler with interval %v", r.interval)

	// Initial reconciliation
	if err := r.Reconcile(ctx); err != nil {
		r.logFn("Initial reconciliation failed: %v", err)
		// Continue to periodic reconciliation
	}

	for {
		select {
		case <-ctx.Done():
			r.logFn("Reconciler stopping: %v", ctx.Err())
			return ctx.Err()
		case <-ticker.C:
			if err := r.Reconcile(ctx); err != nil {
				r.logFn("Reconciliation failed: %v", err)
			}
		}
	}
}
