package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

type Reconciler struct {
	cfg        *Config
	interval   time.Duration
	logFn      func(string, ...any)
	conn       *nftables.Conn
	monitorCmd *exec.Cmd
	monitorCh  chan struct{}
	stopCh     chan struct{}
}

func DefaultReconciler(cfg *Config) *Reconciler {
	return &Reconciler{
		cfg:       cfg,
		interval:  5 * time.Minute,
		logFn:     log.Printf,
		conn:      nil,
		monitorCh: make(chan struct{}, 1),
		stopCh:    make(chan struct{}),
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
	tables, err = conn.ListTables()
	if err != nil {
		return fmt.Errorf("refresh tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == r.cfg.TableName && t.Family == nftables.TableFamilyNetdev {
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

	// Refresh chain list to include newly created chains
	chains, err = conn.ListChains()
	if err != nil {
		return fmt.Errorf("refresh chains: %w", err)
	}

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

// parseMonitorEvent parses a line from nft monitor output and detects relevant events
func (r *Reconciler) parseMonitorEvent(line string) bool {
	// Look for table events
	if strings.Contains(line, "add table") && strings.Contains(line, r.cfg.TableName) {
		r.logFn("Detected table addition event for %q", r.cfg.TableName)
		return true
	}
	if strings.Contains(line, "delete table") && strings.Contains(line, r.cfg.TableName) {
		r.logFn("Detected table deletion event for %q", r.cfg.TableName)
		return true
	}

	// Look for chain events
	for _, iface := range r.cfg.LanInterfaces {
		chainName := r.cfg.ChainName + "_" + iface
		if strings.Contains(line, "add chain") && strings.Contains(line, chainName) {
			r.logFn("Detected chain addition event for %q", chainName)
			return true
		}
		if strings.Contains(line, "delete chain") && strings.Contains(line, chainName) {
			r.logFn("Detected chain deletion event for %q", chainName)
			return true
		}
	}

	// Look for set events
	for _, p := range r.cfg.Policies {
		macName := "wlt_" + p.Name + "_mac"
		if strings.Contains(line, "add set") && strings.Contains(line, macName) {
			r.logFn("Detected set addition event for %q", macName)
			return true
		}
		if strings.Contains(line, "delete set") && strings.Contains(line, macName) {
			r.logFn("Detected set deletion event for %q", macName)
			return true
		}
	}

	// Look for rule events
	for _, iface := range r.cfg.LanInterfaces {
		chainName := r.cfg.ChainName + "_" + iface
		if strings.Contains(line, "add rule") && strings.Contains(line, chainName) {
			r.logFn("Detected potential rule addition event for %q", chainName)
			return true
		}
		if strings.Contains(line, "delete rule") && strings.Contains(line, chainName) {
			r.logFn("Detected potential rule deletion event for %q", chainName)
			return true
		}
	}

	return false
}

// startMonitor starts the nft monitor process in a goroutine
func (r *Reconciler) startMonitor(ctx context.Context) {
	cmd := exec.CommandContext(ctx, "nft", "monitor", "json")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		r.logFn("Failed to create stdout pipe for nft monitor: %v", err)
		return
	}

	if err := cmd.Start(); err != nil {
		r.logFn("Failed to start nft monitor: %v", err)
		return
	}

	r.monitorCmd = cmd

	// Parse monitor output in a separate goroutine
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			select {
			case <-r.stopCh:
				return
			default:
				line := scanner.Text()
				if r.parseMonitorEvent(line) {
					// Send signal that reconciliation is needed
					select {
					case r.monitorCh <- struct{}{}:
					default:
						// Channel is already full, skip
					}
				}
			}
		}

		if err := scanner.Err(); err != nil {
			r.logFn("Error reading nft monitor output: %v", err)
		}
	}()

	// Monitor the process in case it dies
	go func() {
		err := cmd.Wait()
		if err != nil && cmd.ProcessState.ExitCode() != 0 {
			r.logFn("nft monitor process exited: %v", err)
			// Restart the monitor if not stopped
			select {
			case <-r.stopCh:
				return
			default:
				r.logFn("Restarting nft monitor...")
				r.startMonitor(ctx)
			}
		}
	}()
}

func (r *Reconciler) Start(ctx context.Context) error {
	// Start the nft monitor
	r.startMonitor(ctx)

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
				r.logFn("Periodic reconciliation failed: %v", err)
			}
		case <-r.monitorCh:
			r.logFn("Triggering reconciliation due to nftables event")
			if err := r.Reconcile(ctx); err != nil {
				r.logFn("Event-triggered reconciliation failed: %v", err)
			}
		}
	}
}

// Stop gracefully shuts down the monitor and periodic reconciliation
func (r *Reconciler) Stop() {
	close(r.stopCh)
	if r.monitorCmd != nil {
		r.monitorCmd.Process.Kill()
	}
}
