package main

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
)

// Reconciler keeps the wlt table in the kernel in line with the desired state.
//
// It triggers NFTManager.Sync on:
//   - nftables netlink notifications touching the wlt table, a table delete,
//     or set elements (e.g. `nft flush ruleset` + `nft -f nftables.conf`,
//     which arrives as one transaction);
//   - a LAN interface appearing or coming up (netdev chains are bound to a
//     device and disappear with it);
//   - a periodic fallback tick, and after the monitor socket is re-opened
//     (events may have been lost meanwhile).
//
// Triggers are debounced so a burst of events results in one Sync.
type Reconciler struct {
	cfg      *Config
	nft      syncer
	interval time.Duration
	debounce time.Duration
	logf     func(string, ...any)
	trigger  chan string
}

type syncer interface {
	Sync() (SyncResult, error)
}

func NewReconciler(cfg *Config, nft syncer) *Reconciler {
	return &Reconciler{
		cfg:      cfg,
		nft:      nft,
		interval: time.Minute,
		debounce: 300 * time.Millisecond,
		logf:     log.Printf,
		trigger:  make(chan string, 1),
	}
}

// Trigger requests a Sync soon. It never blocks.
func (r *Reconciler) Trigger(reason string) {
	select {
	case r.trigger <- reason:
	default:
	}
}

// Start runs until ctx is cancelled.
func (r *Reconciler) Start(ctx context.Context) error {
	go r.watchNFT(ctx)
	go r.watchLinks(ctx)

	r.runSync("startup")

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			r.runSync("periodic")
		case reason := <-r.trigger:
			// Debounce: coalesce everything arriving within the window.
			timer := time.NewTimer(r.debounce)
		drain:
			for {
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-r.trigger:
				case <-timer.C:
					break drain
				}
			}
			r.runSync(reason)
		}
	}
}

func (r *Reconciler) runSync(reason string) {
	res, err := r.nft.Sync()
	if err != nil {
		r.logf("nft sync (%s) failed: %v", reason, err)
		return
	}
	if len(res.Changes) > 0 {
		r.logf("nft sync (%s) repaired ruleset: %s", reason, strings.Join(res.Changes, "; "))
	}
	if len(res.MissingIfaces) > 0 {
		r.logf("nft sync (%s): LAN interface(s) not present, waiting for them: %v", reason, res.MissingIfaces)
	}
}

// relevantNFTEvent reports whether a monitor event may mean the wlt table drifted.
func (r *Reconciler) relevantNFTEvent(ev *nftables.MonitorEvent) bool {
	if ev == nil {
		return false
	}
	switch ev.Type {
	case nftables.MonitorEventTypeOOB:
		return ev.Error != nil
	case nftables.MonitorEventTypeDelTable, nftables.MonitorEventTypeNewTable:
		if t, ok := ev.Data.(*nftables.Table); ok && t != nil {
			return t.Name == r.cfg.TableName
		}
		return true
	case nftables.MonitorEventTypeNewChain, nftables.MonitorEventTypeDelChain:
		if c, ok := ev.Data.(*nftables.Chain); ok && c != nil && c.Table != nil {
			return c.Table.Name == r.cfg.TableName
		}
		return true
	case nftables.MonitorEventTypeNewSet, nftables.MonitorEventTypeDelSet:
		if s, ok := ev.Data.(*nftables.Set); ok && s != nil && s.Table != nil {
			return s.Table.Name == r.cfg.TableName
		}
		return true
	case nftables.MonitorEventTypeNewRule, nftables.MonitorEventTypeDelRule:
		if rl, ok := ev.Data.(*nftables.Rule); ok && rl != nil && rl.Table != nil {
			return rl.Table.Name == r.cfg.TableName
		}
		return true
	case nftables.MonitorEventTypeNewSetElem, nftables.MonitorEventTypeDelSetElem:
		// Element notifications carry no set name; a no-op Sync is cheap.
		return true
	}
	return false
}

func (r *Reconciler) watchNFT(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		conn, err := nftables.New()
		if err != nil {
			r.logf("nft monitor: connect: %v", err)
			sleepCtx(ctx, backoff)
			continue
		}
		mon := nftables.NewMonitor(nftables.WithMonitorEventBuffer(256))
		ch, err := conn.AddGenerationalMonitor(mon)
		if err != nil {
			r.logf("nft monitor: subscribe: %v", err)
			sleepCtx(ctx, backoff)
			continue
		}
		// We may have missed changes while not subscribed.
		r.Trigger("nft monitor (re)subscribed")

		stop := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
			case <-stop:
			}
			mon.Close()
		}()
		for evs := range ch {
			if evs == nil {
				continue
			}
			hit := r.relevantNFTEvent(evs.GeneratedBy) && evs.GeneratedBy.Type == nftables.MonitorEventTypeOOB
			for _, ev := range evs.Changes {
				if r.relevantNFTEvent(ev) {
					hit = true
					break
				}
			}
			if hit {
				r.Trigger("nftables change")
			}
		}
		close(stop)
		if ctx.Err() == nil {
			r.logf("nft monitor: stream closed, re-subscribing")
			sleepCtx(ctx, backoff)
		}
	}
}

func (r *Reconciler) watchLinks(ctx context.Context) {
	want := map[string]bool{}
	for _, iface := range r.cfg.LanInterfaces {
		want[iface] = true
	}
	for ctx.Err() == nil {
		updates := make(chan netlink.LinkUpdate, 64)
		done := make(chan struct{})
		err := netlink.LinkSubscribeWithOptions(updates, done, netlink.LinkSubscribeOptions{
			ErrorCallback: func(err error) {
				if ctx.Err() == nil {
					r.logf("link monitor: %v", err)
				}
			},
		})
		if err != nil {
			r.logf("link monitor: subscribe: %v", err)
			sleepCtx(ctx, 5*time.Second)
			continue
		}
		r.Trigger("link monitor (re)subscribed")
	loop:
		for {
			select {
			case <-ctx.Done():
				close(done)
				return
			case u, ok := <-updates:
				if !ok {
					break loop
				}
				if u.Link != nil && want[u.Link.Attrs().Name] {
					r.Trigger("link change on " + u.Link.Attrs().Name)
				}
			}
		}
		close(done)
		sleepCtx(ctx, time.Second)
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
