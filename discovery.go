package main

import (
	"context"
	"log"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Passive device discovery.  It only reads the kernel's ARP/NDP neighbour
// table; it does not send ARP probes, TCP connects, or any port scans.
func localAddresses() (macs, ips map[string]bool) {
	macs = make(map[string]bool)
	ips = make(map[string]bool)
	ifaces, err := net.Interfaces()
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		if mac := iface.HardwareAddr.String(); mac != "" {
			macs[strings.ToLower(mac)] = true
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP != nil {
				ips[ipnet.IP.String()] = true
			}
		}
	}
	return
}

func unionStrings(a, b []string) ([]string, bool) {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	changed := false
	for _, s := range b {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
			changed = true
		}
	}
	sort.Strings(out)
	return out, changed
}

func (s *Server) discoverOnce() {
	localMACs, localIPs := localAddresses()

	found := make(map[string]map[string]bool)
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		neighbors, err := netlink.NeighList(0, family)
		if err != nil {
			continue
		}
		for _, n := range neighbors {
			if n.IP == nil || len(n.HardwareAddr) != 6 || !validNUDStates[n.State] {
				continue
			}
			if n.IP.IsLoopback() || n.IP.IsMulticast() || n.IP.IsLinkLocalUnicast() {
				continue
			}
			mac := strings.ToLower(n.HardwareAddr.String())
			if localMACs[mac] || localIPs[n.IP.String()] {
				continue
			}
			if found[mac] == nil {
				found[mac] = make(map[string]bool)
			}
			found[mac][n.IP.String()] = true
		}
	}

	for mac, ipset := range found {
		var v4s, v6s []string
		for ip := range ipset {
			if strings.Contains(ip, ".") {
				v4s = append(v4s, ip)
			} else {
				v6s = append(v6s, ip)
			}
		}
		sort.Strings(v4s)
		sort.Strings(v6s)

		if existing := s.state.Get(mac); existing != nil {
			merged := *existing
			merged.IPv4s, _ = unionStrings(existing.IPv4s, v4s)
			merged.IPv6s, _ = unionStrings(existing.IPv6s, v6s)
			// Preserve the last-seen time from real traffic; discovery is
			// only here to make new MACs visible to the router sync.
			if len(merged.IPv4s) != len(existing.IPv4s) || len(merged.IPv6s) != len(existing.IPv6s) {
				s.mu.Lock()
				s.state.Set(&merged)
				if err := s.state.Save(s.cfg.StatePath); err != nil {
					log.Printf("discovery: save state: %v", err)
				}
				s.mu.Unlock()
			}
			continue
		}

		hw, err := net.ParseMAC(mac)
		if err != nil {
			continue
		}
		dev := &DeviceState{
			MAC:      mac,
			IPv4s:    v4s,
			IPv6s:    v6s,
			Policy:   s.cfg.DefaultPolicy,
			LastSeen: time.Now(),
		}
		s.mu.Lock()
		if s.state.Get(mac) == nil {
			if err := s.applyPolicy(dev, nil, hw, ""); err != nil {
				log.Printf("discovery: add %s: %v", mac, err)
			} else {
				log.Printf("discovery: added %s (%s) policy=%s", mac, strings.Join(append(v4s, v6s...), ","), s.cfg.DefaultPolicy)
			}
		}
		s.mu.Unlock()
	}
}

// StartDiscovery runs passive discovery until ctx is cancelled.
func (s *Server) StartDiscovery(ctx context.Context) {
	interval := time.Duration(s.cfg.DiscoveryIntervalSeconds) * time.Second
	if interval < 30*time.Second {
		interval = 60 * time.Second
	}
	s.discoverOnce()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.discoverOnce()
		}
	}
}
