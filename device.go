package main

import (
	"fmt"
	"net"
	"net/http"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func extractIP(r *http.Request) (net.IP, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("parse RemoteAddr %q: %w", r.RemoteAddr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", host)
	}
	return ip, nil
}

func lookupMAC(ip net.IP) (net.HardwareAddr, error) {
	families := []int{unix.AF_INET, unix.AF_INET6}

	for _, family := range families {
		neighbors, err := netlink.NeighList(0, family)
		if err != nil {
			continue
		}
		for _, n := range neighbors {
			if n.IP.Equal(ip) && n.HardwareAddr != nil {
				return n.HardwareAddr, nil
			}
		}
	}

	return nil, fmt.Errorf("no neighbor entry found for IP %s", ip)
}

var validNUDStates = map[int]bool{
	netlink.NUD_REACHABLE: true,
	netlink.NUD_STALE:     true,
	netlink.NUD_DELAY:     true,
	netlink.NUD_PERMANENT: true,
}

func lookupAllIPs(mac net.HardwareAddr) (ipv4s []net.IP, ipv6s []net.IP, err error) {
	macStr := mac.String()

	families := []int{unix.AF_INET, unix.AF_INET6}
	for _, family := range families {
		neighbors, err := netlink.NeighList(0, family)
		if err != nil {
			continue
		}
		for _, n := range neighbors {
			if n.HardwareAddr == nil || n.HardwareAddr.String() != macStr {
				continue
			}
			if !validNUDStates[n.State] {
				continue
			}
			if n.IP == nil {
				continue
			}

			ip4 := n.IP.To4()
			if ip4 != nil {
				ipv4s = append(ipv4s, ip4)
			} else {
				// Filter out link-local IPv6 (fe80::/10)
				if !n.IP.IsLinkLocalUnicast() {
					ipv6s = append(ipv6s, n.IP)
				}
			}
		}
	}

	return ipv4s, ipv6s, nil
}
