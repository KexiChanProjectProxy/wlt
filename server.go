package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type Server struct {
	cfg     *Config
	state   *State
	nft     *NFTManager
	mu      sync.Mutex // covers detect+nft+state flow
	handler http.Handler
}

func NewServer(cfg *Config, state *State, nft *NFTManager) *Server {
	s := &Server{
		cfg:   cfg,
		state: state,
		nft:   nft,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/device", s.handleDevice)
	mux.HandleFunc("/api/policies", s.handlePolicies)
	mux.HandleFunc("/api/policy", s.handleSetPolicy)
	s.handler = mux
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

type deviceResponse struct {
	SourceIP string   `json:"source_ip"`
	MAC      string   `json:"mac"`
	IPv4s    []string `json:"ipv4s"`
	IPv6s    []string `json:"ipv6s"`
	Policy   string   `json:"policy"`
}

func (s *Server) detectDevice(r *http.Request) (*DeviceState, error) {
	srcIP, err := extractIP(r)
	if err != nil {
		return nil, fmt.Errorf("extract IP: %w", err)
	}

	mac, err := lookupMAC(srcIP)
	if err != nil {
		return nil, fmt.Errorf("lookup MAC for %s: %w", srcIP, err)
	}

	macStr := mac.String()
	ipv4s, ipv6s, err := lookupAllIPs(mac)
	if err != nil {
		// Non-fatal: use just the source IP
		ipv4s = []net.IP{srcIP}
		ipv6s = nil
	}

	toStrings := func(ips []net.IP) []string {
		ss := make([]string, len(ips))
		for i, ip := range ips {
			ss[i] = ip.String()
		}
		return ss
	}

	dev := &DeviceState{
		MAC:      macStr,
		IPv4s:    toStrings(ipv4s),
		IPv6s:    toStrings(ipv6s),
		LastSeen: time.Now(),
	}

	// Look up existing policy or assign default
	if existing := s.state.Get(macStr); existing != nil {
		dev.Policy = existing.Policy
	} else {
		dev.Policy = s.cfg.DefaultPolicy
	}

	return dev, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func devToResponse(dev *DeviceState) deviceResponse {
	return deviceResponse{
		MAC:    dev.MAC,
		IPv4s:  dev.IPv4s,
		IPv6s:  dev.IPv6s,
		Policy: dev.Policy,
	}
}

func (s *Server) handleDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	srcIP, err := extractIP(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	mac, err := lookupMAC(srcIP)
	if err != nil {
		// Return partial info without MAC
		resp := deviceResponse{
			SourceIP: srcIP.String(),
			MAC:      "unknown",
			IPv4s:    []string{srcIP.String()},
			IPv6s:    []string{},
			Policy:   s.cfg.DefaultPolicy,
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	macStr := mac.String()
	ipv4s, ipv6s, _ := lookupAllIPs(mac)

	toStrings := func(ips []net.IP) []string {
		ss := make([]string, len(ips))
		for i, ip := range ips {
			ss[i] = ip.String()
		}
		return ss
	}

	policy := s.cfg.DefaultPolicy
	if existing := s.state.Get(macStr); existing != nil {
		policy = existing.Policy
	} else {
		// Auto-assign default policy
		dev := &DeviceState{
			MAC:      macStr,
			IPv4s:    toStrings(ipv4s),
			IPv6s:    toStrings(ipv6s),
			Policy:   policy,
			LastSeen: time.Now(),
		}
		s.state.Set(dev)
		// Apply nft rules for default policy
		if err := s.nft.SetDevicePolicy(mac, "", policy); err != nil {
			// Log but continue
			fmt.Printf("warn: nft SetDevicePolicy for new device %s: %v\n", macStr, err)
		}
	}

	resp := deviceResponse{
		SourceIP: srcIP.String(),
		MAC:      macStr,
		IPv4s:    toStrings(ipv4s),
		IPv6s:    toStrings(ipv6s),
		Policy:   policy,
	}
	writeJSON(w, http.StatusOK, resp)
}

type policyResponse struct {
	Name        string `json:"name"`
	Mark        uint32 `json:"mark"`
	Description string `json:"description"`
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	resp := make([]policyResponse, len(s.cfg.Policies))
	for i, p := range s.cfg.Policies {
		resp[i] = policyResponse{Name: p.Name, Mark: p.Mark, Description: p.Description}
	}
	writeJSON(w, http.StatusOK, resp)
}

type setPolicyRequest struct {
	Policy         string `json:"policy"`
	FlushConntrack bool   `json:"flush_conntrack"`
}

func flushConntrack(ipv4s []net.IP, ipv6s []net.IP) (uint, error) {
	var total uint
	for _, ip := range ipv4s {
		f := &netlink.ConntrackFilter{}
		if err := f.AddIP(netlink.ConntrackOrigSrcIP, ip); err != nil {
			return total, err
		}
		n, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, unix.AF_INET, f)
		total += n
		if err != nil {
			return total, err
		}
	}
	for _, ip := range ipv6s {
		f := &netlink.ConntrackFilter{}
		if err := f.AddIP(netlink.ConntrackOrigSrcIP, ip); err != nil {
			return total, err
		}
		n, err := netlink.ConntrackDeleteFilters(netlink.ConntrackTable, unix.AF_INET6, f)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (s *Server) handleSetPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req setPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if s.cfg.PolicyByName(req.Policy) == nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown policy: %q", req.Policy))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	srcIP, err := extractIP(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	mac, err := lookupMAC(srcIP)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("lookup MAC: %v", err))
		return
	}

	macStr := mac.String()
	ipv4s, ipv6s, _ := lookupAllIPs(mac)

	toStrings := func(ips []net.IP) []string {
		ss := make([]string, len(ips))
		for i, ip := range ips {
			ss[i] = ip.String()
		}
		return ss
	}

	oldPolicy := ""
	if existing := s.state.Get(macStr); existing != nil {
		oldPolicy = existing.Policy
	}

	// Move MAC between nft sets
	if err := s.nft.SetDevicePolicy(mac, oldPolicy, req.Policy); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("nft error: %v", err))
		return
	}

	if req.FlushConntrack {
		n, err := flushConntrack(ipv4s, ipv6s)
		if err != nil {
			fmt.Printf("warn: flush conntrack for %s: %v\n", macStr, err)
		} else if n > 0 {
			fmt.Printf("info: flushed %d conntrack entries for %s\n", n, macStr)
		}
	}

	dev := &DeviceState{
		MAC:      macStr,
		IPv4s:    toStrings(ipv4s),
		IPv6s:    toStrings(ipv6s),
		Policy:   req.Policy,
		LastSeen: time.Now(),
	}
	s.state.Set(dev)

	if err := s.state.Save(s.cfg.StatePath); err != nil {
		fmt.Printf("warn: save state: %v\n", err)
	}

	resp := deviceResponse{
		SourceIP: srcIP.String(),
		MAC:      macStr,
		IPv4s:    toStrings(ipv4s),
		IPv6s:    toStrings(ipv6s),
		Policy:   req.Policy,
	}
	writeJSON(w, http.StatusOK, resp)
}
