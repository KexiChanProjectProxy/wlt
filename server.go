package main

import (
	"crypto/subtle"
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
	nft     devicePolicySetter
	mu      sync.Mutex // covers detect+nft+state flow
	handler http.Handler
}

type devicePolicySetter interface {
	SetDevicePolicy(mac net.HardwareAddr, oldPolicyName, newPolicyName string) error
}

var (
	extractIPFunc      = extractIP
	lookupMACFunc      = lookupMAC
	lookupAllIPsFunc   = lookupAllIPs
	flushConntrackFunc = flushConntrack
	parseMACFunc       = net.ParseMAC
)

func NewServer(cfg *Config, state *State, nft devicePolicySetter) *Server {
	s := &Server{
		cfg:   cfg,
		state: state,
		nft:   nft,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/device", s.handleDevice)
	mux.HandleFunc("/api/features", s.handleFeatures)
	mux.HandleFunc("/api/policies", s.handlePolicies)
	mux.HandleFunc("/api/policy", s.handleSetPolicy)
	if cfg.AdminPSK != "" {
		mux.Handle("/api/admin/device", s.adminOnly(http.HandlerFunc(s.handleAdminDevice)))
		mux.Handle("/api/admin/policy", s.adminOnly(http.HandlerFunc(s.handleAdminSetPolicy)))
	}
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

type featuresResponse struct {
	AdminEnabled bool `json:"admin_enabled"`
}

func (s *Server) detectDevice(r *http.Request) (*DeviceState, error) {
	srcIP, err := extractIPFunc(r)
	if err != nil {
		return nil, fmt.Errorf("extract IP: %w", err)
	}

	mac, err := lookupMACFunc(srcIP)
	if err != nil {
		return nil, fmt.Errorf("lookup MAC for %s: %w", srcIP, err)
	}

	macStr := mac.String()
	ipv4s, ipv6s, err := lookupAllIPsFunc(mac)
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

type deviceTarget struct {
	mac      net.HardwareAddr
	sourceIP net.IP
	explicit bool
}

const (
	publicDeviceSelectorError = "ip/mac selectors are only supported on /api/admin/device"
	publicPolicySelectorError = "ip/mac selectors are only supported on /api/admin/policy"
	adminAuthError            = "missing or invalid X-WLT-PSK"
)

func hasSelector(macValue, ipValue string) bool {
	return macValue != "" || ipValue != ""
}

func requireExactSelector(macValue, ipValue string) error {
	if (macValue == "" && ipValue == "") || (macValue != "" && ipValue != "") {
		return fmt.Errorf("exactly one of mac or ip must be specified")
	}
	return nil
}

func requireIPSelector(macValue, ipValue string) error {
	if ipValue == "" {
		if macValue != "" {
			return fmt.Errorf("admin routes only support ip selectors")
		}
		return fmt.Errorf("ip selector is required")
	}
	if macValue != "" {
		return fmt.Errorf("admin routes only support ip selectors")
	}
	return nil
}

func (s *Server) adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-WLT-PSK")), []byte(s.cfg.AdminPSK)) != 1 {
			writeError(w, http.StatusUnauthorized, adminAuthError)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) findStateByIP(ip net.IP) *DeviceState {
	if ip == nil {
		return nil
	}
	ipStr := ip.String()
	for _, dev := range s.state.All() {
		for _, ipv4 := range dev.IPv4s {
			if ipv4 == ipStr {
				return dev
			}
		}
		for _, ipv6 := range dev.IPv6s {
			if ipv6 == ipStr {
				return dev
			}
		}
	}
	return nil
}

func toIPStrings(ips []net.IP) []string {
	ss := make([]string, len(ips))
	for i, ip := range ips {
		ss[i] = ip.String()
	}
	return ss
}

func (s *Server) parseSelector(macValue, ipValue string) (*deviceTarget, error) {
	if macValue != "" && ipValue != "" {
		return nil, fmt.Errorf("at most one of mac or ip may be specified")
	}
	if macValue == "" && ipValue == "" {
		return nil, nil
	}

	if macValue != "" {
		mac, err := parseMACFunc(macValue)
		if err != nil {
			return nil, fmt.Errorf("invalid MAC address")
		}
		return &deviceTarget{mac: mac, explicit: true}, nil
	}

	ip := net.ParseIP(ipValue)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address")
	}
	mac, err := lookupMACFunc(ip)
	if err != nil {
		if existing := s.findStateByIP(ip); existing != nil {
			mac, parseErr := parseMACFunc(existing.MAC)
			if parseErr == nil {
				return &deviceTarget{mac: mac, sourceIP: ip, explicit: true}, nil
			}
		}
		return &deviceTarget{sourceIP: ip, explicit: true}, fmt.Errorf("lookup MAC: %w", err)
	}
	return &deviceTarget{mac: mac, sourceIP: ip, explicit: true}, nil
}

func (s *Server) resolveGetTarget(r *http.Request) (*deviceTarget, error) {
	target, err := s.parseSelector(r.URL.Query().Get("mac"), r.URL.Query().Get("ip"))
	if err != nil || target != nil {
		return target, err
	}

	srcIP, err := extractIPFunc(r)
	if err != nil {
		return nil, err
	}
	mac, err := lookupMACFunc(srcIP)
	if err != nil {
		return &deviceTarget{sourceIP: srcIP}, fmt.Errorf("lookup MAC: %w", err)
	}
	return &deviceTarget{mac: mac, sourceIP: srcIP}, nil
}

func (s *Server) resolvePostTarget(r *http.Request, req setPolicyRequest) (*deviceTarget, error) {
	target, err := s.parseSelector(req.MAC, req.IP)
	if err != nil || target != nil {
		return target, err
	}

	srcIP, err := extractIPFunc(r)
	if err != nil {
		return nil, err
	}
	mac, err := lookupMACFunc(srcIP)
	if err != nil {
		return &deviceTarget{sourceIP: srcIP}, fmt.Errorf("lookup MAC: %w", err)
	}
	return &deviceTarget{mac: mac, sourceIP: srcIP}, nil
}

func postTargetErrorStatus(req setPolicyRequest, target *deviceTarget) int {
	if req.MAC != "" || req.IP != "" {
		if req.IP != "" && target != nil && target.sourceIP != nil && target.mac == nil {
			return http.StatusNotFound
		}
		return http.StatusBadRequest
	}
	if target != nil && target.sourceIP != nil && target.mac == nil {
		return http.StatusInternalServerError
	}
	return http.StatusBadRequest
}

func parseIPStrings(values []string) []net.IP {
	ips := make([]net.IP, 0, len(values))
	for _, value := range values {
		if ip := net.ParseIP(value); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

func (s *Server) buildDeviceState(mac net.HardwareAddr, sourceIP net.IP) *DeviceState {
	macStr := mac.String()
	dev := &DeviceState{
		MAC:      macStr,
		Policy:   s.cfg.DefaultPolicy,
		LastSeen: time.Now(),
	}

	if existing := s.state.Get(macStr); existing != nil {
		dev.IPv4s = append([]string(nil), existing.IPv4s...)
		dev.IPv6s = append([]string(nil), existing.IPv6s...)
		dev.Policy = existing.Policy
		dev.LastSeen = existing.LastSeen
	}

	ipv4s, ipv6s, err := lookupAllIPsFunc(mac)
	if err == nil {
		if len(ipv4s) > 0 {
			dev.IPv4s = toIPStrings(ipv4s)
		}
		if len(ipv6s) > 0 {
			dev.IPv6s = toIPStrings(ipv6s)
		}
	}

	if sourceIP != nil {
		sourceIPStr := sourceIP.String()
		if sourceIP.To4() != nil {
			if len(dev.IPv4s) == 0 {
				dev.IPv4s = []string{sourceIPStr}
			}
		} else if len(dev.IPv6s) == 0 {
			dev.IPv6s = []string{sourceIPStr}
		}
	}

	return dev
}

func (s *Server) handleDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if hasSelector(r.URL.Query().Get("mac"), r.URL.Query().Get("ip")) {
		writeError(w, http.StatusBadRequest, publicDeviceSelectorError)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	target, err := s.resolveGetTarget(r)
	if err != nil {
		if target != nil && target.sourceIP != nil && target.mac == nil {
			ipv4s := []string{}
			ipv6s := []string{}
			if target.sourceIP.To4() != nil {
				ipv4s = []string{target.sourceIP.String()}
			} else {
				ipv6s = []string{target.sourceIP.String()}
			}
			resp := deviceResponse{
				SourceIP: target.sourceIP.String(),
				MAC:      "unknown",
				IPv4s:    ipv4s,
				IPv6s:    ipv6s,
				Policy:   s.cfg.DefaultPolicy,
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if target.mac == nil {
		ipv4s := []string{}
		ipv6s := []string{}
		if target.sourceIP.To4() != nil {
			ipv4s = []string{target.sourceIP.String()}
		} else {
			ipv6s = []string{target.sourceIP.String()}
		}
		resp := deviceResponse{
			SourceIP: target.sourceIP.String(),
			MAC:      "unknown",
			IPv4s:    ipv4s,
			IPv6s:    ipv6s,
			Policy:   s.cfg.DefaultPolicy,
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	dev := s.buildDeviceState(target.mac, target.sourceIP)

	if !target.explicit && s.state.Get(dev.MAC) == nil {
		// Auto-assign default policy
		dev.LastSeen = time.Now()
		s.state.Set(dev)
		// Apply nft rules for default policy
		if err := s.nft.SetDevicePolicy(target.mac, "", dev.Policy); err != nil {
			// Log but continue
			fmt.Printf("warn: nft SetDevicePolicy for new device %s: %v\n", dev.MAC, err)
		}
	}

	resp := deviceResponse{
		SourceIP: "",
		MAC:      dev.MAC,
		IPv4s:    dev.IPv4s,
		IPv6s:    dev.IPv6s,
		Policy:   dev.Policy,
	}
	if target.sourceIP != nil {
		resp.SourceIP = target.sourceIP.String()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAdminDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := requireIPSelector(r.URL.Query().Get("mac"), r.URL.Query().Get("ip")); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	target, err := s.parseSelector("", r.URL.Query().Get("ip"))
	if err != nil {
		if target != nil && target.sourceIP != nil && target.mac == nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if target == nil || target.mac == nil {
		writeError(w, http.StatusNotFound, errString(err, "device not found"))
		return
	}

	dev := s.buildDeviceState(target.mac, target.sourceIP)
	resp := deviceResponse{
		MAC:    dev.MAC,
		IPv4s:  dev.IPv4s,
		IPv6s:  dev.IPv6s,
		Policy: dev.Policy,
	}
	if target.sourceIP != nil {
		resp.SourceIP = target.sourceIP.String()
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

func (s *Server) handleFeatures(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	writeJSON(w, http.StatusOK, featuresResponse{AdminEnabled: s.cfg.AdminPSK != ""})
}

type setPolicyRequest struct {
	Policy         string `json:"policy"`
	FlushConntrack bool   `json:"flush_conntrack"`
	MAC            string `json:"mac"`
	IP             string `json:"ip"`
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
	if hasSelector(req.MAC, req.IP) {
		writeError(w, http.StatusBadRequest, publicPolicySelectorError)
		return
	}

	if s.cfg.PolicyByName(req.Policy) == nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown policy: %q", req.Policy))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	target, err := s.resolvePostTarget(r, req)
	if err != nil {
		writeError(w, postTargetErrorStatus(req, target), err.Error())
		return
	}

	dev := s.buildDeviceState(target.mac, target.sourceIP)

	oldPolicy := ""
	if existing := s.state.Get(dev.MAC); existing != nil {
		oldPolicy = existing.Policy
	}

	// Move MAC between nft sets
	if err := s.nft.SetDevicePolicy(target.mac, oldPolicy, req.Policy); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("nft error: %v", err))
		return
	}

	if req.FlushConntrack {
		n, err := flushConntrackFunc(parseIPStrings(dev.IPv4s), parseIPStrings(dev.IPv6s))
		if err != nil {
			fmt.Printf("warn: flush conntrack for %s: %v\n", dev.MAC, err)
		} else if n > 0 {
			fmt.Printf("info: flushed %d conntrack entries for %s\n", n, dev.MAC)
		}
	}

	dev.Policy = req.Policy
	if !target.explicit {
		dev.LastSeen = time.Now()
	}
	s.state.Set(dev)

	if err := s.state.Save(s.cfg.StatePath); err != nil {
		fmt.Printf("warn: save state: %v\n", err)
	}

	resp := deviceResponse{
		SourceIP: "",
		MAC:      dev.MAC,
		IPv4s:    dev.IPv4s,
		IPv6s:    dev.IPv6s,
		Policy:   req.Policy,
	}
	if target.sourceIP != nil {
		resp.SourceIP = target.sourceIP.String()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAdminSetPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req setPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := requireIPSelector(req.MAC, req.IP); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.cfg.PolicyByName(req.Policy) == nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unknown policy: %q", req.Policy))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	target, err := s.parseSelector("", req.IP)
	if err != nil {
		if target != nil && target.sourceIP != nil && target.mac == nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if target == nil || target.mac == nil {
		writeError(w, http.StatusNotFound, errString(err, "device not found"))
		return
	}

	dev := s.buildDeviceState(target.mac, target.sourceIP)
	if existing := s.state.Get(dev.MAC); existing != nil {
		dev.LastSeen = existing.LastSeen
	} else {
		dev.LastSeen = time.Time{}
	}

	oldPolicy := ""
	if existing := s.state.Get(dev.MAC); existing != nil {
		oldPolicy = existing.Policy
	}

	if err := s.nft.SetDevicePolicy(target.mac, oldPolicy, req.Policy); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("nft error: %v", err))
		return
	}

	if req.FlushConntrack {
		n, err := flushConntrackFunc(parseIPStrings(dev.IPv4s), parseIPStrings(dev.IPv6s))
		if err != nil {
			fmt.Printf("warn: flush conntrack for %s: %v\n", dev.MAC, err)
		} else if n > 0 {
			fmt.Printf("info: flushed %d conntrack entries for %s\n", n, dev.MAC)
		}
	}

	dev.Policy = req.Policy
	s.state.Set(dev)

	if err := s.state.Save(s.cfg.StatePath); err != nil {
		fmt.Printf("warn: save state: %v\n", err)
	}

	resp := deviceResponse{
		MAC:    dev.MAC,
		IPv4s:  dev.IPv4s,
		IPv6s:  dev.IPv6s,
		Policy: req.Policy,
	}
	if target.sourceIP != nil {
		resp.SourceIP = target.sourceIP.String()
	}
	writeJSON(w, http.StatusOK, resp)
}

func errString(err error, fallback string) string {
	if err != nil {
		return err.Error()
	}
	return fallback
}
