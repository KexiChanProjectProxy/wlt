package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

type nftCall struct {
	mac       string
	oldPolicy string
	newPolicy string
}

type nftStub struct {
	calls []nftCall
	err   error
}

func (n *nftStub) SetDevicePolicy(mac net.HardwareAddr, oldPolicyName, newPolicyName string) error {
	n.calls = append(n.calls, nftCall{
		mac:       mac.String(),
		oldPolicy: oldPolicyName,
		newPolicy: newPolicyName,
	})
	return n.err
}

func testConfig(t *testing.T) *Config {
	t.Helper()
	return &Config{
		Listen:        ":0",
		TableName:     "wlt",
		ChainName:     "mark_traffic",
		LanInterfaces: []string{"br-lan"},
		StatePath:     filepath.Join(t.TempDir(), "state.json"),
		DefaultPolicy: "direct",
		Policies: []Policy{
			{Name: "direct", Mark: 1, Description: "Direct"},
			{Name: "proxy", Mark: 2, Description: "Proxy"},
			{Name: "vpn", Mark: 3, Description: "VPN"},
		},
	}
}

func restoreServerGlobals(t *testing.T) {
	t.Helper()
	oldExtractIP := extractIPFunc
	oldLookupMAC := lookupMACFunc
	oldLookupAllIPs := lookupAllIPsFunc
	oldFlushConntrack := flushConntrackFunc
	oldParseMAC := parseMACFunc
	t.Cleanup(func() {
		extractIPFunc = oldExtractIP
		lookupMACFunc = oldLookupMAC
		lookupAllIPsFunc = oldLookupAllIPs
		flushConntrackFunc = oldFlushConntrack
		parseMACFunc = oldParseMAC
	})
}

func decodeDeviceResponse(t *testing.T, rr *httptest.ResponseRecorder) deviceResponse {
	t.Helper()
	var resp deviceResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode device response: %v", err)
	}
	return resp
}

func decodeErrorResponse(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	return resp["error"]
}

func TestHandleDeviceLegacyAutoEnrollsRequester(t *testing.T) {
	restoreServerGlobals(t)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:ff")
	lookupMACFunc = func(ip net.IP) (net.HardwareAddr, error) {
		if got, want := ip.String(), "192.0.2.10"; got != want {
			return nil, fmt.Errorf("unexpected ip %s", got)
		}
		return mac, nil
	}
	lookupAllIPsFunc = func(gotMAC net.HardwareAddr) ([]net.IP, []net.IP, error) {
		if gotMAC.String() != mac.String() {
			return nil, nil, fmt.Errorf("unexpected mac %s", gotMAC)
		}
		return []net.IP{net.ParseIP("192.0.2.10")}, []net.IP{net.ParseIP("2001:db8::10")}, nil
	}

	nft := &nftStub{}
	state := NewState()
	srv := NewServer(testConfig(t), state, nft)

	req := httptest.NewRequest(http.MethodGet, "/api/device", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	resp := decodeDeviceResponse(t, rr)
	if resp.SourceIP != "192.0.2.10" || resp.MAC != mac.String() || resp.Policy != "direct" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if !reflect.DeepEqual(resp.IPv4s, []string{"192.0.2.10"}) || !reflect.DeepEqual(resp.IPv6s, []string{"2001:db8::10"}) {
		t.Fatalf("unexpected IPs: %+v", resp)
	}
	if got := state.Get(mac.String()); got == nil || got.Policy != "direct" {
		t.Fatalf("state not auto-enrolled: %+v", got)
	}
	if !reflect.DeepEqual(nft.calls, []nftCall{{mac: mac.String(), oldPolicy: "", newPolicy: "direct"}}) {
		t.Fatalf("unexpected nft calls: %+v", nft.calls)
	}
}

func TestHandleDeviceExplicitMACIsReadOnly(t *testing.T) {
	restoreServerGlobals(t)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:01")
	lookupAllIPsFunc = func(gotMAC net.HardwareAddr) ([]net.IP, []net.IP, error) {
		if gotMAC.String() != mac.String() {
			return nil, nil, fmt.Errorf("unexpected mac %s", gotMAC)
		}
		return []net.IP{net.ParseIP("192.0.2.99")}, []net.IP{net.ParseIP("2001:db8::99")}, nil
	}

	nft := &nftStub{}
	state := NewState()
	seen := time.Unix(1700000000, 0)
	state.Set(&DeviceState{
		MAC:      mac.String(),
		IPv4s:    []string{"192.0.2.5"},
		IPv6s:    []string{"2001:db8::5"},
		Policy:   "proxy",
		LastSeen: seen,
	})
	srv := NewServer(testConfig(t), state, nft)

	req := httptest.NewRequest(http.MethodGet, "/api/device?mac="+mac.String(), nil)
	req.RemoteAddr = "198.51.100.20:23456"
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	resp := decodeDeviceResponse(t, rr)
	if resp.SourceIP != "" || resp.MAC != mac.String() || resp.Policy != "proxy" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if !reflect.DeepEqual(resp.IPv4s, []string{"192.0.2.99"}) || !reflect.DeepEqual(resp.IPv6s, []string{"2001:db8::99"}) {
		t.Fatalf("unexpected live IPs: %+v", resp)
	}
	if len(nft.calls) != 0 {
		t.Fatalf("explicit GET should be read-only, got nft calls: %+v", nft.calls)
	}
	if got := state.Get(mac.String()); got == nil || got.Policy != "proxy" || !got.LastSeen.Equal(seen) {
		t.Fatalf("state mutated unexpectedly: %+v", got)
	}
}

func TestHandleDeviceExplicitIPUsesSelectedTarget(t *testing.T) {
	restoreServerGlobals(t)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:02")
	lookupMACFunc = func(ip net.IP) (net.HardwareAddr, error) {
		if got, want := ip.String(), "192.0.2.77"; got != want {
			return nil, fmt.Errorf("unexpected ip %s", got)
		}
		return mac, nil
	}
	lookupAllIPsFunc = func(net.HardwareAddr) ([]net.IP, []net.IP, error) {
		return nil, nil, fmt.Errorf("no live data")
	}

	nft := &nftStub{}
	state := NewState()
	state.Set(&DeviceState{
		MAC:      mac.String(),
		IPv4s:    []string{"192.0.2.77"},
		IPv6s:    []string{"2001:db8::77"},
		Policy:   "vpn",
		LastSeen: time.Unix(1700000100, 0),
	})
	srv := NewServer(testConfig(t), state, nft)

	req := httptest.NewRequest(http.MethodGet, "/api/device?ip=192.0.2.77", nil)
	req.RemoteAddr = "198.51.100.20:34567"
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	resp := decodeDeviceResponse(t, rr)
	if resp.SourceIP != "192.0.2.77" || resp.MAC != mac.String() || resp.Policy != "vpn" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if !reflect.DeepEqual(resp.IPv4s, []string{"192.0.2.77"}) || !reflect.DeepEqual(resp.IPv6s, []string{"2001:db8::77"}) {
		t.Fatalf("expected state-backed IPs, got %+v", resp)
	}
	if len(nft.calls) != 0 {
		t.Fatalf("explicit GET should not touch nft, got %+v", nft.calls)
	}
}

func TestHandleDeviceExplicitIPFallsBackToState(t *testing.T) {
	restoreServerGlobals(t)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:12")
	lookupMACFunc = func(ip net.IP) (net.HardwareAddr, error) {
		return nil, fmt.Errorf("no neighbor entry found for IP %s", ip)
	}
	lookupAllIPsFunc = func(net.HardwareAddr) ([]net.IP, []net.IP, error) {
		return nil, nil, fmt.Errorf("no live data")
	}

	state := NewState()
	state.Set(&DeviceState{
		MAC:      mac.String(),
		IPv4s:    []string{"192.0.2.88"},
		IPv6s:    []string{"2001:db8::88"},
		Policy:   "proxy",
		LastSeen: time.Unix(1700000200, 0),
	})
	srv := NewServer(testConfig(t), state, &nftStub{})

	req := httptest.NewRequest(http.MethodGet, "/api/device?ip=192.0.2.88", nil)
	req.RemoteAddr = "198.51.100.20:34567"
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	resp := decodeDeviceResponse(t, rr)
	if resp.SourceIP != "192.0.2.88" || resp.MAC != mac.String() || resp.Policy != "proxy" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestHandleDeviceUnknownIPv6UsesIPv6Field(t *testing.T) {
	restoreServerGlobals(t)
	lookupMACFunc = func(ip net.IP) (net.HardwareAddr, error) {
		return nil, fmt.Errorf("no neighbor entry found for IP %s", ip)
	}
	srv := NewServer(testConfig(t), NewState(), &nftStub{})

	req := httptest.NewRequest(http.MethodGet, "/api/device?ip=2001:db8::55", nil)
	req.RemoteAddr = "198.51.100.20:45678"
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	resp := decodeDeviceResponse(t, rr)
	if !reflect.DeepEqual(resp.IPv4s, []string{}) || !reflect.DeepEqual(resp.IPv6s, []string{"2001:db8::55"}) {
		t.Fatalf("unexpected IP classification: %+v", resp)
	}
}

func TestHandleDeviceSelectorValidation(t *testing.T) {
	restoreServerGlobals(t)
	srv := NewServer(testConfig(t), NewState(), &nftStub{})

	tests := []struct {
		name string
		path string
		want string
	}{
		{name: "invalid mac", path: "/api/device?mac=not-a-mac", want: "invalid MAC address"},
		{name: "invalid ip", path: "/api/device?ip=bad-ip", want: "invalid IP address"},
		{name: "both selectors", path: "/api/device?mac=aa:bb:cc:dd:ee:ff&ip=192.0.2.1", want: "at most one of mac or ip may be specified"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req.RemoteAddr = "198.51.100.20:45678"
			rr := httptest.NewRecorder()

			srv.ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
			}
			if got := decodeErrorResponse(t, rr); got != tt.want {
				t.Fatalf("error = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHandleSetPolicyLegacyUsesRequester(t *testing.T) {
	restoreServerGlobals(t)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:03")
	lookupMACFunc = func(ip net.IP) (net.HardwareAddr, error) {
		if got, want := ip.String(), "192.0.2.30"; got != want {
			return nil, fmt.Errorf("unexpected ip %s", got)
		}
		return mac, nil
	}
	lookupAllIPsFunc = func(net.HardwareAddr) ([]net.IP, []net.IP, error) {
		return []net.IP{net.ParseIP("192.0.2.30")}, nil, nil
	}

	nft := &nftStub{}
	state := NewState()
	state.Set(&DeviceState{MAC: mac.String(), Policy: "direct"})
	srv := NewServer(testConfig(t), state, nft)

	req := httptest.NewRequest(http.MethodPost, "/api/policy", bytes.NewBufferString(`{"policy":"proxy"}`))
	req.RemoteAddr = "192.0.2.30:56789"
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	resp := decodeDeviceResponse(t, rr)
	if resp.SourceIP != "192.0.2.30" || resp.MAC != mac.String() || resp.Policy != "proxy" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if got := state.Get(mac.String()); got == nil || got.Policy != "proxy" {
		t.Fatalf("state not updated: %+v", got)
	}
	if !reflect.DeepEqual(nft.calls, []nftCall{{mac: mac.String(), oldPolicy: "direct", newPolicy: "proxy"}}) {
		t.Fatalf("unexpected nft calls: %+v", nft.calls)
	}
}

func TestHandleSetPolicyExplicitIPTargetsSelectedDevice(t *testing.T) {
	restoreServerGlobals(t)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:04")
	lookupMACFunc = func(ip net.IP) (net.HardwareAddr, error) {
		if got, want := ip.String(), "192.0.2.44"; got != want {
			return nil, fmt.Errorf("unexpected ip %s", got)
		}
		return mac, nil
	}
	lookupAllIPsFunc = func(net.HardwareAddr) ([]net.IP, []net.IP, error) {
		return []net.IP{net.ParseIP("192.0.2.44")}, []net.IP{net.ParseIP("2001:db8::44")}, nil
	}
	var flushedV4, flushedV6 []net.IP
	flushConntrackFunc = func(ipv4s []net.IP, ipv6s []net.IP) (uint, error) {
		flushedV4 = append([]net.IP(nil), ipv4s...)
		flushedV6 = append([]net.IP(nil), ipv6s...)
		return 0, nil
	}

	nft := &nftStub{}
	state := NewState()
	state.Set(&DeviceState{MAC: mac.String(), Policy: "direct"})
	srv := NewServer(testConfig(t), state, nft)

	body := `{"policy":"vpn","ip":"192.0.2.44","flush_conntrack":true}`
	req := httptest.NewRequest(http.MethodPost, "/api/policy", bytes.NewBufferString(body))
	req.RemoteAddr = "198.51.100.20:60000"
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	resp := decodeDeviceResponse(t, rr)
	if resp.SourceIP != "192.0.2.44" || resp.MAC != mac.String() || resp.Policy != "vpn" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if !reflect.DeepEqual(nft.calls, []nftCall{{mac: mac.String(), oldPolicy: "direct", newPolicy: "vpn"}}) {
		t.Fatalf("unexpected nft calls: %+v", nft.calls)
	}
	if got := state.Get(mac.String()); got == nil || got.Policy != "vpn" {
		t.Fatalf("state not updated: %+v", got)
	}
	if !reflect.DeepEqual(toIPStrings(flushedV4), []string{"192.0.2.44"}) || !reflect.DeepEqual(toIPStrings(flushedV6), []string{"2001:db8::44"}) {
		t.Fatalf("unexpected flushed IPs: v4=%v v6=%v", toIPStrings(flushedV4), toIPStrings(flushedV6))
	}
}

func TestHandleSetPolicyExplicitIPFallsBackToState(t *testing.T) {
	restoreServerGlobals(t)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:14")
	lookupMACFunc = func(ip net.IP) (net.HardwareAddr, error) {
		return nil, fmt.Errorf("no neighbor entry found for IP %s", ip)
	}
	lookupAllIPsFunc = func(net.HardwareAddr) ([]net.IP, []net.IP, error) {
		return nil, nil, fmt.Errorf("no live data")
	}

	state := NewState()
	lastSeen := time.Unix(1700000300, 0)
	state.Set(&DeviceState{
		MAC:      mac.String(),
		IPv4s:    []string{"192.0.2.144"},
		Policy:   "direct",
		LastSeen: lastSeen,
	})
	nft := &nftStub{}
	srv := NewServer(testConfig(t), state, nft)

	body := `{"policy":"vpn","ip":"192.0.2.144"}`
	req := httptest.NewRequest(http.MethodPost, "/api/policy", bytes.NewBufferString(body))
	req.RemoteAddr = "198.51.100.20:60000"
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if !reflect.DeepEqual(nft.calls, []nftCall{{mac: mac.String(), oldPolicy: "direct", newPolicy: "vpn"}}) {
		t.Fatalf("unexpected nft calls: %+v", nft.calls)
	}
	if got := state.Get(mac.String()); got == nil || got.Policy != "vpn" || !got.LastSeen.Equal(lastSeen) {
		t.Fatalf("unexpected state after explicit update: %+v", got)
	}
}

func TestHandleSetPolicyExplicitIPUnresolvedReturnsNotFound(t *testing.T) {
	restoreServerGlobals(t)
	lookupMACFunc = func(ip net.IP) (net.HardwareAddr, error) {
		return nil, fmt.Errorf("no neighbor entry found for IP %s", ip)
	}
	srv := NewServer(testConfig(t), NewState(), &nftStub{})

	body := `{"policy":"vpn","ip":"192.0.2.200"}`
	req := httptest.NewRequest(http.MethodPost, "/api/policy", bytes.NewBufferString(body))
	req.RemoteAddr = "198.51.100.20:60000"
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHandleSetPolicyExplicitMACPreservesLastSeen(t *testing.T) {
	restoreServerGlobals(t)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:15")
	lookupAllIPsFunc = func(net.HardwareAddr) ([]net.IP, []net.IP, error) {
		return nil, nil, fmt.Errorf("no live data")
	}

	state := NewState()
	lastSeen := time.Unix(1700000400, 0)
	state.Set(&DeviceState{
		MAC:      mac.String(),
		Policy:   "direct",
		LastSeen: lastSeen,
	})
	nft := &nftStub{}
	srv := NewServer(testConfig(t), state, nft)

	body := `{"policy":"proxy","mac":"aa:bb:cc:dd:ee:15"}`
	req := httptest.NewRequest(http.MethodPost, "/api/policy", bytes.NewBufferString(body))
	req.RemoteAddr = "198.51.100.20:60000"
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if got := state.Get(mac.String()); got == nil || got.Policy != "proxy" || !got.LastSeen.Equal(lastSeen) {
		t.Fatalf("unexpected state after explicit MAC update: %+v", got)
	}
}

func mustMAC(t *testing.T, value string) net.HardwareAddr {
	t.Helper()
	mac, err := net.ParseMAC(value)
	if err != nil {
		t.Fatalf("parse mac %q: %v", value, err)
	}
	return mac
}
