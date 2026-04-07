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

func testAdminConfig(t *testing.T) *Config {
	t.Helper()
	cfg := testConfig(t)
	cfg.AdminPSK = "secret-psk"
	return cfg
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

func adminRequest(method, target string, body *bytes.Buffer, psk string) *http.Request {
	var req *http.Request
	if body == nil {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, body)
	}
	if psk != "" {
		req.Header.Set("X-WLT-PSK", psk)
	}
	return req
}

func TestHandleDeviceSelfAutoEnrollsRequester(t *testing.T) {
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

func TestHandleDeviceRejectsRemoteSelectorsOnPublicRoute(t *testing.T) {
	restoreServerGlobals(t)
	srv := NewServer(testConfig(t), NewState(), &nftStub{})

	for _, path := range []string{
		"/api/device?ip=192.0.2.1",
		"/api/device?mac=aa:bb:cc:dd:ee:ff",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.RemoteAddr = "198.51.100.20:45678"
			rr := httptest.NewRecorder()

			srv.ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
			}
			if got := decodeErrorResponse(t, rr); got != publicDeviceSelectorError {
				t.Fatalf("error = %q, want %q", got, publicDeviceSelectorError)
			}
		})
	}
}

func TestHandleSetPolicySelfUsesRequester(t *testing.T) {
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

func TestHandleSetPolicyRejectsRemoteSelectorsOnPublicRoute(t *testing.T) {
	restoreServerGlobals(t)
	srv := NewServer(testConfig(t), NewState(), &nftStub{})

	for _, body := range []string{
		`{"policy":"proxy","ip":"192.0.2.44"}`,
		`{"policy":"proxy","mac":"aa:bb:cc:dd:ee:15"}`,
	} {
		t.Run(body, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/policy", bytes.NewBufferString(body))
			req.RemoteAddr = "198.51.100.20:60000"
			rr := httptest.NewRecorder()

			srv.ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
			}
			if got := decodeErrorResponse(t, rr); got != publicPolicySelectorError {
				t.Fatalf("error = %q, want %q", got, publicPolicySelectorError)
			}
		})
	}
}

func TestAdminRoutesRegisterOnlyWhenPSKConfigured(t *testing.T) {
	restoreServerGlobals(t)
	srv := NewServer(testConfig(t), NewState(), &nftStub{})

	req := httptest.NewRequest(http.MethodGet, "/api/admin/device?ip=192.0.2.1", nil)
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHandleFeaturesReportsAdminAvailability(t *testing.T) {
	restoreServerGlobals(t)

	t.Run("disabled", func(t *testing.T) {
		srv := NewServer(testConfig(t), NewState(), &nftStub{})
		req := httptest.NewRequest(http.MethodGet, "/api/features", nil)
		rr := httptest.NewRecorder()

		srv.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
		}
		var resp featuresResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode features response: %v", err)
		}
		if resp.AdminEnabled {
			t.Fatalf("admin_enabled = true, want false")
		}
	})

	t.Run("enabled", func(t *testing.T) {
		srv := NewServer(testAdminConfig(t), NewState(), &nftStub{})
		req := httptest.NewRequest(http.MethodGet, "/api/features", nil)
		rr := httptest.NewRecorder()

		srv.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
		}
		var resp featuresResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode features response: %v", err)
		}
		if !resp.AdminEnabled {
			t.Fatalf("admin_enabled = false, want true")
		}
	})
}

func TestAdminRoutesRequirePSK(t *testing.T) {
	restoreServerGlobals(t)
	srv := NewServer(testAdminConfig(t), NewState(), &nftStub{})

	requests := []*http.Request{
		adminRequest(http.MethodGet, "/api/admin/device?ip=192.0.2.44", nil, ""),
		adminRequest(http.MethodGet, "/api/admin/device?ip=192.0.2.44", nil, "wrong"),
		adminRequest(http.MethodPost, "/api/admin/policy", bytes.NewBufferString(`{"policy":"vpn","ip":"192.0.2.44"}`), ""),
		adminRequest(http.MethodPost, "/api/admin/policy", bytes.NewBufferString(`{"policy":"vpn","ip":"192.0.2.44"}`), "wrong"),
	}

	for i, req := range requests {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			req.RemoteAddr = "198.51.100.20:60000"
			rr := httptest.NewRecorder()
			srv.ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
			}
			if got := decodeErrorResponse(t, rr); got != adminAuthError {
				t.Fatalf("error = %q, want %q", got, adminAuthError)
			}
		})
	}
}

func TestHandleAdminDeviceSelectorValidation(t *testing.T) {
	restoreServerGlobals(t)
	srv := NewServer(testAdminConfig(t), NewState(), &nftStub{})

	tests := []struct {
		name string
		path string
		want int
		err  string
	}{
		{name: "missing selector", path: "/api/admin/device", want: http.StatusBadRequest, err: "ip selector is required"},
		{name: "both selectors", path: "/api/admin/device?mac=aa:bb:cc:dd:ee:ff&ip=192.0.2.1", want: http.StatusBadRequest, err: "admin routes only support ip selectors"},
		{name: "mac selector", path: "/api/admin/device?mac=not-a-mac", want: http.StatusBadRequest, err: "admin routes only support ip selectors"},
		{name: "invalid ip", path: "/api/admin/device?ip=bad-ip", want: http.StatusBadRequest, err: "invalid IP address"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := adminRequest(http.MethodGet, tt.path, nil, "secret-psk")
			req.RemoteAddr = "198.51.100.20:45678"
			rr := httptest.NewRecorder()

			srv.ServeHTTP(rr, req)

			if rr.Code != tt.want {
				t.Fatalf("status = %d, want %d", rr.Code, tt.want)
			}
			if got := decodeErrorResponse(t, rr); got != tt.err {
				t.Fatalf("error = %q, want %q", got, tt.err)
			}
		})
	}
}

func TestHandleAdminDeviceRejectsMACSelector(t *testing.T) {
	restoreServerGlobals(t)
	srv := NewServer(testAdminConfig(t), NewState(), &nftStub{})

	req := adminRequest(http.MethodGet, "/api/admin/device?mac=aa:bb:cc:dd:ee:01", nil, "secret-psk")
	req.RemoteAddr = "198.51.100.20:23456"
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	if got := decodeErrorResponse(t, rr); got != "admin routes only support ip selectors" {
		t.Fatalf("error = %q", got)
	}
}

func TestHandleAdminDeviceExplicitIPUsesSelectedTarget(t *testing.T) {
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
	srv := NewServer(testAdminConfig(t), state, nft)

	req := adminRequest(http.MethodGet, "/api/admin/device?ip=192.0.2.77", nil, "secret-psk")
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

func TestHandleAdminDeviceExplicitIPFallsBackToState(t *testing.T) {
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
	srv := NewServer(testAdminConfig(t), state, &nftStub{})

	req := adminRequest(http.MethodGet, "/api/admin/device?ip=192.0.2.88", nil, "secret-psk")
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

func TestHandleAdminDeviceExplicitIPUnresolvedReturnsNotFound(t *testing.T) {
	restoreServerGlobals(t)
	lookupMACFunc = func(ip net.IP) (net.HardwareAddr, error) {
		return nil, fmt.Errorf("no neighbor entry found for IP %s", ip)
	}
	srv := NewServer(testAdminConfig(t), NewState(), &nftStub{})

	req := adminRequest(http.MethodGet, "/api/admin/device?ip=2001:db8::55", nil, "secret-psk")
	req.RemoteAddr = "198.51.100.20:45678"
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
	if got := decodeErrorResponse(t, rr); got != "lookup MAC: no neighbor entry found for IP 2001:db8::55" {
		t.Fatalf("error = %q", got)
	}
}

func TestHandleAdminSetPolicySelectorValidation(t *testing.T) {
	restoreServerGlobals(t)
	srv := NewServer(testAdminConfig(t), NewState(), &nftStub{})

	tests := []struct {
		name string
		body string
		want int
		err  string
	}{
		{name: "missing selector", body: `{"policy":"vpn"}`, want: http.StatusBadRequest, err: "ip selector is required"},
		{name: "both selectors", body: `{"policy":"vpn","mac":"aa:bb:cc:dd:ee:ff","ip":"192.0.2.1"}`, want: http.StatusBadRequest, err: "admin routes only support ip selectors"},
		{name: "mac selector", body: `{"policy":"vpn","mac":"not-a-mac"}`, want: http.StatusBadRequest, err: "admin routes only support ip selectors"},
		{name: "invalid ip", body: `{"policy":"vpn","ip":"bad-ip"}`, want: http.StatusBadRequest, err: "invalid IP address"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := adminRequest(http.MethodPost, "/api/admin/policy", bytes.NewBufferString(tt.body), "secret-psk")
			req.RemoteAddr = "198.51.100.20:60000"
			rr := httptest.NewRecorder()

			srv.ServeHTTP(rr, req)

			if rr.Code != tt.want {
				t.Fatalf("status = %d, want %d", rr.Code, tt.want)
			}
			if got := decodeErrorResponse(t, rr); got != tt.err {
				t.Fatalf("error = %q, want %q", got, tt.err)
			}
		})
	}
}

func TestHandleAdminSetPolicyExplicitIPTargetsSelectedDevice(t *testing.T) {
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
	lastSeen := time.Unix(1700000300, 0)
	state.Set(&DeviceState{MAC: mac.String(), Policy: "direct", LastSeen: lastSeen})
	srv := NewServer(testAdminConfig(t), state, nft)

	body := `{"policy":"vpn","ip":"192.0.2.44","flush_conntrack":true}`
	req := adminRequest(http.MethodPost, "/api/admin/policy", bytes.NewBufferString(body), "secret-psk")
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
	if got := state.Get(mac.String()); got == nil || got.Policy != "vpn" || !got.LastSeen.Equal(lastSeen) {
		t.Fatalf("state not updated with preserved last_seen: %+v", got)
	}
	if !reflect.DeepEqual(toIPStrings(flushedV4), []string{"192.0.2.44"}) || !reflect.DeepEqual(toIPStrings(flushedV6), []string{"2001:db8::44"}) {
		t.Fatalf("unexpected flushed IPs: v4=%v v6=%v", toIPStrings(flushedV4), toIPStrings(flushedV6))
	}
}

func TestHandleAdminSetPolicyExplicitIPFallsBackToState(t *testing.T) {
	restoreServerGlobals(t)
	mac := mustMAC(t, "aa:bb:cc:dd:ee:14")
	lookupMACFunc = func(ip net.IP) (net.HardwareAddr, error) {
		return nil, fmt.Errorf("no neighbor entry found for IP %s", ip)
	}
	lookupAllIPsFunc = func(net.HardwareAddr) ([]net.IP, []net.IP, error) {
		return nil, nil, fmt.Errorf("no live data")
	}

	state := NewState()
	lastSeen := time.Unix(1700000400, 0)
	state.Set(&DeviceState{
		MAC:      mac.String(),
		IPv4s:    []string{"192.0.2.144"},
		Policy:   "direct",
		LastSeen: lastSeen,
	})
	nft := &nftStub{}
	srv := NewServer(testAdminConfig(t), state, nft)

	body := `{"policy":"vpn","ip":"192.0.2.144"}`
	req := adminRequest(http.MethodPost, "/api/admin/policy", bytes.NewBufferString(body), "secret-psk")
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

func TestHandleAdminSetPolicyExplicitIPUnresolvedReturnsNotFound(t *testing.T) {
	restoreServerGlobals(t)
	lookupMACFunc = func(ip net.IP) (net.HardwareAddr, error) {
		return nil, fmt.Errorf("no neighbor entry found for IP %s", ip)
	}
	srv := NewServer(testAdminConfig(t), NewState(), &nftStub{})

	body := `{"policy":"vpn","ip":"192.0.2.200"}`
	req := adminRequest(http.MethodPost, "/api/admin/policy", bytes.NewBufferString(body), "secret-psk")
	req.RemoteAddr = "198.51.100.20:60000"
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHandleAdminSetPolicyRejectsMACSelector(t *testing.T) {
	restoreServerGlobals(t)
	srv := NewServer(testAdminConfig(t), NewState(), &nftStub{})

	body := `{"policy":"proxy","mac":"aa:bb:cc:dd:ee:15"}`
	req := adminRequest(http.MethodPost, "/api/admin/policy", bytes.NewBufferString(body), "secret-psk")
	req.RemoteAddr = "198.51.100.20:60000"
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	if got := decodeErrorResponse(t, rr); got != "admin routes only support ip selectors" {
		t.Fatalf("error = %q", got)
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
