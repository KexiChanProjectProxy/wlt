package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLiveEndpoints(t *testing.T) {
	restoreServerGlobals(t)
	var gotQuery string
	traffic := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/live" {
			http.NotFound(w, r)
			return
		}
		gotQuery = r.URL.RawQuery
		json.NewEncoder(w).Encode(map[string]any{
			"interval_seconds": 1,
			"devices": []map[string]any{
				{"mac": "aa:00:00:00:00:01", "upload_bps": 100, "download_bps": 2000},
				{"mac": "aa:00:00:00:00:02", "upload_bps": 5, "download_bps": 6},
			},
		})
	}))
	defer traffic.Close()

	cfg := testAdminConfig(t)
	cfg.TrafficAPIURL = traffic.URL
	srv := NewServer(cfg, NewState(), &nftStub{})
	extractIPFunc = func(*http.Request) (net.IP, error) { return net.ParseIP("192.168.1.10"), nil }
	lookupMACFunc = func(net.IP) (net.HardwareAddr, error) { return net.ParseMAC("aa:00:00:00:00:01") }

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/live", nil))
	var self liveResponse
	json.NewDecoder(rr.Body).Decode(&self)
	if !self.Available || self.DownloadBps != 2000 || self.UploadBps != 100 || self.IntervalSeconds != 1 {
		t.Fatalf("self live = %+v", self)
	}
	if gotQuery != "mac=aa%3A00%3A00%3A00%3A00%3A01" {
		t.Fatalf("query = %q", gotQuery)
	}

	rr = httptest.NewRecorder()
	srv.ServeHTTP(rr, adminRequest(http.MethodGet, "/api/admin/live", nil, ""))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("admin live without psk: %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	srv.ServeHTTP(rr, adminRequest(http.MethodGet, "/api/admin/live", nil, "secret-psk"))
	var all struct {
		Devices map[string]liveRate `json:"devices"`
	}
	json.NewDecoder(rr.Body).Decode(&all)
	if len(all.Devices) != 2 || all.Devices["aa:00:00:00:00:02"].DownloadBps != 6 {
		t.Fatalf("admin live = %+v", all)
	}

	// Traffic service down: self endpoint degrades quietly.
	traffic.Close()
	rr = httptest.NewRecorder()
	srv.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/live", nil))
	self = liveResponse{}
	json.NewDecoder(rr.Body).Decode(&self)
	if rr.Code != 200 || self.Available {
		t.Fatalf("down: %d %+v", rr.Code, self)
	}
}
