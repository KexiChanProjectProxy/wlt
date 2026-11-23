package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"
)

// Client side of the traffic-count (wlt-traffic) API. Upload means sent by
// the device, download means received by the device.

type trafficWindowStats struct {
	Upload   uint64 `json:"upload"`
	Download uint64 `json:"download"`
	Total    uint64 `json:"total"`
}

type trafficDay struct {
	Date     string `json:"date"`
	Upload   uint64 `json:"upload"`
	Download uint64 `json:"download"`
}

type liveRate struct {
	UploadBps   uint64 `json:"upload_bps"`
	DownloadBps uint64 `json:"download_bps"`
}

type trafficResponse struct {
	Available bool               `json:"available"`
	Error     string             `json:"error,omitempty"`
	Today     trafficWindowStats `json:"today"`
	Yesterday trafficWindowStats `json:"yesterday"`
	Week      trafficWindowStats `json:"week"`
	Month     trafficWindowStats `json:"month"`
	LastMonth trafficWindowStats `json:"last_month"`
	Series    []trafficDay       `json:"series"`
	Live      liveRate           `json:"live"`
	Timezone  string             `json:"timezone,omitempty"`
}

func (s *Server) trafficGet(ctx context.Context, path string, q url.Values, out any) error {
	if s.trafficAPIURL == "" {
		return fmt.Errorf("traffic statistics are not configured")
	}
	u := s.trafficAPIURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := s.trafficHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("traffic service unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("traffic service returned HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type apiWindow struct {
	UploadBytes   uint64 `json:"upload_bytes"`
	DownloadBytes uint64 `json:"download_bytes"`
	TotalBytes    uint64 `json:"total_bytes"`
}

func (w apiWindow) stats() trafficWindowStats {
	return trafficWindowStats{Upload: w.UploadBytes, Download: w.DownloadBytes, Total: w.TotalBytes}
}

// fetchDeviceTraffic gathers everything the UI shows for one device.
func (s *Server) fetchDeviceTraffic(ctx context.Context, mac string) trafficResponse {
	out := trafficResponse{Series: []trafficDay{}}
	var sum struct {
		Timezone string               `json:"timezone"`
		Windows  map[string]apiWindow `json:"windows"`
		Live     *struct {
			UploadBps   uint64 `json:"upload_bps"`
			DownloadBps uint64 `json:"download_bps"`
		} `json:"live"`
	}
	if err := s.trafficGet(ctx, "/api/v1/summary", url.Values{"mac": {mac}}, &sum); err != nil {
		out.Error = err.Error()
		return out
	}
	out.Available = true
	out.Timezone = sum.Timezone
	out.Today = sum.Windows["today"].stats()
	out.Yesterday = sum.Windows["yesterday"].stats()
	out.Week = sum.Windows["7days"].stats()
	out.Month = sum.Windows["month"].stats()
	out.LastMonth = sum.Windows["lastmonth"].stats()
	if sum.Live != nil {
		out.Live = liveRate{UploadBps: sum.Live.UploadBps, DownloadBps: sum.Live.DownloadBps}
	}

	var ser struct {
		Days []struct {
			Date          string `json:"date"`
			UploadBytes   uint64 `json:"upload_bytes"`
			DownloadBytes uint64 `json:"download_bytes"`
		} `json:"days"`
	}
	if err := s.trafficGet(ctx, "/api/v1/series", url.Values{"mac": {mac}, "days": {"14"}}, &ser); err == nil {
		for _, d := range ser.Days {
			out.Series = append(out.Series, trafficDay{Date: d.Date, Upload: d.UploadBytes, Download: d.DownloadBytes})
		}
	}
	return out
}

// GET /api/traffic: the requesting device's own usage.
func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if hasSelector(r.URL.Query().Get("mac"), r.URL.Query().Get("ip")) {
		writeError(w, http.StatusBadRequest, "ip/mac selectors are only supported on /api/admin/traffic")
		return
	}
	target, err := s.resolveGetTarget(r)
	if err != nil || target == nil || target.mac == nil {
		msg := "could not identify this device"
		if err != nil {
			msg = err.Error()
		}
		writeJSON(w, http.StatusOK, trafficResponse{Error: msg, Series: []trafficDay{}})
		return
	}
	writeJSON(w, http.StatusOK, s.fetchDeviceTraffic(r.Context(), target.mac.String()))
}

// GET /api/admin/traffic?ip=...
func (s *Server) handleAdminTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := requireIPSelector(r.URL.Query().Get("mac"), r.URL.Query().Get("ip")); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.mu.Lock()
	target, err := s.parseSelector("", r.URL.Query().Get("ip"))
	s.mu.Unlock()
	if err != nil {
		if target != nil && target.sourceIP != nil && target.mac == nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if target == nil || target.mac == nil {
		writeError(w, http.StatusNotFound, "device not found")
		return
	}
	writeJSON(w, http.StatusOK, s.fetchDeviceTraffic(r.Context(), target.mac.String()))
}

var trafficWindows = map[string]bool{"today": true, "yesterday": true, "7days": true, "30days": true, "month": true, "lastmonth": true}

type topKEntry struct {
	IP          string `json:"ip"`
	MAC         string `json:"mac"`
	Upload      uint64 `json:"upload"`
	Download    uint64 `json:"download"`
	Total       uint64 `json:"total"`
	Policy      string `json:"policy"`
	UploadBps   uint64 `json:"upload_bps"`
	DownloadBps uint64 `json:"download_bps"`
}

type apiRecord struct {
	MAC           string `json:"mac"`
	UploadBytes   uint64 `json:"upload_bytes"`
	DownloadBytes uint64 `json:"download_bytes"`
	TotalBytes    uint64 `json:"total_bytes"`
}

func (s *Server) fetchLive(ctx context.Context) map[string]liveRate {
	var live struct {
		Devices []struct {
			MAC         string `json:"mac"`
			UploadBps   uint64 `json:"upload_bps"`
			DownloadBps uint64 `json:"download_bps"`
		} `json:"devices"`
	}
	out := map[string]liveRate{}
	if err := s.trafficGet(ctx, "/api/v1/live", nil, &live); err == nil {
		for _, d := range live.Devices {
			out[d.MAC] = liveRate{d.UploadBps, d.DownloadBps}
		}
	}
	return out
}

func primaryIP(dev *DeviceState) string {
	if dev == nil {
		return ""
	}
	for _, ip := range dev.IPv4s {
		if ip != "" {
			return ip
		}
	}
	for _, ip := range dev.IPv6s {
		if ip != "" {
			return ip
		}
	}
	return ""
}

// GET /api/admin/topk-traffic?window=today&k=10
func (s *Server) handleAdminTopKTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	k := 10
	if v := r.URL.Query().Get("k"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 100 {
			writeError(w, http.StatusBadRequest, "k must be between 1 and 100")
			return
		}
		k = n
	}
	window := r.URL.Query().Get("window")
	if window == "" {
		window = "today"
	}
	if !trafficWindows[window] {
		writeError(w, http.StatusBadRequest, "invalid window")
		return
	}
	var resp struct {
		Records []apiRecord `json:"records"`
	}
	q := url.Values{"window": {window}, "group": {"mac"}, "sort": {"total"}, "limit": {strconv.Itoa(k)}}
	if iface := r.URL.Query().Get("iface"); iface != "" {
		q.Set("interface", iface)
	}
	if err := s.trafficGet(r.Context(), "/api/v1/traffic", q, &resp); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	live := s.fetchLive(r.Context())
	entries := make([]topKEntry, 0, len(resp.Records))
	for _, rec := range resp.Records {
		dev := s.state.Get(rec.MAC)
		e := topKEntry{
			IP: primaryIP(dev), MAC: rec.MAC,
			Upload: rec.UploadBytes, Download: rec.DownloadBytes, Total: rec.TotalBytes,
			UploadBps: live[rec.MAC].UploadBps, DownloadBps: live[rec.MAC].DownloadBps,
		}
		if dev != nil {
			e.Policy = dev.Policy
		}
		entries = append(entries, e)
	}
	writeJSON(w, http.StatusOK, entries)
}

type adminDeviceEntry struct {
	MAC         string    `json:"mac"`
	IP          string    `json:"ip"`
	IPv4s       []string  `json:"ipv4s"`
	IPv6s       []string  `json:"ipv6s"`
	Policy      string    `json:"policy"`
	LastSeen    time.Time `json:"last_seen"`
	Today       uint64    `json:"today"`
	TodayUp     uint64    `json:"today_upload"`
	TodayDown   uint64    `json:"today_download"`
	UploadBps   uint64    `json:"upload_bps"`
	DownloadBps uint64    `json:"download_bps"`
}

// GET /api/admin/devices: every known device with its policy and today's usage.
func (s *Server) handleAdminDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	today := map[string]apiRecord{}
	trafficOK := false
	if s.trafficAPIURL != "" {
		var resp struct {
			Records []apiRecord `json:"records"`
		}
		q := url.Values{"window": {"today"}, "group": {"mac"}, "limit": {"1000"}}
		if err := s.trafficGet(r.Context(), "/api/v1/traffic", q, &resp); err == nil {
			trafficOK = true
			for _, rec := range resp.Records {
				today[rec.MAC] = rec
			}
		}
	}
	live := s.fetchLive(r.Context())
	devs := s.state.All()
	out := make([]adminDeviceEntry, 0, len(devs))
	for _, d := range devs {
		t := today[d.MAC]
		out = append(out, adminDeviceEntry{
			MAC: d.MAC, IP: primaryIP(d), IPv4s: nonNilStrings(d.IPv4s), IPv6s: nonNilStrings(d.IPv6s),
			Policy: d.Policy, LastSeen: d.LastSeen,
			Today: t.TotalBytes, TodayUp: t.UploadBytes, TodayDown: t.DownloadBytes,
			UploadBps: live[d.MAC].UploadBps, DownloadBps: live[d.MAC].DownloadBps,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Today != out[j].Today {
			return out[i].Today > out[j].Today
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	writeJSON(w, http.StatusOK, map[string]any{"traffic_available": trafficOK, "devices": out})
}

func nonNilStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
