package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Built-in traffic aggregator.  This replaces the former
// wlt-traffic-pi.py/wlt-traffic-py service: it reads the router's traffic
// API, the local Clash API and per-device nft counters, and serves the
// traffic-count-compatible loopback API that the wlt UI already uses.

type aggCounter struct {
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

type aggCacheEntry struct {
	at     time.Time
	status int
	body   []byte
	ctype  string
}

type trafficAgg struct {
	cfg   *Config
	state *State
	nft   string

	mu           sync.Mutex
	date         string
	singbox      map[string]*aggCounter
	wg           map[string]*aggCounter
	router       map[string]*aggCounter
	live         map[string]liveRate
	liveInterval float64
	lastWG       map[string]uint64
	connLast     map[string][2]uint64
	ip2mac       map[string]string
	mac2ips      map[string][]string
	mapSig       string

	proxyMu    sync.Mutex
	proxyCache map[string]aggCacheEntry

	client *http.Client
}

func todayCST() string {
	return time.Now().In(time.FixedZone("CST", 8*3600)).Format("2006-01-02")
}

func NewTrafficAgg(cfg *Config, st *State) *trafficAgg {
	return &trafficAgg{
		cfg:        cfg,
		state:      st,
		nft:        findNFT(),
		date:       todayCST(),
		singbox:    map[string]*aggCounter{},
		wg:         map[string]*aggCounter{},
		router:     map[string]*aggCounter{},
		live:       map[string]liveRate{},
		lastWG:     map[string]uint64{},
		connLast:   map[string][2]uint64{},
		ip2mac:     map[string]string{},
		mac2ips:    map[string][]string{},
		proxyCache: map[string]aggCacheEntry{},
		client:     &http.Client{Timeout: 8 * time.Second},
	}
}

func findNFT() string {
	if p, err := exec.LookPath("nft"); err == nil {
		return p
	}
	for _, p := range []string{"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

type aggPersist struct {
	Date    string                `json:"date"`
	Singbox map[string]aggCounter `json:"singbox"`
	WG      map[string]aggCounter `json:"wg"`
	Router  map[string]aggCounter `json:"router"`
}

func (a *trafficAgg) load() {
	b, err := os.ReadFile(a.cfg.TrafficStatePath)
	if err != nil {
		return
	}
	var p aggPersist
	if json.Unmarshal(b, &p) != nil || p.Date != todayCST() {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for mac, c := range p.Singbox {
		a.singbox[mac] = &aggCounter{Up: c.Up, Down: c.Down}
	}
	for mac, c := range p.WG {
		a.wg[mac] = &aggCounter{Up: c.Up, Down: c.Down}
	}
	for mac, c := range p.Router {
		a.router[mac] = &aggCounter{Up: c.Up, Down: c.Down}
	}
}

func (a *trafficAgg) save() {
	a.mu.Lock()
	p := aggPersist{Date: a.date, Singbox: map[string]aggCounter{}, WG: map[string]aggCounter{}, Router: map[string]aggCounter{}}
	for mac, c := range a.singbox {
		p.Singbox[mac] = *c
	}
	for mac, c := range a.wg {
		p.WG[mac] = *c
	}
	for mac, c := range a.router {
		p.Router[mac] = *c
	}
	a.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(a.cfg.TrafficStatePath), 0755); err != nil {
		return
	}
	b, err := json.Marshal(p)
	if err != nil {
		return
	}
	tmp := a.cfg.TrafficStatePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return
	}
	_ = os.Rename(tmp, a.cfg.TrafficStatePath)
}

func (a *trafficAgg) resetLocked() {
	d := todayCST()
	if a.date == d {
		return
	}
	a.date = d
	a.singbox = map[string]*aggCounter{}
	a.wg = map[string]*aggCounter{}
	a.router = map[string]*aggCounter{}
	a.lastWG = map[string]uint64{}
	a.connLast = map[string][2]uint64{}
}

func aggAdd(m map[string]*aggCounter, mac, dir string, v uint64) {
	if mac == "" || v == 0 {
		return
	}
	c := m[mac]
	if c == nil {
		c = &aggCounter{}
		m[mac] = c
	}
	if dir == "up" {
		c.Up += v
	} else {
		c.Down += v
	}
}

func (a *trafficAgg) refreshDevices() {
	devs := a.state.All()
	ip2mac := make(map[string]string)
	mac2ips := make(map[string][]string)
	parts := make([]string, 0, len(devs))
	for _, d := range devs {
		mac := strings.ToLower(d.MAC)
		ips := make([]string, 0, len(d.IPv4s)+len(d.IPv6s))
		for _, ip := range append(append([]string{}, d.IPv4s...), d.IPv6s...) {
			if ip == "" {
				continue
			}
			ips = append(ips, ip)
			ip2mac[ip] = mac
		}
		if len(ips) == 0 {
			continue
		}
		mac2ips[mac] = ips
		parts = append(parts, mac+"="+strings.Join(ips, ","))
	}
	sort.Strings(parts)
	sig := strings.Join(parts, "|")

	a.mu.Lock()
	if sig == a.mapSig {
		a.mu.Unlock()
		return
	}
	a.mapSig = sig
	a.ip2mac = ip2mac
	a.mac2ips = mac2ips
	a.mu.Unlock()
	a.rebuildWGTable()
}

func (a *trafficAgg) pollClash() {
	var data struct {
		Connections []struct {
			ID       string `json:"id"`
			Upload   int64  `json:"upload"`
			Download int64  `json:"download"`
			Metadata struct {
				SourceIP string `json:"sourceIP"`
			} `json:"metadata"`
		} `json:"connections"`
	}
	if err := a.getJSON(a.cfg.TrafficClashURL+"/connections", &data); err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.resetLocked()
	seen := make(map[string]bool, len(data.Connections))
	for _, c := range data.Connections {
		if c.ID == "" {
			continue
		}
		seen[c.ID] = true
		mac := a.ip2mac[c.Metadata.SourceIP]
		if mac == "" {
			continue
		}
		cur := [2]uint64{uint64(max64(c.Upload, 0)), uint64(max64(c.Download, 0))}
		old, ok := a.connLast[c.ID]
		if !ok {
			a.connLast[c.ID] = cur
			continue
		}
		du, dd := uint64(0), uint64(0)
		if cur[0] >= old[0] {
			du = cur[0] - old[0]
		} else {
			du = cur[0]
		}
		if cur[1] >= old[1] {
			dd = cur[1] - old[1]
		} else {
			dd = cur[1]
		}
		aggAdd(a.singbox, mac, "up", du)
		aggAdd(a.singbox, mac, "down", dd)
		a.connLast[c.ID] = cur
	}
	for id := range a.connLast {
		if !seen[id] {
			delete(a.connLast, id)
		}
	}
}

func max64(v, floor int64) int64 {
	if v < floor {
		return floor
	}
	return v
}

func (a *trafficAgg) pollWG() {
	if a.nft == "" {
		return
	}
	out, err := exec.Command(a.nft, "-j", "list", "table", "inet", a.cfg.TrafficAccountTable).Output()
	if err != nil {
		return
	}
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Comment string `json:"comment"`
				Expr    []struct {
					Counter *struct {
						Bytes uint64 `json:"bytes"`
					} `json:"counter"`
				} `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if json.Unmarshal(out, &doc) != nil {
		return
	}
	current := make(map[string]uint64)
	for _, item := range doc.Nftables {
		if item.Rule == nil || item.Rule.Comment == "" {
			continue
		}
		var total uint64
		for _, expr := range item.Rule.Expr {
			if expr.Counter != nil {
				total += expr.Counter.Bytes
			}
		}
		current[item.Rule.Comment] += total
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.resetLocked()
	for comment, value := range current {
		old := a.lastWG[comment]
		delta := uint64(0)
		if value >= old {
			delta = value - old
		} else {
			delta = value
		}
		if delta == 0 {
			continue
		}
		switch {
		case strings.HasPrefix(comment, "up6:"):
			aggAdd(a.wg, comment[4:], "up", delta)
		case strings.HasPrefix(comment, "down6:"):
			aggAdd(a.wg, comment[6:], "down", delta)
		case strings.HasPrefix(comment, "up:"):
			aggAdd(a.wg, comment[3:], "up", delta)
		case strings.HasPrefix(comment, "down:"):
			aggAdd(a.wg, comment[5:], "down", delta)
		}
	}
	a.lastWG = current
}

func (a *trafficAgg) rebuildWGTable() {
	if a.nft == "" {
		return
	}
	lan, wg := a.cfg.TrafficLanInterface, a.cfg.TrafficWGInterface
	wg4, wg6 := a.cfg.TrafficWG4CIDRs, a.cfg.TrafficWG6CIDRs
	if lan == "" || wg == "" || (len(wg4) == 0 && len(wg6) == 0) {
		log.Printf("traffic: WG accounting disabled (set traffic_lan_interface, traffic_wg_interface and traffic_wg4_cidrs/traffic_wg6_cidrs)")
		return
	}
	table := a.cfg.TrafficAccountTable

	a.mu.Lock()
	mac2ips := make(map[string][]string, len(a.mac2ips))
	for mac, ips := range a.mac2ips {
		mac2ips[mac] = append([]string{}, ips...)
	}
	a.mu.Unlock()

	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", table)
	b.WriteString(" set wg4 { type ipv4_addr; flags interval; elements = { ")
	b.WriteString(strings.Join(wg4, ", "))
	b.WriteString(" } }\n")
	b.WriteString(" set wg6 { type ipv6_addr; flags interval; elements = { ")
	b.WriteString(strings.Join(wg6, ", "))
	b.WriteString(" } }\n")
	b.WriteString(" chain forward {\n  type filter hook forward priority -10; policy accept;\n")
	macs := make([]string, 0, len(mac2ips))
	for mac := range mac2ips {
		macs = append(macs, mac)
	}
	sort.Strings(macs)
	for _, mac := range macs {
		for _, ip := range mac2ips[mac] {
			if strings.Contains(ip, ".") {
				fmt.Fprintf(&b, "  iifname \"%s\" ip saddr %s ip daddr @wg4 counter comment \"up:%s\"\n", lan, ip, mac)
				fmt.Fprintf(&b, "  iifname \"%s\" ip daddr %s counter comment \"down:%s\"\n", wg, ip, mac)
			} else {
				fmt.Fprintf(&b, "  iifname \"%s\" ip6 saddr %s ip6 daddr @wg6 counter comment \"up6:%s\"\n", lan, ip, mac)
				fmt.Fprintf(&b, "  iifname \"%s\" ip6 daddr %s counter comment \"down6:%s\"\n", wg, ip, mac)
			}
		}
	}
	b.WriteString(" }\n}\n")

	_ = exec.Command(a.nft, "delete", "table", "inet", table).Run()
	cmd := exec.Command(a.nft, "-f", "-")
	cmd.Stdin = strings.NewReader(b.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("traffic: install %s counters: %v: %s", table, err, strings.TrimSpace(string(out)))
		return
	}
	a.mu.Lock()
	a.lastWG = map[string]uint64{}
	a.mu.Unlock()
}

func (a *trafficAgg) pollRouter() {
	var tr struct {
		Records []apiRecord `json:"records"`
	}
	trafficOK := false
	if err := a.getJSON(a.cfg.TrafficRouterURL+"/api/v1/traffic?window=today&group=mac&limit=1000", &tr); err == nil {
		trafficOK = true
	}
	var lv struct {
		IntervalSeconds float64 `json:"interval_seconds"`
		Devices         []struct {
			MAC         string `json:"mac"`
			UploadBps   uint64 `json:"upload_bps"`
			DownloadBps uint64 `json:"download_bps"`
		} `json:"devices"`
	}
	liveOK := a.getJSON(a.cfg.TrafficRouterURL+"/api/v1/live", &lv) == nil

	a.mu.Lock()
	defer a.mu.Unlock()
	a.resetLocked()
	if trafficOK {
		next := make(map[string]*aggCounter, len(tr.Records))
		for _, r := range tr.Records {
			mac := strings.ToLower(r.MAC)
			if mac == "" {
				continue
			}
			next[mac] = &aggCounter{Up: r.UploadBytes, Down: r.DownloadBytes}
		}
		a.router = next
	}
	if liveOK {
		next := make(map[string]liveRate, len(lv.Devices))
		for _, d := range lv.Devices {
			mac := strings.ToLower(d.MAC)
			if mac != "" {
				next[mac] = liveRate{UploadBps: d.UploadBps, DownloadBps: d.DownloadBps}
			}
		}
		a.live = next
		a.liveInterval = lv.IntervalSeconds
	}
}

func (a *trafficAgg) getJSON(u string, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (a *trafficAgg) categories(mac string) map[string]trafficWindowStats {
	a.mu.Lock()
	r := aggCounter{}
	if c := a.router[mac]; c != nil {
		r = *c
	}
	s := aggCounter{}
	if c := a.singbox[mac]; c != nil {
		s = *c
	}
	w := aggCounter{}
	if c := a.wg[mac]; c != nil {
		w = *c
	}
	a.mu.Unlock()

	directUp := uint64(0)
	if r.Up > s.Up+w.Up {
		directUp = r.Up - s.Up - w.Up
	}
	return map[string]trafficWindowStats{
		"singbox": {Upload: s.Up, Download: s.Down, Total: s.Up + s.Down},
		"wg":      {Upload: w.Up, Download: w.Down, Total: w.Up + w.Down},
		"direct":  {Upload: directUp, Download: r.Down, Total: directUp + r.Down},
	}
}

func (a *trafficAgg) trafficRecords(mac string) []apiRecord {
	a.mu.Lock()
	router := make(map[string]aggCounter, len(a.router))
	for m, c := range a.router {
		router[m] = *c
	}
	mac2ips := make(map[string]bool, len(a.mac2ips))
	for m := range a.mac2ips {
		mac2ips[m] = true
	}
	a.mu.Unlock()

	out := make([]apiRecord, 0, len(router))
	for m := range router {
		if mac != "" && m != mac {
			continue
		}
		if !mac2ips[m] {
			continue
		}
		cats := a.categories(m)
		var up, down uint64
		for _, c := range cats {
			up += c.Upload
			down += c.Download
		}
		if up == 0 && down == 0 {
			continue
		}
		out = append(out, apiRecord{MAC: m, UploadBytes: up, DownloadBytes: down, TotalBytes: up + down})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TotalBytes > out[j].TotalBytes })
	return out
}

func (a *trafficAgg) liveResponse() map[string]any {
	a.mu.Lock()
	interval := a.liveInterval
	devices := make([]map[string]any, 0, len(a.live))
	for mac, r := range a.live {
		devices = append(devices, map[string]any{"mac": mac, "upload_bps": r.UploadBps, "download_bps": r.DownloadBps})
	}
	a.mu.Unlock()
	return map[string]any{"interval_seconds": interval, "devices": devices}
}

func (a *trafficAgg) proxyRaw(path, query string) (int, []byte, string, error) {
	key := path + "?" + query
	a.proxyMu.Lock()
	if c, ok := a.proxyCache[key]; ok && time.Since(c.at) < 30*time.Second {
		a.proxyMu.Unlock()
		return c.status, c.body, c.ctype, nil
	}
	a.proxyMu.Unlock()

	u := strings.TrimRight(a.cfg.TrafficRouterURL, "/") + path
	if query != "" {
		u += "?" + query
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, nil, "", err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, "", err
	}
	ctype := resp.Header.Get("Content-Type")
	if ctype == "" {
		ctype = "application/json"
	}
	status := resp.StatusCode
	a.proxyMu.Lock()
	a.proxyCache[key] = aggCacheEntry{at: time.Now(), status: status, body: body, ctype: ctype}
	a.proxyMu.Unlock()
	return status, body, ctype, nil
}

func (a *trafficAgg) serveSummary(w http.ResponseWriter, r *http.Request) {
	qs := r.URL.Query()
	mac := strings.ToLower(qs.Get("mac"))
	status, body, ctype, err := a.proxyRaw("/api/v1/summary", r.URL.RawQuery)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if mac != "" {
		var data map[string]any
		if json.Unmarshal(body, &data) == nil {
			cats := a.categories(mac)
			data["categories"] = cats
			windows, _ := data["windows"].(map[string]any)
			if windows == nil {
				windows = map[string]any{}
				data["windows"] = windows
			}
			today, _ := windows["today"].(map[string]any)
			if today == nil {
				today = map[string]any{}
				windows["today"] = today
			}
			var up, down uint64
			for _, c := range cats {
				up += c.Upload
				down += c.Download
			}
			today["upload_bytes"] = up
			today["download_bytes"] = down
			today["total_bytes"] = up + down
			if b, err := json.Marshal(data); err == nil {
				body = b
			}
		}
	}
	w.Header().Set("Content-Type", ctype)
	w.WriteHeader(status)
	w.Write(body)
}

func (a *trafficAgg) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz":
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	case "/api/v1/traffic":
		qs := r.URL.Query()
		window := qs.Get("window")
		if window == "" {
			window = "today"
		}
		if window == "today" {
			records := a.trafficRecords(strings.ToLower(qs.Get("mac")))
			writeJSON(w, http.StatusOK, map[string]any{
				"from": todayCST(), "limit": len(records), "offset": 0, "records": records,
			})
			return
		}
		a.proxy(w, r)
	case "/api/v1/live":
		writeJSON(w, http.StatusOK, a.liveResponse())
	case "/api/v1/summary":
		a.serveSummary(w, r)
	default:
		a.proxy(w, r)
	}
}

func (a *trafficAgg) proxy(w http.ResponseWriter, r *http.Request) {
	status, body, ctype, err := a.proxyRaw(r.URL.Path, r.URL.RawQuery)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.WriteHeader(status)
	w.Write(body)
}

func (a *trafficAgg) pollLoop(ctx context.Context) {
	lastDev := time.Time{}
	lastSave := time.Time{}
	for {
		now := time.Now()
		if now.Sub(lastDev) >= 5*time.Second {
			a.refreshDevices()
			lastDev = now
		}
		a.pollClash()
		a.pollWG()
		if now.Sub(lastSave) >= 10*time.Second {
			a.save()
			lastSave = now
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func (a *trafficAgg) routerLoop(ctx context.Context) {
	for {
		a.pollRouter()
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// Start runs the loopback traffic API until ctx is cancelled.
func (a *trafficAgg) Start(ctx context.Context) {
	a.load()
	a.refreshDevices()
	a.rebuildWGTable()
	go a.pollLoop(ctx)
	go a.routerLoop(ctx)

	srv := &http.Server{Addr: a.cfg.TrafficListen, Handler: a, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Printf("traffic aggregator listening on %s (router=%s)", a.cfg.TrafficListen, a.cfg.TrafficRouterURL)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("traffic aggregator: %v", err)
		}
	}()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	a.save()
}
