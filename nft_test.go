package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
)

func TestDiffElements(t *testing.T) {
	a, _ := net.ParseMAC("aa:00:00:00:00:01")
	b, _ := net.ParseMAC("aa:00:00:00:00:02")
	c, _ := net.ParseMAC("aa:00:00:00:00:03")
	add, del := diffElements([]net.HardwareAddr{a, b}, []nftables.SetElement{{Key: b}, {Key: c}})
	if len(add) != 1 || string(add[0].Key) != string(a) || len(del) != 1 || string(del[0].Key) != string(c) {
		t.Fatalf("add=%v del=%v", add, del)
	}
}

func TestDesiredFromStateFallsBackToDefaultPolicy(t *testing.T) {
	cfg := testKernelConfig()
	st := NewState()
	st.Set(&DeviceState{MAC: "aa:00:00:00:00:01", Policy: "proxy"})
	st.Set(&DeviceState{MAC: "aa:00:00:00:00:02", Policy: "removed-policy"})
	st.Set(&DeviceState{MAC: "garbage", Policy: "proxy"})
	got := DesiredFromState(cfg, st)()
	if len(got["proxy"]) != 1 || len(got["direct"]) != 1 {
		t.Fatalf("got %v", got)
	}
}

func TestRelevantNFTEvent(t *testing.T) {
	r := NewReconciler(testKernelConfig(), nil)
	ours := &nftables.Table{Name: "wlttest"}
	other := &nftables.Table{Name: "fw4"}
	cases := []struct {
		ev   *nftables.MonitorEvent
		want bool
	}{
		{&nftables.MonitorEvent{Type: nftables.MonitorEventTypeDelTable, Data: ours}, true},
		{&nftables.MonitorEvent{Type: nftables.MonitorEventTypeDelTable, Data: other}, false},
		{&nftables.MonitorEvent{Type: nftables.MonitorEventTypeDelRule, Data: &nftables.Rule{Table: ours}}, true},
		{&nftables.MonitorEvent{Type: nftables.MonitorEventTypeNewChain, Data: &nftables.Chain{Table: other}}, false},
		{&nftables.MonitorEvent{Type: nftables.MonitorEventTypeDelSetElem}, true},
		{&nftables.MonitorEvent{Type: nftables.MonitorEventTypeNewObj}, false},
	}
	for i, c := range cases {
		if got := r.relevantNFTEvent(c.ev); got != c.want {
			t.Errorf("case %d: got %v want %v", i, got, c.want)
		}
	}
}

// ---- real kernel tests ----
//
// WLT_NFT_KERNEL_TEST=1 runs them against the kernel. They create a veth
// pair and flush the whole ruleset, so only run them as root inside a
// throw-away network namespace:
//
//	sudo unshare -n env WLT_NFT_KERNEL_TEST=1 go test -run Kernel ./...

func testKernelConfig() *Config {
	return &Config{
		TableName:     "wlttest",
		ChainName:     "mark",
		LanInterfaces: []string{"wltlan0", "wltlan1"},
		CreateTable:   true,
		ChainPriority: -150,
		DefaultPolicy: "direct",
		Policies:      []Policy{{Name: "direct", Mark: 1}, {Name: "proxy", Mark: 2}},
	}
}

func requireKernel(t *testing.T) {
	t.Helper()
	if os.Getenv("WLT_NFT_KERNEL_TEST") != "1" {
		t.Skip("set WLT_NFT_KERNEL_TEST=1 (root, own netns) to run")
	}
}

func sh(t *testing.T, cmd string) string {
	t.Helper()
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", cmd, err, out)
	}
	return string(out)
}

// snapshot summarises the wlt table as "chain:rule-count" and "set:elements".
func snapshot(t *testing.T) map[string]string {
	t.Helper()
	out, err := exec.Command("nft", "-j", "list", "table", "netdev", "wlttest").Output()
	if err != nil {
		return map[string]string{}
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	res := map[string]string{}
	rules := map[string]int{}
	for _, obj := range doc.Nftables {
		if raw, ok := obj["chain"]; ok {
			var c struct {
				Name string `json:"name"`
				Dev  any    `json:"dev"`
			}
			json.Unmarshal(raw, &c)
			rules[c.Name] += 0
		}
		if raw, ok := obj["rule"]; ok {
			var r struct {
				Chain string `json:"chain"`
			}
			json.Unmarshal(raw, &r)
			rules[r.Chain]++
		}
		if raw, ok := obj["set"]; ok {
			var s struct {
				Name string `json:"name"`
				Elem []any  `json:"elem"`
			}
			json.Unmarshal(raw, &s)
			var es []string
			for _, e := range s.Elem {
				if str, ok := e.(string); ok {
					es = append(es, str)
				}
			}
			res["set:"+s.Name] = strings.Join(es, ",")
		}
	}
	for c, n := range rules {
		res["chain:"+c] = strings.Repeat("r", n)
	}
	return res
}

func wantFull(t *testing.T, got map[string]string, direct, proxy string) {
	t.Helper()
	want := map[string]string{
		"chain:mark_wltlan0": "rr",
		"chain:mark_wltlan1": "rr",
		"set:wlt_direct_mac": direct,
		"set:wlt_proxy_mac":  proxy,
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s = %q, want %q (full: %v)", k, got[k], v, got)
		}
	}
}

func setupKernel(t *testing.T) (*Config, *State, *NFTManager) {
	t.Helper()
	requireKernel(t)
	sh(t, "ip link add wltlan0 type veth peer name wltpeer0 && ip link add wltlan1 type veth peer name wltpeer1")
	t.Cleanup(func() {
		exec.Command("sh", "-c", "ip link del wltlan0; ip link del wltlan1; nft delete table netdev wlttest").Run()
	})
	cfg := testKernelConfig()
	st := NewState()
	st.Set(&DeviceState{MAC: "aa:00:00:00:00:01", Policy: "direct"})
	st.Set(&DeviceState{MAC: "aa:00:00:00:00:02", Policy: "proxy"})
	m := NewNFTManager(cfg, DesiredFromState(cfg, st))
	m.logf = t.Logf
	return cfg, st, m
}

func TestKernelSyncRebuildsAfterFlushRuleset(t *testing.T) {
	_, st, m := setupKernel(t)

	res, err := m.Sync()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Changes) == 0 {
		t.Fatal("first sync made no changes")
	}
	wantFull(t, snapshot(t), "aa:00:00:00:00:01", "aa:00:00:00:00:02")

	// Idempotent: nothing to do the second time.
	if res, err := m.Sync(); err != nil || len(res.Changes) != 0 {
		t.Fatalf("second sync: %v %v", res.Changes, err)
	}

	// `nft flush ruleset` + re-apply of an unrelated config.
	sh(t, `nft flush ruleset && nft -f - <<'EOF'
table inet filter {
	chain input {
		type filter hook input priority 0; policy accept;
	}
}
EOF`)
	if len(snapshot(t)) != 0 {
		t.Fatal("flush did not remove the table")
	}
	if _, err := m.Sync(); err != nil {
		t.Fatal(err)
	}
	wantFull(t, snapshot(t), "aa:00:00:00:00:01", "aa:00:00:00:00:02")
	if !strings.Contains(sh(t, "nft list tables"), "inet filter") {
		t.Fatal("foreign table was touched")
	}

	// Partial drift: a rule deleted, an element removed, a foreign element added.
	sh(t, `h=$(nft -a list chain netdev wlttest mark_wltlan0 | awk '/wlt_proxy_mac/{print $NF; exit}'); nft delete rule netdev wlttest mark_wltlan0 handle $h`)
	sh(t, "nft delete element netdev wlttest wlt_direct_mac '{ aa:00:00:00:00:01 }'")
	sh(t, "nft add element netdev wlttest wlt_proxy_mac '{ aa:00:00:00:00:09 }'")
	if _, err := m.Sync(); err != nil {
		t.Fatal(err)
	}
	wantFull(t, snapshot(t), "aa:00:00:00:00:01", "aa:00:00:00:00:02")

	// Policy change, including when the MAC is missing from its old set.
	mac, _ := net.ParseMAC("aa:00:00:00:00:01")
	sh(t, "nft delete element netdev wlttest wlt_direct_mac '{ aa:00:00:00:00:01 }'")
	st.Set(&DeviceState{MAC: "aa:00:00:00:00:01", Policy: "proxy"})
	if err := m.SetDevicePolicy(mac, "direct", "proxy"); err != nil {
		t.Fatal(err)
	}
	wantFull(t, snapshot(t), "", "aa:00:00:00:00:01,aa:00:00:00:00:02")

	// A changed mark replaces the rule.
	m.cfg.Policies[1].Mark = 7
	if _, err := m.Sync(); err != nil {
		t.Fatal(err)
	}
	if out := sh(t, "nft list chain netdev wlttest mark_wltlan1"); !strings.Contains(out, "0x00000007") || strings.Contains(out, "0x00000002") {
		t.Fatalf("mark not updated:\n%s", out)
	}
}

func TestKernelMissingInterfaceDoesNotBlockOthers(t *testing.T) {
	_, _, m := setupKernel(t)
	sh(t, "ip link del wltlan1")
	res, err := m.Sync()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.MissingIfaces) != 1 || res.MissingIfaces[0] != "wltlan1" {
		t.Fatalf("missing = %v", res.MissingIfaces)
	}
	if snap := snapshot(t); snap["chain:mark_wltlan0"] != "rr" {
		t.Fatalf("wltlan0 chain not created: %v", snap)
	}
}

func TestKernelReconcilerRepairsWithoutPolling(t *testing.T) {
	cfg, _, m := setupKernel(t)
	r := NewReconciler(cfg, m)
	r.interval = time.Hour // only events may repair
	r.logf = t.Logf
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Start(ctx)

	waitFor := func(what string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			s := snapshot(t)
			if s["chain:mark_wltlan0"] == "rr" && s["chain:mark_wltlan1"] == "rr" && s["set:wlt_proxy_mac"] == "aa:00:00:00:00:02" {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("%s: not repaired: %v", what, snapshot(t))
	}
	waitFor("startup")

	sh(t, "nft flush ruleset")
	waitFor("after flush ruleset")

	sh(t, "nft flush set netdev wlttest wlt_proxy_mac")
	waitFor("after set flush")

	// Interface deleted and re-created: its netdev chain goes away with it.
	sh(t, "ip link del wltlan1 && ip link add wltlan1 type veth peer name wltpeer1")
	waitFor("after interface re-creation")
}
