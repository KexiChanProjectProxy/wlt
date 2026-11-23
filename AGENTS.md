# AGENTS.md - Development Workflow

## Project Overview

**wlt** is a nftables-based LAN traffic marking daemon with a web UI. It identifies devices by MAC address and sets nftables packet marks (`meta mark`) for policy routing.

## Key Files

| File | Purpose |
|------|---------|
| `main.go` | Entry point, signal handling, graceful shutdown |
| `config.go` | Config struct and loading |
| `nft.go` | NFTManager for nftables set/rule management |
| `reconcile.go` | Event-driven reconciler + nft monitor watcher |
| `state.go` | Device state persistence |
| `device.go` | IP/MAC resolution via ARP/NDP neighbor table |
| `server.go` | HTTP API + Web UI |
| `web/index.html` | Embedded SPA |

## Architecture

### nftables Structure

```
table netdev wlt {
    set wlt_{policy}_mac { type ether_addr; }
    chain mark_traffic_{iface} {
        type filter hook ingress device "{iface}" priority -150;
        ether saddr @wlt_{policy}_mac meta mark set {mark}
    }
}
```

### Reconciliation Flow

`NFTManager.Sync()` (nft.go) is the single source of truth: it compares the
kernel with config + `state.json` (table, one ingress chain per existing LAN
interface, one MAC set per policy **including its elements**, one rule per
policy tagged `wlt:v2:<policy>:<mark>`) and applies only the difference in one
atomic batch. With no drift it sends nothing.

`Reconciler` (reconcile.go) calls `Sync()`:

1. on nftables netlink notifications (google/nftables `AddGenerationalMonitor`,
   no `nft` binary) that touch the wlt table, delete a table, or change set
   elements — this covers `nft flush ruleset` + `nft -f nftables.conf`;
2. on RTM_NEWLINK/DELLINK for a LAN interface (netdev chains die with their device);
3. every minute as a fallback, and after a monitor re-subscribe.

Triggers are debounced (300 ms). Policy changes write `state` first, then call
`SetDevicePolicy`, so a concurrent `Sync` never reverts them.

Kernel tests (root, own netns): `go test -c -o /tmp/wlt.test . && sudo unshare -n env WLT_NFT_KERNEL_TEST=1 /tmp/wlt.test -test.run Kernel -test.v`

## Common Tasks

### Build

```bash
go build -o wlt .
```

### Run

```bash
sudo ./wlt -config /etc/wlt/config.json
```

### Test

```bash
go test ./...
```

### Release (CI/CD)

**Prerequisites**: All changes must be committed and pushed to `main` branch first.

```bash
# 1. Commit changes
git add <files>
git commit -m "description"

# 2. Push to origin
git push origin main

# 3. Tag and push (triggers GitHub Actions: test → build → release)
git tag -a vX.Y.Z -m "release message"
git push origin vX.Y.Z
```

**Workflow**: test → build (amd64, arm64) → create GitHub release with binaries

**Artifacts**: `dist/wlt-linux-amd64`, `dist/wlt-linux-arm64` attached to GitHub release

### Release Workflow (GitHub Actions)

See `.github/workflows/release.yml`:

- Runs on: `push tags v*`
- Jobs: test → build (amd64, arm64) → release
- Artifacts uploaded to GitHub release

## Debugging

### Check nftables rules

```bash
sudo nft list ruleset
sudo nft list set netdev wlt wlt_*
```

### Check wlt logs

```bash
# If running via systemd
journalctl -u wlt -f

# Or run directly with output
sudo ./wlt 2>&1
```

### Watch nft events

```bash
sudo nft monitor json
```

## Common Issues

### Table not rebuilt after `nft flush ruleset` (pre-v0.6.0)

The old watcher matched text such as "add table" against `nft monitor json`
output, which never contains it, and the rebuild never restored set elements.
Replaced by the netlink monitor + `Sync()` described above.
