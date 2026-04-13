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

1. `nft monitor json` runs as subprocess watching for changes
2. On detected events (add/delete table/chain/set/rule), triggers `Reconcile()`
3. `Reconcile()` ensures table, chains, sets, and rules exist (creates if missing)
4. Periodic fallback every 5 minutes for edge cases

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

1. Push a tag matching `v*` to trigger GitHub Actions
2. Workflow: test → build (amd64, arm64) → create GitHub release with binaries
3. Binaries: `dist/wlt-linux-amd64`, `dist/wlt-linux-arm64`

```bash
# Create and push release
git tag -a vX.Y.Z -m "release message"
git push origin vX.Y.Z
```

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

### nftables watcher not detecting external clears

Fixed in v0.5.0: The reconciler now uses `nft monitor` for event-driven detection instead of polling.

### Chain snapshot staleness (pre-v0.5.0 bug)

When reconciler created new chains, the subsequent rule-check loop used a stale chain list snapshot. Fixed by re-fetching chains after flush.

### Table re-fetch condition was broken (pre-v0.5.0)

Condition `t == nil` inside a `for _, t := range tables` loop was never true. Fixed by properly re-listing tables.
