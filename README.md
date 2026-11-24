# 网络通（wlt）

基于 nftables 的局域网流量标记守护进程，带有 Web 管理界面。通过 MAC 地址识别设备，为每台设备设置 nftables 数据包标记（`meta mark`），供下游路由规则（如策略路由、WireGuard 分流）使用。

## 工作原理

```
局域网设备访问 Web UI
       │
       ▼
server.go 提取请求来源 IP
       │
       ▼ ARP/NDP 邻居表
device.go 查询 MAC 地址
       │
       ▼
nft.go 将 MAC 加入对应策略的 nftables set
       │
       ▼
nftables netdev ingress 钩子匹配 ether saddr
在数据包上打 meta mark
       │
       ▼
ip rule / WireGuard / 其他路由工具按 mark 分流
```

### 为什么用 MAC 而不用 IP

IPv6 SLAAC 隐私扩展会频繁轮换临时地址，基于 IP 的 set 需要不断更新。MAC 地址在设备整个生命周期内稳定，一次配置永久生效。

### 为什么用 netdev + ingress

`inet` 表的 `prerouting` 钩子工作在 L3，以太网头已被剥离，无法匹配 `ether saddr`。`netdev` 表的 `ingress` 钩子直接处理从网络接口进来的原始帧，可以访问完整的 L2 头部。

### 生成的 nftables 规则结构

```nft
table netdev wlt {
    set wlt_direct_mac { type ether_addr; elements = { aa:bb:cc:dd:ee:01 } }
    set wlt_proxy_mac  { type ether_addr; elements = { aa:bb:cc:dd:ee:02 } }
    set wlt_vpn_mac    { type ether_addr; }

    chain mark_traffic_br-lan {
        type filter hook ingress device "br-lan" priority -150; policy accept;
        ether saddr @wlt_direct_mac meta mark set 0x1
        ether saddr @wlt_proxy_mac  meta mark set 0x2
        ether saddr @wlt_vpn_mac    meta mark set 0x3
    }
}
```

每个 LAN 接口生成一条独立的 chain，所有 chain 共享同一组 MAC set。

---

## 目录结构

```
wlt/
├── main.go          # 入口：启动、信号处理、优雅关闭
├── config.go        # Config 结构体、配置加载与校验
├── state.go         # 设备状态持久化（JSON，原子写入）
├── device.go        # IP/MAC 解析，查询内核邻居表
├── discovery.go     # 被动邻居发现（只读 ARP/NDP，不做端口扫描）
├── nft.go           # nftables 管理：set、rule、标记操作
├── server.go        # HTTP 服务：API 与 Web UI
├── traffic.go       # 流量 API 客户端 / UI 数据模型
├── traffic_agg.go   # 内置流量聚合器（router API + Clash + 可选 WG 计数器）
├── probe/
│   ├── traffic.c    # 小型 tc/eBPF per-MAC 探针（路由器侧）
│   └── README.md    # 探针构建与部署说明
├── web/
│   └── index.html   # 内嵌 SPA（无外部依赖）
└── config.json      # 示例配置
```

---

## 配置文件

默认路径：`/etc/wlt/config.json`，可通过 `-config` 标志覆盖。

```json
{
  "listen": ":8080",
  "table_name": "wlt",
  "chain_name": "mark_traffic",
  "lan_interfaces": ["br-lan"],
  "create_table": true,
  "chain_priority": -150,
  "cleanup_on_exit": true,
  "state_path": "/var/lib/wlt/state.json",
  "admin_psk": "change-me-to-a-long-random-string",
  "traffic_api_url": "http://127.0.0.1:8081",
  "traffic_listen": "127.0.0.1:8081",
  "traffic_router_url": "http://192.168.1.1:18081",
  "traffic_clash_url": "http://127.0.0.1:9090",
  "traffic_state_path": "/var/lib/wlt/traffic-state.json",
  "traffic_lan_interface": "eth0",
  "traffic_wg_interface": "",
  "traffic_wg4_cidrs": [],
  "traffic_wg6_cidrs": [],
  "traffic_account_table": "wlt_acct",
  "discovery_interval_seconds": 60,
  "default_policy": "direct",
  "policies": [
    {"name": "direct", "mark": 1, "description": "直接连接"},
    {"name": "proxy",  "mark": 2, "description": "通过代理"},
    {"name": "vpn",    "mark": 3, "description": "通过 VPN"}
  ]
}
```

### 字段说明

| 字段 | 类型 | 说明 |
|---|---|---|
| `listen` | string | HTTP 监听地址，如 `:8080` |
| `table_name` | string | nftables 表名 |
| `chain_name` | string | chain 名称前缀，实际名称为 `{chain_name}_{接口名}` |
| `lan_interfaces` | []string | 需要挂载 ingress 钩子的 LAN 接口列表，**不能为空** |
| `create_table` | bool | 表不存在时是否自动创建 |
| `chain_priority` | int32 | chain 优先级，`-150` 在 conntrack 之前 |
| `cleanup_on_exit` | bool | 退出时清理：`create_table` 为 true 时删除整张表，否则只清空 set 元素 |
| `state_path` | string | 设备策略状态文件路径 |
| `admin_psk` | string | 管理接口使用的预共享密钥，请通过 `X-WLT-PSK` 请求头传入。为空时管理接口禁用 |
| `traffic_api_url` | string | 流量 API 地址；默认指向内置聚合器的 `http://127.0.0.1:8081`。为空时流量统计功能禁用 |
| `traffic_listen` | string | 内置聚合器监听地址，默认 `127.0.0.1:8081`（仅回环） |
| `traffic_router_url` | string | 路由器侧 traffic-count/eBPF 探针 API 地址，如 `http://192.168.1.1:18081` |
| `traffic_clash_url` | string | 本机 Clash API 地址，默认 `http://127.0.0.1:9090` |
| `traffic_state_path` | string | 内置聚合器的当日分类计数状态文件 |
| `traffic_lan_interface` | string | 统计 WG 上传的 LAN 接口；留空则关闭 nft WG 计数 |
| `traffic_wg_interface` | string | WireGuard 接口；与 `traffic_wg4_cidrs`/`traffic_wg6_cidrs` 一起启用 WG 分类 |
| `traffic_wg4_cidrs` | []string | WG IPv4 目的网段（例如 `192.168.59.0/24`）；不在代码中写死 |
| `traffic_wg6_cidrs` | []string | WG IPv6 目的网段 |
| `traffic_account_table` | string | WG 计数 nftables 表名，默认 `wlt_acct` |
| `discovery_interval_seconds` | int | 被动邻居发现间隔，默认 60 秒；只读邻居表，不主动扫描 |
| `default_policy` | string | 新设备首次访问或被动发现时分配的策略名 |
| `policies` | []Policy | 策略列表，见下表 |

### Policy 字段

| 字段 | 类型 | 说明 |
|---|---|---|
| `name` | string | 策略名，唯一 |
| `mark` | uint32 | nftables mark 值，非零，唯一 |
| `description` | string | 界面显示的描述文字 |

---

## 状态文件

状态保存在 `state_path` 指定的 JSON 文件中，记录每台已见设备的 MAC、IP 列表、策略和最后活跃时间。守护进程启动时自动加载并重建 nftables set，无需重新访问 Web UI。

写入使用原子 rename（先写临时文件，再移动），不会产生损坏的中间状态。

```json
{
  "devices": {
    "aa:bb:cc:dd:ee:01": {
      "mac": "aa:bb:cc:dd:ee:01",
      "ipv4s": ["192.168.1.100"],
      "ipv6s": ["2001:db8::1"],
      "policy": "vpn",
      "last_seen": "2026-03-03T12:00:00Z"
    }
  }
}
```

---

## HTTP API

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/` | Web 管理界面（内嵌 HTML） |

设备识别完全自动：服务端从 `RemoteAddr` 提取 IP，查询内核 ARP/NDP 邻居表得到 MAC，不需要客户端提供任何标识信息。

### 公开自助接口

以下接口始终基于当前请求来源 IP 识别设备，不需要认证，适合设备自助查看和切换自己的策略。

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/api/device` | 返回当前请求设备的信息和策略 |
| `GET` | `/api/policies` | 返回所有可用策略列表 |
| `POST` | `/api/policy` | 为当前请求设备设置策略 |

### GET /api/device

响应示例：

```json
{
  "source_ip": "192.168.1.100",
  "mac": "aa:bb:cc:dd:ee:01",
  "ipv4s": ["192.168.1.100"],
  "ipv6s": ["2001:db8::1"],
  "policy": "vpn"
}
```

首次访问的新设备会自动分配 `default_policy` 并写入 nftables set。

### POST /api/policy

请求体：

```json
{"policy": "proxy"}
```

响应：同 `/api/device`，包含更新后的策略。

### 管理接口

以下接口用于远程管理指定设备，要求请求头携带 `X-WLT-PSK`。当 `admin_psk` 为空字符串时，这些接口不会启用。

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/api/admin/device?ip=...` | 按 IP 查询指定设备的信息和策略 |
| `POST` | `/api/admin/policy` | 为指定设备设置策略 |
| `GET` | `/api/admin/traffic?ip=...` | 按 IP 查询指定设备的流量统计 |
| `GET` | `/api/admin/topk-traffic?window=...&k=10` | 流量排行（window：today/yesterday/7days/30days/month/lastmonth） |
| `GET` | `/api/admin/devices` | 所有已知设备及其策略、今日流量、实时速率 |

### 流量统计接口

流量统计由 wlt 内置聚合器提供（默认 `traffic_api_url` 指向 `http://127.0.0.1:8081`）；路由器侧 eBPF 探针通过 `traffic_router_url` 接入，详见下文。

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/api/traffic` | 返回当前设备的流量统计（今日/本周/本月） |

#### GET /api/traffic

```json
{
  "available": true,
  "today": {"upload": 3259414, "download": 30261558, "total": 33520972},
  "yesterday": {"upload": 0, "download": 0, "total": 0},
  "week": {"upload": 3259414, "download": 30261558, "total": 33520972},
  "month": {"upload": 3259414, "download": 30261558, "total": 33520972},
  "last_month": {"upload": 0, "download": 0, "total": 0},
  "series": [{"date": "2026-11-23", "upload": 3259414, "download": 30261558}],
  "live": {"upload_bps": 113918, "download_bps": 113918},
  "timezone": "Asia/Shanghai"
}
```

- `upload`：设备发出的字节数；`download`：设备接收的字节数
- `week` 为近 7 天（含今天），`series` 为近 14 天按天数据，`live` 为最近一个采样周期的速率（字节/秒）
- traffic-count 不可用时 `available` 为 false，并在 `error` 中说明原因

查询指定 IP 的设备：

```bash
curl -H 'X-WLT-PSK: change-me-to-a-long-random-string' \
  'http://127.0.0.1:8080/api/admin/device?ip=192.168.1.100'
```

为指定 IP 设置策略：

```bash
curl -X POST 'http://127.0.0.1:8080/api/admin/policy' \
  -H 'Content-Type: application/json' \
  -H 'X-WLT-PSK: change-me-to-a-long-random-string' \
  -d '{"ip":"192.168.1.100","policy":"proxy"}'
```

错误时返回 HTTP 4xx/5xx 及 `{"error": "..."}` 消息体。

---

## 构建与运行

### 依赖

- Go 1.21+
- Linux 内核支持 nftables netdev 家族（4.2+）
- 运行需要 root 或 `CAP_NET_ADMIN`

### 构建

```bash
go build -o wlt .
```

### 运行

```bash
sudo ./wlt -config config.json
```

或使用默认路径：

```bash
sudo ./wlt
# 读取 /etc/wlt/config.json
```

### 验证

启动后检查 nftables 规则是否正确生成：

```bash
sudo nft list ruleset
```

从局域网设备打开 Web UI（`http://<路由器IP>:8080`），选择策略后验证 MAC 出现在对应 set：

```bash
sudo nft list set netdev wlt wlt_vpn_mac
```

切换策略后验证 MAC 从旧 set 移走、加入新 set。

重启守护进程后验证状态正确恢复（无需重新在 UI 中操作）。

---

## 与路由规则集成

网络通只负责打标记，实际的路由分流由系统路由规则完成。以 WireGuard 为例：

```bash
# 对 mark=3（vpn 策略）的流量走 VPN 路由表
ip rule add fwmark 3 lookup 100
ip route add default dev wg0 table 100

# 对 mark=2（proxy 策略）的流量走代理路由表
ip rule add fwmark 2 lookup 200
ip route add default via 192.168.1.1 table 200
```

由于 nftables ingress 钩子在 prerouting 之前执行，标记在路由决策前已经完成。

---

## 设备发现与流量统计（内置）

wlt 现在内置了设备发现和流量聚合，不再需要 `wlt-discover.py`、`wlt-traffic-pi.py` 或额外的流量守护进程。

### 被动设备发现

`discovery.go` 每 `discovery_interval_seconds` 秒读取一次内核 ARP/NDP 邻居表，只做只读邻居查询：

- 不发送 ARP 探测、不建立 TCP 连接、不做端口扫描；
- 新 MAC 以 `default_policy` 加入状态并同步到 nftables；
- 已有设备的策略保持不变，只合并新看到的 IP。

### 流量聚合

`traffic_agg.go` 在 wlt 进程内监听 `traffic_listen`（默认仅 `127.0.0.1:8081`）并实现原来的 traffic-count API，数据源可配置：

```
wlt Web UI :8080
      │
      ▼
内置聚合器 127.0.0.1:8081
      ├── traffic_router_url  路由器侧 eBPF/traffic-count API（每台设备的直连总量）
      ├── traffic_clash_url   本机 Clash API（sing-box 每条连接的字节数）
      └── traffic_account_table nftables WG 计数器（可选的 WG 分类）
```

分类口径与 UI 一致：`singbox`、`direct`、`wg`。`traffic_api_url` 默认指向内置聚合器，仍可覆盖为外部兼容 API。

### 小型 eBPF 探针

路由器侧提供一个小型 tc/eBPF per-MAC 探针源码：`probe/traffic.c`。它按 LAN 接口的源/目的 MAC 统计上传/下载，编译与部署说明见 `probe/README.md`。探针 API 通过 `traffic_router_url` 接入 wlt；wlt 自身不要求 clang/libbpf，普通 `go build` 即可。

### 配置要点

```json
{
  "traffic_listen": "127.0.0.1:8081",
  "traffic_router_url": "http://192.168.1.1:18081",
  "traffic_clash_url": "http://127.0.0.1:9090",
  "traffic_lan_interface": "eth0",
  "traffic_wg_interface": "",
  "traffic_wg4_cidrs": [],
  "traffic_wg6_cidrs": [],
  "traffic_account_table": "wlt_acct",
  "discovery_interval_seconds": 60
}
```

接口名、网段、表名全部来自配置，代码中不写死具体 WireGuard 名称或网段。`traffic_wg_interface` 为空时不启用 WG 计数器。

### 注意事项

- 内置聚合器只监听回环地址；不要暴露到 LAN。
- 路由器侧 eBPF 探针仍需能看到 LAN 的原始 MAC（通常部署在路由器/LAN 网桥上）。
- 设备发现是**被动**的：完全空闲且从未在邻居表中出现过的设备不会被主动探测出来；这是为了不做端口扫描。

---

## 注意事项

- 守护进程必须与 Web UI 访问者处于**同一个二层网络**（同一广播域），否则无法通过邻居表查到访问设备的 MAC。
- 若 `lan_interfaces` 中的接口暂不存在，会跳过该接口并在其出现后自动创建 chain，不影响其他接口。

## 规则自愈

wlt 通过 netlink 订阅 nftables 变更与网卡变更，任何导致 wlt 表偏离期望状态的操作（`nft flush ruleset` 后重新 `nft -f /etc/nftables.conf`、手动删除规则/元素、`flush set`、LAN 网桥被删除重建等）都会在约 0.3 秒内被修复，且**会从状态文件恢复所有设备 MAC**。修复以单个原子事务提交；没有偏差时不做任何写入。另有每分钟一次的兜底检查。
- `chain_priority: -150` 早于 conntrack（优先级 -100），适合大多数场景。如与其他防火墙规则冲突可调整。
- 状态文件中保存的 IPv4/IPv6 列表仅用于 Web UI 展示，nftables 规则只依赖 MAC，因此 IP 地址变化不影响流量标记。
