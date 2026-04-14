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
├── nft.go           # nftables 管理：set、rule、标记操作
├── server.go        # HTTP 服务：API 与 Web UI
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
| `cleanup_on_exit` | bool | 退出时是否清空 set 元素（恢复无标记状态） |
| `state_path` | string | 设备策略状态文件路径 |
| `admin_psk` | string | 管理接口使用的预共享密钥，请通过 `X-WLT-PSK` 请求头传入。为空时管理接口禁用 |
| `traffic_api_url` | string | traffic-count 服务 API 地址（用于流量统计展示），如 `http://127.0.0.1:8081`。为空时流量统计功能禁用 |
| `default_policy` | string | 新设备首次访问时自动分配的策略名 |
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
| `GET` | `/api/admin/topk-traffic?window=...` | 查询流量排行最高的 K 个设备 |

### 流量统计接口

启用流量统计需要部署 [wlt-traffic](https://github.com/KexiChanProjectProxy/wlt-traffic) 服务，并在配置中设置 `traffic_api_url`。

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/api/traffic` | 返回当前设备的流量统计（今日/本周/本月） |

#### GET /api/traffic

响应示例：

```json
{
  "today": {"upload": 1234567, "download": 9876543, "total": 11111110},
  "week": {"upload": 8765432, "download": 6543210, "total": 15308642},
  "month": {"upload": 34567890, "download": 23456789, "total": 58024679}
}
```

字段说明：
- `upload`：出站字节数（从设备发出）
- `download`：入站字节数（设备接收）
- `total`：合计字节数

当 `traffic_api_url` 为空或 traffic-count 服务不可用时，返回全零数据。

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

## 流量统计（可选）

wlt 支持通过集成 [wlt-traffic](https://github.com/KexiChanProjectProxy/wlt-traffic) 服务显示设备流量使用情况。

### 架构

```
wlt Web UI (port 8080)
       │
       │ /api/traffic
       ▼
wlt server.go ──────► wlt-traffic API (127.0.0.1:8081)
                            │
                            ▼
                       SQLite 数据库
                       (/var/lib/traffic-count/traffic-count.db)
```

wlt 本身不采集流量数据，只是代理到 wlt-traffic 服务查询，并以 MB/GB 等人类可读格式在 Web UI 中展示。

### 部署 wlt-traffic

参考 [wlt-traffic 文档](https://github.com/KexiChanProjectProxy/wlt-traffic)。

### 配置 wlt

在 wlt 的 `config.json` 中添加 `traffic_api_url`：

```json
{
  "listen": ":8080",
  "traffic_api_url": "http://127.0.0.1:8081",
  ...
}
```

wlt 会将请求转发到 wlt-traffic 的 `GET /api/v1/traffic` 接口，按 MAC 聚合今日/本周/本月的入站/出站流量。

### 注意事项

- wlt-traffic 必须与 wlt 部署在同一台机器上（仅监听 localhost）
- wlt 对 traffic-count API 调用有 5 秒超时，服务不可用时 Web UI 显示为零而不报错
- wlt 不管理 wlt-traffic 的生命周期，需要独立部署和运维

---

## 注意事项

- 守护进程必须与 Web UI 访问者处于**同一个二层网络**（同一广播域），否则无法通过邻居表查到访问设备的 MAC。
- 若 `lan_interfaces` 中的接口不存在，nftables 创建 chain 时会报错，进程启动失败。
- `chain_priority: -150` 早于 conntrack（优先级 -100），适合大多数场景。如与其他防火墙规则冲突可调整。
- 状态文件中保存的 IPv4/IPv6 列表仅用于 Web UI 展示，nftables 规则只依赖 MAC，因此 IP 地址变化不影响流量标记。
