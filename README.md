# 网络通（wlt）

本项目是对中国科学技术大学（USTC）校园网「网络通」系统的复刻实现，适用于基于 Linux 的路由器/网关环境。

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
| `GET` | `/api/device` | 返回当前请求设备的信息和策略 |
| `GET` | `/api/policies` | 返回所有可用策略列表 |
| `POST` | `/api/policy` | 为当前设备设置策略 |

设备识别完全自动：服务端从 `RemoteAddr` 提取 IP，查询内核 ARP/NDP 邻居表得到 MAC，不需要客户端提供任何标识信息。

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

## 注意事项

- 守护进程必须与 Web UI 访问者处于**同一个二层网络**（同一广播域），否则无法通过邻居表查到访问设备的 MAC。
- 若 `lan_interfaces` 中的接口不存在，nftables 创建 chain 时会报错，进程启动失败。
- `chain_priority: -150` 早于 conntrack（优先级 -100），适合大多数场景。如与其他防火墙规则冲突可调整。
- 状态文件中保存的 IPv4/IPv6 列表仅用于 Web UI 展示，nftables 规则只依赖 MAC，因此 IP 地址变化不影响流量标记。
