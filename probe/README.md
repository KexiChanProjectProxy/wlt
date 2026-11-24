# 小型 tc/eBPF 流量探针

`traffic.c` 是一个很小的 tc/eBPF 探针，用于在**能看到 LAN 原始 MAC** 的接口上按
设备（对端 MAC）统计上行/下行字节数和包数。它不修改报文去向，只更新一个
per-CPU LRU hash，用户态按秒读取即可。

它来自 [wlt-traffic](https://github.com/KexiChanProjectProxy/wlt-traffic) 的
`bpf/traffic.c`，在 wlt 仓库中作为路由器侧探针源码保留。wlt 的 Pi/主机进程只
消费探针的 HTTP API，通过 `traffic_router_url` 配置，不要求本机安装 clang。

## 计数口径

| 挂载点 | 报文 | 设备 MAC | 计入 |
|---|---|---|---|
| LAN 接口 ingress | 设备 → 路由器 | 以太网源 MAC | upload |
| LAN 接口 egress | 路由器 → 设备 | 以太网目的 MAC | download |

组播/广播帧不归属任何设备；`skb->len` 为 L2 字节；GSO 包按 `gso_segs` 计包。
程序返回 `TC_ACT_UNSPEC`，不会吞掉后续 tc/tcx 程序。

## 编译

需要 clang、libbpf 头文件和内核头文件：

```sh
clang -O2 -g -target bpf \
  -I/usr/include/$(uname -m)-linux-gnu \
  -c traffic.c -o traffic.o
```

推荐直接用 wlt-traffic 项目的 `bpf2go` 生成器和加载器（它同时负责 TCX/clsact
挂载、接口重建后重挂、API 与 SQLite 存储）：

```sh
git clone https://github.com/KexiChanProjectProxy/wlt-traffic
cd wlt-traffic
make generate   # 只在修改 traffic.c 后需要
make build
```

## 与 wlt 集成

1. 路由器侧运行 traffic-count/wlt-traffic，监听 `127.0.0.1:8081`，通过 nginx
   或端口映射暴露为 `http://<router>:18081`。
2. wlt 配置：

```json
{
  "traffic_router_url": "http://192.168.1.1:18081",
  "traffic_lan_interface": "br-lan",
  "traffic_wg_interface": "wg0",
  "traffic_wg4_cidrs": ["192.168.59.0/24"],
  "traffic_wg6_cidrs": ["2001:db8::/32"],
  "traffic_account_table": "wlt_acct"
}
```

3. wlt 内置聚合器会合并路由器 per-MAC 总量、Clash API 的 sing-box 字节和 nft WG
   计数器，生成 `singbox` / `direct` / `wg` 分类。

接口名和网段全部来自配置；源码中没有写死 `nyist`、`eth0` 或特定网段。
