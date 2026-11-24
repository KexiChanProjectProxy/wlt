// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
//
// Per-device (per peer MAC) traffic accounting on a LAN-facing interface.
//
// Direction is defined from the LAN device's point of view:
//
//   tc ingress on the LAN interface = frames the device sent to us
//       -> peer MAC is the Ethernet SOURCE      -> counted as "upload"
//   tc egress on the LAN interface  = frames we send to the device
//       -> peer MAC is the Ethernet DESTINATION -> counted as "download"
//
// Frames whose peer MAC is multicast/broadcast are not attributable to one
// device and are not counted.
//
// The programs never change the packet's fate: they return TC_ACT_UNSPEC
// (== TCX_NEXT), so later TCX programs and legacy tc filters (e.g. an SQM/ifb
// redirect) still run. Returning TC_ACT_OK (== TCX_PASS) would skip them.
//
// The program uses only the stable __sk_buff context, so the object does not
// need CO-RE/BTF relocations and runs on any kernel with TCX (>= 6.6) or
// legacy cls_bpf/clsact.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

struct traffic_key {
    __u32 ifindex;
    __u8  mac[6];
    __u16 pad; // always zero; keeps the key free of uninitialised padding
};

// Per-CPU values: no atomics, no lost updates, summed in user space.
struct traffic_value {
    __u64 up_bytes;
    __u64 up_packets;
    __u64 down_bytes;
    __u64 down_packets;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, struct traffic_key);
    __type(value, struct traffic_value);
    __uint(max_entries, 16384);
} traffic_map SEC(".maps");

static __always_inline int account(struct __sk_buff *skb, int upload)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_UNSPEC;

    const __u8 *peer = upload ? eth->h_source : eth->h_dest;
    if (peer[0] & 0x01) // multicast or broadcast
        return TC_ACT_UNSPEC;

    struct traffic_key key;
    __builtin_memset(&key, 0, sizeof(key));
    key.ifindex = skb->ifindex;
    __builtin_memcpy(key.mac, peer, ETH_ALEN);

    __u64 bytes = skb->len;
    __u64 pkts = skb->gso_segs > 1 ? skb->gso_segs : 1;

    struct traffic_value *v = bpf_map_lookup_elem(&traffic_map, &key);
    if (!v) {
        struct traffic_value init;
        __builtin_memset(&init, 0, sizeof(init));
        // NOEXIST: if another CPU created the entry first, keep it.
        bpf_map_update_elem(&traffic_map, &key, &init, BPF_NOEXIST);
        v = bpf_map_lookup_elem(&traffic_map, &key);
        if (!v)
            return TC_ACT_UNSPEC;
    }

    if (upload) {
        v->up_bytes += bytes;
        v->up_packets += pkts;
    } else {
        v->down_bytes += bytes;
        v->down_packets += pkts;
    }
    return TC_ACT_UNSPEC;
}

SEC("tc")
int count_ingress(struct __sk_buff *skb)
{
    return account(skb, 1);
}

SEC("tc")
int count_egress(struct __sk_buff *skb)
{
    return account(skb, 0);
}

char __license[] SEC("license") = "Dual BSD/GPL";
