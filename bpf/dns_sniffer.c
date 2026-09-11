// CO-RE DNS sniffer (TC egress)

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>

#define ETH_P_IP 0x0800
#define IPPROTO_UDP 17
#define DNS_PORT 53

struct dns_key {
    __u32 ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct dns_key);
    __type(value, __u64);
} dns_map SEC(".maps");

static __always_inline int parse_packet(void *data, void *data_end, struct dns_key *key, __u16 *dport)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    if (ip->protocol != IPPROTO_UDP)
        return -1;

    struct udphdr *udp = (void *)ip + ip->ihl * 4;
    if ((void *)(udp + 1) > data_end)
        return -1;

    *dport = bpf_ntohs(udp->dest);
    key->ip = ip->daddr;

    return 0;
}

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct dns_key key = {};
    __u16 dport = 0;

    if (parse_packet(data, data_end, &key, &dport) < 0)
        return TC_ACT_OK;

    if (dport != DNS_PORT)
        return TC_ACT_OK;

    __u64 *val = bpf_map_lookup_elem(&dns_map, &key);
    if (val)
        __sync_fetch_and_add(val, 1);
    else {
        __u64 init = 1;
        bpf_map_update_elem(&dns_map, &key, &init, BPF_ANY);
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";