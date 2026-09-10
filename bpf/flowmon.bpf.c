#include "flow_stats.h"

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define SMALL_PACKET_BYTES 300
#define LARGE_PACKET_BYTES 1000
#define MAX_FLOWS 8192

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
} flow_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow_policy);
} flow_policy_map SEC(".maps");

static __always_inline int parse_ports(void *data_end, struct iphdr *iph, struct flow_key *key)
{
    void *l4 = (void *)iph + (iph->ihl * 4);

    if (key->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        if ((void *)(tcp + 1) > data_end) {
            return -1;
        }
        key->src_port = tcp->source;
        key->dst_port = tcp->dest;
        return 0;
    }

    if (key->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end) {
            return -1;
        }
        key->src_port = udp->source;
        key->dst_port = udp->dest;
        return 0;
    }

    return -1;
}

SEC("tc")
int flowmon_tc(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct flow_key key = {};
    struct flow_stats *stats;
    struct flow_policy *policy;
    struct flow_stats initial = {};
    __u64 now = bpf_ktime_get_ns();
    __u64 len = skb->len;

    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_UNSPEC;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_UNSPEC;
    }

    iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return TC_ACT_UNSPEC;
    }

    key.src_ip = iph->saddr;
    key.dst_ip = iph->daddr;
    key.protocol = iph->protocol;

    if (parse_ports(data_end, iph, &key) < 0) {
        return TC_ACT_UNSPEC;
    }

    policy = bpf_map_lookup_elem(&flow_policy_map, &key);
    if (policy && policy->class_id) {
        skb->priority = policy->class_id;
    }

    stats = bpf_map_lookup_elem(&flow_stats_map, &key);
    if (!stats) {
        initial.first_seen_ns = now;
        initial.last_seen_ns = now;
        bpf_map_update_elem(&flow_stats_map, &key, &initial, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&flow_stats_map, &key);
        if (!stats) {
            return TC_ACT_UNSPEC;
        }
    }

    __sync_fetch_and_add(&stats->packets, 1);
    __sync_fetch_and_add(&stats->bytes, len);
    if (len <= SMALL_PACKET_BYTES) {
        __sync_fetch_and_add(&stats->small_packets, 1);
    }
    if (len >= LARGE_PACKET_BYTES) {
        __sync_fetch_and_add(&stats->large_packets, 1);
    }
    stats->last_seen_ns = now;

    return TC_ACT_UNSPEC;
}

char LICENSE[] SEC("license") = "GPL";
