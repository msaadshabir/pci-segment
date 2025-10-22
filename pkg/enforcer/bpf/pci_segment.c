// SPDX-License-Identifier: MIT
// PCI-DSS Network Segmentation eBPF Program
// Implements packet filtering for Requirements 1.2 and 1.3

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Maximum number of policy rules
#define MAX_RULES 1024

// Action types
#define ACTION_ALLOW 0
#define ACTION_DENY 1

// Protocol types
#define PROTO_TCP 6
#define PROTO_UDP 17
#define PROTO_ICMP 1

// Policy rule structure (must match Go struct)
struct policy_rule
{
    __u32 src_ip;       // Source IP (network byte order)
    __u32 src_mask;     // Source netmask
    __u32 dst_ip;       // Destination IP
    __u32 dst_mask;     // Destination netmask
    __u16 dst_port_min; // Destination port range start
    __u16 dst_port_max; // Destination port range end
    __u8 protocol;      // TCP/UDP/ICMP (0 = any)
    __u8 action;        // ALLOW or DENY
    __u16 _pad;         // Padding for alignment
};

// Event structure for logging
struct enforcement_event
{
    __u64 timestamp; // Nanoseconds since boot
    __u32 src_ip;
    __u32 dst_ip;
    __u16 dst_port;
    __u8 protocol;
    __u8 action;
    __u32 rule_id;
};

// BPF Maps
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct policy_rule);
    __uint(max_entries, MAX_RULES);
} ingress_rules SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct policy_rule);
    __uint(max_entries, MAX_RULES);
} egress_rules SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB ring buffer
} events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 4);
} stats SEC(".maps");

// Stats counters
#define STAT_PACKETS_ALLOWED 0
#define STAT_PACKETS_BLOCKED 1
#define STAT_PACKETS_TOTAL 2
#define STAT_BYTES_TOTAL 3

// Helper to check if IP matches CIDR
static __always_inline int ip_matches(__u32 ip, __u32 cidr_ip, __u32 cidr_mask)
{
    return (ip & cidr_mask) == (cidr_ip & cidr_mask);
}

// Helper to check if port is in range
static __always_inline int port_in_range(__u16 port, __u16 min, __u16 max)
{
    if (min == 0 && max == 0)
    {
        return 1; // Any port
    }
    return port >= min && port <= max;
}

// Helper to increment stats counter
static __always_inline void inc_stat(__u32 key, __u64 delta)
{
    __u64 *value = bpf_map_lookup_elem(&stats, &key);
    if (value)
    {
        __sync_fetch_and_add(value, delta);
    }
}

// Log enforcement event to ring buffer
static __always_inline void log_event(
    __u32 src_ip,
    __u32 dst_ip,
    __u16 dst_port,
    __u8 protocol,
    __u8 action,
    __u32 rule_id)
{
    struct enforcement_event *evt;
    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
    {
        return;
    }

    evt->timestamp = bpf_ktime_get_ns();
    evt->src_ip = src_ip;
    evt->dst_ip = dst_ip;
    evt->dst_port = dst_port;
    evt->protocol = protocol;
    evt->action = action;
    evt->rule_id = rule_id;

    bpf_ringbuf_submit(evt, 0);
}

// Match packet against a policy rule
static __always_inline int match_rule(
    struct policy_rule *rule,
    __u32 src_ip,
    __u32 dst_ip,
    __u16 dst_port,
    __u8 protocol)
{
    // Check protocol
    if (rule->protocol != 0 && rule->protocol != protocol)
    {
        return 0;
    }

    // Check source IP
    if (!ip_matches(src_ip, rule->src_ip, rule->src_mask))
    {
        return 0;
    }

    // Check destination IP
    if (!ip_matches(dst_ip, rule->dst_ip, rule->dst_mask))
    {
        return 0;
    }

    // Check destination port
    if (!port_in_range(dst_port, rule->dst_port_min, rule->dst_port_max))
    {
        return 0;
    }

    return 1;
}

// Main XDP program for ingress traffic
SEC("xdp")
int pci_segment_ingress(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Update total packet stats
    inc_stat(STAT_PACKETS_TOTAL, 1);
    inc_stat(STAT_BYTES_TOTAL, data_end - data);

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
    {
        return XDP_PASS; // Malformed packet
    }

    // Only process IPv4 for now
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return XDP_PASS;
    }

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
    {
        return XDP_PASS;
    }

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u8 protocol = ip->protocol;
    __u16 dst_port = 0;

    // Parse transport layer for port
    if (protocol == PROTO_TCP)
    {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
        {
            return XDP_PASS;
        }
        dst_port = bpf_ntohs(tcp->dest);
    }
    else if (protocol == PROTO_UDP)
    {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
        {
            return XDP_PASS;
        }
        dst_port = bpf_ntohs(udp->dest);
    }

    // Check against ingress rules
    // Default deny - must match an ALLOW rule
    int action = ACTION_DENY;
    __u32 matched_rule_id = 0;

#pragma unroll
    for (__u32 i = 0; i < MAX_RULES; i++)
    {
        struct policy_rule *rule = bpf_map_lookup_elem(&ingress_rules, &i);
        if (!rule)
        {
            break;
        }

        // Skip empty rules (all zeros)
        if (rule->action == 0 && rule->protocol == 0)
        {
            continue;
        }

        if (match_rule(rule, src_ip, dst_ip, dst_port, protocol))
        {
            action = rule->action;
            matched_rule_id = i;
            break; // First match wins
        }
    }

    // Log the decision
    log_event(src_ip, dst_ip, dst_port, protocol, action, matched_rule_id);

    // Update stats
    if (action == ACTION_ALLOW)
    {
        inc_stat(STAT_PACKETS_ALLOWED, 1);
        return XDP_PASS;
    }
    else
    {
        inc_stat(STAT_PACKETS_BLOCKED, 1);
        return XDP_DROP;
    }
}

// TC program for egress traffic
SEC("tc")
int pci_segment_egress(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
    {
        return 0; // TC_ACT_OK
    }

    // Only process IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return 0; // TC_ACT_OK
    }

    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
    {
        return 0;
    }

    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u8 protocol = ip->protocol;
    __u16 dst_port = 0;

    // Parse transport layer
    if (protocol == PROTO_TCP)
    {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
        {
            return 0;
        }
        dst_port = bpf_ntohs(tcp->dest);
    }
    else if (protocol == PROTO_UDP)
    {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
        {
            return 0;
        }
        dst_port = bpf_ntohs(udp->dest);
    }

    // Check against egress rules
    int action = ACTION_DENY;
    __u32 matched_rule_id = 0;

#pragma unroll
    for (__u32 i = 0; i < MAX_RULES; i++)
    {
        struct policy_rule *rule = bpf_map_lookup_elem(&egress_rules, &i);
        if (!rule)
        {
            break;
        }

        if (rule->action == 0 && rule->protocol == 0)
        {
            continue;
        }

        if (match_rule(rule, src_ip, dst_ip, dst_port, protocol))
        {
            action = rule->action;
            matched_rule_id = i;
            break;
        }
    }

    // Log the decision
    log_event(src_ip, dst_ip, dst_port, protocol, action, matched_rule_id);

    // Return TC action
    if (action == ACTION_ALLOW)
    {
        return 0; // TC_ACT_OK
    }
    else
    {
        return 2; // TC_ACT_SHOT (drop)
    }
}

char _license[] SEC("license") = "MIT";
