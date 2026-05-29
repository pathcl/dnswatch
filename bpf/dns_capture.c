// SPDX-License-Identifier: GPL-2.0

// XDP program: captures DNS queries and responses on UDP port 53.
// Pushes a fixed-size event into a ring buffer for userspace consumption.
// DNS payload parsing is intentionally left to userspace to avoid
// BPF verifier complexity with variable-length label loops.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Maximum DNS payload we copy into the event.
// DNS messages are limited to 512 bytes over UDP (RFC 1035 §2.3.4),
// though EDNS0 can extend this. 512 covers all standard queries.
#define DNS_MAX_PAYLOAD 512

// Event pushed to userspace for every DNS packet seen.
struct dns_event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 payload_len;   // actual bytes copied — may be less than packet size
    __u8  is_response;   // 1 if source port is 53 (response), 0 if dest port is 53 (query)
    __u8  pad;           // explicit padding to avoid struct holes
    __u8  payload[DNS_MAX_PAYLOAD];
};

// Ring buffer map — kernel 5.8+. More efficient than perf event array:
// no per-CPU buffers, no sample loss on slow consumers, variable-length records.
// 4MB total capacity (must be a multiple of page size and a power of two).
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

SEC("xdp")
int dns_capture(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // --- Ethernet header ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only handle IPv4. IPv6 DNS is uncommon on home LANs; add later if needed.
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // --- IP header ---
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // ip->ihl is in 32-bit words; multiply by 4 for bytes.
    // Handles IP options without assuming a fixed 20-byte header.
    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    __u16 sport = bpf_ntohs(udp->source);
    __u16 dport = bpf_ntohs(udp->dest);

    // Filter: only DNS traffic (port 53 in either direction).
    if (sport != 53 && dport != 53)
        return XDP_PASS;

    // --- DNS payload ---
    void *dns_start = (void *)(udp + 1);
    if (dns_start >= data_end)
        return XDP_PASS;

    // Use __u32 for the length computation. The BPF verifier tracks __u16
    // as having range [0, 65535] and does not always narrow that range after
    // a conditional cap, causing a spurious out-of-bounds error on the copy.
    __u32 avail = (long)data_end - (long)dns_start;

    // Reserve space in the ring buffer. BPF_RB_NO_WAKEUP defers the
    // consumer notification — we submit immediately after, which triggers it.
    struct dns_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return XDP_PASS; // ring buffer full; drop event, pass packet

    e->src_ip      = ip->saddr;
    e->dst_ip      = ip->daddr;
    e->src_port    = sport;
    e->dst_port    = dport;
    e->is_response = (sport == 53) ? 1 : 0;
    e->payload_len = avail < DNS_MAX_PAYLOAD ? (__u16)avail : DNS_MAX_PAYLOAD;
    e->pad         = 0;

    // Two explicit branches so each bpf_probe_read_kernel call has a
    // compile-time-provable size that the verifier can check against
    // sizeof(e->payload) == DNS_MAX_PAYLOAD == 512:
    //
    //   Branch 1 (avail >= 512): copy exactly 512 bytes — a constant.
    //   Branch 2 (avail <  512): avail <= 511, and (avail & 511) == avail,
    //            so the masked value is in [0, 511] < 512. ✓
    if (avail >= DNS_MAX_PAYLOAD) {
        bpf_probe_read_kernel(e->payload, DNS_MAX_PAYLOAD, dns_start);
    } else {
        bpf_probe_read_kernel(e->payload, avail & (DNS_MAX_PAYLOAD - 1), dns_start);
    }

    bpf_ringbuf_submit(e, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
