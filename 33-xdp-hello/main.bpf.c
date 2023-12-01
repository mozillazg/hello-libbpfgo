#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/ // ipv4
#define ETH_HLEN 14 /* Total octets in header.	 */


struct event_t {
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("xdp")
int handle_xdp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct iphdr *ip_hdr = data + ETH_HLEN;
    if ((void *)ip_hdr + sizeof(struct iphdr) > data_end) {
        return XDP_PASS;
    }
    if (ip_hdr->protocol != IPPROTO_TCP) { // not tcp
        return XDP_PASS;
    }

    struct tcphdr *tcp_hdr = (void *)ip_hdr + sizeof(struct iphdr);
    if ((void *)tcp_hdr + sizeof(struct tcphdr) > data_end) {
        return XDP_PASS;
    }
    if (tcp_hdr->dest != bpf_htons(9090)) // not 9090 port
        return XDP_PASS;
    // if (tcp_hdr->psh == 0) // no payload
    //     return XDP_PASS;

    struct event_t event = {};

    u64 flags = BPF_F_CURRENT_CPU;
    u64 save_size = (u64)(data_end - data);
    // save_size = min(save_size, 1024);
    flags |= save_size << 32;
    bpf_perf_event_output(ctx, &events, flags, &event, sizeof(event));

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
