#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/ // ipv4
#define ETH_HLEN 14 /* Total octets in header.	 */

#define TC_ACT_UNSPEC -1
#define TC_ACT_SHOT 2
#define TC_ACT_SHOT 2

#define DATA_LEN 1024
struct payload_t {
    char data[DATA_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct payload_t);
    __uint(max_entries, 1);
} tmp_map SEC(".maps");

SEC("tc")
int handle_ingress(struct __sk_buff *skb) {
    u16 h_proto;
    if (bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &h_proto,
                           sizeof(h_proto)) < 0)
        return TC_ACT_UNSPEC;
    if (bpf_ntohs(h_proto) != ETH_P_IP) // not ipv4
        return TC_ACT_UNSPEC;

    u8 protocol;
    if (bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, protocol),
                           &protocol, sizeof(protocol)) < 0)
        return TC_ACT_UNSPEC;
    if (protocol != IPPROTO_TCP) // not tcp
        return TC_ACT_UNSPEC;

    struct tcphdr tcp_hdr;
    if (bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(struct iphdr), &tcp_hdr,
                           sizeof(tcp_hdr)) < 0)
        return TC_ACT_UNSPEC;
    if (tcp_hdr.dest != bpf_htons(9090)) // not 9090 port
        return TC_ACT_UNSPEC;
    if (tcp_hdr.psh == 0) // no payload
        return TC_ACT_UNSPEC;

    // parse tcp payload
    u16 offset = ETH_HLEN + sizeof(struct iphdr) + (tcp_hdr.doff << 2);
    if (offset == 0 || offset > skb->len) {
        return TC_ACT_UNSPEC;
    }

    u32 id = 0;
    struct payload_t *payload = bpf_map_lookup_elem(&tmp_map, &id);
    if (!payload)
        return TC_ACT_UNSPEC;

    u32 i;
    for (i = 0; i < DATA_LEN; i++) {
        char b;
        bpf_skb_load_bytes(skb, offset + i, &b, 1);
        if (b == '\0')
            break;
        payload->data[i] = b;
    }

    char fmt[] = "payload:\n%s";
    bpf_trace_printk(fmt, sizeof(fmt), payload->data);

    return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
