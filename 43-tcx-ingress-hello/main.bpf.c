#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/ // ipv4
#define ETH_HLEN 14 /* Total octets in header.	 */

#define TCX_NEXT	 -1
#define TCX_PASS	  0
#define TCX_DROP	  2
#define TCX_REDIRECT  7

SEC("tcx/ingress")
int handle_ingress(struct __sk_buff *skb) {
    bpf_skb_pull_data(skb, 0);

    u16 h_proto;
    if (bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &h_proto,
                           sizeof(h_proto)) < 0)
        goto out;
    if (bpf_ntohs(h_proto) != ETH_P_IP) // not ipv4
        goto out;

    struct iphdr ip_hdr;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip_hdr, sizeof(ip_hdr)) < 0)
        return 0;
    if (ip_hdr.protocol != IPPROTO_TCP) // not tcp
        return 0;

    struct tcphdr tcp_hdr;
    if (bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(struct iphdr), &tcp_hdr,
                           sizeof(tcp_hdr)) < 0)
        goto out;

    bpf_printk("saddr: %pI4:%d, daddr: %pI4:%d", &ip_hdr.saddr, bpf_htons(tcp_hdr.source), &ip_hdr.daddr, bpf_htons(tcp_hdr.dest));

out:
    return TCX_NEXT;
}

char _license[] SEC("license") = "GPL";
