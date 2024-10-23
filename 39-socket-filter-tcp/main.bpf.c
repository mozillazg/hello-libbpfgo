#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/ // ipv4
#define ETH_HLEN	14		/* Total octets in header.	 */

SEC("socket")
int socket__filter_tcp(struct __sk_buff *skb)
{
    u16 h_proto;
    if (bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_proto), &h_proto,
                           sizeof(h_proto)) < 0)
        return 0;
    if (bpf_ntohs(h_proto) != ETH_P_IP) // not ipv4
        return 0;

    struct iphdr ip_hdr;
    if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip_hdr, sizeof(ip_hdr)) < 0)
        return 0;
    if (ip_hdr.protocol != IPPROTO_TCP) // not tcp
        return 0;

    struct tcphdr tcp_hdr;
    if (bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(struct iphdr), &tcp_hdr,
                           sizeof(tcp_hdr)) < 0)
        return 0;
    if (tcp_hdr.dest != bpf_htons(9090))  // filter dest port
        return 0;

    bpf_printk("saddr: %pI4, daddr: %pI4:%d", &ip_hdr.saddr, &ip_hdr.daddr, bpf_htons(tcp_hdr.dest));
    return -1;
}

char _license[] SEC("license") = "GPL";
