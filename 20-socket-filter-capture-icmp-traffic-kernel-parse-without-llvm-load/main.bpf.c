#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#define ETH_P_IP	0x0800		/* Internet Protocol packet	*/ // ipv4
#define ETH_HLEN	14		/* Total octets in header.	 */

unsigned long long load_byte(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.byte");
unsigned long long load_half(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");
unsigned long long load_word(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");

/* BPF ringbuf map */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 /* 16 KB */);
} events SEC(".maps");

SEC("socket")
int socket__filter_icmp(struct __sk_buff *skb)
{
	// Skip non-IP packets
	struct ethhdr eth_hdr;
	if (bpf_skb_load_bytes(skb, 0, &eth_hdr, sizeof(eth_hdr)) < 0)
	    return 0;
	if (bpf_ntohs(eth_hdr.h_proto) != ETH_P_IP)
		return 0;

	// Skip non-ICMP packets
	struct iphdr ip_hdr;
	if (bpf_skb_load_bytes(skb, ETH_HLEN, &ip_hdr, sizeof(ip_hdr)) < 0)
        return 0;
	if (ip_hdr.protocol != IPPROTO_ICMP)
		return 0;

    u32 src_addr = ip_hdr.saddr;
    u32 dst_addr = ip_hdr.daddr;

    struct icmphdr icmp_hdr;
    if (bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(struct iphdr), &icmp_hdr, sizeof(icmp_hdr)) < 0)
        return 0;

    u8 type = icmp_hdr.type;
    u8 code = icmp_hdr.code;

    struct event_t *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->src_addr = src_addr;
    event->dst_addr = dst_addr;
    event->type = type;
    event->code = code;

    char fmt[] = "ICMP packet: %x -> %x %d";
    bpf_trace_printk(fmt, sizeof(fmt), event->src_addr, event->dst_addr, event->type);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
