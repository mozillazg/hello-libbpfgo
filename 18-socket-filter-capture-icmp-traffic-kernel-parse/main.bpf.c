#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
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

SEC("socket/filter_icmp")
int socket__filter_icmp(struct __sk_buff *skb)
{
	// Skip non-IP packets
	if (load_half(skb, offsetof(struct ethhdr, h_proto)) != ETH_P_IP)
		return 0;

	// Skip non-ICMP packets
	if (load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol)) != IPPROTO_ICMP)
		return 0;

    u32 src_addr = load_word(skb, ETH_HLEN + offsetof(struct iphdr, saddr));
    u32 dst_addr = load_word(skb, ETH_HLEN + offsetof(struct iphdr, daddr));
    u8 type = load_byte(skb, ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type));
    u8 code = load_byte(skb, ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, code));

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
