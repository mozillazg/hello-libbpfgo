#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/ // ipv4
#define ETH_HLEN 14 /* Total octets in header.	 */

#define TC_ACT_UNSPEC -1
#define TC_ACT_OK      0
#define TC_ACT_SHOT    2

struct event_t {
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("tc")
int handle_ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct iphdr *ip_hdr = data + ETH_HLEN;
    if ((void *)ip_hdr + sizeof(struct iphdr) > data_end) {
        return TC_ACT_OK;
    }
    if (ip_hdr->protocol != IPPROTO_TCP) { // not tcp
        return TC_ACT_OK;
    }

    struct tcphdr *tcp_hdr = (void *)ip_hdr + sizeof(struct iphdr);
    if ((void *)tcp_hdr + sizeof(struct tcphdr) > data_end) {
        return TC_ACT_OK;
    }
    if (tcp_hdr->dest != bpf_htons(9090)) // not 9090 port
        return TC_ACT_OK;
    // if (tcp_hdr->psh == 0) // no payload
    //     return TC_ACT_OK;

    struct event_t event = {};

    u64 flags = BPF_F_CURRENT_CPU;
    u64 save_size = (u64)(skb->len);
    flags |= save_size << 32;
    bpf_perf_event_output(skb, &events, flags, &event, sizeof(event));

    // parse tcp payload
    // char *raw_payload = (void *)tcp_hdr + tcp_hdr->doff * 4;;
    // unsigned raw_payload_size = bpf_htons(ip_hdr->tot_len) - (tcp_hdr->doff * 4) - sizeof(struct iphdr);
    // if ((void *)raw_payload + raw_payload_size > data_end) {
    //     return TC_ACT_OK;
    // }

    // u32 id = 0;
    // struct payload_t *payload = bpf_map_lookup_elem(&tmp_map, &id);
    // if (!payload)
    //     return TC_ACT_OK;

    // __builtin_memset(payload->data, 0, sizeof(payload->data));
    // bpf_probe_read_kernel(&payload->data, sizeof(payload->data), raw_payload);

    // char fmt[] = "payload:\n%s";
    // bpf_trace_printk(fmt, sizeof(fmt), payload->data);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
