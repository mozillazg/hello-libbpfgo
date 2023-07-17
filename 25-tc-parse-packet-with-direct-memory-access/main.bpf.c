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
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct iphdr *ip_hdr = data + ETH_HLEN;
    if ((void *)ip_hdr + sizeof(struct iphdr) > data_end) {
        return TC_ACT_UNSPEC;
    }
    if (ip_hdr->protocol != IPPROTO_TCP) { // not tcp
        return TC_ACT_UNSPEC;
    }

    struct tcphdr *tcp_hdr = (void *)ip_hdr + sizeof(struct iphdr);
    if ((void *)tcp_hdr + sizeof(struct tcphdr) > data_end) {
        return TC_ACT_UNSPEC;
    }
    if (tcp_hdr->dest != bpf_htons(9090)) // not 9090 port
        return TC_ACT_UNSPEC;
    if (tcp_hdr->psh == 0) // no payload
        return TC_ACT_UNSPEC;

    // parse tcp payload
    char *raw_payload = (void *)tcp_hdr + tcp_hdr->doff * 4;;
    unsigned raw_payload_size = bpf_htons(ip_hdr->tot_len) - (tcp_hdr->doff * 4) - sizeof(struct iphdr);
    if ((void *)raw_payload + raw_payload_size > data_end) {
        return TC_ACT_UNSPEC;
    }

    u32 id = 0;
    struct payload_t *payload = bpf_map_lookup_elem(&tmp_map, &id);
    if (!payload)
        return TC_ACT_UNSPEC;

    bpf_probe_read_kernel(&payload->data, sizeof(payload->data), raw_payload);

    char fmt[] = "payload:\n%s";
    bpf_trace_printk(fmt, sizeof(fmt), payload->data);

    return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
