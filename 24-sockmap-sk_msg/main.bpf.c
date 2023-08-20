#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, int);
} sock_map_rx SEC(".maps");

SEC("sk_skb/stream_parser")
int bpf_prog_parser(struct __sk_buff *skb)
{
bpf_printk("bpf_prog_parser");
        return skb->len;
}

SEC("sk_skb/stream_verdict")
int bpf_prog_verdict(struct __sk_buff *skb)
{
        __u32 lport = skb->local_port;
        int idx = 0;

        bpf_printk("bpf_prog_verdict: %d", lport);
//        if (lport == 10000)
                return bpf_sk_redirect_map(skb, &sock_map_rx, idx, 0);

//        return SK_PASS;
}



char _license[] SEC("license") = "GPL";
