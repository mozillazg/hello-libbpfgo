#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 0x2


SEC("iter/tcp")
int iter__tcpv4(struct bpf_iter__tcp *ctx) {
    struct sock_common *sk_common = ctx->sk_common;
    struct seq_file *seq = ctx->meta->seq;

    if (sk_common == NULL)
        return 0;
    if (sk_common->skc_family != AF_INET)
        return 0;

    u32 family = sk_common->skc_family;
    u32 saddr = sk_common->skc_rcv_saddr;
    u16 sport = sk_common->skc_num;
    u32 daddr = sk_common->skc_daddr;
    u16 dport = sk_common->skc_dport;

    BPF_SEQ_PRINTF(seq, "%d\t%pI4\t%d\t%pI4\t%d\n",
                   family, &saddr, sport, &daddr, dport);

    return 0;
}


char _license[] SEC("license") = "GPL";
