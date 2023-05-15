#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("tracepoint/sched/sched_switch")
int tracepoint__sched__sched_switch(struct trace_event_raw_sched_switch *ctx) {
    u32 prev_pid = BPF_CORE_READ(ctx, prev_pid);
    u32 next_pid = BPF_CORE_READ(ctx, next_pid);

    char fmt[] = "sched_switch %d -> %d\n";
    bpf_trace_printk(fmt, sizeof(fmt), prev_pid, next_pid);
    return 0;
}

char _license[] SEC("license") = "GPL";
