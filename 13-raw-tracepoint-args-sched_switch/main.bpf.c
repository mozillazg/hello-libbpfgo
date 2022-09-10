#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// include/trace/events/sched.h
SEC("raw_tracepoint/sched_switch")
int raw_tracepoint__sched__sched_switch(struct bpf_raw_tracepoint_args *ctx) {
    struct task_struct *prev_task =
        (struct task_struct *)BPF_CORE_READ(ctx, args[1]);
    struct task_struct *next_task =
        (struct task_struct *)BPF_CORE_READ(ctx, args[2]);

    u32 prev_pid = BPF_CORE_READ(prev_task, tgid);
    u32 next_pid = BPF_CORE_READ(next_task, tgid);

    char fmt[] = "sched_switch %d -> %d\n";
    bpf_trace_printk(fmt, sizeof(fmt), prev_pid, next_pid);
    return 0;
}

char _license[] SEC("license") = "GPL";
