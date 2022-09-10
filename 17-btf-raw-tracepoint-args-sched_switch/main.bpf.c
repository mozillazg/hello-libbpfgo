#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// include/trace/events/sched.h
// typedef void (*btf_trace_sched_switch)(void *, bool, struct task_struct *,
// struct task_struct *);
SEC("tp_btf/sched_switch")
int btf_raw_tracepoint__sched_switch(u64 *ctx) {
    struct task_struct *prev_task = (struct task_struct *)ctx[1];
    struct task_struct *next_task = (struct task_struct *)ctx[2];
    u32 prev_pid = prev_task->tgid;
    u32 next_pid = next_task->tgid;

    char fmt[] = "sched_switch %d -> %d\n";
    bpf_trace_printk(fmt, sizeof(fmt), prev_pid, next_pid);
    return 0;
}

char _license[] SEC("license") = "GPL";
