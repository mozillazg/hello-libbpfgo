#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// sudo cat /sys/kernel/debug/tracing/events/sched/sched_switch/format
struct sched_switch_args {
    char _[8];
    char prev_comm[16];
    pid_t prev_pid;
    int prev_prio;
    long prev_state;
    char next_comm[16];
    pid_t next_pid;
    int next_prio;
};

SEC("tracepoint/sched/sched_switch")
int tracepoint__sched__sched_switch(struct sched_switch_args *ctx) {
    u32 prev_pid = (u32)ctx->prev_pid;
    u32 next_pid = (u32)ctx->next_pid;

    char fmt[] = "sched_switch %d -> %d\n";
    bpf_trace_printk(fmt, sizeof(fmt), prev_pid, next_pid);
    return 0;
}

char _license[] SEC("license") = "GPL";
