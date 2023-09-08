#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_openat(struct trace_event_raw_sys_enter *ctx) {
    char fmt[] = "hello world:\n";
    bpf_trace_printk(fmt, sizeof(fmt));

    return 0;
}

char _license[] SEC("license") = "GPL";
