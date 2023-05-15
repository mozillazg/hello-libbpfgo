#include "vmlinux.h"

#include "common.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* BPF ringbuf map */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_openat(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;

    char *fn_ptr;
    fn_ptr = (char *)(ctx->args[1]);
    bpf_core_read_user_str(&e->filename, sizeof(e->filename), fn_ptr);

    bpf_ringbuf_submit(e, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";
