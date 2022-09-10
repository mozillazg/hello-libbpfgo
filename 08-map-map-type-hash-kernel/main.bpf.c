#include "vmlinux.h"

#include "common.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* BPF_MAP_TYPE_HASH */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct event_t);
    __uint(max_entries, 1024 * 16 /* number */);
} pid_event_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(
    struct trace_event_raw_sys_enter *ctx) {
    u64 tgid = bpf_get_current_pid_tgid();
    u32 pid = tgid >> 32;
    if (pid != (u32)tgid) {
        return 0;
    }
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    // filter cat
    if (!(comm[0] == 'c' && comm[1] == 'a' && comm[2] == 't' &&
          comm[3] == '\0')) {
        return 0;
    }

    struct event_t event = {};
    event.pid = pid;

    char *fn_ptr;
    fn_ptr = (char *)(ctx->args[1]);
    bpf_core_read_user_str(&event.filename, sizeof(event.filename), fn_ptr);

    char fmt[] = "%d open %s\n";
    bpf_trace_printk(fmt, sizeof(fmt), event.pid, event.filename);

    bpf_map_update_elem(&pid_event_map, &pid, &event, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(
    struct trace_event_raw_sys_exit *ctx) {
    u64 tgid = bpf_get_current_pid_tgid();
    u32 pid = tgid >> 32;
    if (pid != (u32)tgid) {
        return 0;
    }

    struct event_t *event;
    event = bpf_map_lookup_elem(&pid_event_map, &pid);
    if (!event) {
        return 0;
    }

    event->ret = (u32)BPF_CORE_READ(ctx, ret);
    char fmt[] = "%d opened %s, ret: %d\n";
    bpf_trace_printk(fmt, sizeof(fmt), event->pid, event->filename, event->ret);
    bpf_map_delete_elem(&pid_event_map, &pid);

    return 0;
}

char _license[] SEC("license") = "GPL";
