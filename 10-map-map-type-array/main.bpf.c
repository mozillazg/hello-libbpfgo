#include "vmlinux.h"

#include "common.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* BPF_MAP_TYPE_ARRAY */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct event_t);
    __uint(max_entries, 1024 * 1024 /* should match key size */);
} pid_event_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u8);
    __uint(max_entries, 1024 * 1024 /* should match key size */);
} pid_filter SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(
    struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 *allow;
    allow = bpf_map_lookup_elem(&pid_filter, &pid);
    if (!(allow && *allow == 1)) {
        return 0;
    }

    struct event_t event = {};
    event.pid = pid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    char *fn_ptr;
    fn_ptr = (char *)(ctx->args[1]);
    bpf_core_read_user_str(&event.file, sizeof(event.file), fn_ptr);

    bpf_map_update_elem(&pid_event_map, &pid, &event, BPF_ANY);

    char fmt[] = "%d %s open %s\n";
    bpf_trace_printk(fmt, sizeof(fmt), event.pid, event.comm, event.file);
    return 0;
}

char _license[] SEC("license") = "GPL";
