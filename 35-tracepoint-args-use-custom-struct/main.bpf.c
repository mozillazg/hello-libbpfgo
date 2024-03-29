#include "vmlinux.h"

#include "common.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* BPF ringbuf map */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 /* 16 KB */);
} events SEC(".maps");


// sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_fchmodat/format
struct sys_enter_fchmodat_args {
    char _[16];
    long dfd;
    long filename_ptr;
    long mode;
};

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int tracepoint__syscalls__sys_enter_fchmodat(
    struct sys_enter_fchmodat_args *ctx) {
    struct event_t *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->host_pid = bpf_get_current_pid_tgid() >> 32;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    char *filename_ptr = (char *)ctx->filename_ptr;
    bpf_core_read_user_str(&event->filename, sizeof(event->filename),
                           filename_ptr);
    event->mode = (u32)ctx->mode;

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
