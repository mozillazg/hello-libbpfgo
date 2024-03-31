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


SEC("tracepoint/sched/sched_process_exec")
int tracepoint__sched__sched_process_exec(
    struct trace_event_raw_sched_process_exec *ctx) {
    struct event_t *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->host_pid = bpf_get_current_pid_tgid() >> 32;
    event->host_ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    unsigned int filename_loc = BPF_CORE_READ(ctx, __data_loc_filename) & 0xFFFF;
    bpf_probe_read_str(&event->filename, sizeof(event->filename), (void *)ctx + filename_loc);

    void *arg_start = (void *)BPF_CORE_READ(task, mm, arg_start);
    void *arg_end = (void *)BPF_CORE_READ(task, mm, arg_end);
    unsigned long arg_length = arg_end - arg_start;
    arg_length = arg_length < ARGV_LEN ? arg_length : ARGV_LEN;
    int arg_ret = bpf_probe_read(&event->argv, arg_length, arg_start);
    if (!arg_ret) {
        event->argv_size = arg_length;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
