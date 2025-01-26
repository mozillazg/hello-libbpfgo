#include "vmlinux.h"
#include "common.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


SEC("iter/task")
int iter__task(struct bpf_iter__task *ctx) {
    struct seq_file *seq = ctx->meta->seq;
    struct task_struct *task = ctx->task;
    if (task == NULL)
        return 0;

    struct event_t event = {0};

    BPF_CORE_READ_INTO(&event.pid, task, tgid);
    BPF_CORE_READ_INTO(&event.ppid, task, parent, tgid);
    BPF_CORE_READ_STR_INTO(&event.comm, task, comm);

    bpf_seq_write(seq, &event, sizeof(event));

    return 0;
}


char _license[] SEC("license") = "GPL";
