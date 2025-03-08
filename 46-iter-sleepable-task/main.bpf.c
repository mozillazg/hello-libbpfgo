#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


SEC("iter.s/task")
int iter__task(struct bpf_iter__task *ctx) {
    struct seq_file *seq = ctx->meta->seq;
    struct task_struct *task = ctx->task;
    if (task == NULL)
        return 0;

    BPF_SEQ_PRINTF(seq, "%d\t%d\t%s\n", task->parent->pid, task->pid, task->comm);

    return 0;
}


char _license[] SEC("license") = "GPL";
