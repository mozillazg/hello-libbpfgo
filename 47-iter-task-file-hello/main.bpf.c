#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


SEC("iter/task_file")
int iter__task_file(struct bpf_iter__task_file *ctx) {
    struct seq_file *seq = ctx->meta->seq;
    struct task_struct *task = ctx->task;
    struct file *file = ctx->file;
    if (task == NULL || file == NULL)
        return 0;

    BPF_SEQ_PRINTF(seq, "%d\t%d\t%s\t%lld\t%lld\n",
    task->parent->pid, task->pid, task->comm, ctx->fd, file->f_pos);

    return 0;
}


char _license[] SEC("license") = "GPL";
