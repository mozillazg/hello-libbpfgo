#include "vmlinux.h"

#include "common.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


SEC("raw_tracepoint/sched_wakeup")
int raw_tp__sched_wakeup(struct bpf_raw_tracepoint_args *ctx) {
    struct task_struct *p;
    pid_t pid;
    char comm[TASK_COMM_LEN];

    p = (struct task_struct*)ctx->args[0];

    pid = BPF_CORE_READ(p, pid);
    /* bpf_probe_read_kernel(&pid, sizeof(pid), &p->pid); */

    BPF_CORE_READ_STR_INTO(&comm, p, comm);
    /* bpf_probe_read_kernel_str(&comm, sizeof(comm), &p->comm); */

    bpf_printk("[sched_wakeup] p->pid: %d, p->comm: %s", pid, comm);
    return 0;
}

char _license[] SEC("license") = "GPL";
