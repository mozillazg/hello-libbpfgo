#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// typedef void (*btf_trace_sys_enter)(void *, struct pt_regs *, long int);
SEC("tp_btf/sys_enter")
int btf_raw_tracepoint__sys_enter(u64 *ctx) {
    long int syscall_id = (long int)ctx[1];
    if (syscall_id != 268) // fchmodat
        return 0;

    struct pt_regs *regs = (struct pt_regs *)ctx[0];
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    // int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);
    char pathname[256];
    u32 mode;

    char *pathname_ptr = (char *)PT_REGS_PARM2_CORE(regs);
    bpf_core_read_user_str(&pathname, sizeof(pathname), pathname_ptr);
    mode = (u32)PT_REGS_PARM3_CORE(regs);

    char fmt[] = "%d fchmodat %s %d\n";
    bpf_trace_printk(fmt, sizeof(fmt), task->tgid, &pathname, mode);
    return 0;
}

char _license[] SEC("license") = "GPL";
