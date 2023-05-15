#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("raw_tracepoint/sys_enter")
int raw_tracepoint__sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    unsigned long syscall_id = ctx->args[1];
    if (syscall_id != 268) // fchmodat
        return 0;

    struct pt_regs *regs;
    regs = (struct pt_regs *)ctx->args[0];

    // int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);
    char pathname[256];
    u32 mode;

    char *pathname_ptr = (char *)PT_REGS_PARM2_CORE(regs);
    bpf_core_read_user_str(&pathname, sizeof(pathname), pathname_ptr);
    mode = (u32)PT_REGS_PARM3_CORE(regs);

    char fmt[] = "fchmodat %s %d\n";
    bpf_trace_printk(fmt, sizeof(fmt), &pathname, mode);
    return 0;
}

char _license[] SEC("license") = "GPL";
