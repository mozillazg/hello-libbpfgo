#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("raw_tracepoint/sys_enter")
int enter_fchmodat(struct bpf_raw_tracepoint_args *ctx) {
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

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} tail_jmp_map SEC(".maps");

// init with values
//struct {
//    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
//    __uint(key_size, sizeof(u32));
//    __uint(value_size, sizeof(u32));
//    __uint(max_entries, 1024);
//    __array(values, int (void *));
//} tail_jmp_map SEC(".maps") = {
//    .values = {
//        [268] = (void *)&enter_fchmodat,
//    },
//};

SEC("raw_tracepoint/sys_enter")
int raw_tracepoint__sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    u32 syscall_id = ctx->args[1];
//    if (syscall_id != 268) // fchmodat
//        return 0;

    bpf_tail_call(ctx, &tail_jmp_map, syscall_id);

    char fmt[] = "no bpf program for syscall %d\n";
    bpf_trace_printk(fmt, sizeof(fmt), syscall_id);
    return 0;
}


char _license[] SEC("license") = "GPL";
