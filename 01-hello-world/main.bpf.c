#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("kprobe/do_sys_openat2")
int kprobe__do_sys_openat2(struct pt_regs *ctx) {
    char file_name[256];
    bpf_probe_read(file_name, sizeof(file_name), PT_REGS_PARM2(ctx));

    char fmt[] = "open file %s\n";
    bpf_trace_printk(fmt, sizeof(fmt), &file_name);

    return 0;
}

char _license[] SEC("license") = "GPL";
