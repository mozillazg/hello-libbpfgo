#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


SEC("lsm/path_chmod")
int lsm_path_chmod(struct path *path) {
    char path_str[32];
    struct qstr dname;

    dname = BPF_CORE_READ(path, dentry, d_name);
    bpf_probe_read_kernel_str(&path_str, sizeof(path_str), dname.name);

    bpf_printk("chmod %s", path_str);

    return 0;
}

char _license[] SEC("license") = "GPL";
