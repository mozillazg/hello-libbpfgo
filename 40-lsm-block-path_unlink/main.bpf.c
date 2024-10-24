#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static __always_inline bool str_eq(const char *a, const char *b, int len)
{
    for (int i = 0; i < len; i++) {
        if (a[i] != b[i])
            return false;
        if (a[i] == '\0')
            break;
    }
    return true;
}

static __always_inline int str_len(char *s, int max_len)
{
    for (int i = 0; i < max_len; i++) {
        if (s[i] == '\0')
            return i;
    }
    if (s[max_len - 1] != '\0')
        return max_len;
    return 0;
}

SEC("lsm/path_unlink")
int BPF_PROG(lsm_path_unlink, struct path *dir, struct dentry *dentry) {
    char file_name_str[32];
    char block_file_name[32] = "a.txt";
    struct qstr file_dname;

    file_dname = BPF_CORE_READ(dentry, d_name);
    bpf_probe_read_kernel_str(&file_name_str, sizeof(file_name_str), file_dname.name);

    if (!str_eq(file_name_str, block_file_name, str_len(block_file_name, 32)))
        return 0;

    bpf_printk("blocked unlink file named %s", file_name_str);

    return -1;
}

char _license[] SEC("license") = "GPL";
