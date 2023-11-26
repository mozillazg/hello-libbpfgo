#include "vmlinux.h"

#include "common.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* BPF ringbuf map */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, pid_t);
    __type(value, struct event);
} tmp_map SEC(".maps");

SEC("ksyscall/openat")
int ksyscall__openat(struct pt_regs *ctx) {
    struct event e = {0} ;

    pid_t tid = (pid_t)bpf_get_current_pid_tgid();

    e.pid = bpf_get_current_pid_tgid() >> 32;

    struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARM1_CORE(ctx);
    char *fn_ptr;
    fn_ptr = (char *)PT_REGS_PARM2_CORE(regs);
    bpf_core_read_user_str(&e.filename, sizeof(e.filename), fn_ptr);

    bpf_map_update_elem(&tmp_map, &tid, &e, BPF_NOEXIST);

    return 0;
}

SEC("kretsyscall/openat")
int kretsyscall__openat(struct pt_regs *ctx) {
    struct event *e;

    pid_t tid = (pid_t)bpf_get_current_pid_tgid();

    struct event *tmp;
    tmp = bpf_map_lookup_elem(&tmp_map, &tid);
    if (!tmp) {
        return 0;
    }

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->ret = (long)PT_REGS_RC_CORE(ctx);
    e->pid = tmp->pid;
    __builtin_memcpy(&e->filename, tmp->filename, sizeof(e->filename));


    bpf_ringbuf_submit(e, 0);

    bpf_map_delete_elem(&tmp_map, &tid);

    return 0;
}

char _license[] SEC("license") = "GPL";
