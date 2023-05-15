#include "vmlinux.h"

#include "common.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* BPF ringbuf map */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 /* 16 KB */);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_openat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *event;
    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent_task = BPF_CORE_READ(task, real_parent);
    u64 tgid = bpf_get_current_pid_tgid();
    u64 ugid = bpf_get_current_uid_gid();

    event->cgroup_id = bpf_get_current_cgroup_id();
    event->host_tid = tgid;
    event->host_pid = tgid >> 32;
    event->host_ppid = BPF_CORE_READ(parent_task, tgid);

    struct nsproxy *namespaceproxy = BPF_CORE_READ(task, nsproxy);
    struct pid_namespace *pid_ns_children =
        BPF_CORE_READ(namespaceproxy, pid_ns_for_children);
    unsigned int level = BPF_CORE_READ(pid_ns_children, level);
    event->tid = BPF_CORE_READ(task, thread_pid, numbers[level].nr);
    event->pid =
        BPF_CORE_READ(task, group_leader, thread_pid, numbers[level].nr);

    struct nsproxy *parent_namespaceproxy = BPF_CORE_READ(parent_task, nsproxy);
    struct pid_namespace *parent_pid_ns_children =
        BPF_CORE_READ(parent_namespaceproxy, pid_ns_for_children);
    unsigned int parent_level = BPF_CORE_READ(parent_pid_ns_children, level);
    event->ppid = BPF_CORE_READ(parent_task, group_leader, thread_pid,
                                numbers[parent_level].nr);

    event->uid = ugid;
    event->gid = ugid >> 32;

    event->cgroup_ns_id = BPF_CORE_READ(namespaceproxy, cgroup_ns, ns.inum);
    event->ipc_ns_id = BPF_CORE_READ(namespaceproxy, ipc_ns, ns.inum);
    event->net_ns_id = BPF_CORE_READ(namespaceproxy, net_ns, ns.inum);
    event->mount_ns_id = BPF_CORE_READ(namespaceproxy, mnt_ns, ns.inum);
    event->pid_ns_id =
        BPF_CORE_READ(namespaceproxy, pid_ns_for_children, ns.inum);
    event->time_ns_id = BPF_CORE_READ(namespaceproxy, time_ns, ns.inum);
    event->user_ns_id = BPF_CORE_READ(namespaceproxy, cgroup_ns, ns.inum);
    event->uts_ns_id = BPF_CORE_READ(namespaceproxy, cgroup_ns, ns.inum);

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";
