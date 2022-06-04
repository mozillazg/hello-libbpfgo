#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
        char comm[16];
        bpf_get_current_comm(&comm, sizeof(comm));
        // filter sh
        if (comm[0] != 's' || comm[1] != 'h' || comm[2] != '\0') {
            return 0;
        }

		u32 pid = bpf_get_current_pid_tgid() >> 32;
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();

        char cgroup_name[128];
        const char *cname = BPF_CORE_READ(task, cgroups, subsys[0], cgroup, kn, name);
        bpf_core_read_str(&cgroup_name, sizeof(cgroup_name), cname);

        char fmt[] = "pid: %d comm: %s cgroup name: %s\n";
        bpf_trace_printk(fmt, sizeof(fmt), pid, comm, cgroup_name);

		return 0;
}

char _license[] SEC("license") = "GPL";
