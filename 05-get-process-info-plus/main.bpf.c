// base on https://github.com/aquasecurity/tracee/tree/main/pkg/ebpf/c

#include "vmlinux.h"
#include "missing_definitions.h"
#include "struct_flavors.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

/* BPF ringbuf map */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} events SEC(".maps");


static __always_inline int init_context(struct context_t *context, struct task_struct *task, u32 options)
{
    u64 id = bpf_get_current_pid_tgid();
    context->host_tid = id;
    context->host_pid = id >> 32;
    context->host_ppid = get_task_ppid(task);
    context->tid = get_task_ns_pid(task);
    context->pid = get_task_ns_tgid(task);
    context->ppid = get_task_ns_ppid(task);
    context->mnt_id = get_task_mnt_ns_id(task);
    context->pid_id = get_task_pid_ns_id(task);
    context->uid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&context->comm, sizeof(context->comm));
    char * uts_name = get_task_uts_name(task);
    if (uts_name)
        bpf_probe_read_str(&context->uts_name, TASK_COMM_LEN, uts_name);
    if (options & OPT_CGROUP_V1) {
        context->cgroup_id = get_cgroup_v1_subsys0_id(task);
    } else {
        context->cgroup_id = bpf_get_current_cgroup_id();
    }

    context->ts = bpf_ktime_get_ns();
    context->argnum = 0;

    // Clean Stack Trace ID
    context->stack_id = 0;

    context->processor_id = (u16)bpf_get_smp_processor_id();

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_openat(struct trace_event_raw_sys_enter *ctx)
{
		struct context_t *context;
		context = bpf_ringbuf_reserve(&events, sizeof(*context), 0);
		if (!context) {
			return 0;
		}

		struct task_struct *task;
        task = bpf_get_current_task();
        init_context(context, task, OPT_CGROUP_V1);

		bpf_ringbuf_submit(context, 0);

		return 0;
}

char _license[] SEC("license") = "GPL";
