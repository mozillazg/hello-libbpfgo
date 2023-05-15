// https://elixir.bootlin.com/linux/v5.13/source/include/linux/sched.h#L215
#define TASK_COMM_LEN 16

struct event_t {
    u64 cgroup_id; // cgroup id
    u32 host_tid;  // tid in host pid namespace
    u32 host_pid;  // pid in host pid namespace
    u32 host_ppid; // ppid in host pid namespace

    u32 tid;  // thread id in userspace
    u32 pid;  // process id in userspace
    u32 ppid; // parent process id in userspace
    u32 uid;
    u32 gid;

    u32 cgroup_ns_id;
    u32 ipc_ns_id;
    u32 net_ns_id;
    u32 mount_ns_id;
    u32 pid_ns_id;
    u32 time_ns_id;
    u32 user_ns_id;
    u32 uts_ns_id;

    char comm[TASK_COMM_LEN]; // the name of the executable (excluding the path)
};
