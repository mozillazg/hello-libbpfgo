// https://elixir.bootlin.com/linux/v5.13/source/include/linux/sched.h#L215
#define TASK_COMM_LEN 16

struct event_t {
    u32 host_pid;  // pid in host pid namespace
    u32 host_ppid; // ppid in host pid namespace

    char comm[TASK_COMM_LEN]; // the name of the executable (excluding the path)
};

// cilium/ebpf need this
const struct event_t *unused __attribute__((unused));
