struct event_t {
    u32 pid;
    u32 ppid;
    char comm[16];
};

// cilium/ebpf need this
const struct event_t *unused __attribute__((unused));
