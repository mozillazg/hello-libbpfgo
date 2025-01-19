struct event {
    u32 pid;
    char filename[256];
};

// cilium/ebpf need this
const struct event *unused __attribute__((unused));
