// https://elixir.bootlin.com/linux/v5.13/source/include/linux/sched.h#L215
#define TASK_COMM_LEN 16
#define FILENAME_LEN 512
#define ARGV_LEN 4096

struct event_t {
    u32 host_pid;  // pid in host pid namespace
    u32 host_ppid; // ppid in host pid namespace

    char comm[TASK_COMM_LEN]; // the name of the executable (excluding the path)
    char filename[FILENAME_LEN];

    u32 argv_size;
    char argv[ARGV_LEN];
};
