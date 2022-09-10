// https://elixir.bootlin.com/linux/v5.13/source/include/linux/sched.h#L215
#define TASK_COMM_LEN 16

struct event_t {
    u32 pid;
    u32 ret;

    char filename[256];
};
