// https://elixir.bootlin.com/linux/v5.13/source/include/linux/sched.h#L215
#define TASK_COMM_LEN			16

struct event_t {
    u16 type;
    u16 code;
    u32 src_addr;
    u32 dst_addr;
};
