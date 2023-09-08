#define _GNU_SOURCE
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include "./bpf_insn.h"


#define ptr_to_u64(x) ((uint64_t)x)
#define LOG_BUF_SIZE 0x1000

char bpf_log_buf[LOG_BUF_SIZE];


int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(__NR_bpf, cmd, attr, size);
}

int bpf_prog_load(enum bpf_prog_type type, const struct bpf_insn* insns, int insn_cnt, const char* license) {
    union bpf_attr attr = {
        .prog_type = type,
        .insns = ptr_to_u64(insns),
        .insn_cnt = insn_cnt,
        .license = ptr_to_u64(license),
        .log_buf = ptr_to_u64(bpf_log_buf),
        .log_size = LOG_BUF_SIZE,
        .log_level = 2,
    };

    return bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int perf_event_open(struct perf_event_attr *evt_attr, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    int ret = syscall(__NR_perf_event_open, evt_attr, pid, cpu, group_fd, flags);
    return ret;
}

static int create_link(int prog_fd, int target_fd) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));

    attr.link_create.prog_fd = prog_fd;
    attr.link_create.target_fd = target_fd;
    attr.link_create.attach_type = BPF_PERF_EVENT;
    attr.link_create.flags = 0;

    return bpf(BPF_LINK_CREATE, &attr, sizeof(attr));
}

int open_perf_event(int prog_fd, int event_id) {
    struct perf_event_attr attr = {};
    memset(&attr, 0, sizeof(attr));

    attr.type = PERF_TYPE_TRACEPOINT;
    attr.sample_type = PERF_SAMPLE_RAW;
    attr.sample_period = 1;
    attr.wakeup_events = 1;
    attr.config = event_id;

    return perf_event_open(&attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
}

int attach_tracepoint(int prog_fd, int perf_fd) {
    // attach via link
    int link_fd = create_link(prog_fd, perf_fd);
    if (link_fd < 0) {
        perror("create link error");
        return -1;
    }

    // ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
    // attach without link
    // if(ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd) < 0) {
    //    perror("ioctl event set bpf error");
    //    return -1;
    // }

    return link_fd;
}


// got via
// * `llvm-objdump-12 -S main.bpf.o`
// or
// 1. `bpftool prog load ./main.bpf.o /sys/fs/bpf/hello`
// 2. `bpftool prog dump xlated id XX`
struct bpf_insn bpf_prog[] = {
    BPF_MOV64_IMM(BPF_REG_1, 10),        // r1 = 10

    // char fmt[] = "hello world:\n";
    BPF_STX_MEM(BPF_H, BPF_REG_10, BPF_REG_1, -4), // *(u16 *)(r10 - 4) = r1
    BPF_MOV64_IMM(BPF_REG_1, 979659890), // r1 = 979659890
    BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_1, -8), // *(u32 *)(r10 - 8) = r1
    BPF_LD_IMM64(BPF_REG_1, 0x6f77206f6c6c6568), // r1 = 0x6f77206f6c6c6568
    BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_1, -16), // *(u64 *)(r10 - 16) = r1
    BPF_MOV64_REG(BPF_REG_1, 10),        // r1 = 10
    BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -16), // r1 += -16

    // bpf_trace_printk(fmt, sizeof(fmt));
    BPF_MOV64_IMM(BPF_REG_2, 14),         // r2 = 14
    BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_trace_printk), // call bpf_trace_printk#-66304

                                           // return 0;
    BPF_MOV64_IMM(BPF_REG_0, 0),          // r0 = 0
    BPF_EXIT_INSN(),                      // exit
};

int main(void){
    int prog_fd, perf_fd, link_fd;

    // load
    prog_fd = bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT, bpf_prog, sizeof(bpf_prog)/sizeof(bpf_prog[0]), "GPL");
    printf("%s\n", bpf_log_buf);
    if (prog_fd < 0) {
        perror("bpf load prog failed");
        exit(-1);
    }

    // open perf event
    // from /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/id
    int exec_id = 721;
    perf_fd = open_perf_event(prog_fd, exec_id);
    if (perf_fd < 0) {
        perror("perf event open error");
        exit(-1);
    }

    // attach
    link_fd = attach_tracepoint(prog_fd, perf_fd);
    if (link_fd < 0) {
        perror("bpf attach prog failed");
        exit(-1);
    }


    printf("you can get the message via `sudo cat /sys/kernel/debug/tracing/trace_pipe`\n");

    // hold on
    getchar();

    close(prog_fd);
    close(perf_fd);
    close(link_fd);

    return 0;
}
