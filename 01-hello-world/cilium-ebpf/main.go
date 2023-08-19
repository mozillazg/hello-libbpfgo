package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../main.bpf.c -- -I../ -I../output

func main() {
	kernel_func_name := "do_sys_openat2"
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	kp, err := link.Kprobe(kernel_func_name, objs.KprobeDoSysOpenat2, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer kp.Close()

	log.Println("Waiting for events...")
	time.Sleep(time.Minute * 100)
}
