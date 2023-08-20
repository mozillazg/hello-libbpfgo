package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../main.bpf.c -- -I../ -I../output

type Event struct {
	Pid      uint32
	Ret      uint32
	FileName [256]byte
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	}); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	tpEnter, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TracepointSyscallsSysEnterOpenat, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer tpEnter.Close()
	tpExit, err := link.Tracepoint("syscalls", "sys_exit_openat", objs.TracepointSyscallsSysExitOpenat, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer tpExit.Close()

	path := "pid_event_map"
	log.Printf("pin path: %s", path)
	log.Println("Waiting...")

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	// unpin
	<-ch
	log.Printf("unpin...")
	if err := objs.PidEventMap.Unpin(); err != nil {
		log.Printf("unpin %s failed: %s", path, err)
	}
}
