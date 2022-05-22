package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		panic(err)
	}
	defer bpfModule.Close()

	if err := bpfModule.BPFLoadObject(); err != nil {
		panic(err)
	}
	progEnter, err := bpfModule.GetProgram("tracepoint__syscalls__sys_enter_openat")
	if err != nil {
		panic(err)
	}
	if _, err := progEnter.AttachTracepoint("syscalls", "sys_enter_openat"); err != nil {
		panic(err)
	}
	progExit, err := bpfModule.GetProgram("tracepoint__syscalls__sys_exit_openat")
	if err != nil {
		panic(err)
	}
	if _, err := progExit.AttachTracepoint("syscalls", "sys_exit_openat"); err != nil {
		panic(err)
	}

	bpfMap, err := bpfModule.GetMap("pid_event_map")
	if err != nil {
		panic(err)
	}
	path := bpfMap.GetPinPath()
	log.Printf("pin path: %s", path)
	log.Println("Waiting...")

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	// unpin
	<-ch
	log.Printf("unpin...")
	if err := bpfMap.Unpin(path); err != nil {
		log.Printf("unpin %s failed: %s", path, err)
	}
}
