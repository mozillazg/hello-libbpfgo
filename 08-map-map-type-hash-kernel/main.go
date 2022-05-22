package main

import (
	"fmt"
	"time"

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

	for {
		fmt.Println("Waiting...")
		time.Sleep(10 * time.Second)
	}
}
