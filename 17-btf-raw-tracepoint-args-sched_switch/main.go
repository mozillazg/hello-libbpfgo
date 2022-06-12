package main

import (
	"fmt"
	"os"
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
	prog, err := bpfModule.GetProgram("btf_raw_tracepoint__sched_switch")
	if err != nil {
		panic(err)
	}
	link, err := prog.AttachGeneric()
	if err != nil {
		panic(err)
	}
	if link.GetFd() == 0 {
		os.Exit(-1)
	}

	for {
		fmt.Println("Waiting...")
		time.Sleep(10 * time.Second)
	}
}
