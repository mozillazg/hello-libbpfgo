package main

import (
	"context"
	bpf "github.com/aquasecurity/libbpfgo"
	"log"
	"os"
	"os/signal"
	"syscall"
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
	prog, err := bpfModule.GetProgram("btf_raw_tracepoint__sys_enter")
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

	log.Println("waiting for events")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
}
