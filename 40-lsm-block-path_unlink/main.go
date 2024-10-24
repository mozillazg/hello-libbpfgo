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
		log.Println(err)
		return
	}
	prog, err := bpfModule.GetProgram("lsm_path_unlink")
	if err != nil {
		log.Println(err)
		return
	}

	if _, err := prog.AttachLSM(); err != nil {
		log.Println(err)
		return
	}

	log.Println("waiting for events")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
}
