package main

import (
	"context"
	"log"
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
	hook := bpfModule.TcHookInit()
	err = hook.SetInterfaceByName("lo")
	if err != nil {
		log.Fatalf("failed to set tc hook on interface lo: %v", err)
	}

	hook.SetAttachPoint(bpf.BPFTcIngress)
	err = hook.Create()
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno != syscall.EEXIST {
			log.Fatalf("tc hook create: %v", err)
		}
	}

	tcProg, err := bpfModule.GetProgram("handle_ingress")
	if tcProg == nil {
		log.Fatal(err)
	}

	var tcOpts bpf.TcOpts
	tcOpts.ProgFd = int(tcProg.GetFd())
	tcOpts.Handle = 1
	tcOpts.Priority = 1
	err = hook.Attach(&tcOpts)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		tcOpts.ProgFd = 0
		tcOpts.ProgId = 0
		if err := hook.Detach(&tcOpts); err != nil {
			log.Println(err)
		}
	}()

	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	defer stop()

	log.Println("...")
	<-ctx.Done()
	log.Println("bye bye")
}
