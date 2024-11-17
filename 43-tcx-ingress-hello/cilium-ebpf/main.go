package main

import (
	"context"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../main.bpf.c -- -I../ -I../output

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	tcIface := "lo"
	if v := os.Getenv("IFACE"); v != "" {
		tcIface = v
	}
	log.Printf("interface name: %s", tcIface)
	devID, err := net.InterfaceByName(tcIface)
	if err != nil {
		log.Println(err)
		return
	}

	lk, err := link.AttachTCX(link.TCXOptions{
		Interface: devID.Index,
		Program:   objs.HandleIngress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Println(err)
		return
	}
	defer lk.Close()

	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	defer stop()

	log.Println("...")
	<-ctx.Done()
	log.Println("bye bye")
}
