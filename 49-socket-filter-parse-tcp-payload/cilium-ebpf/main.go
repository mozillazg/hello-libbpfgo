package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../main.bpf.c -- -I../ -I../output

const (
	SO_ATTACH_BPF = 0x32                     // 50
	SO_DETACH_BPF = syscall.SO_DETACH_FILTER // 27
)

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func TracePipeListen() error {
	f, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err != nil {
		return fmt.Errorf("failed to open trace pipe: %w", err)
	}
	defer f.Close()

	r := bufio.NewReader(f)
	b := make([]byte, 1024)

	for {
		l, err := r.Read(b)
		if err != nil {
			return fmt.Errorf("failed to read from trace pipe: %w", err)
		}

		s := string(b[:l])
		fmt.Println(s)
	}
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	socketFd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		panic(err)
	}
	defer syscall.Close(socketFd)

	fd := objs.SocketFilterDemo.FD()
	if err := syscall.SetsockoptInt(socketFd, syscall.SOL_SOCKET, SO_ATTACH_BPF, fd); err != nil {
		log.Panic(err)
	}
	defer syscall.SetsockoptInt(socketFd, syscall.SOL_SOCKET, SO_DETACH_BPF, fd)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		if err := TracePipeListen(); err != nil {
			log.Printf("Error: %v", err)
			cancel()
		}
	}()
	<-ctx.Done()

	log.Println("Exiting...")
}
