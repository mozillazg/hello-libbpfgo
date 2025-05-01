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

	bpf "github.com/aquasecurity/libbpfgo"
)

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
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		panic(err)
	}
	defer bpfModule.Close()

	if err := bpfModule.BPFLoadObject(); err != nil {
		panic(err)
	}
	prog, err := bpfModule.GetProgram("socket__filter_demo")
	if err != nil {
		panic(err)
	}
	socketFd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		panic(err)
	}
	defer syscall.Close(socketFd)

	if err := syscall.SetsockoptInt(socketFd, syscall.SOL_SOCKET, SO_ATTACH_BPF, prog.FileDescriptor()); err != nil {
		log.Panic(err)
	}
	defer syscall.SetsockoptInt(socketFd, syscall.SOL_SOCKET, SO_DETACH_BPF, prog.FileDescriptor())

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
