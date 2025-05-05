package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"golang.org/x/sys/unix"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../main.bpf.c -- -I../ -I../output

const (
	SO_ATTACH_BPF = 0x32                     // 50
	SO_DETACH_BPF = syscall.SO_DETACH_FILTER // 27
	ProtocolICMP  = 1                        // Internet Control Message
)

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func attachTc(devID *net.Interface, prog *ebpf.Program) (func(), error) {
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return nil, err
	}
	closeFunc := func() {
		if err := tcnl.Close(); err != nil {
			log.Println(err)
		}
	}

	qdisc := tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  core.BuildHandle(tc.HandleRoot, 0x0000),
			Parent:  tc.HandleIngress,
		},
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}
	if err := tcnl.Qdisc().Add(&qdisc); err != nil {
		return closeFunc, err
	}
	newCloseFunc := func() {
		if err := tcnl.Qdisc().Delete(&qdisc); err != nil {
			log.Println(err)
		}
		closeFunc()
	}

	fd := uint32(prog.FD())
	name := "handle_egress"

	filter := tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  0,
			Parent:  core.BuildHandle(tc.HandleRoot, tc.HandleMinEgress),
			Info:    uint32(htons(unix.ETH_P_ALL)),
		},
		tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:   &fd,
				Name: &name,
			},
		},
	}
	if err := tcnl.Filter().Add(&filter); err != nil {
		fmt.Fprintf(os.Stderr, "could not attach filter for eBPF program: %v\n", err)
		return newCloseFunc, err
	}
	return newCloseFunc, nil

}

func tracePipeListen() error {
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
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			log.Fatalf("%+v", verr)
		}
		log.Fatal(err)
	}
	defer objs.Close()

	tcIface := "lo"
	devID, err := net.InterfaceByName(tcIface)
	if err != nil {
		log.Println(err)
		return
	}

	closeFunc, err := attachTc(devID, objs.HandleEgress)
	if err != nil {
		if closeFunc != nil {
			closeFunc()
		}
		log.Println(err)
		return
	}
	defer closeFunc()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		if err := tracePipeListen(); err != nil {
			log.Printf("Error: %v", err)
			cancel()
		}
	}()
	<-ctx.Done()

	log.Println("Exiting...")
}
