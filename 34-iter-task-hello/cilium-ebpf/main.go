package main

import (
	"bufio"
	"log"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../main.bpf.c -- -I../ -I../output

type RawLinkReader struct {
	l *link.RawLink
}

func (r *RawLinkReader) Read(p []byte) (n int, err error) {
	return syscall.Read(r.l.FD(), p)
}

func (r *RawLinkReader) Close() error {
	return syscall.Close(r.l.FD())
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

	iter, err := link.AttachIter(link.IterOptions{
		Program: objs.IterTask,
	})
	if err != nil {
		log.Println(err)
		return
	}

	reader, err := iter.Open()
	if err != nil {
		log.Println(err)
		return
	}
	defer reader.Close()

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		log.Printf("ppid: %s, pid: %s, comm: %s", fields[0], fields[1], fields[2])
	}

}
