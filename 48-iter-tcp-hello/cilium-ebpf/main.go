package main

import (
	"bufio"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"strings"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile
//
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

	iter, err := link.AttachIter(link.IterOptions{
		Program: objs.IterTcpv4,
	})
	if err != nil {
		log.Println(err)
		return
	}
	defer iter.Close()

	reader, err := iter.Open()
	if err != nil {
		log.Println(err)
		return
	}
	defer reader.Close()

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		log.Printf("family: %s, saddr: %s, sport: %s, daddr: %s, dport: %s",
			fields[0], fields[1], fields[2], fields[3], fields[4])
	}

}
