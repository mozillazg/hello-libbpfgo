package main

import (
	"encoding/binary"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"io"
	"log"
	"strings"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type event_t Bpf ../main.bpf.c -- -I../ -I../output

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := BpfObjects{}
	if err := LoadBpfObjects(&objs, nil); err != nil {
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
	defer iter.Close()

	reader, err := iter.Open()
	if err != nil {
		log.Println(err)
		return
	}
	defer reader.Close()

	for {
		event := BpfEventT{}
		if err := binary.Read(reader, binary.LittleEndian, &event); err != nil {
			log.Printf("read event: %s", err)
			if err == io.EOF {
				break
			}
			continue
		}

		log.Printf("ppid: %d, pid: %d, comm: %s",
			event.Ppid, event.Pid, GoString(event.Comm[:]))
	}
}

func GoString(cstring []int8) string {
	var bs strings.Builder

	for _, i := range cstring {
		b := byte(i)
		if b == '\x00' {
			break
		}
		bs.WriteByte(b)
	}

	return bs.String()
}
