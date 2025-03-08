package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type event Bpf ../main.bpf.c -- -I../ -I../output

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := BpfObjects{}
	if err := LoadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TracepointOpenat, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer tp.Close()

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Println(err)
		return
	}
	defer reader.Close()

	log.Println("Waiting for events...")

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting...")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}
		var event BpfEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parse event: %s", err)
			continue
		}
		log.Printf("pid %d, file: %s", event.Pid, GoString(event.Filename[:]))

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
