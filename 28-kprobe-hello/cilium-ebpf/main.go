package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../main.bpf.c -- -I../ -I../output

type Event struct {
	Pid      uint64
	Ret      int64
	FileName [256]byte
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

	kp, err := link.Kprobe("do_sys_openat2", objs.KprobeDoSysOpenat2, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer kp.Close()
	krp, err := link.Kretprobe("do_sys_openat2", objs.KretprobeDoSysOpenat2, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer krp.Close()

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
		var event Event
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parse event: %s", err)
			continue
		}
		log.Printf("pid %d, file: %s, ret: %d", event.Pid, unix.ByteSliceToString(event.FileName[:]), event.Ret)

	}
}
