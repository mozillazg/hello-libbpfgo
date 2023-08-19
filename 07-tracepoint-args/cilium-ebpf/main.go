package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"strconv"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../main.bpf.c -- -I../ -I../output

type Event struct {
	HostPid  uint32
	HostPpid uint32

	Mod uint32

	Comm [16]byte

	FileName [256]byte
}

func (e Event) commName() string {
	return unix.ByteSliceToString(e.Comm[:])
}
func (e Event) fileName() string {
	return unix.ByteSliceToString(e.FileName[:])
}

func (e Event) modStr() string {
	return strconv.FormatUint(uint64(e.Mod), 8)
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

	tp, err := link.Tracepoint("syscalls", "sys_enter_fchmodat", objs.TracepointSyscallsSysEnterFchmodat, nil)
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

		log.Printf(`HostPid: %d, HostPpid: %d, Comm: %s, Mod: %s, File: %s`,
			event.HostPid, event.HostPpid, event.commName(), event.modStr(), event.fileName())

	}
}
