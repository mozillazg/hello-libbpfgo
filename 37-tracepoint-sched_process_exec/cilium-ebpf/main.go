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
	"golang.org/x/sys/unix"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../main.bpf.c -- -I../ -I../output

type Event struct {
	HostPid  uint32
	HostPpid uint32

	Comm     [16]byte
	FileName [512]byte

	ArgvSize uint32
	Argv     [4096]byte
}

func (e Event) commName() string {
	return unix.ByteSliceToString(e.Comm[:])
}
func (e Event) fileName() string {
	return unix.ByteSliceToString(e.FileName[:])
}
func (e Event) argv() string {
	var i uint32
	builder := strings.Builder{}
	for ; i < e.ArgvSize; i++ {
		c := e.Argv[i]
		if c == '\x00' {
			builder.WriteString(" ")
		} else {
			builder.WriteByte(c)
		}
	}
	return builder.String()
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

	tp, err := link.Tracepoint("sched", "sched_process_exec", objs.TracepointSchedSchedProcessExec, nil)
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
		var event Event
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parse event: %s", err)
			continue
		}

		log.Printf(`HostPid: %d, HostPpid: %d, Comm: %s, FileName: %s, Argv: %s`,
			event.HostPid, event.HostPpid, event.commName(), event.fileName(), event.argv())

	}
}
