package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type event Bpf ../main.bpf.c -- -I../ -I../output

func main() {
	kernel_func_name := "do_sys_openat2"
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := BpfObjects{}
	if err := LoadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	kp, err := link.Kprobe(kernel_func_name, objs.KprobeDoSysOpenat2, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer kp.Close()

	reader, err := perf.NewReader(objs.Events, 4096)
	if err != nil {
		log.Println(err)
		return
	}
	defer reader.Close()

	log.Println("Waiting for events...")

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("Received signal, exiting...")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}
		if record.LostSamples > 0 {
			log.Printf("lost %d events", record.LostSamples)
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
