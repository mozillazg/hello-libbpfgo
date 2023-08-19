package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"

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

	Comm [16]byte
}

var reContainerId = regexp.MustCompile(`/kubepods/besteffort/pod[^/]+/([0-9a-f]{64})$`)

func (e Event) commName() string {
	return unix.ByteSliceToString(e.Comm[:])
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

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TracepointSyscallsSysEnterExecve, nil)
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

		log.Printf(`HostPid: %d, HostPpid: %d, Comm: %s, ContainerId: %s`,
			event.HostPid, event.HostPpid, event.commName(), getContainerId(event.HostPpid))

	}
}

func getContainerId(pid uint32) string {
	if pid == 0 {
		return ""
	}
	path := fmt.Sprintf("/proc/%d/cgroup", pid)
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		log.Printf("open file %s failed: %+v", path, err)
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		matches := reContainerId.FindAllStringSubmatch(line, 1)
		if len(matches) > 0 {
			return matches[0][1]
		}
	}
	return ""
}
