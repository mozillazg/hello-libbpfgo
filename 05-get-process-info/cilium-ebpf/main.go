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
	CgroupId uint64
	HostTid  uint32
	HostPid  uint32
	HostPpid uint32

	Tid  uint32
	Pid  uint32
	Ppid uint32
	Uid  uint32
	Gid  uint32

	CgroupNsId uint32
	IpcNsId    uint32
	NetNsId    uint32
	MountNsId  uint32
	PidNsId    uint32
	TimeNsId   uint32
	UserNsId   uint32
	UtsNsId    uint32

	Comm [16]byte
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

		log.Printf(`
CgroupId: %d
HostTid: %d
HostPid: %d
HostPpid: %d

Tid: %d
Pid: %d
Ppid: %d
Uid: %d
Gid: %d

CgroupNsId: %d
IpcNsId: %d
NetNsId: %d
MountNsId: %d
PidNsId: %d
TimeNsId: %d
UserNsId: %d
UtsNsId: %d

Comm: %s
`,
			event.CgroupId, event.HostTid, event.HostPid, event.HostPpid,
			event.Tid, event.Pid, event.Ppid, event.Uid, event.Gid,
			event.CgroupNsId, event.IpcNsId, event.NetNsId, event.NetNsId, event.MountNsId, event.TimeNsId, event.UserNsId, event.UtsNsId,
			unix.ByteSliceToString(event.Comm[:]))

	}
}
