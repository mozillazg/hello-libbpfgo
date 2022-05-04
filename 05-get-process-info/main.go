package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	bpf "github.com/aquasecurity/libbpfgo"
)

type Context struct {
	Ts          uint64
	CgroupID    uint64
	Pid         uint32
	Tid         uint32
	Ppid        uint32
	HostPid     uint32
	HostTid     uint32
	HostPpid    uint32
	Uid         uint32
	MntID       uint32
	PidID       uint32
	Comm        [16]byte
	UtsName     [16]byte
	EventID     int32
	Retval      int64
	StackID     uint32
	ProcessorId uint16
	Argnum      uint8
	_           [1]byte // padding
}

func resizeMap(module *bpf.Module, name string, size uint32) error {
	m, err := module.GetMap(name)
	if err != nil {
		return err
	}

	if err = m.Resize(size); err != nil {
		return err
	}

	if actual := m.GetMaxEntries(); actual != size {
		return fmt.Errorf("map resize failed, expected %v, actual %v", size, actual)
	}

	return nil
}

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		panic(err)
	}
	defer bpfModule.Close()
	if err := resizeMap(bpfModule, "events", 8192); err != nil {
		panic(err)
	}

	if err := bpfModule.BPFLoadObject(); err != nil {
		panic(err)
	}
	prog, err := bpfModule.GetProgram("tracepoint_openat")
	if err != nil {
		panic(err)
	}
	if _, err := prog.AttachTracepoint("syscalls", "sys_enter_openat"); err != nil {
		panic(err)
	}

	eventsChannel := make(chan []byte)
	pb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		panic(err)
	}

	pb.Start()
	defer func() {
		pb.Stop()
		pb.Close()
	}()

	for {
		select {
		case e := <-eventsChannel:
			var ctx Context
			var dataBuffer *bytes.Buffer

			dataBuffer = bytes.NewBuffer(e)
			err = binary.Read(dataBuffer, binary.LittleEndian, &ctx)
			if err != nil {
				log.Println(err)
				continue
			}
			log.Printf("ts: %d, cgroup: %d, pid: %d, tid: %d,"+
				"ppid: %d, hostpid: %d, hosttid: %d, hostppid: %d,"+
				"uid: %d, mntid: %d, pidid: %d,"+
				"comm: %s, uts: %s, eid: %d, retval: %d, sid: %d, pcid: %d, an: %d",
				ctx.Ts, ctx.CgroupID, ctx.Pid, ctx.Tid, ctx.Ppid, ctx.HostPid,
				ctx.HostTid, ctx.HostPpid, ctx.Uid, ctx.MntID, ctx.PidID,
				toString(ctx.Comm), toString(ctx.UtsName),
				ctx.EventID, ctx.Retval, ctx.StackID, ctx.ProcessorId, ctx.Argnum)
		}
	}
}

func toString(b [16]byte) string {
	return string(bytes.TrimRight(b[:], "\x00"))
}
