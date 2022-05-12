package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	bpf "github.com/aquasecurity/libbpfgo"
)

type cdata struct {
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

func (c cdata) commName() string {
	return string(bytes.TrimRight(c.Comm[:], "\x00"))
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
			var cd cdata
			var dataBuffer *bytes.Buffer

			dataBuffer = bytes.NewBuffer(e)
			err = binary.Read(dataBuffer, binary.LittleEndian, &cd)
			if err != nil {
				log.Println(err)
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
				cd.CgroupId, cd.HostTid, cd.HostPid, cd.HostPpid,
				cd.Tid, cd.Pid, cd.Ppid, cd.Uid, cd.Gid,
				cd.CgroupNsId, cd.IpcNsId, cd.NetNsId, cd.NetNsId, cd.MountNsId, cd.TimeNsId, cd.UserNsId, cd.UtsNsId,
				cd.commName())
		}
	}
}
