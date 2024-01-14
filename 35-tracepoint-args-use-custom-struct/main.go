package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"strconv"

	bpf "github.com/aquasecurity/libbpfgo"
)

type cdata struct {
	HostPid  uint32
	HostPpid uint32

	Mod uint32

	Comm [16]byte

	FileName [256]byte
}

func (c cdata) commName() string {
	return string(bytes.Split(c.Comm[:], []byte("\x00"))[0])
}
func (c cdata) fileName() string {
	return string(bytes.Split(c.FileName[:], []byte("\x00"))[0])
}

func (c cdata) modStr() string {
	return strconv.FormatUint(uint64(c.Mod), 8)
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
	prog, err := bpfModule.GetProgram("tracepoint__syscalls__sys_enter_fchmodat")
	if err != nil {
		panic(err)
	}
	if _, err := prog.AttachTracepoint("syscalls", "sys_enter_fchmodat"); err != nil {
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
			log.Printf(`HostPid: %d, HostPpid: %d, Comm: %s, Mod: %s, File: %s`,
				cd.HostPid, cd.HostPpid, cd.commName(), cd.modStr(), cd.fileName())
		}
	}
}
