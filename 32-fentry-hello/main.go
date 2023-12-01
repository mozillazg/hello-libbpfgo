package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	bpf "github.com/aquasecurity/libbpfgo"
	"golang.org/x/sys/unix"
)

type Event struct {
	Pid      uint64
	Ret      int64
	FileName [256]byte
}

func goString(s []byte) string {
	return string(bytes.Split(s, []byte("\x00"))[0])
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
	prog1, err := bpfModule.GetProgram("fentry__do_sys_openat2")
	if err != nil {
		panic(err)
	}
	if _, err := prog1.AttachGeneric(); err != nil {
		panic(err)
	}
	prog2, err := bpfModule.GetProgram("fexit__do_sys_openat2")
	if err != nil {
		panic(err)
	}
	if _, err := prog2.AttachGeneric(); err != nil {
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
		case data := <-eventsChannel:
			var event Event
			if err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event); err != nil {
				log.Printf("parse event: %s", err)
				continue
			}
			log.Printf("pid %d, file: %s, ret: %d", event.Pid, unix.ByteSliceToString(event.FileName[:]), event.Ret)
		}
	}
}
