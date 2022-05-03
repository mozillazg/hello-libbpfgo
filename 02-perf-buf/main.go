package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"

	bpf "github.com/aquasecurity/libbpfgo"
)

type gdata struct {
	Pid      uint32
	FileName string
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
	if err = resizeMap(bpfModule, "events", 8192); err != nil {
		panic(err)
	}

	if err := bpfModule.BPFLoadObject(); err != nil {
		panic(err)
	}
	prog, err := bpfModule.GetProgram("kprobe__do_sys_openat2")
	if err != nil {
		panic(err)
	}
	if _, err := prog.AttachKprobe("do_sys_openat2"); err != nil {
		panic(err)
	}

	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	pb, err := bpfModule.InitPerfBuf("events", eventsChannel, lostChannel, 1)
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
			pid := binary.LittleEndian.Uint32(e[0:4])
			fileName := string(bytes.TrimRight(e[4:], "\x00"))
			gd := gdata{
				Pid:      pid,
				FileName: fileName,
			}
			log.Printf("pid %d opened %q", gd.Pid, gd.FileName)
		case e := <-lostChannel:
			log.Printf("lost %d events", e)
		}
	}
}
