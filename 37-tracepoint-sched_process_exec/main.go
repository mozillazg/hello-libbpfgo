package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"strings"

	bpf "github.com/aquasecurity/libbpfgo"
	"golang.org/x/sys/unix"
)

type cdata struct {
	HostPid  uint32
	HostPpid uint32

	Comm     [16]byte
	FileName [512]byte

	ArgvSize uint32
	Argv     [4096]byte
}

func (c cdata) commName() string {
	return unix.ByteSliceToString(c.Comm[:])
}
func (c cdata) fileName() string {
	return unix.ByteSliceToString(c.FileName[:])
}
func (c cdata) argv() string {
	var i uint32
	builder := strings.Builder{}
	for ; i < c.ArgvSize; i++ {
		b := c.Argv[i]
		if b == '\x00' {
			builder.WriteString(" ")
		} else {
			builder.WriteByte(b)
		}
	}
	return builder.String()
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
	progIter := bpfModule.Iterator()
	for {
		prog := progIter.NextProgram()
		if prog == nil {
			break
		}
		_, err = prog.AttachGeneric()
		if err != nil {
			panic(err)
		}
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
			log.Printf(`HostPid: %d, HostPpid: %d, Comm: %s, FileName: %s, Argv: %s`,
				cd.HostPid, cd.HostPpid, cd.commName(), cd.fileName(), cd.argv())
		}
	}
}
