package main

import (
	"encoding/binary"
	bpf "github.com/aquasecurity/libbpfgo"
	"golang.org/x/sys/unix"
	"io"
	"log"
)

type EventT struct {
	Pid  uint32
	Ppid uint32
	Comm [16]byte
}

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		log.Printf("error: %s", err)
		return
	}
	defer bpfModule.Close()

	if err := bpfModule.BPFLoadObject(); err != nil {
		log.Printf("error: %s", err)
		return
	}
	prog, err := bpfModule.GetProgram("iter__task")
	if err != nil {
		log.Printf("error: %s", err)
		return
	}

	link, err := prog.AttachIter(bpf.IterOpts{})
	if err != nil {
		log.Printf("error: %s", err)
		return
	}
	defer link.Destroy()

	reader, err := link.Reader()
	if err != nil {
		log.Printf("error: %s", err)
		return
	}
	defer reader.Close()

	for {
		event := EventT{}
		if err := binary.Read(reader, binary.LittleEndian, &event); err != nil {
			log.Printf("read event: %s", err)
			if err == io.EOF {
				break
			}
			continue
		}

		log.Printf("ppid: %d, pid: %d, comm: %s",
			event.Ppid, event.Pid, unix.ByteSliceToString(event.Comm[:]))
	}
}
