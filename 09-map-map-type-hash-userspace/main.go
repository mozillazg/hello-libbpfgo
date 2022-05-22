package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

type gdata struct {
	Pid  uint32
	Comm [16]byte
	File [256]byte
}

func (d gdata) commName() string {
	return string(bytes.TrimRight(d.Comm[:], "\x00"))
}

func (d gdata) fileName() string {
	return string(bytes.Split(d.File[:], []byte("\x00"))[0])
}

func generateEvents() {
	paths := []string{
		"/foo/bar",
		os.Args[0],
	}
	for {
		for _, p := range paths {
			f, err := os.Open(p)
			if err == nil {
				f.Close()
			}
			time.Sleep(time.Second * 10)
		}
	}
}

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		panic(err)
	}
	defer bpfModule.Close()

	if err := bpfModule.BPFLoadObject(); err != nil {
		panic(err)
	}
	progEnter, err := bpfModule.GetProgram("tracepoint__syscalls__sys_enter_openat")
	if err != nil {
		panic(err)
	}
	if _, err := progEnter.AttachTracepoint("syscalls", "sys_enter_openat"); err != nil {
		panic(err)
	}
	eventMap, err := bpfModule.GetMap("pid_event_map")
	if err != nil {
		panic(err)
	}
	filterMap, err := bpfModule.GetMap("pid_filter")
	if err != nil {
		panic(err)
	}
	go generateEvents()

	currPid := uint32(os.Getpid())
	log.Printf("current pid: %d", currPid)
	allow := uint8(1)
	kp := unsafe.Pointer(&currPid)
	vp := unsafe.Pointer(&allow)

	// update map key: add filter
	log.Printf("add filter key")
	if err := filterMap.Update(kp, vp); err != nil {
		panic(err)
	}

	var count int
	for {
		fmt.Println("Waiting...")
		// read map
		rdata, err := eventMap.GetValue(kp)
		if err != nil {
			log.Printf("get event failed: %s", err)
		} else {
			count++
			var data gdata
			if err := binary.Read(bytes.NewReader(rdata), binary.LittleEndian, &data); err != nil {
				log.Printf("decode data failed: %s", err)
			} else {
				log.Printf("%d %s opened %s", data.Pid, data.commName(), data.fileName())
			}
			log.Printf("delete event key")
			eventMap.DeleteKey(kp)
		}
		// delete map key: delete filter
		if count > 4 {
			log.Printf("delete filter key")
			filterMap.DeleteKey(kp)
		}
		time.Sleep(5 * time.Second)
	}
}
