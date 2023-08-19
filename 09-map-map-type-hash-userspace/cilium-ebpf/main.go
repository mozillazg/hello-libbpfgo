package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../main.bpf.c -- -I../ -I../output

type Event struct {
	Pid      uint32
	Comm     [16]byte
	FileName [256]byte
}

func (e Event) commName() string {
	return unix.ByteSliceToString(e.Comm[:])
}
func (e Event) fileName() string {
	return unix.ByteSliceToString(e.FileName[:])
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
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TracepointSyscallsSysEnterOpenat, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer tp.Close()
	go generateEvents()

	currPid := uint32(os.Getpid())
	log.Printf("current pid: %d", currPid)

	allow := uint8(1)
	log.Printf("add filter key")
	if err := objs.PidFilter.Update(currPid, allow, ebpf.UpdateAny); err != nil {
		log.Println(err)
		return
	}

	var count int
	for {
		fmt.Println("Waiting...")
		// read map
		var event Event
		if err := objs.PidEventMap.Lookup(currPid, &event); err != nil {
			log.Printf("get event failed: %s", err)
		} else {
			count++
			log.Printf("%d %s opened %s", event.Pid, event.commName(), event.fileName())
			log.Printf("delete event key")
			objs.PidEventMap.Delete(currPid)
		}
		// delete map key: delete filter
		if count > 4 {
			log.Printf("delete filter key")
			objs.PidFilter.Delete(currPid)
		}
		time.Sleep(5 * time.Second)
	}

}
