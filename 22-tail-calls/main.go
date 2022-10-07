package main

import (
	"fmt"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		panic(err)
	}
	defer bpfModule.Close()

	if err := bpfModule.BPFLoadObject(); err != nil {
		panic(err)
	}

	tailMap, err := bpfModule.GetMap("tail_jmp_map")
	if err != nil {
		panic(err)
	}
	enterFchmodat, err := bpfModule.GetProgram("enter_fchmodat")
	if err != nil {
		panic(err)
	}
	syscallId := 268
	enterFchmodatFd := enterFchmodat.GetFd()
	if err := tailMap.Update(unsafe.Pointer(&syscallId), unsafe.Pointer(&enterFchmodatFd)); err != nil {
		panic(err)
	}

	prog, err := bpfModule.GetProgram("raw_tracepoint__sys_enter")
	if err != nil {
		panic(err)
	}
	if _, err := prog.AttachRawTracepoint("sys_enter"); err != nil {
		panic(err)
	}

	for {
		fmt.Println("Waiting...")
		time.Sleep(10 * time.Second)
	}
}
