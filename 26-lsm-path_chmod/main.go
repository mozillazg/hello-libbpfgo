package main

import (
	"log"
	"time"

	bpf "github.com/aquasecurity/libbpfgo"
)

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		panic(err)
	}
	defer bpfModule.Close()

	if err := bpfModule.BPFLoadObject(); err != nil {
		log.Println(err)
		return
	}
	prog, err := bpfModule.GetProgram("lsm_path_chmod")
	if err != nil {
		log.Println(err)
		return
	}

	if _, err := prog.AttachLSM(); err != nil {
		log.Println(err)
		return
	}

	log.Println("waiting for events")
	time.Sleep(time.Minute * 1024)
}
