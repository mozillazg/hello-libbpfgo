package main

import (
	"bufio"
	"log"
	"strings"

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
	prog, err := bpfModule.GetProgram("iter__task")
	if err != nil {
		panic(err)
	}
	link, err := prog.AttachIter(bpf.IterOpts{})
	if err != nil {
		panic(err)
	}
	reader, err := link.Reader()
	if err != nil {
		panic(err)
	}
	defer reader.Close()

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		log.Printf("ppid: %s, pid: %s, comm: %s", fields[0], fields[1], fields[2])
	}
}
