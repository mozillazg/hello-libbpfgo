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
	prog, err := bpfModule.GetProgram("iter__tcpv4")
	if err != nil {
		log.Println(err)
		return
	}
	link, err := prog.AttachIter(bpf.IterOpts{})
	if err != nil {
		log.Println(err)
		return
	}
	defer link.Destroy()
	reader, err := link.Reader()
	if err != nil {
		log.Println(err)
		return
	}
	defer reader.Close()

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		log.Printf("family: %s, saddr: %s, sport: %s, daddr: %s, dport: %s",
			fields[0], fields[1], fields[2], fields[3], fields[4])
	}
}
