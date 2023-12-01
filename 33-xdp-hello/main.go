package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func parseEvent(data []byte) {
	// Decode a packet
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	// Get the TCP layer from this packet
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		log.Println("This is a TCP packet!")
		// Get actual TCP data from this layer
		tcp, _ := tcpLayer.(*layers.TCP)
		log.Printf("From src port %d to dst port %d", tcp.SrcPort, tcp.DstPort)
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

	xdpProg, err := bpfModule.GetProgram("handle_xdp")
	if xdpProg == nil {
		log.Fatal(err)
	}
	link, err := xdpProg.AttachXDP("lo")
	if err != nil {
		log.Fatal(err)
	}
	defer link.Destroy()

	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	pb, err := bpfModule.InitPerfBuf("events", eventsChannel, lostChannel, 1024)
	if err != nil {
		return
	}
	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	pb.Start()
	defer func() {
		pb.Stop()
		pb.Close()
		stop()
	}()

	log.Println("...")
loop:
	for {
		select {
		case data := <-eventsChannel:
			parseEvent(data)
		case n := <-lostChannel:
			log.Printf("lost %d events", n)
		case <-ctx.Done():
			break loop
		}
	}
	log.Println("bye bye~")
}
