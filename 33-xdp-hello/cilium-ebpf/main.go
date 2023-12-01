package main

import (
	"context"
	"errors"
	"log"
	"net"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../main.bpf.c -- -I../ -I../output

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
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	xdpIface := "lo"
	devID, err := net.InterfaceByName(xdpIface)
	if err != nil {
		log.Println(err)
		return
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.HandleXdp,
		Interface: devID.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	reader, err := perf.NewReader(objs.Events, 4096)
	if err != nil {
		log.Println(err)
		return
	}
	defer reader.Close()

	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	defer stop()

	log.Println("...")
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		default:
		}
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("Received signal, exiting...")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}
		if record.LostSamples > 0 {
			log.Printf("lost %d events", record.LostSamples)
			continue
		}
		parseEvent(record.RawSample)
	}
	log.Println("bye bye")
}
