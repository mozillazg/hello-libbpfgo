package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"syscall"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

const (
	SO_ATTACH_BPF = 0x32                     // 50
	SO_DETACH_BPF = syscall.SO_DETACH_FILTER // 27
)

type Event struct {
	SrcAddr uint32
	DstAddr uint32
}

func (e Event) Src() net.IP {
	return uint32ToIpV4(e.SrcAddr)
}
func (e Event) Dst() net.IP {
	return uint32ToIpV4(e.DstAddr)
}

func uint32ToIpV4(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
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
	prog, err := bpfModule.GetProgram("socket__filter_icmp")
	if err != nil {
		panic(err)
	}
	socketFd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		panic(err)
	}
	defer syscall.Close(socketFd)

	if err := syscall.SetsockoptInt(socketFd, syscall.SOL_SOCKET, SO_ATTACH_BPF, prog.GetFd()); err != nil {
		log.Panic(err)
	}
	defer syscall.SetsockoptInt(socketFd, syscall.SOL_SOCKET, SO_DETACH_BPF, prog.GetFd())
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
		case rawData := <-eventsChannel:
			var event Event
			err := binary.Read(bytes.NewBuffer(rawData), binary.LittleEndian, &event)
			if err != nil {
				log.Println(err)
				continue
			}
			log.Printf("[ICMP] %s -> %s", event.Src(), event.Dst())
		}
	}
}
