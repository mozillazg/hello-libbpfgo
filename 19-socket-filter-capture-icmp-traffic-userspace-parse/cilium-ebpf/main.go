package main

import (
	"encoding/binary"
	"log"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/net/icmp"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../main.bpf.c -- -I../ -I../output

const (
	SO_ATTACH_BPF = 0x32                     // 50
	SO_DETACH_BPF = syscall.SO_DETACH_FILTER // 27
	ProtocolICMP  = 1                        // Internet Control Message
)

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
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

	socketFd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		panic(err)
	}
	defer syscall.Close(socketFd)

	fd := objs.SocketFilterIcmp.FD()
	if err := syscall.SetsockoptInt(socketFd, syscall.SOL_SOCKET, SO_ATTACH_BPF, fd); err != nil {
		log.Panic(err)
	}
	defer syscall.SetsockoptInt(socketFd, syscall.SOL_SOCKET, SO_DETACH_BPF, fd)

	for {
		buf := make([]byte, 1500)
		numRead, _, err := syscall.Recvfrom(socketFd, buf, 0)
		if err != nil {
			log.Println(err)
			continue
		}
		rawData := buf[:numRead]
		// log.Printf("recv:\n% X", rawData)
		// rawData[0:14]     : mac header
		// rawData[14:14+20] : ip header
		// rawData[14+20:]   : icmp message
		if numRead <= 14+20 {
			log.Print("invalid icmp packet")
			continue
		}
		header, err := icmp.ParseIPv4Header(rawData[14:])
		if err != nil {
			continue
		}
		// log.Printf("ip header: %s -> %s", header.Src, header.Dst)
		msg, err := icmp.ParseMessage(ProtocolICMP, rawData[14+header.Len:])
		if err != nil {
			continue
		}
		log.Printf("[ICMP] %s -> %s: %s %d", header.Src, header.Dst, msg.Type, msg.Code)

	}
}
