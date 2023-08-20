package main

/*
#cgo LDFLAGS: -lelf -lz
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h> // uapi
*/
import "C"

import (
	"encoding/binary"
	"log"
	"syscall"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"golang.org/x/sys/unix"
)

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

func bpf_prog_attach(prog_fd int, attachable_fd int, attachType bpf.BPFAttachType, flags int) {
	ret := C.bpf_prog_attach(C.int(prog_fd), C.int(attachable_fd),
		C.enum_bpf_attach_type(int(attachType)), C.uint(flags))
	if ret != 0 {
		log.Panic(ret)
	}
}

func main() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		log.Panic(err)
	}
	defer bpfModule.Close()

	if err := bpfModule.BPFLoadObject(); err != nil {
		log.Panic(err)
	}

	socketFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, unix.IPPROTO_IP)
	if err != nil {
		log.Panic(err)
	}
	defer syscall.Close(socketFd)

	// if err := syscall.SetsockoptInt(socketFd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
	// 	log.Panic(err)
	// }

	sock_map_rx, err := bpfModule.GetMap("sock_map_rx")
	if err != nil {
		log.Panic(err)
	}

	prog, err := bpfModule.GetProgram("bpf_prog_parser")
	bpf_prog_attach(prog.FileDescriptor(), sock_map_rx.FileDescriptor(),
		bpf.BPFAttachTypeSKSKBStreamParser, 0)

	prog, err = bpfModule.GetProgram("bpf_prog_verdict")
	bpf_prog_attach(prog.FileDescriptor(), sock_map_rx.FileDescriptor(),
		bpf.BPFAttachTypeSKSKBStreamVerdict, 0)

	// err = sock_map_rx.UpdateValueFlags(unsafe.Pointer(&key), unsafe.Pointer(&val), bpf.MapFlagUpdateNoExist)
	// if err != nil {
	// 	log.Panic(err)
	// }
	// errC := C.bpf_map_update_elem(C.int(sock_map_rx.FileDescriptor()),
	// 	unsafe.Pointer(&key), unsafe.Pointer(&val), C.ulonglong(flags))

	log.Println("bind and listen on 127.0.0.1:19090")
	addr := &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}, Port: 19090}
	if err = syscall.Bind(socketFd, addr); err != nil {
		log.Panic(err)
	}

	if err := syscall.Listen(socketFd, 1024); err != nil {
		log.Panic(err)
	}
	fd, _, err := syscall.Accept(socketFd)
	if err != nil {
		log.Fatalln("Failed to accept(): ", err)
	}

	var key int = 0
	var val int = int(fd)
	err = sock_map_rx.UpdateValueFlags(unsafe.Pointer(&key), unsafe.Pointer(&val), bpf.MapFlagUpdateNoExist)
	if err != nil {
		log.Panic(err)
	}

	// for {
	// fd, _, err := syscall.Accept(socketFd)
	// if err != nil {
	// 	log.Fatalln("Failed to accept(): ", err)
	// }

	// for {
	// 	buf := make([]byte, 1024)
	// 	n, _, err := syscall.Recvfrom(fd, buf, 0)
	// 	if err != nil {
	// 		log.Println(err)
	// 		break
	// 	}
	// 	if n == 0 {
	// 		continue
	// 	}
	// 	log.Println(n)
	// 	log.Println(string(buf))
	// 	if _, err := syscall.Write(fd, []byte("pong")); err != nil {
	// 		log.Printf("write error: %s", err)
	// 	}
	// }
	// }
	select {}

	log.Println("bye bye")
	//
	// for {
	// 	buf := make([]byte, 1500)
	// 	numRead, _, err := syscall.Recvfrom(socketFd, buf, 0)
	// 	if err != nil {
	// 		log.Println(err)
	// 		continue
	// 	}
	// 	rawData := buf[:numRead]
	// 	// log.Printf("recv:\n% X", rawData)
	// 	// rawData[0:14]     : mac header
	// 	// rawData[14:14+20] : ip header
	// 	// rawData[14+20:]   : icmp message
	// 	if numRead <= 14+20 {
	// 		log.Print("invalid icmp packet")
	// 		continue
	// 	}
	// 	header, err := icmp.ParseIPv4Header(rawData[14:])
	// 	if err != nil {
	// 		continue
	// 	}
	// 	// log.Printf("ip header: %s -> %s", header.Src, header.Dst)
	// 	msg, err := icmp.ParseMessage(ProtocolICMP, rawData[14+header.Len:])
	// 	if err != nil {
	// 		continue
	// 	}
	// 	log.Printf("[ICMP] %s -> %s: %s %d", header.Src, header.Dst, msg.Type, msg.Code)
	// }
}
