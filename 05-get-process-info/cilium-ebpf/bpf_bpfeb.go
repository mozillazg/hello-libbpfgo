// Code generated by bpf2go; DO NOT EDIT.
//go:build mips || mips64 || ppc64 || s390x

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type BpfEventT struct {
	CgroupId   uint64
	HostTid    uint32
	HostPid    uint32
	HostPpid   uint32
	Tid        uint32
	Pid        uint32
	Ppid       uint32
	Uid        uint32
	Gid        uint32
	CgroupNsId uint32
	IpcNsId    uint32
	NetNsId    uint32
	MountNsId  uint32
	PidNsId    uint32
	TimeNsId   uint32
	UserNsId   uint32
	UtsNsId    uint32
	Comm       [16]int8
}

// LoadBpf returns the embedded CollectionSpec for Bpf.
func LoadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load Bpf: %w", err)
	}

	return spec, err
}

// LoadBpfObjects loads Bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*BpfObjects
//	*BpfPrograms
//	*BpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// BpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfSpecs struct {
	BpfProgramSpecs
	BpfMapSpecs
}

// BpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfProgramSpecs struct {
	TracepointOpenat *ebpf.ProgramSpec `ebpf:"tracepoint_openat"`
}

// BpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfMapSpecs struct {
	Events *ebpf.MapSpec `ebpf:"events"`
}

// BpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfObjects struct {
	BpfPrograms
	BpfMaps
}

func (o *BpfObjects) Close() error {
	return _BpfClose(
		&o.BpfPrograms,
		&o.BpfMaps,
	)
}

// BpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfMaps struct {
	Events *ebpf.Map `ebpf:"events"`
}

func (m *BpfMaps) Close() error {
	return _BpfClose(
		m.Events,
	)
}

// BpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfPrograms struct {
	TracepointOpenat *ebpf.Program `ebpf:"tracepoint_openat"`
}

func (p *BpfPrograms) Close() error {
	return _BpfClose(
		p.TracepointOpenat,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_bpfeb.o
var _BpfBytes []byte
