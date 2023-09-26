package main

import (
	"errors"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	var progSpec = &ebpf.ProgramSpec{
		Name:    "hello_world",
		Type:    ebpf.TracePoint,
		License: "GPL",
	}
	progSpec.Instructions = asm.Instructions{
		asm.Mov.Imm(asm.R1, 10),

		// char fmt[] = "hello world:\n";
		asm.StoreMem(asm.R10, -4, asm.R1, asm.Half),
		asm.Mov.Imm(asm.R1, 979659890),
		asm.StoreMem(asm.R10, -8, asm.R1, asm.Word),
		asm.LoadImm(asm.R1, 0x6f77206f6c6c6568, asm.DWord),
		asm.StoreMem(asm.R10, -16, asm.R1, asm.DWord),
		asm.Mov.Reg(asm.R1, 10),
		asm.ALUOp.Imm(asm.Add, asm.R1, -16),

		// bpf_trace_printk(fmt, sizeof(fmt));
		asm.Mov.Imm(asm.R2, 14),
		asm.FnTracePrintk.Call(),

		// return 0;
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// Using %+v will print the whole verifier error, not just the last
			// few lines.
			log.Printf("Verifier error: %+v\n", ve)
		}
		log.Printf("creating ebpf program: %+v", err)
		return
	}
	defer prog.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
	if err != nil {
		log.Printf("opening tracepoint: %+v", err)
		return
	}
	defer tp.Close()

	log.Println("you can get the message via `sudo cat /sys/kernel/debug/tracing/trace_pipe`")
	time.Sleep(time.Minute)

}
