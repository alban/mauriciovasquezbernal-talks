// This program demonstrates the use of a hashmap. It count the number
// of invocations to openat() per pid.
// go run -exec sudo .
package main

// #include <linux/types.h>
// #include "./bpf/execsnoop.h"
import "C"

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang execsnoop bpf/execsnoop.bpf.c

var (
	enterLink link.Link
	exitLink  link.Link
	reader    *perf.Reader
)

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := execsnoopObjects{}
	if err := loadExecsnoopObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// attach the pre-compiled program.
	var err error
	enterLink, exitLink, err = loadExecsnoopLinks(objs)
	if err != nil {
		log.Fatal(err)
	}

	reader, err = perf.NewReader(objs.execsnoopMaps.Events, 64*os.Getpagesize())
	if err != nil {
		log.Fatalf("error creating perf ring buffer: %w", err)
	}

	fmt.Println("Ready, press Ctrl+C to close: ")

	// Graceful shutdown
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)

	go run()
	<-exit
}

func run() {
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				// nothing to do, we're done
				return
			}

			log.Fatalf("Error reading perf ring buffer: %s", err)
			return
		}

		if record.LostSamples > 0 {
			fmt.Printf("lost %d samples", record.LostSamples)
			continue
		}

		eventC := (*C.struct_event)(unsafe.Pointer(&record.RawSample[0]))

		fmt.Printf("pid: %v, ppid: %v, comm: %s\n",
			uint32(eventC.pid),
			uint32(eventC.ppid),
			C.GoString(&eventC.comm[0]),
		)

		buf := []byte{}

		for i := 0; i < int(eventC.args_size); i++ {
			c := eventC.args[i]
			if c == 0 {
				fmt.Printf("  Arg: %q\n", string(buf))
				buf = []byte{}
			} else {
				buf = append(buf, byte(c))
			}
		}
	}
}

func loadExecsnoopLinks(objs execsnoopObjects) (link.Link, link.Link, error) {
	enter, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.IgExecveE, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("error opening tracepoint: %w", err)
	}

	exit, err := link.Tracepoint("syscalls", "sys_exit_execve", objs.IgExecveX, nil)
	if err != nil {
		CloseLink(enter)
		return nil, nil, fmt.Errorf("error opening tracepoint: %w", err)
	}

	return enter, exit, nil
}

func CloseLink(l link.Link) link.Link {
	if l != nil {
		l.Close()
	}
	return nil
}
