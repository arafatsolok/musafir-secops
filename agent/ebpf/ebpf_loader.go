//go:build linux

package main

import (
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Event structure matching the eBPF program
type Event struct {
	Pid       uint32
	Tgid      uint32
	Uid       uint32
	Gid       uint32
	Comm      [16]byte
	Filename  [256]byte
	Syscall   uint32
	Timestamp uint64
}

// eBPFLoader handles loading and running eBPF programs
type eBPFLoader struct {
	collection *ebpf.Collection
	links      []link.Link
	eventChan  chan Event
}

func NeweBPFLoader() (*eBPFLoader, error) {
	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, err
	}

	// Load the eBPF program
	spec, err := ebpf.LoadCollectionSpec("ebpf_probe.o")
	if err != nil {
		return nil, err
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, err
	}

	return &eBPFLoader{
		collection: coll,
		eventChan:  make(chan Event, 1000),
	}, nil
}

func (e *eBPFLoader) Start() error {
	// Attach tracepoints
	execveLink, err := link.OpenTracepoint(link.TracepointOptions{
		Subsystem: "syscalls",
		Name:      "sys_enter_execve",
		Program:   e.collection.Programs["trace_execve"],
	})
	if err != nil {
		return err
	}
	e.links = append(e.links, execveLink)

	openatLink, err := link.OpenTracepoint(link.TracepointOptions{
		Subsystem: "syscalls",
		Name:      "sys_enter_openat",
		Program:   e.collection.Programs["trace_openat"],
	})
	if err != nil {
		return err
	}
	e.links = append(e.links, openatLink)

	// Start reading events
	go e.readEvents()

	return nil
}

func (e *eBPFLoader) readEvents() {
	// Get the events map
	eventsMap := e.collection.Maps["events"]
	if eventsMap == nil {
		log.Fatal("events map not found")
	}

	// Create perf event reader
	rd, err := eventsMap.NewReader(&ebpf.ReaderOptions{
		PerCPUBuffer: 4096,
		Watermark:    1,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	for {
		record, err := rd.Read()
		if err != nil {
			if err == ebpf.ErrClosed {
				return
			}
			log.Printf("Error reading eBPF events: %v", err)
			continue
		}

		if len(record.RawSample) < int(unsafe.Sizeof(Event{})) {
			continue
		}

		// Parse the event
		var evt Event
		if err := binary.Read(record.RawSample, binary.LittleEndian, &evt); err != nil {
			log.Printf("Error parsing event: %v", err)
			continue
		}

		// Send to channel
		select {
		case e.eventChan <- evt:
		default:
			// Channel full, drop event
		}
	}
}

func (e *eBPFLoader) GetEventChannel() <-chan Event {
	return e.eventChan
}

func (e *eBPFLoader) Close() {
	for _, l := range e.links {
		l.Close()
	}
	e.collection.Close()
	close(e.eventChan)
}

// eBPF event processor for Linux agent
func processeBPFEvents() {
	loader, err := NeweBPFLoader()
	if err != nil {
		log.Printf("Failed to load eBPF: %v", err)
		return
	}
	defer loader.Close()

	if err := loader.Start(); err != nil {
		log.Printf("Failed to start eBPF: %v", err)
		return
	}

	log.Println("eBPF monitoring started")

	// Handle shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case evt := <-loader.GetEventChannel():
			// Convert eBPF event to MUSAFIR event format
			processeBPFEvent(evt)
		case <-sigChan:
			log.Println("Shutting down eBPF monitoring")
			return
		}
	}
}

func processeBPFEvent(evt Event) {
	// Convert to MUSAFIR event format
	event := map[string]interface{}{
		"class":    "process",
		"name":     "syscall",
		"severity": 2,
		"attrs": map[string]interface{}{
			"pid":      evt.Pid,
			"tgid":     evt.Tgid,
			"uid":      evt.Uid,
			"gid":      evt.Gid,
			"comm":     string(evt.Comm[:]),
			"filename": string(evt.Filename[:]),
			"syscall":  evt.Syscall,
			"source":   "ebpf",
		},
	}

	// Send to gateway (reuse existing logic)
	// This would integrate with the existing agent event sending
	log.Printf("eBPF Event: PID=%d, Comm=%s, File=%s", evt.Pid, string(evt.Comm[:]), string(evt.Filename[:]))
}
