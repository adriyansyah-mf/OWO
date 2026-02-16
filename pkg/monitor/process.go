// Package monitor: process creation (fork, clone, clone3) via tracepoint sys_exit_*.
package monitor

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	processEventsMap   = "process_events"
	processTypeFork    = 1
	processTypeClone   = 2
	processTypeClone3  = 3
)

// ProcessEvent is one fork/clone/clone3 event (parent -> child).
type ProcessEvent struct {
	Type       string // "fork", "clone", "clone3"
	ParentPid  uint32
	ParentTid  uint32
	ChildPid   uint32
	Uid        uint32
	Comm       string
}

// ProcessMonitor loads process_events.o and attaches sys_exit_fork/clone/clone3 tracepoints.
type ProcessMonitor struct {
	coll   *ebpf.Collection
	links  []link.Link
	reader *ringbuf.Reader
}

// NewProcessMonitor loads from path.
func NewProcessMonitor(objPath string) (*ProcessMonitor, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("process_events load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("process_events new collection: %w", err)
	}
	m, ok := coll.Maps[processEventsMap]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("map %s not found", processEventsMap)
	}
	var links []link.Link
	for name, progSpec := range spec.Programs {
		prog := coll.Programs[name]
		if prog == nil || progSpec == nil {
			continue
		}
		sec := progSpec.SectionName
		if !strings.HasPrefix(sec, "tracepoint/") {
			continue
		}
		parts := strings.SplitN(sec, "/", 3)
		if len(parts) != 3 {
			continue
		}
		l, err := link.Tracepoint(parts[1], parts[2], prog, nil)
		if err != nil {
			for _, lnk := range links {
				lnk.Close()
			}
			coll.Close()
			return nil, fmt.Errorf("attach %s: %w", sec, err)
		}
		links = append(links, l)
	}
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		for _, l := range links {
			l.Close()
		}
		coll.Close()
		return nil, err
	}
	return &ProcessMonitor{coll: coll, links: links, reader: rd}, nil
}

// NewProcessMonitorFromEmbed finds bpf/process_events.o and loads.
func NewProcessMonitorFromEmbed() (*ProcessMonitor, error) {
	for _, p := range []string{"bpf/process_events.o", "process_events.o"} {
		if _, err := os.Stat(p); err == nil {
			return NewProcessMonitor(p)
		}
	}
	exe, _ := os.Executable()
	if exe != "" {
		for _, p := range []string{filepath.Join(filepath.Dir(exe), "bpf/process_events.o"), filepath.Join(filepath.Dir(exe), "process_events.o")} {
			if _, err := os.Stat(p); err == nil {
				return NewProcessMonitor(p)
			}
		}
	}
	return nil, fmt.Errorf("process_events.o not found")
}

// ReadProcessEvent blocks until next event.
func (p *ProcessMonitor) ReadProcessEvent() (ProcessEvent, error) {
	var ev ProcessEvent
	rec, err := p.reader.Read()
	if err != nil {
		return ev, err
	}
	raw := rec.RawSample
	if len(raw) < 32 {
		return ev, fmt.Errorf("process event too short")
	}
	typ := raw[0]
	ev.ParentPid = binary.LittleEndian.Uint32(raw[4:8])
	ev.ParentTid = binary.LittleEndian.Uint32(raw[8:12])
	ev.ChildPid = binary.LittleEndian.Uint32(raw[12:16])
	ev.Uid = binary.LittleEndian.Uint32(raw[16:20])
	ev.Comm = strings.TrimRight(string(raw[20:36]), "\x00")
	switch typ {
	case processTypeFork:
		ev.Type = "fork"
	case processTypeClone:
		ev.Type = "clone"
	case processTypeClone3:
		ev.Type = "clone3"
	default:
		ev.Type = "unknown"
	}
	return ev, nil
}

// Close detaches and closes.
func (p *ProcessMonitor) Close() error {
	if p.reader != nil {
		p.reader.Close()
	}
	for _, l := range p.links {
		l.Close()
	}
	if p.coll != nil {
		p.coll.Close()
	}
	return nil
}
