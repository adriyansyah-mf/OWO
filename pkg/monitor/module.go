// Package monitor: kernel module load events (init_module, finit_module).
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
	moduleEventsMap = "module_events"
	modInitModule   = 1
	modFinitModule  = 2
)

// ModuleEvent is one kernel module load event.
type ModuleEvent struct {
	Type string // "init_module", "finit_module"
	Pid  uint32
	Uid  uint32
	Comm string
}

// ModuleMonitor loads module_events.o and attaches kprobes.
type ModuleMonitor struct {
	coll   *ebpf.Collection
	links  []link.Link
	reader *ringbuf.Reader
}

// NewModuleMonitor loads from path.
func NewModuleMonitor(objPath string) (*ModuleMonitor, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("module_events load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("module_events new collection: %w", err)
	}
	m, ok := coll.Maps[moduleEventsMap]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("map %s not found", moduleEventsMap)
	}
	var links []link.Link
	for name, progSpec := range spec.Programs {
		prog := coll.Programs[name]
		if prog == nil || progSpec == nil {
			continue
		}
		sym := strings.TrimPrefix(progSpec.SectionName, "kprobe/")
		kp, err := link.Kprobe(sym, prog, nil)
		if err != nil {
			for _, l := range links {
				l.Close()
			}
			coll.Close()
			return nil, fmt.Errorf("attach %s: %w", progSpec.SectionName, err)
		}
		links = append(links, kp)
	}
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		for _, l := range links {
			l.Close()
		}
		coll.Close()
		return nil, err
	}
	return &ModuleMonitor{coll: coll, links: links, reader: rd}, nil
}

// NewModuleMonitorFromEmbed finds bpf/module_events.o and loads.
func NewModuleMonitorFromEmbed() (*ModuleMonitor, error) {
	for _, p := range []string{"bpf/module_events.o", "module_events.o"} {
		if _, err := os.Stat(p); err == nil {
			return NewModuleMonitor(p)
		}
	}
	exe, _ := os.Executable()
	if exe != "" {
		for _, p := range []string{filepath.Join(filepath.Dir(exe), "bpf/module_events.o"), filepath.Join(filepath.Dir(exe), "module_events.o")} {
			if _, err := os.Stat(p); err == nil {
				return NewModuleMonitor(p)
			}
		}
	}
	return nil, fmt.Errorf("module_events.o not found")
}

// ReadModuleEvent blocks until next event.
func (m *ModuleMonitor) ReadModuleEvent() (ModuleEvent, error) {
	var ev ModuleEvent
	rec, err := m.reader.Read()
	if err != nil {
		return ev, err
	}
	raw := rec.RawSample
	if len(raw) < 24 {
		return ev, fmt.Errorf("module event too short")
	}
	typ := raw[0]
	ev.Pid = binary.LittleEndian.Uint32(raw[4:8])
	ev.Uid = binary.LittleEndian.Uint32(raw[8:12])
	ev.Comm = strings.TrimRight(string(raw[12:28]), "\x00")
	if typ == modInitModule {
		ev.Type = "init_module"
	} else {
		ev.Type = "finit_module"
	}
	return ev, nil
}

// Close detaches and closes.
func (m *ModuleMonitor) Close() error {
	if m.reader != nil {
		m.reader.Close()
	}
	for _, l := range m.links {
		l.Close()
	}
	if m.coll != nil {
		m.coll.Close()
	}
	return nil
}
