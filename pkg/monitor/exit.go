// Package monitor: process exit (exit_group) events.
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

const exitEventsMap = "exit_events"

// ExitEvent is one process exit event.
type ExitEvent struct {
	Pid      uint32
	Tid      uint32
	Uid      uint32
	ExitCode int32
	Comm     string
}

// ExitMonitor loads exit_events.o and attaches kprobe.
type ExitMonitor struct {
	coll   *ebpf.Collection
	links  []link.Link
	reader *ringbuf.Reader
}

// NewExitMonitor loads from path.
func NewExitMonitor(objPath string) (*ExitMonitor, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("exit_events load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("exit_events new collection: %w", err)
	}
	m, ok := coll.Maps[exitEventsMap]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("map %s not found", exitEventsMap)
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
	return &ExitMonitor{coll: coll, links: links, reader: rd}, nil
}

// NewExitMonitorFromEmbed finds bpf/exit_events.o and loads.
func NewExitMonitorFromEmbed() (*ExitMonitor, error) {
	for _, p := range []string{"bpf/exit_events.o", "exit_events.o"} {
		if _, err := os.Stat(p); err == nil {
			return NewExitMonitor(p)
		}
	}
	exe, _ := os.Executable()
	if exe != "" {
		for _, p := range []string{filepath.Join(filepath.Dir(exe), "bpf/exit_events.o"), filepath.Join(filepath.Dir(exe), "exit_events.o")} {
			if _, err := os.Stat(p); err == nil {
				return NewExitMonitor(p)
			}
		}
	}
	return nil, fmt.Errorf("exit_events.o not found")
}

// ReadExitEvent blocks until next event.
func (e *ExitMonitor) ReadExitEvent() (ExitEvent, error) {
	var ev ExitEvent
	rec, err := e.reader.Read()
	if err != nil {
		return ev, err
	}
	raw := rec.RawSample
	if len(raw) < 28 {
		return ev, fmt.Errorf("exit event too short")
	}
	ev.Pid = binary.LittleEndian.Uint32(raw[4:8])
	ev.Tid = binary.LittleEndian.Uint32(raw[8:12])
	ev.Uid = binary.LittleEndian.Uint32(raw[12:16])
	ev.ExitCode = int32(binary.LittleEndian.Uint32(raw[16:20]))
	ev.Comm = strings.TrimRight(string(raw[20:36]), "\x00")
	return ev, nil
}

// Close detaches and closes.
func (e *ExitMonitor) Close() error {
	if e.reader != nil {
		e.reader.Close()
	}
	for _, l := range e.links {
		l.Close()
	}
	if e.coll != nil {
		e.coll.Close()
	}
	return nil
}
