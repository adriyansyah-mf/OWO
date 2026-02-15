// Package monitor: write syscall events (pid, fd, count). Path resolved in userspace via /proc/pid/fd.
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

const writeEventsMap = "write_events"

// WriteEvent is one write syscall event.
type WriteEvent struct {
	Pid   uint32
	Tid   uint32
	Uid   uint32
	Fd    int32
	Count uint64
	Comm  string
	Path  string // resolved from /proc/pid/fd/fd when possible
}

// WriteMonitor loads write_events.o and attaches kprobe.
type WriteMonitor struct {
	coll   *ebpf.Collection
	links  []link.Link
	reader *ringbuf.Reader
}

// NewWriteMonitor loads from path.
func NewWriteMonitor(objPath string) (*WriteMonitor, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("write_events load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("write_events new collection: %w", err)
	}
	m, ok := coll.Maps[writeEventsMap]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("map %s not found", writeEventsMap)
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
	return &WriteMonitor{coll: coll, links: links, reader: rd}, nil
}

// NewWriteMonitorFromEmbed finds bpf/write_events.o and loads.
func NewWriteMonitorFromEmbed() (*WriteMonitor, error) {
	for _, p := range []string{"bpf/write_events.o", "write_events.o"} {
		if _, err := os.Stat(p); err == nil {
			return NewWriteMonitor(p)
		}
	}
	exe, _ := os.Executable()
	if exe != "" {
		for _, p := range []string{filepath.Join(filepath.Dir(exe), "bpf/write_events.o"), filepath.Join(filepath.Dir(exe), "write_events.o")} {
			if _, err := os.Stat(p); err == nil {
				return NewWriteMonitor(p)
			}
		}
	}
	return nil, fmt.Errorf("write_events.o not found")
}

// ReadWriteEvent blocks until next event.
func (w *WriteMonitor) ReadWriteEvent() (WriteEvent, error) {
	var ev WriteEvent
	rec, err := w.reader.Read()
	if err != nil {
		return ev, err
	}
	raw := rec.RawSample
	if len(raw) < 40 {
		return ev, fmt.Errorf("write event too short")
	}
	ev.Pid = binary.LittleEndian.Uint32(raw[4:8])
	ev.Tid = binary.LittleEndian.Uint32(raw[8:12])
	ev.Uid = binary.LittleEndian.Uint32(raw[12:16])
	ev.Fd = int32(binary.LittleEndian.Uint32(raw[20:24]))
	ev.Count = binary.LittleEndian.Uint64(raw[24:32])
	ev.Comm = strings.TrimRight(string(raw[32:48]), "\x00")
	ev.Path = resolveFdPath(ev.Pid, ev.Fd)
	return ev, nil
}

func resolveFdPath(pid uint32, fd int32) string {
	if fd < 0 {
		return ""
	}
	p := fmt.Sprintf("/proc/%d/fd/%d", pid, fd)
	lnk, err := os.Readlink(p)
	if err != nil {
		return ""
	}
	return lnk
}

// Close detaches and closes.
func (w *WriteMonitor) Close() error {
	if w.reader != nil {
		w.reader.Close()
	}
	for _, l := range w.links {
		l.Close()
	}
	if w.coll != nil {
		w.coll.Close()
	}
	return nil
}
