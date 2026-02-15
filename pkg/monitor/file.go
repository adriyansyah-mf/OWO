// Package monitor: file events (openat, unlink, rename) on watched paths.
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
	fileEventsMap   = "file_events"
	fileConfigMap   = "file_config"
	fileEventOpen   = 1
	fileEventUnlink = 2
	fileEventRename = 3
)

// FileEvent is one file operation event.
type FileEvent struct {
	Type   string // "openat", "unlink", "rename"
	Pid    uint32
	Tid    uint32
	Uid    uint32
	Path   string
	Path2  string // for rename
	Comm   string
}

// FileMonitor loads file_events.o and attaches openat/unlink/rename kprobes.
type FileMonitor struct {
	coll   *ebpf.Collection
	links  []link.Link
	reader *ringbuf.Reader
}

// NewFileMonitor loads from path (e.g. "bpf/file_events.o"). If watchAllPaths is true, all absolute paths are monitored; else only /etc,/usr/bin,/bin,/tmp,/dev/shm.
func NewFileMonitor(objPath string, watchAllPaths bool) (*FileMonitor, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("file_events load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("file_events new collection: %w", err)
	}
	m, ok := coll.Maps[fileEventsMap]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("map %s not found", fileEventsMap)
	}
	if watchAllPaths {
		if cfgMap, ok := coll.Maps[fileConfigMap]; ok {
			var val uint32 = 1
			_ = cfgMap.Put(uint32(0), val)
		}
	}
	var links []link.Link
	for name, prog := range coll.Programs {
		if prog == nil {
			continue
		}
		kp, err := link.Kprobe(name, prog, nil)
		if err != nil {
			for _, l := range links {
				l.Close()
			}
			coll.Close()
			return nil, fmt.Errorf("attach %s: %w", name, err)
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
	return &FileMonitor{coll: coll, links: links, reader: rd}, nil
}

// NewFileMonitorFromEmbed finds bpf/file_events.o and loads. watchAllPaths: false = only watched paths.
func NewFileMonitorFromEmbed(watchAllPaths bool) (*FileMonitor, error) {
	for _, p := range []string{"bpf/file_events.o", "file_events.o"} {
		if _, err := os.Stat(p); err == nil {
			return NewFileMonitor(p, watchAllPaths)
		}
	}
	exe, _ := os.Executable()
	if exe != "" {
		for _, p := range []string{filepath.Join(filepath.Dir(exe), "bpf/file_events.o"), filepath.Join(filepath.Dir(exe), "file_events.o")} {
			if _, err := os.Stat(p); err == nil {
				return NewFileMonitor(p, watchAllPaths)
			}
		}
	}
	return nil, fmt.Errorf("file_events.o not found")
}

// ReadFileEvent blocks until next file event.
func (f *FileMonitor) ReadFileEvent() (FileEvent, error) {
	var ev FileEvent
	rec, err := f.reader.Read()
	if err != nil {
		return ev, err
	}
	raw := rec.RawSample
	const minLen = 20 + 256 + 256 + 16
	if len(raw) < minLen {
		return ev, fmt.Errorf("file event too short")
	}
	typ := raw[0]
	ev.Pid = binary.LittleEndian.Uint32(raw[4:8])
	ev.Tid = binary.LittleEndian.Uint32(raw[8:12])
	ev.Uid = binary.LittleEndian.Uint32(raw[12:16])
	ev.Path = strings.TrimRight(string(raw[20:276]), "\x00")
	ev.Path2 = strings.TrimRight(string(raw[276:532]), "\x00")
	ev.Comm = strings.TrimRight(string(raw[532:548]), "\x00")
	switch typ {
	case fileEventOpen:
		ev.Type = "openat"
	case fileEventUnlink:
		ev.Type = "unlink"
	case fileEventRename:
		ev.Type = "rename"
	default:
		ev.Type = "unknown"
	}
	return ev, nil
}

// Close detaches and closes.
func (f *FileMonitor) Close() error {
	if f.reader != nil {
		f.reader.Close()
	}
	for _, l := range f.links {
		l.Close()
	}
	if f.coll != nil {
		f.coll.Close()
	}
	return nil
}
