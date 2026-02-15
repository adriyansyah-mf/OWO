// Package monitor: privilege change events (setuid, setgid, setreuid, setregid).
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
	privilegeEventsMap = "privilege_events"
	privSetuid         = 1
	privSetgid         = 2
	privSetreuid       = 3
	privSetregid       = 4
	privSetresuid      = 5
	privSetresgid      = 6
)

// PrivilegeEvent is one privilege change event.
type PrivilegeEvent struct {
	Type   string // "setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid"
	Pid    uint32
	Tid    uint32
	Uid    uint32
	Gid    uint32
	NewUid uint32
	NewGid uint32
	Comm   string
}

// PrivilegeMonitor loads privilege_events.o and attaches kprobes.
type PrivilegeMonitor struct {
	coll   *ebpf.Collection
	links  []link.Link
	reader *ringbuf.Reader
}

// NewPrivilegeMonitor loads from path.
func NewPrivilegeMonitor(objPath string) (*PrivilegeMonitor, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("privilege_events load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("privilege_events new collection: %w", err)
	}
	m, ok := coll.Maps[privilegeEventsMap]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("map %s not found", privilegeEventsMap)
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
	return &PrivilegeMonitor{coll: coll, links: links, reader: rd}, nil
}

// NewPrivilegeMonitorFromEmbed finds bpf/privilege_events.o and loads.
func NewPrivilegeMonitorFromEmbed() (*PrivilegeMonitor, error) {
	for _, p := range []string{"bpf/privilege_events.o", "privilege_events.o"} {
		if _, err := os.Stat(p); err == nil {
			return NewPrivilegeMonitor(p)
		}
	}
	exe, _ := os.Executable()
	if exe != "" {
		for _, p := range []string{filepath.Join(filepath.Dir(exe), "bpf/privilege_events.o"), filepath.Join(filepath.Dir(exe), "privilege_events.o")} {
			if _, err := os.Stat(p); err == nil {
				return NewPrivilegeMonitor(p)
			}
		}
	}
	return nil, fmt.Errorf("privilege_events.o not found")
}

// ReadPrivilegeEvent blocks until next event.
func (p *PrivilegeMonitor) ReadPrivilegeEvent() (PrivilegeEvent, error) {
	var ev PrivilegeEvent
	rec, err := p.reader.Read()
	if err != nil {
		return ev, err
	}
	raw := rec.RawSample
	if len(raw) < 32 {
		return ev, fmt.Errorf("privilege event too short")
	}
	typ := raw[0]
	ev.Pid = binary.LittleEndian.Uint32(raw[4:8])
	ev.Tid = binary.LittleEndian.Uint32(raw[8:12])
	ev.Uid = binary.LittleEndian.Uint32(raw[12:16])
	ev.Gid = binary.LittleEndian.Uint32(raw[16:20])
	ev.NewUid = binary.LittleEndian.Uint32(raw[20:24])
	ev.NewGid = binary.LittleEndian.Uint32(raw[24:28])
	ev.Comm = strings.TrimRight(string(raw[28:44]), "\x00")
	switch typ {
	case privSetuid:
		ev.Type = "setuid"
	case privSetgid:
		ev.Type = "setgid"
	case privSetreuid:
		ev.Type = "setreuid"
	case privSetregid:
		ev.Type = "setregid"
	case privSetresuid:
		ev.Type = "setresuid"
	case privSetresgid:
		ev.Type = "setresgid"
	default:
		ev.Type = "unknown"
	}
	return ev, nil
}

// Close detaches and closes.
func (p *PrivilegeMonitor) Close() error {
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
