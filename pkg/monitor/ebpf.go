// Package monitor loads eBPF programs and consumes ring buffer events for EDR.
package monitor

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	progName = "trace_execve"
	mapName  = "events"
)

// ExecveEvent is the payload sent from the eBPF program for each execve.
type ExecveEvent struct {
	Pid      uint32
	Tid      uint32
	Uid      uint32
	Gid      uint32
	Ppid     uint32
	Comm     [16]byte
	Filename [256]byte
}

// Monitor holds eBPF collection and ring buffer reader.
type Monitor struct {
	coll   *ebpf.Collection
	link   link.Link
	reader *ringbuf.Reader
}

// New loads the eBPF object from path (e.g. "bpf/execve.o") and attaches the kprobe.
func New(objPath string) (*Monitor, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("load collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new collection: %w", err)
	}

	prog, ok := coll.Programs[progName]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("program %q not found", progName)
	}

	eventsMap, ok := coll.Maps[mapName]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("map %q not found", mapName)
	}

	// Attach kprobe to __x64_sys_execve (x86_64). For arm64 use __arm64_sys_execve.
	kp, err := link.Kprobe("__x64_sys_execve", prog, nil)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach kprobe: %w", err)
	}

	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		kp.Close()
		coll.Close()
		return nil, fmt.Errorf("ringbuf new reader: %w", err)
	}

	return &Monitor{coll: coll, link: kp, reader: reader}, nil
}

// NewFromEmbed tries common paths for execve.o (current dir, bpf/, executable dir).
func NewFromEmbed() (*Monitor, error) {
	candidates := []string{
		"bpf/execve.o",
		"execve.o",
	}
	exe, _ := os.Executable()
	if exe != "" {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(exeDir, "bpf/execve.o"),
			filepath.Join(exeDir, "execve.o"),
		)
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return New(p)
		}
	}
	return nil, fmt.Errorf("execve.o not found in %v", candidates)
}

// Event layout: either old (288 bytes) or new (296 bytes).
// Old: pid, tid, uid, gid (16), comm[16], filename[256]
// New: pid, tid, uid, gid, ppid, pad (24), comm[16], filename[256]
const (
	eventLenOld = 4*4 + 16 + 256   // 288
	eventLenNew = 6*4 + 16 + 256   // 296
)

// ReadEvent blocks until the next event and parses it into ExecveEvent.
func (m *Monitor) ReadEvent() (ExecveEvent, error) {
	var e ExecveEvent
	record, err := m.reader.Read()
	if err != nil {
		return e, err
	}
	raw := record.RawSample
	if len(raw) < eventLenOld {
		return e, fmt.Errorf("event too short (%d < %d)", len(raw), eventLenOld)
	}
	e.Pid = binary.LittleEndian.Uint32(raw[0:4])
	e.Tid = binary.LittleEndian.Uint32(raw[4:8])
	e.Uid = binary.LittleEndian.Uint32(raw[8:12])
	e.Gid = binary.LittleEndian.Uint32(raw[12:16])
	if len(raw) >= eventLenNew {
		e.Ppid = binary.LittleEndian.Uint32(raw[16:20])
		copy(e.Comm[:], raw[24:40])
		copy(e.Filename[:], raw[40:296])
	} else {
		copy(e.Comm[:], raw[16:32])
		copy(e.Filename[:], raw[32:288])
	}
	return e, nil
}

// Close releases the kprobe link and collection.
func (m *Monitor) Close() error {
	if m.reader != nil {
		m.reader.Close()
	}
	if m.link != nil {
		m.link.Close()
	}
	if m.coll != nil {
		m.coll.Close()
	}
	return nil
}
