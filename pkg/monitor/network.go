// Package monitor: network events (connect, sendto) for correlation.
package monitor

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	networkEventsMap = "network_events"
	netEventConnect  = 1
	netEventSendto   = 2
	netEventAccept   = 3
	afINET           = 2
	afINET6          = 10
)

// NetworkEvent is one connect, sendto, or accept (inbound) event.
type NetworkEvent struct {
	Type     string // "connect", "sendto", "accept"
	Pid      uint32
	Tid      uint32
	Uid      uint32
	Family   string // "inet", "inet6"
	DAddr    string // "ip:port" (peer for accept)
	DPort    uint16
	Comm     string
	IsDNS    bool   // true when port 53
}

// NetworkMonitor loads network_events.o and attaches connect/sendto kprobes.
type NetworkMonitor struct {
	coll   *ebpf.Collection
	links  []link.Link
	reader *ringbuf.Reader
}

// NewNetworkMonitor loads from path (e.g. "bpf/network_events.o").
func NewNetworkMonitor(objPath string) (*NetworkMonitor, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("network_events load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("network_events new collection: %w", err)
	}
	m, ok := coll.Maps[networkEventsMap]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("map %s not found", networkEventsMap)
	}
	var links []link.Link
	for name, progSpec := range spec.Programs {
		prog := coll.Programs[name]
		if prog == nil || progSpec == nil {
			continue
		}
		sec := progSpec.SectionName
		var l link.Link
		if strings.HasPrefix(sec, "tracepoint/") {
			// tracepoint/syscalls/sys_enter_connect -> group=syscalls, name=sys_enter_connect
			parts := strings.SplitN(sec, "/", 3)
			if len(parts) != 3 {
				continue
			}
			l, err = link.Tracepoint(parts[1], parts[2], prog, nil)
		} else if strings.HasPrefix(sec, "kretprobe/") {
			sym := strings.TrimPrefix(sec, "kretprobe/")
			l, err = link.Kretprobe(sym, prog, nil)
		} else if strings.HasPrefix(sec, "kprobe/") {
			sym := strings.TrimPrefix(sec, "kprobe/")
			l, err = link.Kprobe(sym, prog, nil)
		} else {
			continue
		}
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
	return &NetworkMonitor{coll: coll, links: links, reader: rd}, nil
}

// NewNetworkMonitorFromEmbed finds bpf/network_events.o and loads.
func NewNetworkMonitorFromEmbed() (*NetworkMonitor, error) {
	for _, p := range []string{"bpf/network_events.o", "network_events.o"} {
		if _, err := os.Stat(p); err == nil {
			return NewNetworkMonitor(p)
		}
	}
	exe, _ := os.Executable()
	if exe != "" {
		for _, p := range []string{filepath.Join(filepath.Dir(exe), "bpf/network_events.o"), filepath.Join(filepath.Dir(exe), "network_events.o")} {
			if _, err := os.Stat(p); err == nil {
				return NewNetworkMonitor(p)
			}
		}
	}
	return nil, fmt.Errorf("network_events.o not found")
}

// ReadNetworkEvent blocks until next network event.
func (n *NetworkMonitor) ReadNetworkEvent() (NetworkEvent, error) {
	var ev NetworkEvent
	rec, err := n.reader.Read()
	if err != nil {
		return ev, err
	}
	raw := rec.RawSample
	// network_event_t: type(1)+family(1)+dport(2)+pid(4)+tid(4)+uid(4)+saddr(4)+daddr(4)+daddr_v6(16)+comm(16)=56
	if len(raw) < 56 {
		return ev, fmt.Errorf("network event too short (%d < 56)", len(raw))
	}
	typ := raw[0]
	family := raw[1]
	ev.DPort = binary.LittleEndian.Uint16(raw[2:4])
	ev.Pid = binary.LittleEndian.Uint32(raw[4:8])
	ev.Tid = binary.LittleEndian.Uint32(raw[8:12])
	ev.Uid = binary.LittleEndian.Uint32(raw[12:16])
	ev.Comm = strings.TrimRight(string(raw[40:56]), "\x00")
	switch typ {
	case netEventConnect:
		ev.Type = "connect"
	case netEventSendto:
		ev.Type = "sendto"
	case netEventAccept:
		ev.Type = "accept"
	default:
		ev.Type = "unknown"
	}
	ev.IsDNS = ev.DPort == 53
	if family == afINET {
		ev.Family = "inet"
		ev.DAddr = net.IP(raw[20:24]).To4().String() + ":" + fmt.Sprintf("%d", ev.DPort)
	} else if family == afINET6 {
		ev.Family = "inet6"
		ev.DAddr = "[" + net.IP(raw[24:40]).String() + "]:" + fmt.Sprintf("%d", ev.DPort)
	} else {
		ev.Family = "unknown"
		ev.DAddr = fmt.Sprintf("?:%d", ev.DPort)
	}
	return ev, nil
}

// Close detaches and closes.
func (n *NetworkMonitor) Close() error {
	if n.reader != nil {
		n.reader.Close()
	}
	for _, l := range n.links {
		l.Close()
	}
	if n.coll != nil {
		n.coll.Close()
	}
	return nil
}
