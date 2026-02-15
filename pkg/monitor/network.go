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
	afINET           = 2
	afINET6          = 10
)

// NetworkEvent is one connect or sendto event.
type NetworkEvent struct {
	Type     string // "connect", "sendto"
	Pid      uint32
	Tid      uint32
	Uid      uint32
	Family   string // "inet", "inet6"
	DAddr    string // "ip:port"
	DPort    uint16
	Comm     string
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
	if len(raw) < 60 {
		return ev, fmt.Errorf("network event too short")
	}
	typ := raw[0]
	family := raw[1]
	ev.DPort = binary.LittleEndian.Uint16(raw[2:4])
	ev.Pid = binary.LittleEndian.Uint32(raw[4:8])
	ev.Tid = binary.LittleEndian.Uint32(raw[8:12])
	ev.Uid = binary.LittleEndian.Uint32(raw[12:16])
	ev.Comm = strings.TrimRight(string(raw[40:56]), "\x00")
	if typ == netEventConnect {
		ev.Type = "connect"
	} else {
		ev.Type = "sendto"
	}
	if family == afINET {
		ev.Family = "inet"
		ev.DAddr = net.IP(raw[20:24]).To4().String() + ":" + fmt.Sprintf("%d", ev.DPort)
	} else if family == afINET6 {
		ev.Family = "inet6"
		ev.DAddr = "[" + net.IP(raw[24:40]).String() + "]:" + fmt.Sprintf("%d", ev.DPort)
	} else {
		ev.DAddr = fmt.Sprintf(":%d", ev.DPort)
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
