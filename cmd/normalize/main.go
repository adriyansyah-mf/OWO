// Normalize service: consumes raw events, produces ECS-like normalized events for detection.
package main

import (
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"edr-linux/pkg/events"

	"github.com/nats-io/nats.go"
)

func main() {
	natsURL := getEnv("NATS_URL", "nats://localhost:4222")

	nc, err := nats.Connect(natsURL)
	if err != nil {
		log.Fatalf("nats connect: %v", err)
	}
	defer nc.Close()

	sub, err := nc.Subscribe("events.normalize", func(m *nats.Msg) {
		var env events.AgentEnvelope
		if err := json.Unmarshal(m.Data, &env); err != nil {
			log.Printf("unmarshal: %v", err)
			return
		}
		norm := normalize(&env)
		out, err := json.Marshal(norm)
		if err != nil {
			log.Printf("marshal: %v", err)
			return
		}
		if err := nc.Publish("events.detection", out); err != nil {
			log.Printf("publish: %v", err)
		}
	})
	if err != nil {
		log.Fatalf("nats subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	log.Println("normalize: listening on events.normalize")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("normalize: shutdown")
}

func normalize(env *events.AgentEnvelope) *events.NormalizedEvent {
	ev := &env.Event
	hostID := env.AgentHost
	if hostID == "" {
		hostID = env.AgentName
	}
	ts := ev.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	name := filepath.Base(ev.Exe)
	if name == "" {
		name = ev.Comm
	}
	norm := &events.NormalizedEvent{
		Timestamp: ts,
		TenantID:  env.TenantID,
		HostID:    hostID,
		EventID:   eventID(),
		EventType: ev.EventType,
		Process: events.ProcessInfo{
			Pid:         ev.Pid,
			Ppid:       ev.Ppid,
			Executable:  ev.Exe,
			CommandLine: ev.Cmdline,
			Name:        name,
			Start:       ts,
		},
		User: events.UserInfo{ID: strconv.FormatUint(uint64(ev.Uid), 10)},
		Host: events.HostInfo{Hostname: env.AgentHost},
		Threat: events.ThreatInfo{
			Mitre:    ev.MitreAttck,
			GTFOBins: ev.GTFOBins,
		},
		Raw: map[string]interface{}{
			"pid": ev.Pid, "ppid": ev.Ppid, "exe": ev.Exe, "cmdline": ev.Cmdline,
		},
	}
	if ev.SHA256 != "" {
		norm.Process.Hash = &events.HashInfo{SHA256: ev.SHA256}
	}
	if ev.ParentPath != "" || ev.ParentCmd != "" {
		norm.Process.Parent = &events.ProcessInfo{
			Executable:  ev.ParentPath,
			CommandLine: ev.ParentCmd,
		}
	}
	if ev.RemoteAddr != "" {
		norm.Network = &events.NetworkInfo{
			RemoteAddr: ev.RemoteAddr,
			RemotePort: ev.RemotePort,
			LocalPort:  ev.LocalPort,
			Protocol:   ev.Protocol,
		}
	}
	return norm
}

func eventID() string {
	return "ev-" + strconv.FormatInt(time.Now().UnixNano(), 10)
}

func getEnv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
