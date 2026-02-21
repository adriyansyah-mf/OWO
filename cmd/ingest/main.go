// Ingest service: receives events via NATS, upserts hosts, process tree, republishes for detection.
package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"syscall"

	"edr-linux/pkg/events"
	"edr-linux/pkg/store"

	"github.com/nats-io/nats.go"
)

func main() {
	natsURL := getEnv("NATS_URL", "nats://localhost:4222")
	tenantID := getEnv("TENANT_ID", "default")
	postgresDSN := getEnv("POSTGRES_DSN", "")

	ctx := context.Background()
	var storePg *store.PostgresStore
	if postgresDSN != "" {
		var err error
		storePg, err = store.NewPostgres(ctx, postgresDSN)
		if err != nil {
			log.Printf("postgres: %v (hosts/process-tree disabled)", err)
			storePg = nil
		} else {
			defer storePg.Close()
		}
	}

	nc, err := nats.Connect(natsURL)
	if err != nil {
		log.Fatalf("nats connect: %v", err)
	}
	defer nc.Close()

	sub, err := nc.Subscribe("events.>", func(m *nats.Msg) {
		// Only process agent events (events.default, events.{tenant}), not pipeline internal subjects
		if m.Subject == "events.normalize" || m.Subject == "events.detection" {
			return
		}
		var env events.AgentEnvelope
		if err := json.Unmarshal(m.Data, &env); err != nil {
			log.Printf("unmarshal: %v", err)
			return
		}
		if env.TenantID == "" {
			env.TenantID = tenantID
		}
		hostID := env.AgentHost
		if hostID == "" {
			hostID = env.AgentName
		}

		if storePg != nil {
			storePg.UpsertHost(ctx, env.TenantID, hostID, env.AgentHost, env.AgentName)
			ev := &env.Event
			if ev.EventType == "execve" {
				storePg.InsertProcessNode(ctx, env.TenantID, hostID, int(ev.Pid), int(ev.Ppid), ev.Exe, ev.Cmdline, ev.MitreAttck, ev.GTFOBins)
			}
			if ev.EventType == "exit" || ev.EventType == "exit_group" {
				storePg.MarkProcessExit(ctx, hostID, int(ev.Pid))
			}
		}

		out, _ := json.Marshal(env)
		nc.Publish("events.normalize", out)

		if os.Getenv("DEBUG") != "" {
			log.Printf("ingest: %s %s pid=%d", hostID, env.Event.EventType, env.Event.Pid)
		}
	})
	if err != nil {
		log.Fatalf("nats subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	log.Printf("ingest: listening on events.> (tenant=%s)", tenantID)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("ingest: shutdown")
}

func getEnv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
