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
		if m.Subject == "events.normalize" || m.Subject == "events.detection" {
			return
		}
		agentSubj := "events." + tenantID
		if tenantID == "" {
			agentSubj = "events.default"
		}
		if m.Subject != "events.default" && m.Subject != agentSubj {
			return
		}
		var raw map[string]interface{}
		if err := json.Unmarshal(m.Data, &raw); err != nil {
			log.Printf("unmarshal: %v", err)
			return
		}
		agentHost, _ := raw["agent_hostname"].(string)
		agentName, _ := raw["agent_name"].(string)
		if agentHost == "" {
			agentHost = agentName
		}
		hostID := agentHost
		tenID, _ := raw["tenant_id"].(string)
		if tenID == "" {
			tenID = tenantID
		}
		ev, _ := raw["event"].(map[string]interface{})
		evType, _ := ev["event_type"].(string)

		if evType == "process_snapshot" {
			if storePg != nil {
				storePg.UpsertHost(ctx, tenID, hostID, agentHost, agentName)
				procs, _ := ev["processes"].([]interface{})
				var procMaps []map[string]interface{}
				for _, p := range procs {
					pm, ok := p.(map[string]interface{})
					if !ok {
						continue
					}
					procMaps = append(procMaps, pm)
				}
				if len(procMaps) > 0 {
					if err := storePg.ReplaceProcessTree(ctx, tenID, hostID, procMaps); err != nil {
						log.Printf("ReplaceProcessTree: %v", err)
					} else if os.Getenv("DEBUG") != "" {
						log.Printf("ingest: %s process_snapshot %d procs", hostID, len(procMaps))
					}
				}
			}
			return
		}

		var env events.AgentEnvelope
		if err := json.Unmarshal(m.Data, &env); err != nil {
			log.Printf("ingest: unmarshal AgentEnvelope: %v (subject=%s)", err, m.Subject)
			return
		}
		if env.TenantID == "" {
			env.TenantID = tenantID
		}
		if storePg != nil {
			storePg.UpsertHost(ctx, env.TenantID, hostID, env.AgentHost, env.AgentName)
		}
		out, _ := json.Marshal(env)
		nc.Publish("events.normalize", out)
		if os.Getenv("DEBUG") != "" {
			log.Printf("ingest: %s %s pid=%v", hostID, env.Event.EventType, env.Event.Pid)
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
