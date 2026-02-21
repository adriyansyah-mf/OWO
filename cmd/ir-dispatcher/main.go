// IR Dispatcher: receives IR commands via API/NATS, publishes to agent subjects.
package main

import (
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"syscall"

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

	sub, err := nc.Subscribe("ir.commands", func(m *nats.Msg) {
		var cmd events.IRAction
		if err := json.Unmarshal(m.Data, &cmd); err != nil {
			log.Printf("unmarshal: %v", err)
			return
		}
		subject := "ir." + cmd.TenantID + "." + cmd.HostID
		if err := nc.Publish(subject, m.Data); err != nil {
			log.Printf("publish %s: %v", subject, err)
		} else {
			log.Printf("ir: dispatched %s to %s", cmd.Action, cmd.HostID)
		}
	})
	if err != nil {
		log.Fatalf("nats subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	log.Println("ir-dispatcher: listening on ir.commands")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("ir-dispatcher: shutdown")
}

func getEnv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
