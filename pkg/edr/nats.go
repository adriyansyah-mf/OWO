// Package edr - NATS output for event streaming.
package edr

import (
	"encoding/json"
	"sync"

	"github.com/nats-io/nats.go"
)

// NatsOutput publishes EventRecord to NATS.
type NatsOutput struct {
	nc     *nats.Conn
	subj   string
	tenant string
	mu     sync.Mutex
}

// NewNatsOutput creates a NATS output. subj e.g. "events.default" or "events.{tenant}".
func NewNatsOutput(nc *nats.Conn, subject, tenantID string) *NatsOutput {
	if subject == "" {
		subject = "events.default"
	}
	if tenantID == "" {
		tenantID = "default"
	}
	return &NatsOutput{nc: nc, subj: subject, tenant: tenantID}
}

// Send publishes the event record. The payload should be EventRecord JSON.
func (n *NatsOutput) Send(_ interface{}, payload []byte) error {
	var rec EventRecord
	if err := json.Unmarshal(payload, &rec); err != nil {
		return err
	}
	env := map[string]interface{}{
		"agent_name":    rec.AgentName,
		"agent_hostname": rec.AgentHost,
		"agent_group":  rec.AgentGroup,
		"tenant_id":    n.tenant,
		"timestamp":    rec.Timestamp,
		"event":        rec.Event,
	}
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return n.nc.Publish(n.subj, b)
}
