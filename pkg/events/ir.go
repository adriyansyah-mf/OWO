package events

import "time"

// IRAction is an incident response command.
type IRAction struct {
	ID          string                 `json:"id"`
	TenantID    string                 `json:"tenant_id"`
	HostID      string                 `json:"host_id"`
	Action      string                 `json:"action"` // isolate, release, kill_process, collect_triage
	Params      map[string]interface{}  `json:"params"`
	Status      string                 `json:"status"` // pending, sent, completed, failed
	RequestedBy string                 `json:"requested_by"`
	RequestedAt time.Time              `json:"requested_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Result      string                 `json:"result,omitempty"`
}
