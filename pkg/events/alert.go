package events

import "time"

// Alert is a detection engine output.
type Alert struct {
	ID        string                 `json:"id"`
	TenantID  string                 `json:"tenant_id"`
	HostID    string                 `json:"host_id"`
	RuleID    string                 `json:"rule_id"`
	RuleName  string                 `json:"rule_name"`
	Severity  string                 `json:"severity"`
	Title     string                 `json:"title"`
	Message   string                 `json:"message"`
	EventJSON map[string]interface{} `json:"event_json,omitempty"`
	Mitre     []string               `json:"mitre,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
}
