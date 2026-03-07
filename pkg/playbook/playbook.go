// Package playbook provides automated response playbooks for the EDR platform.
//
// A Playbook defines a set of conditions evaluated against incoming alerts.
// When all conditions match, the playbook fires a sequence of actions.
//
// Conditions match on:
//   - severity (e.g. "critical", "high")
//   - rule_id  (exact or prefix match)
//   - host_id  (exact match)
//   - mitre_tag (any of the alert's MITRE tags starts with the condition value)
//   - attack_chain (incident attack chain name, if correlation is available)
//   - source_ip (alert event source IP)
//
// Actions available:
//   - isolate_host  — publish ir.commands isolate to NATS
//   - notify        — fire a named webhook channel
//   - tag_ioc       — add alert source_ip/domain to IOC store
//   - create_ticket — placeholder for ticketing system integration
package playbook

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ─── Types ────────────────────────────────────────────────────────────────────

// ConditionField defines which alert field to match.
type ConditionField string

const (
	FieldSeverity    ConditionField = "severity"
	FieldRuleID      ConditionField = "rule_id"
	FieldHostID      ConditionField = "host_id"
	FieldMitreTag    ConditionField = "mitre_tag"
	FieldAttackChain ConditionField = "attack_chain"
	FieldSourceIP    ConditionField = "source_ip"
	FieldTenantID    ConditionField = "tenant_id"
)

// ConditionOp is the comparison operator.
type ConditionOp string

const (
	OpEquals     ConditionOp = "eq"
	OpContains   ConditionOp = "contains"
	OpStartsWith ConditionOp = "startswith"
	OpIn         ConditionOp = "in" // value is comma-separated list
)

// Condition is a single match predicate.
type Condition struct {
	Field ConditionField `json:"field"`
	Op    ConditionOp    `json:"op"`
	Value string         `json:"value"`
}

// ActionType defines what a playbook action does.
type ActionType string

const (
	ActionIsolateHost  ActionType = "isolate_host"
	ActionNotify       ActionType = "notify"        // params: channel name(s), message template
	ActionTagIOC       ActionType = "tag_ioc"        // params: ioc_field (source_ip/domain), severity, source
	ActionCreateTicket ActionType = "create_ticket"  // placeholder
)

// Action is a single response step.
type Action struct {
	Type   ActionType        `json:"type"`
	Params map[string]string `json:"params,omitempty"`
}

// Playbook is a named rule with conditions and actions.
type Playbook struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Enabled     bool        `json:"enabled"`
	Conditions  []Condition `json:"conditions"`
	// ConditionMode: "all" (AND, default) or "any" (OR)
	ConditionMode string   `json:"condition_mode,omitempty"`
	Actions       []Action `json:"actions"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
	FireCount     int       `json:"fire_count"`
	LastFiredAt   *time.Time `json:"last_fired_at,omitempty"`
}

// FiredEvent records a single playbook execution.
type FiredEvent struct {
	PlaybookID   string    `json:"playbook_id"`
	PlaybookName string    `json:"playbook_name"`
	AlertID      string    `json:"alert_id,omitempty"`
	HostID       string    `json:"host_id,omitempty"`
	TenantID     string    `json:"tenant_id,omitempty"`
	ActionsRun   []string  `json:"actions_run"`
	FiredAt      time.Time `json:"fired_at"`
}

// ─── ActionHandler ────────────────────────────────────────────────────────────

// ActionHandler is a callback invoked when a playbook fires an action.
// It receives the action and the alert that triggered it.
// Return an error to abort remaining actions in the sequence (non-fatal).
type ActionHandler func(action Action, alert map[string]interface{}) error

// ─── Engine ───────────────────────────────────────────────────────────────────

// Engine manages playbooks and evaluates them against incoming alerts.
type Engine struct {
	mu        sync.RWMutex
	playbooks map[string]*Playbook
	history   []FiredEvent // ring buffer, max historyMax entries
	historyMu sync.RWMutex
	storePath string
	handlers  map[ActionType]ActionHandler
}

const historyMax = 500

// New creates a new Engine. storePath is the JSON persistence file.
func New(storePath string) *Engine {
	e := &Engine{
		playbooks: make(map[string]*Playbook),
		handlers:  make(map[ActionType]ActionHandler),
		storePath: storePath,
	}
	if storePath != "" {
		_ = e.load()
	}
	return e
}

// RegisterHandler registers a callback for a given action type.
// Call this before starting alert ingestion.
func (e *Engine) RegisterHandler(t ActionType, h ActionHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.handlers[t] = h
}

// ─── Evaluate ─────────────────────────────────────────────────────────────────

// Evaluate checks all enabled playbooks against the alert.
// It fires matching playbooks synchronously and records execution history.
// Returns the list of playbook IDs that fired.
func (e *Engine) Evaluate(alert map[string]interface{}) []string {
	e.mu.RLock()
	pbs := make([]*Playbook, 0, len(e.playbooks))
	for _, pb := range e.playbooks {
		if pb.Enabled {
			pbs = append(pbs, pb)
		}
	}
	e.mu.RUnlock()

	var fired []string
	for _, pb := range pbs {
		if e.matches(pb, alert) {
			actionsRun := e.fire(pb, alert)
			fired = append(fired, pb.ID)

			alertID, _ := alert["id"].(string)
			hostID, _ := alert["host_id"].(string)
			tenantID, _ := alert["tenant_id"].(string)

			ev := FiredEvent{
				PlaybookID:   pb.ID,
				PlaybookName: pb.Name,
				AlertID:      alertID,
				HostID:       hostID,
				TenantID:     tenantID,
				ActionsRun:   actionsRun,
				FiredAt:      time.Now().UTC(),
			}
			e.historyMu.Lock()
			e.history = append(e.history, ev)
			if len(e.history) > historyMax {
				e.history = e.history[len(e.history)-historyMax:]
			}
			e.historyMu.Unlock()

			e.mu.Lock()
			pb.FireCount++
			now := time.Now().UTC()
			pb.LastFiredAt = &now
			e.mu.Unlock()
		}
	}
	if len(fired) > 0 {
		e.mu.RLock()
		_ = e.save()
		e.mu.RUnlock()
	}
	return fired
}

func (e *Engine) matches(pb *Playbook, alert map[string]interface{}) bool {
	if len(pb.Conditions) == 0 {
		return false // safety: don't fire on empty conditions
	}
	mode := pb.ConditionMode
	if mode == "" {
		mode = "all"
	}
	for _, cond := range pb.Conditions {
		result := e.evalCondition(cond, alert)
		if mode == "any" && result {
			return true
		}
		if mode == "all" && !result {
			return false
		}
	}
	return mode == "all" // all matched, or any found none
}

func (e *Engine) evalCondition(cond Condition, alert map[string]interface{}) bool {
	var fieldVal string
	switch cond.Field {
	case FieldSeverity:
		fieldVal, _ = alert["severity"].(string)
	case FieldRuleID:
		fieldVal, _ = alert["rule_id"].(string)
	case FieldHostID:
		fieldVal, _ = alert["host_id"].(string)
	case FieldTenantID:
		fieldVal, _ = alert["tenant_id"].(string)
	case FieldAttackChain:
		fieldVal, _ = alert["attack_chain"].(string)
	case FieldSourceIP:
		// Try nested event_json.src_ip
		if ev, ok := alert["event_json"].(map[string]interface{}); ok {
			fieldVal, _ = ev["src_ip"].(string)
		}
		if fieldVal == "" {
			fieldVal, _ = alert["source_ip"].(string)
		}
	case FieldMitreTag:
		// Special: check if ANY of the alert's MITRE tags match
		if tags, ok := alert["mitre"].([]interface{}); ok {
			for _, t := range tags {
				ts, _ := t.(string)
				if matchOp(cond.Op, ts, cond.Value) {
					return true
				}
			}
		}
		if strTags, ok := alert["mitre"].([]string); ok {
			for _, ts := range strTags {
				if matchOp(cond.Op, ts, cond.Value) {
					return true
				}
			}
		}
		return false
	default:
		return false
	}
	return matchOp(cond.Op, fieldVal, cond.Value)
}

func matchOp(op ConditionOp, fieldVal, condVal string) bool {
	fieldVal = strings.ToLower(fieldVal)
	condVal = strings.ToLower(condVal)
	switch op {
	case OpEquals, "":
		return fieldVal == condVal
	case OpContains:
		return strings.Contains(fieldVal, condVal)
	case OpStartsWith:
		return strings.HasPrefix(fieldVal, condVal)
	case OpIn:
		for _, v := range strings.Split(condVal, ",") {
			if strings.TrimSpace(v) == fieldVal {
				return true
			}
		}
		return false
	default:
		return fieldVal == condVal
	}
}

func (e *Engine) fire(pb *Playbook, alert map[string]interface{}) []string {
	var run []string
	for _, action := range pb.Actions {
		e.mu.RLock()
		h := e.handlers[action.Type]
		e.mu.RUnlock()
		if h == nil {
			run = append(run, string(action.Type)+"(no_handler)")
			continue
		}
		err := h(action, alert)
		if err != nil {
			run = append(run, string(action.Type)+"(err:"+err.Error()+")")
		} else {
			run = append(run, string(action.Type))
		}
	}
	return run
}

// ─── CRUD ─────────────────────────────────────────────────────────────────────

// Add creates or replaces a playbook (upsert by ID).
func (e *Engine) Add(pb Playbook) Playbook {
	e.mu.Lock()
	defer e.mu.Unlock()
	if pb.ID == "" {
		pb.ID = newID()
		pb.CreatedAt = time.Now().UTC()
	} else if existing, ok := e.playbooks[pb.ID]; ok {
		pb.CreatedAt = existing.CreatedAt
		pb.FireCount = existing.FireCount
		pb.LastFiredAt = existing.LastFiredAt
	}
	pb.UpdatedAt = time.Now().UTC()
	e.playbooks[pb.ID] = &pb
	_ = e.save()
	return pb
}

// Remove deletes a playbook by ID.
func (e *Engine) Remove(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.playbooks[id]; !ok {
		return fmt.Errorf("playbook not found: %s", id)
	}
	delete(e.playbooks, id)
	return e.save()
}

// SetEnabled toggles a playbook on or off.
func (e *Engine) SetEnabled(id string, enabled bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	pb, ok := e.playbooks[id]
	if !ok {
		return fmt.Errorf("playbook not found: %s", id)
	}
	pb.Enabled = enabled
	pb.UpdatedAt = time.Now().UTC()
	return e.save()
}

// List returns all playbooks sorted by name.
func (e *Engine) List() []Playbook {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Playbook, 0, len(e.playbooks))
	for _, pb := range e.playbooks {
		out = append(out, *pb)
	}
	return out
}

// GetByID returns a playbook by ID.
func (e *Engine) GetByID(id string) (Playbook, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	pb, ok := e.playbooks[id]
	if !ok {
		return Playbook{}, false
	}
	return *pb, true
}

// History returns recent fired events (newest first, up to limit).
func (e *Engine) History(limit int) []FiredEvent {
	e.historyMu.RLock()
	defer e.historyMu.RUnlock()
	if limit <= 0 || limit > len(e.history) {
		limit = len(e.history)
	}
	out := make([]FiredEvent, limit)
	// Return newest first
	src := e.history
	for i := 0; i < limit; i++ {
		out[i] = src[len(src)-1-i]
	}
	return out
}

// Stats returns summary counts.
func (e *Engine) Stats() map[string]interface{} {
	e.mu.RLock()
	total := len(e.playbooks)
	enabled := 0
	totalFires := 0
	for _, pb := range e.playbooks {
		if pb.Enabled {
			enabled++
		}
		totalFires += pb.FireCount
	}
	e.mu.RUnlock()
	e.historyMu.RLock()
	histLen := len(e.history)
	e.historyMu.RUnlock()
	return map[string]interface{}{
		"total":        total,
		"enabled":      enabled,
		"total_fires":  totalFires,
		"history_size": histLen,
	}
}

// ─── Default playbooks ────────────────────────────────────────────────────────

// DefaultPlaybooks returns a set of built-in starter playbooks (disabled by default).
func DefaultPlaybooks() []Playbook {
	return []Playbook{
		{
			ID:          "pb-auto-isolate-critical",
			Name:        "Auto-Isolate on Critical + Attack Chain",
			Description: "Automatically isolate a host when a critical incident with an attack chain is detected.",
			Enabled:     false,
			ConditionMode: "all",
			Conditions: []Condition{
				{Field: FieldSeverity, Op: OpEquals, Value: "critical"},
				{Field: FieldAttackChain, Op: OpContains, Value: ""},
			},
			Actions: []Action{
				{Type: ActionIsolateHost},
				{Type: ActionNotify, Params: map[string]string{"message": "AUTO-ISOLATE: Critical attack chain detected on {{host_id}}"}},
			},
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		},
		{
			ID:          "pb-notify-critical",
			Name:        "Notify on Critical Alert",
			Description: "Send a webhook notification for every critical severity alert.",
			Enabled:     false,
			ConditionMode: "all",
			Conditions: []Condition{
				{Field: FieldSeverity, Op: OpEquals, Value: "critical"},
			},
			Actions: []Action{
				{Type: ActionNotify, Params: map[string]string{"message": "CRITICAL ALERT: {{title}} on {{host_id}} (rule: {{rule_id}})"}},
			},
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		},
		{
			ID:          "pb-tag-ioc-malware",
			Name:        "Tag Malware Source as IOC",
			Description: "Automatically add the source IP to the IOC database when malware is detected.",
			Enabled:     false,
			ConditionMode: "all",
			Conditions: []Condition{
				{Field: FieldRuleID, Op: OpEquals, Value: "malware_detected"},
			},
			Actions: []Action{
				{Type: ActionTagIOC, Params: map[string]string{"ioc_field": "source_ip", "severity": "high", "source": "auto-playbook"}},
			},
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		},
		{
			ID:          "pb-notify-lateral-movement",
			Name:        "Notify on Lateral Movement",
			Description: "Send webhook when Credential Access + Lateral Movement attack chain is detected.",
			Enabled:     false,
			ConditionMode: "all",
			Conditions: []Condition{
				{Field: FieldAttackChain, Op: OpContains, Value: "lateral movement"},
			},
			Actions: []Action{
				{Type: ActionNotify, Params: map[string]string{"message": "LATERAL MOVEMENT detected on {{host_id}}: {{attack_chain}}"}},
			},
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		},
	}
}

// SeedDefaults adds default playbooks only if the store is empty.
func (e *Engine) SeedDefaults() {
	e.mu.Lock()
	if len(e.playbooks) > 0 {
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()
	for _, pb := range DefaultPlaybooks() {
		e.Add(pb)
	}
}

// ─── Persistence ──────────────────────────────────────────────────────────────

func (e *Engine) load() error {
	data, err := os.ReadFile(e.storePath)
	if err != nil {
		return err
	}
	var pbs []*Playbook
	if err := json.Unmarshal(data, &pbs); err != nil {
		return err
	}
	for _, pb := range pbs {
		e.playbooks[pb.ID] = pb
	}
	return nil
}

// save must be called with e.mu held (at least read).
func (e *Engine) save() error {
	if e.storePath == "" {
		return nil
	}
	pbs := make([]*Playbook, 0, len(e.playbooks))
	for _, pb := range e.playbooks {
		pbs = append(pbs, pb)
	}
	b, err := json.Marshal(pbs)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(e.storePath), 0755); err != nil {
		return err
	}
	tmp := e.storePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, e.storePath)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "pb-" + strings.ToLower(base64.RawURLEncoding.EncodeToString(b))
}
