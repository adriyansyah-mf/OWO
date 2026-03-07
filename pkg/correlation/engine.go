// Package correlation provides multi-event alert correlation and incident management.
//
// Features:
//   - Alert deduplication: suppress repeated firing of the same rule on the same host
//     within a configurable time window (default 5 min).
//   - Incident grouping: alerts from the same host within a rolling window (default 30 min)
//     are merged into a single open incident.
//   - Attack chain detection: predefined MITRE-tag sequences that escalate incident severity
//     to "critical" when matched.
//   - Incident lifecycle: open → investigating → resolved, with MTTD/MTTR tracking.
//   - JSON file persistence.
package correlation

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

// ─── Incident ─────────────────────────────────────────────────────────────────

// IncidentStatus represents the lifecycle state of an incident.
type IncidentStatus string

const (
	IncidentOpen         IncidentStatus = "open"
	IncidentInvestigating IncidentStatus = "investigating"
	IncidentResolved     IncidentStatus = "resolved"
)

// Incident groups related alerts into a single investigation unit.
type Incident struct {
	ID           string         `json:"id"`
	Title        string         `json:"title"`
	TenantID     string         `json:"tenant_id"`
	HostID       string         `json:"host_id"`
	Severity     string         `json:"severity"`
	Status       IncidentStatus `json:"status"`
	AlertCount   int            `json:"alert_count"`
	AlertIDs     []string       `json:"alert_ids,omitempty"`
	RuleIDs      []string       `json:"rule_ids,omitempty"`   // unique rule IDs across all alerts
	MitreTags    []string       `json:"mitre_tags,omitempty"` // union of MITRE tags
	AttackChain  string         `json:"attack_chain,omitempty"` // matched chain name, if any
	Notes        string         `json:"notes,omitempty"`
	AssignedTo   string         `json:"assigned_to,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	FirstAlertAt time.Time      `json:"first_alert_at"`
	LastAlertAt  time.Time      `json:"last_alert_at"`
	ResolvedAt   *time.Time     `json:"resolved_at,omitempty"`
	// MTTD: time from first alert to incident creation (always near-zero since we create on first alert)
	// MTTR: populated when resolved
	MTTR *string `json:"mttr,omitempty"` // human-readable, e.g. "2h35m"
}

// ─── Attack chains ────────────────────────────────────────────────────────────

// AttackChain defines a known multi-stage attack sequence detected via MITRE tags.
type AttackChain struct {
	Name      string        // display name
	MitreTags []string      // all tags must be present (unordered)
	Window    time.Duration // must occur within this window
	Severity  string        // escalate to this severity
}

// DefaultAttackChains are the built-in detection chains.
var DefaultAttackChains = []AttackChain{
	{
		Name:      "Execution + Exfiltration",
		MitreTags: []string{"T1059", "T1048"},
		Window:    60 * time.Minute,
		Severity:  "critical",
	},
	{
		Name:      "Reverse Shell + Privilege Escalation",
		MitreTags: []string{"T1059", "T1055"},
		Window:    30 * time.Minute,
		Severity:  "critical",
	},
	{
		Name:      "Credential Access + Lateral Movement",
		MitreTags: []string{"T1003", "T1021"},
		Window:    60 * time.Minute,
		Severity:  "critical",
	},
	{
		Name:      "Discovery + Exfiltration via USB",
		MitreTags: []string{"T1083", "T1052"},
		Window:    30 * time.Minute,
		Severity:  "high",
	},
	{
		Name:      "Defense Evasion + Persistence",
		MitreTags: []string{"T1055", "T1547"},
		Window:    45 * time.Minute,
		Severity:  "high",
	},
}

// ─── Dedup entry ──────────────────────────────────────────────────────────────

type dedupKey struct {
	ruleID string
	hostID string
}

// ─── Engine ───────────────────────────────────────────────────────────────────

// Engine is the correlation engine. It is safe for concurrent use.
type Engine struct {
	mu           sync.RWMutex
	incidents    map[string]*Incident  // id → Incident
	dedup        map[dedupKey]time.Time // last seen timestamp per rule+host
	DedupWindow  time.Duration          // default: 5 min
	GroupWindow  time.Duration          // default: 30 min  (group alerts from same host)
	AttackChains []AttackChain
	storePath    string
}

// New creates a new Engine. storePath is the JSON file for persistence.
func New(storePath string) *Engine {
	e := &Engine{
		incidents:    make(map[string]*Incident),
		dedup:        make(map[dedupKey]time.Time),
		DedupWindow:  5 * time.Minute,
		GroupWindow:  30 * time.Minute,
		AttackChains: DefaultAttackChains,
		storePath:    storePath,
	}
	if storePath != "" {
		_ = e.load()
	}
	return e
}

// IngestResult is returned by IngestAlert.
type IngestResult struct {
	Duplicate    bool      // alert was suppressed (duplicate within dedup window)
	IncidentID   string    // incident this alert was assigned to
	NewIncident  bool      // true if a new incident was created
	ChainMatched string    // attack chain name if escalated
}

// IngestAlert processes an incoming alert (from NATS or elsewhere).
// It extracts host_id, rule_id, severity, mitre tags, and title from the alert map.
func (e *Engine) IngestAlert(alert map[string]interface{}) IngestResult {
	ruleID, _ := alert["rule_id"].(string)
	hostID, _ := alert["host_id"].(string)
	tenantID, _ := alert["tenant_id"].(string)
	severity, _ := alert["severity"].(string)
	title, _ := alert["title"].(string)
	if title == "" {
		title, _ = alert["rule_name"].(string)
	}
	alertID, _ := alert["id"].(string)
	if tenantID == "" {
		tenantID = "default"
	}

	// Parse alert timestamp
	alertTime := time.Now().UTC()
	if ts, ok := alert["created_at"].(string); ok {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			alertTime = t
		}
	}

	// Parse MITRE tags
	var mitreTags []string
	if m, ok := alert["mitre"].([]interface{}); ok {
		for _, v := range m {
			if s, ok := v.(string); ok {
				mitreTags = append(mitreTags, s)
			}
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// ── Deduplication ──
	dk := dedupKey{ruleID: ruleID, hostID: hostID}
	if lastSeen, seen := e.dedup[dk]; seen && time.Since(lastSeen) < e.DedupWindow {
		// Still within dedup window — suppress but still update the incident
		inc := e.findOpenIncidentUnlocked(hostID, tenantID, alertTime)
		if inc != nil {
			inc.AlertCount++
			inc.LastAlertAt = alertTime
			inc.UpdatedAt = time.Now().UTC()
		}
		return IngestResult{Duplicate: true, IncidentID: func() string {
			if inc != nil {
				return inc.ID
			}
			return ""
		}()}
	}
	e.dedup[dk] = alertTime

	// ── Find or create incident ──
	inc := e.findOpenIncidentUnlocked(hostID, tenantID, alertTime)
	newIncident := false
	if inc == nil {
		inc = &Incident{
			ID:           newID(),
			Title:        incidentTitle(title, hostID),
			TenantID:     tenantID,
			HostID:       hostID,
			Severity:     severity,
			Status:       IncidentOpen,
			CreatedAt:    time.Now().UTC(),
			UpdatedAt:    time.Now().UTC(),
			FirstAlertAt: alertTime,
			LastAlertAt:  alertTime,
		}
		e.incidents[inc.ID] = inc
		newIncident = true
	}

	// Update incident
	inc.AlertCount++
	inc.LastAlertAt = alertTime
	inc.UpdatedAt = time.Now().UTC()
	if alertID != "" {
		inc.AlertIDs = appendUnique(inc.AlertIDs, alertID)
	}
	if ruleID != "" {
		inc.RuleIDs = appendUnique(inc.RuleIDs, ruleID)
	}
	for _, tag := range mitreTags {
		inc.MitreTags = appendUnique(inc.MitreTags, tag)
	}
	inc.Severity = higherSeverity(inc.Severity, severity)

	// ── Attack chain detection ──
	chainMatched := ""
	for _, chain := range e.AttackChains {
		if inc.AttackChain != "" {
			break // already escalated
		}
		if time.Since(inc.FirstAlertAt) > chain.Window {
			continue
		}
		if containsAllTags(inc.MitreTags, chain.MitreTags) {
			inc.AttackChain = chain.Name
			inc.Severity = chain.Severity
			chainMatched = chain.Name
		}
	}

	_ = e.save()
	return IngestResult{
		Duplicate:    false,
		IncidentID:   inc.ID,
		NewIncident:  newIncident,
		ChainMatched: chainMatched,
	}
}

// findOpenIncidentUnlocked finds the most recent open incident for a host
// within the grouping window. Caller must hold e.mu (write or read).
func (e *Engine) findOpenIncidentUnlocked(hostID, tenantID string, alertTime time.Time) *Incident {
	var best *Incident
	for _, inc := range e.incidents {
		if inc.Status == IncidentResolved {
			continue
		}
		if inc.HostID != hostID || inc.TenantID != tenantID {
			continue
		}
		if alertTime.Sub(inc.LastAlertAt) > e.GroupWindow {
			continue
		}
		if best == nil || inc.LastAlertAt.After(best.LastAlertAt) {
			best = inc
		}
	}
	return best
}

// ─── CRUD ─────────────────────────────────────────────────────────────────────

// ListIncidents returns incidents filtered by status, host_id, and tenant_id.
func (e *Engine) ListIncidents(status IncidentStatus, hostID, tenantID string, limit int) []Incident {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if limit <= 0 {
		limit = 200
	}
	out := make([]Incident, 0)
	for _, inc := range e.incidents {
		if status != "" && inc.Status != status {
			continue
		}
		if hostID != "" && inc.HostID != hostID {
			continue
		}
		if tenantID != "" && inc.TenantID != tenantID {
			continue
		}
		out = append(out, *inc)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// GetIncident returns an incident by ID.
func (e *Engine) GetIncident(id string) (Incident, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	inc, ok := e.incidents[id]
	if !ok {
		return Incident{}, false
	}
	return *inc, true
}

// UpdateIncident updates mutable fields: status, notes, assigned_to.
func (e *Engine) UpdateIncident(id, status, notes, assignedTo string) (Incident, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	inc, ok := e.incidents[id]
	if !ok {
		return Incident{}, fmt.Errorf("incident not found: %s", id)
	}
	if status != "" {
		inc.Status = IncidentStatus(status)
		if inc.Status == IncidentResolved && inc.ResolvedAt == nil {
			now := time.Now().UTC()
			inc.ResolvedAt = &now
			mttr := now.Sub(inc.CreatedAt).Round(time.Minute).String()
			inc.MTTR = &mttr
		}
	}
	if notes != "" {
		inc.Notes = notes
	}
	if assignedTo != "" {
		inc.AssignedTo = assignedTo
	}
	inc.UpdatedAt = time.Now().UTC()
	_ = e.save()
	return *inc, nil
}

// DeleteIncident removes an incident.
func (e *Engine) DeleteIncident(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.incidents[id]; !ok {
		return fmt.Errorf("incident not found: %s", id)
	}
	delete(e.incidents, id)
	return e.save()
}

// Stats returns summary counts.
func (e *Engine) Stats() map[string]int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	counts := map[string]int{"total": len(e.incidents)}
	for _, inc := range e.incidents {
		counts[string(inc.Status)]++
		counts["sev_"+inc.Severity]++
	}
	return counts
}

// PruneDedup removes stale dedup entries to prevent unbounded memory growth.
// Call periodically (e.g. every 10 minutes).
func (e *Engine) PruneDedup() {
	e.mu.Lock()
	defer e.mu.Unlock()
	threshold := time.Now().Add(-e.DedupWindow)
	for k, t := range e.dedup {
		if t.Before(threshold) {
			delete(e.dedup, k)
		}
	}
}

// ─── Persistence ──────────────────────────────────────────────────────────────

func (e *Engine) load() error {
	data, err := os.ReadFile(e.storePath)
	if err != nil {
		return err
	}
	var incidents []*Incident
	if err := json.Unmarshal(data, &incidents); err != nil {
		return err
	}
	for _, inc := range incidents {
		e.incidents[inc.ID] = inc
	}
	return nil
}

func (e *Engine) save() error {
	if e.storePath == "" {
		return nil
	}
	incidents := make([]*Incident, 0, len(e.incidents))
	for _, inc := range e.incidents {
		incidents = append(incidents, inc)
	}
	b, err := json.Marshal(incidents)
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

func incidentTitle(alertTitle, hostID string) string {
	if alertTitle != "" && hostID != "" {
		return fmt.Sprintf("%s on %s", alertTitle, hostID)
	}
	if hostID != "" {
		return "Incident on " + hostID
	}
	return "New Incident"
}

func higherSeverity(a, b string) string {
	rank := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

func appendUnique(slice []string, s string) []string {
	if s == "" {
		return slice
	}
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

func containsAllTags(have, need []string) bool {
	if len(need) == 0 {
		return false
	}
	set := make(map[string]bool, len(have))
	for _, t := range have {
		// MITRE tag prefix matching: "T1059" matches "T1059.003"
		set[t] = true
		if len(t) >= 5 {
			set[t[:5]] = true
		}
	}
	for _, n := range need {
		key := n
		if len(key) >= 5 {
			key = key[:5]
		}
		if !set[key] && !set[n] {
			return false
		}
	}
	return true
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "inc-" + strings.ToLower(base64.RawURLEncoding.EncodeToString(b))
}
