// Package hunt provides a threat hunting query engine over alert history.
//
// Features:
//   - Multi-field filtering: time range, host_id, tenant_id, severity,
//     rule_id (prefix), mitre_tag (prefix), attack_chain, keyword (title/message)
//   - Faceted results: counts by severity, host, rule_id, mitre_tag
//   - Saved hunts: named, reusable queries stored to JSON
//   - Pagination: offset + limit
package hunt

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

// ─── Query ────────────────────────────────────────────────────────────────────

// Query defines the parameters of a threat hunt.
type Query struct {
	// Time range (zero values = no bound)
	From time.Time `json:"from,omitempty"`
	To   time.Time `json:"to,omitempty"`

	// Field filters (empty = match all)
	TenantID    string `json:"tenant_id,omitempty"`
	HostID      string `json:"host_id,omitempty"`
	Severity    string `json:"severity,omitempty"`    // exact or "high+" (high and above)
	RuleID      string `json:"rule_id,omitempty"`     // prefix match
	MitreTag    string `json:"mitre_tag,omitempty"`   // prefix match against any tag
	AttackChain string `json:"attack_chain,omitempty"` // substring

	// Full-text search across title + message + rule_name
	Keyword string `json:"keyword,omitempty"`

	// Pagination
	Offset int `json:"offset,omitempty"`
	Limit  int `json:"limit,omitempty"` // default 100, max 1000
}

// ─── Result ───────────────────────────────────────────────────────────────────

// Result is returned by Engine.Execute.
type Result struct {
	Total  int                      `json:"total"`  // total matches before pagination
	Hits   []map[string]interface{} `json:"hits"`   // paginated page
	Facets Facets                   `json:"facets"` // counts from full result set
}

// Facets contains aggregate counts over the full result set.
type Facets struct {
	BySeverity map[string]int `json:"by_severity"`
	ByHost     map[string]int `json:"by_host"`
	ByRule     map[string]int `json:"by_rule"`
	ByMitre    map[string]int `json:"by_mitre"`
}

// ─── SavedHunt ────────────────────────────────────────────────────────────────

// SavedHunt is a named, reusable query.
type SavedHunt struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Query       Query     `json:"query"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	RunCount    int       `json:"run_count"`
	LastRunAt   *time.Time `json:"last_run_at,omitempty"`
}

// ─── Engine ───────────────────────────────────────────────────────────────────

// Engine executes hunt queries and manages saved hunts.
// It receives alerts from the outside (via Ingest) and holds an in-memory
// ring buffer of the last maxAlerts alerts. It is safe for concurrent use.
type Engine struct {
	mu         sync.RWMutex
	alerts     []map[string]interface{} // ring buffer
	savedMu    sync.RWMutex
	saved      map[string]*SavedHunt
	storePath  string
	maxAlerts  int
}

const defaultMaxAlerts = 10000

// New creates a Hunt Engine.
// storePath is the JSON file for saved hunts persistence.
func New(storePath string) *Engine {
	e := &Engine{
		saved:     make(map[string]*SavedHunt),
		storePath: storePath,
		maxAlerts: defaultMaxAlerts,
	}
	if storePath != "" {
		_ = e.load()
	}
	return e
}

// Ingest adds an alert to the in-memory ring buffer.
// Call this from the NATS alerts subscriber after broadcastAlert.
func (e *Engine) Ingest(alert map[string]interface{}) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.alerts = append(e.alerts, alert)
	if len(e.alerts) > e.maxAlerts {
		e.alerts = e.alerts[len(e.alerts)-e.maxAlerts:]
	}
}

// Seed populates the engine with an existing slice of alerts (e.g. on startup
// from in-memory alertsMem). Replaces current buffer.
func (e *Engine) Seed(alerts []map[string]interface{}) {
	e.mu.Lock()
	defer e.mu.Unlock()
	cp := make([]map[string]interface{}, len(alerts))
	copy(cp, alerts)
	if len(cp) > e.maxAlerts {
		cp = cp[len(cp)-e.maxAlerts:]
	}
	e.alerts = cp
}

// ─── Execute ──────────────────────────────────────────────────────────────────

// Execute runs a Query against the in-memory alert buffer.
func (e *Engine) Execute(q Query) Result {
	if q.Limit <= 0 {
		q.Limit = 100
	}
	if q.Limit > 1000 {
		q.Limit = 1000
	}

	e.mu.RLock()
	all := make([]map[string]interface{}, len(e.alerts))
	copy(all, e.alerts)
	e.mu.RUnlock()

	// Filter
	matched := make([]map[string]interface{}, 0, 256)
	for i := len(all) - 1; i >= 0; i-- { // newest first
		a := all[i]
		if matchAlert(a, q) {
			matched = append(matched, a)
		}
	}

	total := len(matched)
	facets := buildFacets(matched)

	// Paginate
	start := q.Offset
	if start >= total {
		start = total
	}
	end := start + q.Limit
	if end > total {
		end = total
	}
	page := matched[start:end]

	return Result{Total: total, Hits: page, Facets: facets}
}

func matchAlert(a map[string]interface{}, q Query) bool {
	// Time range
	if !q.From.IsZero() || !q.To.IsZero() {
		ts := alertTime(a)
		if !q.From.IsZero() && ts.Before(q.From) {
			return false
		}
		if !q.To.IsZero() && ts.After(q.To) {
			return false
		}
	}

	// Exact field matches
	if q.TenantID != "" {
		if v, _ := a["tenant_id"].(string); !strings.EqualFold(v, q.TenantID) {
			return false
		}
	}
	if q.HostID != "" {
		if v, _ := a["host_id"].(string); !strings.EqualFold(v, q.HostID) {
			return false
		}
	}
	if q.Severity != "" {
		sev, _ := a["severity"].(string)
		if !matchSeverity(sev, q.Severity) {
			return false
		}
	}

	// Rule ID prefix
	if q.RuleID != "" {
		v, _ := a["rule_id"].(string)
		if !strings.HasPrefix(strings.ToLower(v), strings.ToLower(q.RuleID)) {
			return false
		}
	}

	// MITRE tag prefix (any tag must match)
	if q.MitreTag != "" {
		if !hasMitrePrefix(a, q.MitreTag) {
			return false
		}
	}

	// Attack chain substring
	if q.AttackChain != "" {
		v, _ := a["attack_chain"].(string)
		if !strings.Contains(strings.ToLower(v), strings.ToLower(q.AttackChain)) {
			return false
		}
	}

	// Keyword: title + message + rule_name
	if q.Keyword != "" {
		kw := strings.ToLower(q.Keyword)
		title, _ := a["title"].(string)
		msg, _ := a["message"].(string)
		rname, _ := a["rule_name"].(string)
		haystack := strings.ToLower(title + " " + msg + " " + rname)
		if !strings.Contains(haystack, kw) {
			return false
		}
	}

	return true
}

func matchSeverity(have, want string) bool {
	have = strings.ToLower(have)
	want = strings.ToLower(want)
	// "high+" means high and critical
	if strings.HasSuffix(want, "+") {
		base := strings.TrimSuffix(want, "+")
		rank := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}
		return rank[have] >= rank[base]
	}
	return have == want
}

func hasMitrePrefix(a map[string]interface{}, prefix string) bool {
	prefix = strings.ToLower(prefix)
	if tags, ok := a["mitre"].([]interface{}); ok {
		for _, t := range tags {
			ts, _ := t.(string)
			if strings.HasPrefix(strings.ToLower(ts), prefix) {
				return true
			}
		}
	}
	if tags, ok := a["mitre"].([]string); ok {
		for _, ts := range tags {
			if strings.HasPrefix(strings.ToLower(ts), prefix) {
				return true
			}
		}
	}
	return false
}

func alertTime(a map[string]interface{}) time.Time {
	if ts, ok := a["created_at"].(string); ok {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			return t
		}
	}
	return time.Time{}
}

func buildFacets(alerts []map[string]interface{}) Facets {
	f := Facets{
		BySeverity: make(map[string]int),
		ByHost:     make(map[string]int),
		ByRule:     make(map[string]int),
		ByMitre:    make(map[string]int),
	}
	for _, a := range alerts {
		if sev, _ := a["severity"].(string); sev != "" {
			f.BySeverity[sev]++
		}
		if host, _ := a["host_id"].(string); host != "" {
			f.ByHost[host]++
		}
		if rule, _ := a["rule_id"].(string); rule != "" {
			f.ByRule[rule]++
		}
		if tags, ok := a["mitre"].([]interface{}); ok {
			seen := make(map[string]bool)
			for _, t := range tags {
				ts, _ := t.(string)
				if ts != "" && !seen[ts] {
					f.ByMitre[ts]++
					seen[ts] = true
				}
			}
		}
	}
	return f
}

// ─── Saved hunts CRUD ─────────────────────────────────────────────────────────

// SaveHunt creates or replaces a saved hunt (upsert by ID).
func (e *Engine) SaveHunt(sh SavedHunt) SavedHunt {
	e.savedMu.Lock()
	defer e.savedMu.Unlock()
	if sh.ID == "" {
		sh.ID = newID()
		sh.CreatedAt = time.Now().UTC()
	} else if existing, ok := e.saved[sh.ID]; ok {
		sh.CreatedAt = existing.CreatedAt
		sh.RunCount = existing.RunCount
		sh.LastRunAt = existing.LastRunAt
	}
	sh.UpdatedAt = time.Now().UTC()
	e.saved[sh.ID] = &sh
	_ = e.saveSaved()
	return sh
}

// DeleteSavedHunt removes a saved hunt by ID.
func (e *Engine) DeleteSavedHunt(id string) error {
	e.savedMu.Lock()
	defer e.savedMu.Unlock()
	if _, ok := e.saved[id]; !ok {
		return fmt.Errorf("saved hunt not found: %s", id)
	}
	delete(e.saved, id)
	return e.saveSaved()
}

// ListSavedHunts returns all saved hunts.
func (e *Engine) ListSavedHunts() []SavedHunt {
	e.savedMu.RLock()
	defer e.savedMu.RUnlock()
	out := make([]SavedHunt, 0, len(e.saved))
	for _, sh := range e.saved {
		out = append(out, *sh)
	}
	return out
}

// RunSaved executes a saved hunt by ID, incrementing its run count.
func (e *Engine) RunSaved(id string) (Result, error) {
	e.savedMu.Lock()
	sh, ok := e.saved[id]
	if !ok {
		e.savedMu.Unlock()
		return Result{}, fmt.Errorf("saved hunt not found: %s", id)
	}
	q := sh.Query
	sh.RunCount++
	now := time.Now().UTC()
	sh.LastRunAt = &now
	e.savedMu.Unlock()

	_ = e.saveSaved()
	return e.Execute(q), nil
}

// ─── Persistence ──────────────────────────────────────────────────────────────

func (e *Engine) load() error {
	data, err := os.ReadFile(e.storePath)
	if err != nil {
		return err
	}
	var hunts []*SavedHunt
	if err := json.Unmarshal(data, &hunts); err != nil {
		return err
	}
	e.savedMu.Lock()
	for _, sh := range hunts {
		e.saved[sh.ID] = sh
	}
	e.savedMu.Unlock()
	return nil
}

// saveSaved must be called with e.savedMu held (at least read) — but we
// take the approach of calling it unlocked and marshaling a snapshot.
func (e *Engine) saveSaved() error {
	if e.storePath == "" {
		return nil
	}
	e.savedMu.RLock()
	hunts := make([]*SavedHunt, 0, len(e.saved))
	for _, sh := range e.saved {
		hunts = append(hunts, sh)
	}
	e.savedMu.RUnlock()

	b, err := json.Marshal(hunts)
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
	return "hunt-" + strings.ToLower(base64.RawURLEncoding.EncodeToString(b))
}
