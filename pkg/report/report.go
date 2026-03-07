// Package report provides compliance and operational reporting for the EDR platform.
//
// Report types:
//   - incident_summary  — counts by status/severity, MTTR, top hosts
//   - alert_summary     — alert volume by severity/rule/host, trend by day
//   - mitre_coverage    — techniques seen vs total ATT&CK techniques, heatmap data
//   - dlp_summary       — DLP scan results, top patterns, top violating hosts
//   - host_risk         — top risky hosts by alert count + severity score
package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// ─── Report types ─────────────────────────────────────────────────────────────

type ReportType string

const (
	TypeIncidentSummary ReportType = "incident_summary"
	TypeAlertSummary    ReportType = "alert_summary"
	TypeMitreCoverage   ReportType = "mitre_coverage"
	TypeDLPSummary      ReportType = "dlp_summary"
	TypeHostRisk        ReportType = "host_risk"
)

// Params controls report scope.
type Params struct {
	From     time.Time `json:"from,omitempty"`
	To       time.Time `json:"to,omitempty"`
	TenantID string    `json:"tenant_id,omitempty"`
	Limit    int       `json:"limit,omitempty"` // for top-N lists
}

// Report is the generated output.
type Report struct {
	ID          string      `json:"id"`
	Type        ReportType  `json:"type"`
	Title       string      `json:"title"`
	GeneratedAt time.Time   `json:"generated_at"`
	Params      Params      `json:"params"`
	Data        interface{} `json:"data"`
}

// ─── Per-report data structures ───────────────────────────────────────────────

type IncidentSummaryData struct {
	Total       int            `json:"total"`
	ByStatus    map[string]int `json:"by_status"`
	BySeverity  map[string]int `json:"by_severity"`
	ByTenant    map[string]int `json:"by_tenant"`
	TopHosts    []HostCount    `json:"top_hosts"`
	TopChains   []NameCount    `json:"top_chains"`
	AvgMTTRMins float64        `json:"avg_mttr_mins"`
	OpenOldest  *time.Time     `json:"open_oldest,omitempty"` // oldest open incident
}

type AlertSummaryData struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByRule     []NameCount    `json:"by_rule"`
	ByHost     []HostCount    `json:"by_host"`
	ByDay      []DayCount     `json:"by_day"` // last 30 days
}

type MitreCoverageData struct {
	TechniquesDetected int             `json:"techniques_detected"`
	TotalKnown         int             `json:"total_known"` // from built-in ATT&CK list
	CoveragePercent    float64         `json:"coverage_percent"`
	Tactics            []TacticCoverage `json:"tactics"`
	TopTechniques      []TechniqueCount `json:"top_techniques"`
}

type TacticCoverage struct {
	Name           string   `json:"name"`
	Detected       int      `json:"detected"`
	TotalKnown     int      `json:"total_known"`
	Techniques     []string `json:"techniques"`
}

type TechniqueCount struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type DLPSummaryData struct {
	TotalScans    int            `json:"total_scans"`
	TotalMatches  int            `json:"total_matches"`
	ByPattern     []NameCount    `json:"by_pattern"`
	ByHost        []HostCount    `json:"by_host"`
	BySeverity    map[string]int `json:"by_severity"`
	ByAction      map[string]int `json:"by_action"`
}

type HostRiskData struct {
	Hosts []HostRiskEntry `json:"hosts"`
}

type HostRiskEntry struct {
	HostID     string `json:"host_id"`
	AlertCount int    `json:"alert_count"`
	RiskScore  int    `json:"risk_score"` // 0-100
	Critical   int    `json:"critical"`
	High       int    `json:"high"`
	Medium     int    `json:"medium"`
	Low        int    `json:"low"`
}

// Shared building blocks
type HostCount struct {
	HostID string `json:"host_id"`
	Count  int    `json:"count"`
}

type NameCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type DayCount struct {
	Date  string `json:"date"` // YYYY-MM-DD
	Count int    `json:"count"`
}

// ─── Generator ────────────────────────────────────────────────────────────────

// Generator builds reports from data sources passed as slices of raw maps.
type Generator struct{}

func New() *Generator { return &Generator{} }

// GenerateIncidentSummary builds an incident summary report from raw incidents.
func (g *Generator) GenerateIncidentSummary(incidents []map[string]interface{}, p Params) Report {
	data := IncidentSummaryData{
		ByStatus:   make(map[string]int),
		BySeverity: make(map[string]int),
		ByTenant:   make(map[string]int),
	}
	hostCounts := make(map[string]int)
	chainCounts := make(map[string]int)
	var mttrTotal float64
	var mttrCount int
	var openOldest *time.Time

	for _, inc := range incidents {
		if !inTimeRange(inc, p) {
			continue
		}
		data.Total++
		if s, _ := inc["status"].(string); s != "" {
			data.ByStatus[s]++
		}
		if s, _ := inc["severity"].(string); s != "" {
			data.BySeverity[s]++
		}
		if t, _ := inc["tenant_id"].(string); t != "" {
			data.ByTenant[t]++
		}
		if h, _ := inc["host_id"].(string); h != "" {
			hostCounts[h]++
		}
		if c, _ := inc["attack_chain"].(string); c != "" {
			chainCounts[c]++
		}
		// MTTR
		if mttr, _ := inc["mttr"].(string); mttr != "" {
			if d, err := time.ParseDuration(strings.ReplaceAll(mttr, "m", "m")); err == nil {
				mttrTotal += d.Minutes()
				mttrCount++
			}
		}
		// Oldest open
		if status, _ := inc["status"].(string); status == "open" {
			if ts, _ := inc["created_at"].(string); ts != "" {
				if t, err := time.Parse(time.RFC3339, ts); err == nil {
					if openOldest == nil || t.Before(*openOldest) {
						tt := t
						openOldest = &tt
					}
				}
			}
		}
	}

	data.TopHosts = topHosts(hostCounts, limit(p))
	data.TopChains = topNames(chainCounts, limit(p))
	if mttrCount > 0 {
		data.AvgMTTRMins = mttrTotal / float64(mttrCount)
	}
	data.OpenOldest = openOldest

	return Report{
		ID: newReportID(), Type: TypeIncidentSummary, Title: "Incident Summary",
		GeneratedAt: time.Now().UTC(), Params: p, Data: data,
	}
}

// GenerateAlertSummary builds an alert volume/trend report.
func (g *Generator) GenerateAlertSummary(alerts []map[string]interface{}, p Params) Report {
	data := AlertSummaryData{BySeverity: make(map[string]int)}
	hostCounts := make(map[string]int)
	ruleCounts := make(map[string]int)
	dayCounts := make(map[string]int)

	for _, a := range alerts {
		if !inTimeRange(a, p) {
			continue
		}
		data.Total++
		if s, _ := a["severity"].(string); s != "" {
			data.BySeverity[s]++
		}
		if h, _ := a["host_id"].(string); h != "" {
			hostCounts[h]++
		}
		if r, _ := a["rule_id"].(string); r != "" {
			name, _ := a["rule_name"].(string)
			if name == "" {
				name = r
			}
			ruleCounts[name]++
		}
		if ts := alertTimeStr(a); ts != "" {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				day := t.UTC().Format("2006-01-02")
				dayCounts[day]++
			}
		}
	}

	data.ByRule = topNames(ruleCounts, limit(p))
	data.ByHost = topHosts(hostCounts, limit(p))
	data.ByDay = buildDayCounts(dayCounts, 30)

	return Report{
		ID: newReportID(), Type: TypeAlertSummary, Title: "Alert Summary",
		GeneratedAt: time.Now().UTC(), Params: p, Data: data,
	}
}

// GenerateMitreCoverage builds MITRE ATT&CK coverage report.
func (g *Generator) GenerateMitreCoverage(alerts []map[string]interface{}, p Params) Report {
	techCounts := make(map[string]int)

	for _, a := range alerts {
		if !inTimeRange(a, p) {
			continue
		}
		if tags, ok := a["mitre"].([]interface{}); ok {
			for _, t := range tags {
				if ts, ok := t.(string); ok && ts != "" {
					techCounts[ts]++
				}
			}
		}
	}

	detectedSet := make(map[string]bool)
	for t := range techCounts {
		// normalize to T-prefix only (strip sub-technique)
		if len(t) >= 5 {
			detectedSet[t[:5]] = true
		}
		detectedSet[t] = true
	}

	tactics := buildTacticCoverage(detectedSet)
	totalDetected := len(detectedSet)
	totalKnown := countKnownTechniques()
	coverage := 0.0
	if totalKnown > 0 {
		coverage = float64(totalDetected) / float64(totalKnown) * 100
	}

	// Top techniques by hit count
	topTechs := make([]TechniqueCount, 0, len(techCounts))
	for id, count := range techCounts {
		topTechs = append(topTechs, TechniqueCount{
			ID: id, Name: mitreNames[id], Count: count,
		})
	}
	sort.Slice(topTechs, func(i, j int) bool { return topTechs[i].Count > topTechs[j].Count })
	if len(topTechs) > 20 {
		topTechs = topTechs[:20]
	}

	data := MitreCoverageData{
		TechniquesDetected: totalDetected,
		TotalKnown:         totalKnown,
		CoveragePercent:    coverage,
		Tactics:            tactics,
		TopTechniques:      topTechs,
	}

	return Report{
		ID: newReportID(), Type: TypeMitreCoverage, Title: "MITRE ATT&CK Coverage",
		GeneratedAt: time.Now().UTC(), Params: p, Data: data,
	}
}

// GenerateDLPSummary builds a DLP scan summary report.
func (g *Generator) GenerateDLPSummary(dlpResults []map[string]interface{}, p Params) Report {
	data := DLPSummaryData{
		BySeverity: make(map[string]int),
		ByAction:   make(map[string]int),
	}
	patternCounts := make(map[string]int)
	hostCounts := make(map[string]int)

	for _, r := range dlpResults {
		if !inTimeRange(r, p) {
			continue
		}
		data.TotalScans++
		if matches, ok := r["matches"].([]interface{}); ok {
			for _, m := range matches {
				mm, _ := m.(map[string]interface{})
				data.TotalMatches++
				if pat, _ := mm["pattern_name"].(string); pat != "" {
					patternCounts[pat]++
				}
				if sev, _ := mm["severity"].(string); sev != "" {
					data.BySeverity[sev]++
				}
			}
		}
		if action, _ := r["action"].(string); action != "" {
			data.ByAction[action]++
		}
		if host, _ := r["host_id"].(string); host != "" {
			hostCounts[host]++
		}
	}

	data.ByPattern = topNames(patternCounts, limit(p))
	data.ByHost = topHosts(hostCounts, limit(p))

	return Report{
		ID: newReportID(), Type: TypeDLPSummary, Title: "DLP Summary",
		GeneratedAt: time.Now().UTC(), Params: p, Data: data,
	}
}

// GenerateHostRisk builds host risk ranking from alerts.
func (g *Generator) GenerateHostRisk(alerts []map[string]interface{}, p Params) Report {
	type hostStats struct {
		critical, high, medium, low int
	}
	hosts := make(map[string]*hostStats)

	for _, a := range alerts {
		if !inTimeRange(a, p) {
			continue
		}
		host, _ := a["host_id"].(string)
		if host == "" {
			continue
		}
		if _, ok := hosts[host]; !ok {
			hosts[host] = &hostStats{}
		}
		sev, _ := a["severity"].(string)
		switch strings.ToLower(sev) {
		case "critical":
			hosts[host].critical++
		case "high":
			hosts[host].high++
		case "medium":
			hosts[host].medium++
		case "low":
			hosts[host].low++
		}
	}

	entries := make([]HostRiskEntry, 0, len(hosts))
	for hostID, s := range hosts {
		total := s.critical + s.high + s.medium + s.low
		// Risk score: weighted sum capped at 100
		score := s.critical*10 + s.high*5 + s.medium*2 + s.low
		if score > 100 {
			score = 100
		}
		entries = append(entries, HostRiskEntry{
			HostID: hostID, AlertCount: total, RiskScore: score,
			Critical: s.critical, High: s.high, Medium: s.medium, Low: s.low,
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].RiskScore > entries[j].RiskScore })
	lim := limit(p)
	if len(entries) > lim {
		entries = entries[:lim]
	}

	return Report{
		ID: newReportID(), Type: TypeHostRisk, Title: "Host Risk Ranking",
		GeneratedAt: time.Now().UTC(), Params: p, Data: HostRiskData{Hosts: entries},
	}
}

// ─── CSV Export ───────────────────────────────────────────────────────────────

// ExportAlerts writes alerts as CSV to w.
func ExportAlerts(w io.Writer, alerts []map[string]interface{}) error {
	cw := csv.NewWriter(w)
	header := []string{"id", "created_at", "tenant_id", "host_id", "rule_id", "rule_name", "severity", "title", "message", "mitre"}
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, a := range alerts {
		id, _ := a["id"].(string)
		ts := alertTimeStr(a)
		tenant, _ := a["tenant_id"].(string)
		host, _ := a["host_id"].(string)
		ruleID, _ := a["rule_id"].(string)
		ruleName, _ := a["rule_name"].(string)
		sev, _ := a["severity"].(string)
		title, _ := a["title"].(string)
		msg, _ := a["message"].(string)
		mitre := mitreString(a)
		row := []string{id, ts, tenant, host, ruleID, ruleName, sev, title, msg, mitre}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// ExportIncidents writes incidents as CSV to w.
func ExportIncidents(w io.Writer, incidents []map[string]interface{}) error {
	cw := csv.NewWriter(w)
	header := []string{"id", "title", "tenant_id", "host_id", "severity", "status", "alert_count", "attack_chain", "mttr", "created_at", "resolved_at"}
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, inc := range incidents {
		id, _ := inc["id"].(string)
		title, _ := inc["title"].(string)
		tenant, _ := inc["tenant_id"].(string)
		host, _ := inc["host_id"].(string)
		sev, _ := inc["severity"].(string)
		status, _ := inc["status"].(string)
		alertCount := fmt.Sprintf("%v", inc["alert_count"])
		chain, _ := inc["attack_chain"].(string)
		mttr, _ := inc["mttr"].(string)
		createdAt, _ := inc["created_at"].(string)
		resolvedAt, _ := inc["resolved_at"].(string)
		row := []string{id, title, tenant, host, sev, status, alertCount, chain, mttr, createdAt, resolvedAt}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func inTimeRange(m map[string]interface{}, p Params) bool {
	if p.From.IsZero() && p.To.IsZero() {
		return true
	}
	ts := alertTimeStr(m)
	if ts == "" {
		return true // no timestamp, include
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return true
	}
	if !p.From.IsZero() && t.Before(p.From) {
		return false
	}
	if !p.To.IsZero() && t.After(p.To) {
		return false
	}
	return true
}

func alertTimeStr(a map[string]interface{}) string {
	if ts, ok := a["created_at"].(string); ok {
		return ts
	}
	return ""
}

func mitreString(a map[string]interface{}) string {
	if tags, ok := a["mitre"].([]interface{}); ok {
		parts := make([]string, 0, len(tags))
		for _, t := range tags {
			if ts, ok := t.(string); ok {
				parts = append(parts, ts)
			}
		}
		return strings.Join(parts, ";")
	}
	return ""
}

func limit(p Params) int {
	if p.Limit <= 0 {
		return 20
	}
	if p.Limit > 100 {
		return 100
	}
	return p.Limit
}

func topHosts(counts map[string]int, n int) []HostCount {
	out := make([]HostCount, 0, len(counts))
	for h, c := range counts {
		out = append(out, HostCount{h, c})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func topNames(counts map[string]int, n int) []NameCount {
	out := make([]NameCount, 0, len(counts))
	for name, c := range counts {
		out = append(out, NameCount{name, c})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func buildDayCounts(dayCounts map[string]int, days int) []DayCount {
	now := time.Now().UTC()
	out := make([]DayCount, days)
	for i := 0; i < days; i++ {
		d := now.AddDate(0, 0, -(days - 1 - i)).Format("2006-01-02")
		out[i] = DayCount{Date: d, Count: dayCounts[d]}
	}
	return out
}

func newReportID() string {
	return fmt.Sprintf("rpt-%d", time.Now().UnixNano())
}

// ─── MITRE ATT&CK reference data ──────────────────────────────────────────────

// mitreTactics maps tactic name → technique IDs present in OWO's rule set.
var mitreTactics = map[string][]string{
	"Initial Access":          {"T1078", "T1190", "T1133", "T1566"},
	"Execution":               {"T1059", "T1053", "T1569", "T1204"},
	"Persistence":             {"T1547", "T1543", "T1053", "T1078"},
	"Privilege Escalation":    {"T1055", "T1068", "T1134", "T1547"},
	"Defense Evasion":         {"T1055", "T1070", "T1036", "T1562"},
	"Credential Access":       {"T1003", "T1110", "T1558", "T1552"},
	"Discovery":               {"T1083", "T1082", "T1057", "T1033"},
	"Lateral Movement":        {"T1021", "T1570", "T1550"},
	"Collection":              {"T1005", "T1039", "T1025", "T1056"},
	"Exfiltration":            {"T1048", "T1041", "T1052", "T1020"},
	"Command and Control":     {"T1071", "T1095", "T1105", "T1572"},
	"Impact":                  {"T1486", "T1490", "T1489", "T1485"},
}

// mitreNames provides display names for technique IDs.
var mitreNames = map[string]string{
	"T1059": "Command and Scripting Interpreter",
	"T1055": "Process Injection",
	"T1003": "OS Credential Dumping",
	"T1021": "Remote Services",
	"T1083": "File and Directory Discovery",
	"T1052": "Exfiltration Over Physical Medium",
	"T1047": "Windows Management Instrumentation",
	"T1547": "Boot or Logon Autostart Execution",
	"T1048": "Exfiltration Over Alternative Protocol",
	"T1190": "Exploit Public-Facing Application",
	"T1078": "Valid Accounts",
	"T1486": "Data Encrypted for Impact",
	"T1082": "System Information Discovery",
	"T1057": "Process Discovery",
	"T1070": "Indicator Removal",
}

func buildTacticCoverage(detected map[string]bool) []TacticCoverage {
	out := make([]TacticCoverage, 0, len(mitreTactics))
	// sort tactic names for deterministic output
	names := make([]string, 0, len(mitreTactics))
	for n := range mitreTactics {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, tactic := range names {
		techs := mitreTactics[tactic]
		detectedTechs := 0
		for _, t := range techs {
			if detected[t] {
				detectedTechs++
			}
		}
		out = append(out, TacticCoverage{
			Name:       tactic,
			Detected:   detectedTechs,
			TotalKnown: len(techs),
			Techniques: techs,
		})
	}
	return out
}

func countKnownTechniques() int {
	seen := make(map[string]bool)
	for _, techs := range mitreTactics {
		for _, t := range techs {
			seen[t] = true
		}
	}
	return len(seen)
}
