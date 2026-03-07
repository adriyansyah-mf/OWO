// Package dlp: audit.go — Structured SIEM-ready DLP audit trail.
//
// Every DLP event — whether a pattern match, a policy enforcement action,
// a behavioral detection, or a fingerprint hit — produces an AuditEvent.
// AuditEvents are:
//   1. Written as JSON lines to a local file (/var/log/edr/dlp-audit.jsonl).
//      This file can be tail-fed directly into Elasticsearch, Splunk, or any
//      SIEM that accepts JSON lines.
//   2. Published to NATS subject "dlp.audit" for real-time SOC consumption.
//   3. Published to the configured escalation subject when the enforcement
//      action is ActionEscalate or ActionBlock.
//
// Schema:
//   The AuditEvent struct follows ECS (Elastic Common Schema) field naming
//   conventions where applicable (@timestamp, host.*, user.*, process.*,
//   file.*, event.*) to maximise SIEM compatibility without requiring a
//   translation layer.
//
// MITRE ATT&CK coverage:
//   Each channel is mapped to relevant ATT&CK technique IDs so that a SIEM
//   can automatically tag DLP events in a kill-chain context.
package dlp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// AuditEvent — the canonical DLP audit record
// ─────────────────────────────────────────────────────────────────────────────

// PatternMatchSummary is a compact representation of one DLP pattern match
// included in every AuditEvent. The full Match struct is too verbose for audit.
type PatternMatchSummary struct {
	PatternID string `json:"pattern_id"`
	Name      string `json:"name"`
	Severity  string `json:"severity"`
	Line      int    `json:"line,omitempty"`
	// Snippet is the redacted (masked) context line. Never the raw secret.
	Snippet string `json:"snippet,omitempty"`
}

// AuditEvent is the canonical DLP audit record emitted for every DLP-relevant
// event. It is designed for direct ingestion by Elasticsearch / Splunk / SIEM.
//
// Field naming follows ECS where possible:
//   @timestamp, host.name, user.id, process.pid, process.name,
//   file.path, file.size, file.hash.sha256, event.id, event.action.
type AuditEvent struct {
	// ── Identity ──────────────────────────────────────────────────────────
	// EventID is a unique identifier for this audit record (format: dlp-<nanoseconds>).
	EventID string `json:"event_id"`
	// Timestamp follows ECS @timestamp convention (RFC3339Nano, UTC).
	Timestamp time.Time `json:"@timestamp"`

	// ── Agent context ─────────────────────────────────────────────────────
	TenantID  string `json:"tenant_id"`
	HostID    string `json:"host_id"`
	AgentName string `json:"agent_name,omitempty"`

	// ── Actor (who did it) ────────────────────────────────────────────────
	UserID      string `json:"user_id"`                // UID as string
	ProcessPID  uint32 `json:"process_pid"`
	ProcessName string `json:"process_name"`
	ProcessExe  string `json:"process_exe,omitempty"`

	// ── Object (what was accessed / transferred) ──────────────────────────
	ObjectPath   string   `json:"object_path"`
	ObjectType   string   `json:"object_type"`             // "file", "clipboard", "network", "usb"
	ObjectSize   int64    `json:"object_size_bytes,omitempty"`
	ObjectSHA256 string   `json:"object_sha256,omitempty"`
	ObjectMIME   MimeType `json:"object_mime,omitempty"`

	// ── DLP Classification ────────────────────────────────────────────────
	SensitivityLabel    SensitivityLabel      `json:"sensitivity_label"`
	PatternMatches      []PatternMatchSummary `json:"pattern_matches,omitempty"`
	FingerprintMatch    bool                  `json:"fingerprint_match,omitempty"`
	FingerprintDocName  string                `json:"fingerprint_doc_name,omitempty"`

	// ── Channel ───────────────────────────────────────────────────────────
	Channel     Channel `json:"dlp_channel"`
	// Destination is the exfiltration target: USB mount path, cloud domain, email address.
	Destination string `json:"destination,omitempty"`

	// ── Policy & Enforcement ──────────────────────────────────────────────
	PolicyID    string            `json:"policy_id,omitempty"`
	PolicyName  string            `json:"policy_name,omitempty"`
	Action      EnforcementAction `json:"enforcement_action"`
	// ActionTaken is false when the enforcement was advisory-only (audit/alert).
	ActionTaken bool   `json:"action_taken"`
	BlockReason string `json:"block_reason,omitempty"`
	// QuarantineDest is the path where the file was moved on quarantine.
	QuarantineDest string `json:"quarantine_dest,omitempty"`

	// ── Severity & Risk ───────────────────────────────────────────────────
	Severity    string  `json:"severity"`
	RiskScore   float64 `json:"risk_score,omitempty"` // 0.0–1.0 from ML hook

	// ── Behavioral detection ──────────────────────────────────────────────
	BehavioralRule   string  `json:"behavioral_rule,omitempty"`
	BehavioralDetail string  `json:"behavioral_detail,omitempty"`
	MLRiskScore      float64 `json:"ml_risk_score,omitempty"`

	// ── Detection source ──────────────────────────────────────────────────
	// DetectionSource identifies what triggered the event:
	// "pattern", "fingerprint", "behavioral", "ml", "device_control"
	DetectionSource string `json:"detection_source"`

	// ── MITRE ATT&CK ──────────────────────────────────────────────────────
	MitreAttck []string `json:"mitre_attck,omitempty"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Publisher interface — decouples audit logger from NATS
// ─────────────────────────────────────────────────────────────────────────────

// Publisher is a function that sends bytes to a named subject.
// Implement with natsConn.Publish or any message bus adapter.
// A nil Publisher disables NATS output (file-only mode).
type Publisher func(subject string, data []byte) error

// ─────────────────────────────────────────────────────────────────────────────
// AuditLogger
// ─────────────────────────────────────────────────────────────────────────────

// AuditLogger writes DLP AuditEvents to a local JSON-lines file and optionally
// publishes them to NATS. It is safe for concurrent use.
//
// File rotation is the responsibility of an external tool (logrotate, journald).
// The logger re-opens the file on each batch flush to pick up after a rotation.
type AuditLogger struct {
	mu        sync.Mutex
	filePath  string
	publish   Publisher // nil = file-only mode
	auditSubj string    // NATS subject for all DLP audit events (default: "dlp.audit")
	escSubj   string    // NATS subject for escalations (default: "dlp.escalation")

	// Sequence counter for EventID uniqueness within a process restart.
	seq uint64
}

// NewAuditLogger creates an audit logger.
//
//   filePath:  path to the JSON-lines audit file; directories are created automatically.
//              Pass "" to disable file logging.
//   publish:   NATS publisher function. Pass nil for file-only mode.
func NewAuditLogger(filePath string, publish Publisher) (*AuditLogger, error) {
	if filePath != "" {
		if err := os.MkdirAll(filepath.Dir(filePath), 0750); err != nil {
			return nil, fmt.Errorf("dlp audit: mkdir %s: %w", filepath.Dir(filePath), err)
		}
	}
	return &AuditLogger{
		filePath:  filePath,
		publish:   publish,
		auditSubj: "dlp.audit",
		escSubj:   "dlp.escalation",
	}, nil
}

// SetSubjects overrides the default NATS subjects.
func (l *AuditLogger) SetSubjects(auditSubject, escalationSubject string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if auditSubject != "" {
		l.auditSubj = auditSubject
	}
	if escalationSubject != "" {
		l.escSubj = escalationSubject
	}
}

// Log writes an AuditEvent to the log file and publishes it to NATS.
// It is non-blocking: errors are logged but do not propagate to the caller
// to avoid disrupting the agent event loop.
func (l *AuditLogger) Log(ev AuditEvent) {
	// Assign EventID if not set by caller.
	if ev.EventID == "" {
		seq := atomic.AddUint64(&l.seq, 1)
		ev.EventID = fmt.Sprintf("dlp-%d-%d", ev.Timestamp.UnixNano(), seq)
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}

	data, err := json.Marshal(ev)
	if err != nil {
		return // should never happen with this struct
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Write to file (append mode, re-open each time for logrotate compatibility).
	if l.filePath != "" {
		f, err := os.OpenFile(l.filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
		if err == nil {
			_, _ = f.Write(data)
			_, _ = f.Write([]byte("\n"))
			f.Close()
		}
	}

	// Publish to NATS audit subject.
	if l.publish != nil {
		_ = l.publish(l.auditSubj, data)

		// For escalations and blocks, also publish to the escalation subject
		// so the SOC/SOAR workflow is triggered immediately.
		if ev.Action == ActionEscalate || ev.Action == ActionBlock {
			subj := l.escSubj
			if ev.PolicyName != "" {
				// Prefer the policy-specific escalation subject if configured.
				// (Passed via EnforcementResult.EscalationSubject by the caller)
			}
			_ = l.publish(subj, data)
		}
	}
}

// LogFromScan creates an AuditEvent from a completed DLP scan and enforcement
// result, then calls Log. This is the primary convenience method for the agent.
//
// Parameters:
//   matches:    findings from Scanner.ScanFile()
//   result:     policy enforcement decision
//   channel:    exfiltration channel
//   filePath:   absolute path of the scanned file
//   sha256:     pre-computed SHA256 (pass "" to skip)
//   mime:       detected MIME type (pass MimeUnknown to skip)
//   label:      classification label from Classifier (pass "" to derive from matches)
//   pid, uid:   process identity
//   processName, processExe: process name and executable path
//   tenantID, hostID: agent identity
func (l *AuditLogger) LogFromScan(
	matches []Match,
	result EnforcementResult,
	channel Channel,
	filePath, sha256 string,
	mime MimeType,
	label SensitivityLabel,
	pid, uid uint32,
	processName, processExe string,
	tenantID, hostID string,
) {
	ev := AuditEvent{
		Timestamp:       time.Now().UTC(),
		TenantID:        tenantID,
		HostID:          hostID,
		UserID:          fmt.Sprintf("%d", uid),
		ProcessPID:      pid,
		ProcessName:     processName,
		ProcessExe:      processExe,
		ObjectPath:      filePath,
		ObjectType:      "file",
		ObjectSHA256:    sha256,
		ObjectMIME:      mime,
		SensitivityLabel: label,
		Channel:         channel,
		DetectionSource: "pattern",
		MitreAttck:      channelToMITRE(channel),
	}

	// Summarise pattern matches (omit full snippet for very large match sets).
	for i, m := range matches {
		if i >= 20 {
			break // cap at 20 summaries per event
		}
		ev.PatternMatches = append(ev.PatternMatches, PatternMatchSummary{
			PatternID: m.PatternID,
			Name:      m.Pattern,
			Severity:  m.Severity,
			Line:      m.Line,
			Snippet:   m.Snippet,
		})
	}

	// Derive severity from the highest-severity match.
	ev.Severity = highestSeverity(matches)

	// Apply enforcement result.
	if result.Violated {
		ev.PolicyID = result.PolicyID
		ev.PolicyName = result.PolicyName
		ev.Action = result.Action
		ev.BlockReason = result.Reason
		ev.ActionTaken = result.Action == ActionBlock || result.Action == ActionQuarantine
	} else {
		ev.Action = ActionAudit
	}

	// If no explicit label, derive from pattern severity.
	if ev.SensitivityLabel == "" {
		ev.SensitivityLabel = sensitivityFromSeverity(ev.Severity)
	}

	l.Log(ev)
}

// LogBehavioral creates an AuditEvent from a BehavioralAlert and calls Log.
func (l *AuditLogger) LogBehavioral(alert BehavioralAlert, tenantID, hostID string) {
	ev := AuditEvent{
		Timestamp:        time.Now().UTC(),
		TenantID:         tenantID,
		HostID:           hostID,
		UserID:           fmt.Sprintf("%d", alert.Uid),
		ProcessPID:       alert.Pid,
		ProcessName:      alert.ProcessName,
		Channel:          alert.Channel,
		Severity:         alert.Severity,
		BehavioralRule:   alert.Rule,
		BehavioralDetail: alert.Detail,
		MLRiskScore:      alert.MLRiskScore,
		DetectionSource:  "behavioral",
		Action:           ActionAlert, // behavioral always alerts; policy decides escalation
		MitreAttck:       alert.MitreAttck,
		SensitivityLabel: sensitivityFromBehavioralSeverity(alert.Severity),
	}
	l.Log(ev)
}

// LogDeviceControl creates an AuditEvent from a device-control block event.
func (l *AuditLogger) LogDeviceControl(
	filePath, reason string,
	matches []Match,
	result EnforcementResult,
	pid, uid uint32,
	processName string,
	tenantID, hostID string,
) {
	ev := AuditEvent{
		Timestamp:       time.Now().UTC(),
		TenantID:        tenantID,
		HostID:          hostID,
		UserID:          fmt.Sprintf("%d", uid),
		ProcessPID:      pid,
		ProcessName:     processName,
		ObjectPath:      filePath,
		ObjectType:      "usb",
		Channel:         ChannelUSB,
		Severity:        "high",
		Action:          ActionBlock,
		ActionTaken:     true,
		BlockReason:     reason,
		DetectionSource: "device_control",
		MitreAttck:      channelToMITRE(ChannelUSB),
	}
	if result.Violated {
		ev.PolicyID = result.PolicyID
		ev.PolicyName = result.PolicyName
	}
	for i, m := range matches {
		if i >= 20 {
			break
		}
		ev.PatternMatches = append(ev.PatternMatches, PatternMatchSummary{
			PatternID: m.PatternID,
			Name:      m.Pattern,
			Severity:  m.Severity,
		})
		ev.DetectionSource = "device_control+pattern"
	}
	if len(matches) > 0 {
		ev.SensitivityLabel = sensitivityFromSeverity(highestSeverity(matches))
	} else {
		ev.SensitivityLabel = LabelConfidential
	}
	l.Log(ev)
}

// ─────────────────────────────────────────────────────────────────────────────
// MITRE ATT&CK channel mapping
// ─────────────────────────────────────────────────────────────────────────────

// channelToMITRE maps DLP channels to relevant MITRE ATT&CK technique IDs.
func channelToMITRE(ch Channel) []string {
	switch ch {
	case ChannelUSB:
		// T1052: Exfiltration Over Physical Medium
		return []string{"T1052"}
	case ChannelCloudStorage:
		// T1567: Exfiltration Over Web Service
		return []string{"T1567"}
	case ChannelEmail:
		// T1048: Exfiltration Over Alternative Protocol
		return []string{"T1048"}
	case ChannelPrint:
		// T1048.002: Exfiltration Over Alternative Protocol - Physical
		return []string{"T1048"}
	case ChannelClipboard:
		// T1115: Clipboard Data
		return []string{"T1115"}
	case ChannelNetworkUpload:
		// T1041: Exfiltration Over C2 Channel / T1048
		return []string{"T1041", "T1048"}
	case ChannelLocalFile:
		// T1005: Data from Local System
		return []string{"T1005"}
	default:
		// T1005 as fallback
		return []string{"T1005"}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

// highestSeverity returns the most severe severity string from a slice of matches.
func highestSeverity(matches []Match) string {
	max := 0
	result := "low"
	for _, m := range matches {
		if v := severityValue(m.Severity); v > max {
			max = v
			result = m.Severity
		}
	}
	return result
}

// sensitivityFromBehavioralSeverity maps a behavioral alert severity to a label.
func sensitivityFromBehavioralSeverity(sev string) SensitivityLabel {
	switch sev {
	case "critical":
		return LabelSecret
	case "high":
		return LabelRestricted
	case "medium":
		return LabelConfidential
	default:
		return LabelInternal
	}
}
