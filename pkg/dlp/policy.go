// Package dlp: policy.go — Enterprise DLP policy engine.
//
// Responsibilities:
//   - Define enforcement actions (alert, block, quarantine, escalate, audit).
//   - Define exfiltration channels (USB, cloud storage, email, clipboard, print, network).
//   - PolicyStore: in-memory store with JSON file offline cache so endpoints stay
//     protected even when disconnected from the backend.
//   - PolicyEngine: evaluate a set of DLP Match results against all active policies
//     and return the most restrictive EnforcementResult.
//   - Quarantine helper: moves a file to an isolated directory (cross-device safe).
//
// Integration points:
//   - PolicyStore is populated from config on startup and updated via NATS messages.
//   - PolicyEngine.Evaluate() is called after every Scanner.ScanFile().
//   - Quarantine() is called by the agent when Action == ActionQuarantine.
package dlp

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Enforcement actions
// ─────────────────────────────────────────────────────────────────────────────

// EnforcementAction describes what the DLP engine does when a policy fires.
type EnforcementAction string

const (
	// ActionAudit records the event silently — no visible effect on the user.
	// Use as a baseline to build a data inventory without interrupting workflows.
	ActionAudit EnforcementAction = "audit"

	// ActionAlert logs the event and sends an alert to the NATS alerts subject.
	// The file operation is allowed to proceed.
	ActionAlert EnforcementAction = "alert"

	// ActionEscalate sends a high-priority ticket to SOC/SOAR via the configured
	// NATS escalation subject. The file operation is still allowed (combine with
	// ActionBlock to both block and escalate).
	ActionEscalate EnforcementAction = "escalate"

	// ActionQuarantine moves the file to an isolated directory before the operation
	// can complete. The write/copy is effectively prevented on the source path.
	ActionQuarantine EnforcementAction = "quarantine"

	// ActionBlock denies the file operation entirely. The agent must enforce this
	// at the point of the write/copy call (device control or eBPF level).
	ActionBlock EnforcementAction = "block"
)

// actionSeverityRank maps each action to a rank used for "most restrictive wins".
// Higher = more restrictive.
var actionSeverityRank = map[EnforcementAction]int{
	ActionAudit:      1,
	ActionAlert:      2,
	ActionEscalate:   3,
	ActionQuarantine: 4,
	ActionBlock:      5,
}

// ─────────────────────────────────────────────────────────────────────────────
// Exfiltration channels
// ─────────────────────────────────────────────────────────────────────────────

// Channel identifies the data exfiltration vector being monitored.
type Channel string

const (
	// ChannelUSB covers writes to removable media (/media, /run/media, /mnt).
	ChannelUSB Channel = "usb"

	// ChannelCloudStorage covers uploads via known cloud-sync processes
	// (rclone, gdrive, onedrive, dropbox, etc.) or outbound to cloud domains.
	ChannelCloudStorage Channel = "cloud_storage"

	// ChannelEmail covers data written to mail-client spool directories
	// or outbound SMTP connections.
	ChannelEmail Channel = "email"

	// ChannelClipboard covers clipboard access (X11/Wayland; future kernel hook).
	ChannelClipboard Channel = "clipboard"

	// ChannelPrint covers data sent to CUPS spool paths (/var/spool/cups, lp).
	ChannelPrint Channel = "print"

	// ChannelNetworkUpload covers generic outbound file transfers not covered
	// by more specific channels (HTTP POST, SCP, rsync, FTP, etc.).
	ChannelNetworkUpload Channel = "network_upload"

	// ChannelLocalFile covers on-demand scans of the local filesystem.
	ChannelLocalFile Channel = "local_file"

	// ChannelAll is a wildcard that matches every channel.
	ChannelAll Channel = "all"
)

// KnownCloudStorageProcesses lists process names associated with cloud sync tools.
// The behavioral engine and channel detection use this list.
var KnownCloudStorageProcesses = []string{
	"rclone", "gdrive", "google-drive-fs", "onedrive", "dropbox",
	"mega-cmd", "megasync", "box", "pcloud", "nextcloud", "aws", "gsutil",
}

// KnownCloudStorageDomains lists domains used by cloud storage APIs.
// Used by the network monitor to tag ChannelCloudStorage events.
var KnownCloudStorageDomains = []string{
	"drive.google.com", "docs.google.com", "storage.googleapis.com",
	"onedrive.live.com", "sharepoint.com", "graph.microsoft.com",
	"dropbox.com", "api.dropboxapi.com", "content.dropboxapi.com",
	"mega.nz", "g.api.mega.co.nz", "box.com", "upload.box.com",
	"pcloud.com", "eapi.pcloud.com",
}

// IsCloudStorageProcess returns true if processName matches a known cloud tool.
func IsCloudStorageProcess(processName string) bool {
	p := strings.ToLower(processName)
	for _, known := range KnownCloudStorageProcesses {
		if p == known || strings.HasPrefix(p, known) {
			return true
		}
	}
	return false
}

// IsCloudStorageDomain returns true if domain matches a known cloud storage domain.
func IsCloudStorageDomain(domain string) bool {
	d := strings.ToLower(domain)
	for _, known := range KnownCloudStorageDomains {
		if d == known || strings.HasSuffix(d, "."+known) {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// DLP Policy definition
// ─────────────────────────────────────────────────────────────────────────────

// DLPPolicy defines an enterprise DLP enforcement rule. Multiple policies can
// be active simultaneously; the PolicyEngine applies all and returns the most
// restrictive result.
type DLPPolicy struct {
	// ID is a stable, unique identifier (slug). Used in audit trails and cache keys.
	ID string `json:"id"`

	// Name is the human-readable label shown in alerts and the web UI.
	Name string `json:"name"`

	// Enabled gates whether this policy is evaluated. Default: true.
	Enabled bool `json:"enabled"`

	// PatternIDs restricts the policy to specific DLP pattern identifiers.
	// An empty slice means "match any pattern."
	PatternIDs []string `json:"pattern_ids,omitempty"`

	// MinSeverity sets the lower bound on pattern severity that activates this policy.
	// Values: "low", "medium", "high", "critical". Default: "medium".
	MinSeverity string `json:"min_severity"`

	// Channels lists which exfiltration vectors this policy applies to.
	// Use ChannelAll or leave empty to apply to every channel.
	Channels []Channel `json:"channels,omitempty"`

	// Actions lists the enforcement steps to take, in preference order.
	// If the first action fails (e.g. quarantine dir missing), the next is tried.
	Actions []EnforcementAction `json:"actions"`

	// QuarantineDir is the target directory when ActionQuarantine is used.
	// Default: /var/lib/edr/dlp/quarantine
	QuarantineDir string `json:"quarantine_dir,omitempty"`

	// EscalationSubject is the NATS subject for SOC/SOAR escalation messages.
	// Required when ActionEscalate is listed in Actions. Default: "dlp.escalation".
	EscalationSubject string `json:"escalation_subject,omitempty"`

	// ScopeUsers limits the policy to specific user IDs (UID as string).
	// An empty slice means "all users."
	ScopeUsers []string `json:"scope_users,omitempty"`

	// ScopePaths limits the policy to file paths under these prefixes.
	// An empty slice means "all paths."
	ScopePaths []string `json:"scope_paths,omitempty"`

	// ScopeProcesses limits the policy to processes with these names.
	// An empty slice means "all processes."
	ScopeProcesses []string `json:"scope_processes,omitempty"`

	// CacheVersion is incremented by the backend on every update.
	// The agent uses this to detect stale offline caches.
	CacheVersion int64 `json:"cache_version"`

	// UpdatedAt is when the policy was last modified on the backend.
	UpdatedAt time.Time `json:"updated_at"`
}

// ─────────────────────────────────────────────────────────────────────────────
// EnforcementResult
// ─────────────────────────────────────────────────────────────────────────────

// EnforcementResult is the output of PolicyEngine.Evaluate(). It carries the
// most restrictive action determined across all matching policies, plus enough
// context for the caller to act and for the audit logger to record.
type EnforcementResult struct {
	// Violated is true when at least one policy triggered.
	Violated bool

	// Action is the most restrictive action to execute.
	Action EnforcementAction

	// PolicyID and PolicyName identify the triggering policy.
	PolicyID   string
	PolicyName string

	// Reason is a human-readable explanation suitable for logs and alerts.
	Reason string

	// EscalationSubject is the NATS subject to publish to when escalating.
	EscalationSubject string

	// QuarantineDir is where to move the file when quarantining.
	QuarantineDir string

	// AllMatchedPolicies collects results from every matching policy (for full
	// audit trail — not just the winning one).
	AllMatchedPolicies []EnforcementResult
}

// ─────────────────────────────────────────────────────────────────────────────
// PolicyStore — thread-safe store with offline persistence
// ─────────────────────────────────────────────────────────────────────────────

// PolicyStore holds the active DLP policies in memory with optional JSON file
// persistence. When the agent is offline, it serves the last-known policies
// from disk, ensuring continuous protection.
type PolicyStore struct {
	mu        sync.RWMutex
	policies  []DLPPolicy
	cacheFile string // empty = no persistence
}

// NewPolicyStore creates a store. If cacheFile is non-empty, the store loads
// previously persisted policies on startup and writes every update to disk.
func NewPolicyStore(cacheFile string) *PolicyStore {
	s := &PolicyStore{cacheFile: cacheFile}
	if cacheFile != "" {
		// Best-effort: ignore missing file on first run.
		_ = s.loadCache()
	}
	return s
}

// SetPolicies atomically replaces all policies and persists to cache.
func (s *PolicyStore) SetPolicies(policies []DLPPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies = policies
	if s.cacheFile != "" {
		_ = s.saveCache()
	}
}

// GetPolicies returns a copy of the current policy slice (safe for the caller to read).
func (s *PolicyStore) GetPolicies() []DLPPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]DLPPolicy, len(s.policies))
	copy(out, s.policies)
	return out
}

// AddOrUpdatePolicy upserts a single policy by its ID.
func (s *PolicyStore) AddOrUpdatePolicy(p DLPPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, existing := range s.policies {
		if existing.ID == p.ID {
			s.policies[i] = p
			if s.cacheFile != "" {
				_ = s.saveCache()
			}
			return
		}
	}
	s.policies = append(s.policies, p)
	if s.cacheFile != "" {
		_ = s.saveCache()
	}
}

// saveCache writes the current policies to the cache file (caller holds mu.Lock).
func (s *PolicyStore) saveCache() error {
	if err := os.MkdirAll(filepath.Dir(s.cacheFile), 0700); err != nil {
		return err
	}
	b, err := json.Marshal(s.policies)
	if err != nil {
		return err
	}
	// Write to a temp file first to avoid a partial write corrupting the cache.
	tmp := s.cacheFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.cacheFile)
}

// loadCache reads policies from the cache file (called once on init, no lock needed).
func (s *PolicyStore) loadCache() error {
	b, err := os.ReadFile(s.cacheFile)
	if err != nil {
		return err
	}
	var policies []DLPPolicy
	if err := json.Unmarshal(b, &policies); err != nil {
		return fmt.Errorf("dlp: policy cache corrupt: %w", err)
	}
	s.mu.Lock()
	s.policies = policies
	s.mu.Unlock()
	return nil
}

// DefaultPolicies returns the built-in enterprise DLP policies used when no
// backend configuration is available. Override via NATS policy sync or config.
func DefaultPolicies() []DLPPolicy {
	now := time.Now().UTC()
	return []DLPPolicy{
		{
			ID:                "pol-critical-usb-block",
			Name:              "Block Critical Secrets to USB",
			Enabled:           true,
			PatternIDs:        []string{"aws_key", "aws_secret", "private_key"},
			MinSeverity:       "critical",
			Channels:          []Channel{ChannelUSB},
			Actions:           []EnforcementAction{ActionBlock, ActionEscalate},
			EscalationSubject: "dlp.escalation",
			QuarantineDir:     "/var/lib/edr/dlp/quarantine",
			CacheVersion:      1,
			UpdatedAt:         now,
		},
		{
			ID:                "pol-high-cloud-block",
			Name:              "Block High-Severity Data to Cloud Storage",
			Enabled:           true,
			MinSeverity:       "high",
			Channels:          []Channel{ChannelCloudStorage, ChannelNetworkUpload},
			Actions:           []EnforcementAction{ActionBlock, ActionEscalate},
			EscalationSubject: "dlp.escalation",
			CacheVersion:      1,
			UpdatedAt:         now,
		},
		{
			ID:                "pol-high-alert-escalate",
			Name:              "Alert & Escalate High-Severity Events",
			Enabled:           true,
			MinSeverity:       "high",
			Channels:          []Channel{ChannelAll},
			Actions:           []EnforcementAction{ActionAlert, ActionEscalate},
			EscalationSubject: "dlp.escalation",
			CacheVersion:      1,
			UpdatedAt:         now,
		},
		{
			ID:          "pol-audit-baseline",
			Name:        "Audit All DLP Events (baseline inventory)",
			Enabled:     true,
			MinSeverity: "low",
			Channels:    []Channel{ChannelAll},
			Actions:     []EnforcementAction{ActionAudit},
			CacheVersion: 1,
			UpdatedAt:   now,
		},
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// PolicyEngine
// ─────────────────────────────────────────────────────────────────────────────

// PolicyEngine evaluates DLP scan results against all active policies and
// returns the most restrictive EnforcementResult.
type PolicyEngine struct {
	store *PolicyStore
}

// NewPolicyEngine creates an engine backed by the given PolicyStore.
func NewPolicyEngine(store *PolicyStore) *PolicyEngine {
	return &PolicyEngine{store: store}
}

// Evaluate determines the enforcement action for a set of DLP matches.
//
// Parameters:
//   - matches:     findings from Scanner.ScanFile() or Scanner.ScanPaths()
//   - channel:     which exfiltration vector triggered the evaluation
//   - uid:         UID of the process performing the operation (string for flexible matching)
//   - processName: name of the process (e.g. "rclone", "bash")
//   - filePath:    absolute path of the file being evaluated
//
// Returns the most restrictive result across all matching policies.
// If no policy fires, Violated is false.
func (e *PolicyEngine) Evaluate(
	matches []Match,
	channel Channel,
	uid, processName, filePath string,
) EnforcementResult {
	if len(matches) == 0 {
		return EnforcementResult{}
	}

	policies := e.store.GetPolicies()

	var winner EnforcementResult
	winnerRank := 0
	var allMatched []EnforcementResult

	for _, pol := range policies {
		if !pol.Enabled {
			continue
		}
		if !channelMatches(pol.Channels, channel) {
			continue
		}
		if !listMatchesValue(pol.ScopeUsers, uid) {
			continue
		}
		if !listMatchesValue(pol.ScopeProcesses, processName) {
			continue
		}
		if !pathInScope(pol.ScopePaths, filePath) {
			continue
		}

		// Filter matches by this policy's pattern IDs and minimum severity.
		var triggered []Match
		for _, m := range matches {
			if !listMatchesValue(pol.PatternIDs, m.PatternID) {
				continue
			}
			if severityValue(m.Severity) < severityValue(pol.MinSeverity) {
				continue
			}
			triggered = append(triggered, m)
		}
		if len(triggered) == 0 {
			continue
		}

		action := firstAction(pol.Actions)
		result := EnforcementResult{
			Violated:          true,
			Action:            action,
			PolicyID:          pol.ID,
			PolicyName:        pol.Name,
			Reason:            fmt.Sprintf("policy %q: %d match(es) on channel %s", pol.Name, len(triggered), channel),
			EscalationSubject: pol.EscalationSubject,
			QuarantineDir:     pol.QuarantineDir,
		}
		allMatched = append(allMatched, result)

		rank := actionSeverityRank[action]
		if rank > winnerRank {
			winnerRank = rank
			winner = result
		}
	}

	if winner.Violated {
		winner.AllMatchedPolicies = allMatched
	}
	return winner
}

// ─────────────────────────────────────────────────────────────────────────────
// Quarantine helper
// ─────────────────────────────────────────────────────────────────────────────

// Quarantine moves src to quarantineDir with a timestamped filename.
// It handles cross-device moves (e.g. USB → local) via copy+remove fallback.
// Returns the quarantine destination path.
func Quarantine(src, quarantineDir string) (string, error) {
	if quarantineDir == "" {
		quarantineDir = "/var/lib/edr/dlp/quarantine"
	}
	if err := os.MkdirAll(quarantineDir, 0700); err != nil {
		return "", fmt.Errorf("dlp: quarantine mkdir: %w", err)
	}

	base := filepath.Base(src)
	ts := time.Now().UTC().Format("20060102T150405Z")
	dst := filepath.Join(quarantineDir, ts+"_"+base)

	if err := os.Rename(src, dst); err != nil {
		// Cross-device: fall back to copy then remove original.
		if err2 := copyThenRemove(src, dst); err2 != nil {
			return "", fmt.Errorf("dlp: quarantine %s: %w", src, err2)
		}
	}
	return dst, nil
}

// copyThenRemove copies src to dst then removes src (cross-device quarantine fallback).
func copyThenRemove(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return err
	}

	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(dst)
		return err
	}
	return os.Remove(src)
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

// severityValue converts severity string to an integer for comparison.
func severityValue(s string) int {
	switch strings.ToLower(s) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return 0
	}
}

// firstAction returns the first listed action, defaulting to ActionAlert.
func firstAction(actions []EnforcementAction) EnforcementAction {
	if len(actions) == 0 {
		return ActionAlert
	}
	return actions[0]
}

// channelMatches returns true when target is covered by the policy's channel list.
func channelMatches(policyChannels []Channel, target Channel) bool {
	if len(policyChannels) == 0 {
		return true
	}
	for _, c := range policyChannels {
		if c == ChannelAll || c == target {
			return true
		}
	}
	return false
}

// listMatchesValue returns true when target is in the list, or the list is empty
// (meaning "no restriction").
func listMatchesValue(list []string, target string) bool {
	if len(list) == 0 {
		return true
	}
	for _, v := range list {
		if v == target {
			return true
		}
	}
	return false
}

// pathInScope returns true when filePath starts with one of the scope prefixes,
// or the scope list is empty (meaning "all paths").
func pathInScope(scopePaths []string, filePath string) bool {
	if len(scopePaths) == 0 {
		return true
	}
	for _, prefix := range scopePaths {
		if filePath == prefix || strings.HasPrefix(filePath, prefix+"/") {
			return true
		}
	}
	return false
}
