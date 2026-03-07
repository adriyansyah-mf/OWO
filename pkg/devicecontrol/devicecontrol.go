// Package devicecontrol provides CrowdStrike-style device control (USB, file extension policies).
//
// Enterprise additions (this refactor):
//   - CheckWithDLP: combines extension-based device control with DLP content
//     scanning and policy enforcement in a single call.  The caller receives
//     the enforcement decision, the DLP matches, and audit context in one shot.
//   - WriteStats: per-process write counters used by the behavioral DLP engine
//     to detect USB bulk-copy activity.
package devicecontrol

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"edr-linux/pkg/dlp"
)

// Policy defines device control rules (extensions allowed/blocked for removable media).
type Policy struct {
	Enabled           bool     `json:"enabled"`
	Mode              string   `json:"mode"`              // "allow" = whitelist, "block" = blacklist
	AllowedExtensions []string `json:"allowed_extensions"` // e.g. [".pdf", ".doc", ".txt"]
	BlockedExtensions []string `json:"blocked_extensions"` // e.g. [".exe", ".sql", ".db"]
	RemovablePaths    []string `json:"removable_paths"`   // e.g. ["/media", "/run/media", "/mnt"]
}

// DefaultPolicy returns a sensible default.
func DefaultPolicy() Policy {
	return Policy{
		Enabled:           false,
		Mode:              "allow",
		AllowedExtensions: []string{".pdf", ".doc", ".docx", ".txt", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png"},
		BlockedExtensions: []string{".exe", ".dll", ".bat", ".sh", ".sql", ".db", ".sqlite"},
		RemovablePaths:    []string{"/media", "/run/media", "/mnt"},
	}
}

// Checker applies policy to file operations.
type Checker struct {
	mu     sync.RWMutex
	policy Policy
}

// NewChecker creates a checker with default policy.
func NewChecker() *Checker {
	return &Checker{policy: DefaultPolicy()}
}

// SetPolicy updates the policy.
func (c *Checker) SetPolicy(p Policy) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(p.RemovablePaths) == 0 {
		p.RemovablePaths = DefaultPolicy().RemovablePaths
	}
	c.policy = p
}

// GetPolicy returns current policy.
func (c *Checker) GetPolicy() Policy {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.policy
}

// IsRemovablePath returns true if path is under a removable media mount.
func (c *Checker) IsRemovablePath(path string) bool {
	c.mu.RLock()
	paths := c.policy.RemovablePaths
	c.mu.RUnlock()
	path = filepath.Clean(path)
	for _, p := range paths {
		p = filepath.Clean(p)
		if p == "" {
			continue
		}
		if path == p || strings.HasPrefix(path, p+"/") {
			return true
		}
	}
	return false
}

// Check returns (allowed, reason). If policy disabled, always allowed.
func (c *Checker) Check(filePath string) (allowed bool, reason string) {
	c.mu.RLock()
	pol := c.policy
	c.mu.RUnlock()

	if !pol.Enabled {
		return true, ""
	}
	if !c.IsRemovablePath(filePath) {
		return true, ""
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == "" {
		ext = ".(no-ext)"
	}

	// Normalize: ensure leading dot
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}

	allowList := normalizeExts(pol.AllowedExtensions)
	blockList := normalizeExts(pol.BlockedExtensions)

	switch pol.Mode {
	case "allow", "whitelist":
		for _, e := range allowList {
			if ext == e {
				return true, ""
			}
		}
		return false, "extension " + ext + " not in allowed list"
	case "block", "blacklist":
		for _, e := range blockList {
			if ext == e {
				return false, "extension " + ext + " is blocked"
			}
		}
		return true, ""
	default:
		return true, ""
	}
}

func normalizeExts(exts []string) []string {
	var out []string
	for _, e := range exts {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if !strings.HasPrefix(e, ".") {
			e = "." + e
		}
		out = append(out, e)
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// DLPResult — output of CheckWithDLP
// ─────────────────────────────────────────────────────────────────────────────

// DLPResult is the combined device-control + DLP enforcement result returned
// by CheckWithDLP. The caller uses it to decide whether to block the write,
// emit an alert, or hand off to the audit logger.
type DLPResult struct {
	// Allowed is false when either the extension policy or a DLP policy blocks the write.
	Allowed bool

	// BlockReason is a human-readable explanation when Allowed is false.
	BlockReason string

	// DLPMatches contains the pattern-match findings (may be non-empty even when Allowed is true).
	DLPMatches []dlp.Match

	// Enforcement is the policy engine decision (Violated, Action, PolicyID, etc.).
	Enforcement dlp.EnforcementResult

	// Channel is always ChannelUSB for device-control calls.
	Channel dlp.Channel
}

// ─────────────────────────────────────────────────────────────────────────────
// CheckWithDLP — extension policy + DLP content scan + policy enforcement
// ─────────────────────────────────────────────────────────────────────────────

// CheckWithDLP performs a three-layer inspection of a file write to removable media:
//
//  Layer 1 — Extension policy (existing Check logic):
//    If the extension is blocked by the device control policy, return immediately
//    with Allowed=false. No content scan is performed (fast path).
//
//  Layer 2 — DLP content scan (Scanner.ScanFile):
//    If the file passes extension check, scan its content for sensitive patterns.
//    Binary files and files over MaxFileSize are skipped (Scanner handles this).
//
//  Layer 3 — Policy engine evaluation (PolicyEngine.Evaluate):
//    If any patterns matched, run the findings through the DLP policy engine to
//    determine the enforcement action (alert, block, quarantine, escalate).
//    If the action is ActionBlock or ActionQuarantine, Allowed is set to false.
//
// Parameters:
//   filePath:    absolute path of the file being written to removable media.
//   scanner:     DLP scanner. Pass nil to skip content scanning (extension-only).
//   engine:      DLP policy engine. Pass nil to skip policy evaluation.
//   uid:         UID of the writing process (string for policy scope matching).
//   processName: name of the writing process.
func (c *Checker) CheckWithDLP(
	filePath string,
	scanner *dlp.Scanner,
	engine *dlp.PolicyEngine,
	uid, processName string,
) DLPResult {
	result := DLPResult{
		Allowed: true,
		Channel: dlp.ChannelUSB,
	}

	// Layer 1: extension-based device control.
	if allowed, reason := c.Check(filePath); !allowed {
		result.Allowed = false
		result.BlockReason = reason
		result.Enforcement = dlp.EnforcementResult{
			Violated: true,
			Action:   dlp.ActionBlock,
			Reason:   reason,
		}
		return result
	}

	// Layer 2: DLP content scan (only if scanner provided).
	if scanner == nil {
		return result
	}
	matches, err := scanner.ScanFile(filePath)
	if err != nil || len(matches) == 0 {
		return result
	}
	result.DLPMatches = matches

	// Layer 3: policy engine (only if engine provided).
	if engine == nil {
		// No policy engine: alert by default when matches found.
		result.Enforcement = dlp.EnforcementResult{
			Violated:   true,
			Action:     dlp.ActionAlert,
			PolicyName: "default",
			Reason:     fmt.Sprintf("DLP pattern match on USB write: %d finding(s)", len(matches)),
		}
		return result
	}

	enforcement := engine.Evaluate(matches, dlp.ChannelUSB, uid, processName, filePath)
	result.Enforcement = enforcement

	if enforcement.Violated &&
		(enforcement.Action == dlp.ActionBlock || enforcement.Action == dlp.ActionQuarantine) {
		result.Allowed = false
		result.BlockReason = enforcement.Reason
	}

	return result
}

// ─────────────────────────────────────────────────────────────────────────────
// WriteStats — per-process USB write tracking for behavioral detection
// ─────────────────────────────────────────────────────────────────────────────

// WriteStats accumulates USB write activity per process for the behavioral engine.
// Counters reset after the configured window to implement a sliding rate limit.
type WriteStats struct {
	mu      sync.Mutex
	entries map[uint32]*writeEntry
	window  time.Duration
}

type writeEntry struct {
	count     int
	bytes     int64
	windowStart time.Time
}

// NewWriteStats creates a write-stats tracker with the given sliding window.
// Pass 60*time.Second for standard per-minute rate tracking.
func NewWriteStats(window time.Duration) *WriteStats {
	if window <= 0 {
		window = 60 * time.Second
	}
	return &WriteStats{
		entries: make(map[uint32]*writeEntry),
		window:  window,
	}
}

// Record increments the write counter for pid by 1 file of sizeBytes.
// Returns (fileCount, totalBytes) within the current window.
func (ws *WriteStats) Record(pid uint32, sizeBytes int64) (fileCount int, totalBytes int64) {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	now := time.Now()
	e, ok := ws.entries[pid]
	if !ok || now.Sub(e.windowStart) > ws.window {
		// Start a new window for this pid.
		e = &writeEntry{windowStart: now}
		ws.entries[pid] = e
	}
	e.count++
	e.bytes += sizeBytes
	return e.count, e.bytes
}

// Remove clears tracking state for a process (call on process exit).
func (ws *WriteStats) Remove(pid uint32) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	delete(ws.entries, pid)
}
