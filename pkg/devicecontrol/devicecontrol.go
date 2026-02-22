// Package devicecontrol provides CrowdStrike-style device control (USB, file extension policies).
package devicecontrol

import (
	"path/filepath"
	"strings"
	"sync"
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
