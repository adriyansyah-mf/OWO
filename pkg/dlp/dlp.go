// Package dlp provides Data Loss Prevention content scanning.
package dlp

import (
	"bufio"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// Pattern defines a DLP detection rule.
type Pattern struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Regex  string `json:"regex"`
	Severity string `json:"severity"` // low, medium, high, critical
	re     *regexp.Regexp
}

// Match is one DLP finding.
type Match struct {
	Path     string `json:"path"`
	Pattern  string `json:"pattern"`
	PatternID string `json:"pattern_id"`
	Severity string `json:"severity"`
	Snippet  string `json:"snippet"` // masked snippet
	Line     int    `json:"line"`
}

// DefaultPatterns returns built-in DLP patterns.
func DefaultPatterns() []Pattern {
	defs := []struct {
		id, name, re, sev string
	}{
		{"cc", "Credit Card", `\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b`, "high"},
		{"ssn", "SSN", `\b\d{3}[\-]?\d{2}[\-]?\d{4}\b`, "high"},
		{"aws_key", "AWS Access Key", `AKIA[0-9A-Z]{16}`, "critical"},
		{"aws_secret", "AWS Secret Key", `(?i)aws_secret_access_key\s*=\s*['\"]?[A-Za-z0-9/+=]{40}`, "critical"},
		{"api_key", "Generic API Key", `(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{20,}`, "high"},
		{"private_key", "Private Key", `-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`, "critical"},
		{"password", "Password in config", `(?i)password\s*[:=]\s*['\"]?[^\s'\"]{8,}`, "medium"},
		{"bearer", "Bearer Token", `(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}`, "high"},
	}
	var out []Pattern
	for _, d := range defs {
		if re, err := regexp.Compile(d.re); err == nil {
			out = append(out, Pattern{ID: d.id, Name: d.name, Regex: d.re, Severity: d.sev, re: re})
		}
	}
	return out
}

// Scanner scans files for sensitive content.
type Scanner struct {
	Patterns    []Pattern
	MaxFileSize int64
	MaxMatches  int
}

// NewScanner creates a scanner with default patterns.
func NewScanner() *Scanner {
	return &Scanner{
		Patterns:    DefaultPatterns(),
		MaxFileSize: 2 * 1024 * 1024, // 2MB
		MaxMatches:  100,
	}
}

// SetPatterns replaces patterns. Regex strings are compiled.
func (s *Scanner) SetPatterns(patterns []Pattern) {
	var out []Pattern
	for _, p := range patterns {
		if re, err := regexp.Compile(p.Regex); err == nil {
			p.re = re
			out = append(out, p)
		} else {
			log.Printf("dlp: invalid pattern %s: %v", p.ID, err)
		}
	}
	s.Patterns = out
}

// mask redacts sensitive part for snippet.
func mask(m string) string {
	if len(m) <= 8 {
		return "***"
	}
	return m[:4] + "****" + m[len(m)-4:]
}

// isTextFile checks if content looks like text.
func isTextFile(b []byte) bool {
	for i := 0; i < len(b) && i < 512; i++ {
		if b[i] == 0 {
			return false
		}
		if b[i] < 32 && b[i] != '\t' && b[i] != '\n' && b[i] != '\r' {
			return false
		}
	}
	return true
}

// ScanFile scans one file for patterns.
func (s *Scanner) ScanFile(path string) ([]Match, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > s.MaxFileSize {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, _ := io.ReadFull(f, buf)
	if n > 0 && !isTextFile(buf[:n]) {
		return nil, nil
	}
	f.Seek(0, 0)

	var matches []Match
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() && len(matches) < s.MaxMatches {
		lineNum++
		line := scanner.Text()
		for _, p := range s.Patterns {
			if p.re == nil {
				continue
			}
			for _, loc := range p.re.FindAllStringIndex(line, -1) {
				snippet := line
				if loc[1]-loc[0] < len(line) {
					snippet = line[:loc[0]] + mask(line[loc[0]:loc[1]]) + line[loc[1]:]
				}
				// Truncate long lines
				if len(snippet) > 120 {
					snippet = snippet[:117] + "..."
				}
				matches = append(matches, Match{
					Path:      path,
					Pattern:   p.Name,
					PatternID: p.ID,
					Severity:  p.Severity,
					Snippet:   snippet,
					Line:      lineNum,
				})
				if len(matches) >= s.MaxMatches {
					return matches, nil
				}
			}
		}
	}
	return matches, nil
}

// ScanPaths walks paths and scans files.
func (s *Scanner) ScanPaths(paths []string) []Match {
	if len(paths) == 0 {
		paths = []string{"/tmp", "/var/tmp", "/home"}
	}
	var all []Match
	skipDir := func(name string) bool {
		return strings.HasPrefix(name, ".") || name == "node_modules" || name == ".git"
	}
	for _, root := range paths {
		root = filepath.Clean(root)
		if root == "" || !strings.HasPrefix(root, "/") {
			continue
		}
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() && skipDir(info.Name()) {
				return filepath.SkipDir
			}
			if info.IsDir() {
				return nil
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return nil
			}
			matches, err := s.ScanFile(path)
			if err != nil {
				return nil
			}
			all = append(all, matches...)
			return nil
		})
	}
	return all
}

// IsText checks if string is likely text (for small content).
func IsText(s string) bool {
	for _, r := range s {
		if r == 0 || (r < 32 && r != '\t' && r != '\n' && r != '\r') {
			return false
		}
		if r > unicode.MaxASCII && !unicode.IsLetter(r) && !unicode.IsNumber(r) {
			return false
		}
	}
	return true
}
