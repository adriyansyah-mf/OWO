// Package gtfobins loads a local GTFOBins API JSON and provides lookup by binary name.
// Data is loaded once at startup; no real-time API calls.
// If path is set but the file does not exist, it is auto-downloaded on first run.
package gtfobins

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const apiURL = "https://gtfobins.org/api.json"

// DB holds binary name -> list of function names and MITRE ATT&CK technique IDs.
type DB struct {
	mu         sync.RWMutex
	byName     map[string][]string // lowercase binary name -> functions
	byNameMitre map[string][]string // lowercase binary name -> MITRE technique IDs (e.g. T1059)
}

// Raw structure for parsing gtfobins api.json (only what we need).
type apiJSON struct {
	Functions   map[string]struct{ Mitre []string `json:"mitre"` } `json:"functions"`   // function type -> mitre IDs
	Executables map[string]struct {
		Functions map[string]interface{} `json:"functions"`
		Alias     string                 `json:"alias,omitempty"`
	} `json:"executables"`
}

// downloadTo fetches api.json and writes it to path, creating parent dirs if needed.
func downloadTo(path string) error {
	dir := filepath.Dir(path)
	if dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("mkdir: %w", err)
		}
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(apiURL)
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %s", resp.Status)
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	_, err = f.ReadFrom(resp.Body)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(path)
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// Load reads a local gtfobins api.json file and returns a DB. If path is empty, returns nil, nil.
// If the file does not exist, it is downloaded from gtfobins.org once, then loaded.
func Load(path string) (*DB, error) {
	if path == "" {
		return nil, nil
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			if err := downloadTo(path); err != nil {
				return nil, fmt.Errorf("gtfobins auto-download: %w", err)
			}
		} else {
			return nil, fmt.Errorf("gtfobins stat %s: %w", path, err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gtfobins read %s: %w", path, err)
	}
	var raw apiJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("gtfobins parse: %w", err)
	}
	db := &DB{
		byName:     make(map[string][]string),
		byNameMitre: make(map[string][]string),
	}
	// Build set of unique MITRE IDs per binary from each binary's function types.
	for name, ent := range raw.Executables {
		if ent.Functions == nil {
			continue
		}
		fns := make([]string, 0, len(ent.Functions))
		mitreSet := make(map[string]struct{})
		for fn := range ent.Functions {
			fns = append(fns, fn)
			if def, ok := raw.Functions[fn]; ok && len(def.Mitre) > 0 {
				for _, t := range def.Mitre {
					mitreSet[t] = struct{}{}
				}
			}
		}
		key := strings.ToLower(strings.TrimSpace(name))
		if key != "" {
			db.byName[key] = fns
			if len(mitreSet) > 0 {
				db.byNameMitre[key] = make([]string, 0, len(mitreSet))
				for t := range mitreSet {
					db.byNameMitre[key] = append(db.byNameMitre[key], t)
				}
			}
		}
	}
	return db, nil
}

// Lookup returns the list of GTFOBins function names for the given binary (e.g. "curl" -> ["download", "file-read", ...]).
// Binary name is normalized to lowercase. Returns nil if not in DB.
func (db *DB) Lookup(binaryName string) []string {
	if db == nil {
		return nil
	}
	key := strings.ToLower(strings.TrimSpace(binaryName))
	if key == "" {
		return nil
	}
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.byName[key]
}

// LookupMITRE returns MITRE ATT&CK technique IDs for the given binary (e.g. "curl" -> ["T1105", "T1005", ...]).
// Aggregated from all GTFOBins function types for that binary. Returns nil if not in DB or no techniques.
func (db *DB) LookupMITRE(binaryName string) []string {
	if db == nil {
		return nil
	}
	key := strings.ToLower(strings.TrimSpace(binaryName))
	if key == "" {
		return nil
	}
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.byNameMitre[key]
}

// BinaryNameFromPath returns the basename of path without extension, lowercased (e.g. /usr/bin/python3 -> "python3").
func BinaryNameFromPath(path string) string {
	base := filepath.Base(path)
	base = strings.TrimSpace(base)
	if base == "" || base == "-" {
		return ""
	}
	return strings.ToLower(base)
}
