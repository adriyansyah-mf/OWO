// Package gtfobins loads a local GTFOBins API JSON and provides lookup by binary name.
// Data is loaded once at startup; no real-time API calls.
package gtfobins

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// DB holds binary name -> list of function names (e.g. "shell", "reverse-shell").
type DB struct {
	mu   sync.RWMutex
	byName map[string][]string // lowercase binary name -> functions
}

// Raw structure for parsing gtfobins api.json (only what we need).
type apiJSON struct {
	Executables map[string]struct {
		Functions map[string]interface{} `json:"functions"`
		Alias     string                 `json:"alias,omitempty"`
	} `json:"executables"`
}

// Load reads a local gtfobins api.json file and returns a DB. If path is empty, returns nil, nil.
func Load(path string) (*DB, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gtfobins read %s: %w", path, err)
	}
	var raw apiJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("gtfobins parse: %w", err)
	}
	db := &DB{byName: make(map[string][]string)}
	for name, ent := range raw.Executables {
		if ent.Functions == nil {
			continue
		}
		fns := make([]string, 0, len(ent.Functions))
		for fn := range ent.Functions {
			fns = append(fns, fn)
		}
		key := strings.ToLower(strings.TrimSpace(name))
		if key != "" {
			db.byName[key] = fns
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

// BinaryNameFromPath returns the basename of path without extension, lowercased (e.g. /usr/bin/python3 -> "python3").
func BinaryNameFromPath(path string) string {
	base := filepath.Base(path)
	base = strings.TrimSpace(base)
	if base == "" || base == "-" {
		return ""
	}
	return strings.ToLower(base)
}
