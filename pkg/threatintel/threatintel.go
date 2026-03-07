// Package threatintel provides local Indicator of Compromise (IOC) management.
//
// Features:
//   - In-memory O(1) lookup by IP, domain, SHA256 hash, or URL.
//   - JSON file persistence with atomic tmp→rename writes.
//   - Bulk import from plain-text lists, JSON arrays, and abuse.ch URLhaus CSV.
//   - HTTP feed fetching with automatic format detection.
//   - Hit-count tracking and optional TTL expiry per IOC.
package threatintel

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ─── Types ────────────────────────────────────────────────────────────────────

// IOCType classifies an indicator.
type IOCType string

const (
	IOCTypeIP     IOCType = "ip"
	IOCTypeDomain IOCType = "domain"
	IOCTypeHash   IOCType = "hash" // SHA256 hex
	IOCTypeURL    IOCType = "url"
)

// TLP defines the Traffic Light Protocol marking for sharing restrictions.
type TLP string

const (
	TLPWhite TLP = "white" // unrestricted
	TLPGreen TLP = "green" // community sharing
	TLPAmber TLP = "amber" // limited distribution
	TLPRed   TLP = "red"   // no external sharing
)

// IOC is a single threat indicator with metadata.
type IOC struct {
	ID          string     `json:"id"`
	Type        IOCType    `json:"type"`
	Value       string     `json:"value"`      // normalized
	Severity    string     `json:"severity"`   // low/medium/high/critical
	Confidence  int        `json:"confidence"` // 0–100
	Source      string     `json:"source"`
	Tags        []string   `json:"tags,omitempty"`
	TLP         TLP        `json:"tlp"`
	Description string     `json:"description,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	HitCount    int        `json:"hit_count"`
	LastHitAt   *time.Time `json:"last_hit_at,omitempty"`
}

// LookupResult is returned by Store.Lookup*.
type LookupResult struct {
	Matched bool    `json:"matched"`
	IOC     *IOC    `json:"ioc,omitempty"`
	Value   string  `json:"value"`
	Type    IOCType `json:"type"`
}

// ImportResult summarises a bulk import operation.
type ImportResult struct {
	Added    int      `json:"added"`
	Skipped  int      `json:"skipped"` // duplicates or invalid
	Errors   []string `json:"errors,omitempty"`
	Source   string   `json:"source"`
	Duration string   `json:"duration"`
}

// Stats holds aggregated IOC statistics.
type Stats struct {
	Total      int            `json:"total"`
	ByType     map[string]int `json:"by_type"`
	BySeverity map[string]int `json:"by_severity"`
	BySource   map[string]int `json:"by_source"`
}

// ─── Store ────────────────────────────────────────────────────────────────────

// Store is the in-memory IOC database with file persistence.
type Store struct {
	mu        sync.RWMutex
	iocs      map[string]*IOC   // id → IOC
	byIP      map[string]string // normalized IP → id
	byDomain  map[string]string // normalized domain → id
	byHash    map[string]string // lowercase sha256 → id
	byURL     map[string]string // normalized URL → id
	storePath string
}

// New creates a Store and loads from storePath if it exists.
func New(storePath string) *Store {
	s := &Store{
		iocs:      make(map[string]*IOC),
		byIP:      make(map[string]string),
		byDomain:  make(map[string]string),
		byHash:    make(map[string]string),
		byURL:     make(map[string]string),
		storePath: storePath,
	}
	if storePath != "" {
		_ = s.load()
	}
	return s
}

// ─── Lookup ───────────────────────────────────────────────────────────────────

// Lookup auto-detects the type and looks up the value.
func (s *Store) Lookup(value string) LookupResult {
	v := strings.TrimSpace(value)
	switch DetectType(v) {
	case IOCTypeIP:
		return s.LookupIP(v)
	case IOCTypeDomain:
		return s.LookupDomain(v)
	case IOCTypeHash:
		return s.LookupHash(v)
	case IOCTypeURL:
		return s.LookupURL(v)
	}
	return LookupResult{Value: v}
}

func (s *Store) LookupIP(ip string) LookupResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	norm := strings.ToLower(strings.TrimSpace(ip))
	id, ok := s.byIP[norm]
	if !ok {
		return LookupResult{Value: ip, Type: IOCTypeIP}
	}
	ioc := s.iocs[id]
	if ioc.isExpired() {
		s.removeUnlocked(id)
		return LookupResult{Value: ip, Type: IOCTypeIP}
	}
	s.recordHit(ioc)
	cp := *ioc
	return LookupResult{Matched: true, IOC: &cp, Value: ip, Type: IOCTypeIP}
}

func (s *Store) LookupDomain(domain string) LookupResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	norm := normalizeDomain(domain)
	id, ok := s.byDomain[norm]
	if !ok {
		// Try parent domains (e.g. sub.evil.com → evil.com)
		parts := strings.Split(norm, ".")
		for i := 1; i < len(parts)-1; i++ {
			parent := strings.Join(parts[i:], ".")
			if pid, ok2 := s.byDomain[parent]; ok2 {
				id = pid
				ok = true
				break
			}
		}
	}
	if !ok {
		return LookupResult{Value: domain, Type: IOCTypeDomain}
	}
	ioc := s.iocs[id]
	if ioc.isExpired() {
		s.removeUnlocked(id)
		return LookupResult{Value: domain, Type: IOCTypeDomain}
	}
	s.recordHit(ioc)
	cp := *ioc
	return LookupResult{Matched: true, IOC: &cp, Value: domain, Type: IOCTypeDomain}
}

func (s *Store) LookupHash(hash string) LookupResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	norm := strings.ToLower(strings.TrimSpace(hash))
	id, ok := s.byHash[norm]
	if !ok {
		return LookupResult{Value: hash, Type: IOCTypeHash}
	}
	ioc := s.iocs[id]
	if ioc.isExpired() {
		s.removeUnlocked(id)
		return LookupResult{Value: hash, Type: IOCTypeHash}
	}
	s.recordHit(ioc)
	cp := *ioc
	return LookupResult{Matched: true, IOC: &cp, Value: hash, Type: IOCTypeHash}
}

func (s *Store) LookupURL(rawURL string) LookupResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	norm := normalizeURL(rawURL)
	id, ok := s.byURL[norm]
	if !ok {
		// Also check the domain component
		if u, err := url.Parse(rawURL); err == nil {
			if did, ok2 := s.byDomain[normalizeDomain(u.Hostname())]; ok2 {
				id = did
				ok = true
			}
		}
	}
	if !ok {
		return LookupResult{Value: rawURL, Type: IOCTypeURL}
	}
	ioc := s.iocs[id]
	if ioc.isExpired() {
		s.removeUnlocked(id)
		return LookupResult{Value: rawURL, Type: IOCTypeURL}
	}
	s.recordHit(ioc)
	cp := *ioc
	return LookupResult{Matched: true, IOC: &cp, Value: rawURL, Type: IOCTypeURL}
}

func (s *Store) recordHit(ioc *IOC) {
	ioc.HitCount++
	now := time.Now().UTC()
	ioc.LastHitAt = &now
}

func (ioc *IOC) isExpired() bool {
	return ioc.ExpiresAt != nil && time.Now().After(*ioc.ExpiresAt)
}

// ─── CRUD ─────────────────────────────────────────────────────────────────────

// Add inserts or updates an IOC. Duplicate values (same type+value) are updated.
func (s *Store) Add(ioc IOC) (IOC, error) {
	if ioc.Value == "" {
		return IOC{}, fmt.Errorf("value is required")
	}
	ioc.Value = normalizeValue(ioc.Type, ioc.Value)
	if ioc.ID == "" {
		ioc.ID = newID()
	}
	if ioc.Severity == "" {
		ioc.Severity = "medium"
	}
	if ioc.Confidence == 0 {
		ioc.Confidence = 70
	}
	if ioc.TLP == "" {
		ioc.TLP = TLPGreen
	}
	if ioc.Source == "" {
		ioc.Source = "manual"
	}
	now := time.Now().UTC()
	if ioc.CreatedAt.IsZero() {
		ioc.CreatedAt = now
	}
	ioc.UpdatedAt = now

	s.mu.Lock()
	defer s.mu.Unlock()

	// Upsert: find existing by type+value
	if existingID := s.lookupIDUnlocked(ioc.Type, ioc.Value); existingID != "" {
		ioc.ID = existingID
		existing := s.iocs[existingID]
		ioc.CreatedAt = existing.CreatedAt
		ioc.HitCount = existing.HitCount
		ioc.LastHitAt = existing.LastHitAt
	}

	s.iocs[ioc.ID] = &ioc
	s.indexUnlocked(&ioc)
	_ = s.save()
	return ioc, nil
}

// Remove deletes an IOC by ID.
func (s *Store) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.iocs[id]; !ok {
		return fmt.Errorf("IOC not found: %s", id)
	}
	s.removeUnlocked(id)
	return s.save()
}

// List returns all non-expired IOCs, optionally filtered.
func (s *Store) List(iocType IOCType, severity, source, query string) []IOC {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]IOC, 0, len(s.iocs))
	for _, ioc := range s.iocs {
		if ioc.isExpired() {
			continue
		}
		if iocType != "" && ioc.Type != iocType {
			continue
		}
		if severity != "" && ioc.Severity != severity {
			continue
		}
		if source != "" && ioc.Source != source {
			continue
		}
		if query != "" {
			q := strings.ToLower(query)
			if !strings.Contains(strings.ToLower(ioc.Value), q) &&
				!strings.Contains(strings.ToLower(ioc.Description), q) {
				continue
			}
		}
		out = append(out, *ioc)
	}
	return out
}

// GetStats returns aggregated statistics.
func (s *Store) GetStats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := Stats{
		ByType:     make(map[string]int),
		BySeverity: make(map[string]int),
		BySource:   make(map[string]int),
	}
	for _, ioc := range s.iocs {
		if ioc.isExpired() {
			continue
		}
		st.Total++
		st.ByType[string(ioc.Type)]++
		st.BySeverity[ioc.Severity]++
		if ioc.Source != "" {
			st.BySource[ioc.Source]++
		}
	}
	return st
}

// ─── Bulk Import ──────────────────────────────────────────────────────────────

// ImportText imports IOCs from a text blob. Supported formats:
// "auto" (detect), "plain" (one value per line), "json" ([]{IOC}), "urlhaus" (abuse.ch CSV).
func (s *Store) ImportText(text, format, source string) ImportResult {
	start := time.Now()
	res := ImportResult{Source: source}
	if source == "" {
		source = "import"
	}

	switch format {
	case "json":
		res = s.importJSON(text, source)
	case "urlhaus":
		res = s.importURLhaus(text, source)
	default: // "auto" or "plain"
		if strings.HasPrefix(strings.TrimSpace(text), "[") {
			res = s.importJSON(text, source)
		} else if strings.Contains(text, "urlhaus") || (strings.Contains(text, ",") && strings.Contains(text, "url_status")) {
			res = s.importURLhaus(text, source)
		} else {
			res = s.importPlain(text, source)
		}
	}
	res.Duration = time.Since(start).String()
	return res
}

// FetchFeed downloads a feed from a URL and imports it.
func (s *Store) FetchFeed(feedURL, format, source string) (ImportResult, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(feedURL)
	if err != nil {
		return ImportResult{}, fmt.Errorf("fetch feed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MB limit
	if err != nil {
		return ImportResult{}, fmt.Errorf("read feed: %w", err)
	}
	if source == "" {
		if u, err2 := url.Parse(feedURL); err2 == nil {
			source = u.Hostname()
		}
	}
	res := s.ImportText(string(body), format, source)
	return res, nil
}

func (s *Store) importPlain(text, source string) ImportResult {
	res := ImportResult{Source: source}
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		t := DetectType(line)
		if t == "" {
			res.Skipped++
			continue
		}
		ioc := IOC{Type: t, Value: line, Source: source, Severity: "medium", Confidence: 60}
		if _, err := s.Add(ioc); err != nil {
			res.Errors = append(res.Errors, err.Error())
		} else {
			res.Added++
		}
	}
	return res
}

func (s *Store) importJSON(text, source string) ImportResult {
	res := ImportResult{Source: source}
	var raw []map[string]interface{}
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		res.Errors = append(res.Errors, "invalid JSON: "+err.Error())
		return res
	}
	for _, m := range raw {
		ioc := IOC{Source: source}
		ioc.Value, _ = m["value"].(string)
		t, _ := m["type"].(string)
		ioc.Type = IOCType(t)
		ioc.Severity, _ = m["severity"].(string)
		ioc.Description, _ = m["description"].(string)
		ioc.Source, _ = m["source"].(string)
		if ioc.Source == "" {
			ioc.Source = source
		}
		tlp, _ := m["tlp"].(string)
		ioc.TLP = TLP(tlp)
		if conf, ok := m["confidence"].(float64); ok {
			ioc.Confidence = int(conf)
		}
		if ioc.Value == "" {
			res.Skipped++
			continue
		}
		if ioc.Type == "" {
			ioc.Type = DetectType(ioc.Value)
		}
		if _, err := s.Add(ioc); err != nil {
			res.Errors = append(res.Errors, err.Error())
		} else {
			res.Added++
		}
	}
	return res
}

func (s *Store) importURLhaus(text, source string) ImportResult {
	res := ImportResult{Source: source}
	r := csv.NewReader(strings.NewReader(text))
	r.Comment = '#'
	r.FieldsPerRecord = -1
	records, err := r.ReadAll()
	if err != nil {
		// Fall back to plain list
		return s.importPlain(text, source)
	}
	for _, record := range records {
		if len(record) == 0 {
			continue
		}
		rawURL := strings.Trim(record[0], `"`)
		if rawURL == "url" || rawURL == "" || strings.HasPrefix(rawURL, "#") {
			continue // header or comment
		}
		ioc := IOC{
			Type:     IOCTypeURL,
			Value:    rawURL,
			Source:   source,
			Severity: "high",
			TLP:      TLPWhite,
		}
		if len(record) >= 4 {
			ioc.Description = strings.Trim(record[3], `"`) // threat column
		}
		if len(record) >= 5 {
			tags := strings.Split(strings.Trim(record[4], `"`), "|")
			for _, t := range tags {
				if t = strings.TrimSpace(t); t != "" {
					ioc.Tags = append(ioc.Tags, t)
				}
			}
		}
		if _, err := s.Add(ioc); err != nil {
			res.Errors = append(res.Errors, err.Error())
		} else {
			res.Added++
		}
	}
	return res
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

var (
	reIPv4  = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	reHash  = regexp.MustCompile(`^[0-9a-fA-F]{64}$`) // SHA256
	reDomain = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
)

// DetectType guesses the IOC type from the value string.
func DetectType(value string) IOCType {
	v := strings.TrimSpace(value)
	if v == "" {
		return ""
	}
	if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "ftp://") {
		return IOCTypeURL
	}
	if reHash.MatchString(v) {
		return IOCTypeHash
	}
	if reIPv4.MatchString(v) {
		if net.ParseIP(v) != nil {
			return IOCTypeIP
		}
	}
	if net.ParseIP(v) != nil {
		return IOCTypeIP // IPv6
	}
	if reDomain.MatchString(v) {
		return IOCTypeDomain
	}
	return ""
}

func normalizeValue(t IOCType, value string) string {
	switch t {
	case IOCTypeIP:
		return strings.ToLower(strings.TrimSpace(value))
	case IOCTypeDomain:
		return normalizeDomain(value)
	case IOCTypeHash:
		return strings.ToLower(strings.TrimSpace(value))
	case IOCTypeURL:
		return normalizeURL(value)
	}
	return strings.TrimSpace(value)
}

func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimSuffix(d, ".")
	// Strip port if present
	if host, _, err := net.SplitHostPort(d); err == nil {
		d = host
	}
	return d
}

func normalizeURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	u, err := url.Parse(rawURL)
	if err != nil {
		return strings.ToLower(rawURL)
	}
	u.Host = strings.ToLower(u.Host)
	u.Scheme = strings.ToLower(u.Scheme)
	return u.String()
}

func (s *Store) lookupIDUnlocked(t IOCType, value string) string {
	switch t {
	case IOCTypeIP:
		return s.byIP[value]
	case IOCTypeDomain:
		return s.byDomain[value]
	case IOCTypeHash:
		return s.byHash[value]
	case IOCTypeURL:
		return s.byURL[value]
	}
	return ""
}

func (s *Store) indexUnlocked(ioc *IOC) {
	switch ioc.Type {
	case IOCTypeIP:
		s.byIP[ioc.Value] = ioc.ID
	case IOCTypeDomain:
		s.byDomain[ioc.Value] = ioc.ID
	case IOCTypeHash:
		s.byHash[ioc.Value] = ioc.ID
	case IOCTypeURL:
		s.byURL[ioc.Value] = ioc.ID
	}
}

func (s *Store) removeUnlocked(id string) {
	ioc, ok := s.iocs[id]
	if !ok {
		return
	}
	switch ioc.Type {
	case IOCTypeIP:
		delete(s.byIP, ioc.Value)
	case IOCTypeDomain:
		delete(s.byDomain, ioc.Value)
	case IOCTypeHash:
		delete(s.byHash, ioc.Value)
	case IOCTypeURL:
		delete(s.byURL, ioc.Value)
	}
	delete(s.iocs, id)
}

// ─── Persistence ──────────────────────────────────────────────────────────────

func (s *Store) load() error {
	data, err := os.ReadFile(s.storePath)
	if err != nil {
		return err
	}
	var iocs []IOC
	if err := json.Unmarshal(data, &iocs); err != nil {
		return err
	}
	for i := range iocs {
		ioc := &iocs[i]
		s.iocs[ioc.ID] = ioc
		s.indexUnlocked(ioc)
	}
	return nil
}

func (s *Store) save() error {
	if s.storePath == "" {
		return nil
	}
	iocs := make([]IOC, 0, len(s.iocs))
	for _, ioc := range s.iocs {
		iocs = append(iocs, *ioc)
	}
	b, err := json.Marshal(iocs)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.storePath), 0755); err != nil {
		return err
	}
	tmp := s.storePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, s.storePath)
}

func (s *Store) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.save()
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
