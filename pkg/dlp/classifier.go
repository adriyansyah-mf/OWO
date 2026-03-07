// Package dlp: classifier.go — File classification by content type, sensitivity
// label, and SHA256 fingerprint matching.
//
// Classification pipeline per file:
//  1. MIME type detection from magic bytes (no external dependencies).
//  2. Sensitivity label inference from DLP pattern match severity.
//  3. Exact-match fingerprint lookup against a registry of known sensitive documents.
//  4. (Reserved) ML scoring hook — see BehavioralEngine in behavioral.go.
//
// The Classifier is the high-level entry point that combines all three steps
// into a single FileClassification result used by the audit trail and policy engine.
package dlp

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Sensitivity labels
// ─────────────────────────────────────────────────────────────────────────────

// SensitivityLabel is the data classification level assigned to a file.
// Labels follow the standard four-tier enterprise classification model.
type SensitivityLabel string

const (
	// LabelPublic: information intended for public consumption; no restrictions.
	LabelPublic SensitivityLabel = "public"

	// LabelInternal: general internal information; not for external distribution.
	LabelInternal SensitivityLabel = "internal"

	// LabelConfidential: business-sensitive data; restricted to authorized staff.
	LabelConfidential SensitivityLabel = "confidential"

	// LabelRestricted: highly sensitive data (PII, credentials, financial records).
	LabelRestricted SensitivityLabel = "restricted"

	// LabelSecret: crown-jewel data; access extremely limited (private keys, master secrets).
	LabelSecret SensitivityLabel = "secret"
)

// sensitivityFromSeverity maps the highest-severity DLP pattern match to a label.
func sensitivityFromSeverity(maxSeverity string) SensitivityLabel {
	switch strings.ToLower(maxSeverity) {
	case "critical":
		return LabelSecret
	case "high":
		return LabelRestricted
	case "medium":
		return LabelConfidential
	case "low":
		return LabelInternal
	default:
		return LabelPublic
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// MIME type detection (magic bytes, no external dependencies)
// ─────────────────────────────────────────────────────────────────────────────

// MimeType is a simplified MIME category used for file classification.
// We do not need the full IANA registry — only what matters for DLP.
type MimeType string

const (
	MimeUnknown    MimeType = "application/octet-stream"
	MimePDF        MimeType = "application/pdf"
	MimeOfficeDocx MimeType = "application/vnd.openxmlformats"  // .docx/.xlsx/.pptx (ZIP-based)
	MimeOfficeDoc  MimeType = "application/msword"               // legacy .doc/.xls/.ppt (OLE)
	MimeZip        MimeType = "application/zip"
	MimeTar        MimeType = "application/x-tar"
	MimeGzip       MimeType = "application/gzip"
	Mime7Zip       MimeType = "application/x-7z-compressed"
	MimeELF        MimeType = "application/x-elf"
	MimeScript     MimeType = "text/x-script"
	MimePlainText  MimeType = "text/plain"
	MimeSQLite     MimeType = "application/x-sqlite3"
	MimePEM        MimeType = "application/x-pem-file"
)

// magicEntry maps a byte prefix to a MIME type.
type magicEntry struct {
	prefix []byte
	mime   MimeType
}

// magicTable is checked in order; first match wins.
var magicTable = []magicEntry{
	{[]byte{0x25, 0x50, 0x44, 0x46}, MimePDF},               // %PDF
	{[]byte{0x50, 0x4B, 0x03, 0x04}, MimeZip},                // PK.. (ZIP / OOXML)
	{[]byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, MimeOfficeDoc}, // OLE2
	{[]byte{0x1F, 0x8B}, MimeGzip},                            // gzip
	{[]byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, Mime7Zip},   // 7-Zip
	{[]byte{0x7F, 0x45, 0x4C, 0x46}, MimeELF},                 // ELF
	{[]byte{0x53, 0x51, 0x4C, 0x69, 0x74, 0x65}, MimeSQLite}, // SQLite
	// tar: no universal magic, but ustar at offset 257. Handled separately below.
}

// DetectMIME identifies a file's MIME type from its first bytes.
// Returns MimePlainText for files that pass the text heuristic,
// and MimeUnknown for unrecognised binary formats.
func DetectMIME(header []byte) MimeType {
	// Check magic table first.
	for _, e := range magicTable {
		if len(header) >= len(e.prefix) {
			match := true
			for i, b := range e.prefix {
				if header[i] != b {
					match = false
					break
				}
			}
			if match {
				// ZIP-based OOXML (.docx, .xlsx, .pptx) shares the PK magic.
				// We keep it as MimeZip here; the caller can refine by extension.
				return e.mime
			}
		}
	}

	// ustar tar: magic at offset 257.
	if len(header) >= 262 {
		if string(header[257:262]) == "ustar" {
			return MimeTar
		}
	}

	// PEM private/public key.
	if len(header) > 10 && string(header[:5]) == "-----" {
		return MimePEM
	}

	// Text heuristic: no NUL bytes and no non-printable control chars in first 512 bytes.
	if isTextFile(header) {
		return MimePlainText
	}

	return MimeUnknown
}

// MIMEFromExtension returns a MIME type hint based on the file extension.
// Used to refine ZIP detection (PK magic shared by .docx, .xlsx, .pptx, .zip).
func MIMEFromExtension(ext string) MimeType {
	switch strings.ToLower(ext) {
	case ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp":
		return MimeOfficeDocx
	case ".doc", ".xls", ".ppt":
		return MimeOfficeDoc
	case ".pdf":
		return MimePDF
	case ".zip":
		return MimeZip
	case ".tar":
		return MimeTar
	case ".gz", ".tgz":
		return MimeGzip
	case ".7z":
		return Mime7Zip
	case ".sh", ".py", ".rb", ".pl", ".bash", ".zsh":
		return MimeScript
	case ".pem", ".key", ".crt", ".cer":
		return MimePEM
	case ".sqlite", ".db", ".sqlite3":
		return MimeSQLite
	default:
		return MimeUnknown
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Fingerprint registry — exact-match DLP for known sensitive documents
// ─────────────────────────────────────────────────────────────────────────────

// FingerprintEntry represents a known sensitive document registered by its SHA256.
// When a scanned file's hash matches an entry, the classification is applied
// directly without needing pattern matching.
type FingerprintEntry struct {
	// Name is a description of the document (e.g. "Employee SSN Database 2024").
	Name string `json:"name"`

	// Label is the pre-assigned sensitivity label for this document.
	Label SensitivityLabel `json:"label"`

	// Notes are optional free-text notes for the analyst.
	Notes string `json:"notes,omitempty"`

	// RegisteredAt records when the fingerprint was added.
	RegisteredAt time.Time `json:"registered_at"`
}

// FingerprintRegistry maps SHA256 hex strings to known sensitive documents.
// It is safe for concurrent reads and writes.
type FingerprintRegistry struct {
	mu      sync.RWMutex
	entries map[string]FingerprintEntry // key: sha256 hex
}

// NewFingerprintRegistry creates an empty registry.
func NewFingerprintRegistry() *FingerprintRegistry {
	return &FingerprintRegistry{entries: make(map[string]FingerprintEntry)}
}

// Register adds or updates an entry. hash must be a lowercase hex SHA256 string.
func (r *FingerprintRegistry) Register(hash string, entry FingerprintEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[strings.ToLower(hash)] = entry
}

// Lookup returns the entry for hash, and whether it was found.
func (r *FingerprintRegistry) Lookup(hash string) (FingerprintEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[strings.ToLower(hash)]
	return e, ok
}

// Remove deletes a fingerprint from the registry.
func (r *FingerprintRegistry) Remove(hash string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, strings.ToLower(hash))
}

// Len returns the number of registered fingerprints.
func (r *FingerprintRegistry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

// HashFile computes the SHA256 of a file and returns it as a lowercase hex string.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// FileClassification — output of Classifier.Classify()
// ─────────────────────────────────────────────────────────────────────────────

// FileClassification is the combined result of running the full classification
// pipeline on a single file.
type FileClassification struct {
	// Path is the absolute file path that was classified.
	Path string `json:"path"`

	// MimeType detected from magic bytes.
	MimeType MimeType `json:"mime_type"`

	// Label is the assigned sensitivity label.
	Label SensitivityLabel `json:"sensitivity_label"`

	// FingerprintMatch is true when the file's SHA256 matched a registered document.
	FingerprintMatch bool `json:"fingerprint_match"`

	// FingerprintEntry holds the registry entry when FingerprintMatch is true.
	FingerprintEntry *FingerprintEntry `json:"fingerprint_entry,omitempty"`

	// PatternMatches lists the DLP findings that drove the label assignment.
	PatternMatches []Match `json:"pattern_matches,omitempty"`

	// SHA256 is the hex-encoded hash of the file contents.
	SHA256 string `json:"sha256"`

	// FileSize in bytes.
	FileSize int64 `json:"file_size"`

	// ClassifiedAt is the timestamp of this classification run.
	ClassifiedAt time.Time `json:"classified_at"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Classifier — combines MIME detection, pattern scanning, and fingerprinting
// ─────────────────────────────────────────────────────────────────────────────

// Classifier runs the full DLP classification pipeline on a file.
// It is safe for concurrent use.
type Classifier struct {
	scanner     *Scanner
	fingerprints *FingerprintRegistry
}

// NewClassifier creates a classifier with the given scanner and fingerprint registry.
// Pass nil for fingerprints to skip exact-match fingerprinting.
func NewClassifier(scanner *Scanner, fingerprints *FingerprintRegistry) *Classifier {
	if scanner == nil {
		scanner = NewScanner()
	}
	if fingerprints == nil {
		fingerprints = NewFingerprintRegistry()
	}
	return &Classifier{scanner: scanner, fingerprints: fingerprints}
}

// Classify runs the full classification pipeline on the file at path.
// It does not block the file (enforcement is the caller's responsibility).
func (c *Classifier) Classify(path string) (FileClassification, error) {
	result := FileClassification{
		Path:         path,
		ClassifiedAt: time.Now().UTC(),
		Label:        LabelPublic,
	}

	fi, err := os.Stat(path)
	if err != nil {
		return result, err
	}
	result.FileSize = fi.Size()

	// --- Step 1: Read header bytes for MIME detection. ---
	f, err := os.Open(path)
	if err != nil {
		return result, err
	}
	header := make([]byte, 512)
	n, _ := io.ReadFull(f, header)
	f.Close()

	mime := DetectMIME(header[:n])
	// Refine ZIP → OOXML using extension.
	if mime == MimeZip {
		if extMime := MIMEFromExtension(filepath.Ext(path)); extMime == MimeOfficeDocx {
			mime = extMime
		}
	}
	result.MimeType = mime

	// --- Step 2: DLP pattern scan. ---
	// Skip binary formats that cannot contain embedded text secrets
	// (ELF binaries, images), but still scan office docs and PDFs since
	// they embed text streams that contain credentials.
	if mime != MimeELF && mime != MimeUnknown {
		matches, err := c.scanner.ScanFile(path)
		if err == nil && len(matches) > 0 {
			result.PatternMatches = matches

			// Derive label from the highest-severity match.
			maxSev := 0
			maxSevStr := "low"
			for _, m := range matches {
				if sv := severityValue(m.Severity); sv > maxSev {
					maxSev = sv
					maxSevStr = m.Severity
				}
			}
			result.Label = sensitivityFromSeverity(maxSevStr)
		}
	}

	// --- Step 3: Exact-match fingerprint lookup. ---
	// Only hash files within a reasonable size; skip multi-GB files.
	const maxHashSize = 100 * 1024 * 1024 // 100 MB
	if fi.Size() <= maxHashSize {
		hash, err := HashFile(path)
		if err == nil {
			result.SHA256 = hash
			if entry, found := c.fingerprints.Lookup(hash); found {
				result.FingerprintMatch = true
				result.FingerprintEntry = &entry
				// Fingerprint entries carry an authoritative label; use it
				// if it is more restrictive than what pattern matching found.
				if labelRank(entry.Label) > labelRank(result.Label) {
					result.Label = entry.Label
				}
			}
		}
	}

	return result, nil
}

// labelRank converts a SensitivityLabel to an integer for comparison.
func labelRank(l SensitivityLabel) int {
	switch l {
	case LabelPublic:
		return 0
	case LabelInternal:
		return 1
	case LabelConfidential:
		return 2
	case LabelRestricted:
		return 3
	case LabelSecret:
		return 4
	default:
		return 0
	}
}
