// Package notify provides webhook-based notification delivery for the EDR platform.
//
// Supports:
//   - Generic webhook (POST JSON body)
//   - Slack (incoming webhook format)
//   - Microsoft Teams (Adaptive Card / simple MessageCard)
//
// Message templates support {{field}} substitution from the alert map
// (e.g. {{host_id}}, {{severity}}, {{title}}, {{rule_id}}, {{attack_chain}}).
package notify

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ─── Channel ──────────────────────────────────────────────────────────────────

// ChannelType identifies the webhook format.
type ChannelType string

const (
	ChannelGeneric ChannelType = "generic"
	ChannelSlack   ChannelType = "slack"
	ChannelTeams   ChannelType = "teams"
)

// Channel is a named notification destination.
type Channel struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Type        ChannelType `json:"type"`
	URL         string      `json:"url"`
	Enabled     bool        `json:"enabled"`
	// DefaultTemplate is used when notify action has no explicit message.
	DefaultTemplate string `json:"default_template,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	SendCount       int       `json:"send_count"`
	LastSentAt      *time.Time `json:"last_sent_at,omitempty"`
	LastError       string    `json:"last_error,omitempty"`
}

// ─── SendResult ───────────────────────────────────────────────────────────────

// SendResult describes the outcome of a single notification attempt.
type SendResult struct {
	ChannelID   string    `json:"channel_id"`
	ChannelName string    `json:"channel_name"`
	OK          bool      `json:"ok"`
	StatusCode  int       `json:"status_code,omitempty"`
	Error       string    `json:"error,omitempty"`
	SentAt      time.Time `json:"sent_at"`
}

// ─── Manager ──────────────────────────────────────────────────────────────────

// Manager holds all notification channels and sends messages.
type Manager struct {
	mu        sync.RWMutex
	channels  map[string]*Channel
	storePath string
	client    *http.Client
}

// New creates a Manager. storePath is the JSON persistence file.
func New(storePath string) *Manager {
	m := &Manager{
		channels:  make(map[string]*Channel),
		storePath: storePath,
		client:    &http.Client{Timeout: 10 * time.Second},
	}
	if storePath != "" {
		_ = m.load()
	}
	return m
}

// ─── Send ─────────────────────────────────────────────────────────────────────

// Send delivers a message to all enabled channels.
// If channelNames is non-empty, only those channels receive the message.
// The template is rendered with values from the alert map ({{field}} syntax).
func (m *Manager) Send(template string, alert map[string]interface{}, channelNames ...string) []SendResult {
	m.mu.RLock()
	chans := make([]*Channel, 0, len(m.channels))
	for _, ch := range m.channels {
		if !ch.Enabled {
			continue
		}
		if len(channelNames) > 0 && !containsName(channelNames, ch.Name) {
			continue
		}
		chans = append(chans, ch)
	}
	m.mu.RUnlock()

	msg := renderTemplate(template, alert)
	results := make([]SendResult, 0, len(chans))
	for _, ch := range chans {
		res := m.sendTo(ch, msg, alert)
		results = append(results, res)

		m.mu.Lock()
		if live, ok := m.channels[ch.ID]; ok {
			if res.OK {
				live.SendCount++
				now := time.Now().UTC()
				live.LastSentAt = &now
				live.LastError = ""
			} else {
				live.LastError = res.Error
			}
		}
		m.mu.Unlock()
	}
	if len(results) > 0 {
		m.mu.RLock()
		_ = m.save()
		m.mu.RUnlock()
	}
	return results
}

// SendToChannel sends a message to a single channel by ID. Used for testing.
func (m *Manager) SendToChannel(id, message string) SendResult {
	m.mu.RLock()
	ch, ok := m.channels[id]
	if !ok {
		m.mu.RUnlock()
		return SendResult{ChannelID: id, OK: false, Error: "channel not found", SentAt: time.Now().UTC()}
	}
	chCopy := *ch
	m.mu.RUnlock()
	return m.sendTo(&chCopy, message, nil)
}

func (m *Manager) sendTo(ch *Channel, message string, alert map[string]interface{}) SendResult {
	result := SendResult{ChannelID: ch.ID, ChannelName: ch.Name, SentAt: time.Now().UTC()}

	var body []byte
	var err error

	switch ch.Type {
	case ChannelSlack:
		body, err = json.Marshal(map[string]string{"text": message})
	case ChannelTeams:
		body, err = json.Marshal(map[string]interface{}{
			"@type":      "MessageCard",
			"@context":   "http://schema.org/extensions",
			"summary":    message,
			"themeColor": teamsColor(alert),
			"sections": []map[string]interface{}{
				{"activityText": message},
			},
		})
	default: // generic
		payload := map[string]interface{}{
			"message":   message,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}
		if alert != nil {
			payload["alert"] = alert
		}
		body, err = json.Marshal(payload)
	}

	if err != nil {
		result.Error = "marshal: " + err.Error()
		return result
	}

	resp, err := m.client.Post(ch.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	result.StatusCode = resp.StatusCode
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		result.OK = true
	} else {
		result.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return result
}

// ─── CRUD ─────────────────────────────────────────────────────────────────────

// AddChannel creates or replaces a channel (upsert by ID).
func (m *Manager) AddChannel(ch Channel) Channel {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ch.ID == "" {
		ch.ID = newID()
		ch.CreatedAt = time.Now().UTC()
	} else if existing, ok := m.channels[ch.ID]; ok {
		ch.CreatedAt = existing.CreatedAt
		ch.SendCount = existing.SendCount
		ch.LastSentAt = existing.LastSentAt
	}
	if ch.Type == "" {
		ch.Type = ChannelGeneric
	}
	ch.UpdatedAt = time.Now().UTC()
	m.channels[ch.ID] = &ch
	_ = m.save()
	return ch
}

// RemoveChannel deletes a channel by ID.
func (m *Manager) RemoveChannel(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.channels[id]; !ok {
		return fmt.Errorf("channel not found: %s", id)
	}
	delete(m.channels, id)
	return m.save()
}

// ListChannels returns all channels (URL is masked for security in list view).
func (m *Manager) ListChannels(maskURL bool) []Channel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Channel, 0, len(m.channels))
	for _, ch := range m.channels {
		c := *ch
		if maskURL && len(c.URL) > 20 {
			c.URL = c.URL[:20] + "…"
		}
		out = append(out, c)
	}
	return out
}

// GetChannel returns a channel by ID (with full URL).
func (m *Manager) GetChannel(id string) (Channel, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ch, ok := m.channels[id]
	if !ok {
		return Channel{}, false
	}
	return *ch, true
}

// ─── Persistence ──────────────────────────────────────────────────────────────

func (m *Manager) load() error {
	data, err := os.ReadFile(m.storePath)
	if err != nil {
		return err
	}
	var chans []*Channel
	if err := json.Unmarshal(data, &chans); err != nil {
		return err
	}
	for _, ch := range chans {
		m.channels[ch.ID] = ch
	}
	return nil
}

// save must be called with m.mu held (at least read).
func (m *Manager) save() error {
	if m.storePath == "" {
		return nil
	}
	chans := make([]*Channel, 0, len(m.channels))
	for _, ch := range m.channels {
		chans = append(chans, ch)
	}
	b, err := json.Marshal(chans)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.storePath), 0755); err != nil {
		return err
	}
	tmp := m.storePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, m.storePath)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// renderTemplate replaces {{field}} placeholders with alert values.
func renderTemplate(tmpl string, alert map[string]interface{}) string {
	if alert == nil {
		return tmpl
	}
	fields := []string{"host_id", "tenant_id", "severity", "title", "rule_id", "rule_name", "attack_chain", "id", "message"}
	result := tmpl
	for _, f := range fields {
		if v, ok := alert[f].(string); ok {
			result = strings.ReplaceAll(result, "{{"+f+"}}", v)
		}
	}
	return result
}

func containsName(names []string, target string) bool {
	for _, n := range names {
		if strings.EqualFold(n, target) {
			return true
		}
	}
	return false
}

func teamsColor(alert map[string]interface{}) string {
	if alert == nil {
		return "0078D7"
	}
	sev, _ := alert["severity"].(string)
	switch sev {
	case "critical":
		return "FF0000"
	case "high":
		return "FF6600"
	case "medium":
		return "FFC000"
	default:
		return "0078D7"
	}
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return "ch-" + strings.ToLower(base64.RawURLEncoding.EncodeToString(b))
}
