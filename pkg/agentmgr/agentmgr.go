// Package agentmgr provides agent enrollment and lifecycle management.
// Agents register themselves, receive a one-time enroll token, and are
// approved/rejected by an admin. Heartbeats track online/offline status.
package agentmgr

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AgentStatus describes the current lifecycle state of an agent.
type AgentStatus string

const (
	// AgentStatusPending: enrolled but not yet approved by an admin.
	AgentStatusPending AgentStatus = "pending"
	// AgentStatusApproved: approved, waiting for first heartbeat.
	AgentStatusApproved AgentStatus = "approved"
	// AgentStatusOnline: heartbeat received within OnlineThreshold.
	AgentStatusOnline AgentStatus = "online"
	// AgentStatusOffline: heartbeat not received within OnlineThreshold.
	AgentStatusOffline AgentStatus = "offline"
	// AgentStatusIsolated: network isolation is active on this agent.
	AgentStatusIsolated AgentStatus = "isolated"
	// AgentStatusRejected: enrollment was rejected by an admin.
	AgentStatusRejected AgentStatus = "rejected"
)

// OnlineThreshold is the maximum age of the last heartbeat before an agent
// is considered offline.
const OnlineThreshold = 3 * time.Minute

// Agent represents an enrolled endpoint.
type Agent struct {
	ID           string      `json:"id"`
	Hostname     string      `json:"hostname"`
	IPAddress    string      `json:"ip_address,omitempty"`
	OS           string      `json:"os"`
	OSVersion    string      `json:"os_version,omitempty"`
	AgentVersion string      `json:"agent_version,omitempty"`
	Groups       []string    `json:"groups,omitempty"`
	Tags         []string    `json:"tags,omitempty"`
	Status       AgentStatus `json:"status"`
	TenantID     string      `json:"tenant_id"`
	EnrolledAt   time.Time   `json:"enrolled_at"`
	LastSeenAt   *time.Time  `json:"last_seen_at,omitempty"`
	ApprovedAt   *time.Time  `json:"approved_at,omitempty"`
	ApprovedBy   string      `json:"approved_by,omitempty"`
	// EnrollToken is a secret token the agent uses to authenticate heartbeat
	// requests. It is cleared after the agent is approved or rejected.
	EnrollToken string `json:"enroll_token,omitempty"`
}

// EffectiveStatus computes the real-time status based on heartbeat age.
// It overrides the persisted Status for online/offline transitions.
func (a Agent) EffectiveStatus() AgentStatus {
	switch a.Status {
	case AgentStatusPending, AgentStatusRejected:
		return a.Status
	case AgentStatusIsolated:
		return AgentStatusIsolated
	}
	if a.LastSeenAt == nil {
		return AgentStatusOffline
	}
	if time.Since(*a.LastSeenAt) > OnlineThreshold {
		return AgentStatusOffline
	}
	return AgentStatusOnline
}

// Store manages agents with JSON file persistence.
type Store struct {
	mu        sync.RWMutex
	agents    map[string]Agent  // id → Agent
	byToken   map[string]string // enroll_token → id
	storePath string
}

// New creates a Store. storePath is the JSON file for persistence.
func New(storePath string) *Store {
	s := &Store{
		agents:    make(map[string]Agent),
		byToken:   make(map[string]string),
		storePath: storePath,
	}
	if storePath != "" {
		_ = s.load()
	}
	return s
}

// Enroll registers a new agent and returns it with a one-time EnrollToken.
// If an agent with the same hostname+tenant already exists (and is not rejected),
// it is re-enrolled: metadata is updated and the existing record is returned.
func (s *Store) Enroll(hostname, ip, osName, osVersion, agentVersion, tenantID string) Agent {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-enrollment: update metadata for existing active agent
	for _, a := range s.agents {
		if a.Hostname == hostname && a.TenantID == tenantID && a.Status != AgentStatusRejected {
			a.IPAddress = ip
			a.OS = osName
			a.OSVersion = osVersion
			a.AgentVersion = agentVersion
			now := time.Now().UTC()
			a.LastSeenAt = &now
			s.agents[a.ID] = a
			_ = s.save()
			return a
		}
	}
	// New enrollment
	token := newToken()
	now := time.Now().UTC()
	a := Agent{
		ID:           newID(),
		Hostname:     hostname,
		IPAddress:    ip,
		OS:           osName,
		OSVersion:    osVersion,
		AgentVersion: agentVersion,
		Status:       AgentStatusPending,
		TenantID:     tenantID,
		EnrolledAt:   now,
		EnrollToken:  token,
	}
	s.agents[a.ID] = a
	s.byToken[token] = a.ID
	_ = s.save()
	return a
}

// Heartbeat updates the last_seen timestamp for an agent.
// The agent authenticates using its enroll_token as a Bearer token.
// Returns the updated agent or an error if the token/ID is invalid.
func (s *Store) Heartbeat(agentID, token, ip, agentVersion string) (Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[agentID]
	if !ok {
		return Agent{}, fmt.Errorf("agent not found")
	}
	if a.Status == AgentStatusRejected {
		return Agent{}, fmt.Errorf("agent is rejected")
	}
	// Verify token if agent still has one
	if a.EnrollToken != "" && a.EnrollToken != token {
		return Agent{}, fmt.Errorf("invalid token")
	}
	now := time.Now().UTC()
	a.LastSeenAt = &now
	if ip != "" {
		a.IPAddress = ip
	}
	if agentVersion != "" {
		a.AgentVersion = agentVersion
	}
	s.agents[agentID] = a
	_ = s.save()
	return a, nil
}

// SetStatus changes the lifecycle status of an agent.
// On approval the enroll token is cleared.
func (s *Store) SetStatus(agentID string, status AgentStatus, byUser string) (Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[agentID]
	if !ok {
		return Agent{}, fmt.Errorf("agent not found: %s", agentID)
	}
	a.Status = status
	if status == AgentStatusApproved {
		now := time.Now().UTC()
		a.ApprovedAt = &now
		a.ApprovedBy = byUser
		// Token is no longer needed after approval
		if a.EnrollToken != "" {
			delete(s.byToken, a.EnrollToken)
			a.EnrollToken = ""
		}
	}
	s.agents[agentID] = a
	_ = s.save()
	return a, nil
}

// UpdateTags sets the groups and tags for an agent.
func (s *Store) UpdateTags(agentID string, groups, tags []string) (Agent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[agentID]
	if !ok {
		return Agent{}, fmt.Errorf("agent not found: %s", agentID)
	}
	a.Groups = groups
	a.Tags = tags
	s.agents[agentID] = a
	_ = s.save()
	return a, nil
}

// List returns all agents with effective (real-time) status.
// EnrollToken is stripped before returning.
func (s *Store) List() []Agent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Agent, 0, len(s.agents))
	for _, a := range s.agents {
		a.Status = a.EffectiveStatus()
		a.EnrollToken = "" // never leak token in list
		out = append(out, a)
	}
	return out
}

// GetByID returns an agent by ID with effective status.
// EnrollToken is included (for enrollment response only — callers must strip it
// before returning to non-agent API consumers).
func (s *Store) GetByID(id string) (Agent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.agents[id]
	if ok {
		a.Status = a.EffectiveStatus()
	}
	return a, ok
}

// Delete removes an agent from the store.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[id]
	if !ok {
		return fmt.Errorf("agent not found: %s", id)
	}
	if a.EnrollToken != "" {
		delete(s.byToken, a.EnrollToken)
	}
	delete(s.agents, id)
	return s.save()
}

// Stats returns counts by status for dashboard display.
func (s *Store) Stats() map[string]int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	counts := map[string]int{
		"total":    len(s.agents),
		"online":   0,
		"offline":  0,
		"pending":  0,
		"isolated": 0,
		"rejected": 0,
	}
	for _, a := range s.agents {
		switch a.EffectiveStatus() {
		case AgentStatusOnline:
			counts["online"]++
		case AgentStatusOffline, AgentStatusApproved:
			counts["offline"]++
		case AgentStatusPending:
			counts["pending"]++
		case AgentStatusIsolated:
			counts["isolated"]++
		case AgentStatusRejected:
			counts["rejected"]++
		}
	}
	return counts
}

// ─── persistence ─────────────────────────────────────────────────────────────

func (s *Store) load() error {
	data, err := os.ReadFile(s.storePath)
	if err != nil {
		return err
	}
	var agents []Agent
	if err := json.Unmarshal(data, &agents); err != nil {
		return err
	}
	for _, a := range agents {
		s.agents[a.ID] = a
		if a.EnrollToken != "" {
			s.byToken[a.EnrollToken] = a.ID
		}
	}
	return nil
}

func (s *Store) save() error {
	if s.storePath == "" {
		return nil
	}
	agents := make([]Agent, 0, len(s.agents))
	for _, a := range s.agents {
		agents = append(agents, a)
	}
	b, err := json.MarshalIndent(agents, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.storePath), 0700); err != nil {
		return err
	}
	tmp := s.storePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.storePath)
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func newID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func newToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
