// Package rbac provides Role-Based Access Control for the EDR API.
// Users, roles, permissions, and session management with bcrypt password hashing
// and JSON file persistence.
package rbac

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ─── Roles ───────────────────────────────────────────────────────────────────

// Role defines a user's access level.
type Role string

const (
	// RoleAdmin has full access to all operations including user management.
	RoleAdmin Role = "admin"

	// RoleAnalyst can read everything and perform IR actions and rule/DLP management.
	// Cannot manage users or platform settings.
	RoleAnalyst Role = "analyst"

	// RoleReadOnly can only read alerts, hosts, and scan results. No write operations.
	RoleReadOnly Role = "readonly"

	// RoleAuditor can read everything including audit logs and user list. No write operations.
	RoleAuditor Role = "auditor"
)

// ─── Permissions ─────────────────────────────────────────────────────────────

// Permission represents a granular API operation.
type Permission string

const (
	PermReadAlerts    Permission = "read:alerts"
	PermReadHosts     Permission = "read:hosts"
	PermReadScans     Permission = "read:scans"
	PermReadRules     Permission = "read:rules"
	PermReadDLP       Permission = "read:dlp"
	PermReadAudit     Permission = "read:audit"
	PermReadUsers     Permission = "read:users"
	PermWriteIR       Permission = "write:ir"
	PermWriteRules    Permission = "write:rules"
	PermWriteDLP      Permission = "write:dlp"
	PermWriteSettings Permission = "write:settings"
	PermWriteUsers    Permission = "write:users"
	PermWriteAgents   Permission = "write:agents"
	// PermAdmin is a super-permission that grants all operations.
	PermAdmin Permission = "admin"
)

// rolePermissions maps each role to its allowed permissions.
var rolePermissions = map[Role][]Permission{
	RoleAdmin: {PermAdmin},
	RoleAnalyst: {
		PermReadAlerts, PermReadHosts, PermReadScans,
		PermReadRules, PermReadDLP, PermReadAudit,
		PermWriteIR, PermWriteRules, PermWriteDLP,
	},
	RoleReadOnly: {
		PermReadAlerts, PermReadHosts, PermReadScans,
		PermReadDLP, PermReadAudit,
	},
	RoleAuditor: {
		PermReadAlerts, PermReadHosts, PermReadScans,
		PermReadRules, PermReadDLP, PermReadAudit, PermReadUsers,
	},
}

// HasPermission returns true if the role grants the given permission.
func (r Role) HasPermission(p Permission) bool {
	perms := rolePermissions[r]
	for _, rp := range perms {
		if rp == PermAdmin || rp == p {
			return true
		}
	}
	return false
}

// ValidRole returns true if the role string is a known role.
func ValidRole(r Role) bool {
	switch r {
	case RoleAdmin, RoleAnalyst, RoleReadOnly, RoleAuditor:
		return true
	}
	return false
}

// ─── User ─────────────────────────────────────────────────────────────────────

// User is a platform user with hashed credentials.
type User struct {
	ID           string     `json:"id"`
	Username     string     `json:"username"`
	PasswordHash string     `json:"password_hash"`
	Role         Role       `json:"role"`
	Email        string     `json:"email,omitempty"`
	Enabled      bool       `json:"enabled"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
}

// UserPublic is a User without the password hash — safe to send in API responses.
type UserPublic struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	Role        Role       `json:"role"`
	Email       string     `json:"email,omitempty"`
	Enabled     bool       `json:"enabled"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

// Public returns a UserPublic view of the user.
func (u User) Public() UserPublic {
	return UserPublic{
		ID:          u.ID,
		Username:    u.Username,
		Role:        u.Role,
		Email:       u.Email,
		Enabled:     u.Enabled,
		CreatedAt:   u.CreatedAt,
		UpdatedAt:   u.UpdatedAt,
		LastLoginAt: u.LastLoginAt,
	}
}

// ─── Session ──────────────────────────────────────────────────────────────────

// Session holds an authenticated session token with its associated user info.
type Session struct {
	Token     string    `json:"token"`
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	Role      Role      `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// ─── UserStore ───────────────────────────────────────────────────────────────

// UserStore manages users and in-memory sessions with file persistence.
// Sessions are not persisted (they reset on server restart).
type UserStore struct {
	mu        sync.RWMutex
	users     map[string]User   // id → User
	byName    map[string]string // username → id
	sessions  map[string]Session
	storePath string
}

// NewUserStore creates a new UserStore. storePath is the JSON file for user persistence.
func NewUserStore(storePath string) *UserStore {
	s := &UserStore{
		users:     make(map[string]User),
		byName:    make(map[string]string),
		sessions:  make(map[string]Session),
		storePath: storePath,
	}
	if storePath != "" {
		_ = s.load()
	}
	return s
}

// SeedAdmin creates the default admin user if no users exist yet.
// Safe to call on every startup.
func (s *UserStore) SeedAdmin(username, password string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.users) > 0 {
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	u := User{
		ID:           newID(),
		Username:     username,
		PasswordHash: string(hash),
		Role:         RoleAdmin,
		Enabled:      true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	s.users[u.ID] = u
	s.byName[username] = u.ID
	return s.save()
}

// AddUser creates a new user. Returns an error if the username already exists.
func (s *UserStore) AddUser(username, password string, role Role, email string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byName[username]; exists {
		return User{}, fmt.Errorf("user %q already exists", username)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return User{}, err
	}
	now := time.Now().UTC()
	u := User{
		ID:           newID(),
		Username:     username,
		PasswordHash: string(hash),
		Role:         role,
		Email:        email,
		Enabled:      true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	s.users[u.ID] = u
	s.byName[username] = u.ID
	_ = s.save()
	return u, nil
}

// UpdateUser updates mutable fields for a user. Pass empty password to keep the existing one.
func (s *UserStore) UpdateUser(id, password string, role Role, email string, enabled bool) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return User{}, fmt.Errorf("user not found: %s", id)
	}
	if password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return User{}, err
		}
		u.PasswordHash = string(hash)
	}
	u.Role = role
	u.Email = email
	u.Enabled = enabled
	u.UpdatedAt = time.Now().UTC()
	s.users[id] = u
	_ = s.save()
	return u, nil
}

// DeleteUser removes a user and invalidates all their sessions.
// Returns an error if the user is the last admin.
func (s *UserStore) DeleteUser(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok {
		return fmt.Errorf("user not found: %s", id)
	}
	// Prevent deleting the last admin
	if u.Role == RoleAdmin {
		adminCount := 0
		for _, usr := range s.users {
			if usr.Role == RoleAdmin && usr.Enabled {
				adminCount++
			}
		}
		if adminCount <= 1 {
			return fmt.Errorf("cannot delete the last admin user")
		}
	}
	delete(s.users, id)
	delete(s.byName, u.Username)
	for tok, sess := range s.sessions {
		if sess.UserID == id {
			delete(s.sessions, tok)
		}
	}
	return s.save()
}

// ListUsers returns all users as public views.
func (s *UserStore) ListUsers() []UserPublic {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]UserPublic, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u.Public())
	}
	return out
}

// GetByID returns a user by ID.
func (s *UserStore) GetByID(id string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	return u, ok
}

// Authenticate validates credentials and returns a new session.
func (s *UserStore) Authenticate(username, password string) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byName[username]
	if !ok {
		return Session{}, fmt.Errorf("invalid credentials")
	}
	u := s.users[id]
	if !u.Enabled {
		return Session{}, fmt.Errorf("account disabled")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return Session{}, fmt.Errorf("invalid credentials")
	}
	b := make([]byte, 32)
	rand.Read(b)
	token := base64.URLEncoding.EncodeToString(b)
	now := time.Now().UTC()
	sess := Session{
		Token:     token,
		UserID:    u.ID,
		Username:  u.Username,
		Role:      u.Role,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}
	s.sessions[token] = sess
	u.LastLoginAt = &now
	s.users[id] = u
	_ = s.save()
	return sess, nil
}

// ValidateToken returns the session for a token if it is valid and not expired.
func (s *UserStore) ValidateToken(token string) (Session, bool) {
	s.mu.RLock()
	sess, ok := s.sessions[token]
	s.mu.RUnlock()
	if !ok {
		return Session{}, false
	}
	if time.Now().After(sess.ExpiresAt) {
		s.mu.Lock()
		delete(s.sessions, token)
		s.mu.Unlock()
		return Session{}, false
	}
	return sess, true
}

// RevokeToken invalidates a session token.
func (s *UserStore) RevokeToken(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// ─── persistence ─────────────────────────────────────────────────────────────

type persistData struct {
	Users []User `json:"users"`
}

func (s *UserStore) load() error {
	data, err := os.ReadFile(s.storePath)
	if err != nil {
		return err
	}
	var pd persistData
	if err := json.Unmarshal(data, &pd); err != nil {
		return err
	}
	for _, u := range pd.Users {
		s.users[u.ID] = u
		s.byName[u.Username] = u.ID
	}
	return nil
}

// save writes users to disk. Callers must hold s.mu (at least read-only for
// user data; this function doesn't acquire the lock).
func (s *UserStore) save() error {
	if s.storePath == "" {
		return nil
	}
	users := make([]User, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, u)
	}
	b, err := json.MarshalIndent(persistData{Users: users}, "", "  ")
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
	b := make([]byte, 8)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
