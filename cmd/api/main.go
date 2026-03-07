// API: REST gateway for EDR platform.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"edr-linux/pkg/agentmgr"
	"edr-linux/pkg/correlation"
	"edr-linux/pkg/devicecontrol"
	"edr-linux/pkg/dlp"
	"edr-linux/pkg/hunt"
	"edr-linux/pkg/notify"
	"edr-linux/pkg/playbook"
	"edr-linux/pkg/rbac"
	"edr-linux/pkg/report"
	"edr-linux/pkg/sigma"
	"edr-linux/pkg/store"
	"edr-linux/pkg/threatintel"

	"github.com/nats-io/nats.go"
)

const (
	clamavPathsFile         = "data/clamav_paths.json"
	dlpPathsFile            = "data/dlp_paths.json"
	dlpPatternsFile         = "data/dlp_patterns.json"
	deviceControlPolicyFile = "data/device_control.json"
	dlpPoliciesFile         = "data/dlp_policies.json"
	dlpBehavioralFile       = "data/dlp_behavioral.json"
	dlpFingerprintsFile     = "data/dlp_fingerprints.json"
	usersFile               = "data/users.json"
	agentsFile              = "data/agents.json"
	adminAuditFile          = "data/admin-audit.jsonl"
	iocStoreFile            = "data/iocs.json"
	incidentsFile           = "data/incidents.json"
	playbooksFile           = "data/playbooks.json"
	notifyChannelsFile      = "data/notify_channels.json"
	savedHuntsFile          = "data/saved_hunts.json"
)

// defaultAdminUser / defaultAdminPass are used only on first startup when no
// users file exists. Change via the UI or env vars ADMIN_USER / ADMIN_PASS.
const (
	defaultAdminUser = "owo"
	defaultAdminPass = "owo"
)

// sessionCtxKey is used to store the rbac.Session in the request context.
type sessionCtxKey struct{}

// dlpBehavioralConfig holds the behavioral DLP engine configuration persisted to disk.
type dlpBehavioralConfig struct {
	Enabled             bool `json:"enabled"`
	MassAccessPerMinute int  `json:"mass_access_per_minute"`
	BulkReadMB          int  `json:"bulk_read_mb"`
	USBCopyPerMinute    int  `json:"usb_copy_per_minute"`
}

// dlpFingerprintEntry is a known-sensitive-document fingerprint stored in the API.
type dlpFingerprintEntry struct {
	Hash  string `json:"hash"`
	Name  string `json:"name"`
	Label string `json:"label"`
	Notes string `json:"notes,omitempty"`
}

var (
	alertsMem        []map[string]interface{}
	alertsMu         sync.RWMutex
	alertStreamChans []chan []byte
	alertStreamMu    sync.RWMutex
	avScanResults    []map[string]interface{}
	avScanMu        sync.RWMutex
	dlpScanResults  []map[string]interface{}
	dlpScanMu       sync.RWMutex
	clamavPaths     = []string{"/tmp", "/var/tmp", "/home"}
	clamavPathsMu   sync.RWMutex
	dlpPaths           = []string{"/tmp", "/var/tmp", "/home"}
	dlpPathsMu         sync.RWMutex
	dlpPatterns        []dlp.Pattern
	dlpPatternsMu      sync.RWMutex
	deviceControlPolicy devicecontrol.Policy
	deviceControlMu     sync.RWMutex
	// DLP enterprise state
	dlpPolicies       []dlp.DLPPolicy
	dlpPoliciesMu     sync.RWMutex
	dlpBehavioralCfg  = dlpBehavioralConfig{MassAccessPerMinute: 100, BulkReadMB: 50, USBCopyPerMinute: 20}
	dlpBehavioralMu   sync.RWMutex
	dlpFingerprints   []dlpFingerprintEntry
	dlpFingerprintsMu sync.RWMutex
	// RBAC and agent management
	userStore         *rbac.UserStore
	agentStore        *agentmgr.Store
	iocStore          *threatintel.Store
	correlationEngine *correlation.Engine
	playbookEngine    *playbook.Engine
	notifyManager     *notify.Manager
	huntEngine        *hunt.Engine
	reportGen         *report.Generator
	storePg    *store.PostgresStore
	nc         *nats.Conn
)

func main() {
	natsURL := getEnv("NATS_URL", "nats://localhost:4222")
	addr := getEnv("ADDR", ":8080")
	postgresDSN := getEnv("POSTGRES_DSN", "")

	ctx := context.Background()
	var err error
	if postgresDSN != "" {
		storePg, err = store.NewPostgres(ctx, postgresDSN)
		if err != nil {
			log.Printf("postgres: %v (using memory)", err)
			storePg = nil
		} else {
			defer storePg.Close()
			log.Println("postgres: connected")
		}
	}

	// Load ClamAV paths from file
	if data, err := os.ReadFile(clamavPathsFile); err == nil {
		var p []string
		if json.Unmarshal(data, &p) == nil && len(p) > 0 {
			clamavPaths = p
			log.Printf("clamav paths: loaded %d from %s", len(p), clamavPathsFile)
		}
	}
	// Load DLP paths from file
	if data, err := os.ReadFile(dlpPathsFile); err == nil {
		var p []string
		if json.Unmarshal(data, &p) == nil && len(p) > 0 {
			dlpPaths = p
			log.Printf("dlp paths: loaded %d from %s", len(p), dlpPathsFile)
		}
	}
	// Load DLP patterns from file
	if data, err := os.ReadFile(dlpPatternsFile); err == nil {
		if patterns := dlp.PatternsFromJSON(data); len(patterns) > 0 {
			dlpPatterns = patterns
			log.Printf("dlp patterns: loaded %d from %s", len(patterns), dlpPatternsFile)
		}
	}
	if len(dlpPatterns) == 0 {
		dlpPatterns = dlp.DefaultPatterns()
	}
	// Load device control policy
	if data, err := os.ReadFile(deviceControlPolicyFile); err == nil {
		var p devicecontrol.Policy
		if json.Unmarshal(data, &p) == nil {
			deviceControlPolicy = p
			log.Printf("device control: loaded from %s (enabled=%v)", deviceControlPolicyFile, p.Enabled)
		}
	} else {
		deviceControlPolicy = devicecontrol.DefaultPolicy()
	}
	// Load DLP enforcement policies
	if data, err := os.ReadFile(dlpPoliciesFile); err == nil {
		var p []dlp.DLPPolicy
		if json.Unmarshal(data, &p) == nil && len(p) > 0 {
			dlpPolicies = p
			log.Printf("dlp policies: loaded %d from %s", len(p), dlpPoliciesFile)
		}
	}
	if len(dlpPolicies) == 0 {
		dlpPolicies = dlp.DefaultPolicies()
	}
	// Load behavioral DLP config
	if data, err := os.ReadFile(dlpBehavioralFile); err == nil {
		var b dlpBehavioralConfig
		if json.Unmarshal(data, &b) == nil {
			dlpBehavioralCfg = b
			log.Printf("dlp behavioral: loaded from %s (enabled=%v)", dlpBehavioralFile, b.Enabled)
		}
	}
	// Load fingerprint registry
	if data, err := os.ReadFile(dlpFingerprintsFile); err == nil {
		var f []dlpFingerprintEntry
		if json.Unmarshal(data, &f) == nil {
			dlpFingerprints = f
			log.Printf("dlp fingerprints: loaded %d from %s", len(f), dlpFingerprintsFile)
		}
	}
	// Init RBAC user store and seed default admin if needed
	userStore = rbac.NewUserStore(usersFile)
	adminUser := getEnv("ADMIN_USER", defaultAdminUser)
	adminPass := getEnv("ADMIN_PASS", defaultAdminPass)
	if err := userStore.SeedAdmin(adminUser, adminPass); err != nil {
		log.Printf("rbac: seed admin: %v", err)
	} else {
		log.Printf("rbac: user store ready (%s)", usersFile)
	}
	// Init agent store
	agentStore = agentmgr.New(agentsFile)
	log.Printf("agentmgr: store ready (%s, %d agent(s))", agentsFile, len(agentStore.List()))
	// Init threat intel IOC store
	iocStore = threatintel.New(iocStoreFile)
	log.Printf("threatintel: ioc store ready (%s)", iocStoreFile)
	// Init correlation engine
	correlationEngine = correlation.New(incidentsFile)
	log.Printf("correlation: engine ready (%s)", incidentsFile)
	// Init notify manager
	notifyManager = notify.New(notifyChannelsFile)
	log.Printf("notify: channel manager ready (%s)", notifyChannelsFile)
	// Init playbook engine
	playbookEngine = playbook.New(playbooksFile)
	playbookEngine.SeedDefaults()
	log.Printf("playbook: engine ready (%s, %d playbook(s))", playbooksFile, len(playbookEngine.List()))
	// Init hunt engine
	huntEngine = hunt.New(savedHuntsFile)
	log.Printf("hunt: engine ready (%s)", savedHuntsFile)
	// Init report generator
	reportGen = report.New()
	// Register playbook action handlers
	playbookEngine.RegisterHandler(playbook.ActionNotify, func(action playbook.Action, alert map[string]interface{}) error {
		tmpl := action.Params["message"]
		if tmpl == "" {
			tmpl = "EDR Alert: {{severity}} — {{title}} on {{host_id}}"
		}
		var chanNames []string
		if cn := action.Params["channels"]; cn != "" {
			for _, n := range strings.Split(cn, ",") {
				chanNames = append(chanNames, strings.TrimSpace(n))
			}
		}
		notifyManager.Send(tmpl, alert, chanNames...)
		return nil
	})
	playbookEngine.RegisterHandler(playbook.ActionIsolateHost, func(action playbook.Action, alert map[string]interface{}) error {
		hostID, _ := alert["host_id"].(string)
		if hostID == "" || nc == nil {
			return nil
		}
		cmd := map[string]interface{}{
			"id":      "pb-ir-" + fmt.Sprintf("%d", time.Now().UnixNano()),
			"host_id": hostID, "action": "isolate", "params": map[string]interface{}{}, "status": "pending",
		}
		b, _ := json.Marshal(cmd)
		nc.Publish("ir.commands", b)
		log.Printf("playbook: auto-isolate triggered for host %s", hostID)
		return nil
	})
	playbookEngine.RegisterHandler(playbook.ActionTagIOC, func(action playbook.Action, alert map[string]interface{}) error {
		var value string
		switch action.Params["ioc_field"] {
		case "source_ip":
			if ev, ok := alert["event_json"].(map[string]interface{}); ok {
				value, _ = ev["src_ip"].(string)
			}
		}
		if value == "" {
			return nil
		}
		sev := action.Params["severity"]
		if sev == "" {
			sev = "medium"
		}
		src := action.Params["source"]
		if src == "" {
			src = "playbook"
		}
		iocStore.Add(threatintel.IOC{Value: value, Severity: sev, Source: src, Confidence: 70})
		return nil
	})

	nc, err = nats.Connect(natsURL)
	if err != nil {
		log.Printf("nats connect: %v (API will run without NATS)", err)
		nc = nil
	}
	if nc != nil {
		defer nc.Close()
		nc.Subscribe("alerts", func(m *nats.Msg) {
			var a map[string]interface{}
			if json.Unmarshal(m.Data, &a) != nil {
				return
			}
			alertsMu.Lock()
			alertsMem = append(alertsMem, a)
			if len(alertsMem) > 1000 {
				alertsMem = alertsMem[len(alertsMem)-1000:]
			}
			alertsMu.Unlock()
			broadcastAlert(a)
			correlationEngine.IngestAlert(a)
			playbookEngine.Evaluate(a)
			huntEngine.Ingest(a)
			if storePg != nil {
				hid, _ := a["host_id"].(string)
				tid, _ := a["tenant_id"].(string)
				if tid == "" {
					tid = "default"
				}
				if hid != "" {
					storePg.UpsertHost(ctx, tid, hid, hid, "")
					sev, _ := a["severity"].(string)
					title, _ := a["title"].(string)
					msg, _ := a["message"].(string)
					ruleID, _ := a["rule_id"].(string)
					evJSON, _ := a["event_json"].(map[string]interface{})
					mitre, _ := a["mitre"].([]string)
					storePg.InsertAlert(ctx, tid, hid, ruleID, sev, title, msg, evJSON, mitre)
					storePg.ComputeAndUpdateRiskScore(ctx, hid)
				}
			}
		})
		nc.Subscribe("av.scan_results", func(m *nats.Msg) {
			var a map[string]interface{}
			if json.Unmarshal(m.Data, &a) != nil {
				return
			}
			avScanMu.Lock()
			avScanResults = append(avScanResults, a)
			if len(avScanResults) > 200 {
				avScanResults = avScanResults[len(avScanResults)-200:]
			}
			avScanMu.Unlock()
			// Publish malware findings to alerts for web UI notification
			if results, ok := a["results"].([]interface{}); ok {
				hostID, _ := a["host_id"].(string)
				tenantID, _ := a["tenant_id"].(string)
				if tenantID == "" {
					tenantID = "default"
				}
				for _, r := range results {
					rm, _ := r.(map[string]interface{})
					if status, _ := rm["status"].(string); status == "infected" {
						path, _ := rm["path"].(string)
						virus, _ := rm["virus"].(string)
						alert := map[string]interface{}{
							"id":         "alt-" + fmt.Sprintf("%d", time.Now().UnixNano()/1e6),
							"tenant_id":  tenantID,
							"host_id":    hostID,
							"rule_id":    "malware_detected",
							"rule_name":  "Malware Detected (AV Scan)",
							"severity":   "critical",
							"title":      "Malware Detected",
							"message":    path + ": " + virus,
							"event_json": map[string]interface{}{"path": path, "virus": virus},
							"created_at": time.Now().UTC(),
						}
						alertsMu.Lock()
						alertsMem = append(alertsMem, alert)
						if len(alertsMem) > 1000 {
							alertsMem = alertsMem[len(alertsMem)-1000:]
						}
						alertsMu.Unlock()
						if storePg != nil && hostID != "" {
							bg := context.Background()
							storePg.UpsertHost(bg, tenantID, hostID, hostID, "")
							storePg.InsertAlert(bg, tenantID, hostID, "malware_detected", "critical", "Malware Detected", path+": "+virus, map[string]interface{}{"path": path, "virus": virus}, nil)
							storePg.ComputeAndUpdateRiskScore(bg, hostID)
						}
						broadcastAlert(alert)
					}
				}
			}
		})
		// Publish device control policy on startup and when agents request it
		if b, err := json.Marshal(deviceControlPolicy); err == nil {
			nc.Publish("device_control.policy", b)
		}
		nc.Subscribe("device_control.request", func(m *nats.Msg) {
			deviceControlMu.RLock()
			p := deviceControlPolicy
			deviceControlMu.RUnlock()
			if b, err := json.Marshal(p); err == nil {
				m.Respond(b)
			}
		})
		nc.Subscribe("dlp.scan_results", func(m *nats.Msg) {
			var a map[string]interface{}
			if json.Unmarshal(m.Data, &a) != nil {
				return
			}
			dlpScanMu.Lock()
			dlpScanResults = append(dlpScanResults, a)
			if len(dlpScanResults) > 200 {
				dlpScanResults = dlpScanResults[len(dlpScanResults)-200:]
			}
			dlpScanMu.Unlock()
		})
	}

	mux := http.NewServeMux()
	// Auth (no RBAC required)
	mux.HandleFunc("/api/v1/auth/login", cors(handleLogin))
	mux.HandleFunc("/api/v1/auth/logout", cors(requirePerm(rbac.PermReadAlerts, handleLogout)))
	mux.HandleFunc("/api/v1/auth/me", cors(requirePerm(rbac.PermReadAlerts, handleAuthMe)))
	mux.HandleFunc("/api/v1/health", cors(handleHealth))
	// Alerts
	mux.HandleFunc("/api/v1/alerts", cors(requirePerm(rbac.PermReadAlerts, handleAlerts)))
	mux.HandleFunc("/api/v1/alerts/stream", cors(requirePerm(rbac.PermReadAlerts, handleAlertsStream)))
	// Hosts
	mux.HandleFunc("/api/v1/hosts", cors(requirePerm(rbac.PermReadHosts, handleHosts)))
	mux.HandleFunc("/api/v1/hosts/", cors(requirePerm(rbac.PermReadHosts, handleHostByID)))
	// Incident Response
	mux.HandleFunc("/api/v1/ir/isolate", cors(requirePerm(rbac.PermWriteIR, handleIRIsolate)))
	mux.HandleFunc("/api/v1/ir/release", cors(requirePerm(rbac.PermWriteIR, handleIRRelease)))
	mux.HandleFunc("/api/v1/ir/kill", cors(requirePerm(rbac.PermWriteIR, handleIRKill)))
	mux.HandleFunc("/api/v1/ir/collect", cors(requirePerm(rbac.PermWriteIR, handleIRCollect)))
	mux.HandleFunc("/api/v1/ir/scan", cors(requirePerm(rbac.PermWriteIR, handleIRScan)))
	mux.HandleFunc("/api/v1/ir/deep-scan", cors(requirePerm(rbac.PermWriteIR, handleIRDeepScan)))
	mux.HandleFunc("/api/v1/ir/av-scan", cors(requirePerm(rbac.PermWriteIR, handleIRAVScan)))
	mux.HandleFunc("/api/v1/ir/dlp-scan", cors(requirePerm(rbac.PermWriteIR, handleIRDLPScan)))
	// Scan results
	mux.HandleFunc("/api/v1/av-scan-results", cors(requirePerm(rbac.PermReadScans, handleAVScanResults)))
	mux.HandleFunc("/api/v1/dlp-scan-results", cors(requirePerm(rbac.PermReadScans, handleDLPScanResults)))
	// Settings
	mux.HandleFunc("/api/v1/settings/clamav-paths", cors(requirePerm(rbac.PermWriteSettings, handleClamAVPaths)))
	mux.HandleFunc("/api/v1/settings/dlp-paths", cors(requirePerm(rbac.PermWriteSettings, handleDLPPaths)))
	// DLP
	mux.HandleFunc("/api/v1/dlp/patterns", cors(requirePerm(rbac.PermWriteDLP, handleDLPPatterns)))
	mux.HandleFunc("/api/v1/dlp/policies", cors(requirePerm(rbac.PermWriteDLP, handleDLPPolicies)))
	mux.HandleFunc("/api/v1/dlp/audit", cors(requirePerm(rbac.PermReadAudit, handleDLPAuditLog)))
	mux.HandleFunc("/api/v1/dlp/behavioral", cors(requirePerm(rbac.PermWriteDLP, handleDLPBehavioral)))
	mux.HandleFunc("/api/v1/dlp/fingerprints", cors(requirePerm(rbac.PermWriteDLP, handleDLPFingerprints)))
	// Policies
	mux.HandleFunc("/api/v1/policies/device-control", cors(requirePerm(rbac.PermWriteSettings, handleDeviceControlPolicy)))
	// Sigma rules
	mux.HandleFunc("/api/v1/rules", cors(requirePerm(rbac.PermReadRules, handleRulesList)))
	mux.HandleFunc("/api/v1/rules/", cors(requirePerm(rbac.PermReadRules, handleRulesByID)))
	// User management (admin only)
	mux.HandleFunc("/api/v1/users", cors(requirePerm(rbac.PermWriteUsers, handleUsers)))
	mux.HandleFunc("/api/v1/users/", cors(requirePerm(rbac.PermWriteUsers, handleUserByID)))
	// Agent management
	mux.HandleFunc("/api/v1/agents/enroll", cors(handleAgentEnroll)) // no user auth — agents call this
	mux.HandleFunc("/api/v1/agents/stats", cors(requirePerm(rbac.PermReadHosts, handleAgentStats)))
	mux.HandleFunc("/api/v1/agents/", cors(requirePerm(rbac.PermReadHosts, handleAgentByID)))
	mux.HandleFunc("/api/v1/agents", cors(requirePerm(rbac.PermReadHosts, handleAgents)))
	// Admin audit log
	mux.HandleFunc("/api/v1/admin/audit", cors(requirePerm(rbac.PermAdmin, handleAdminAuditLog)))
	// Threat Intelligence
	mux.HandleFunc("/api/v1/threat-intel/iocs", cors(requirePerm(rbac.PermReadAlerts, handleThreatIntelIOCs)))
	mux.HandleFunc("/api/v1/threat-intel/iocs/", cors(requirePerm(rbac.PermReadAlerts, handleThreatIntelIOCByID)))
	mux.HandleFunc("/api/v1/threat-intel/lookup", cors(requirePerm(rbac.PermReadAlerts, handleThreatIntelLookup)))
	mux.HandleFunc("/api/v1/threat-intel/feed", cors(requirePerm(rbac.PermWriteSettings, handleThreatIntelFeed)))
	mux.HandleFunc("/api/v1/threat-intel/stats", cors(requirePerm(rbac.PermReadAlerts, handleThreatIntelStats)))
	// Incidents
	mux.HandleFunc("/api/v1/incidents", cors(requirePerm(rbac.PermReadAlerts, handleIncidents)))
	mux.HandleFunc("/api/v1/incidents/", cors(requirePerm(rbac.PermReadAlerts, handleIncidentByID)))
	// Playbooks
	mux.HandleFunc("/api/v1/playbooks", cors(requirePerm(rbac.PermReadAlerts, handlePlaybooks)))
	mux.HandleFunc("/api/v1/playbooks/history", cors(requirePerm(rbac.PermReadAlerts, handlePlaybookHistory)))
	mux.HandleFunc("/api/v1/playbooks/", cors(requirePerm(rbac.PermReadAlerts, handlePlaybookByID)))
	// Notify channels
	mux.HandleFunc("/api/v1/notify/channels", cors(requirePerm(rbac.PermWriteSettings, handleNotifyChannels)))
	mux.HandleFunc("/api/v1/notify/channels/", cors(requirePerm(rbac.PermWriteSettings, handleNotifyChannelByID)))
	mux.HandleFunc("/api/v1/notify/test", cors(requirePerm(rbac.PermWriteSettings, handleNotifyTest)))
	// Hunt
	mux.HandleFunc("/api/v1/hunt", cors(requirePerm(rbac.PermReadAlerts, handleHunt)))
	mux.HandleFunc("/api/v1/hunt/saved", cors(requirePerm(rbac.PermReadAlerts, handleSavedHunts)))
	mux.HandleFunc("/api/v1/hunt/saved/", cors(requirePerm(rbac.PermReadAlerts, handleSavedHuntByID)))
	// Reports
	mux.HandleFunc("/api/v1/reports/generate", cors(requirePerm(rbac.PermReadAlerts, handleReportGenerate)))
	mux.HandleFunc("/api/v1/reports/export", cors(requirePerm(rbac.PermReadAlerts, handleReportExport)))
	// Test
	mux.HandleFunc("/api/v1/test/inject-event", cors(requirePerm(rbac.PermAdmin, handleTestInjectEvent)))

	// TLS support: set TLS_CERT_FILE and TLS_KEY_FILE env vars to enable HTTPS
	certFile := getEnv("TLS_CERT_FILE", "")
	keyFile := getEnv("TLS_KEY_FILE", "")
	if certFile != "" && keyFile != "" {
		log.Printf("api: TLS enabled, listening on %s", addr)
		log.Fatal(http.ListenAndServeTLS(addr, certFile, keyFile, mux))
	} else {
		log.Printf("api: listening on %s (plaintext — set TLS_CERT_FILE/TLS_KEY_FILE for HTTPS)", addr)
		log.Fatal(http.ListenAndServe(addr, mux))
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		writeJSONError(w, 400, "invalid body")
		return
	}
	sess, err := userStore.Authenticate(body.Username, body.Password)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid credentials"})
		return
	}
	writeAdminAudit("login", sess.Username, string(sess.Role), r.RemoteAddr, "")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token":    sess.Token,
		"username": sess.Username,
		"role":     string(sess.Role),
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if sess, ok := r.Context().Value(sessionCtxKey{}).(rbac.Session); ok {
		userStore.RevokeToken(sess.Token)
		writeAdminAudit("logout", sess.Username, string(sess.Role), r.RemoteAddr, "")
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
}

func handleAuthMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	sess, _ := r.Context().Value(sessionCtxKey{}).(rbac.Session)
	u, ok := userStore.GetByID(sess.UserID)
	if !ok {
		writeJSONError(w, 404, "user not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(u.Public())
}

// requirePerm returns a middleware that enforces a required permission.
// It stores the validated session in the request context for downstream handlers.
func requirePerm(perm rbac.Permission, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			writeJSONError(w, 401, "unauthorized")
			return
		}
		sess, ok := userStore.ValidateToken(token)
		if !ok {
			writeJSONError(w, 401, "unauthorized")
			return
		}
		if !sess.Role.HasPermission(perm) {
			writeJSONError(w, 403, fmt.Sprintf("forbidden: role %q lacks permission %q", sess.Role, perm))
			return
		}
		ctx := context.WithValue(r.Context(), sessionCtxKey{}, sess)
		h(w, r.WithContext(ctx))
	}
}

func extractToken(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return r.URL.Query().Get("token")
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "time": time.Now().Format(time.RFC3339)})
}

func broadcastAlert(a map[string]interface{}) {
	b, err := json.Marshal(a)
	if err != nil {
		return
	}
	alertStreamMu.RLock()
	chans := make([]chan []byte, len(alertStreamChans))
	copy(chans, alertStreamChans)
	alertStreamMu.RUnlock()
	for _, ch := range chans {
		select {
		case ch <- b:
		default:
			// client slow, skip
		}
	}
}

func handleAlertsStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", 500)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	ch := make(chan []byte, 8)
	alertStreamMu.Lock()
	alertStreamChans = append(alertStreamChans, ch)
	alertStreamMu.Unlock()
	defer func() {
		alertStreamMu.Lock()
		for i, c := range alertStreamChans {
			if c == ch {
				alertStreamChans = append(alertStreamChans[:i], alertStreamChans[i+1:]...)
				break
			}
		}
		alertStreamMu.Unlock()
		close(ch)
	}()
	flusher.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case data, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func handleAlerts(w http.ResponseWriter, r *http.Request) {
	hostID := r.URL.Query().Get("host_id")
	tenantID := r.URL.Query().Get("tenant_id")

	if storePg != nil {
		list, err := storePg.ListAlerts(r.Context(), tenantID, hostID, 500)
		if err == nil && len(list) > 0 {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(list)
			return
		}
	}

	alertsMu.RLock()
	out := make([]map[string]interface{}, len(alertsMem))
	copy(out, alertsMem)
	alertsMu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func handleHosts(w http.ResponseWriter, r *http.Request) {
	tenantID := r.URL.Query().Get("tenant_id")

	if storePg != nil {
		list, err := storePg.ListHosts(r.Context(), tenantID)
		if err == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(list)
			return
		}
	}

	hosts := []map[string]interface{}{
		{"id": "JIMBE", "hostname": "JIMBE", "status": "online", "risk_score": 0, "last_seen": time.Now().Format(time.RFC3339)},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hosts)
}

func handleHostByID(w http.ResponseWriter, r *http.Request) {
	// /api/v1/hosts/{id} or /api/v1/hosts/{id}/process-tree
	path := r.URL.Path
	if len(path) < len("/api/v1/hosts/") {
		http.NotFound(w, r)
		return
	}
	rest := path[len("/api/v1/hosts/"):]
	hostID := rest
	for i, c := range rest {
		if c == '/' {
			hostID = rest[:i]
			break
		}
	}
	if hostID == "" {
		http.NotFound(w, r)
		return
	}

	if len(rest) > len(hostID) && rest[len(hostID):] == "/process-tree" {
		handleProcessTree(w, r, hostID)
		return
	}

	// Single host - return stub for now
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id": hostID, "hostname": hostID, "status": "online", "risk_score": 0,
		"last_seen": time.Now().Format(time.RFC3339),
	})
}

func handleProcessTree(w http.ResponseWriter, r *http.Request, hostID string) {
	if storePg != nil {
		limit := 300
		if l := r.URL.Query().Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 {
				if n > 2000 {
					n = 2000
				}
				limit = n
			}
		}
		list, err := storePg.ListProcessTree(r.Context(), hostID, false, limit)
		if err == nil && len(list) > 0 {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(list)
			return
		}
	}

	// Demo fallback
	demo := []map[string]interface{}{
		{"id": "p1", "ppid": nil, "name": "systemd", "exe": "/usr/lib/systemd/systemd", "risk": "normal"},
		{"id": "p2", "ppid": "p1", "name": "xfce4-session", "exe": "/usr/bin/xfce4-session", "risk": "normal"},
		{"id": "p3", "ppid": "p2", "name": "xfce4-panel", "exe": "/usr/bin/xfce4-panel", "risk": "normal"},
		{"id": "p4", "ppid": "p3", "name": "ip", "exe": "/usr/bin/ip", "risk": "normal", "meta": []string{"shell"}},
		{"id": "p5", "ppid": "p3", "name": "nc", "exe": "/usr/bin/nc", "risk": "high", "meta": []string{"reverse-shell"}, "alerts": 2},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(demo)
}

func handleIRIsolate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var body struct {
		HostID string `json:"host_id"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.HostID == "" {
		http.Error(w, "host_id required", 400)
		return
	}
	cmd := map[string]interface{}{
		"id":        "ir-" + time.Now().Format("20060102150405"),
		"tenant_id": "default",
		"host_id":   body.HostID,
		"action":    "isolate",
		"params":    map[string]interface{}{},
		"status":    "pending",
	}
	b, _ := json.Marshal(cmd)
	if storePg != nil {
		storePg.InsertIRAction(r.Context(), "default", body.HostID, "isolate", map[string]interface{}{}, "")
		storePg.UpdateHostStatus(r.Context(), body.HostID, "isolated")
	}
	if nc != nil {
		nc.Publish("ir.commands", b)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cmd)
}

func handleIRKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var body struct {
		HostID string `json:"host_id"`
		Pid    int    `json:"pid"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.HostID == "" || body.Pid == 0 {
		http.Error(w, "host_id and pid required", 400)
		return
	}
	params := map[string]interface{}{"pid": body.Pid}
	cmd := map[string]interface{}{
		"id":        "ir-" + time.Now().Format("20060102150405"),
		"tenant_id": "default",
		"host_id":   body.HostID,
		"action":    "kill_process",
		"params":    params,
		"status":    "pending",
	}
	b, _ := json.Marshal(cmd)
	if storePg != nil {
		storePg.InsertIRAction(r.Context(), "default", body.HostID, "kill_process", params, "")
	}
	if nc != nil {
		nc.Publish("ir.commands", b)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cmd)
}

func handleIRRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var body struct {
		HostID string `json:"host_id"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.HostID == "" {
		http.Error(w, "host_id required", 400)
		return
	}
	cmd := map[string]interface{}{
		"id":        "ir-" + time.Now().Format("20060102150405"),
		"tenant_id": "default",
		"host_id":   body.HostID,
		"action":    "release",
		"params":    map[string]interface{}{},
		"status":    "pending",
	}
	b, _ := json.Marshal(cmd)
	if storePg != nil {
		storePg.InsertIRAction(r.Context(), "default", body.HostID, "release", map[string]interface{}{}, "")
		storePg.UpdateHostStatus(r.Context(), body.HostID, "online")
	}
	if nc != nil {
		nc.Publish("ir.commands", b)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cmd)
}

func handleIRScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var body struct {
		HostID string `json:"host_id"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.HostID == "" {
		http.Error(w, "host_id required", 400)
		return
	}
	cmd := map[string]interface{}{
		"id":        "ir-" + time.Now().Format("20060102150405"),
		"tenant_id": "default",
		"host_id":   body.HostID,
		"action":    "scan",
		"params":    map[string]interface{}{},
		"status":    "pending",
	}
	b, _ := json.Marshal(cmd)
	go func() {
		if storePg != nil {
			storePg.InsertIRAction(context.Background(), "default", body.HostID, "scan", map[string]interface{}{}, "")
		}
		if nc != nil {
			nc.Publish("ir.commands", b)
		}
	}()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cmd)
}

func handleIRDeepScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var body struct {
		HostID string `json:"host_id"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.HostID == "" {
		http.Error(w, "host_id required", 400)
		return
	}
	cmd := map[string]interface{}{
		"id":        "ir-" + time.Now().Format("20060102150405"),
		"tenant_id": "default",
		"host_id":   body.HostID,
		"action":    "deep_scan",
		"params":    map[string]interface{}{},
		"status":    "pending",
	}
	b, _ := json.Marshal(cmd)
	go func() {
		if storePg != nil {
			storePg.InsertIRAction(context.Background(), "default", body.HostID, "deep_scan", map[string]interface{}{}, "")
		}
		if nc != nil {
			nc.Publish("ir.commands", b)
		}
	}()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cmd)
}

func handleIRAVScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var body struct {
		HostID string   `json:"host_id"`
		Paths  []string `json:"paths"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.HostID == "" {
		http.Error(w, "host_id required", 400)
		return
	}
	params := map[string]interface{}{}
	clamavPathsMu.RLock()
	paths := clamavPaths
	clamavPathsMu.RUnlock()
	if len(body.Paths) > 0 {
		paths = body.Paths
		params["paths"] = body.Paths
	} else {
		params["paths"] = paths
	}
	cmd := map[string]interface{}{
		"id":        "ir-" + time.Now().Format("20060102150405"),
		"tenant_id": "default",
		"host_id":   body.HostID,
		"action":    "av_scan",
		"params":    params,
		"status":    "pending",
	}
	b, _ := json.Marshal(cmd)
	// Lempar ke background: jangan block response
	go func() {
		if storePg != nil {
			storePg.InsertIRAction(context.Background(), "default", body.HostID, "av_scan", params, "")
		}
		if nc != nil {
			nc.Publish("ir.commands", b)
		}
	}()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cmd)
}

func handleIRDLPScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var body struct {
		HostID string   `json:"host_id"`
		Paths  []string `json:"paths"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.HostID == "" {
		http.Error(w, "host_id required", 400)
		return
	}
	params := map[string]interface{}{}
	dlpPathsMu.RLock()
	paths := dlpPaths
	dlpPathsMu.RUnlock()
	if len(body.Paths) > 0 {
		paths = body.Paths
		params["paths"] = body.Paths
	} else {
		params["paths"] = paths
	}
	dlpPatternsMu.RLock()
	patMaps := make([]map[string]interface{}, len(dlpPatterns))
	for i, p := range dlpPatterns {
		patMaps[i] = map[string]interface{}{"id": p.ID, "name": p.Name, "regex": p.Regex, "severity": p.Severity}
	}
	dlpPatternsMu.RUnlock()
	params["patterns"] = patMaps
	cmd := map[string]interface{}{
		"id":        "ir-" + time.Now().Format("20060102150405"),
		"tenant_id": "default",
		"host_id":   body.HostID,
		"action":    "dlp_scan",
		"params":    params,
		"status":    "pending",
	}
	b, _ := json.Marshal(cmd)
	go func() {
		if storePg != nil {
			storePg.InsertIRAction(context.Background(), "default", body.HostID, "dlp_scan", params, "")
		}
		if nc != nil {
			nc.Publish("ir.commands", b)
		}
	}()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cmd)
}

func handleDLPScanResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	hostID := r.URL.Query().Get("host_id")
	dlpScanMu.RLock()
	out := make([]map[string]interface{}, len(dlpScanResults))
	copy(out, dlpScanResults)
	dlpScanMu.RUnlock()
	if hostID != "" {
		filtered := make([]map[string]interface{}, 0)
		for _, a := range out {
			if h, _ := a["host_id"].(string); h == hostID {
				filtered = append(filtered, a)
			}
		}
		out = filtered
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func handleDLPPatterns(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		dlpPatternsMu.RLock()
		p := make([]dlp.Pattern, len(dlpPatterns))
		copy(p, dlpPatterns)
		dlpPatternsMu.RUnlock()
		out := make([]map[string]interface{}, len(p))
		for i, x := range p {
			out[i] = map[string]interface{}{"id": x.ID, "name": x.Name, "regex": x.Regex, "severity": x.Severity}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(out)
	case http.MethodPut:
		var raw []map[string]interface{}
		if json.NewDecoder(r.Body).Decode(&raw) != nil {
			http.Error(w, "invalid body: expected JSON array of patterns", 400)
			return
		}
		var patterns []dlp.Pattern
		for _, m := range raw {
			regex, _ := m["regex"].(string)
			if strings.TrimSpace(regex) == "" {
				continue
			}
			id, _ := m["id"].(string)
			name, _ := m["name"].(string)
			p, err := dlp.PatternFromMap(m)
			if err != nil {
				http.Error(w, fmt.Sprintf("invalid regex in pattern %q (id=%s): %v", name, id, err), 400)
				return
			}
			patterns = append(patterns, p)
		}
		if len(patterns) == 0 {
			patterns = dlp.DefaultPatterns()
		}
		dlpPatternsMu.Lock()
		dlpPatterns = patterns
		dlpPatternsMu.Unlock()
		if err := os.MkdirAll(filepath.Dir(dlpPatternsFile), 0755); err == nil {
			out := make([]map[string]interface{}, len(patterns))
			for i, p := range patterns {
				out[i] = map[string]interface{}{"id": p.ID, "name": p.Name, "regex": p.Regex, "severity": p.Severity}
			}
			if b, err := json.Marshal(out); err == nil {
				_ = os.WriteFile(dlpPatternsFile, b, 0644)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		res := make([]map[string]interface{}, len(patterns))
		for i, p := range patterns {
			res[i] = map[string]interface{}{"id": p.ID, "name": p.Name, "regex": p.Regex, "severity": p.Severity}
		}
		json.NewEncoder(w).Encode(res)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func handleDLPPaths(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		dlpPathsMu.RLock()
		p := make([]string, len(dlpPaths))
		copy(p, dlpPaths)
		dlpPathsMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(p)
	case http.MethodPut:
		var p []string
		if json.NewDecoder(r.Body).Decode(&p) != nil {
			http.Error(w, "invalid body", 400)
			return
		}
		var valid []string
		for _, s := range p {
			s = filepath.Clean(s)
			if s != "" && strings.HasPrefix(s, "/") && !strings.Contains(s, "..") {
				valid = append(valid, s)
			}
		}
		dlpPathsMu.Lock()
		dlpPaths = valid
		dlpPathsMu.Unlock()
		if err := os.MkdirAll(filepath.Dir(dlpPathsFile), 0755); err == nil {
			if b, err := json.Marshal(valid); err == nil {
				_ = os.WriteFile(dlpPathsFile, b, 0644)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(valid)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func handleDeviceControlPolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		deviceControlMu.RLock()
		p := deviceControlPolicy
		deviceControlMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(p)
	case http.MethodPut:
		var p devicecontrol.Policy
		if json.NewDecoder(r.Body).Decode(&p) != nil {
			http.Error(w, "invalid body", 400)
			return
		}
		if p.Mode != "allow" && p.Mode != "block" && p.Mode != "whitelist" && p.Mode != "blacklist" {
			p.Mode = "allow"
		}
		if len(p.RemovablePaths) == 0 {
			p.RemovablePaths = devicecontrol.DefaultPolicy().RemovablePaths
		}
		deviceControlMu.Lock()
		deviceControlPolicy = p
		deviceControlMu.Unlock()
		if err := os.MkdirAll(filepath.Dir(deviceControlPolicyFile), 0755); err == nil {
			if b, err := json.Marshal(p); err == nil {
				_ = os.WriteFile(deviceControlPolicyFile, b, 0644)
			}
		}
		if nc != nil {
			if b, err := json.Marshal(p); err == nil {
				nc.Publish("device_control.policy", b)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(p)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func handleClamAVPaths(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		clamavPathsMu.RLock()
		p := make([]string, len(clamavPaths))
		copy(p, clamavPaths)
		clamavPathsMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(p)
	case http.MethodPut:
		var p []string
		if json.NewDecoder(r.Body).Decode(&p) != nil {
			http.Error(w, "invalid body", 400)
			return
		}
		// Validate: absolute paths only, no traversal
		var valid []string
		for _, s := range p {
			s = filepath.Clean(s)
			if s != "" && strings.HasPrefix(s, "/") && !strings.Contains(s, "..") {
				valid = append(valid, s)
			}
		}
		clamavPathsMu.Lock()
		clamavPaths = valid
		clamavPathsMu.Unlock()
		if err := os.MkdirAll(filepath.Dir(clamavPathsFile), 0755); err == nil {
			if b, err := json.Marshal(valid); err == nil {
				_ = os.WriteFile(clamavPathsFile, b, 0644)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(valid)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func handleAVScanResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	hostID := r.URL.Query().Get("host_id")
	avScanMu.RLock()
	out := make([]map[string]interface{}, len(avScanResults))
	copy(out, avScanResults)
	avScanMu.RUnlock()
	if hostID != "" {
		filtered := make([]map[string]interface{}, 0)
		for _, a := range out {
			if h, _ := a["host_id"].(string); h == hostID {
				filtered = append(filtered, a)
			}
		}
		out = filtered
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func handleIRCollect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var body struct {
		HostID   string   `json:"host_id"`
		Paths    []string `json:"paths"`
		Artifact string   `json:"artifact_name"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.HostID == "" {
		http.Error(w, "host_id required", 400)
		return
	}
	if len(body.Paths) == 0 {
		body.Paths = []string{"/tmp", "/var/log"}
	}
	if body.Artifact == "" {
		body.Artifact = "triage"
	}
	params := map[string]interface{}{
		"paths":         body.Paths,
		"artifact_name": body.Artifact,
	}
	cmd := map[string]interface{}{
		"id":        "ir-" + time.Now().Format("20060102150405"),
		"tenant_id": "default",
		"host_id":   body.HostID,
		"action":    "collect_triage",
		"params":    params,
		"status":    "pending",
	}
	b, _ := json.Marshal(cmd)
	if storePg != nil {
		storePg.InsertIRAction(r.Context(), "default", body.HostID, "collect_triage", params, "")
	}
	if nc != nil {
		nc.Publish("ir.commands", b)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cmd)
}

func getEnv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func getSigmaRulesDir() string {
	return getEnv("SIGMA_RULES", "sigma/rules")
}

func handleRulesList(w http.ResponseWriter, r *http.Request) {
	dir := getSigmaRulesDir()

	if r.Method == http.MethodPost {
		// Upload new rule
		var body struct {
			Yaml string `json:"yaml"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Yaml == "" {
			writeJSONError(w, 400, "yaml required")
			return
		}
		var sr sigma.SigmaRule
		if err := sigma.ParseYAML(body.Yaml, &sr); err != nil {
			writeJSONError(w, 400, "invalid sigma yaml: "+err.Error())
			return
		}
		if sr.ID == "" || sr.Title == "" {
			writeJSONError(w, 400, "id and title required")
			return
		}
		filename := sanitizeFilename(sr.ID) + ".yml"
		path := filepath.Join(dir, filename)
		if err := os.WriteFile(path, []byte(body.Yaml), 0644); err != nil {
			log.Printf("rules write %s: %v", path, err)
			writeJSONError(w, 500, "failed to write rule")
			return
		}
		if nc != nil {
			nc.Publish("detection.reload", []byte("reload"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id": sr.ID, "title": sr.Title, "file": filename,
		})
		return
	}

	// GET: list rules
	meta, err := sigma.ListRuleMeta(dir)
	if err != nil {
		log.Printf("rules list %s: %v", dir, err)
		http.Error(w, "failed to list rules", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(meta)
}

func handleRulesByID(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if len(path) <= len("/api/v1/rules/") {
		http.NotFound(w, r)
		return
	}
	ruleID := path[len("/api/v1/rules/"):]
	if ruleID == "" {
		http.NotFound(w, r)
		return
	}
	dir := getSigmaRulesDir()

	if r.Method == http.MethodDelete {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			fpath := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(fpath)
			if err != nil {
				continue
			}
			var sr sigma.SigmaRule
			if sigma.ParseYAML(string(data), &sr) != nil {
				continue
			}
			if sr.ID == ruleID {
				if err := os.Remove(fpath); err != nil {
					http.Error(w, "failed to delete", 500)
					return
				}
				if nc != nil {
					nc.Publish("detection.reload", []byte("reload"))
				}
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{"deleted": ruleID})
				return
			}
		}
		http.NotFound(w, r)
		return
	}

	// GET: return raw YAML
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fpath := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(fpath)
		if err != nil {
			continue
		}
		var sr sigma.SigmaRule
		if sigma.ParseYAML(string(data), &sr) != nil {
			continue
		}
		if sr.ID == ruleID {
			w.Header().Set("Content-Type", "text/yaml")
			w.Write(data)
			return
		}
	}
	http.NotFound(w, r)
}

var safeFilename = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

func sanitizeFilename(s string) string {
	return safeFilename.ReplaceAllString(s, "_")
}

func handleTestInjectEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if nc == nil {
		writeJSONError(w, 500, "NATS not connected")
		return
	}
	// Inject fake nc -e event to verify pipeline (ingest→normalize→detection→alerts)
	env := map[string]interface{}{
		"agent_name":     "test-agent",
		"agent_hostname": "test-host",
		"tenant_id":      "default",
		"timestamp":      time.Now().Format(time.RFC3339),
		"event": map[string]interface{}{
			"event_type":     "execve",
			"timestamp":      time.Now().Format(time.RFC3339),
			"pid":            99999,
			"ppid":           1000,
			"uid":            1000,
			"gid":            1000,
			"comm":           "nc",
			"exe":            "/usr/bin/nc",
			"cmdline":        "nc -e /bin/sh 127.0.0.1 4444",
			"parent_path":    "/usr/bin/bash",
			"parent_cmdline": "bash",
		},
	}
	b, _ := json.Marshal(env)
	if err := nc.Publish("events.default", b); err != nil {
		writeJSONError(w, 500, "publish failed: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"ok": "injected", "message": "Check Threat Alerts in a few seconds"})
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// handleDLPPolicies manages DLP enforcement policies (GET list / PUT full replace).
func handleDLPPolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		dlpPoliciesMu.RLock()
		p := make([]dlp.DLPPolicy, len(dlpPolicies))
		copy(p, dlpPolicies)
		dlpPoliciesMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(p)
	case http.MethodPut:
		var p []dlp.DLPPolicy
		if json.NewDecoder(r.Body).Decode(&p) != nil {
			writeJSONError(w, 400, "invalid body: expected JSON array of DLPPolicy")
			return
		}
		if len(p) == 0 {
			p = dlp.DefaultPolicies()
		}
		dlpPoliciesMu.Lock()
		dlpPolicies = p
		dlpPoliciesMu.Unlock()
		saveDLPPolicies(p)
		// Hot-reload: publish to NATS so connected agents refresh their PolicyStore
		if nc != nil {
			if b, err := json.Marshal(p); err == nil {
				nc.Publish("dlp.policies.update", b)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(p)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func saveDLPPolicies(p []dlp.DLPPolicy) {
	if err := os.MkdirAll(filepath.Dir(dlpPoliciesFile), 0755); err != nil {
		return
	}
	if b, err := json.Marshal(p); err == nil {
		_ = os.WriteFile(dlpPoliciesFile, b, 0644)
	}
}

// handleDLPAuditLog streams the last N lines of the DLP audit log (JSON lines).
// Query params: limit (default 100, max 1000), severity (filter), action (filter).
func handleDLPAuditLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			if n > 1000 {
				n = 1000
			}
			limit = n
		}
	}
	severityFilter := r.URL.Query().Get("severity")
	actionFilter := r.URL.Query().Get("action")

	logPath := getEnv("DLP_AUDIT_LOG", "/var/log/edr/dlp-audit.jsonl")
	data, err := os.ReadFile(logPath)
	if err != nil {
		// Return empty array rather than 500 when file doesn't exist yet
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	// Take last `limit` lines (most recent first in reverse)
	var events []map[string]interface{}
	for i := len(lines) - 1; i >= 0 && len(events) < limit; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var ev map[string]interface{}
		if json.Unmarshal([]byte(line), &ev) != nil {
			continue
		}
		// Apply filters
		if severityFilter != "" {
			if sev, _ := ev["severity"].(string); !strings.EqualFold(sev, severityFilter) {
				continue
			}
		}
		if actionFilter != "" {
			if act, _ := ev["action"].(string); !strings.EqualFold(act, actionFilter) {
				continue
			}
		}
		events = append(events, ev)
	}
	if events == nil {
		events = []map[string]interface{}{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

// handleDLPBehavioral manages behavioral DLP engine config (GET / PUT).
func handleDLPBehavioral(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		dlpBehavioralMu.RLock()
		cfg := dlpBehavioralCfg
		dlpBehavioralMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	case http.MethodPut:
		var cfg dlpBehavioralConfig
		if json.NewDecoder(r.Body).Decode(&cfg) != nil {
			writeJSONError(w, 400, "invalid body")
			return
		}
		// Apply safe defaults for zero values
		if cfg.MassAccessPerMinute <= 0 {
			cfg.MassAccessPerMinute = 100
		}
		if cfg.BulkReadMB <= 0 {
			cfg.BulkReadMB = 50
		}
		if cfg.USBCopyPerMinute <= 0 {
			cfg.USBCopyPerMinute = 20
		}
		dlpBehavioralMu.Lock()
		dlpBehavioralCfg = cfg
		dlpBehavioralMu.Unlock()
		if err := os.MkdirAll(filepath.Dir(dlpBehavioralFile), 0755); err == nil {
			if b, err := json.Marshal(cfg); err == nil {
				_ = os.WriteFile(dlpBehavioralFile, b, 0644)
			}
		}
		// Hot-reload agents
		if nc != nil {
			if b, err := json.Marshal(cfg); err == nil {
				nc.Publish("dlp.behavioral.update", b)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

// handleDLPFingerprints manages the SHA256 fingerprint registry (GET / POST / DELETE).
// DELETE expects query param ?hash=<sha256hex>.
func handleDLPFingerprints(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		dlpFingerprintsMu.RLock()
		f := make([]dlpFingerprintEntry, len(dlpFingerprints))
		copy(f, dlpFingerprints)
		dlpFingerprintsMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(f)
	case http.MethodPost:
		var entry dlpFingerprintEntry
		if json.NewDecoder(r.Body).Decode(&entry) != nil {
			writeJSONError(w, 400, "invalid body")
			return
		}
		entry.Hash = strings.ToLower(strings.TrimSpace(entry.Hash))
		if len(entry.Hash) != 64 {
			writeJSONError(w, 400, "hash must be a 64-character SHA256 hex string")
			return
		}
		if entry.Name == "" {
			writeJSONError(w, 400, "name is required")
			return
		}
		if entry.Label == "" {
			entry.Label = "restricted"
		}
		dlpFingerprintsMu.Lock()
		// Upsert: replace if hash already exists
		found := false
		for i, f := range dlpFingerprints {
			if f.Hash == entry.Hash {
				dlpFingerprints[i] = entry
				found = true
				break
			}
		}
		if !found {
			dlpFingerprints = append(dlpFingerprints, entry)
		}
		snap := make([]dlpFingerprintEntry, len(dlpFingerprints))
		copy(snap, dlpFingerprints)
		dlpFingerprintsMu.Unlock()
		saveDLPFingerprints(snap)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(entry)
	case http.MethodDelete:
		hash := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("hash")))
		if len(hash) != 64 {
			writeJSONError(w, 400, "hash query param must be a 64-character SHA256 hex string")
			return
		}
		dlpFingerprintsMu.Lock()
		newList := dlpFingerprints[:0]
		for _, f := range dlpFingerprints {
			if f.Hash != hash {
				newList = append(newList, f)
			}
		}
		dlpFingerprints = newList
		snap := make([]dlpFingerprintEntry, len(dlpFingerprints))
		copy(snap, dlpFingerprints)
		dlpFingerprintsMu.Unlock()
		saveDLPFingerprints(snap)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"deleted": hash})
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func saveDLPFingerprints(f []dlpFingerprintEntry) {
	if err := os.MkdirAll(filepath.Dir(dlpFingerprintsFile), 0755); err != nil {
		return
	}
	if b, err := json.Marshal(f); err == nil {
		_ = os.WriteFile(dlpFingerprintsFile, b, 0644)
	}
}

// ─── Admin audit trail ───────────────────────────────────────────────────────

func writeAdminAudit(action, username, role, remoteAddr, detail string) {
	entry := map[string]interface{}{
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"action":      action,
		"username":    username,
		"role":        role,
		"remote_addr": remoteAddr,
		"detail":      detail,
	}
	b, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(adminAuditFile), 0755)
	f, err := os.OpenFile(adminAuditFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(b, '\n'))
}

func handleAdminAuditLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	limit := 200
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 2000 {
			limit = n
		}
	}
	data, err := os.ReadFile(adminAuditFile)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var events []map[string]interface{}
	for i := len(lines) - 1; i >= 0 && len(events) < limit; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var ev map[string]interface{}
		if json.Unmarshal([]byte(line), &ev) == nil {
			events = append(events, ev)
		}
	}
	if events == nil {
		events = []map[string]interface{}{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

// ─── User management ─────────────────────────────────────────────────────────

func handleUsers(w http.ResponseWriter, r *http.Request) {
	sess, _ := r.Context().Value(sessionCtxKey{}).(rbac.Session)
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(userStore.ListUsers())
	case http.MethodPost:
		var body struct {
			Username string    `json:"username"`
			Password string    `json:"password"`
			Role     rbac.Role `json:"role"`
			Email    string    `json:"email"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Username == "" || body.Password == "" {
			writeJSONError(w, 400, "username and password are required")
			return
		}
		if !rbac.ValidRole(body.Role) {
			writeJSONError(w, 400, "invalid role (valid: admin, analyst, readonly, auditor)")
			return
		}
		u, err := userStore.AddUser(body.Username, body.Password, body.Role, body.Email)
		if err != nil {
			writeJSONError(w, 409, err.Error())
			return
		}
		writeAdminAudit("user.create", sess.Username, string(sess.Role), r.RemoteAddr,
			fmt.Sprintf("created user %q role=%s", body.Username, body.Role))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(u.Public())
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func handleUserByID(w http.ResponseWriter, r *http.Request) {
	sess, _ := r.Context().Value(sessionCtxKey{}).(rbac.Session)
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	if id == "" {
		writeJSONError(w, 400, "user id required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		u, ok := userStore.GetByID(id)
		if !ok {
			writeJSONError(w, 404, "user not found")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(u.Public())
	case http.MethodPut:
		var body struct {
			Password string    `json:"password"`
			Role     rbac.Role `json:"role"`
			Email    string    `json:"email"`
			Enabled  bool      `json:"enabled"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			writeJSONError(w, 400, "invalid body")
			return
		}
		if body.Role != "" && !rbac.ValidRole(body.Role) {
			writeJSONError(w, 400, "invalid role")
			return
		}
		// Default enabled to true if not specified
		u, err := userStore.UpdateUser(id, body.Password, body.Role, body.Email, body.Enabled)
		if err != nil {
			writeJSONError(w, 404, err.Error())
			return
		}
		writeAdminAudit("user.update", sess.Username, string(sess.Role), r.RemoteAddr,
			fmt.Sprintf("updated user %q", u.Username))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(u.Public())
	case http.MethodDelete:
		u, ok := userStore.GetByID(id)
		if !ok {
			writeJSONError(w, 404, "user not found")
			return
		}
		if u.ID == sess.UserID {
			writeJSONError(w, 400, "cannot delete your own account")
			return
		}
		if err := userStore.DeleteUser(id); err != nil {
			writeJSONError(w, 400, err.Error())
			return
		}
		writeAdminAudit("user.delete", sess.Username, string(sess.Role), r.RemoteAddr,
			fmt.Sprintf("deleted user %q", u.Username))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"deleted": id})
	default:
		http.Error(w, "method not allowed", 405)
	}
}

// ─── Agent management ────────────────────────────────────────────────────────

// handleAgentEnroll is called by agents (no user auth).
// POST with JSON body: { hostname, ip, os, os_version, agent_version, tenant_id }
func handleAgentEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var body struct {
		Hostname     string `json:"hostname"`
		IPAddress    string `json:"ip_address"`
		OS           string `json:"os"`
		OSVersion    string `json:"os_version"`
		AgentVersion string `json:"agent_version"`
		TenantID     string `json:"tenant_id"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.Hostname == "" {
		writeJSONError(w, 400, "hostname is required")
		return
	}
	if body.TenantID == "" {
		body.TenantID = "default"
	}
	agent := agentStore.Enroll(
		body.Hostname, body.IPAddress, body.OS,
		body.OSVersion, body.AgentVersion, body.TenantID,
	)
	log.Printf("agentmgr: enrolled %s (%s) status=%s", agent.Hostname, agent.ID, agent.Status)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	json.NewEncoder(w).Encode(agent) // includes EnrollToken for the agent
}

func handleAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(agentStore.List())
}

func handleAgentStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(agentStore.Stats())
}

func handleAgentByID(w http.ResponseWriter, r *http.Request) {
	sess, _ := r.Context().Value(sessionCtxKey{}).(rbac.Session)
	// Path: /api/v1/agents/{id} or /api/v1/agents/{id}/heartbeat or /api/v1/agents/{id}/status
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/agents/")
	parts := strings.SplitN(rest, "/", 2)
	agentID := parts[0]
	sub := ""
	if len(parts) == 2 {
		sub = parts[1]
	}

	if agentID == "" {
		writeJSONError(w, 400, "agent id required")
		return
	}

	// Heartbeat: agents POST without user auth — validate with enroll token
	if sub == "heartbeat" {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		token := extractToken(r)
		var body struct {
			IPAddress    string `json:"ip_address"`
			AgentVersion string `json:"agent_version"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		agent, err := agentStore.Heartbeat(agentID, token, body.IPAddress, body.AgentVersion)
		if err != nil {
			writeJSONError(w, 403, err.Error())
			return
		}
		agent.EnrollToken = "" // never leak token
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(agent)
		return
	}

	// All other sub-routes require authenticated user
	if sess.UserID == "" {
		writeJSONError(w, 401, "unauthorized")
		return
	}

	switch sub {
	case "status":
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", 405)
			return
		}
		if !sess.Role.HasPermission(rbac.PermWriteAgents) {
			writeJSONError(w, 403, "forbidden: requires write:agents")
			return
		}
		var body struct {
			Status agentmgr.AgentStatus `json:"status"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			writeJSONError(w, 400, "invalid body")
			return
		}
		agent, err := agentStore.SetStatus(agentID, body.Status, sess.Username)
		if err != nil {
			writeJSONError(w, 404, err.Error())
			return
		}
		writeAdminAudit("agent.status", sess.Username, string(sess.Role), r.RemoteAddr,
			fmt.Sprintf("agent %s (%s) → %s", agent.Hostname, agentID, body.Status))
		agent.EnrollToken = ""
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(agent)
	case "tags":
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", 405)
			return
		}
		var body struct {
			Groups []string `json:"groups"`
			Tags   []string `json:"tags"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		agent, err := agentStore.UpdateTags(agentID, body.Groups, body.Tags)
		if err != nil {
			writeJSONError(w, 404, err.Error())
			return
		}
		agent.EnrollToken = ""
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(agent)
	case "":
		switch r.Method {
		case http.MethodGet:
			agent, ok := agentStore.GetByID(agentID)
			if !ok {
				writeJSONError(w, 404, "agent not found")
				return
			}
			agent.EnrollToken = ""
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(agent)
		case http.MethodDelete:
			if !sess.Role.HasPermission(rbac.PermWriteAgents) {
				writeJSONError(w, 403, "forbidden: requires write:agents")
				return
			}
			if err := agentStore.Delete(agentID); err != nil {
				writeJSONError(w, 404, err.Error())
				return
			}
			writeAdminAudit("agent.delete", sess.Username, string(sess.Role), r.RemoteAddr, agentID)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"deleted": agentID})
		default:
			http.Error(w, "method not allowed", 405)
		}
	default:
		http.NotFound(w, r)
	}
}

// ─── Threat Intel handlers ────────────────────────────────────────────────────

func handleThreatIntelIOCs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		iocType := r.URL.Query().Get("type")
		severity := r.URL.Query().Get("severity")
		source := r.URL.Query().Get("source")
		query := r.URL.Query().Get("q")
		list := iocStore.List(iocType, severity, source, query)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)
	case http.MethodPost:
		sess, _ := r.Context().Value(sessionCtxKey{}).(rbac.Session)
		if !sess.Role.HasPermission(rbac.PermWriteSettings) {
			writeJSONError(w, 403, "forbidden: requires write:settings")
			return
		}
		var ioc threatintel.IOC
		if err := json.NewDecoder(r.Body).Decode(&ioc); err != nil {
			writeJSONError(w, 400, "invalid body")
			return
		}
		if ioc.Value == "" {
			writeJSONError(w, 400, "value required")
			return
		}
		added, err := iocStore.Add(ioc)
		if err != nil {
			writeJSONError(w, 400, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(added)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func handleThreatIntelIOCByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/threat-intel/iocs/")
	if id == "" {
		writeJSONError(w, 400, "id required")
		return
	}
	sess, _ := r.Context().Value(sessionCtxKey{}).(rbac.Session)
	switch r.Method {
	case http.MethodDelete:
		if !sess.Role.HasPermission(rbac.PermWriteSettings) {
			writeJSONError(w, 403, "forbidden: requires write:settings")
			return
		}
		if err := iocStore.Remove(id); err != nil {
			writeJSONError(w, 404, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"deleted": id})
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func handleThreatIntelLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	value := r.URL.Query().Get("value")
	if value == "" && r.Method == http.MethodPost {
		var body struct {
			Value string `json:"value"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		value = body.Value
	}
	if value == "" {
		writeJSONError(w, 400, "value required")
		return
	}
	result := iocStore.Lookup(value)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleThreatIntelFeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var body struct {
		URL    string `json:"url"`
		Text   string `json:"text"`
		Format string `json:"format"`
		Source string `json:"source"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, 400, "invalid body")
		return
	}
	if body.Format == "" {
		body.Format = "auto"
	}
	if body.Source == "" {
		body.Source = "manual"
	}
	var result threatintel.ImportResult
	if body.URL != "" {
		r2, err := iocStore.FetchFeed(body.URL, body.Format, body.Source)
		if err != nil {
			writeJSONError(w, 400, err.Error())
			return
		}
		result = r2
	} else if body.Text != "" {
		result = iocStore.ImportText(body.Text, body.Format, body.Source)
	} else {
		writeJSONError(w, 400, "url or text required")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func handleThreatIntelStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(iocStore.GetStats())
}

// ─── Incident handlers ────────────────────────────────────────────────────────

func handleIncidents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		status := correlation.IncidentStatus(r.URL.Query().Get("status"))
		hostID := r.URL.Query().Get("host_id")
		tenantID := r.URL.Query().Get("tenant_id")
		limit := 200
		if l := r.URL.Query().Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil && n > 0 {
				limit = n
			}
		}
		list := correlationEngine.ListIncidents(status, hostID, tenantID, limit)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func handleIncidentByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/incidents/")
	parts := strings.SplitN(rest, "/", 2)
	incidentID := parts[0]
	if incidentID == "" {
		writeJSONError(w, 400, "incident id required")
		return
	}
	sess, _ := r.Context().Value(sessionCtxKey{}).(rbac.Session)

	switch r.Method {
	case http.MethodGet:
		inc, ok := correlationEngine.GetIncident(incidentID)
		if !ok {
			writeJSONError(w, 404, "incident not found")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(inc)
	case http.MethodPut:
		if !sess.Role.HasPermission(rbac.PermWriteIR) {
			writeJSONError(w, 403, "forbidden: requires write:ir")
			return
		}
		var body struct {
			Status     string `json:"status"`
			Notes      string `json:"notes"`
			AssignedTo string `json:"assigned_to"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSONError(w, 400, "invalid body")
			return
		}
		inc, err := correlationEngine.UpdateIncident(incidentID, body.Status, body.Notes, body.AssignedTo)
		if err != nil {
			writeJSONError(w, 404, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(inc)
	case http.MethodDelete:
		if !sess.Role.HasPermission(rbac.PermAdmin) {
			writeJSONError(w, 403, "forbidden: requires admin")
			return
		}
		if err := correlationEngine.DeleteIncident(incidentID); err != nil {
			writeJSONError(w, 404, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"deleted": incidentID})
	default:
		http.Error(w, "method not allowed", 405)
	}
}

// ─── Playbook handlers ────────────────────────────────────────────────────────

func handlePlaybooks(w http.ResponseWriter, r *http.Request) {
	sess, _ := r.Context().Value(sessionCtxKey{}).(rbac.Session)
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(playbookEngine.List())
	case http.MethodPost:
		if !sess.Role.HasPermission(rbac.PermWriteSettings) {
			writeJSONError(w, 403, "forbidden: requires write:settings")
			return
		}
		var pb playbook.Playbook
		if err := json.NewDecoder(r.Body).Decode(&pb); err != nil {
			writeJSONError(w, 400, "invalid body")
			return
		}
		if pb.Name == "" {
			writeJSONError(w, 400, "name required")
			return
		}
		created := playbookEngine.Add(pb)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(created)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func handlePlaybookHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(playbookEngine.History(limit))
}

func handlePlaybookByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/playbooks/")
	parts := strings.SplitN(rest, "/", 2)
	pbID := parts[0]
	if pbID == "" {
		writeJSONError(w, 400, "playbook id required")
		return
	}
	sess, _ := r.Context().Value(sessionCtxKey{}).(rbac.Session)

	switch r.Method {
	case http.MethodGet:
		pb, ok := playbookEngine.GetByID(pbID)
		if !ok {
			writeJSONError(w, 404, "playbook not found")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(pb)
	case http.MethodPut:
		if !sess.Role.HasPermission(rbac.PermWriteSettings) {
			writeJSONError(w, 403, "forbidden: requires write:settings")
			return
		}
		var pb playbook.Playbook
		if err := json.NewDecoder(r.Body).Decode(&pb); err != nil {
			writeJSONError(w, 400, "invalid body")
			return
		}
		pb.ID = pbID
		updated := playbookEngine.Add(pb)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updated)
	case http.MethodPatch:
		// Toggle enabled: PATCH {"enabled": true/false}
		if !sess.Role.HasPermission(rbac.PermWriteSettings) {
			writeJSONError(w, 403, "forbidden: requires write:settings")
			return
		}
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSONError(w, 400, "invalid body")
			return
		}
		if err := playbookEngine.SetEnabled(pbID, body.Enabled); err != nil {
			writeJSONError(w, 404, err.Error())
			return
		}
		pb, _ := playbookEngine.GetByID(pbID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(pb)
	case http.MethodDelete:
		if !sess.Role.HasPermission(rbac.PermWriteSettings) {
			writeJSONError(w, 403, "forbidden: requires write:settings")
			return
		}
		if err := playbookEngine.Remove(pbID); err != nil {
			writeJSONError(w, 404, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"deleted": pbID})
	default:
		http.Error(w, "method not allowed", 405)
	}
}

// ─── Notify channel handlers ──────────────────────────────────────────────────

func handleNotifyChannels(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(notifyManager.ListChannels(true))
	case http.MethodPost:
		var ch notify.Channel
		if err := json.NewDecoder(r.Body).Decode(&ch); err != nil {
			writeJSONError(w, 400, "invalid body")
			return
		}
		if ch.Name == "" || ch.URL == "" {
			writeJSONError(w, 400, "name and url required")
			return
		}
		created := notifyManager.AddChannel(ch)
		created.URL = "" // don't return URL in response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(created)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func handleNotifyChannelByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/notify/channels/")
	if id == "" {
		writeJSONError(w, 400, "channel id required")
		return
	}
	switch r.Method {
	case http.MethodPut:
		var ch notify.Channel
		if err := json.NewDecoder(r.Body).Decode(&ch); err != nil {
			writeJSONError(w, 400, "invalid body")
			return
		}
		ch.ID = id
		updated := notifyManager.AddChannel(ch)
		updated.URL = ""
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(updated)
	case http.MethodDelete:
		if err := notifyManager.RemoveChannel(id); err != nil {
			writeJSONError(w, 404, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"deleted": id})
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var body struct {
		ChannelID string `json:"channel_id"`
		Message   string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, 400, "invalid body")
		return
	}
	if body.ChannelID == "" {
		writeJSONError(w, 400, "channel_id required")
		return
	}
	msg := body.Message
	if msg == "" {
		msg = "OWO EDR — test notification from " + time.Now().UTC().Format(time.RFC3339)
	}
	result := notifyManager.SendToChannel(body.ChannelID, msg)
	w.Header().Set("Content-Type", "application/json")
	if !result.OK {
		w.WriteHeader(http.StatusBadGateway)
	}
	json.NewEncoder(w).Encode(result)
}

// ─── Hunt handlers ────────────────────────────────────────────────────────────

func handleHunt(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		q := hunt.Query{}
		qs := r.URL.Query()
		if v := qs.Get("from"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				q.From = t
			}
		}
		if v := qs.Get("to"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				q.To = t
			}
		}
		q.TenantID = qs.Get("tenant_id")
		q.HostID = qs.Get("host_id")
		q.Severity = qs.Get("severity")
		q.RuleID = qs.Get("rule_id")
		q.MitreTag = qs.Get("mitre_tag")
		q.AttackChain = qs.Get("attack_chain")
		q.Keyword = qs.Get("keyword")
		if v := qs.Get("offset"); v != "" {
			q.Offset, _ = strconv.Atoi(v)
		}
		if v := qs.Get("limit"); v != "" {
			q.Limit, _ = strconv.Atoi(v)
		}
		result := huntEngine.Execute(q)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	case http.MethodPost:
		var q hunt.Query
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			writeJSONError(w, 400, "invalid body")
			return
		}
		result := huntEngine.Execute(q)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func handleSavedHunts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(huntEngine.ListSavedHunts())
	case http.MethodPost:
		sess, _ := r.Context().Value(sessionCtxKey{}).(rbac.Session)
		if !sess.Role.HasPermission(rbac.PermWriteSettings) {
			writeJSONError(w, 403, "forbidden: requires write:settings")
			return
		}
		var sh hunt.SavedHunt
		if err := json.NewDecoder(r.Body).Decode(&sh); err != nil {
			writeJSONError(w, 400, "invalid body")
			return
		}
		if sh.Name == "" {
			writeJSONError(w, 400, "name required")
			return
		}
		saved := huntEngine.SaveHunt(sh)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(saved)
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func handleSavedHuntByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/hunt/saved/")
	if id == "" {
		writeJSONError(w, 400, "id required")
		return
	}
	// Handle run sub-path
	if strings.HasSuffix(id, "/run") {
		id = strings.TrimSuffix(id, "/run")
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		result, err := huntEngine.RunSaved(id)
		if err != nil {
			writeJSONError(w, 404, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
		return
	}
	sess, _ := r.Context().Value(sessionCtxKey{}).(rbac.Session)
	switch r.Method {
	case http.MethodDelete:
		if !sess.Role.HasPermission(rbac.PermWriteSettings) {
			writeJSONError(w, 403, "forbidden: requires write:settings")
			return
		}
		if err := huntEngine.DeleteSavedHunt(id); err != nil {
			writeJSONError(w, 404, err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"deleted": id})
	default:
		http.Error(w, "method not allowed", 405)
	}
}

// ─── Report handlers ──────────────────────────────────────────────────────────

func handleReportGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Type     report.ReportType `json:"type"`
		From     time.Time         `json:"from"`
		To       time.Time         `json:"to"`
		TenantID string            `json:"tenant_id"`
		Limit    int               `json:"limit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, 400, "invalid body")
		return
	}
	p := report.Params{From: req.From, To: req.To, TenantID: req.TenantID, Limit: req.Limit}

	alertsMu.RLock()
	alerts := make([]map[string]interface{}, len(alertsMem))
	copy(alerts, alertsMem)
	alertsMu.RUnlock()

	var rpt report.Report
	switch req.Type {
	case report.TypeAlertSummary:
		rpt = reportGen.GenerateAlertSummary(alerts, p)
	case report.TypeMitreCoverage:
		rpt = reportGen.GenerateMitreCoverage(alerts, p)
	case report.TypeDLPSummary:
		dlpScanMu.RLock()
		dlpCopy := make([]map[string]interface{}, len(dlpScanResults))
		copy(dlpCopy, dlpScanResults)
		dlpScanMu.RUnlock()
		rpt = reportGen.GenerateDLPSummary(dlpCopy, p)
	case report.TypeHostRisk:
		rpt = reportGen.GenerateHostRisk(alerts, p)
	case report.TypeIncidentSummary:
		incidents := correlationEngine.ListIncidents("", "", "", 0)
		incMaps := make([]map[string]interface{}, 0, len(incidents))
		for _, inc := range incidents {
			b, _ := json.Marshal(inc)
			var m map[string]interface{}
			json.Unmarshal(b, &m)
			incMaps = append(incMaps, m)
		}
		rpt = reportGen.GenerateIncidentSummary(incMaps, p)
	default:
		writeJSONError(w, 400, "unknown report type: "+string(req.Type))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rpt)
}

func handleReportExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", 405)
		return
	}
	exportType := r.URL.Query().Get("type")
	switch exportType {
	case "alerts":
		alertsMu.RLock()
		alerts := make([]map[string]interface{}, len(alertsMem))
		copy(alerts, alertsMem)
		alertsMu.RUnlock()
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=\"alerts.csv\"")
		report.ExportAlerts(w, alerts)
	case "incidents":
		incidents := correlationEngine.ListIncidents("", "", "", 0)
		incMaps := make([]map[string]interface{}, 0, len(incidents))
		for _, inc := range incidents {
			b, _ := json.Marshal(inc)
			var m map[string]interface{}
			json.Unmarshal(b, &m)
			incMaps = append(incMaps, m)
		}
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=\"incidents.csv\"")
		report.ExportIncidents(w, incMaps)
	default:
		writeJSONError(w, 400, "type must be 'alerts' or 'incidents'")
	}
}

func cors(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		h(w, r)
	}
}
