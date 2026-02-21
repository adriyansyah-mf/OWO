// API: REST gateway for EDR platform.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	"edr-linux/pkg/store"
	"edr-linux/pkg/sigma"

	"github.com/nats-io/nats.go"
)

const (
	defaultAdminUser = "owo"
	defaultAdminPass = "owo"
)

var (
	alertsMem   []map[string]interface{}
	alertsMu    sync.RWMutex
	storePg     *store.PostgresStore
	nc          *nats.Conn
	validTokens = make(map[string]time.Time)
	tokensMu    sync.RWMutex
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
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/login", cors(handleLogin))
	mux.HandleFunc("/api/v1/auth/logout", cors(handleLogout))
	mux.HandleFunc("/api/v1/health", cors(handleHealth))
	mux.HandleFunc("/api/v1/alerts", cors(authRequired(handleAlerts)))
	mux.HandleFunc("/api/v1/hosts", cors(authRequired(handleHosts)))
	mux.HandleFunc("/api/v1/hosts/", cors(authRequired(handleHostByID)))
	mux.HandleFunc("/api/v1/ir/isolate", cors(authRequired(handleIRIsolate)))
	mux.HandleFunc("/api/v1/ir/release", cors(authRequired(handleIRRelease)))
	mux.HandleFunc("/api/v1/ir/kill", cors(authRequired(handleIRKill)))
	mux.HandleFunc("/api/v1/ir/collect", cors(authRequired(handleIRCollect)))
	mux.HandleFunc("/api/v1/rules", cors(authRequired(handleRulesList)))
	mux.HandleFunc("/api/v1/rules/", cors(authRequired(handleRulesByID)))
	mux.HandleFunc("/api/v1/test/inject-event", cors(authRequired(handleTestInjectEvent)))

	log.Printf("api: listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
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
		http.Error(w, "invalid body", 400)
		return
	}
	if body.Username != defaultAdminUser || body.Password != defaultAdminPass {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid credentials"})
		return
	}
	b := make([]byte, 32)
	rand.Read(b)
	token := base64.URLEncoding.EncodeToString(b)
	tokensMu.Lock()
	validTokens[token] = time.Now().Add(24 * time.Hour)
	tokensMu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		token := auth[7:]
		tokensMu.Lock()
		delete(validTokens, token)
		tokensMu.Unlock()
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
}

func authRequired(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if len(auth) < 8 || auth[:7] != "Bearer " {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		token := auth[7:]
		tokensMu.RLock()
		exp, ok := validTokens[token]
		tokensMu.RUnlock()
		if !ok || time.Now().After(exp) {
			if ok {
				tokensMu.Lock()
				delete(validTokens, token)
				tokensMu.Unlock()
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		h(w, r)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "time": time.Now().Format(time.RFC3339)})
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

func cors(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		h(w, r)
	}
}
