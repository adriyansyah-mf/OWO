// API: REST gateway for EDR platform.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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

	"edr-linux/pkg/devicecontrol"
	"edr-linux/pkg/dlp"
	"edr-linux/pkg/store"
	"edr-linux/pkg/sigma"

	"github.com/nats-io/nats.go"
)

const (
	clamavPathsFile       = "data/clamav_paths.json"
	dlpPathsFile          = "data/dlp_paths.json"
	dlpPatternsFile       = "data/dlp_patterns.json"
	deviceControlPolicyFile = "data/device_control.json"
)

const (
	defaultAdminUser = "owo"
	defaultAdminPass = "owo"
)

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
	storePg        *store.PostgresStore
	nc             *nats.Conn
	validTokens    = make(map[string]time.Time)
	tokensMu       sync.RWMutex
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
	mux.HandleFunc("/api/v1/auth/login", cors(handleLogin))
	mux.HandleFunc("/api/v1/auth/logout", cors(handleLogout))
	mux.HandleFunc("/api/v1/health", cors(handleHealth))
	mux.HandleFunc("/api/v1/alerts", cors(authRequired(handleAlerts)))
	mux.HandleFunc("/api/v1/alerts/stream", cors(authRequired(handleAlertsStream)))
	mux.HandleFunc("/api/v1/hosts", cors(authRequired(handleHosts)))
	mux.HandleFunc("/api/v1/hosts/", cors(authRequired(handleHostByID)))
	mux.HandleFunc("/api/v1/ir/isolate", cors(authRequired(handleIRIsolate)))
	mux.HandleFunc("/api/v1/ir/release", cors(authRequired(handleIRRelease)))
	mux.HandleFunc("/api/v1/ir/kill", cors(authRequired(handleIRKill)))
	mux.HandleFunc("/api/v1/ir/collect", cors(authRequired(handleIRCollect)))
	mux.HandleFunc("/api/v1/ir/scan", cors(authRequired(handleIRScan)))
	mux.HandleFunc("/api/v1/ir/deep-scan", cors(authRequired(handleIRDeepScan)))
	mux.HandleFunc("/api/v1/ir/av-scan", cors(authRequired(handleIRAVScan)))
	mux.HandleFunc("/api/v1/ir/dlp-scan", cors(authRequired(handleIRDLPScan)))
	mux.HandleFunc("/api/v1/av-scan-results", cors(authRequired(handleAVScanResults)))
	mux.HandleFunc("/api/v1/dlp-scan-results", cors(authRequired(handleDLPScanResults)))
	mux.HandleFunc("/api/v1/settings/clamav-paths", cors(authRequired(handleClamAVPaths)))
	mux.HandleFunc("/api/v1/settings/dlp-paths", cors(authRequired(handleDLPPaths)))
	mux.HandleFunc("/api/v1/dlp/patterns", cors(authRequired(handleDLPPatterns)))
	mux.HandleFunc("/api/v1/policies/device-control", cors(authRequired(handleDeviceControlPolicy)))
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
		token := ""
		if auth := r.Header.Get("Authorization"); len(auth) >= 8 && auth[:7] == "Bearer " {
			token = auth[7:]
		} else if t := r.URL.Query().Get("token"); t != "" {
			token = t
		}
		if token == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
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
