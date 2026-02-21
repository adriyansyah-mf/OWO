// Package store provides database access for EDR platform.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/lib/pq"
)


// PostgresStore handles PostgreSQL operations.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgres creates a store from DSN. DSN empty = nil store (no-op).
func NewPostgres(ctx context.Context, dsn string) (*PostgresStore, error) {
	if dsn == "" {
		return nil, nil
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return &PostgresStore{db: db}, nil
}

// Close closes the db.
func (s *PostgresStore) Close() {
	if s != nil && s.db != nil {
		s.db.Close()
	}
}

// UpsertHost creates or updates host.
func (s *PostgresStore) UpsertHost(ctx context.Context, tenantID, hostID, hostname, agentName string) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO hosts (id, tenant_id, hostname, agent_name, last_seen, status)
		VALUES ($1, $2, $3, $4, NOW(), 'online')
		ON CONFLICT (id) DO UPDATE SET last_seen = NOW(), status = 'online', agent_name = COALESCE($4, hosts.agent_name)
	`, hostID, tenantID, hostname, agentName)
	return err
}

// InsertAlert inserts an alert.
func (s *PostgresStore) InsertAlert(ctx context.Context, tenantID, hostID, ruleID, severity, title, message string, eventJSON map[string]interface{}, mitre []string) error {
	if s == nil {
		return nil
	}
	ev, _ := json.Marshal(eventJSON)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO alerts (tenant_id, host_id, rule_id, severity, title, message, event_json, mitre)
		VALUES ($1, $2, NULLIF($3,'')::uuid, $4, $5, $6, $7, $8)
	`, tenantID, hostID, ruleID, severity, title, message, ev, pq.Array(mitre))
	return err
}

// ListAlerts returns alerts (limit 500).
func (s *PostgresStore) ListAlerts(ctx context.Context, tenantID, hostID string, limit int) ([]map[string]interface{}, error) {
	if s == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 500
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id::text, tenant_id, host_id, severity, title, message, event_json, mitre, created_at
		FROM alerts
		WHERE ($1 = '' OR tenant_id = $1) AND ($2 = '' OR host_id = $2)
		ORDER BY created_at DESC
		LIMIT $3
	`, tenantID, hostID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var id, tid, hid, sev, title, msg string
		var evJSON []byte
		var mitre []string
		var createdAt time.Time
		if err := rows.Scan(&id, &tid, &hid, &sev, &title, &msg, &evJSON, pq.Array(&mitre), &createdAt); err != nil {
			continue
		}
		var ev map[string]interface{}
		_ = json.Unmarshal(evJSON, &ev)
		out = append(out, map[string]interface{}{
			"id": id, "tenant_id": tid, "host_id": hid, "severity": sev,
			"title": title, "message": msg, "event_json": ev, "mitre": mitre,
			"created_at": createdAt.Format(time.RFC3339),
		})
	}
	return out, nil
}

// ListHosts returns hosts.
func (s *PostgresStore) ListHosts(ctx context.Context, tenantID string) ([]map[string]interface{}, error) {
	if s == nil {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, hostname, agent_name, last_seen, risk_score, status
		FROM hosts
		WHERE $1 = '' OR tenant_id = $1
		ORDER BY last_seen DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var id, hostname, agentName, status string
		var lastSeen time.Time
		var riskScore float64
		if err := rows.Scan(&id, &hostname, &agentName, &lastSeen, &riskScore, &status); err != nil {
			continue
		}
		out = append(out, map[string]interface{}{
			"id": id, "hostname": hostname, "agent_name": agentName,
			"last_seen": lastSeen.Format(time.RFC3339), "risk_score": riskScore, "status": status,
		})
	}
	return out, nil
}

// InsertIRAction inserts an IR action.
func (s *PostgresStore) InsertIRAction(ctx context.Context, tenantID, hostID, action string, params map[string]interface{}, requestedBy string) (string, error) {
	if s == nil {
		return "", nil
	}
	paramsJSON, _ := json.Marshal(params)
	var id string
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO ir_actions (tenant_id, host_id, action, params, requested_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id::text
	`, tenantID, hostID, action, paramsJSON, requestedBy).Scan(&id)
	return id, err
}

// ComputeAndUpdateRiskScore computes risk from alerts and updates host.
func (s *PostgresStore) ComputeAndUpdateRiskScore(ctx context.Context, hostID string) error {
	if s == nil {
		return nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT severity, mitre, created_at FROM alerts
		WHERE host_id = $1 AND created_at > NOW() - INTERVAL '24 hours'
	`, hostID)
	if err != nil {
		return err
	}
	defer rows.Close()
	var baseScore float64
	mitreSet := make(map[string]struct{})
	var lastAlert time.Time
	sevWeight := map[string]float64{"critical": 10, "high": 5, "medium": 2, "low": 1}
	for rows.Next() {
		var sev string
		var mitre []string
		var createdAt time.Time
		if err := rows.Scan(&sev, pq.Array(&mitre), &createdAt); err != nil {
			continue
		}
		w := sevWeight[sev]
		if w == 0 {
			w = 1
		}
		baseScore += w
		for _, m := range mitre {
			mitreSet[m] = struct{}{}
		}
		if createdAt.After(lastAlert) {
			lastAlert = createdAt
		}
	}
	mitreMult := 1.0 + 0.1*float64(len(mitreSet))
	recency := 0.5
	if !lastAlert.IsZero() {
		ago := time.Since(lastAlert)
		if ago < time.Hour {
			recency = 1.0
		} else if ago < 24*time.Hour {
			recency = 0.8
		}
	}
	score := baseScore * mitreMult * recency
	return s.UpdateRiskScore(ctx, hostID, score)
}

// UpdateHostStatus sets host status (online, isolated, offline).
func (s *PostgresStore) UpdateHostStatus(ctx context.Context, hostID, status string) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `UPDATE hosts SET status = $2 WHERE id = $1`, hostID, status)
	return err
}

// UpdateRiskScore updates host risk score.
func (s *PostgresStore) UpdateRiskScore(ctx context.Context, hostID string, score float64) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `UPDATE hosts SET risk_score = $2 WHERE id = $1`, hostID, score)
	return err
}

// InsertProcessNode inserts a process tree node (execve).
func (s *PostgresStore) InsertProcessNode(ctx context.Context, tenantID, hostID string, pid, ppid int, exe, cmdline string, mitre, gtfobins []string) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO process_tree (tenant_id, host_id, pid, ppid, exe, cmdline, mitre, gtfobins)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, tenantID, hostID, pid, ppid, exe, cmdline, pq.Array(mitre), pq.Array(gtfobins))
	return err
}

// MarkProcessExit marks process as exited.
func (s *PostgresStore) MarkProcessExit(ctx context.Context, hostID string, pid int) error {
	if s == nil {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE process_tree SET exit_ts = NOW()
		WHERE id = (SELECT id FROM process_tree WHERE host_id = $1 AND pid = $2 AND exit_ts IS NULL ORDER BY start_ts DESC LIMIT 1)
	`, hostID, pid)
	return err
}

// ListProcessTree returns process tree for host (live processes only by default).
func (s *PostgresStore) ListProcessTree(ctx context.Context, hostID string, includeExited bool) ([]map[string]interface{}, error) {
	if s == nil {
		return nil, nil
	}
	q := `
		SELECT pid, ppid, exe, cmdline, start_ts, exit_ts, mitre, gtfobins
		FROM process_tree
		WHERE host_id = $1
	`
	if !includeExited {
		q += ` AND exit_ts IS NULL`
	}
	q += ` ORDER BY start_ts`
	rows, err := s.db.QueryContext(ctx, q, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]interface{}
	for rows.Next() {
		var pid, ppid int
		var exe, cmdline string
		var startTs time.Time
		var exitTs *time.Time
		var mitre, gtfobins []string
		if err := rows.Scan(&pid, &ppid, &exe, &cmdline, &startTs, &exitTs, pq.Array(&mitre), pq.Array(&gtfobins)); err != nil {
			continue
		}
		m := map[string]interface{}{
			"pid": pid, "ppid": ppid, "exe": exe, "cmdline": cmdline,
			"start_ts": startTs.Format(time.RFC3339), "mitre": mitre, "gtfobins": gtfobins,
		}
		if exitTs != nil {
			m["exit_ts"] = exitTs.Format(time.RFC3339)
			m["risk"] = "normal"
		} else {
			m["risk"] = "normal"
		}
		// Simple name from exe
		if exe != "" {
			parts := strings.Split(exe, "/")
			m["name"] = parts[len(parts)-1]
		} else {
			m["name"] = ""
		}
		out = append(out, m)
	}
	return out, nil
}
