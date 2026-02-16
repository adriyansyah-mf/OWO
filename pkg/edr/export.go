// Package edr provides EDR alert export and logging.
package edr

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// NewExporterSimple is a backward-compat constructor (no remote, no agent).
func NewExporterSimple(path string, alsoLogToStderr bool) (*Exporter, error) {
	return NewExporter(ExporterOptions{
		FilePath:  path,
		Stderr:    alsoLogToStderr,
		AgentName: "",
		AgentHost: "",
	})
}

// EventRecord is one exported event for monitoring/SIEM. Agent identity + raw event (no verdict/score).
type EventRecord struct {
	AgentName  string          `json:"agent_name"`
	AgentHost  string          `json:"agent_hostname"`
	AgentGroup string          `json:"agent_group,omitempty"`
	Timestamp  time.Time       `json:"timestamp"`
	Event      json.RawMessage `json:"event"`
}

// Exporter writes alert records to file, stderr, and/or remote (Wazuh-style).
type Exporter struct {
	mu       sync.Mutex
	path     string
	f        *os.File
	alsoLog  bool
	remote   *RemoteOutput
	agentName  string
	agentHost  string
	agentGroup string
}

// ExporterOptions configures file, stderr, remote, and agent identity.
type ExporterOptions struct {
	FilePath   string
	Stderr     bool
	Remote     *RemoteOutput
	AgentName  string
	AgentHost  string
	AgentGroup string
}

// NewExporter creates an exporter from options. All of file/stderr/remote are optional.
func NewExporter(opts ExporterOptions) (*Exporter, error) {
	e := &Exporter{
		alsoLog:    opts.Stderr,
		remote:     opts.Remote,
		agentName:  opts.AgentName,
		agentHost:  opts.AgentHost,
		agentGroup: opts.AgentGroup,
	}
	if opts.FilePath != "" {
		e.path = opts.FilePath
		if err := os.MkdirAll(filepath.Dir(opts.FilePath), 0755); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(opts.FilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, err
		}
		e.f = f
	}
	return e, nil
}

// WriteEvent appends one event as a JSON line to file/stderr and sends to remote. Monitoring-only (no verdict/score).
func (e *Exporter) WriteEvent(eventJSON []byte) error {
	rec := EventRecord{
		AgentName:  e.agentName,
		AgentHost:  e.agentHost,
		AgentGroup: e.agentGroup,
		Timestamp:  time.Now().UTC(),
		Event:      eventJSON,
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	lineNL := append(line, '\n')
	e.mu.Lock()
	if e.f != nil {
		_, _ = e.f.Write(lineNL)
	}
	if e.alsoLog {
		os.Stderr.Write(lineNL)
	}
	e.mu.Unlock()
	if e.remote != nil {
		go e.remote.Send(nil, line) // non-blocking; avoid slowing event pipeline
	}
	return nil
}

// Close flushes and closes the export file.
func (e *Exporter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.f != nil {
		_ = e.f.Sync()
		err := e.f.Close()
		e.f = nil
		return err
	}
	return nil
}
