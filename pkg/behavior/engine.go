// Package behavior correlates exec, file, and network events for detection.
package behavior

import (
	"sync"
	"time"
)

const (
	windowSeconds = 15
	maxPids       = 4096
)

// Alert from behavior rule.
type Alert struct {
	Rule      string
	Pid       uint32
	Detail    string
	Timestamp time.Time
}

type pidState struct {
	lastExecPath string
	lastExecTime time.Time
	lastConnect  time.Time
	lastFileOp   time.Time
	lastFilePath string
}

// Engine holds per-pid state and evaluates correlation rules.
type Engine struct {
	mu    sync.Mutex
	pids  map[uint32]*pidState
	alerts []Alert
}

// NewEngine creates a new behavior engine.
func NewEngine() *Engine {
	return &Engine{pids: make(map[uint32]*pidState)}
}

// AddExec records an exec event. Call Check() after for new alerts.
func (e *Engine) AddExec(pid uint32, path string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	if e.pids[pid] == nil {
		if len(e.pids) >= maxPids {
			e.pruneLocked()
		}
		e.pids[pid] = &pidState{}
	}
	s := e.pids[pid]
	s.lastExecPath = path
	s.lastExecTime = now
}

// AddFile records a file event (openat/unlink/rename).
func (e *Engine) AddFile(pid uint32, op, path string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	if e.pids[pid] == nil {
		if len(e.pids) >= maxPids {
			e.pruneLocked()
		}
		e.pids[pid] = &pidState{}
	}
	e.pids[pid].lastFileOp = now
	e.pids[pid].lastFilePath = path
}

// AddNetwork records a connect/sendto event.
func (e *Engine) AddNetwork(pid uint32, daddr string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	if e.pids[pid] == nil {
		if len(e.pids) >= maxPids {
			e.pruneLocked()
		}
		e.pids[pid] = &pidState{}
	}
	e.pids[pid].lastConnect = now
}

// Check runs correlation rules and returns new alerts. Does not clear state.
func (e *Engine) Check() []Alert {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Alert
	now := time.Now()
	for pid, s := range e.pids {
		// Rule: exec from /tmp or /dev/shm followed by connect within window -> potential reverse shell
		if isWatchedExecPath(s.lastExecPath) && !s.lastConnect.IsZero() {
			dt := s.lastConnect.Sub(s.lastExecTime)
			if dt >= 0 && dt <= windowSeconds*time.Second {
				out = append(out, Alert{
					Rule:      "exec_then_connect",
					Pid:       pid,
					Detail:    "exec from " + s.lastExecPath + " then outbound connect (potential reverse shell)",
					Timestamp: now,
				})
			}
		}
	}
	// Prune old state periodically
	if len(e.pids) >= maxPids/2 {
		e.pruneLocked()
	}
	return out
}

func isWatchedExecPath(p string) bool {
	if len(p) < 4 {
		return false
	}
	return (p[0] == '/' && p[1] == 't' && p[2] == 'm' && p[3] == 'p') ||
		(len(p) >= 8 && p[0] == '/' && p[1] == 'd' && p[2] == 'e' && p[3] == 'v' && p[4] == '/' && p[5] == 's' && p[6] == 'h' && p[7] == 'm')
}

func (e *Engine) pruneLocked() {
	cut := time.Now().Add(-windowSeconds * 2 * time.Second)
	for pid, s := range e.pids {
		if s.lastExecTime.Before(cut) && s.lastConnect.Before(cut) && s.lastFileOp.Before(cut) {
			delete(e.pids, pid)
		}
	}
}
