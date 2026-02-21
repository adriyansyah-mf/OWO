package sigma

import (
	"os"
	"path/filepath"
	"testing"

	"edr-linux/pkg/detection"
)

func TestCompile_NetcatRule(t *testing.T) {
	// Load from sigma/rules (relative to project root when run via go test)
	paths := []string{"sigma/rules/process_suspicious_netcat.yml", "../../sigma/rules/process_suspicious_netcat.yml"}
	var r *detection.Rule
	var err error
	for _, p := range paths {
		r, err = LoadFile(p)
		if err == nil && r != nil {
			break
		}
	}
	if r == nil {
		// Try LoadDir to find any rule
		dirs := []string{"sigma/rules", "../../sigma/rules"}
		for _, d := range dirs {
			rules, e := LoadDir(d)
			if e == nil && len(rules) > 0 {
				r = &rules[0]
				err = nil
				break
			}
		}
	}
	if r == nil {
		t.Skip("no sigma rules found (run from project root or sigma/rules empty)")
		return
	}
	if r.Cond.Op != "or" && r.Cond.Op != "and" {
		t.Errorf("cond op = %s", r.Cond.Op)
	}
}

func TestCompile_InlineYAML(t *testing.T) {
	// Verify Compile works with minimal YAML
	tmp := t.TempDir()
	yml := `title: Test
id: test-1
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains: 'evil'
  condition: selection
level: high
`
	f := filepath.Join(tmp, "test.yml")
	os.WriteFile(f, []byte(yml), 0644)
	r, err := LoadFile(f)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if r == nil {
		t.Fatal("rule is nil")
	}
	if r.ID != "test-1" {
		t.Errorf("id = %s", r.ID)
	}
}
