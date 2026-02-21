// Package sigma loads and compiles Sigma rules to detection.Rule format.
package sigma

import (
	"os"
	"path/filepath"
	"strings"

	"edr-linux/pkg/detection"
	"gopkg.in/yaml.v3"
)

// ParseYAML unmarshals YAML into a SigmaRule (or any struct).
func ParseYAML(data string, v interface{}) error {
	return yaml.Unmarshal([]byte(data), v)
}

// SigmaRule is the YAML structure for Sigma rules.
type SigmaRule struct {
	ID          string                 `yaml:"id"`
	Title       string                 `yaml:"title"`
	Level       string                 `yaml:"level"`
	Status      string                 `yaml:"status"`
	Tags        []string               `yaml:"tags"`
	LogSource   map[string]string      `yaml:"logsource"`
	Detection   map[string]interface{} `yaml:"detection"`
}

// sigmaFieldMap maps Sigma field names to ECS/normalized field names.
var sigmaFieldMap = map[string]string{
	"CommandLine": "process.command_line",
	"Image":       "process.executable",
	"ParentImage": "process.parent.executable",
}

func mapField(sigmaField string) string {
	if m, ok := sigmaFieldMap[sigmaField]; ok {
		return m
	}
	return "process." + strings.ToLower(sigmaField)
}

func levelToSeverity(level string) string {
	switch strings.ToLower(level) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "informational":
		return "low"
	default:
		return "medium"
	}
}

// tagsToMitre maps common Sigma tags to MITRE IDs (simplified).
func tagsToMitre(tags []string) []string {
	var out []string
	for _, t := range tags {
		if strings.HasPrefix(t, "attack.") {
			// attack.execution -> T1059, attack.defense_evasion -> T1562, etc.
			switch {
			case strings.Contains(t, "execution"):
				out = append(out, "T1059")
			case strings.Contains(t, "defense_evasion"):
				out = append(out, "T1562")
			case strings.Contains(t, "persistence"):
				out = append(out, "T1547")
			case strings.Contains(t, "privilege"):
				out = append(out, "T1068")
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// parseSelection converts a Sigma selection (map of field|modifier: value) to Condition.
func parseSelection(sel interface{}) *detection.Condition {
	m, ok := sel.(map[string]interface{})
	if !ok {
		return nil
	}
	var children []detection.Condition
	for k, v := range m {
		if k == "condition" {
			continue
		}
		valStr, ok := v.(string)
		if !ok {
			continue
		}
		parts := strings.SplitN(k, "|", 2)
		field := parts[0]
		modifier := "contains"
		if len(parts) == 2 {
			modifier = strings.TrimSpace(parts[1])
		}
		ecsField := mapField(field)
		children = append(children, detection.Condition{
			Op:    modifier,
			Field: ecsField,
			Value: valStr,
		})
	}
	if len(children) == 0 {
		return nil
	}
	if len(children) == 1 {
		return &children[0]
	}
	return &detection.Condition{Op: "and", Children: children}
}

// parseCondition parses "1 of selection*" or "selection" etc.
func parseCondition(det map[string]interface{}, condStr string) *detection.Condition {
	condStr = strings.TrimSpace(condStr)
	// "1 of selection*" -> OR of selection, selection_ncat, ...
	if strings.Contains(condStr, " of ") {
		parts := strings.SplitN(condStr, " of ", 2)
		if len(parts) != 2 {
			return nil
		}
		selPattern := strings.TrimSpace(parts[1])
		selPattern = strings.TrimSuffix(selPattern, "*")
		var children []detection.Condition
		for k, v := range det {
			if k == "condition" {
				continue
			}
			if selPattern == "selection" && (k == "selection" || strings.HasPrefix(k, "selection_")) {
				c := parseSelection(v)
				if c != nil {
					children = append(children, *c)
				}
			} else if k == selPattern || strings.HasPrefix(k, selPattern+"_") {
				c := parseSelection(v)
				if c != nil {
					children = append(children, *c)
				}
			}
		}
		if len(children) == 0 {
			return nil
		}
		if len(children) == 1 {
			return &children[0]
		}
		return &detection.Condition{Op: "or", Children: children}
	}
	// single selection name
	if sel, ok := det[condStr]; ok {
		return parseSelection(sel)
	}
	return nil
}

// Compile converts a SigmaRule to detection.Rule.
func Compile(sr *SigmaRule) (*detection.Rule, error) {
	if sr.ID == "" || sr.Title == "" {
		return nil, nil
	}
	condVal, ok := sr.Detection["condition"]
	if !ok {
		return nil, nil
	}
	condStr, ok := condVal.(string)
	if !ok {
		return nil, nil
	}
	cond := parseCondition(sr.Detection, condStr)
	if cond == nil {
		return nil, nil
	}
	mitre := tagsToMitre(sr.Tags)
	return &detection.Rule{
		ID:       sr.ID,
		Name:     sr.Title,
		Severity: levelToSeverity(sr.Level),
		Cond:     *cond,
		Mitre:    mitre,
	}, nil
}

// LoadFile loads and compiles a single Sigma YAML file.
func LoadFile(path string) (*detection.Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sr SigmaRule
	if err := yaml.Unmarshal(data, &sr); err != nil {
		return nil, err
	}
	return Compile(&sr)
}

// RuleMeta is metadata for a Sigma rule (for API listing).
type RuleMeta struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Level  string `json:"level"`
	Status string `json:"status"`
	File   string `json:"file"`
}

// ListRuleMeta lists rule metadata from a directory without full compilation.
func ListRuleMeta(dir string) ([]RuleMeta, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []RuleMeta
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var sr SigmaRule
		if yaml.Unmarshal(data, &sr) != nil {
			continue
		}
		if sr.ID == "" {
			sr.ID = name
		}
		out = append(out, RuleMeta{
			ID:     sr.ID,
			Title:  sr.Title,
			Level:  sr.Level,
			Status: sr.Status,
			File:   name,
		})
	}
	return out, nil
}

// LoadDir loads all .yml/.yaml files from a directory and returns compiled rules.
func LoadDir(dir string) ([]detection.Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var rules []detection.Rule
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}
		path := filepath.Join(dir, name)
		r, err := LoadFile(path)
		if err != nil {
			continue // skip invalid rules
		}
		if r != nil {
			rules = append(rules, *r)
		}
	}
	return rules, nil
}
