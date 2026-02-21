// Package detection provides rule evaluation for normalized events.
package detection

import (
	"encoding/json"
	"regexp"
	"strings"

	"edr-linux/pkg/events"
)

// Rule is a compiled detection rule.
type Rule struct {
	ID       string
	Name     string
	Severity string
	Cond     Condition
	Mitre    []string
}

// Condition is a tree of conditions (and/or with field comparisons).
type Condition struct {
	Op      string     `json:"op"` // "and", "or", or field op
	Field   string     `json:"field,omitempty"`
	Value   string     `json:"value,omitempty"`
	Children []Condition `json:"children,omitempty"`
}

// Eval evaluates the condition against event (as JSON-like map).
func (c *Condition) Eval(ev map[string]interface{}) bool {
	switch c.Op {
	case "and":
		for _, ch := range c.Children {
			if !ch.Eval(ev) {
				return false
			}
		}
		return true
	case "or":
		for _, ch := range c.Children {
			if ch.Eval(ev) {
				return true
			}
		}
		return false
	default:
		return evalField(ev, c.Field, c.Op, c.Value)
	}
}

func evalField(ev map[string]interface{}, field, op, value string) bool {
	v := getPath(ev, field)
	s, ok := v.(string)
	if !ok {
		return false
	}
	switch op {
	case "contains":
		return strings.Contains(s, value)
	case "endswith":
		return strings.HasSuffix(s, value)
	case "startswith":
		return strings.HasPrefix(s, value)
	case "eq", "equals":
		return s == value
	case "re", "regex":
		re, err := regexp.Compile(value)
		if err != nil {
			return false
		}
		return re.MatchString(s)
	default:
		return false
	}
}

func getPath(m map[string]interface{}, path string) interface{} {
	parts := strings.Split(path, ".")
	cur := interface{}(m)
	for _, p := range parts {
		if cur == nil {
			return nil
		}
		if m, ok := cur.(map[string]interface{}); ok {
			cur = m[p]
		}
	}
	return cur
}

// Engine evaluates rules against events.
type Engine struct {
	rules []Rule
}

// NewEngine creates a detection engine.
func NewEngine() *Engine {
	return &Engine{rules: nil}
}

// AddRule adds a rule.
func (e *Engine) AddRule(r Rule) {
	e.rules = append(e.rules, r)
}

// SetRules replaces all rules.
func (e *Engine) SetRules(rules []Rule) {
	e.rules = rules
}

// Eval evaluates all rules against the normalized event. Returns matching rules.
func (e *Engine) Eval(norm *events.NormalizedEvent) []Rule {
	var matched []Rule
	evMap := normToMap(norm)
	for _, r := range e.rules {
		if r.Cond.Eval(evMap) {
			matched = append(matched, r)
		}
	}
	return matched
}

func normToMap(n *events.NormalizedEvent) map[string]interface{} {
	b, _ := json.Marshal(n)
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	return m
}
