package mutator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Direction string

const (
	DirRequest  Direction = "request"
	DirResponse Direction = "response"
	DirBoth     Direction = "both"
)

type Rule struct {
	Method    string                     `json:"method"`
	Direction Direction                  `json:"direction"`
	Set       map[string]json.RawMessage `json:"set,omitempty"`
	Delete    []string                   `json:"delete,omitempty"`
}

type Engine struct {
	rules []Rule
}

func NewEngine() *Engine {
	return &Engine{}
}

func LoadRules(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading rules file %q: %w", path, err)
	}
	return LoadRulesFromBytes(data)
}

func LoadRulesFromBytes(data []byte) (*Engine, error) {
	rules, err := parseRules(data)
	if err != nil {
		return nil, err
	}
	return &Engine{rules: rules}, nil
}

func parseRules(data []byte) ([]Rule, error) {
	var rules []Rule
	if err := json.Unmarshal(data, &rules); err == nil {
		return rules, nil
	}

	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		var r Rule
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("rules line %d: %w", i+1, err)
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func (e *Engine) Apply(method string, dir Direction, jsonPayload string) (string, bool, error) {
	if len(e.rules) == 0 || jsonPayload == "" {
		return jsonPayload, false, nil
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(jsonPayload), &doc); err != nil {
		return jsonPayload, false, nil // not a JSON object (e.g. a scalar) — nothing to mutate
	}

	mutated := false
	for _, rule := range e.rules {
		if !matchesMethod(rule.Method, method) {
			continue
		}
		if !matchesDirection(rule.Direction, dir) {
			continue
		}

		for k, v := range rule.Set {
			if err := setNestedField(doc, k, v); err != nil {
				return jsonPayload, false, fmt.Errorf("rule set %q: %w", k, err)
			}
			mutated = true
		}
		for _, k := range rule.Delete {
			deleteNestedField(doc, k)
			mutated = true
		}
	}

	if !mutated {
		return jsonPayload, false, nil
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return jsonPayload, false, fmt.Errorf("re-marshaling mutated payload: %w", err)
	}
	return string(out), true, nil
}

func (e *Engine) RuleCount() int { return len(e.rules) }

func matchesMethod(pattern, method string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	matched, err := filepath.Match(pattern, method)
	if err != nil {
		return pattern == method
	}
	return matched
}

func matchesDirection(ruleDir, callDir Direction) bool {
	if ruleDir == DirBoth || ruleDir == "" {
		return true
	}
	return ruleDir == callDir
}

// path uses dot notation, e.g. "user.name" -> doc["user"]["name"].
func setNestedField(doc map[string]any, path string, value json.RawMessage) error {
	parts := strings.SplitN(path, ".", 2)
	key := parts[0]

	if len(parts) == 1 {
		var v any
		if err := json.Unmarshal(value, &v); err != nil {
			return fmt.Errorf("decoding value for %q: %w", path, err)
		}
		doc[key] = v
		return nil
	}

	child, ok := doc[key].(map[string]any)
	if !ok {
		child = map[string]any{}
		doc[key] = child
	}
	return setNestedField(child, parts[1], value)
}

func deleteNestedField(doc map[string]any, path string) {
	parts := strings.SplitN(path, ".", 2)
	key := parts[0]
	if len(parts) == 1 {
		delete(doc, key)
		return
	}
	child, ok := doc[key].(map[string]any)
	if !ok {
		return
	}
	deleteNestedField(child, parts[1])
}
