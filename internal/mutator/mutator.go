// Package mutator provides a rule-based JSON mutation engine for Loom.
//
// Rules are loaded from a JSON file (one object per line or a JSON array).
// Each rule specifies a method glob, a direction, and field overrides to apply.
//
// Example rules file (mutate.json):
//
//	[
//	  {
//	    "method": "/user.UserService/GetUser",
//	    "direction": "request",
//	    "set": {"userId": "injected-by-loom"}
//	  },
//	  {
//	    "method": "/user.UserService/*",
//	    "direction": "response",
//	    "delete": ["user.createdAt"]
//	  }
//	]
package mutator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Direction controls which side of the call a rule applies to.
type Direction string

const (
	DirRequest  Direction = "request"
	DirResponse Direction = "response"
	DirBoth     Direction = "both"
)

// Rule is a single mutation rule.
type Rule struct {
	// Method is an exact gRPC path or a glob (e.g. "/user.UserService/*").
	Method string `json:"method"`
	// Direction is "request", "response", or "both".
	Direction Direction `json:"direction"`
	// Set is a map of top-level JSON field names to new values.
	// Nested paths use dot notation: "user.name".
	Set map[string]json.RawMessage `json:"set,omitempty"`
	// Delete is a list of top-level (or dotted) field names to remove.
	Delete []string `json:"delete,omitempty"`
}

// Engine applies mutation rules to decoded JSON frames.
type Engine struct {
	rules []Rule
}

// NewEngine creates an Engine with no rules (pass-through).
func NewEngine() *Engine {
	return &Engine{}
}

// LoadRules creates an Engine from a rules file (JSON array or NDJSON).
func LoadRules(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading rules file %q: %w", path, err)
	}

	var rules []Rule
	// Try JSON array first
	if err := json.Unmarshal(data, &rules); err != nil {
		// Try NDJSON (one rule per line)
		rules = nil
		for i, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "//") {
				continue
			}
			var r Rule
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				return nil, fmt.Errorf("rules file line %d: %w", i+1, err)
			}
			rules = append(rules, r)
		}
	}

	return &Engine{rules: rules}, nil
}

// Apply runs all matching rules against the given JSON payload.
// It returns the (potentially modified) JSON and whether any mutation occurred.
// If no rules match or the payload is empty, the original is returned unchanged.
func (e *Engine) Apply(method string, dir Direction, jsonPayload string) (string, bool, error) {
	if len(e.rules) == 0 || jsonPayload == "" {
		return jsonPayload, false, nil
	}

	// Parse the payload into a generic map
	var doc map[string]any
	if err := json.Unmarshal([]byte(jsonPayload), &doc); err != nil {
		// Not a JSON object (e.g. scalar) — skip
		return jsonPayload, false, nil
	}

	mutated := false
	for _, rule := range e.rules {
		if !matchesMethod(rule.Method, method) {
			continue
		}
		if !matchesDirection(rule.Direction, dir) {
			continue
		}

		// Apply Set overrides
		for k, v := range rule.Set {
			if err := setNestedField(doc, k, v); err != nil {
				return jsonPayload, false, fmt.Errorf("rule set %q: %w", k, err)
			}
			mutated = true
		}

		// Apply Delete removals
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

// RuleCount returns the number of loaded rules.
func (e *Engine) RuleCount() int { return len(e.rules) }

// ─── Internal helpers ──────────────────────────────────────────────────────────

// matchesMethod supports exact match and simple glob (*).
func matchesMethod(pattern, method string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	// Glob: "/pkg.Service/*" matches any method in that service
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

// setNestedField sets a value at a dotted path in a generic JSON map.
// e.g. "user.name" → doc["user"]["name"] = value
func setNestedField(doc map[string]any, path string, value json.RawMessage) error {
	parts := strings.SplitN(path, ".", 2)
	key := parts[0]

	if len(parts) == 1 {
		// Leaf: decode the JSON value and set it
		var v any
		if err := json.Unmarshal(value, &v); err != nil {
			return fmt.Errorf("decoding value for %q: %w", path, err)
		}
		doc[key] = v
		return nil
	}

	// Intermediate node: ensure it's a map and recurse
	rest := parts[1]
	child, ok := doc[key]
	if !ok {
		child = map[string]any{}
		doc[key] = child
	}
	childMap, ok := child.(map[string]any)
	if !ok {
		// Replace non-map with a map
		childMap = map[string]any{}
		doc[key] = childMap
	}
	return setNestedField(childMap, rest, value)
}

// deleteNestedField removes a field at a dotted path.
func deleteNestedField(doc map[string]any, path string) {
	parts := strings.SplitN(path, ".", 2)
	key := parts[0]
	if len(parts) == 1 {
		delete(doc, key)
		return
	}
	child, ok := doc[key]
	if !ok {
		return
	}
	childMap, ok := child.(map[string]any)
	if !ok {
		return
	}
	deleteNestedField(childMap, parts[1])
}
