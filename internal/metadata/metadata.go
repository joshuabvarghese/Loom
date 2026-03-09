// Package metadata provides header/gRPC-metadata mutation for Loom.
//
// It extends the mutator package by allowing rules to add, set, or delete
// gRPC request metadata (HTTP/2 headers). This is critical for testing:
//   - Expired or forged auth tokens
//   - Missing tracing headers
//   - Custom tenant IDs, feature flags, etc.
//
// Rule format (added to the same rules.json as body mutations):
//
//	{
//	  "method": "/user.UserService/*",
//	  "direction": "request",
//	  "headers": {
//	    "set":    {"authorization": "Bearer expired-token-for-testing"},
//	    "add":    {"x-custom-flag": "true"},
//	    "delete": ["x-forwarded-for"]
//	  }
//	}
//
// The "set" action replaces any existing value; "add" appends; "delete" removes.
package metadata

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// HeaderRule describes header mutations for one rule.
type HeaderRule struct {
	// Set replaces (or creates) a header value. Key is canonical HTTP header form.
	Set map[string]string `json:"set,omitempty"`
	// Add appends a value to a header (useful for multi-value headers).
	Add map[string]string `json:"add,omitempty"`
	// Delete removes headers by name.
	Delete []string `json:"delete,omitempty"`
}

// Rule is a single header mutation rule.
type Rule struct {
	// Method is an exact gRPC path or glob (e.g. "/pkg.Service/*").
	Method string `json:"method"`
	// Direction is "request", "response", or "both".
	Direction string `json:"direction"`
	// Headers contains the header mutations to apply.
	Headers HeaderRule `json:"headers"`
}

// Engine applies header mutation rules to HTTP headers.
type Engine struct {
	rules []Rule
}

// NewEngine creates an Engine with no rules (pass-through).
func NewEngine() *Engine { return &Engine{} }

// LoadRules loads header mutation rules from a JSON file.
// The file may be a JSON array of Rule objects, or NDJSON (one per line).
// Rules without a "headers" field are silently skipped.
func LoadRules(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading rules file %q: %w", path, err)
	}

	// We accept the same file format as the body mutator so a single
	// rules.json can contain both body and header rules.
	type rawRule struct {
		Method    string          `json:"method"`
		Direction string          `json:"direction"`
		Headers   *HeaderRule     `json:"headers,omitempty"`
		Set       json.RawMessage `json:"set,omitempty"`   // body rule field — ignored here
		Delete    json.RawMessage `json:"delete,omitempty"` // body rule field — ignored here
	}

	var raw []rawRule
	if err := json.Unmarshal(data, &raw); err != nil {
		// Try NDJSON
		raw = nil
		for i, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "//") {
				continue
			}
			var r rawRule
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				return nil, fmt.Errorf("rules file line %d: %w", i+1, err)
			}
			raw = append(raw, r)
		}
	}

	var rules []Rule
	for _, r := range raw {
		if r.Headers == nil {
			continue // not a header rule
		}
		rules = append(rules, Rule{
			Method:    r.Method,
			Direction: r.Direction,
			Headers:   *r.Headers,
		})
	}

	return &Engine{rules: rules}, nil
}

// Apply mutates the given http.Header according to matching rules.
// Returns true if any header was modified.
// direction should be "request" or "response".
func (e *Engine) Apply(method, direction string, h http.Header) bool {
	if len(e.rules) == 0 {
		return false
	}
	mutated := false
	for _, rule := range e.rules {
		if !matchesMethod(rule.Method, method) {
			continue
		}
		if !matchesDirection(rule.Direction, direction) {
			continue
		}

		// Set (replaces)
		for k, v := range rule.Headers.Set {
			h.Set(k, v)
			mutated = true
		}
		// Add (appends)
		for k, v := range rule.Headers.Add {
			h.Add(k, v)
			mutated = true
		}
		// Delete
		for _, k := range rule.Headers.Delete {
			h.Del(k)
			mutated = true
		}
	}
	return mutated
}

// RuleCount returns the number of loaded header rules.
func (e *Engine) RuleCount() int { return len(e.rules) }

// ─── helpers ──────────────────────────────────────────────────────────────────

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

func matchesDirection(ruleDir, callDir string) bool {
	if ruleDir == "both" || ruleDir == "" {
		return true
	}
	return ruleDir == callDir
}
