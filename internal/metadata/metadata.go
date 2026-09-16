package metadata

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type HeaderRule struct {
	Set    map[string]string `json:"set,omitempty"`
	Add    map[string]string `json:"add,omitempty"`
	Delete []string          `json:"delete,omitempty"`
}

type Rule struct {
	Method    string     `json:"method"`
	Direction string     `json:"direction"`
	Headers   HeaderRule `json:"headers"`
}

type Engine struct {
	rules []Rule
}

func NewEngine() *Engine { return &Engine{} }

func LoadRules(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading rules file %q: %w", path, err)
	}

	// Same file format as the body mutator, so one rules.json can hold both
	// body and header rules; the body-only fields are parsed and ignored.
	type rawRule struct {
		Method    string          `json:"method"`
		Direction string          `json:"direction"`
		Headers   *HeaderRule     `json:"headers,omitempty"`
		Set       json.RawMessage `json:"set,omitempty"`
		Delete    json.RawMessage `json:"delete,omitempty"`
	}

	var raw []rawRule
	if err := json.Unmarshal(data, &raw); err != nil {
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
			continue
		}
		rules = append(rules, Rule{
			Method:    r.Method,
			Direction: r.Direction,
			Headers:   *r.Headers,
		})
	}

	return &Engine{rules: rules}, nil
}

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

		for k, v := range rule.Headers.Set {
			h.Set(k, v)
			mutated = true
		}
		for k, v := range rule.Headers.Add {
			h.Add(k, v)
			mutated = true
		}
		for _, k := range rule.Headers.Delete {
			h.Del(k)
			mutated = true
		}
	}
	return mutated
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

func matchesDirection(ruleDir, callDir string) bool {
	if ruleDir == "both" || ruleDir == "" {
		return true
	}
	return ruleDir == callDir
}
