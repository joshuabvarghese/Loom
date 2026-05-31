// Package config loads Loom's configuration from a TOML or YAML file,
// merging it with CLI flags (flags always win over file values).
//
// Search order (first found wins):
//  1. Path given by --config flag
//  2. ./loom.toml  or  ./loom.yaml
//  3. ~/.config/loom/config.toml  or  ~/.config/loom/config.yaml
//
// A missing file is not an error — Loom operates perfectly from flags alone.
//
// Example loom.toml:
//
//	listen      = ":9999"
//	backend     = "localhost:50051"
//	session     = "default"
//	ui          = ":9998"
//	verbose     = false
//	no_color    = false
//	backend_tls = false
//
//	[mutate]
//	  file = "/etc/loom/rules.json"
//
//	[log]
//	  file  = "/var/log/loom/calls.jsonl"
//	  level = "info"   # debug | info | warn | error
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// File mirrors the structure of loom.toml / loom.yaml.
// All fields are optional; zero values mean "defer to the CLI flag default".
type File struct {
	Listen               string `json:"listen"`
	Backend              string `json:"backend"`
	Session              string `json:"session"`
	UI                   string `json:"ui"`
	ProtoDir             string `json:"proto_dir"`
	ReplayFile           string `json:"replay"`
	Verbose              bool   `json:"verbose"`
	NoColor              bool   `json:"no_color"`
	BackendTLS           bool   `json:"backend_tls"`
	BackendTLSSkipVerify bool   `json:"backend_tls_skip_verify"`

	Mutate struct {
		File string `json:"file"`
	} `json:"mutate"`

	Log struct {
		File  string `json:"file"`
		Level string `json:"level"`
	} `json:"log"`
}

// Load reads a config file from path.  If path is empty, the default search
// locations are tried in order.  Returns a zero-value File (not an error)
// when no config file is found, so all-flag operation keeps working.
func Load(path string) (*File, error) {
	candidates := buildCandidates(path)
	for _, c := range candidates {
		if c == "" {
			continue
		}
		data, err := os.ReadFile(c)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("reading config %q: %w", c, err)
		}

		var f File
		ext := strings.ToLower(filepath.Ext(c))
		switch ext {
		case ".toml":
			if err := parseTOML(data, &f); err != nil {
				return nil, fmt.Errorf("parsing TOML config %q: %w", c, err)
			}
		case ".yaml", ".yml":
			if err := parseYAML(data, &f); err != nil {
				return nil, fmt.Errorf("parsing YAML config %q: %w", c, err)
			}
		default:
			// Fallback: try JSON (convenient for programmatic generation).
			if err := json.Unmarshal(data, &f); err != nil {
				return nil, fmt.Errorf("parsing config %q (unrecognized extension, tried JSON): %w", c, err)
			}
		}
		return &f, nil
	}
	return &File{}, nil // no file found — not an error
}

func buildCandidates(explicit string) []string {
	if explicit != "" {
		return []string{explicit}
	}
	home, _ := os.UserHomeDir()
	return []string{
		"loom.toml",
		"loom.yaml",
		filepath.Join(home, ".config", "loom", "config.toml"),
		filepath.Join(home, ".config", "loom", "config.yaml"),
	}
}

// ── minimal TOML subset parser ────────────────────────────────────────────────
// Handles the flat + one-level section structure that loom.toml requires.
// For full TOML spec compliance, swap in github.com/BurntSushi/toml.
func parseTOML(data []byte, f *File) error {
	section := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.Trim(strings.TrimSpace(parts[1]), `"`)

		fullKey := key
		if section != "" {
			fullKey = section + "." + key
		}
		applyField(f, fullKey, val)
	}
	return nil
}

// ── minimal YAML subset parser ────────────────────────────────────────────────
// Handles key: value and one-level indented sections.
// For full YAML spec compliance, swap in gopkg.in/yaml.v3.
func parseYAML(data []byte, f *File) error {
	section := ""
	for _, raw := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Section header: no leading spaces, ends with ":", no ": " (not a kv pair)
		if !strings.HasPrefix(raw, " ") && !strings.HasPrefix(raw, "\t") &&
			strings.HasSuffix(trimmed, ":") && !strings.Contains(trimmed, ": ") {
			section = strings.TrimSuffix(trimmed, ":")
			continue
		}
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		fullKey := key
		isIndented := strings.HasPrefix(raw, " ") || strings.HasPrefix(raw, "\t")
		if section != "" && isIndented {
			fullKey = section + "." + key
		} else {
			section = ""
		}
		applyField(f, fullKey, val)
	}
	return nil
}

func applyField(f *File, key, val string) {
	boolVal := strings.ToLower(val) == "true"
	switch key {
	case "listen":
		f.Listen = val
	case "backend":
		f.Backend = val
	case "session":
		f.Session = val
	case "ui":
		f.UI = val
	case "proto_dir":
		f.ProtoDir = val
	case "replay":
		f.ReplayFile = val
	case "verbose":
		f.Verbose = boolVal
	case "no_color":
		f.NoColor = boolVal
	case "backend_tls":
		f.BackendTLS = boolVal
	case "backend_tls_skip_verify":
		f.BackendTLSSkipVerify = boolVal
	case "mutate.file":
		f.Mutate.File = val
	case "log.file":
		f.Log.File = val
	case "log.level":
		f.Log.Level = val
	}
}
