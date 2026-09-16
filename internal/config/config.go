package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

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

func Load(path string) (*File, error) {
	for _, c := range buildCandidates(path) {
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
		return parseConfigFile(c, data)
	}
	return &File{}, nil
}

func parseConfigFile(path string, data []byte) (*File, error) {
	var f File
	switch strings.ToLower(filepath.Ext(path)) {
	case ".toml":
		if err := parseTOML(data, &f); err != nil {
			return nil, fmt.Errorf("parsing TOML config %q: %w", path, err)
		}
	case ".yaml", ".yml":
		if err := parseYAML(data, &f); err != nil {
			return nil, fmt.Errorf("parsing YAML config %q: %w", path, err)
		}
	default:
		// Unrecognized extension: accept JSON too, for programmatic config generation.
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("parsing config %q (unrecognized extension, tried JSON): %w", path, err)
		}
	}
	return &f, nil
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

// Minimal hand-rolled subset covering only the flat + one-level-section
// shape loom.toml needs. Swap in github.com/BurntSushi/toml if full TOML
// spec compliance is ever required.
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
		applyField(f, qualifiedKey(section, key), val)
	}
	return nil
}

// Minimal hand-rolled subset covering only "key: value" plus one level of
// indented sections. Swap in gopkg.in/yaml.v3 if full YAML spec compliance
// is ever required.
func parseYAML(data []byte, f *File) error {
	section := ""
	for _, raw := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if isYAMLSectionHeader(raw, trimmed) {
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
		if section != "" && isIndentedLine(raw) {
			fullKey = qualifiedKey(section, key)
		} else {
			section = ""
		}
		applyField(f, fullKey, val)
	}
	return nil
}

func isYAMLSectionHeader(raw, trimmed string) bool {
	return !isIndentedLine(raw) && strings.HasSuffix(trimmed, ":") && !strings.Contains(trimmed, ": ")
}

func isIndentedLine(raw string) bool {
	return strings.HasPrefix(raw, " ") || strings.HasPrefix(raw, "\t")
}

func qualifiedKey(section, key string) string {
	if section == "" {
		return key
	}
	return section + "." + key
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
