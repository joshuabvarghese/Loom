// Package store manages Loom's session persistence.
//
// A session is a named NDJSON file stored under ~/.loom/sessions/<name>.jsonl.
// On startup the file is read to restore historical calls; new calls are
// appended in real-time.
//
// The Store also wires together a Recorder (for live fan-out) and exposes
// session metadata (name, call count).
package store

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/joshuabvarghese/loom/internal/recorder"
)

// SessionInfo contains metadata about the current session.
type SessionInfo struct {
	Name  string
	Count int
}

// Store combines persistent NDJSON storage with a live Recorder.
type Store struct {
	path      string
	sessionName string
	Recorder  *recorder.Recorder
	file      *os.File
	enc       *json.Encoder
}

// New opens (or creates) the session file for sessionName and returns a Store.
// Historical calls are loaded into the in-memory ring buffer.
func New(sessionName string) (*Store, error) {
	dir, err := sessionDir()
	if err != nil {
		return nil, err
	}

	path := filepath.Join(dir, sessionName+".jsonl")

	// Load historical calls first
	historical, _ := loadFile(path) // ignore read errors on first run

	// Open file for appending
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("opening session file %q: %w", path, err)
	}

	rec, err := recorder.New("") // no extra log file; we handle persistence here
	if err != nil {
		f.Close()
		return nil, err
	}

	// Seed ring buffer with historical records
	for _, cr := range historical {
		rec.Store.Add(cr)
	}

	s := &Store{
		path:        path,
		sessionName: sessionName,
		Recorder:    rec,
		file:        f,
		enc:         json.NewEncoder(f),
	}

	// Tap into hub so every new call is also persisted
	ch := rec.Hub.Subscribe()
	go func() {
		for call := range ch {
			s.persist(call)
		}
	}()

	return s, nil
}

// SessionInfo returns metadata about the session.
func (s *Store) SessionInfo() SessionInfo {
	return SessionInfo{
		Name:  s.sessionName,
		Count: len(s.Recorder.Store.All()),
	}
}

// Close flushes and closes the underlying session file.
func (s *Store) Close() error {
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func (s *Store) persist(call *recorder.CallRecord) {
	if s.enc != nil {
		_ = s.enc.Encode(call)
	}
}

func sessionDir() (string, error) {
	// Allow override via env
	if d := os.Getenv("LOOM_DATA_DIR"); d != "" {
		if err := os.MkdirAll(d, 0755); err != nil {
			return "", fmt.Errorf("creating LOOM_DATA_DIR %q: %w", d, err)
		}
		return d, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("finding home directory: %w", err)
	}
	dir := filepath.Join(home, ".loom", "sessions")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("creating session directory: %w", err)
	}
	return dir, nil
}

func loadFile(path string) ([]*recorder.CallRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err // file doesn't exist yet — that's fine
	}
	defer f.Close()

	var records []*recorder.CallRecord
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var cr recorder.CallRecord
		if err := json.Unmarshal(line, &cr); err != nil {
			continue // skip malformed lines
		}
		records = append(records, &cr)
	}
	return records, scanner.Err()
}
