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

type SessionInfo struct {
	Name  string
	Count int
}

type Store struct {
	sessionName string
	Recorder    *recorder.Recorder
	file        *os.File
	enc         *json.Encoder
}

func New(sessionName string) (*Store, error) {
	dir, err := sessionDir()
	if err != nil {
		return nil, err
	}

	path := filepath.Join(dir, sessionName+".jsonl")
	historical, _ := loadFile(path)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("opening session file %q: %w", path, err)
	}

	rec, err := recorder.New("") // persistence is handled here, not by the recorder's own log file
	if err != nil {
		f.Close()
		return nil, err
	}

	for _, cr := range historical {
		rec.Store.Add(cr)
	}

	s := &Store{
		sessionName: sessionName,
		Recorder:    rec,
		file:        f,
		enc:         json.NewEncoder(f),
	}

	ch := rec.Hub.Subscribe()
	go func() {
		for call := range ch {
			s.persist(call)
		}
	}()

	return s, nil
}

func (s *Store) SessionInfo() SessionInfo {
	return SessionInfo{
		Name:  s.sessionName,
		Count: len(s.Recorder.Store.All()),
	}
}

func (s *Store) Close() error {
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

func (s *Store) persist(call *recorder.CallRecord) {
	if s.enc != nil {
		_ = s.enc.Encode(call)
	}
}

func sessionDir() (string, error) {
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
		return nil, err // no session file yet is a normal first run, not an error the caller needs
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
			continue // corrupt line: skip it rather than fail the whole session load
		}
		records = append(records, &cr)
	}
	return records, scanner.Err()
}
