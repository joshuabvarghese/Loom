// Package slog provides structured JSON logging for Loom.
//
// Every log entry is a single-line JSON object written to stderr (or a
// configured writer). The "request_id" field is propagated through a
// context.Context so all log lines from a single proxied call share the
// same ID.
//
// Usage:
//
//	// At startup — set minimum level
//	slog.SetLevel(slog.LevelInfo)
//
//	// In ServeHTTP — attach a request ID
//	ctx := slog.WithRequestID(r.Context(), callID)
//
//	// Anywhere with the context
//	slog.Info(ctx, "forwarding call", "method", method, "backend", addr)
//	slog.Error(ctx, "backend unreachable", "err", err)
//
// Key-value pairs follow the slog convention: alternating string keys and
// arbitrary values. Errors are automatically converted to their string form.
package slog

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Level controls log verbosity.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "unknown"
	}
}

// ── global logger ─────────────────────────────────────────────────────────────

var global = &logger{
	w:     os.Stderr,
	level: LevelInfo,
}

type logger struct {
	mu    sync.Mutex
	w     io.Writer
	level Level
}

// SetLevel sets the minimum level for the global logger. Lines below this
// level are discarded without allocation.
func SetLevel(l Level) {
	global.mu.Lock()
	global.level = l
	global.mu.Unlock()
}

// SetWriter redirects log output. Useful in tests.
func SetWriter(w io.Writer) {
	global.mu.Lock()
	global.w = w
	global.mu.Unlock()
}

// ── context propagation ───────────────────────────────────────────────────────

type ctxKeyType struct{}

var ctxKey = ctxKeyType{}

// WithRequestID attaches id to ctx. All log calls made with the returned
// context include "request_id": id in their JSON output.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey, id)
}

// RequestID extracts the request ID from ctx, or returns "" if not set.
func RequestID(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKey).(string); ok {
		return v
	}
	return ""
}

// ── logging functions ─────────────────────────────────────────────────────────

// Debug logs at debug level.
func Debug(ctx context.Context, msg string, kv ...any) {
	global.log(ctx, LevelDebug, msg, kv)
}

// Info logs at info level.
func Info(ctx context.Context, msg string, kv ...any) {
	global.log(ctx, LevelInfo, msg, kv)
}

// Warn logs at warn level.
func Warn(ctx context.Context, msg string, kv ...any) {
	global.log(ctx, LevelWarn, msg, kv)
}

// Error logs at error level.
func Error(ctx context.Context, msg string, kv ...any) {
	global.log(ctx, LevelError, msg, kv)
}

func (l *logger) log(ctx context.Context, level Level, msg string, kv []any) {
	l.mu.Lock()
	minLevel := l.level
	l.mu.Unlock()

	if level < minLevel {
		return
	}

	entry := map[string]any{
		"time":  time.Now().UTC().Format(time.RFC3339Nano),
		"level": level.String(),
		"msg":   msg,
	}

	if id := RequestID(ctx); id != "" {
		entry["request_id"] = id
	}

	// Absorb key-value pairs: key must be a string, value is arbitrary.
	for i := 0; i+1 < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok {
			continue
		}
		v := kv[i+1]
		// Unwrap errors to their string form for clean JSON output.
		if err, isErr := v.(error); isErr {
			entry[k] = err.Error()
		} else {
			entry[k] = v
		}
	}

	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	line = append(line, '\n')

	l.mu.Lock()
	_, _ = l.w.Write(line)
	l.mu.Unlock()
}
