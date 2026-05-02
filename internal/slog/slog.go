// Package slog provides structured JSON logging for Loom.
//
// Every log entry is a JSON object written to stderr (or a configured writer).
// The "request_id" field is propagated via context so all log lines from a
// single proxy call share the same ID.
//
// Usage:
//
//	// At startup
//	slog.SetLevel(slog.LevelDebug)
//
//	// In ServeHTTP — attach a request ID to the context
//	ctx := slog.WithRequestID(r.Context(), callID)
//
//	// Anywhere that has the context
//	slog.Info(ctx, "forwarding call", "method", method, "backend", addr)
//	slog.Error(ctx, "backend unreachable", "err", err)
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

// SetLevel sets the minimum level for the global logger.
func SetLevel(l Level) { global.level = l }

// SetWriter redirects log output (useful in tests).
func SetWriter(w io.Writer) {
	global.mu.Lock()
	global.w = w
	global.mu.Unlock()
}

// ── context key ───────────────────────────────────────────────────────────────

type ctxKey struct{}

// WithRequestID attaches a request ID to ctx. All log calls made with the
// returned context will include "request_id": id in their JSON output.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// RequestID retrieves the request ID from ctx, or "" if not set.
func RequestID(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKey{}).(string); ok {
		return v
	}
	return ""
}

// ── logging helpers ───────────────────────────────────────────────────────────

func Debug(ctx context.Context, msg string, kv ...any) { global.log(ctx, LevelDebug, msg, kv) }
func Info(ctx context.Context, msg string, kv ...any)  { global.log(ctx, LevelInfo, msg, kv) }
func Warn(ctx context.Context, msg string, kv ...any)  { global.log(ctx, LevelWarn, msg, kv) }
func Error(ctx context.Context, msg string, kv ...any) { global.log(ctx, LevelError, msg, kv) }

func (l *logger) log(ctx context.Context, level Level, msg string, kv []any) {
	if level < l.level {
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

	// Absorb key-value pairs: slog(ctx, "msg", "key", val, "key2", val2, ...)
	for i := 0; i+1 < len(kv); i += 2 {
		if k, ok := kv[i].(string); ok {
			v := kv[i+1]
			// Unwrap errors to their string representation for clean JSON.
			if err, ok := v.(error); ok {
				entry[k] = err.Error()
			} else {
				entry[k] = v
			}
		}
	}

	line, err := json.Marshal(entry)
	if err != nil {
		return // shouldn't happen
	}
	line = append(line, '\n')

	l.mu.Lock()
	_, _ = l.w.Write(line)
	l.mu.Unlock()
}
