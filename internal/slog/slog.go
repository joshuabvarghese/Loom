package slog

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

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

var global = &logger{
	w:     os.Stderr,
	level: LevelInfo,
}

type logger struct {
	mu    sync.Mutex
	w     io.Writer
	level Level
}

func SetLevel(l Level) {
	global.mu.Lock()
	global.level = l
	global.mu.Unlock()
}

func SetWriter(w io.Writer) {
	global.mu.Lock()
	global.w = w
	global.mu.Unlock()
}

type ctxKeyType struct{}

var ctxKey = ctxKeyType{}

func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey, id)
}

func RequestID(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKey).(string); ok {
		return v
	}
	return ""
}

func Debug(ctx context.Context, msg string, kv ...any) {
	global.log(ctx, LevelDebug, msg, kv)
}

func Info(ctx context.Context, msg string, kv ...any) {
	global.log(ctx, LevelInfo, msg, kv)
}

func Warn(ctx context.Context, msg string, kv ...any) {
	global.log(ctx, LevelWarn, msg, kv)
}

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

	// A trailing key with no value is dropped rather than erroring.
	for i := 0; i+1 < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok {
			continue
		}
		entry[k] = stringifyIfError(kv[i+1])
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

func stringifyIfError(v any) any {
	if err, ok := v.(error); ok {
		return err.Error()
	}
	return v
}
