package metadata_test

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/joshuabvarghese/loom/internal/metadata"
)

// ─── LoadRules ────────────────────────────────────────────────────────────────

func TestLoadRules_JSONArray(t *testing.T) {
	t.Parallel()
	path := writeRules(t, `[{
		"method": "/svc/M",
		"direction": "request",
		"headers": {"set": {"authorization": "Bearer test"}}
	}]`)

	eng, err := metadata.LoadRules(path)
	if err != nil {
		t.Fatalf("LoadRules error: %v", err)
	}
	if eng.RuleCount() != 1 {
		t.Errorf("expected 1 rule, got %d", eng.RuleCount())
	}
}

func TestLoadRules_SkipsBodyOnlyRules(t *testing.T) {
	t.Parallel()
	// Rules with only "set"/"delete" (body rules) should be ignored
	path := writeRules(t, `[
		{"method": "/svc/M", "direction": "request", "set": {"foo": "bar"}},
		{"method": "/svc/M", "direction": "request", "headers": {"set": {"x-flag": "1"}}}
	]`)

	eng, _ := metadata.LoadRules(path)
	if eng.RuleCount() != 1 {
		t.Errorf("expected 1 header rule (body rule skipped), got %d", eng.RuleCount())
	}
}

func TestLoadRules_NDJSON(t *testing.T) {
	t.Parallel()
	path := writeRawRules(t,
		`{"method":"/a/B","direction":"request","headers":{"set":{"x-a":"1"}}}`+"\n"+
			`{"method":"/a/C","direction":"response","headers":{"delete":["x-b"]}}`+"\n",
	)
	eng, err := metadata.LoadRules(path)
	if err != nil {
		t.Fatalf("LoadRules NDJSON error: %v", err)
	}
	if eng.RuleCount() != 2 {
		t.Errorf("expected 2 rules, got %d", eng.RuleCount())
	}
}

func TestLoadRules_MissingFile(t *testing.T) {
	t.Parallel()
	_, err := metadata.LoadRules("/no/such/rules.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadRules_EmptyFile(t *testing.T) {
	t.Parallel()
	path := writeRules(t, `[]`)
	eng, err := metadata.LoadRules(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eng.RuleCount() != 0 {
		t.Errorf("expected 0 rules, got %d", eng.RuleCount())
	}
}

// ─── Apply — Set ──────────────────────────────────────────────────────────────

func TestApply_SetHeader(t *testing.T) {
	t.Parallel()
	eng := engine(t, `[{"method":"/svc/M","direction":"request","headers":{"set":{"authorization":"Bearer injected"}}}]`)

	h := make(http.Header)
	h.Set("Authorization", "Bearer original")

	changed := eng.Apply("/svc/M", "request", h)
	if !changed {
		t.Error("expected changed=true")
	}
	if got := h.Get("Authorization"); got != "Bearer injected" {
		t.Errorf("expected 'Bearer injected', got %q", got)
	}
}

func TestApply_SetCreatesNewHeader(t *testing.T) {
	t.Parallel()
	eng := engine(t, `[{"method":"/svc/M","direction":"request","headers":{"set":{"x-custom":"loom"}}}]`)

	h := make(http.Header)
	eng.Apply("/svc/M", "request", h)

	if got := h.Get("X-Custom"); got != "loom" {
		t.Errorf("expected x-custom=loom, got %q", got)
	}
}

// ─── Apply — Add ──────────────────────────────────────────────────────────────

func TestApply_AddHeader_AppendsValue(t *testing.T) {
	t.Parallel()
	eng := engine(t, `[{"method":"/svc/M","direction":"request","headers":{"add":{"x-feature":"beta"}}}]`)

	h := make(http.Header)
	h.Add("X-Feature", "alpha")

	eng.Apply("/svc/M", "request", h)

	vals := h["X-Feature"]
	if len(vals) != 2 {
		t.Errorf("expected 2 values for x-feature, got %v", vals)
	}
}

// ─── Apply — Delete ───────────────────────────────────────────────────────────

func TestApply_DeleteHeader(t *testing.T) {
	t.Parallel()
	eng := engine(t, `[{"method":"/svc/M","direction":"request","headers":{"delete":["x-forwarded-for"]}}]`)

	h := make(http.Header)
	h.Set("X-Forwarded-For", "192.168.1.1")
	h.Set("Content-Type", "application/grpc")

	eng.Apply("/svc/M", "request", h)

	if h.Get("X-Forwarded-For") != "" {
		t.Error("x-forwarded-for should have been deleted")
	}
	if h.Get("Content-Type") == "" {
		t.Error("content-type should be preserved")
	}
}

func TestApply_DeleteNonExistent_NoError(t *testing.T) {
	t.Parallel()
	eng := engine(t, `[{"method":"/svc/M","direction":"request","headers":{"delete":["x-ghost"]}}]`)

	h := make(http.Header)
	// Should not panic or error
	eng.Apply("/svc/M", "request", h)
}

// ─── Apply — Direction ────────────────────────────────────────────────────────

func TestApply_SkipsWrongDirection(t *testing.T) {
	t.Parallel()
	eng := engine(t, `[{"method":"/svc/M","direction":"response","headers":{"set":{"x-tag":"resp"}}}]`)

	h := make(http.Header)
	changed := eng.Apply("/svc/M", "request", h)
	if changed {
		t.Error("response rule should not apply to request direction")
	}
}

func TestApply_DirectionBoth(t *testing.T) {
	t.Parallel()
	eng := engine(t, `[{"method":"/svc/M","direction":"both","headers":{"set":{"x-tag":"both"}}}]`)

	for _, dir := range []string{"request", "response"} {
		h := make(http.Header)
		changed := eng.Apply("/svc/M", dir, h)
		if !changed {
			t.Errorf("direction=both should apply to %s", dir)
		}
	}
}

func TestApply_EmptyDirection_AppliesToBoth(t *testing.T) {
	t.Parallel()
	eng := engine(t, `[{"method":"/svc/M","headers":{"set":{"x-tag":"any"}}}]`)

	for _, dir := range []string{"request", "response"} {
		h := make(http.Header)
		changed := eng.Apply("/svc/M", dir, h)
		if !changed {
			t.Errorf("empty direction should apply to %s", dir)
		}
	}
}

// ─── Apply — Method matching ──────────────────────────────────────────────────

func TestApply_ExactMethodMatch(t *testing.T) {
	t.Parallel()
	eng := engine(t, `[{"method":"/svc/Method","direction":"request","headers":{"set":{"x":"1"}}}]`)

	h := make(http.Header)
	if !eng.Apply("/svc/Method", "request", h) {
		t.Error("exact match should fire")
	}
}

func TestApply_GlobMatch(t *testing.T) {
	t.Parallel()
	eng := engine(t, `[{"method":"/svc/*","direction":"request","headers":{"set":{"x":"glob"}}}]`)

	for _, m := range []string{"/svc/A", "/svc/B", "/svc/GetUser"} {
		h := make(http.Header)
		if !eng.Apply(m, "request", h) {
			t.Errorf("glob /svc/* should match %s", m)
		}
	}
}

func TestApply_NoMatch_NoChange(t *testing.T) {
	t.Parallel()
	eng := engine(t, `[{"method":"/svc/M","direction":"request","headers":{"set":{"x":"1"}}}]`)

	h := make(http.Header)
	if eng.Apply("/other/Method", "request", h) {
		t.Error("should not match /other/Method")
	}
}

// ─── Apply — No rules ─────────────────────────────────────────────────────────

func TestApply_NoRules_NoChange(t *testing.T) {
	t.Parallel()
	eng := metadata.NewEngine()

	h := make(http.Header)
	h.Set("Authorization", "Bearer original")
	if eng.Apply("/svc/M", "request", h) {
		t.Error("engine with no rules should not mutate")
	}
	if h.Get("Authorization") != "Bearer original" {
		t.Error("header should be unchanged")
	}
}

// ─── Apply — Combined ─────────────────────────────────────────────────────────

func TestApply_SetAddDelete_Together(t *testing.T) {
	t.Parallel()
	eng := engine(t, `[{
		"method": "/svc/M",
		"direction": "request",
		"headers": {
			"set":    {"authorization": "Bearer new"},
			"add":    {"x-trace": "loom-123"},
			"delete": ["x-internal"]
		}
	}]`)

	h := make(http.Header)
	h.Set("Authorization", "Bearer old")
	h.Set("X-Internal", "secret")

	eng.Apply("/svc/M", "request", h)

	if h.Get("Authorization") != "Bearer new" {
		t.Errorf("authorization not set: %s", h.Get("Authorization"))
	}
	if h.Get("X-Trace") != "loom-123" {
		t.Errorf("x-trace not added: %s", h.Get("X-Trace"))
	}
	if h.Get("X-Internal") != "" {
		t.Error("x-internal should be deleted")
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func writeRules(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	os.WriteFile(path, []byte(content), 0644)
	return path
}

func writeRawRules(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.ndjson")
	os.WriteFile(path, []byte(content), 0644)
	return path
}

func engine(t *testing.T, rulesJSON string) *metadata.Engine {
	t.Helper()
	path := writeRules(t, rulesJSON)
	eng, err := metadata.LoadRules(path)
	if err != nil {
		t.Fatalf("engine(): %v", err)
	}
	return eng
}
