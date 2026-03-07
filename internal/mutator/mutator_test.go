package mutator_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/joshuabvarghese/loom/internal/mutator"
)

// ─── LoadRules Tests ───────────────────────────────────────────────────────────

func TestLoadRules_JSONArray(t *testing.T) {
	t.Parallel()
	path := writeTempRules(t, `[
		{"method": "/svc/Method", "direction": "request", "set": {"foo": "bar"}}
	]`)

	eng, err := mutator.LoadRules(path)
	if err != nil {
		t.Fatalf("LoadRules error: %v", err)
	}
	if eng.RuleCount() != 1 {
		t.Errorf("expected 1 rule, got %d", eng.RuleCount())
	}
}

func TestLoadRules_NDJSONFormat(t *testing.T) {
	t.Parallel()
	path := writeTempRulesRaw(t,
		`{"method": "/svc/A", "direction": "request", "set": {"x": 1}}`+"\n"+
			`{"method": "/svc/B", "direction": "response", "delete": ["field"]}`+"\n",
	)

	eng, err := mutator.LoadRules(path)
	if err != nil {
		t.Fatalf("LoadRules NDJSON error: %v", err)
	}
	if eng.RuleCount() != 2 {
		t.Errorf("expected 2 rules, got %d", eng.RuleCount())
	}
}

func TestLoadRules_MissingFile(t *testing.T) {
	t.Parallel()
	_, err := mutator.LoadRules("/no/such/file.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadRules_MalformedJSON(t *testing.T) {
	t.Parallel()
	path := writeTempRulesRaw(t, `{this is not valid json}`)
	_, err := mutator.LoadRules(path)
	if err == nil {
		t.Error("expected error for malformed JSON")
	}
}

func TestLoadRules_EmptyRulesFile(t *testing.T) {
	t.Parallel()
	path := writeTempRules(t, `[]`)
	eng, err := mutator.LoadRules(path)
	if err != nil {
		t.Fatalf("LoadRules error: %v", err)
	}
	if eng.RuleCount() != 0 {
		t.Errorf("expected 0 rules, got %d", eng.RuleCount())
	}
}

func TestLoadRules_IgnoresBlankAndCommentLines(t *testing.T) {
	t.Parallel()
	path := writeTempRulesRaw(t,
		"\n"+
			"// this is a comment\n"+
			`{"method": "/svc/M", "direction": "request", "set": {"a": 1}}`+"\n"+
			"\n",
	)
	eng, err := mutator.LoadRules(path)
	if err != nil {
		t.Fatalf("LoadRules error: %v", err)
	}
	if eng.RuleCount() != 1 {
		t.Errorf("expected 1 rule, got %d", eng.RuleCount())
	}
}

// ─── Engine.Apply — Set Tests ─────────────────────────────────────────────────

func TestApply_SetTopLevelField(t *testing.T) {
	t.Parallel()
	eng := engineWithRule(t, `[{
		"method": "/svc/M", "direction": "request",
		"set": {"userId": "injected"}
	}]`)

	out, changed, err := eng.Apply("/svc/M", mutator.DirRequest, `{"userId": "original"}`)
	assertNoError(t, err)
	if !changed {
		t.Error("expected mutation to be detected")
	}
	assertJSONField(t, out, "userId", "injected")
}

func TestApply_SetNestedField(t *testing.T) {
	t.Parallel()
	eng := engineWithRule(t, `[{
		"method": "/svc/M", "direction": "request",
		"set": {"user.name": "Bob"}
	}]`)

	out, changed, err := eng.Apply("/svc/M", mutator.DirRequest, `{"user": {"name": "Alice", "age": 30}}`)
	assertNoError(t, err)
	if !changed {
		t.Error("expected changed=true")
	}
	// Parse the nested field
	var doc map[string]any
	json.Unmarshal([]byte(out), &doc)
	user := doc["user"].(map[string]any)
	if user["name"] != "Bob" {
		t.Errorf("nested set failed: user.name=%v", user["name"])
	}
	if user["age"] != float64(30) {
		t.Errorf("sibling field should be preserved: user.age=%v", user["age"])
	}
}

func TestApply_SetCreatesIntermediateObject(t *testing.T) {
	t.Parallel()
	eng := engineWithRule(t, `[{
		"method": "/svc/M", "direction": "request",
		"set": {"meta.source": "loom"}
	}]`)

	out, changed, err := eng.Apply("/svc/M", mutator.DirRequest, `{"id": "x"}`)
	assertNoError(t, err)
	if !changed {
		t.Error("expected changed=true for new field creation")
	}
	var doc map[string]any
	json.Unmarshal([]byte(out), &doc)
	meta, ok := doc["meta"].(map[string]any)
	if !ok || meta["source"] != "loom" {
		t.Errorf("intermediate object not created: meta=%v", doc["meta"])
	}
}

// ─── Engine.Apply — Delete Tests ─────────────────────────────────────────────

func TestApply_DeleteTopLevelField(t *testing.T) {
	t.Parallel()
	eng := engineWithRule(t, `[{
		"method": "/svc/M", "direction": "response",
		"delete": ["secret"]
	}]`)

	out, changed, err := eng.Apply("/svc/M", mutator.DirResponse, `{"id": "1", "secret": "topsecret"}`)
	assertNoError(t, err)
	if !changed {
		t.Error("expected changed=true")
	}
	var doc map[string]any
	json.Unmarshal([]byte(out), &doc)
	if _, has := doc["secret"]; has {
		t.Error("field 'secret' should have been deleted")
	}
	if doc["id"] != "1" {
		t.Error("sibling field 'id' should be preserved")
	}
}

func TestApply_DeleteNestedField(t *testing.T) {
	t.Parallel()
	eng := engineWithRule(t, `[{
		"method": "/svc/M", "direction": "response",
		"delete": ["user.email"]
	}]`)

	out, _, err := eng.Apply("/svc/M", mutator.DirResponse, `{"user": {"name": "Ada", "email": "ada@example.com"}}`)
	assertNoError(t, err)
	var doc map[string]any
	json.Unmarshal([]byte(out), &doc)
	user := doc["user"].(map[string]any)
	if _, has := user["email"]; has {
		t.Error("user.email should have been deleted")
	}
	if user["name"] != "Ada" {
		t.Error("user.name should be preserved")
	}
}

func TestApply_DeleteNonExistentField_NoError(t *testing.T) {
	t.Parallel()
	eng := engineWithRule(t, `[{
		"method": "/svc/M", "direction": "request",
		"delete": ["doesNotExist"]
	}]`)

	// Should not error or panic even if field doesn't exist
	_, _, err := eng.Apply("/svc/M", mutator.DirRequest, `{"foo": "bar"}`)
	if err != nil {
		t.Errorf("unexpected error deleting missing field: %v", err)
	}
}

// ─── Engine.Apply — Direction Matching ────────────────────────────────────────

func TestApply_SkipsWrongDirection(t *testing.T) {
	t.Parallel()
	eng := engineWithRule(t, `[{
		"method": "/svc/M", "direction": "response",
		"set": {"injected": true}
	}]`)

	out, changed, err := eng.Apply("/svc/M", mutator.DirRequest, `{"foo": "bar"}`)
	assertNoError(t, err)
	if changed {
		t.Error("rule with direction=response should not apply to request")
	}
	if out != `{"foo": "bar"}` {
		t.Errorf("payload should be unchanged: %s", out)
	}
}

func TestApply_DirectionBoth_AppliesToRequest(t *testing.T) {
	t.Parallel()
	eng := engineWithRule(t, `[{
		"method": "/svc/M", "direction": "both",
		"set": {"tag": "loom"}
	}]`)

	_, changed, _ := eng.Apply("/svc/M", mutator.DirRequest, `{"x": 1}`)
	if !changed {
		t.Error("direction=both should apply to request")
	}
}

func TestApply_DirectionBoth_AppliesToResponse(t *testing.T) {
	t.Parallel()
	eng := engineWithRule(t, `[{
		"method": "/svc/M", "direction": "both",
		"set": {"tag": "loom"}
	}]`)

	_, changed, _ := eng.Apply("/svc/M", mutator.DirResponse, `{"x": 1}`)
	if !changed {
		t.Error("direction=both should apply to response")
	}
}

// ─── Engine.Apply — Method Matching ──────────────────────────────────────────

func TestApply_ExactMethodMatch(t *testing.T) {
	t.Parallel()
	eng := engineWithRule(t, `[{
		"method": "/svc/Method", "direction": "request",
		"set": {"x": 1}
	}]`)

	_, changed, _ := eng.Apply("/svc/Method", mutator.DirRequest, `{}`)
	if !changed {
		t.Error("exact method match should apply")
	}
}

func TestApply_ExactMethodNoMatch(t *testing.T) {
	t.Parallel()
	eng := engineWithRule(t, `[{
		"method": "/svc/Method", "direction": "request",
		"set": {"x": 1}
	}]`)

	_, changed, _ := eng.Apply("/svc/OtherMethod", mutator.DirRequest, `{}`)
	if changed {
		t.Error("exact method should not match a different path")
	}
}

func TestApply_GlobMethodMatch(t *testing.T) {
	t.Parallel()
	eng := engineWithRule(t, `[{
		"method": "/svc/*", "direction": "request",
		"set": {"tag": "glob"}
	}]`)

	for _, method := range []string{"/svc/A", "/svc/B", "/svc/GetUser"} {
		_, changed, _ := eng.Apply(method, mutator.DirRequest, `{}`)
		if !changed {
			t.Errorf("glob /svc/* should match %s", method)
		}
	}
}

func TestApply_GlobDoesNotMatchOtherService(t *testing.T) {
	t.Parallel()
	eng := engineWithRule(t, `[{
		"method": "/svc/*", "direction": "request",
		"set": {"tag": "glob"}
	}]`)

	_, changed, _ := eng.Apply("/other/Method", mutator.DirRequest, `{}`)
	if changed {
		t.Error("glob /svc/* should not match /other/Method")
	}
}

func TestApply_WildcardMethodMatchesAll(t *testing.T) {
	t.Parallel()
	eng := engineWithRule(t, `[{
		"method": "*", "direction": "request",
		"set": {"universal": true}
	}]`)

	_, changed, _ := eng.Apply("/anything/Goes", mutator.DirRequest, `{}`)
	if !changed {
		t.Error("method=* should match any path")
	}
}

// ─── Engine.Apply — Edge Cases ────────────────────────────────────────────────

func TestApply_EmptyPayload_NoChange(t *testing.T) {
	t.Parallel()
	eng := engineWithRule(t, `[{
		"method": "/svc/M", "direction": "request",
		"set": {"x": 1}
	}]`)

	out, changed, err := eng.Apply("/svc/M", mutator.DirRequest, "")
	assertNoError(t, err)
	if changed {
		t.Error("empty payload should not be changed")
	}
	if out != "" {
		t.Errorf("expected empty output, got: %s", out)
	}
}

func TestApply_NoRules_PassThrough(t *testing.T) {
	t.Parallel()
	eng := mutator.NewEngine()

	payload := `{"hello": "world"}`
	out, changed, err := eng.Apply("/svc/M", mutator.DirRequest, payload)
	assertNoError(t, err)
	if changed {
		t.Error("engine with no rules should not mutate")
	}
	if out != payload {
		t.Errorf("payload should be unchanged: %s", out)
	}
}

func TestApply_NonJSONPayload_PassThrough(t *testing.T) {
	t.Parallel()
	eng := engineWithRule(t, `[{"method": "/svc/M", "direction": "request", "set": {"x": 1}}]`)

	payload := "not json at all"
	out, changed, _ := eng.Apply("/svc/M", mutator.DirRequest, payload)
	if changed {
		t.Error("non-JSON payload should not be changed")
	}
	if out != payload {
		t.Errorf("non-JSON payload should be returned unchanged: %s", out)
	}
}

func TestApply_MultipleRulesApplied(t *testing.T) {
	t.Parallel()
	path := writeTempRules(t, `[
		{"method": "/svc/M", "direction": "request", "set": {"a": "from-rule-1"}},
		{"method": "/svc/M", "direction": "request", "set": {"b": "from-rule-2"}}
	]`)
	eng, _ := mutator.LoadRules(path)

	out, changed, _ := eng.Apply("/svc/M", mutator.DirRequest, `{}`)
	if !changed {
		t.Error("at least one rule should have fired")
	}
	assertJSONField(t, out, "a", "from-rule-1")
	assertJSONField(t, out, "b", "from-rule-2")
}

func TestRuleCount_ReflectsLoadedRules(t *testing.T) {
	t.Parallel()
	eng := mutator.NewEngine()
	if eng.RuleCount() != 0 {
		t.Errorf("new engine should have 0 rules, got %d", eng.RuleCount())
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func writeTempRules(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writeTempRules: %v", err)
	}
	return path
}

func writeTempRulesRaw(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.ndjson")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writeTempRulesRaw: %v", err)
	}
	return path
}

func engineWithRule(t *testing.T, rulesJSON string) *mutator.Engine {
	t.Helper()
	path := writeTempRules(t, rulesJSON)
	eng, err := mutator.LoadRules(path)
	if err != nil {
		t.Fatalf("engineWithRule: %v", err)
	}
	return eng
}

func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func assertJSONField(t *testing.T, jsonStr, key, wantVal string) {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &doc); err != nil {
		t.Fatalf("assertJSONField: invalid JSON %q: %v", jsonStr, err)
	}
	got, ok := doc[key]
	if !ok {
		t.Fatalf("assertJSONField: key %q not found in %s", key, jsonStr)
	}
	if fmt.Sprintf("%v", got) != wantVal {
		t.Errorf("field %q: got %v, want %s", key, got, wantVal)
	}
}
