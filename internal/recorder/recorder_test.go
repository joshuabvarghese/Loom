package recorder_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/joshuabvarghese/loom/internal/recorder"
)

// ─── Store Tests ──────────────────────────────────────────────────────────────

func TestStore_EmptyOnCreate(t *testing.T) {
	t.Parallel()
	s := recorder.NewStore(10)
	got := s.All()
	if len(got) != 0 {
		t.Fatalf("new store should be empty, got %d records", len(got))
	}
}

func TestStore_AddAndRetrieve(t *testing.T) {
	t.Parallel()
	s := recorder.NewStore(10)
	s.Add(makeCall("a"))
	s.Add(makeCall("b"))
	s.Add(makeCall("c"))

	all := s.All()
	if len(all) != 3 {
		t.Fatalf("expected 3 records, got %d", len(all))
	}
}

func TestStore_AllReturnsNewestFirst(t *testing.T) {
	t.Parallel()
	s := recorder.NewStore(10)
	s.Add(makeCall("first"))
	s.Add(makeCall("second"))
	s.Add(makeCall("third"))

	all := s.All()
	if all[0].ID != "third" {
		t.Errorf("All() should return newest first; got %s", all[0].ID)
	}
	if all[2].ID != "first" {
		t.Errorf("All() last element should be oldest; got %s", all[2].ID)
	}
}

func TestStore_RingEvictsOldest(t *testing.T) {
	t.Parallel()
	const max = 3
	s := recorder.NewStore(max)

	for i := 1; i <= 5; i++ {
		s.Add(makeCall(fmt.Sprintf("%d", i)))
	}

	all := s.All()
	if len(all) != max {
		t.Fatalf("expected ring buffer to cap at %d, got %d", max, len(all))
	}
	// Should contain calls 3,4,5 (1 and 2 evicted)
	ids := map[string]bool{}
	for _, r := range all {
		ids[r.ID] = true
	}
	for _, want := range []string{"3", "4", "5"} {
		if !ids[want] {
			t.Errorf("expected call %q to survive eviction", want)
		}
	}
}

func TestStore_DefaultCapacityNonZero(t *testing.T) {
	t.Parallel()
	s := recorder.NewStore(0) // 0 → use default
	// Add more than 0 and make sure it doesn't panic
	for i := 0; i < 10; i++ {
		s.Add(makeCall(fmt.Sprintf("d%d", i)))
	}
	if len(s.All()) == 0 {
		t.Error("store with 0 capacity should use a positive default")
	}
}

func TestStore_ByID_Found(t *testing.T) {
	t.Parallel()
	s := recorder.NewStore(0)
	s.Add(makeCall("target"))
	s.Add(makeCall("other"))

	r, ok := s.ByID("target")
	if !ok {
		t.Fatal("ByID should find existing call")
	}
	if r.ID != "target" {
		t.Errorf("expected id=target, got %s", r.ID)
	}
}

func TestStore_ByID_NotFound(t *testing.T) {
	t.Parallel()
	s := recorder.NewStore(0)
	s.Add(makeCall("present"))

	_, ok := s.ByID("absent")
	if ok {
		t.Error("ByID should return false for missing id")
	}
}

func TestStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	s := recorder.NewStore(200)
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s.Add(makeCall(fmt.Sprintf("c%d", n)))
		}(i)
	}
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.All()
		}()
	}
	wg.Wait() // must not race or deadlock
}

// ─── StreamKind Constants ──────────────────────────────────────────────────────

func TestStreamKind_Values(t *testing.T) {
	t.Parallel()
	cases := []struct {
		kind recorder.StreamKind
		want string
	}{
		{recorder.StreamUnary, "unary"},
		{recorder.StreamServer, "server_streaming"},
		{recorder.StreamClient, "client_streaming"},
		{recorder.StreamBidi, "bidi_streaming"},
	}
	for _, tc := range cases {
		if string(tc.kind) != tc.want {
			t.Errorf("StreamKind %q: expected %q", tc.kind, tc.want)
		}
	}
}

// ─── EventHub Tests ───────────────────────────────────────────────────────────

func TestEventHub_PublishReachesSubscriber(t *testing.T) {
	t.Parallel()
	h := recorder.NewEventHub()
	ch := h.Subscribe()
	defer h.Unsubscribe(ch)

	h.Publish(makeCall("hub-1"))

	select {
	case got := <-ch:
		if got.ID != "hub-1" {
			t.Errorf("expected id=hub-1, got %s", got.ID)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timed out waiting for event")
	}
}

func TestEventHub_BroadcastsToAllSubscribers(t *testing.T) {
	t.Parallel()
	h := recorder.NewEventHub()
	ch1 := h.Subscribe()
	ch2 := h.Subscribe()
	ch3 := h.Subscribe()
	defer h.Unsubscribe(ch1)
	defer h.Unsubscribe(ch2)
	defer h.Unsubscribe(ch3)

	h.Publish(makeCall("bcast"))

	for i, ch := range []chan *recorder.CallRecord{ch1, ch2, ch3} {
		select {
		case got := <-ch:
			if got.ID != "bcast" {
				t.Errorf("ch%d: expected bcast, got %s", i+1, got.ID)
			}
		case <-time.After(200 * time.Millisecond):
			t.Fatalf("ch%d: timed out", i+1)
		}
	}
}

func TestEventHub_UnsubscribeClosesChannel(t *testing.T) {
	t.Parallel()
	h := recorder.NewEventHub()
	ch := h.Subscribe()
	h.Unsubscribe(ch)

	_, open := <-ch
	if open {
		t.Error("channel should be closed after Unsubscribe")
	}
}

func TestEventHub_SlowSubscriberDoesNotBlock(t *testing.T) {
	t.Parallel()
	h := recorder.NewEventHub()
	ch := h.Subscribe()
	defer h.Unsubscribe(ch)

	// Flood beyond the channel buffer without reading
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			h.Publish(makeCall(fmt.Sprintf("flood-%d", i)))
		}
		close(done)
	}()

	select {
	case <-done:
		// success — no deadlock
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on slow subscriber")
	}
}

// ─── Recorder Tests ───────────────────────────────────────────────────────────

func TestRecorder_New_NoLogFile(t *testing.T) {
	t.Parallel()
	rec, err := recorder.New("")
	if err != nil {
		t.Fatalf("New() with empty path should not error: %v", err)
	}
	if rec.Store == nil {
		t.Error("Store should be initialised")
	}
	if rec.Hub == nil {
		t.Error("Hub should be initialised")
	}
	_ = rec.Close()
}

func TestRecorder_New_BadPath(t *testing.T) {
	t.Parallel()
	_, err := recorder.New("/nonexistent/directory/loom.ndjson")
	if err == nil {
		t.Error("expected error when log directory does not exist")
	}
}

func TestRecorder_Record_FanoutToStoreAndHub(t *testing.T) {
	t.Parallel()
	rec, _ := recorder.New("")
	defer rec.Close()

	ch := rec.Hub.Subscribe()
	defer rec.Hub.Unsubscribe(ch)

	rec.Record(makeCall("fanout"))

	// Store
	if len(rec.Store.All()) != 1 {
		t.Error("record should appear in store")
	}
	// Hub
	select {
	case got := <-ch:
		if got.ID != "fanout" {
			t.Errorf("hub: expected fanout, got %s", got.ID)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("hub: timed out")
	}
}

func TestRecorder_Record_WritesNDJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "calls.ndjson")

	rec, err := recorder.New(path)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	rec.Record(makeCall("line-1"))
	rec.Record(makeCall("line-2"))
	if err := rec.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}

	records, err := recorder.ReadNDJSON(path)
	if err != nil {
		t.Fatalf("ReadNDJSON error: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 log lines, got %d", len(records))
	}
	if records[0].ID != "line-1" || records[1].ID != "line-2" {
		t.Errorf("unexpected log order: %s, %s", records[0].ID, records[1].ID)
	}
}

func TestRecorder_NDJSON_IsValidJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "valid.ndjson")

	rec, _ := recorder.New(path)
	rec.Record(&recorder.CallRecord{
		ID:         "json-valid",
		Timestamp:  time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		Method:     "/pkg.Svc/Method",
		StreamKind: recorder.StreamUnary,
		StatusCode: "0",
		StatusName: "OK (0)",
		DurationMs: 3.14,
	})
	rec.Close()

	data, _ := os.ReadFile(path)
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Errorf("line %d is not valid JSON: %v\n%s", i, err, line)
		}
	}
}

func TestRecorder_ConcurrentRecord(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "concurrent.ndjson")

	rec, _ := recorder.New(path)
	defer rec.Close()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			rec.Record(makeCall(fmt.Sprintf("c%d", n)))
		}(i)
	}
	wg.Wait()
	// No race — recorder must serialize writes
}

// ─── ReadNDJSON Tests ──────────────────────────────────────────────────────────

func TestReadNDJSON_MissingFile(t *testing.T) {
	t.Parallel()
	_, err := recorder.ReadNDJSON("/does/not/exist.ndjson")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestReadNDJSON_EmptyFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.ndjson")
	os.WriteFile(path, []byte(""), 0644)

	records, err := recorder.ReadNDJSON(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
}

func TestReadNDJSON_IgnoresBlankLines(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "blanks.ndjson")

	call := makeCall("skips-blanks")
	data, _ := json.Marshal(call)
	os.WriteFile(path, []byte("\n"+string(data)+"\n\n"), 0644)

	records, err := recorder.ReadNDJSON(path)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(records) != 1 || records[0].ID != "skips-blanks" {
		t.Errorf("unexpected records: %v", records)
	}
}

func TestReadNDJSON_ReturnsErrorOnBadJSON(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.ndjson")
	os.WriteFile(path, []byte("{this is not json}\n"), 0644)

	_, err := recorder.ReadNDJSON(path)
	if err == nil {
		t.Error("expected error for malformed NDJSON")
	}
}

// ─── BuildRawBody Tests ───────────────────────────────────────────────────────

func TestBuildRawBody_ConcatenatesFrames(t *testing.T) {
	t.Parallel()
	frames := []recorder.FrameRecord{
		{Index: 0, Raw: []byte{0x01, 0x02}},
		{Index: 1, Raw: []byte{0x03, 0x04, 0x05}},
	}
	r := recorder.BuildRawBody(frames)
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	want := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	if !bytes.Equal(got, want) {
		t.Errorf("BuildRawBody: got %v, want %v", got, want)
	}
}

func TestBuildRawBody_EmptyFrames(t *testing.T) {
	t.Parallel()
	r := recorder.BuildRawBody(nil)
	got, _ := io.ReadAll(r)
	if len(got) != 0 {
		t.Errorf("expected empty body, got %d bytes", len(got))
	}
}

func TestBuildRawBody_SingleFrame(t *testing.T) {
	t.Parallel()
	want := []byte("hello-grpc-frame")
	frames := []recorder.FrameRecord{{Index: 0, Raw: want}}
	r := recorder.BuildRawBody(frames)
	got, _ := io.ReadAll(r)
	if !bytes.Equal(got, want) {
		t.Errorf("single frame: got %q, want %q", got, want)
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func makeCall(id string) *recorder.CallRecord {
	return &recorder.CallRecord{
		ID:         id,
		Timestamp:  time.Now(),
		Method:     "/test.Service/TestMethod",
		StreamKind: recorder.StreamUnary,
		StatusCode: "0",
		StatusName: "OK (0)",
		DurationMs: 1.0,
	}
}
