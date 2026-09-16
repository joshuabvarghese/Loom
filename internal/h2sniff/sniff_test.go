package h2sniff_test

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/joshuabvarghese/loom/internal/h2sniff"
)

// ─── Frame decoding (end-to-end via a real net.Pipe + real http2.Framer) ──────

// TestSniffer_DecodesHeadersFrame writes a real client preface + SETTINGS +
// HEADERS sequence through a tapped connection and checks that the sniffer
// recovers the frame types, flags, and HPACK-decoded pseudo-headers.
func TestSniffer_DecodesHeadersFrame(t *testing.T) {
	t.Parallel()

	loomSide, backendSide := net.Pipe()
	defer loomSide.Close()
	defer backendSide.Close()

	// net.Pipe is synchronous and unbuffered: writes block until the other
	// end reads. Something has to drain backendSide or Write calls below
	// never return.
	go io.Copy(io.Discard, backendSide) //nolint:errcheck

	snf := h2sniff.New(0)
	// WrapDialedConn: Loom is acting as the HTTP/2 client here (as it does
	// against a real backend), so the preface goes out on writes.
	wrapped := snf.WrapDialedConn(loomSide)

	if _, err := wrapped.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatalf("writing preface: %v", err)
	}

	framer := http2.NewFramer(wrapped, wrapped)
	if err := framer.WriteSettings(); err != nil {
		t.Fatalf("writing SETTINGS: %v", err)
	}

	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "http"},
		{Name: ":path", Value: "/user.UserService/GetUser"},
		{Name: ":authority", Value: "localhost"},
	} {
		if err := enc.WriteField(f); err != nil {
			t.Fatalf("hpack encode: %v", err)
		}
	}
	if err := framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hbuf.Bytes(),
		EndStream:     false,
		EndHeaders:    true,
	}); err != nil {
		t.Fatalf("writing HEADERS: %v", err)
	}

	headers := waitForFrame(t, snf, "HEADERS")
	if headers.Path != "/user.UserService/GetUser" {
		t.Errorf("Path = %q, want /user.UserService/GetUser", headers.Path)
	}
	if headers.Method != "POST" {
		t.Errorf("Method = %q, want POST", headers.Method)
	}
	if headers.Direction != "out" {
		t.Errorf("Direction = %q, want %q (Loom is the client leg here)", headers.Direction, "out")
	}
	if headers.StreamID != 1 {
		t.Errorf("StreamID = %d, want 1", headers.StreamID)
	}
	if !containsFlag(headers.Flags, "END_HEADERS") {
		t.Errorf("Flags = %v, want to contain END_HEADERS", headers.Flags)
	}
	if containsFlag(headers.Flags, "END_STREAM") {
		t.Errorf("Flags = %v, should not contain END_STREAM", headers.Flags)
	}

	settings := waitForFrame(t, snf, "SETTINGS")
	if settings.Direction != "out" {
		t.Errorf("SETTINGS Direction = %q, want out", settings.Direction)
	}
}

// TestSniffer_DecodesWindowUpdateAndRSTStream checks the frame-specific
// fields (flow-control increment, error code) that only apply to certain
// frame types.
func TestSniffer_DecodesWindowUpdateAndRSTStream(t *testing.T) {
	t.Parallel()

	loomSide, backendSide := net.Pipe()
	defer loomSide.Close()
	defer backendSide.Close()
	go io.Copy(io.Discard, backendSide) //nolint:errcheck

	snf := h2sniff.New(0)
	wrapped := snf.WrapDialedConn(loomSide)
	if _, err := wrapped.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatalf("writing preface: %v", err)
	}
	framer := http2.NewFramer(wrapped, wrapped)

	if err := framer.WriteWindowUpdate(1, 65535); err != nil {
		t.Fatalf("writing WINDOW_UPDATE: %v", err)
	}
	if err := framer.WriteRSTStream(1, http2.ErrCodeCancel); err != nil {
		t.Fatalf("writing RST_STREAM: %v", err)
	}

	wu := waitForFrame(t, snf, "WINDOW_UPDATE")
	if wu.WindowIncrement != 65535 {
		t.Errorf("WindowIncrement = %d, want 65535", wu.WindowIncrement)
	}

	rst := waitForFrame(t, snf, "RST_STREAM")
	if rst.ErrorCode != "CANCEL" {
		t.Errorf("ErrorCode = %q, want CANCEL", rst.ErrorCode)
	}
}

func waitForFrame(t *testing.T, snf *h2sniff.Sniffer, frameType string) *h2sniff.FrameEvent {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, ev := range snf.Store.All() {
			if ev.Type == frameType {
				return ev
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for a %s frame event", frameType)
	return nil
}

func containsFlag(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}

// ─── Hub pub/sub (mirrors internal/recorder's EventHub tests) ─────────────────

func TestHub_PublishReachesSubscriber(t *testing.T) {
	t.Parallel()
	h := h2sniff.NewHub()
	ch := h.Subscribe()
	defer h.Unsubscribe(ch)

	h.Publish(&h2sniff.FrameEvent{ConnID: "hub-1"})

	select {
	case got := <-ch:
		if got.ConnID != "hub-1" {
			t.Errorf("expected conn=hub-1, got %s", got.ConnID)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("timed out waiting for event")
	}
}

func TestHub_UnsubscribeClosesChannel(t *testing.T) {
	t.Parallel()
	h := h2sniff.NewHub()
	ch := h.Subscribe()
	h.Unsubscribe(ch)

	if _, ok := <-ch; ok {
		t.Fatal("expected channel to be closed after Unsubscribe")
	}
}

// ─── Store ring buffer (mirrors internal/recorder's Store tests) ──────────────

func TestStore_EvictsOldestWhenFull(t *testing.T) {
	t.Parallel()
	s := h2sniff.NewStore(2)
	s.Add(&h2sniff.FrameEvent{ConnID: "a"})
	s.Add(&h2sniff.FrameEvent{ConnID: "b"})
	s.Add(&h2sniff.FrameEvent{ConnID: "c"})

	all := s.All()
	if len(all) != 2 {
		t.Fatalf("expected 2 events after eviction, got %d", len(all))
	}
	// All() returns newest first.
	if all[0].ConnID != "c" || all[1].ConnID != "b" {
		t.Errorf("expected [c, b], got [%s, %s]", all[0].ConnID, all[1].ConnID)
	}
}
