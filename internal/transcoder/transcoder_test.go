package transcoder_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/joshuabvarghese/loom/internal/transcoder"
)

// ─── DecodeStream — No Descriptor ─────────────────────────────────────────────

func TestDecodeStream_NoDescriptor_ReturnsRawFrames(t *testing.T) {
	t.Parallel()
	body := makeGRPCFrame(false, []byte("raw bytes"))
	frames, err := transcoder.DecodeStream(bytes.NewReader(body), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}
	if frames[0].Err != nil {
		t.Errorf("expected no frame error, got: %v", frames[0].Err)
	}
	if !bytes.Equal(frames[0].Raw, body) {
		t.Errorf("Raw bytes mismatch")
	}
}

func TestDecodeStream_EmptyReader_ReturnsNoFrames(t *testing.T) {
	t.Parallel()
	frames, err := transcoder.DecodeStream(bytes.NewReader(nil), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(frames) != 0 {
		t.Errorf("expected 0 frames from empty reader, got %d", len(frames))
	}
}

func TestDecodeStream_MultipleFrames(t *testing.T) {
	t.Parallel()
	f1 := makeGRPCFrame(false, []byte("frame-one"))
	f2 := makeGRPCFrame(false, []byte("frame-two"))
	combined := append(f1, f2...)

	frames, err := transcoder.DecodeStream(bytes.NewReader(combined), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}
}

func TestDecodeStream_CompressedFrame_HasError(t *testing.T) {
	t.Parallel()
	compressed := makeGRPCFrame(true, []byte("compressed-payload"))
	frames, err := transcoder.DecodeStream(bytes.NewReader(compressed), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}
	if frames[0].Err == nil {
		t.Error("expected error for compressed frame (not supported)")
	}
	if !frames[0].Compressed {
		t.Error("expected Compressed=true for compressed frame")
	}
}

func TestDecodeStream_TruncatedHeader_ReturnsError(t *testing.T) {
	t.Parallel()
	// Only 3 bytes — header requires 5
	truncated := []byte{0x00, 0x00, 0x00}
	_, err := transcoder.DecodeStream(bytes.NewReader(truncated), nil)
	if err == nil {
		t.Error("expected error for truncated frame header")
	}
}

func TestDecodeStream_TruncatedBody_ReturnsError(t *testing.T) {
	t.Parallel()
	// Header claims 10 bytes, but body only has 3
	header := make([]byte, 5)
	header[0] = 0 // not compressed
	binary.BigEndian.PutUint32(header[1:], 10)
	data := append(header, []byte{1, 2, 3}...)

	_, err := transcoder.DecodeStream(bytes.NewReader(data), nil)
	if err == nil {
		t.Error("expected error for truncated frame body")
	}
}

func TestDecodeStream_EmptyMessageBody(t *testing.T) {
	t.Parallel()
	// gRPC allows 0-length messages (e.g. empty proto)
	frame := makeGRPCFrame(false, []byte{})
	frames, err := transcoder.DecodeStream(bytes.NewReader(frame), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame for empty body, got %d", len(frames))
	}
	if len(frames[0].Raw) != 5 {
		t.Errorf("raw should be exactly the 5-byte header, got %d bytes", len(frames[0].Raw))
	}
}

// ─── StreamFrames ─────────────────────────────────────────────────────────────

func TestStreamFrames_WritesRawToWriter(t *testing.T) {
	t.Parallel()
	body := makeGRPCFrame(false, []byte("stream-content"))
	var w bytes.Buffer
	ch := transcoder.StreamFrames(bytes.NewReader(body), &w, nil)

	for range ch {
		// consume
	}

	if !bytes.Equal(w.Bytes(), body) {
		t.Errorf("StreamFrames should write raw bytes to writer")
	}
}

func TestStreamFrames_ClosesChannelOnEOF(t *testing.T) {
	t.Parallel()
	body := makeGRPCFrame(false, []byte("frame"))
	ch := transcoder.StreamFrames(bytes.NewReader(body), io.Discard, nil)

	count := 0
	for range ch {
		count++
	}
	if count != 1 {
		t.Errorf("expected 1 frame, got %d", count)
	}
}

func TestStreamFrames_EmptyReader_ClosesImmediately(t *testing.T) {
	t.Parallel()
	ch := transcoder.StreamFrames(bytes.NewReader(nil), io.Discard, nil)

	count := 0
	for range ch {
		count++
	}
	if count != 0 {
		t.Errorf("expected 0 frames from empty reader, got %d", count)
	}
}

func TestStreamFrames_MultipleFrames_AllDelivered(t *testing.T) {
	t.Parallel()
	f1 := makeGRPCFrame(false, []byte("a"))
	f2 := makeGRPCFrame(false, []byte("b"))
	f3 := makeGRPCFrame(false, []byte("c"))
	data := append(append(f1, f2...), f3...)

	ch := transcoder.StreamFrames(bytes.NewReader(data), io.Discard, nil)

	count := 0
	for range ch {
		count++
	}
	if count != 3 {
		t.Errorf("expected 3 frames, got %d", count)
	}
}

// ─── BuildFrame ───────────────────────────────────────────────────────────────

func TestBuildFrame_NilDescriptor_ReturnsError(t *testing.T) {
	t.Parallel()
	_, err := transcoder.BuildFrame(nil, `{"hello": "world"}`)
	if err == nil {
		t.Error("expected error when descriptor is nil")
	}
}

func TestBuildFrame_InvalidJSON_ReturnsError(t *testing.T) {
	t.Parallel()
	// We can't easily get a real descriptor here without a compiled .proto,
	// but we can verify the nil path returns an error.
	_, err := transcoder.BuildFrame(nil, "not json")
	if err == nil {
		t.Error("expected error for invalid JSON or nil descriptor")
	}
}

// ─── Frame fields ──────────────────────────────────────────────────────────────

func TestFrame_RawPreservedOnDecodeError(t *testing.T) {
	t.Parallel()
	// A valid gRPC frame with random non-proto bytes (will fail proto.Unmarshal)
	// but Raw should still be set
	badProto := []byte{0xFF, 0xFF, 0xFF} // garbage, not valid protobuf
	frame := makeGRPCFrame(false, badProto)
	frames, _ := transcoder.DecodeStream(bytes.NewReader(frame), nil)
	if len(frames) == 0 {
		t.Fatal("expected at least 1 frame")
	}
	// Without a descriptor, no unmarshal happens — Raw is always set
	if frames[0].Raw == nil {
		t.Error("Raw should always be set even when decode has errors")
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// makeGRPCFrame builds a 5-byte-header gRPC frame with the given payload.
func makeGRPCFrame(compressed bool, payload []byte) []byte {
	header := make([]byte, 5)
	if compressed {
		header[0] = 1
	}
	binary.BigEndian.PutUint32(header[1:5], uint32(len(payload)))
	return append(header, payload...)
}
