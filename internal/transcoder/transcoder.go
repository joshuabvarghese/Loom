// Package transcoder handles the gRPC wire-format <-> JSON conversion.
//
// gRPC DATA frames carry length-prefixed protobuf messages:
//
//	┌──────────┬────────────────────┬───────────────────────────┐
//	│ 1 byte   │ 4 bytes (big-end.) │ N bytes                   │
//	│ compress │ message length     │ protobuf-encoded payload  │
//	└──────────┴────────────────────┴───────────────────────────┘
package transcoder

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/jhump/protoreflect/desc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/dynamicpb"
)

const grpcHeaderSize = 5

// Frame is a single decoded gRPC message.
type Frame struct {
	// Raw is the original bytes (header + body) so they can be forwarded unchanged.
	Raw []byte
	// JSON is the pretty-printed JSON representation (empty if decode failed).
	JSON string
	// Err is set when decoding failed but Raw is still valid for forwarding.
	Err error
	// Compressed is true when the compression flag byte was set.
	Compressed bool
}

// DecodeStream reads all gRPC frames from r, decoding each one using msgDesc.
// It returns each Frame as decoded and the raw bytes for forwarding.
// The function reads until EOF or an unrecoverable error.
func DecodeStream(r io.Reader, msgDesc *desc.MessageDescriptor) ([]*Frame, error) {
	var frames []*Frame
	for {
		frame, err := readFrame(r, msgDesc)
		if err == io.EOF {
			break
		}
		if err != nil {
			return frames, err
		}
		frames = append(frames, frame)
	}
	return frames, nil
}

// StreamFrames reads gRPC frames one by one from r, decoding each with msgDesc,
// and writing the raw bytes to w. Each decoded Frame is sent on the returned channel.
// The channel is closed when r returns EOF or an error.
func StreamFrames(r io.Reader, w io.Writer, msgDesc *desc.MessageDescriptor) <-chan *Frame {
	ch := make(chan *Frame, 8)
	go func() {
		defer close(ch)
		for {
			frame, err := readFrame(r, msgDesc)
			if frame != nil {
				// Always forward raw bytes, even if JSON decode failed
				if _, werr := w.Write(frame.Raw); werr != nil {
					return
				}
				ch <- frame
			}
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return
			}
			if err != nil {
				ch <- &Frame{Err: err}
				return
			}
		}
	}()
	return ch
}

// readFrame reads exactly one length-prefixed gRPC message from r.
func readFrame(r io.Reader, msgDesc *desc.MessageDescriptor) (*Frame, error) {
	// Read the 5-byte gRPC envelope header
	header := make([]byte, grpcHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("reading frame header: %w", err)
	}

	compressed := header[0] == 1
	msgLen := binary.BigEndian.Uint32(header[1:5])

	// Read the protobuf payload
	body := make([]byte, msgLen)
	if msgLen > 0 {
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, fmt.Errorf("reading frame body (%d bytes): %w", msgLen, err)
		}
	}

	raw := append(header, body...)

	if compressed {
		return &Frame{
			Raw:        raw,
			JSON:       "",
			Compressed: true,
			Err:        fmt.Errorf("compressed frames are not decoded (gzip compression detected)"),
		}, nil
	}

	if msgDesc == nil {
		return &Frame{Raw: raw, JSON: fmt.Sprintf("(raw %d bytes — no descriptor)", msgLen)}, nil
	}

	// Unwrap to protoreflect.MessageDescriptor for dynamicpb
	dynMsg := dynamicpb.NewMessage(msgDesc.UnwrapMessage())

	if err := proto.Unmarshal(body, dynMsg); err != nil {
		return &Frame{
			Raw: raw,
			Err: fmt.Errorf("protobuf unmarshal: %w", err),
			JSON: fmt.Sprintf("(unmarshal error — raw %d bytes)", msgLen),
		}, nil
	}

	jsonBytes, err := protojson.MarshalOptions{
		Multiline:       true,
		Indent:          "  ",
		EmitUnpopulated: false,
		UseProtoNames:   false,
	}.Marshal(dynMsg)
	if err != nil {
		return &Frame{
			Raw: raw,
			Err: fmt.Errorf("json marshal: %w", err),
			JSON: fmt.Sprintf("(json error — raw %d bytes)", msgLen),
		}, nil
	}

	return &Frame{
		Raw:  raw,
		JSON: string(jsonBytes),
	}, nil
}

// BuildFrame encodes a JSON string back into a gRPC length-prefixed frame.
// Returns an error if msgDesc is nil or the JSON cannot be parsed.
func BuildFrame(msgDesc *desc.MessageDescriptor, jsonStr string) ([]byte, error) {
	if msgDesc == nil {
		return nil, fmt.Errorf("BuildFrame: nil message descriptor")
	}

	dynMsg := dynamicpb.NewMessage(msgDesc.UnwrapMessage())

	if err := protojson.Unmarshal([]byte(jsonStr), dynMsg); err != nil {
		return nil, fmt.Errorf("json unmarshal: %w", err)
	}

	body, err := proto.Marshal(dynMsg)
	if err != nil {
		return nil, fmt.Errorf("proto marshal: %w", err)
	}

	var buf bytes.Buffer
	buf.WriteByte(0) // not compressed
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(body)))
	buf.Write(lenBytes)
	buf.Write(body)
	return buf.Bytes(), nil
}
