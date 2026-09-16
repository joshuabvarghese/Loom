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
	"errors"
	"fmt"
	"io"

	"github.com/jhump/protoreflect/desc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/dynamicpb"
)

const grpcHeaderSize = 5

// A raw uint32 length from the wire can claim up to ~4 GB; without a
// ceiling, a malformed or malicious frame causes an OOM before the read
// even fails. 32 MB is generous for any real gRPC payload.
const MaxFrameSize = 32 * 1024 * 1024

type Frame struct {
	Raw        []byte
	JSON       string
	Err        error
	Compressed bool
}

func DecodeStream(r io.Reader, msgDesc *desc.MessageDescriptor) ([]*Frame, error) {
	var frames []*Frame
	for {
		frame, err := readFrame(r, msgDesc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return frames, err
		}
		frames = append(frames, frame)
	}
	return frames, nil
}

func StreamFrames(r io.Reader, w io.Writer, msgDesc *desc.MessageDescriptor) <-chan *Frame {
	ch := make(chan *Frame, 8)
	go func() {
		defer close(ch)
		for {
			frame, err := readFrame(r, msgDesc)
			if frame != nil {
				// Forward raw bytes regardless of whether JSON decoding succeeded.
				if _, werr := w.Write(frame.Raw); werr != nil {
					return
				}
				ch <- frame
			}
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
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

func readFrame(r io.Reader, msgDesc *desc.MessageDescriptor) (*Frame, error) {
	header := make([]byte, grpcHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("reading frame header: %w", err)
	}

	compressed := header[0] == 1
	msgLen := binary.BigEndian.Uint32(header[1:5])

	if msgLen > MaxFrameSize {
		return nil, fmt.Errorf(
			"frame too large: %d bytes exceeds MaxFrameSize (%d); "+
				"use a custom build with a higher MaxFrameSize if needed",
			msgLen, MaxFrameSize,
		)
	}

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
			Compressed: true,
			Err:        fmt.Errorf("compressed frames are not decoded (gzip compression detected)"),
		}, nil
	}

	if msgDesc == nil {
		return &Frame{Raw: raw, JSON: fmt.Sprintf("(raw %d bytes — no descriptor)", msgLen)}, nil
	}

	dynMsg := dynamicpb.NewMessage(msgDesc.UnwrapMessage())

	if err := proto.Unmarshal(body, dynMsg); err != nil {
		return &Frame{
			Raw:  raw,
			Err:  fmt.Errorf("protobuf unmarshal: %w", err),
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
			Raw:  raw,
			Err:  fmt.Errorf("json marshal: %w", err),
			JSON: fmt.Sprintf("(json error — raw %d bytes)", msgLen),
		}, nil
	}

	return &Frame{
		Raw:  raw,
		JSON: string(jsonBytes),
	}, nil
}

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
	buf.WriteByte(0) // compression flag: always uncompressed
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(body)))
	buf.Write(lenBytes)
	buf.Write(body)
	return buf.Bytes(), nil
}
