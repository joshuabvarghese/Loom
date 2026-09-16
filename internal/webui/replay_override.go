package webui

import (
	"context"
	"fmt"

	recpkg "github.com/joshuabvarghese/loom/internal/recorder"
	"github.com/joshuabvarghese/loom/internal/transcoder"
)

// Only the first request frame is replaced with payload; that covers unary
// and server-streaming calls without trying to solve editing a full
// client-streaming sequence in one text box. Any further recorded frames
// replay unchanged. The record is shallow-copied so a botched edit can't
// corrupt the copy sitting in the recorder's store.
func (s *Server) applyPayloadOverride(ctx context.Context, call *recpkg.CallRecord, payload string) (*recpkg.CallRecord, error) {
	if s.refl == nil {
		return nil, fmt.Errorf("editing a payload before replay requires the reflector, which isn't configured for this session")
	}

	info, err := s.refl.Resolve(ctx, call.Method)
	if err != nil {
		return nil, fmt.Errorf("resolving %q: %w", call.Method, err)
	}
	if info.Input == nil {
		return nil, fmt.Errorf("no request descriptor available for %q", call.Method)
	}

	raw, err := transcoder.BuildFrame(info.Input, payload)
	if err != nil {
		return nil, fmt.Errorf("encoding edited payload against %s: %w", info.Input.GetFullyQualifiedName(), err)
	}

	edited := *call

	frames := make([]recpkg.FrameRecord, len(call.Request))
	copy(frames, call.Request)
	if len(frames) == 0 {
		frames = append(frames, recpkg.FrameRecord{})
	}
	frames[0] = recpkg.FrameRecord{Index: 0, JSON: payload, Raw: raw}
	edited.Request = frames

	return &edited, nil
}
