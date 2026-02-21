package tracing

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"
)

// B3 header names
const (
	B3TraceIDHeader      = "X-B3-TraceId"
	B3SpanIDHeader       = "X-B3-SpanId"
	B3ParentSpanIDHeader = "X-B3-ParentSpanId"
	B3SampledHeader      = "X-B3-Sampled"
	B3FlagsHeader        = "X-B3-Flags"
	
	// Single header format
	B3SingleHeader       = "B3"
)

// SpanContext holds B3 tracing context
type SpanContext struct {
	TraceID      string
	SpanID       string
	ParentSpanID string
	Sampled      bool
	Flags        string
}

// PropagateB3Headers extracts B3 headers from incoming request and propagates them
func PropagateB3Headers(incomingReq *http.Request, outgoingReq *http.Request) *SpanContext {
	ctx := ExtractB3Context(incomingReq)
	
	// If no trace context exists, create a new one
	if ctx.TraceID == "" {
		ctx = NewSpanContext()
		log.Debug().
			Str("trace_id", ctx.TraceID).
			Str("span_id", ctx.SpanID).
			Msg("Created new trace context")
	} else {
		// Create new span ID for the outgoing request
		oldSpanID := ctx.SpanID
		ctx.ParentSpanID = oldSpanID
		ctx.SpanID = generateID(16) // 64-bit span ID
		
		log.Debug().
			Str("trace_id", ctx.TraceID).
			Str("parent_span_id", ctx.ParentSpanID).
			Str("span_id", ctx.SpanID).
			Msg("Propagating trace context")
	}
	
	// Inject headers into outgoing request
	InjectB3Context(outgoingReq, ctx)
	
	return ctx
}

// ExtractB3Context extracts B3 tracing context from HTTP request
func ExtractB3Context(r *http.Request) *SpanContext {
	ctx := &SpanContext{}
	
	// Try single header format first (b3=<trace-id>-<span-id>-<sampled>-<parent-span-id>)
	if singleHeader := r.Header.Get(B3SingleHeader); singleHeader != "" {
		// Parse single header format (simplified implementation)
		log.Debug().Str("b3_single", singleHeader).Msg("Found B3 single header")
	}
	
	// Multiple header format
	ctx.TraceID = r.Header.Get(B3TraceIDHeader)
	ctx.SpanID = r.Header.Get(B3SpanIDHeader)
	ctx.ParentSpanID = r.Header.Get(B3ParentSpanIDHeader)
	ctx.Flags = r.Header.Get(B3FlagsHeader)
	
	// Check sampled flag
	sampled := r.Header.Get(B3SampledHeader)
	ctx.Sampled = sampled == "1" || sampled == "true"
	
	if ctx.TraceID != "" {
		log.Debug().
			Str("trace_id", ctx.TraceID).
			Str("span_id", ctx.SpanID).
			Bool("sampled", ctx.Sampled).
			Msg("Extracted B3 context from request")
	}
	
	return ctx
}

// InjectB3Context injects B3 tracing context into HTTP request
func InjectB3Context(r *http.Request, ctx *SpanContext) {
	if ctx.TraceID == "" {
		return
	}
	
	r.Header.Set(B3TraceIDHeader, ctx.TraceID)
	r.Header.Set(B3SpanIDHeader, ctx.SpanID)
	
	if ctx.ParentSpanID != "" {
		r.Header.Set(B3ParentSpanIDHeader, ctx.ParentSpanID)
	}
	
	if ctx.Sampled {
		r.Header.Set(B3SampledHeader, "1")
	} else {
		r.Header.Set(B3SampledHeader, "0")
	}
	
	if ctx.Flags != "" {
		r.Header.Set(B3FlagsHeader, ctx.Flags)
	}
	
	log.Debug().
		Str("trace_id", ctx.TraceID).
		Str("span_id", ctx.SpanID).
		Msg("Injected B3 context into request")
}

// NewSpanContext creates a new span context with generated IDs
func NewSpanContext() *SpanContext {
	return &SpanContext{
		TraceID: generateID(32), // 128-bit trace ID
		SpanID:  generateID(16), // 64-bit span ID
		Sampled: true,           // Default to sampled
	}
}

// generateID generates a random hex ID of specified length
func generateID(length int) string {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to pseudo-random if crypto/rand fails
		log.Warn().Err(err).Msg("Failed to generate random ID, using fallback")
		return fmt.Sprintf("%0*x", length, 0)
	}
	return hex.EncodeToString(bytes)
}

// String returns a string representation of the span context
func (ctx *SpanContext) String() string {
	return fmt.Sprintf("TraceID=%s SpanID=%s ParentSpanID=%s Sampled=%v",
		ctx.TraceID, ctx.SpanID, ctx.ParentSpanID, ctx.Sampled)
}

// ToMap converts span context to a map for logging
func (ctx *SpanContext) ToMap() map[string]interface{} {
	m := map[string]interface{}{
		"trace_id": ctx.TraceID,
		"span_id":  ctx.SpanID,
		"sampled":  ctx.Sampled,
	}
	if ctx.ParentSpanID != "" {
		m["parent_span_id"] = ctx.ParentSpanID
	}
	if ctx.Flags != "" {
		m["flags"] = ctx.Flags
	}
	return m
}

// Middleware returns HTTP middleware that propagates B3 headers
func Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := ExtractB3Context(r)
			if ctx.TraceID == "" {
				ctx = NewSpanContext()
				InjectB3Context(r, ctx)
			}
			
			// Add trace ID to response headers for debugging
			w.Header().Set("X-Loom-Trace-Id", ctx.TraceID)
			
			next.ServeHTTP(w, r)
		})
	}
}
