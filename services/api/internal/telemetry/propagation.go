package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"regexp"

	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

const maximumTraceStateSize = 512

var persistedTraceParentPattern = regexp.MustCompile(`^00-([0-9a-f]{32})-([0-9a-f]{16})-(00|01)$`)

// PersistedSpanContext is the closed application representation stored with
// an outbox event. TraceState is nil when W3C tracestate is absent; an empty
// string is never serialized.
type PersistedSpanContext struct {
	TraceParent string
	TraceState  *string
}

// PersistedSpanContextFromContext snapshots a local producer span. Remote
// caller headers are never persisted directly.
func PersistedSpanContextFromContext(ctx context.Context) (PersistedSpanContext, bool) {
	spanContext := trace.SpanContextFromContext(ctx)
	if !spanContext.IsValid() || spanContext.IsRemote() {
		return PersistedSpanContext{}, false
	}
	result := PersistedSpanContext{TraceParent: fmt.Sprintf(
		"00-%s-%s-%02x",
		spanContext.TraceID(), spanContext.SpanID(), byte(spanContext.TraceFlags()&trace.FlagsSampled),
	)}
	if state := spanContext.TraceState().String(); state != "" {
		result.TraceState = &state
	}
	return result, true
}

// ParsePersistedSpanContext validates the database boundary and returns a
// remote context suitable only for an explicit consumer Link.
func ParsePersistedSpanContext(value PersistedSpanContext) (trace.SpanContext, error) {
	match := persistedTraceParentPattern.FindStringSubmatch(value.TraceParent)
	if match == nil {
		return trace.SpanContext{}, fmt.Errorf("persisted trace parent is invalid")
	}
	traceID, err := trace.TraceIDFromHex(match[1])
	if err != nil || !traceID.IsValid() {
		return trace.SpanContext{}, fmt.Errorf("persisted trace ID is invalid")
	}
	spanID, err := trace.SpanIDFromHex(match[2])
	if err != nil || !spanID.IsValid() {
		return trace.SpanContext{}, fmt.Errorf("persisted span ID is invalid")
	}
	flags := trace.TraceFlags(0)
	if match[3] == "01" {
		flags = trace.FlagsSampled
	}
	state := trace.TraceState{}
	if value.TraceState != nil {
		if *value.TraceState == "" || len(*value.TraceState) > maximumTraceStateSize {
			return trace.SpanContext{}, fmt.Errorf("persisted trace state is invalid")
		}
		state, err = trace.ParseTraceState(*value.TraceState)
		if err != nil || state.String() != *value.TraceState {
			return trace.SpanContext{}, fmt.Errorf("persisted trace state is invalid")
		}
	}
	return trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: spanID, TraceFlags: flags,
		TraceState: state, Remote: true,
	}), nil
}

// ConsumerLink returns one validated producer link. Invalid database values
// fail closed instead of silently creating an unrelated trace.
func ConsumerLink(value PersistedSpanContext) (trace.Link, error) {
	spanContext, err := ParsePersistedSpanContext(value)
	if err != nil {
		return trace.Link{}, err
	}
	return trace.Link{SpanContext: spanContext}, nil
}

type boundedTraceContextPropagator struct{}

func (boundedTraceContextPropagator) Inject(ctx context.Context, carrier propagation.TextMapCarrier) {
	propagation.TraceContext{}.Inject(ctx, carrier)
}

func (boundedTraceContextPropagator) Extract(ctx context.Context, carrier propagation.TextMapCarrier) context.Context {
	traceParent := carrier.Get("traceparent")
	traceState := carrier.Get("tracestate")
	if !validIncomingTraceHeaders(traceParent, traceState) {
		return ctx
	}
	return propagation.TraceContext{}.Extract(ctx, propagation.MapCarrier{
		"traceparent": traceParent,
		"tracestate":  traceState,
	})
}

func (boundedTraceContextPropagator) Fields() []string {
	return []string{"traceparent", "tracestate"}
}

func extractHTTPTraceContext(ctx context.Context, header http.Header) context.Context {
	root := trace.ContextWithSpanContext(ctx, trace.SpanContext{})
	traceParents := header.Values("Traceparent")
	traceStates := header.Values("Tracestate")
	if len(traceParents) != 1 || len(traceStates) > 1 {
		return root
	}
	carrier := propagation.MapCarrier{"traceparent": traceParents[0]}
	if len(traceStates) == 1 {
		carrier["tracestate"] = traceStates[0]
	}
	return boundedTraceContextPropagator{}.Extract(root, carrier)
}

func validIncomingTraceHeaders(traceParent, traceState string) bool {
	value := PersistedSpanContext{TraceParent: traceParent}
	if traceState != "" {
		value.TraceState = &traceState
	}
	_, err := ParsePersistedSpanContext(value)
	return err == nil
}
