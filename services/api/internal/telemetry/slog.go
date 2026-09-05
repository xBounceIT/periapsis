package telemetry

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/trace"
)

// NewTraceContextHandler decorates structured logs with bounded identifiers
// from the active span. It never adds baggage or span attributes.
func NewTraceContextHandler(next slog.Handler) slog.Handler {
	if next == nil {
		panic("telemetry: slog handler is required")
	}
	return traceContextHandler{next: next}
}

type traceContextHandler struct {
	next slog.Handler
}

func (h traceContextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h traceContextHandler) Handle(ctx context.Context, record slog.Record) error {
	spanContext := trace.SpanContextFromContext(ctx)
	if spanContext.IsValid() {
		record.AddAttrs(
			slog.String("trace_id", spanContext.TraceID().String()),
			slog.String("span_id", spanContext.SpanID().String()),
			slog.Bool("trace_sampled", spanContext.IsSampled()),
		)
	}
	return h.next.Handle(ctx, record)
}

func (h traceContextHandler) WithAttrs(attributes []slog.Attr) slog.Handler {
	return traceContextHandler{next: h.next.WithAttrs(attributes)}
}

func (h traceContextHandler) WithGroup(name string) slog.Handler {
	return traceContextHandler{next: h.next.WithGroup(name)}
}
