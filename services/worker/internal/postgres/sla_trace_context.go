package postgres

import (
	"context"

	applicationtelemetry "github.com/periapsis-im/periapsis/services/worker/internal/telemetry"
)

// slaTraceContextArguments returns exactly two positional parameters so every
// SLA producer statement locally overwrites both database trace settings. The
// empty pair prevents stale pooled-session settings from becoming provenance.
func slaTraceContextArguments(ctx context.Context) (string, string) {
	persisted, ok := applicationtelemetry.PersistedSpanContextFromContext(ctx)
	if !ok {
		return "", ""
	}
	tracestate := ""
	if persisted.TraceState != nil {
		tracestate = *persisted.TraceState
	}
	return persisted.TraceParent, tracestate
}
