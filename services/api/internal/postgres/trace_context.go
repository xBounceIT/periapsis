package postgres

import (
	"context"
	"errors"

	applicationtelemetry "github.com/periapsis-im/periapsis/services/api/internal/telemetry"
)

func installPersistedTraceContext(ctx context.Context, tx databaseTransaction) error {
	if tx == nil {
		return errors.New("database transaction is required")
	}
	traceparent, tracestate := "", ""
	persistedParent, persistedState := persistedTraceContextParameters(ctx)
	if persistedParent != nil {
		traceparent = *persistedParent
	}
	if persistedState != nil {
		tracestate = *persistedState
	}
	var installedParent, installedState string
	if err := tx.QueryRow(ctx, `
		SELECT set_config('app.traceparent', $1, true),
		       set_config('app.tracestate', $2, true)
	`, traceparent, tracestate).Scan(&installedParent, &installedState); err != nil {
		return err
	}
	if installedParent != traceparent || installedState != tracestate {
		return errors.New("database trace context was not installed")
	}
	return nil
}

func persistedTraceContextParameters(ctx context.Context) (*string, *string) {
	persisted, ok := applicationtelemetry.PersistedSpanContextFromContext(ctx)
	if !ok {
		return nil, nil
	}
	traceparent := persisted.TraceParent
	var tracestate *string
	if persisted.TraceState != nil {
		value := *persisted.TraceState
		tracestate = &value
	}
	return &traceparent, tracestate
}
