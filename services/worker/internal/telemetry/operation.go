package telemetry

import (
	"context"
	"errors"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// StartOperation creates a bounded internal span. Operation names are a closed
// set so caller-controlled values cannot create high-cardinality telemetry.
func (r *Runtime) StartOperation(ctx context.Context, operation string) (context.Context, func(error)) {
	if ctx == nil {
		ctx = context.Background()
	}
	operation = canonicalWorkerOperation(operation)
	if r == nil || !r.enabled || operation == "" {
		return ctx, func(error) {}
	}
	spanContext, span := r.Tracer().Start(
		ctx,
		"worker."+operation,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attribute.String("worker.operation.name", operation)),
	)
	return spanContext, func(err error) {
		if err != nil {
			span.SetStatus(codes.Error, "worker operation failed")
			switch {
			case errors.Is(err, context.Canceled):
				span.SetAttributes(attribute.String("error.type", "context.canceled"))
			case errors.Is(err, context.DeadlineExceeded):
				span.SetAttributes(attribute.String("error.type", "context.deadline_exceeded"))
			default:
				span.SetAttributes(attribute.String("error.type", "worker.operation_error"))
			}
		}
		span.End()
	}
}

func canonicalWorkerOperation(value string) string {
	switch value {
	case "auth.cleanup", "database.readiness", "ldap.sync.poll", "sla.action", "sla.evaluate",
		"oidc.maintenance.expire_access_lease", "oidc.maintenance.cleanup_retention",
		"sla.event_ingress", "oidc.maintenance.claim.logout_retry", "oidc.maintenance.claim.refresh",
		"oidc.maintenance.claim.scrub", "oidc.maintenance.refresh", "oidc.maintenance.refresh.complete",
		"oidc.maintenance.logout_retry", "oidc.maintenance.logout_retry.complete":
		return value
	default:
		return ""
	}
}
