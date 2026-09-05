package telemetry

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

var sqlStatePattern = regexp.MustCompile(`^[0-9A-Z]{5}$`)

// InstrumentPGX installs a query tracer that deliberately omits SQL text,
// arguments, database URLs, peer addresses, and error messages.
func (r *Runtime) InstrumentPGX(config *pgxpool.Config) error {
	if config == nil || config.ConnConfig == nil {
		return errors.New("pgx pool configuration is required")
	}
	if r == nil || !r.enabled {
		return nil
	}
	if config.ConnConfig.Tracer != nil {
		return errors.New("pgx tracing is already configured")
	}
	config.ConnConfig.Tracer = pgxTracer{tracer: r.Tracer()}
	return nil
}

type pgxTracer struct {
	tracer trace.Tracer
}

func (t pgxTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	ctx, _ = t.tracer.Start(
		ctx,
		"postgresql.query",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attribute.String("db.system.name", "postgresql")),
	)
	return ctx
}

func (pgxTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	span := trace.SpanFromContext(ctx)
	if operation := databaseOperation(data.CommandTag); operation != "" {
		span.SetName("postgresql." + strings.ToLower(operation))
		span.SetAttributes(attribute.String("db.operation.name", operation))
	}
	if data.Err != nil {
		span.SetStatus(codes.Error, "database operation failed")
		span.SetAttributes(attribute.String("error.type", databaseErrorType(data.Err)))
	}
	span.End()
}

func databaseOperation(tag pgconn.CommandTag) string {
	operation, _, _ := strings.Cut(tag.String(), " ")
	switch operation {
	case "BEGIN", "CALL", "COMMIT", "DELETE", "INSERT", "MERGE", "RELEASE", "ROLLBACK", "SAVEPOINT", "SELECT", "SET", "SHOW", "UPDATE":
		return operation
	default:
		return ""
	}
}

func databaseErrorType(err error) string {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && sqlStatePattern.MatchString(postgresError.Code) {
		return "postgresql.sqlstate." + postgresError.Code
	}
	return "postgresql.error"
}
