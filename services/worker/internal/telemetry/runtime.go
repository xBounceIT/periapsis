package telemetry

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"regexp"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

const instrumentationName = "github.com/periapsis-im/periapsis/services/worker/internal/telemetry"

var errorTypePattern = regexp.MustCompile(`^[A-Za-z0-9_./*-]{1,128}$`)

// Runtime owns one trace provider and its bounded OTLP exporter lifecycle.
type Runtime struct {
	enabled         bool
	provider        trace.TracerProvider
	propagator      propagation.TextMapPropagator
	shutdown        func(context.Context) error
	shutdownMu      sync.Mutex
	shutdownDone    chan struct{}
	shutdownErr     error
	shutdownStarted bool
}

// Start initializes an OTLP/HTTP exporter when explicitly enabled.
func Start(ctx context.Context, cfg Config, logger *slog.Logger) (*Runtime, error) {
	if ctx == nil {
		return nil, errors.New("OpenTelemetry startup context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.New("OpenTelemetry startup context expired")
	}
	if !cfg.validated {
		return nil, errors.New("OpenTelemetry configuration was not constructed by LoadConfig")
	}
	propagator := boundedTraceContextPropagator{}
	if !cfg.Enabled {
		return &Runtime{
			provider: trace.NewNoopTracerProvider(), propagator: propagator,
			shutdown: func(context.Context) error { return nil },
		}, nil
	}
	if logger == nil {
		return nil, errors.New("OpenTelemetry structured logger is required")
	}
	if _, err := validateConfig(cfg); err != nil {
		return nil, err
	}

	exporter, err := otlptracehttp.New(
		ctx,
		otlptracehttp.WithEndpointURL(cfg.Endpoint+"/v1/traces"),
		otlptracehttp.WithCompression(otlptracehttp.GzipCompression),
		otlptracehttp.WithTimeout(cfg.ExportTimeout),
		otlptracehttp.WithRetry(otlptracehttp.RetryConfig{
			Enabled: true, InitialInterval: 250 * time.Millisecond,
			MaxInterval: time.Second, MaxElapsedTime: 5 * time.Second,
		}),
	)
	if err != nil {
		return nil, errors.New("initialize OpenTelemetry OTLP exporter")
	}
	processor := sdktrace.NewBatchSpanProcessor(
		exporter,
		sdktrace.WithMaxQueueSize(2_048),
		sdktrace.WithMaxExportBatchSize(256),
		sdktrace.WithBatchTimeout(2*time.Second),
		sdktrace.WithExportTimeout(cfg.ExportTimeout),
	)
	rootSampler := sdktrace.TraceIDRatioBased(cfg.SampleRatio)
	sampler := sdktrace.ParentBased(
		rootSampler,
		// A remote caller cannot force expensive sampling by setting its flag.
		sdktrace.WithRemoteParentSampled(rootSampler),
		sdktrace.WithRemoteParentNotSampled(rootSampler),
	)
	limits := sdktrace.SpanLimits{
		AttributeValueLengthLimit:   256,
		AttributeCountLimit:         32,
		EventCountLimit:             0,
		LinkCountLimit:              4,
		AttributePerEventCountLimit: 0,
		AttributePerLinkCountLimit:  8,
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sampler),
		sdktrace.WithSpanProcessor(processor),
		sdktrace.WithSpanLimits(limits),
		sdktrace.WithResource(resource.NewSchemaless(
			attribute.String("service.name", cfg.ServiceName),
			attribute.String("service.version", cfg.Version),
			attribute.String("deployment.environment.name", cfg.Environment),
		)),
	)
	otel.SetErrorHandler(redactedErrorHandler{logger: logger})
	otel.SetTextMapPropagator(propagator)
	otel.SetTracerProvider(provider)
	return &Runtime{
		enabled: true, provider: provider, propagator: propagator,
		shutdown: provider.Shutdown,
	}, nil
}

// Enabled reports whether this explicitly configured runtime records spans.
func (r *Runtime) Enabled() bool {
	return r != nil && r.enabled
}

// TracerProvider returns the runtime-owned provider for explicit instrumentation.
func (r *Runtime) TracerProvider() trace.TracerProvider {
	if r == nil || r.provider == nil {
		return trace.NewNoopTracerProvider()
	}
	return r.provider
}

// Tracer returns the worker instrumentation tracer.
func (r *Runtime) Tracer() trace.Tracer {
	return r.TracerProvider().Tracer(instrumentationName)
}

// ForceFlush exports queued spans within the caller's deadline.
func (r *Runtime) ForceFlush(ctx context.Context) error {
	if r == nil || !r.enabled {
		return nil
	}
	provider, ok := r.provider.(*sdktrace.TracerProvider)
	if !ok {
		return errors.New("OpenTelemetry provider does not support flushing")
	}
	if ctx == nil {
		return errors.New("OpenTelemetry flush context is required")
	}
	if err := provider.ForceFlush(ctx); err != nil {
		return errors.New("flush OpenTelemetry spans")
	}
	return nil
}

// Shutdown flushes and closes the exporter once. The first caller owns the
// provider deadline; every concurrent caller retains its own wait deadline.
func (r *Runtime) Shutdown(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("OpenTelemetry shutdown context is required")
	}
	if !r.enabled {
		return nil
	}
	r.shutdownMu.Lock()
	if !r.shutdownStarted {
		r.shutdownStarted = true
		r.shutdownDone = make(chan struct{})
		shutdown := r.shutdown
		done := r.shutdownDone
		go func() {
			var err error
			func() {
				defer func() {
					if recover() != nil {
						err = errors.New("OpenTelemetry shutdown panic")
					}
				}()
				if shutdown == nil {
					err = errors.New("OpenTelemetry shutdown is unavailable")
					return
				}
				err = shutdown(ctx)
			}()
			r.shutdownMu.Lock()
			if err != nil {
				r.shutdownErr = errors.New("shutdown OpenTelemetry")
			}
			close(done)
			r.shutdownMu.Unlock()
		}()
	}
	done := r.shutdownDone
	r.shutdownMu.Unlock()

	select {
	case <-done:
		r.shutdownMu.Lock()
		err := r.shutdownErr
		r.shutdownMu.Unlock()
		return err
	case <-ctx.Done():
		return errors.New("OpenTelemetry shutdown deadline expired")
	}
}

func validateConfig(cfg Config) (Config, error) {
	if !cfg.validated || !cfg.Enabled || cfg.Endpoint == "" || cfg.Environment == "" || cfg.ServiceName == "" || cfg.Version == "" ||
		cfg.ExportTimeout < 100*time.Millisecond || cfg.ExportTimeout > 30*time.Second ||
		cfg.SampleRatio < 0 || cfg.SampleRatio > 1 {
		return Config{}, errors.New("OpenTelemetry configuration is invalid")
	}
	return cfg, nil
}

type redactedErrorHandler struct {
	logger *slog.Logger
}

func (h redactedErrorHandler) Handle(err error) {
	if h.logger == nil {
		return
	}
	errorType := "unknown"
	if err != nil {
		errorType = reflect.TypeOf(err).String()
		if !errorTypePattern.MatchString(errorType) {
			errorType = "unknown"
		}
	}
	h.logger.Error("OpenTelemetry export failed", "error_type", errorType)
}
