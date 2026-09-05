package telemetry

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestLoadConfigRequiresExplicitClosedOTLPHTTPConfiguration(t *testing.T) {
	environment := map[string]string{
		"OTEL_SDK_DISABLED":                "false",
		"OTEL_SERVICE_NAME":                "periapsis-api",
		"OTEL_EXPORTER_OTLP_PROTOCOL":      "http/protobuf",
		"OTEL_EXPORTER_OTLP_ENDPOINT":      "http://otel-collector:4318",
		"OTEL_PROPAGATORS":                 "tracecontext",
		"OTEL_TRACES_SAMPLER":              "parentbased_traceidratio",
		"OTEL_TRACES_SAMPLER_ARG":          "0.25",
		"PERIAPSIS_OTEL_EXPORT_TIMEOUT_MS": "2500",
	}
	config, err := LoadConfigFrom("production", "periapsis-api", "release-1", mapLookup(environment))
	if err != nil {
		t.Fatalf("LoadConfigFrom() error = %v", err)
	}
	if !config.Enabled || config.Endpoint != "http://otel-collector:4318" || config.SampleRatio != 0.25 || config.ExportTimeout != 2500*time.Millisecond {
		t.Fatalf("config = %#v", config)
	}

	disabled, err := LoadConfigFrom("test", "periapsis-api", "test", mapLookup(map[string]string{
		"OTEL_SDK_DISABLED": "true",
	}))
	if err != nil || disabled.Enabled {
		t.Fatalf("disabled config = %#v, error = %v", disabled, err)
	}
}

func TestLoadConfigRejectsAmbiguousAndHostileValues(t *testing.T) {
	valid := map[string]string{
		"OTEL_SDK_DISABLED":           "false",
		"OTEL_SERVICE_NAME":           "periapsis-api",
		"OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
		"OTEL_EXPORTER_OTLP_ENDPOINT": "https://otel.example.invalid:4318",
	}
	tests := map[string]func(map[string]string){
		"missing explicit enablement": func(values map[string]string) { delete(values, "OTEL_SDK_DISABLED") },
		"empty enablement":            func(values map[string]string) { values["OTEL_SDK_DISABLED"] = "" },
		"wrong service":               func(values map[string]string) { values["OTEL_SERVICE_NAME"] = "notifier" },
		"gRPC protocol":               func(values map[string]string) { values["OTEL_EXPORTER_OTLP_PROTOCOL"] = "grpc" },
		"URL credential": func(values map[string]string) {
			values["OTEL_EXPORTER_OTLP_ENDPOINT"] = "https://user:secret@otel.invalid"
		},
		"URL query":            func(values map[string]string) { values["OTEL_EXPORTER_OTLP_ENDPOINT"] += "?token=secret" },
		"URL path":             func(values map[string]string) { values["OTEL_EXPORTER_OTLP_ENDPOINT"] += "/tenant" },
		"URL control":          func(values map[string]string) { values["OTEL_EXPORTER_OTLP_ENDPOINT"] += "\n" },
		"export headers":       func(values map[string]string) { values["OTEL_EXPORTER_OTLP_HEADERS"] = "authorization=secret" },
		"resource attributes":  func(values map[string]string) { values["OTEL_RESOURCE_ATTRIBUTES"] = "tenant.id=secret" },
		"baggage propagator":   func(values map[string]string) { values["OTEL_PROPAGATORS"] = "tracecontext,baggage" },
		"unbounded sampler":    func(values map[string]string) { values["OTEL_TRACES_SAMPLER"] = "always_on" },
		"noncanonical ratio":   func(values map[string]string) { values["OTEL_TRACES_SAMPLER_ARG"] = "1.0" },
		"not-a-number ratio":   func(values map[string]string) { values["OTEL_TRACES_SAMPLER_ARG"] = "NaN" },
		"leading-zero timeout": func(values map[string]string) { values["PERIAPSIS_OTEL_EXPORT_TIMEOUT_MS"] = "0100" },
		"oversized timeout":    func(values map[string]string) { values["PERIAPSIS_OTEL_EXPORT_TIMEOUT_MS"] = "30001" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			values := cloneMap(valid)
			mutate(values)
			if _, err := LoadConfigFrom("production", "periapsis-api", "release-1", mapLookup(values)); err == nil {
				t.Fatal("hostile configuration accepted")
			}
		})
	}
}

func TestPersistedSpanContextRoundTripAndHostileCorpus(t *testing.T) {
	runtime, exporter := inMemoryRuntime(t)
	state, err := trace.ParseTraceState("vendor=value")
	if err != nil {
		t.Fatal(err)
	}
	remote := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled,
		TraceState: state, Remote: true,
	})
	parent := trace.ContextWithRemoteSpanContext(context.Background(), remote)
	ctx, span := runtime.Tracer().Start(parent, "producer")
	persisted, ok := PersistedSpanContextFromContext(ctx)
	span.End()
	if !ok || persisted.TraceState == nil || *persisted.TraceState != "vendor=value" {
		t.Fatalf("persisted = %#v, ok = %v", persisted, ok)
	}
	parsed, err := ParsePersistedSpanContext(persisted)
	if err != nil || !parsed.IsRemote() || parsed.TraceID() != trace.SpanContextFromContext(ctx).TraceID() || parsed.SpanID() != trace.SpanContextFromContext(ctx).SpanID() {
		t.Fatalf("parsed = %#v, error = %v", parsed, err)
	}
	if len(exporter.GetSpans()) != 1 {
		t.Fatalf("exported spans = %d", len(exporter.GetSpans()))
	}

	empty := ""
	tooLarge := strings.Repeat("a", maximumTraceStateSize+1)
	for name, value := range map[string]PersistedSpanContext{
		"empty":           {},
		"zero trace":      {TraceParent: "00-00000000000000000000000000000000-1111111111111111-01"},
		"zero span":       {TraceParent: "00-11111111111111111111111111111111-0000000000000000-01"},
		"uppercase":       {TraceParent: "00-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-1111111111111111-01"},
		"unknown flags":   {TraceParent: "00-11111111111111111111111111111111-1111111111111111-03"},
		"empty state":     {TraceParent: "00-11111111111111111111111111111111-1111111111111111-01", TraceState: &empty},
		"oversized state": {TraceParent: "00-11111111111111111111111111111111-1111111111111111-01", TraceState: &tooLarge},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePersistedSpanContext(value); err == nil {
				t.Fatal("hostile persisted span context accepted")
			}
		})
	}
}

func TestHTTPMiddlewareUsesBoundedW3CParentAndNeverRecordsRawTarget(t *testing.T) {
	runtime, exporter := inMemoryRuntime(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /tenants/{tenant}/alerts/{alert}", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusServiceUnavailable)
	})
	handler := runtime.WrapHTTP(mux)
	request := httptest.NewRequest(http.MethodGet, "/tenants/secret-tenant/alerts/secret-alert?token=secret", nil)
	request.Header.Set("Traceparent", "00-11111111111111111111111111111111-2222222222222222-01")
	request.Header.Set("Tracestate", "vendor=value")
	handler.ServeHTTP(httptest.NewRecorder(), request)
	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("spans = %d", len(spans))
	}
	span := spans[0]
	if span.Parent.TraceID().String() != "11111111111111111111111111111111" || span.Name != "GET /tenants/{tenant}/alerts/{alert}" {
		t.Fatalf("span parent/name = %s / %q", span.Parent.TraceID(), span.Name)
	}
	serialized := span.Name + attributesText(span.Attributes)
	for _, forbidden := range []string{"secret-tenant", "secret-alert", "token", "vendor=value"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("span contains forbidden input %q: %s", forbidden, serialized)
		}
	}
	if span.Status.Code != codes.Error {
		t.Fatalf("span status = %#v", span.Status)
	}
}

func TestHTTPMiddlewareIgnoresDuplicateMalformedAndOversizedTraceHeaders(t *testing.T) {
	for name, configure := range map[string]func(http.Header){
		"duplicate": func(header http.Header) {
			header.Add("Traceparent", "00-11111111111111111111111111111111-2222222222222222-01")
			header.Add("Traceparent", "00-33333333333333333333333333333333-4444444444444444-01")
		},
		"malformed": func(header http.Header) { header.Set("Traceparent", "hostile") },
		"oversized": func(header http.Header) { header.Set("Traceparent", strings.Repeat("a", 513)) },
		"unknown flags": func(header http.Header) {
			header.Set("Traceparent", "00-11111111111111111111111111111111-2222222222222222-02")
		},
		"invalid state": func(header http.Header) {
			header.Set("Traceparent", "00-11111111111111111111111111111111-2222222222222222-01")
			header.Set("Tracestate", "vendor=value,vendor=duplicate")
		},
	} {
		t.Run(name, func(t *testing.T) {
			runtime, exporter := inMemoryRuntime(t)
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			ambientCtx, ambient := runtime.Tracer().Start(request.Context(), "ambient")
			request = request.WithContext(ambientCtx)
			configure(request.Header)
			runtime.WrapHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(httptest.NewRecorder(), request)
			if spans := exporter.GetSpans(); len(spans) != 1 || spans[0].Parent.IsValid() {
				t.Fatalf("unexpected remote parent: %#v", spans)
			}
			ambient.End()
		})
	}
}

func TestHTTPMiddlewareMarksPanicsWithoutRecordingTheirValue(t *testing.T) {
	runtime, exporter := inMemoryRuntime(t)
	handler := runtime.WrapHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("secret customer payload")
	}))
	func() {
		defer func() { _ = recover() }()
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	}()
	spans := exporter.GetSpans()
	if len(spans) != 1 || spans[0].Status.Code != codes.Error {
		t.Fatalf("panic span = %#v", spans)
	}
	serialized := spans[0].Name + attributesText(spans[0].Attributes)
	if !strings.Contains(serialized, "http.response.status_code=500") {
		t.Fatalf("panic span omitted synthetic 500 status: %s", serialized)
	}
	if strings.Contains(serialized, "secret") || strings.Contains(serialized, "customer") {
		t.Fatalf("panic value leaked: %s", serialized)
	}
}

func TestPGXTracerOmitsSQLArgumentsAndErrorMessages(t *testing.T) {
	runtime, exporter := inMemoryRuntime(t)
	tracer := pgxTracer{tracer: runtime.Tracer()}
	ctx := tracer.TraceQueryStart(context.Background(), nil, pgx.TraceQueryStartData{
		SQL: "SELECT secret FROM private_table WHERE token=$1", Args: []any{"secret-value"},
	})
	tracer.TraceQueryEnd(ctx, nil, pgx.TraceQueryEndData{
		CommandTag: pgconn.NewCommandTag("SELECT 1"),
		Err:        &pgconn.PgError{Code: "23505", Message: "secret-value duplicated"},
	})
	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("spans = %d", len(spans))
	}
	serialized := spans[0].Name + attributesText(spans[0].Attributes)
	for _, forbidden := range []string{"private_table", "secret-value", "duplicated", "token=$1"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("database span contains %q: %s", forbidden, serialized)
		}
	}
	if !strings.Contains(serialized, "postgresql.sqlstate.23505") {
		t.Fatalf("database span lacks bounded SQLSTATE: %s", serialized)
	}
}

func TestInstrumentPGXRejectsTracerReplacement(t *testing.T) {
	runtime, _ := inMemoryRuntime(t)
	config, err := pgxpool.ParseConfig("postgresql://api@localhost/periapsis?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.InstrumentPGX(config); err != nil {
		t.Fatal(err)
	}
	if err := runtime.InstrumentPGX(config); err == nil {
		t.Fatal("existing pgx tracer was replaced")
	}
}

func TestTraceContextLogHandlerAddsOnlyActiveIdentifiers(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(NewTraceContextHandler(slog.NewJSONHandler(&output, nil)))
	runtime, _ := inMemoryRuntime(t)
	ctx, span := runtime.Tracer().Start(context.Background(), "logged")
	logger.InfoContext(ctx, "operation", "outcome", "ok")
	span.End()
	text := output.String()
	spanContext := trace.SpanContextFromContext(ctx)
	for _, required := range []string{spanContext.TraceID().String(), spanContext.SpanID().String(), `"trace_sampled":true`} {
		if !strings.Contains(text, required) {
			t.Fatalf("log lacks %q: %s", required, text)
		}
	}
}

func TestRedactedErrorHandlerNeverLogsErrorValue(t *testing.T) {
	var output bytes.Buffer
	redactedErrorHandler{logger: slog.New(slog.NewJSONHandler(&output, nil))}.Handle(errors.New("secret endpoint token"))
	if strings.Contains(output.String(), "secret") || strings.Contains(output.String(), "token") {
		t.Fatalf("error value leaked: %s", output.String())
	}
}

func TestOTLPHTTPExporterFlushesOnBoundedShutdown(t *testing.T) {
	requestSeen := make(chan []byte, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/traces" || request.Header.Get("Content-Type") != "application/x-protobuf" {
			t.Errorf("OTLP request = %s %s %q", request.Method, request.URL.Path, request.Header.Get("Content-Type"))
		}
		reader := io.Reader(request.Body)
		if request.Header.Get("Content-Encoding") == "gzip" {
			gzipReader, err := gzip.NewReader(request.Body)
			if err != nil {
				t.Errorf("gzip reader: %v", err)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			defer gzipReader.Close()
			reader = gzipReader
		}
		body, err := io.ReadAll(io.LimitReader(reader, 1<<20))
		if err != nil {
			t.Errorf("read OTLP body: %v", err)
		}
		requestSeen <- body
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runtime, err := Start(ctx, Config{
		Enabled: true, Endpoint: server.URL, Environment: "test",
		ExportTimeout: time.Second, SampleRatio: 1,
		ServiceName: "periapsis-api", Version: "test", validated: true,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	_, span := runtime.Tracer().Start(context.Background(), "bounded.operation")
	span.End()
	if err := runtime.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	select {
	case body := <-requestSeen:
		if len(body) == 0 {
			t.Fatal("empty OTLP payload")
		}
	case <-ctx.Done():
		t.Fatal("OTLP payload was not flushed")
	}
}

func TestRuntimeShutdownIsIdempotent(t *testing.T) {
	var calls atomic.Int32
	runtime := &Runtime{
		enabled:  true,
		provider: trace.NewNoopTracerProvider(),
		shutdown: func(context.Context) error { calls.Add(1); return nil },
	}
	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("shutdown calls = %d", calls.Load())
	}
}

func TestRuntimeShutdownKeepsConcurrentCallerDeadlinesBounded(t *testing.T) {
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	runtime := &Runtime{
		enabled:  true,
		provider: trace.NewNoopTracerProvider(),
		shutdown: func(context.Context) error {
			calls.Add(1)
			close(entered)
			<-release
			return nil
		},
	}
	first := make(chan error, 1)
	go func() { first <- runtime.Shutdown(context.Background()) }()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := runtime.Shutdown(ctx); err == nil || time.Since(started) > time.Second {
		t.Fatalf("concurrent bounded shutdown error = %v, duration = %v", err, time.Since(started))
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("first shutdown error = %v", err)
	}
	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatalf("completed shutdown error = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("shutdown calls = %d", calls.Load())
	}
}

func inMemoryRuntime(t *testing.T) (*Runtime, *tracetest.InMemoryExporter) {
	t.Helper()
	exporter := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSyncer(exporter),
	)
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	return &Runtime{
		enabled: true, provider: provider, propagator: boundedTraceContextPropagator{},
		shutdown: provider.Shutdown,
	}, exporter
}

func mapLookup(values map[string]string) EnvironmentLookup {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func cloneMap(input map[string]string) map[string]string {
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func attributesText(attributes []attribute.KeyValue) string {
	var builder strings.Builder
	for _, item := range attributes {
		builder.WriteString(string(item.Key))
		builder.WriteByte('=')
		builder.WriteString(item.Value.Emit())
		builder.WriteByte('\n')
	}
	return builder.String()
}
