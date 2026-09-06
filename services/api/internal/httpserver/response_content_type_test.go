package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/telemetry"
	"go.opentelemetry.io/otel/trace"
)

func TestResponseWrappersPreserveJSONSecurityAtDecoderBoundaries(t *testing.T) {
	tracing := responseBoundaryTracing(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	const hostile = `<script>alert("response-boundary")</script><svg onload=alert(1)>&`
	for _, decoder := range []struct {
		name   string
		decode func(*http.Request, any) error
	}{
		{"authentication", decodeJSONBody},
		{"authorization", func(request *http.Request, destination any) error {
			return decodeAuthorizationBody(request, destination, "application/json")
		}},
	} {
		for _, invalid := range []bool{false, true} {
			name := decoder.name + "/json"
			if invalid {
				name = decoder.name + "/problem"
			}
			t.Run(name, func(t *testing.T) {
				field := "value"
				if invalid {
					field = hostile
				}
				body, err := json.Marshal(map[string]string{field: hostile})
				if err != nil {
					t.Fatal("encode synthetic request")
				}
				metrics := telemetry.NewMetrics()
				handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
					if !trace.SpanFromContext(request.Context()).IsRecording() {
						t.Error("trace response wrapper was not enabled")
					}
					var value struct {
						Value string `json:"value"`
					}
					if decodeErr := decoder.decode(request, &value); decodeErr != nil {
						writeProblem(writer, request, http.StatusBadRequest, "invalid_request", "Invalid request", decodeErr.Error())
						return
					}
					writeJSON(writer, http.StatusOK, value)
				})
				// Same response-writer nesting as Router: tracing -> access log -> metrics.
				wrapped := securityHeadersMiddleware(tracing.WrapHTTP(accessLogMiddleware(logger, metrics.WrapHTTP(handler))))
				request := httptest.NewRequest(http.MethodPost, "/response-boundary", bytes.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				response := httptest.NewRecorder()
				wrapped.ServeHTTP(response, request)
				expectedType, expectedStatus := "application/json; charset=utf-8", http.StatusOK
				if invalid {
					expectedType, expectedStatus = "application/problem+json; charset=utf-8", http.StatusBadRequest
				}
				if response.Code != expectedStatus || response.Header().Get("Content-Type") != expectedType || response.Header().Get("X-Content-Type-Options") != "nosniff" {
					t.Fatal("JSON response lost its status, media type or nosniff boundary")
				}
				if strings.ContainsAny(response.Body.String(), "<>&") {
					t.Fatal("JSON response contains unescaped HTML metacharacters")
				}
				if response.Header().Get("Content-Security-Policy") != "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'" {
					t.Fatal("API response lost its restrictive CSP")
				}
				if invalid {
					var problem contract.Problem
					if json.Unmarshal(response.Body.Bytes(), &problem) != nil || problem.Code != "invalid_request" || problem.Status != expectedStatus || problem.Detail == nil || problem.Instance == nil || *problem.Instance != request.URL.Path {
						t.Fatal("Problem Details contract changed")
					}
					if decoder.name == "authentication" && !strings.Contains(*problem.Detail, "<script>") {
						t.Fatal("test no longer exercises reflected decoder input as JSON data")
					}
					if response.Header().Get("Cache-Control") != "no-store" {
						t.Fatal("problem caching policy changed")
					}
				} else {
					var decoded struct {
						Value string `json:"value"`
					}
					if json.Unmarshal(response.Body.Bytes(), &decoded) != nil || decoded.Value != hostile {
						t.Fatal("wrapper corrupted the JSON value through double escaping")
					}
				}
				if !strings.Contains(metrics.RenderPrometheus(), "periapsis_http_requests_total{") {
					t.Fatal("metrics response wrapper was not exercised")
				}
			})
		}
	}
}

func TestResponseWrappersDoNotRewriteDeclaredResponseFormats(t *testing.T) {
	tracing := responseBoundaryTracing(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, format := range []struct{ name, contentType, body string }{
		{"plaintext", "text/plain; charset=utf-8", "<script>text only</script>&\n"},
		{"metrics", "text/plain; version=0.0.4; charset=utf-8", "# HELP fixture <bounded> & literal\nfixture_total 1\n"},
		{"events", "text/event-stream", "event: fixture\ndata: {\"value\":\"<bounded>&\"}\n\n"},
		{"trusted-html", "text/html; charset=utf-8", "<!doctype html><form method=post></form>"},
	} {
		t.Run(format.name, func(t *testing.T) {
			for _, explicitStatus := range []bool{false, true} {
				metrics := telemetry.NewMetrics()
				handler := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
					writer.Header().Set("Content-Type", format.contentType)
					if explicitStatus {
						writer.WriteHeader(http.StatusAccepted)
					}
					if _, err := writer.Write([]byte(format.body)); err != nil {
						t.Error("write response fixture")
					}
				})
				wrapped := securityHeadersMiddleware(tracing.WrapHTTP(accessLogMiddleware(logger, metrics.WrapHTTP(handler))))
				response := httptest.NewRecorder()
				wrapped.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/response-boundary", nil))
				expectedStatus := http.StatusOK
				if explicitStatus {
					expectedStatus = http.StatusAccepted
				}
				if response.Code != expectedStatus || response.Header().Get("Content-Type") != format.contentType || response.Header().Get("X-Content-Type-Options") != "nosniff" || response.Body.String() != format.body {
					t.Fatal("transparent response wrapper rewrote the declared format, bytes or status")
				}
			}
		})
	}
}

func responseBoundaryTracing(t *testing.T) *telemetry.Runtime {
	t.Helper()
	collector := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, io.LimitReader(request.Body, 1<<20))
		writer.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(collector.Close)
	values := map[string]string{
		"OTEL_SDK_DISABLED": "false", "OTEL_SERVICE_NAME": "periapsis-api",
		"OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf", "OTEL_EXPORTER_OTLP_ENDPOINT": collector.URL,
		"OTEL_TRACES_SAMPLER_ARG": "1",
	}
	config, err := telemetry.LoadConfigFrom("test", "periapsis-api", "response-boundary-test", func(name string) (string, bool) { value, ok := values[name]; return value, ok })
	if err != nil {
		t.Fatal("configure local response-boundary tracing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runtime, err := telemetry.Start(ctx, config, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal("start local response-boundary tracing")
	}
	t.Cleanup(func() {
		shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if runtime.Shutdown(shutdown) != nil {
			t.Error("stop local response-boundary tracing")
		}
	})
	return runtime
}
