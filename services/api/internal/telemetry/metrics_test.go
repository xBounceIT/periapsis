package telemetry

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPMetricsUseRegisteredPatternsAndFixedLabels(t *testing.T) {
	metrics := NewMetrics()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/tenants/{tenantId}/alerts/{alertId}", func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("secret") == "" {
			t.Fatal("test request query was not available to the application")
		}
		writer.WriteHeader(http.StatusCreated)
	})
	handler := metrics.WrapHTTP(mux)
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/tenants/tenant-secret/alerts/alert-secret?secret=query-secret",
		nil,
	)
	handler.ServeHTTP(httptest.NewRecorder(), request)

	output := metrics.RenderPrometheus()
	for _, expected := range []string{
		`periapsis_http_requests_total{service="api",method="GET",route="/api/v1/tenants/{tenantId}/alerts/{alertId}",status_class="2xx"} 1`,
		`periapsis_http_request_duration_seconds_bucket{service="api",method="GET",route="/api/v1/tenants/{tenantId}/alerts/{alertId}",status_class="2xx",le="+Inf"} 1`,
		`periapsis_http_request_duration_seconds_count{service="api",method="GET",route="/api/v1/tenants/{tenantId}/alerts/{alertId}",status_class="2xx"} 1`,
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("metrics output missing %q:\n%s", expected, output)
		}
	}
	for _, forbidden := range []string{"tenant-secret", "alert-secret", "query-secret"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("metrics output exposed %q: %s", forbidden, output)
		}
	}
}

func TestHTTPMetricsAggregateUnmatchedAndHostileMethods(t *testing.T) {
	metrics := NewMetrics()
	handler := metrics.WrapHTTP(http.NotFoundHandler())
	request := httptest.NewRequest(http.MethodGet, "/private/customer/path", nil)
	request.Method = "CUSTOM\r\nSECRET"
	handler.ServeHTTP(
		httptest.NewRecorder(),
		request,
	)
	output := metrics.RenderPrometheus()
	if !strings.Contains(output, `method="OTHER",route="unmatched",status_class="4xx"} 1`) {
		t.Fatalf("unmatched metrics were not bounded: %s", output)
	}
	if strings.Contains(output, "CUSTOM") || strings.Contains(output, "/private/customer/path") {
		t.Fatalf("unmatched metrics retained caller input: %s", output)
	}
}

func TestHTTPMetricsBucketsAreCumulativeAndDeterministic(t *testing.T) {
	metrics := NewMetrics()
	metrics.observeHTTP("GET", "/health/live", "2xx", 25*time.Millisecond)
	metrics.observeHTTP("GET", "/health/live", "2xx", 2*time.Second)
	first := metrics.RenderPrometheus()
	second := metrics.RenderPrometheus()
	if first != second {
		t.Fatal("metrics rendering changed without an observation")
	}
	for _, expected := range []string{
		`le="0.01"} 0`,
		`le="0.025"} 1`,
		`le="1"} 1`,
		`le="2.5"} 2`,
		`le="+Inf"} 2`,
		`_count{service="api",method="GET",route="/health/live",status_class="2xx"} 2`,
	} {
		if !strings.Contains(first, expected) {
			t.Fatalf("cumulative histogram missing %q:\n%s", expected, first)
		}
	}
}

func TestHTTPMetricsRecordAndRethrowPanics(t *testing.T) {
	metrics := NewMetrics()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /panic", func(http.ResponseWriter, *http.Request) {
		panic("private panic material")
	})
	handler := metrics.WrapHTTP(mux)
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("panic was swallowed")
			}
		}()
		handler.ServeHTTP(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/panic", nil),
		)
	}()
	output := metrics.RenderPrometheus()
	if !strings.Contains(output, `method="GET",route="/panic",status_class="5xx"} 1`) ||
		strings.Contains(output, "private panic material") {
		t.Fatalf("panic metrics were not bounded: %s", output)
	}
}

func TestHTTPMetricsCountOnlyAuthenticationStepRoutes(t *testing.T) {
	metrics := NewMetrics()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/login", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
	})
	mux.HandleFunc("POST /api/v1/auth/mfa", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusTooManyRequests)
	})
	mux.HandleFunc("GET /api/v1/auth/session", func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
	})
	handler := metrics.WrapHTTP(mux)
	for method, target := range map[string]string{
		http.MethodPost: "/api/v1/auth/login",
		"MFA":           "/api/v1/auth/mfa",
		http.MethodGet:  "/api/v1/auth/session",
	} {
		actualMethod := method
		if method == "MFA" {
			actualMethod = http.MethodPost
		}
		handler.ServeHTTP(
			httptest.NewRecorder(),
			httptest.NewRequest(actualMethod, target, nil),
		)
	}
	output := metrics.RenderPrometheus()
	for _, expected := range []string{
		`periapsis_authentication_attempt_total{outcome="success"} 0`,
		`periapsis_authentication_attempt_total{outcome="failed"} 1`,
		`periapsis_authentication_attempt_total{outcome="throttled"} 1`,
		`periapsis_authentication_attempt_total{outcome="unavailable"} 0`,
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("authentication metrics missing %q:\n%s", expected, output)
		}
	}
}

func TestMetricsHandlerUsesPrometheusHeadersAndRejectsMutatingMethods(t *testing.T) {
	metrics := NewMetrics()
	get := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if get.Code != http.StatusOK ||
		get.Header().Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" ||
		get.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(get.Body.String(), "periapsis_http_requests_total") {
		t.Fatalf("GET metrics response = %d %#v %q", get.Code, get.Header(), get.Body.String())
	}

	post := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if post.Code != http.StatusMethodNotAllowed || post.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("POST metrics response = %d %#v", post.Code, post.Header())
	}
}
