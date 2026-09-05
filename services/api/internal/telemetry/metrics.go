package telemetry

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var httpDurationBuckets = [...]float64{
	0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
}

// Metrics owns API process metrics. Labels are derived only from a closed HTTP
// method set, response classes, and registered ServeMux route templates.
type Metrics struct {
	mu             sync.Mutex
	http           map[httpMetricKey]*httpMetricValue
	authentication map[string]uint64
}

type httpMetricKey struct {
	method      string
	route       string
	statusClass string
}

type httpMetricValue struct {
	count   uint64
	sum     float64
	buckets [len(httpDurationBuckets)]uint64
}

func NewMetrics() *Metrics {
	return &Metrics{
		http: make(map[httpMetricKey]*httpMetricValue),
		authentication: map[string]uint64{
			"success": 0, "failed": 0, "throttled": 0, "unavailable": 0,
		},
	}
}

// Handler serves process metrics without caching or content sniffing. It is
// intentionally unauthenticated for a network-policy-restricted scraper.
func (m *Metrics) Handler() http.Handler {
	if m == nil {
		panic("telemetry: metrics registry is required")
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			writer.Header().Set("Allow", http.MethodGet)
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(m.RenderPrometheus()))
	})
}

// WrapHTTP records one result after the downstream handler has selected a
// registered pattern. Raw URL paths and query strings are never retained.
func (m *Metrics) WrapHTTP(next http.Handler) http.Handler {
	if next == nil {
		panic("telemetry: metrics HTTP handler is required")
	}
	if m == nil {
		return next
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started := time.Now()
		recorder := &metricResponseWriter{ResponseWriter: writer, status: http.StatusOK}
		defer func() {
			panicked := recover()
			status := recorder.status
			if panicked != nil {
				status = http.StatusInternalServerError
			}
			m.observeHTTP(
				canonicalHTTPMethod(request.Method),
				canonicalMetricRoute(request.Pattern),
				statusClass(status),
				time.Since(started),
			)
			m.observeAuthentication(request.Pattern, status)
			if panicked != nil {
				panic(panicked)
			}
		}()
		next.ServeHTTP(recorder, request)
	})
}

func (m *Metrics) observeAuthentication(pattern string, status int) {
	if m == nil || pattern != "POST /api/v1/auth/login" && pattern != "POST /api/v1/auth/mfa" {
		return
	}
	outcome := "failed"
	switch {
	case status >= 200 && status <= 299:
		outcome = "success"
	case status == http.StatusTooManyRequests:
		outcome = "throttled"
	case status >= 500 && status <= 599:
		outcome = "unavailable"
	}
	m.mu.Lock()
	if m.authentication == nil {
		m.authentication = make(map[string]uint64)
	}
	m.authentication[outcome]++
	m.mu.Unlock()
}

func (m *Metrics) observeHTTP(method, route, class string, elapsed time.Duration) {
	if m == nil {
		return
	}
	key := httpMetricKey{method: method, route: route, statusClass: class}
	seconds := max(0, elapsed.Seconds())
	m.mu.Lock()
	if m.http == nil {
		m.http = make(map[httpMetricKey]*httpMetricValue)
	}
	value := m.http[key]
	if value == nil {
		value = &httpMetricValue{}
		m.http[key] = value
	}
	value.count++
	value.sum += seconds
	for index, upperBound := range httpDurationBuckets {
		if seconds <= upperBound {
			value.buckets[index]++
		}
	}
	m.mu.Unlock()
}

// RenderPrometheus returns a deterministic Prometheus 0.0.4 exposition.
func (m *Metrics) RenderPrometheus() string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	rows := make([]struct {
		key   httpMetricKey
		value httpMetricValue
	}, 0, len(m.http))
	for key, value := range m.http {
		if value != nil {
			rows = append(rows, struct {
				key   httpMetricKey
				value httpMetricValue
			}{key: key, value: *value})
		}
	}
	authentication := make(map[string]uint64, len(m.authentication))
	for outcome, count := range m.authentication {
		authentication[outcome] = count
	}
	m.mu.Unlock()
	sort.Slice(rows, func(left, right int) bool {
		return metricKeyText(rows[left].key) < metricKeyText(rows[right].key)
	})

	var output strings.Builder
	output.WriteString("# HELP periapsis_authentication_attempt_total Local authentication step attempts by bounded outcome.\n")
	output.WriteString("# TYPE periapsis_authentication_attempt_total counter\n")
	for _, outcome := range []string{"success", "failed", "throttled", "unavailable"} {
		fmt.Fprintf(
			&output,
			"periapsis_authentication_attempt_total{outcome=\"%s\"} %d\n",
			outcome, authentication[outcome],
		)
	}
	output.WriteString("# HELP periapsis_http_requests_total API HTTP requests by registered route and response class.\n")
	output.WriteString("# TYPE periapsis_http_requests_total counter\n")
	for _, row := range rows {
		fmt.Fprintf(
			&output,
			"periapsis_http_requests_total{service=\"api\",method=\"%s\",route=\"%s\",status_class=\"%s\"} %d\n",
			row.key.method, row.key.route, row.key.statusClass, row.value.count,
		)
	}
	output.WriteString("# HELP periapsis_http_request_duration_seconds API HTTP request duration by registered route and response class.\n")
	output.WriteString("# TYPE periapsis_http_request_duration_seconds histogram\n")
	for _, row := range rows {
		labels := fmt.Sprintf(
			"service=\"api\",method=\"%s\",route=\"%s\",status_class=\"%s\"",
			row.key.method, row.key.route, row.key.statusClass,
		)
		for index, upperBound := range httpDurationBuckets {
			fmt.Fprintf(
				&output,
				"periapsis_http_request_duration_seconds_bucket{%s,le=\"%s\"} %d\n",
				labels, strconv.FormatFloat(upperBound, 'f', -1, 64), row.value.buckets[index],
			)
		}
		fmt.Fprintf(
			&output,
			"periapsis_http_request_duration_seconds_bucket{%s,le=\"+Inf\"} %d\n",
			labels, row.value.count,
		)
		fmt.Fprintf(
			&output,
			"periapsis_http_request_duration_seconds_sum{%s} %s\n",
			labels, strconv.FormatFloat(row.value.sum, 'f', 9, 64),
		)
		fmt.Fprintf(
			&output,
			"periapsis_http_request_duration_seconds_count{%s} %d\n",
			labels, row.value.count,
		)
	}
	return output.String()
}

type metricResponseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *metricResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *metricResponseWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func (w *metricResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func canonicalMetricRoute(pattern string) string {
	canonical := canonicalRoutePattern(pattern)
	if canonical == "" {
		return "unmatched"
	}
	_, route, found := strings.Cut(canonical, " ")
	if found {
		return route
	}
	return canonical
}

func statusClass(status int) string {
	if status >= 100 && status <= 599 {
		return strconv.Itoa(status/100) + "xx"
	}
	return "other"
}

func metricKeyText(key httpMetricKey) string {
	return key.method + "\x00" + key.route + "\x00" + key.statusClass
}
