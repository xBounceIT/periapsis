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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres"
	"github.com/periapsis-im/periapsis/services/api/internal/telemetry"
)

type fixedChecker struct {
	ready bool
}

type countingChecker struct {
	calls int
	ready bool
}

type cancellationIsolatedChecker struct {
	entered  chan struct{}
	release  chan struct{}
	canceled chan bool
}

type blockingCountingChecker struct {
	ready   atomic.Bool
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *blockingCountingChecker) Check(ctx context.Context) []postgres.DependencyCheck {
	c.calls.Add(1)
	c.once.Do(func() { close(c.entered) })
	select {
	case <-ctx.Done():
		return []postgres.DependencyCheck{{Name: "postgresql", Ready: false}}
	case <-c.release:
		return []postgres.DependencyCheck{{Name: "postgresql", Ready: c.ready.Load()}}
	}
}

type mutableChecker struct {
	ready atomic.Bool
	calls atomic.Int32
}

func (c *mutableChecker) Check(context.Context) []postgres.DependencyCheck {
	c.calls.Add(1)
	return []postgres.DependencyCheck{{Name: "postgresql", Ready: c.ready.Load()}}
}

type blockingResponseWriter struct {
	*httptest.ResponseRecorder
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (w *blockingResponseWriter) WriteHeader(status int) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	w.ResponseRecorder.WriteHeader(status)
}

func (c cancellationIsolatedChecker) Check(ctx context.Context) []postgres.DependencyCheck {
	close(c.entered)
	select {
	case <-ctx.Done():
		c.canceled <- true
		return []postgres.DependencyCheck{{Name: "postgresql", Ready: false}}
	case <-c.release:
		c.canceled <- false
		return []postgres.DependencyCheck{{Name: "postgresql", Ready: true}}
	}
}

func (c *countingChecker) Check(context.Context) []postgres.DependencyCheck {
	c.calls++
	return []postgres.DependencyCheck{{Name: "postgresql", Ready: c.ready}}
}

func (c fixedChecker) Check(context.Context) []postgres.DependencyCheck {
	return []postgres.DependencyCheck{{
		Name:    "postgresql",
		Ready:   c.ready,
		Latency: time.Millisecond,
	}}
}

func TestLivenessUsesGeneratedContract(t *testing.T) {
	router := newTestRouter(true)
	request := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if _, err := uuid.Parse(response.Header().Get(requestIDHeader)); err != nil {
		t.Fatalf("X-Request-ID is not a UUID: %v", err)
	}
	var body contract.Liveness
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Status != contract.Alive || body.Version != "test" {
		t.Fatalf("body = %#v", body)
	}
}

func TestReadinessFailsClosed(t *testing.T) {
	router := newTestRouter(false)
	request := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if got := response.Header().Get("Content-Type"); got != "application/problem+json; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := response.Header().Get("Retry-After"); got != "5" {
		t.Fatalf("Retry-After = %q", got)
	}
}

func TestStatusReportsDegradedWithoutLeakingDependencyErrors(t *testing.T) {
	router := newTestRouter(false)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	var body contract.SystemStatus
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Status != contract.SystemStatusStatusDegraded {
		t.Fatalf("status = %q, want degraded", body.Status)
	}
}

func TestSystemStatusUsesOnlyTheLastActiveReadinessSnapshot(t *testing.T) {
	checker := &countingChecker{ready: true}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewHandler(checker, logger, "test", time.Second)
	router := Router(handler, logger, false)

	statusResponse := httptest.NewRecorder()
	router.ServeHTTP(
		statusResponse,
		httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil),
	)
	if checker.calls != 0 {
		t.Fatalf("anonymous system status performed %d active checks", checker.calls)
	}
	var initial contract.SystemStatus
	if err := json.NewDecoder(statusResponse.Body).Decode(&initial); err != nil {
		t.Fatalf("decode initial status: %v", err)
	}
	if initial.Status != contract.SystemStatusStatusDegraded {
		t.Fatalf("initial status = %q, want degraded", initial.Status)
	}
	repeatedResponse := httptest.NewRecorder()
	router.ServeHTTP(
		repeatedResponse,
		httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil),
	)
	var repeated contract.SystemStatus
	if err := json.NewDecoder(repeatedResponse.Body).Decode(&repeated); err != nil {
		t.Fatalf("decode repeated status: %v", err)
	}
	if !repeated.CheckedAt.Equal(initial.CheckedAt) || checker.calls != 0 {
		t.Fatalf(
			"repeated snapshot checkedAt = %s, initial = %s, active checks = %d",
			repeated.CheckedAt, initial.CheckedAt, checker.calls,
		)
	}

	readyResponse := httptest.NewRecorder()
	router.ServeHTTP(
		readyResponse,
		httptest.NewRequest(http.MethodGet, "/health/ready", nil),
	)
	if readyResponse.Code != http.StatusOK || checker.calls != 1 {
		t.Fatalf("readiness status = %d, checks = %d", readyResponse.Code, checker.calls)
	}
	statusResponse = httptest.NewRecorder()
	router.ServeHTTP(
		statusResponse,
		httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil),
	)
	var refreshed contract.SystemStatus
	if err := json.NewDecoder(statusResponse.Body).Decode(&refreshed); err != nil {
		t.Fatalf("decode refreshed status: %v", err)
	}
	if refreshed.Status != contract.SystemStatusStatusReady || checker.calls != 1 {
		t.Fatalf("refreshed status = %q, active checks = %d", refreshed.Status, checker.calls)
	}
}

func TestCanceledReadinessLeaderCannotCancelTheSharedDependencyCheck(t *testing.T) {
	checker := cancellationIsolatedChecker{
		entered: make(chan struct{}), release: make(chan struct{}), canceled: make(chan bool, 1),
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewHandler(checker, logger, "test", time.Second)
	parent, cancel := context.WithCancel(context.Background())
	request := httptest.NewRequest(http.MethodGet, "/health/ready", nil).WithContext(parent)
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		handler.GetReadiness(response, request)
		close(done)
	}()
	<-checker.entered
	cancel()
	select {
	case <-done:
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("canceled readiness status = %d, want unavailable", response.Code)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled readiness caller did not abandon the shared check")
	}
	close(checker.release)
	if wasCanceled := <-checker.canceled; wasCanceled {
		t.Fatal("shared dependency context was canceled by the elected requester")
	}
	followup := httptest.NewRecorder()
	handler.GetReadiness(followup, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if followup.Code != http.StatusOK {
		t.Fatalf("readiness after canceled leader = %d: %s", followup.Code, followup.Body.String())
	}
}

func TestConcurrentReadinessRequestsShareOneDependencyCheck(t *testing.T) {
	checker := &blockingCountingChecker{entered: make(chan struct{}), release: make(chan struct{})}
	checker.ready.Store(true)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewHandler(checker, logger, "test", time.Second)

	const callers = 32
	results := make(chan int, callers)
	for range callers {
		go func() {
			response := httptest.NewRecorder()
			handler.GetReadiness(response, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
			results <- response.Code
		}()
	}
	<-checker.entered
	close(checker.release)
	for range callers {
		if status := <-results; status != http.StatusOK {
			t.Fatalf("readiness status = %d, want OK", status)
		}
	}
	if calls := checker.calls.Load(); calls != 1 {
		t.Fatalf("dependency checks = %d, want one", calls)
	}
}

func TestLateCachedReadinessResponseCannotOverwriteNewerSnapshot(t *testing.T) {
	checker := &mutableChecker{}
	checker.ready.Store(true)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewHandler(checker, logger, "test", time.Second)
	if snapshot, err := handler.readiness(context.Background()); err != nil || !snapshot.ready {
		t.Fatalf("initial readiness = (%v, %v), want ready", snapshot, err)
	}

	lateWriter := &blockingResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
		entered:          make(chan struct{}),
		release:          make(chan struct{}),
	}
	lateDone := make(chan struct{})
	go func() {
		handler.GetReadiness(lateWriter, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
		close(lateDone)
	}()
	<-lateWriter.entered

	oldSnapshot := handler.readinessSnapshot.Load()
	expiredSnapshot := *oldSnapshot
	expiredSnapshot.expiresAt = expiredSnapshot.checkedAt
	handler.readinessSnapshot.Store(&expiredSnapshot)
	checker.ready.Store(false)
	newerResponse := httptest.NewRecorder()
	handler.GetReadiness(newerResponse, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if newerResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("newer readiness status = %d, want unavailable", newerResponse.Code)
	}
	newerSnapshot := handler.readinessSnapshot.Load()
	if newerSnapshot.ready {
		t.Fatal("newer readiness snapshot unexpectedly ready")
	}

	close(lateWriter.release)
	<-lateDone
	if current := handler.readinessSnapshot.Load(); current != newerSnapshot || current.ready {
		t.Fatal("late cached response overwrote the newer unavailable snapshot")
	}
}

func TestRequestDeadlineReachesUseCasesAndReturnsProblemDetails(t *testing.T) {
	deadlineObserved := make(chan struct{}, 1)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Context().Deadline(); !ok {
			t.Error("request context has no deadline")
		}
		deadlineObserved <- struct{}{}
		<-r.Context().Done()
		writeProblem(
			w, r, http.StatusServiceUnavailable, "service_unavailable",
			"Service unavailable", "The request deadline expired.",
		)
	})
	router := requestIDMiddleware(requestTimeoutMiddleware(5*time.Millisecond, next))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)
	<-deadlineObserved

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if contentType := response.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "application/problem+json") {
		t.Fatalf("Content-Type = %q, want RFC 9457 problem", contentType)
	}
	var problem contract.Problem
	if err := json.NewDecoder(response.Body).Decode(&problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Code != "service_unavailable" || problem.RequestId == uuid.Nil {
		t.Fatalf("problem = %#v", problem)
	}
}

func TestRequestIDMiddlewareAcceptsOnlyOneUUIDv7(t *testing.T) {
	t.Parallel()
	accepted := uuid.Must(uuid.NewV7())

	for _, test := range []struct {
		name       string
		values     []string
		want       uuid.UUID
		regenerate bool
	}{
		{name: "missing", regenerate: true},
		{name: "malformed", values: []string{"not-a-uuid"}, regenerate: true},
		{name: "version four", values: []string{uuid.NewString()}, regenerate: true},
		{name: "duplicate", values: []string{accepted.String(), accepted.String()}, regenerate: true},
		{name: "version seven", values: []string{accepted.String()}, want: accepted},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var contextValue string
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				contextValue = requestIDFromContext(r.Context())
				w.WriteHeader(http.StatusNoContent)
			})
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			for _, value := range test.values {
				request.Header.Add(requestIDHeader, value)
			}
			response := httptest.NewRecorder()

			requestIDMiddleware(next).ServeHTTP(response, request)

			responseID, err := uuid.Parse(response.Header().Get(requestIDHeader))
			if err != nil || responseID.Version() != 7 || responseID.Variant() != uuid.RFC4122 ||
				contextValue != responseID.String() {
				t.Fatalf("request ID = %q / %q: %v", responseID, contextValue, err)
			}
			if test.regenerate && responseID == accepted || !test.regenerate && responseID != test.want {
				t.Fatalf("request ID = %s, regenerate=%t, want=%s", responseID, test.regenerate, test.want)
			}
		})
	}
}

func TestRouterMountsMetricsInsideTheRegisteredRouteBoundary(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewHandler(fixedChecker{ready: true}, logger, "test", time.Second)
	metrics := telemetry.NewMetrics()
	router := Router(handler, logger, false, RouterObservability{Metrics: metrics})

	health := httptest.NewRecorder()
	router.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d", health.Code)
	}

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if response.Code != http.StatusOK ||
		response.Header().Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" ||
		response.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(
			response.Body.String(),
			`method="GET",route="/health/live",status_class="2xx"} 1`,
		) {
		t.Fatalf("metrics response = %d %#v %q", response.Code, response.Header(), response.Body.String())
	}

	methodNotAllowed := httptest.NewRecorder()
	router.ServeHTTP(methodNotAllowed, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if methodNotAllowed.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /metrics status = %d, want 405", methodNotAllowed.Code)
	}
}

func TestAccessLogUsesRouteTemplatesAndOmitsRawURLs(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	handler := NewHandler(fixedChecker{ready: true}, logger, "test", time.Second)
	router := Router(handler, logger, false)
	tenantID := "0198c97d-cf4f-7000-8000-00000000a001"
	alertID := "0198c97d-cf4f-7000-8000-00000000a002"
	rawTarget := "/api/v1/tenants/" + tenantID + "/alerts/" + alertID + "?secret=query-secret"
	router.ServeHTTP(
		httptest.NewRecorder(),
		httptest.NewRequest(http.MethodGet, rawTarget, nil),
	)

	output := logs.String()
	if !strings.Contains(output, `"route":"GET /api/v1/tenants/{tenantId}/alerts/{alertId}"`) {
		t.Fatalf("access log omitted route template: %s", output)
	}
	for _, forbidden := range []string{tenantID, alertID, "query-secret", `"path"`} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("access log exposed %q: %s", forbidden, output)
		}
	}
}

func newTestRouter(ready bool) http.Handler {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewHandler(fixedChecker{ready: ready}, logger, "test", time.Second)
	return Router(handler, logger, false)
}
