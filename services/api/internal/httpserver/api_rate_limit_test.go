package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/apiratelimit"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
)

type apiRateLimiterStub struct {
	requests []apiratelimit.Request
	decision apiratelimit.Decision
	err      error
}

func (s *apiRateLimiterStub) Admit(
	_ context.Context,
	request apiratelimit.Request,
) (apiratelimit.Decision, error) {
	s.requests = append(s.requests, request)
	return s.decision, s.err
}

func TestAPIRateLimitMiddlewareUsesTrustedNetworkCredentialAndTenantTuple(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	limiter := &apiRateLimiterStub{decision: apiratelimit.Decision{Admitted: true}}
	handler := &Handler{
		cookie:         sessionCookiePolicy{name: developmentCookie},
		trustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}
	nextCalls := 0
	middleware := apiRateLimitMiddleware(handler, limiter, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalls++
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/alerts", nil)
	request.RemoteAddr = "10.0.0.4:443"
	request.Header.Set("X-Forwarded-For", "2001:db8:1234:5678:abcd::99, 10.0.0.3")
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session-token"})
	response := httptest.NewRecorder()

	middleware.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent || nextCalls != 1 || len(limiter.requests) != 1 {
		t.Fatalf("response = %d, next = %d, admissions = %d", response.Code, nextCalls, len(limiter.requests))
	}
	got := limiter.requests[0]
	if got.ClientNetwork != netip.MustParsePrefix("2001:db8:1234:5678::/64") ||
		got.Credential != "opaque-session-token" || got.TenantID == nil || *got.TenantID != tenantID {
		t.Fatalf("admission request = %#v", got)
	}
}

func TestAPIRateLimitMiddlewareReturnsRFCProblemAndIntegerRetryAfter(t *testing.T) {
	limiter := &apiRateLimiterStub{decision: apiratelimit.Decision{RetryAfterSeconds: 2}}
	handler := &Handler{cookie: sessionCookiePolicy{name: developmentCookie}}
	middleware := requestIDMiddleware(apiRateLimitMiddleware(handler, limiter, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("denied request reached the application handler")
	})))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil)
	request.RemoteAddr = "198.51.100.4:443"
	response := httptest.NewRecorder()

	middleware.ServeHTTP(response, request)

	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "2" ||
		response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Content-Type") != "application/problem+json; charset=utf-8" {
		t.Fatalf("response = %d %#v", response.Code, response.Header())
	}
	var problem contract.Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil ||
		problem.Status != http.StatusTooManyRequests || problem.Code != "rate_limited" ||
		problem.RequestId == uuid.Nil || problem.Type != "about:blank" {
		t.Fatalf("problem = %#v, %v", problem, err)
	}
}

func TestAPIRateLimitMiddlewareFailsClosed(t *testing.T) {
	for name, test := range map[string]struct {
		limiter    *apiRateLimiterStub
		mutate     func(*http.Request)
		wantStatus int
	}{
		"database unavailable": {
			limiter: &apiRateLimiterStub{err: context.DeadlineExceeded},
			mutate:  func(*http.Request) {}, wantStatus: http.StatusServiceUnavailable,
		},
		"contradictory decision": {
			limiter: &apiRateLimiterStub{decision: apiratelimit.Decision{}},
			mutate:  func(*http.Request) {}, wantStatus: http.StatusServiceUnavailable,
		},
		"admitted with retry": {
			limiter: &apiRateLimiterStub{decision: apiratelimit.Decision{Admitted: true, RetryAfterSeconds: 1}},
			mutate:  func(*http.Request) {}, wantStatus: http.StatusServiceUnavailable,
		},
		"malformed trusted chain": {
			limiter: &apiRateLimiterStub{decision: apiratelimit.Decision{Admitted: true}},
			mutate: func(request *http.Request) {
				request.RemoteAddr = "10.0.0.2:443"
				request.Header["X-Forwarded-For"] = []string{"198.51.100.2", "198.51.100.3"}
			},
			wantStatus: http.StatusBadRequest,
		},
	} {
		t.Run(name, func(t *testing.T) {
			handler := &Handler{
				cookie:         sessionCookiePolicy{name: developmentCookie},
				trustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			}
			middleware := requestIDMiddleware(apiRateLimitMiddleware(handler, test.limiter, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("failed-closed request reached the application handler")
			})))
			request := httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil)
			request.RemoteAddr = "198.51.100.4:443"
			test.mutate(request)
			response := httptest.NewRecorder()
			middleware.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.wantStatus, response.Body.String())
			}
			if test.wantStatus == http.StatusServiceUnavailable && response.Header().Get("Retry-After") != "1" {
				t.Fatalf("Retry-After = %q", response.Header().Get("Retry-After"))
			}
		})
	}
}

func TestAPIRateLimitMiddlewareExemptsHealthAndIgnoresAmbiguousCredentials(t *testing.T) {
	limiter := &apiRateLimiterStub{decision: apiratelimit.Decision{Admitted: true}}
	handler := &Handler{cookie: sessionCookiePolicy{name: developmentCookie}}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	middleware := apiRateLimitMiddleware(handler, limiter, next)

	for _, path := range []string{
		"/health/live", "/health/ready", "/metrics", "/openapi.json", "/docs", "/docs/asset.js",
	} {
		response := httptest.NewRecorder()
		middleware.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNoContent {
			t.Fatalf("health %s status = %d", path, response.Code)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/system/status", nil)
	request.RemoteAddr = "192.0.2.1:443"
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "session-secret"})
	request.Header.Set("Authorization", "Bearer bearer-secret")
	response := httptest.NewRecorder()
	middleware.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || len(limiter.requests) != 1 || limiter.requests[0].Credential != "" {
		t.Fatalf("ambiguous credential admission = %#v, response %d", limiter.requests, response.Code)
	}
}

func TestRouterRateLimitsUnknownRequestsAndExemptsOperationalSurfaces(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := NewHandler(fixedChecker{ready: true}, logger, "test", time.Second)
	limiter := &apiRateLimiterStub{decision: apiratelimit.Decision{RetryAfterSeconds: 1}}
	router := Router(handler, logger, false, RouterObservability{RateLimiter: limiter})

	for _, path := range []string{
		"/health/live", "/health/ready", "/metrics", "/openapi.json", "/docs", "/docs/asset.js",
	} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.RemoteAddr = "192.0.2.10:443"
		router.ServeHTTP(response, request)
	}
	if len(limiter.requests) != 0 {
		t.Fatalf("operational surfaces consumed %d admissions", len(limiter.requests))
	}

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/not-a-route", nil)
	request.RemoteAddr = "192.0.2.10:443"
	router.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests || len(limiter.requests) != 1 {
		t.Fatalf("unknown API response = %d, admissions = %d", response.Code, len(limiter.requests))
	}
}

func TestAPIRateLimitTenantCanonicalizesV7IdentifiersAndRejectsOtherPaths(t *testing.T) {
	v7 := uuid.Must(uuid.NewV7())
	for _, path := range []string{
		"/api/v1/tenants/" + v7.String() + "/alerts",
		"/api/v1/tenants/" + strings.ToUpper(v7.String()) + "/alerts",
		"/api/v1/tenants/{" + v7.String() + "}/alerts",
	} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		if tenant := apiRateLimitTenant(request); tenant == nil || *tenant != v7 {
			t.Fatalf("apiRateLimitTenant(%q) = %v, want %s", path, tenant, v7)
		}
	}
	for _, path := range []string{
		"/api/v1/tenants/not-a-uuid/alerts",
		"/api/v1/tenants/" + uuid.NewString() + "/alerts",
		"/api/v1/platform/tenants",
	} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		if tenant := apiRateLimitTenant(request); tenant != nil {
			t.Fatalf("apiRateLimitTenant(%q) = %s", path, tenant)
		}
	}
}

var _ APIRateLimiter = (*apiRateLimiterStub)(nil)
