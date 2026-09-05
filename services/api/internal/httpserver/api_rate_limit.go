package httpserver

import (
	"context"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/apiratelimit"
)

// APIRateLimiter is the shared admission boundary used before every request
// except health, metrics, and documentation surfaces. The production
// implementation is backed by PostgreSQL; no per-process fallback is permitted.
type APIRateLimiter interface {
	Admit(context.Context, apiratelimit.Request) (apiratelimit.Decision, error)
}

func apiRateLimitMiddleware(handler *Handler, limiter APIRateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if apiRateLimitExempt(r) {
			next.ServeHTTP(w, r)
			return
		}
		if handler == nil || limiter == nil || r == nil {
			writeAPIRateLimitUnavailable(w, r)
			return
		}
		address, err := resolveClientAddress(r, handler.trustedProxies)
		if err != nil {
			writeProblem(
				w, r, http.StatusBadRequest, "invalid_request", "Invalid request",
				"The trusted client network could not be resolved.",
			)
			return
		}
		request := apiratelimit.Request{
			ClientNetwork: apiRateLimitNetwork(address),
			Credential:    apiRateLimitCredential(handler, r),
			TenantID:      apiRateLimitTenant(r),
		}
		decision, err := limiter.Admit(r.Context(), request)
		if err != nil || !decision.Valid() {
			writeAPIRateLimitUnavailable(w, r)
			return
		}
		if !decision.Admitted {
			w.Header().Set("Retry-After", strconv.Itoa(decision.RetryAfterSeconds))
			writeProblem(
				w, r, http.StatusTooManyRequests, "rate_limited", "Too many requests",
				"The shared API request limit was exceeded. Retry after the indicated delay.",
			)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func apiRateLimitExempt(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	switch r.URL.Path {
	case "/health/live", "/health/ready", "/metrics", "/openapi.json", "/docs":
		return true
	default:
		return strings.HasPrefix(r.URL.Path, "/docs/")
	}
}

func apiRateLimitNetwork(address netip.Addr) netip.Prefix {
	bits := 64
	if address.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(address.Unmap(), bits).Masked()
}

func apiRateLimitCredential(handler *Handler, r *http.Request) string {
	if handler == nil || r == nil {
		return ""
	}
	if token, err := handler.bearerToken(r); err == nil {
		return token
	}
	if token, err := handler.sessionToken(r); err == nil {
		return token
	}
	return ""
}

func apiRateLimitTenant(r *http.Request) *uuid.UUID {
	if r == nil || r.URL == nil {
		return nil
	}
	const prefix = "/api/v1/tenants/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return nil
	}
	remainder := strings.TrimPrefix(r.URL.Path, prefix)
	if separator := strings.IndexByte(remainder, '/'); separator >= 0 {
		remainder = remainder[:separator]
	}
	parsed, err := uuid.Parse(remainder)
	if err != nil || parsed == uuid.Nil || parsed.Version() != 7 || parsed.Variant() != uuid.RFC4122 {
		return nil
	}
	return &parsed
}

func writeAPIRateLimitUnavailable(w http.ResponseWriter, r *http.Request) {
	if r == nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Retry-After", "1")
	writeProblem(
		w, r, http.StatusServiceUnavailable, "service_unavailable", "Service unavailable",
		"Shared API admission is temporarily unavailable.",
	)
}
