package httpserver

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

func TestEventContextFallsBackFromUntrustedCorrelationUUID(t *testing.T) {
	t.Parallel()
	requestID := uuid.Must(uuid.NewV7())
	handler := &Handler{}

	for _, value := range []string{"malformed", uuid.NewString()} {
		request := httptest.NewRequest(http.MethodPost, "/", nil)
		request.RemoteAddr = "198.51.100.25:443"
		request.Header.Set(correlationIDHeader, value)
		request = request.WithContext(context.WithValue(
			request.Context(), requestIDKey{}, requestID.String(),
		))

		event, err := handler.eventContext(request)
		if err != nil || event.RequestID != requestID || event.CorrelationID != requestID {
			t.Fatalf("eventContext(%q) = %#v, %v", value, event, err)
		}
	}

	validCorrelationID := uuid.Must(uuid.NewV7())
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.RemoteAddr = "198.51.100.25:443"
	request.Header.Set(correlationIDHeader, validCorrelationID.String())
	request = request.WithContext(context.WithValue(
		request.Context(), requestIDKey{}, requestID.String(),
	))
	event, err := handler.eventContext(request)
	if err != nil || event.CorrelationID != validCorrelationID {
		t.Fatalf("eventContext(valid) = %#v, %v", event, err)
	}
}

func TestEventContextCanonicalizesOnlyEmptyUserAgent(t *testing.T) {
	t.Parallel()
	requestID := uuid.Must(uuid.NewV7())
	handler := &Handler{}

	for _, test := range []struct {
		name      string
		userAgent string
		want      string
	}{
		{name: "absent", want: unknownUserAgent},
		{name: "nonempty", userAgent: "periapsis-test/1", want: "periapsis-test/1"},
		{name: "controls removed", userAgent: "periapsis\x00-test/1", want: "periapsis-test/1"},
		{name: "controls only", userAgent: "\x00\t", want: unknownUserAgent},
		{name: "spaces only", userAgent: "   ", want: unknownUserAgent},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest(http.MethodPost, "/", nil)
			request.RemoteAddr = "198.51.100.25:443"
			if test.userAgent != "" {
				request.Header.Set("User-Agent", test.userAgent)
			}
			request = request.WithContext(context.WithValue(
				request.Context(), requestIDKey{}, requestID.String(),
			))

			event, err := handler.eventContext(request)
			if err != nil || event.UserAgent != test.want {
				t.Fatalf("eventContext() UserAgent = %q, error = %v, want %q", event.UserAgent, err, test.want)
			}
		})
	}
}

func TestCookieAndBearerAuthenticationAreExclusive(t *testing.T) {
	t.Parallel()

	handler := &Handler{cookie: sessionCookiePolicy{name: developmentCookie}}
	session := httptest.NewRequest(http.MethodGet, "/", nil)
	session.AddCookie(&http.Cookie{Name: developmentCookie, Value: strings.Repeat("s", 43)})
	if token, err := handler.sessionToken(session); err != nil || len(token) != 43 {
		t.Fatalf("sessionToken() = (%q, %v)", token, err)
	}
	session.Header.Set("Authorization", "Bearer "+strings.Repeat("b", 80))
	if _, err := handler.sessionToken(session); err == nil {
		t.Fatal("sessionToken() accepted an Authorization header")
	}
	if _, err := handler.bearerToken(session); err == nil {
		t.Fatal("bearerToken() accepted a simultaneous session cookie")
	}
}

func TestMFABrowserHandleRequiresCanonicalNonZeroEntropy(t *testing.T) {
	t.Parallel()

	valid := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("\x01", 32)))
	for _, test := range []struct {
		name  string
		value string
		want  bool
	}{
		{name: "canonical", value: valid, want: true},
		{name: "all zero", value: strings.Repeat("A", len(valid))},
		{name: "padded", value: valid + "="},
		{name: "whitespace", value: " " + valid},
		{name: "invalid alphabet", value: strings.Repeat("!", len(valid))},
		{name: "short", value: strings.Repeat("B", len(valid)-1)},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := validMFABrowserHandle(test.value); got != test.want {
				t.Fatalf("validMFABrowserHandle(%q) = %t, want %t", test.value, got, test.want)
			}
		})
	}
}

func FuzzMFABrowserHandleIsCanonical(f *testing.F) {
	f.Add(base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("\x01", 32))))
	f.Add(strings.Repeat("A", base64.RawURLEncoding.EncodedLen(32)))
	f.Add("AQ==")
	f.Fuzz(func(t *testing.T, value string) {
		if !validMFABrowserHandle(value) {
			return
		}
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
		if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != value {
			t.Fatalf("accepted non-canonical handle %q: bytes=%d error=%v", value, len(decoded), err)
		}
	})
}

func TestBearerTokenRequiresOneUnambiguousCredential(t *testing.T) {
	t.Parallel()

	handler := &Handler{cookie: sessionCookiePolicy{name: developmentCookie}}
	want := "periapsis_api_v1.1.locator.secret"
	valid := httptest.NewRequest(http.MethodPost, "/", nil)
	valid.Header.Set("Authorization", "bearer "+want)
	if token, err := handler.bearerToken(valid); err != nil || token != want {
		t.Fatalf("bearerToken() = (%q, %v), want %q", token, err, want)
	}

	for _, values := range [][]string{
		nil,
		{"Basic " + want},
		{"Bearer"},
		{" Bearer " + want},
		{"Bearer " + want + " "},
		{"Bearer first, Bearer second"},
		{"Bearer " + strings.Repeat("x", maximumBearerTokenSize+1)},
		{"Bearer " + want, "Bearer " + want},
	} {
		request := httptest.NewRequest(http.MethodPost, "/", nil)
		for _, value := range values {
			request.Header.Add("Authorization", value)
		}
		if _, err := handler.bearerToken(request); err == nil {
			t.Fatalf("bearerToken() accepted values %#v", values)
		}
	}
}

func TestStrongVersionPrecondition(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name        string
		values      []string
		wantVersion int64
		wantPresent bool
		wantError   bool
	}{
		{name: "missing"},
		{name: "valid", values: []string{`"v42"`}, wantVersion: 42, wantPresent: true},
		{name: "surrounding whitespace", values: []string{`  "v7"  `}, wantVersion: 7, wantPresent: true},
		{name: "weak", values: []string{`W/"v1"`}, wantPresent: true, wantError: true},
		{name: "wildcard", values: []string{"*"}, wantPresent: true, wantError: true},
		{name: "zero", values: []string{`"v0"`}, wantPresent: true, wantError: true},
		{name: "leading zero", values: []string{`"v01"`}, wantPresent: true, wantError: true},
		{name: "signed", values: []string{`"v+1"`}, wantPresent: true, wantError: true},
		{name: "unquoted", values: []string{"v1"}, wantPresent: true, wantError: true},
		{name: "list", values: []string{`"v1", "v2"`}, wantPresent: true, wantError: true},
		{name: "duplicate", values: []string{`"v1"`, `"v1"`}, wantPresent: true, wantError: true},
		{name: "database integer overflow", values: []string{`"v2147483648"`}, wantPresent: true, wantError: true},
		{name: "overflow", values: []string{`"v9223372036854775808"`}, wantPresent: true, wantError: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest("PATCH", "/", nil)
			for _, value := range test.values {
				request.Header.Add(ifMatchHeader, value)
			}
			version, present, err := strongVersionPrecondition(request)
			if present != test.wantPresent || version != test.wantVersion ||
				(err != nil) != test.wantError {
				t.Fatalf(
					"strongVersionPrecondition() = (%d, %t, %v), want (%d, %t, error=%t)",
					version, present, err, test.wantVersion, test.wantPresent, test.wantError,
				)
			}
		})
	}
}

func TestStrongVersionETag(t *testing.T) {
	t.Parallel()

	value, err := strongVersionETag(42)
	if err != nil || value != `"v42"` {
		t.Fatalf("strongVersionETag(42) = (%q, %v)", value, err)
	}
	if _, err := strongVersionETag(0); err == nil {
		t.Fatal("strongVersionETag(0) unexpectedly succeeded")
	}
	if _, err := strongVersionETag(maximumResourceVersion + 1); err == nil {
		t.Fatal("strongVersionETag(MaxInt32+1) unexpectedly succeeded")
	}
}

func TestRequestedEdgeEntityTag(t *testing.T) {
	t.Parallel()

	valid := `"v42-` + strings.Repeat("A", 43) + `"`
	for _, test := range []struct {
		name      string
		values    []string
		want      string
		wantError error
	}{
		{name: "valid", values: []string{valid}, want: valid},
		{name: "surrounding whitespace", values: []string{"  " + valid + "  "}, want: valid},
		{name: "missing", wantError: authorization.ErrPreconditionRequired},
		{name: "version only", values: []string{`"v42"`}, wantError: authorization.ErrInvalidInput},
		{name: "weak", values: []string{"W/" + valid}, wantError: authorization.ErrInvalidInput},
		{name: "wildcard", values: []string{"*"}, wantError: authorization.ErrInvalidInput},
		{name: "duplicate", values: []string{valid, valid}, wantError: authorization.ErrInvalidInput},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest("POST", "/", nil)
			for _, value := range test.values {
				request.Header.Add(ifMatchHeader, value)
			}
			actual, err := requestedEdgeEntityTag(request)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("requestedEdgeEntityTag() error = %v, want %v", err, test.wantError)
			}
			if test.wantError == nil && (actual == nil || *actual != test.want) {
				t.Fatalf("requestedEdgeEntityTag() = %v, want %q", actual, test.want)
			}
		})
	}
}

func TestRequestIdempotencyKey(t *testing.T) {
	t.Parallel()

	valid := "role-create_01.~retry"
	for _, test := range []struct {
		name      string
		values    []string
		want      string
		wantError bool
	}{
		{name: "valid", values: []string{valid}, want: valid},
		{name: "missing", wantError: true},
		{name: "too short", values: []string{"short"}, wantError: true},
		{name: "space", values: []string{"role create retry key"}, wantError: true},
		{name: "unicode", values: []string{"role-create-retry-è"}, wantError: true},
		{name: "comma", values: []string{"role-create,retry"}, wantError: true},
		{name: "duplicate", values: []string{valid, valid}, wantError: true},
		{name: "too long", values: []string{strings.Repeat("a", 129)}, wantError: true},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := httptest.NewRequest("POST", "/", nil)
			for _, value := range test.values {
				request.Header.Add(idempotencyKeyHeader, value)
			}
			value, err := requestIdempotencyKey(request)
			if value != test.want || (err != nil) != test.wantError {
				t.Fatalf(
					"requestIdempotencyKey() = (%q, %v), want (%q, error=%t)",
					value, err, test.want, test.wantError,
				)
			}
		})
	}
}
