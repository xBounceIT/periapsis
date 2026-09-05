package httpserver

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/periapsis-im/periapsis/services/api/internal/ldapauth"
)

type ldapAuthenticationStub struct {
	calls    int
	command  ldapauth.Command
	password []byte
	err      error
}

func (stub *ldapAuthenticationStub) Authenticate(_ context.Context, command ldapauth.Command) (ldapauth.Result, error) {
	stub.calls++
	stub.command = command
	stub.password = command.Password
	return ldapauth.Result{}, stub.err
}

func TestLDAPLoginUsesStrictNativeFormAndClearsOwnedPassword(t *testing.T) {
	stub := &ldapAuthenticationStub{err: ldapauth.ErrAuthentication}
	router := newLDAPAuthenticationTestRouter(t, stub)
	values := url.Values{
		"username":   {"alice@example.test"},
		"password":   {"secret + percent % value"},
		"returnPath": {"/cases?queue=mine"},
	}
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/auth/ldap/acme-soc/employees_ad", strings.NewReader(values.Encode()),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://localhost:8081")
	request.Header.Set("User-Agent", "Periapsis test browser")
	request.RemoteAddr = "192.0.2.40:4567"
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized || stub.calls != 1 {
		t.Fatalf("response=%d calls=%d body=%s", response.Code, stub.calls, response.Body)
	}
	if stub.command.TenantSlug != "acme-soc" || stub.command.LoginKey != "employees_ad" ||
		stub.command.Username != "alice@example.test" || stub.command.ReturnPath != "/cases?queue=mine" ||
		stub.command.ClientIP.String() != "192.0.2.40" || stub.command.RequestID == [16]byte{} {
		t.Fatalf("command = %s", stub.command)
	}
	for _, value := range stub.password {
		if value != 0 {
			t.Fatal("request-owned LDAP password was not cleared")
		}
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("sensitive headers = %#v", response.Header())
	}
}

func TestLDAPLoginRejectsExistingAuthorityAndMalformedBodiesUniformly(t *testing.T) {
	stub := &ldapAuthenticationStub{err: ldapauth.ErrAuthentication}
	router := newLDAPAuthenticationTestRouter(t, stub)
	for name, mutate := range map[string]func(*http.Request){
		"bearer authority": func(request *http.Request) {
			request.Header.Set("Authorization", "Bearer "+strings.Repeat("A", 43))
		},
		"session cookie": func(request *http.Request) {
			request.AddCookie(&http.Cookie{Name: developmentCookie, Value: strings.Repeat("A", 43)})
		},
		"MFA cookie": func(request *http.Request) {
			request.AddCookie(&http.Cookie{Name: developmentMFACookie, Value: strings.Repeat("A", 43)})
		},
		"continuation cookie": func(request *http.Request) {
			request.AddCookie(&http.Cookie{Name: developmentFederatedContinuationCookie, Value: strings.Repeat("A", 43)})
		},
		"CSRF substitute": func(request *http.Request) {
			request.Header.Set(csrfTokenHeader, strings.Repeat("A", 43))
		},
		"OIDC transaction": func(request *http.Request) {
			request.AddCookie(&http.Cookie{Name: developmentOIDCTransactionCookie, Value: strings.Repeat("A", 43)})
		},
		"SAML transaction": func(request *http.Request) {
			request.AddCookie(&http.Cookie{Name: developmentSAMLTransactionCookie, Value: strings.Repeat("A", 43)})
		},
		"duplicate password": func(request *http.Request) {
			request.Body = io.NopCloser(strings.NewReader("username=alice&password=one&password=two&returnPath=%2F"))
		},
		"unknown field": func(request *http.Request) {
			request.Body = io.NopCloser(strings.NewReader("username=alice&password=one&returnPath=%2F&provider=evil"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(
				http.MethodPost, "/api/v1/auth/ldap/acme-soc/employees_ad",
				strings.NewReader("username=alice&password=wrong&returnPath=%2F"),
			)
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.Header.Set("Origin", "http://localhost:8081")
			request.RemoteAddr = "192.0.2.40:4567"
			mutate(request)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "authentication_failed") {
				t.Fatalf("response=%d body=%s", response.Code, response.Body)
			}
		})
	}
	if stub.calls != 0 {
		t.Fatalf("LDAP service called %d times for rejected authority/body", stub.calls)
	}
}

func TestLDAPLoginMapsThrottleAndAvailabilityWithoutSensitiveDetails(t *testing.T) {
	for name, fixture := range map[string]struct {
		err        error
		statusCode int
		problem    string
	}{
		"rate limited": {ldapauth.ErrRateLimited, http.StatusTooManyRequests, "authentication_rate_limited"},
		"unavailable":  {ldapauth.ErrUnavailable, http.StatusServiceUnavailable, "service_unavailable"},
	} {
		t.Run(name, func(t *testing.T) {
			stub := &ldapAuthenticationStub{err: fixture.err}
			request := httptest.NewRequest(
				http.MethodPost, "/api/v1/auth/ldap/acme-soc/employees_ad",
				strings.NewReader("username=alice&password=secret&returnPath=%2F"),
			)
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.Header.Set("Origin", "http://localhost:8081")
			request.Header.Set("User-Agent", "Periapsis test browser")
			request.RemoteAddr = "192.0.2.40:4567"
			response := httptest.NewRecorder()
			newLDAPAuthenticationTestRouter(t, stub).ServeHTTP(response, request)

			if response.Code != fixture.statusCode || response.Header().Get("Retry-After") != "5" ||
				!strings.Contains(response.Body.String(), fixture.problem) ||
				strings.Contains(response.Body.String(), "alice") || strings.Contains(response.Body.String(), "secret") {
				t.Fatalf("response=%d headers=%v body=%s", response.Code, response.Header(), response.Body)
			}
		})
	}
}

func newLDAPAuthenticationTestRouter(t testing.TB, service LDAPAuthenticationService) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	options := completeFederatedApplicationOptions(&transportAuthStub{})
	options.LDAPAuthentication = service
	handler, err := NewApplicationHandler(fixedChecker{ready: true}, logger, "test", time.Second, options)
	if err != nil {
		t.Fatalf("NewApplicationHandler: %v", err)
	}
	return Router(handler, logger, false)
}
