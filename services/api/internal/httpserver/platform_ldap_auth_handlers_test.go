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

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/platformldapauth"
)

type platformLDAPAuthenticationStub struct {
	calls    int
	command  platformldapauth.Command
	password []byte
	totpCode []byte
	result   platformldapauth.Result
	err      error
}

func (stub *platformLDAPAuthenticationStub) Authenticate(
	_ context.Context,
	command platformldapauth.Command,
) (platformldapauth.Result, error) {
	stub.calls++
	stub.command = command
	stub.password = command.Password
	stub.totpCode = command.TOTPCode
	return stub.result, stub.err
}

func TestPlatformLDAPLoginUsesExactNativeFormAndClearsOwnedSecrets(t *testing.T) {
	stub := &platformLDAPAuthenticationStub{err: platformldapauth.ErrAuthentication}
	router := newPlatformLDAPAuthenticationTestRouter(t, stub, &transportAuthStub{})
	values := url.Values{
		"username":   {"alice@example.test"},
		"password":   {"secret + percent % value"},
		"totpCode":   {"012345"},
		"returnPath": {"/platform/providers?tab=ldap"},
	}
	request := newPlatformLDAPLoginRequest(values.Encode())
	request.Header.Set("User-Agent", "Periapsis test browser")
	request.RemoteAddr = "192.0.2.40:4567"
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized || stub.calls != 1 {
		t.Fatalf("response=%d calls=%d body=%s", response.Code, stub.calls, response.Body)
	}
	if stub.command.ProviderKey != "employees_ldap" || stub.command.Username != "alice@example.test" ||
		stub.command.ReturnPath != "/platform/providers?tab=ldap" || stub.command.ClientIP.String() != "192.0.2.40" ||
		stub.command.RequestID == uuid.Nil {
		t.Fatalf("command = %s", stub.command)
	}
	assertClearedPlatformLDAPSecret(t, "password", stub.password)
	assertClearedPlatformLDAPSecret(t, "TOTP code", stub.totpCode)
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("sensitive headers = %#v", response.Header())
	}
}

func TestPlatformLDAPLoginRejectsAuthorityOriginQueryAndMalformedFormsUniformly(t *testing.T) {
	validBody := "username=alice&password=wrong&totpCode=012345&returnPath=%2F"
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
		"tenant OIDC transaction": func(request *http.Request) {
			request.AddCookie(&http.Cookie{Name: developmentOIDCTransactionCookie, Value: strings.Repeat("A", 43)})
		},
		"tenant SAML transaction": func(request *http.Request) {
			request.AddCookie(&http.Cookie{Name: developmentSAMLTransactionCookie, Value: strings.Repeat("A", 43)})
		},
		"platform OIDC transaction": func(request *http.Request) {
			request.AddCookie(&http.Cookie{Name: developmentPlatformOIDCTransactionCookie, Value: strings.Repeat("A", 43)})
		},
		"platform SAML transaction": func(request *http.Request) {
			request.AddCookie(&http.Cookie{Name: developmentPlatformSAMLTransactionCookie, Value: strings.Repeat("A", 43)})
		},
		"cross origin": func(request *http.Request) {
			request.Header.Set("Origin", "https://attacker.example.test")
		},
		"query authority": func(request *http.Request) {
			request.URL.RawQuery = "returnPath=%2F"
		},
		"duplicate password": func(request *http.Request) {
			request.Body = io.NopCloser(strings.NewReader(validBody + "&password=again"))
		},
		"missing TOTP": func(request *http.Request) {
			request.Body = io.NopCloser(strings.NewReader("username=alice&password=wrong&returnPath=%2F"))
		},
		"unknown fifth field": func(request *http.Request) {
			request.Body = io.NopCloser(strings.NewReader(validBody + "&tenant=evil"))
		},
		"malformed percent encoding": func(request *http.Request) {
			request.Body = io.NopCloser(strings.NewReader("username=alice&password=%GG&totpCode=012345&returnPath=%2F"))
		},
		"oversized form": func(request *http.Request) {
			request.Body = io.NopCloser(strings.NewReader("username=" + strings.Repeat("A", maximumLDAPLoginBodyBytes) +
				"&password=wrong&totpCode=012345&returnPath=%2F"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			stub := &platformLDAPAuthenticationStub{err: platformldapauth.ErrAuthentication}
			request := newPlatformLDAPLoginRequest(validBody)
			mutate(request)
			response := httptest.NewRecorder()

			newPlatformLDAPAuthenticationTestRouter(t, stub, &transportAuthStub{}).ServeHTTP(response, request)

			if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "authentication_failed") ||
				strings.Contains(response.Body.String(), "alice") || strings.Contains(response.Body.String(), "wrong") {
				t.Fatalf("response=%d body=%s", response.Code, response.Body)
			}
			if stub.calls != 0 {
				t.Fatalf("platform LDAP service called %d times", stub.calls)
			}
		})
	}
}

func TestPlatformLDAPLoginMapsThrottleAndAvailabilityWithoutSensitiveDetails(t *testing.T) {
	for name, fixture := range map[string]struct {
		err        error
		statusCode int
		problem    string
	}{
		"rate limited": {platformldapauth.ErrRateLimited, http.StatusTooManyRequests, "authentication_rate_limited"},
		"unavailable":  {platformldapauth.ErrUnavailable, http.StatusServiceUnavailable, "service_unavailable"},
	} {
		t.Run(name, func(t *testing.T) {
			stub := &platformLDAPAuthenticationStub{err: fixture.err}
			response := httptest.NewRecorder()
			newPlatformLDAPAuthenticationTestRouter(t, stub, &transportAuthStub{}).ServeHTTP(
				response, newPlatformLDAPLoginRequest("username=alice&password=secret&totpCode=012345&returnPath=%2F"),
			)

			if response.Code != fixture.statusCode || response.Header().Get("Retry-After") != "5" ||
				!strings.Contains(response.Body.String(), fixture.problem) || strings.Contains(response.Body.String(), "alice") ||
				strings.Contains(response.Body.String(), "secret") || strings.Contains(response.Body.String(), "012345") {
				t.Fatalf("response=%d headers=%v body=%s", response.Code, response.Header(), response.Body)
			}
			assertClearedPlatformLDAPSecret(t, "password", stub.password)
			assertClearedPlatformLDAPSecret(t, "TOTP code", stub.totpCode)
		})
	}
}

func TestPlatformLDAPLoginDeliversOnlyTenantlessLDAPSession(t *testing.T) {
	fixture := newFederatedSessionFixture(t, federatedauth.AuthenticationMethodLDAP, "/platform/providers", 0x93)
	auth := &transportAuthStub{currentResult: fixture.current}
	stub := &platformLDAPAuthenticationStub{result: platformldapauth.Result{
		UserID: uuid.UUID(fixture.result.UserID), SessionID: fixture.result.SessionID,
		ReturnPath: fixture.result.ReturnPath, Credential: fixture.result.Credential,
	}}
	response := httptest.NewRecorder()

	newPlatformLDAPAuthenticationTestRouter(t, stub, auth).ServeHTTP(
		response, newPlatformLDAPLoginRequest("username=alice&password=secret&totpCode=012345&returnPath=%2Fplatform%2Fproviders"),
	)

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/platform/providers" ||
		auth.currentToken != fixture.token {
		t.Fatalf("response=%d location=%q token_match=%t body=%s",
			response.Code, response.Header().Get("Location"), auth.currentToken == fixture.token, response.Body)
	}
	assertSessionCookie(t, response.Result().Cookies(), developmentCookie, fixture.token)
	if cookie := findResponseCookie(response.Result().Cookies(), developmentFederatedContinuationCookie); cookie != nil && cookie.Value != "" {
		t.Fatalf("platform LDAP emitted a continuation cookie: %#v", cookie)
	}
	if _, ok := fixture.result.Credential.Consume(); ok {
		t.Fatal("platform LDAP browser credential remained consumable")
	}
}

func TestPlatformLDAPLoginRejectsRelabeledTenantOrMalformedCredential(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		result func(testing.TB) (platformldapauth.Result, authentication.SessionCredential)
	}{
		{name: "tenant scoped LDAP session", result: func(t testing.TB) (platformldapauth.Result, authentication.SessionCredential) {
			fixture := newFederatedSessionFixture(t, federatedauth.AuthenticationMethodLDAP, "/", 0xa0)
			tenantID := uuid.Must(uuid.NewV7())
			fixture.current.Session.ActiveTenantID = &tenantID
			return platformLDAPResultFromFixture(fixture), fixture.current
		}},
		{name: "non LDAP session", result: func(t testing.TB) (platformldapauth.Result, authentication.SessionCredential) {
			fixture := newFederatedSessionFixture(t, federatedauth.AuthenticationMethodLDAP, "/", 0xa2)
			fixture.current.Session.AuthenticationMethod = string(federatedauth.AuthenticationMethodOIDC)
			return platformLDAPResultFromFixture(fixture), fixture.current
		}},
		{name: "session id mismatch", result: func(t testing.TB) (platformldapauth.Result, authentication.SessionCredential) {
			fixture := newFederatedSessionFixture(t, federatedauth.AuthenticationMethodLDAP, "/", 0xa4)
			result := platformLDAPResultFromFixture(fixture)
			result.SessionID = identity.EntityID(uuid.Must(uuid.NewV7()))
			return result, fixture.current
		}},
		{name: "continuation credential", result: func(t testing.TB) (platformldapauth.Result, authentication.SessionCredential) {
			fixture := newFederatedContinuationFixture(t, "/", time.Now().UTC().Truncate(time.Millisecond), 0xa6)
			return platformldapauth.Result{
				UserID: uuid.UUID(fixture.result.UserID), ReturnPath: fixture.result.ReturnPath,
				Credential: fixture.result.Credential,
			}, authentication.SessionCredential{}
		}},
		{name: "missing credential", result: func(testing.TB) (platformldapauth.Result, authentication.SessionCredential) {
			return platformldapauth.Result{
				UserID: uuid.Must(uuid.NewV7()), SessionID: identity.EntityID(uuid.Must(uuid.NewV7())), ReturnPath: "/",
			}, authentication.SessionCredential{}
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			result, current := testCase.result(t)
			stub := &platformLDAPAuthenticationStub{result: result}
			response := httptest.NewRecorder()

			newPlatformLDAPAuthenticationTestRouter(t, stub, &transportAuthStub{currentResult: current}).ServeHTTP(
				response, newPlatformLDAPLoginRequest("username=alice&password=secret&totpCode=012345&returnPath=%2F"),
			)

			if response.Code != http.StatusUnauthorized || findResponseCookie(response.Result().Cookies(), developmentCookie) != nil ||
				findPositiveResponseCookie(response.Result().Cookies(), developmentFederatedContinuationCookie) != nil {
				t.Fatalf("response=%d cookies=%#v body=%s", response.Code, response.Result().Cookies(), response.Body)
			}
		})
	}
}

func platformLDAPResultFromFixture(fixture federatedSessionFixture) platformldapauth.Result {
	return platformldapauth.Result{
		UserID: uuid.UUID(fixture.result.UserID), SessionID: fixture.result.SessionID,
		ReturnPath: fixture.result.ReturnPath, Credential: fixture.result.Credential,
	}
}

func newPlatformLDAPLoginRequest(body string) *http.Request {
	request := httptest.NewRequest(
		http.MethodPost, "/api/v1/auth/platform/ldap/employees_ldap", strings.NewReader(body),
	)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://localhost:8081")
	request.RemoteAddr = "192.0.2.40:4567"
	return request
}

func newPlatformLDAPAuthenticationTestRouter(
	t testing.TB,
	service PlatformLDAPAuthenticationService,
	auth AuthenticationService,
) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	options := completeFederatedApplicationOptions(auth)
	options.PlatformLDAPAuthentication = service
	handler, err := NewApplicationHandler(fixedChecker{ready: true}, logger, "test", time.Second, options)
	if err != nil {
		t.Fatalf("NewApplicationHandler: %v", err)
	}
	return Router(handler, logger, false)
}

func assertClearedPlatformLDAPSecret(t testing.TB, name string, material []byte) {
	t.Helper()
	if len(material) == 0 {
		t.Fatalf("%s was not passed to the platform LDAP service", name)
	}
	for _, value := range material {
		if value != 0 {
			t.Fatalf("request-owned platform LDAP %s was not cleared", name)
		}
	}
}
