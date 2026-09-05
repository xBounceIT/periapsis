package httpserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/mfaauth"
	"github.com/periapsis-im/periapsis/services/api/internal/operatorteam"
	"github.com/periapsis-im/periapsis/services/api/internal/platform"
	"github.com/periapsis-im/periapsis/services/api/internal/sessionlogout"
)

type transportOperatorTeamStub struct {
	*operatorteam.Service
}

type transportAuthStub struct {
	*authentication.Service
	authenticateCalls  int
	authenticateError  error
	authenticateResult authentication.Session
	csrfCalls          int
	csrfError          error
	loginError         error
	logoutCalls        int
	currentError       error
	currentResult      authentication.SessionCredential
	currentToken       string
	currentTokenMu     sync.Mutex
	membershipAfter    *uuid.UUID
	membershipError    error
	membershipLimit    int
	membershipPage     authentication.TenantMembershipPage
	sessionAfter       *uuid.UUID
	sessionError       error
	sessionLimit       int
	sessionPage        authentication.SessionPage
	startLoginCalls    int
	reserveCalls       int
	reserveCurrent     *authentication.Session
	reserveMethod      mfa.SessionAuthenticationMethod
	reserveIssuedAt    time.Time
	reserveResult      authentication.MFASessionReservation
	reserveError       error
	switchResult       authentication.SessionCredential
	switchCalls        int
	switchError        error
}

type transportSessionLogoutStub struct {
	result             sessionlogout.Result
	err                error
	calls              int
	auth               *transportAuthStub
	continueURL        string
	continueErr        error
	continueCalls      int
	continuationID     identity.EntityID
	continuationSecret []byte
}

func (stub *transportSessionLogoutStub) Logout(
	context.Context,
	string,
	string,
	sessionlogout.EventContext,
) (sessionlogout.Result, error) {
	stub.calls++
	if stub.auth != nil {
		stub.auth.logoutCalls++
	}
	return stub.result, stub.err
}

func (stub *transportSessionLogoutStub) Continue(
	_ context.Context,
	continuationID identity.EntityID,
	credential []byte,
) (string, error) {
	stub.continueCalls++
	stub.continuationID = continuationID
	stub.continuationSecret = append(stub.continuationSecret[:0], credential...)
	return stub.continueURL, stub.continueErr
}

func (s *transportAuthStub) Authenticate(context.Context, string) (authentication.Session, error) {
	s.authenticateCalls++
	return s.authenticateResult, s.authenticateError
}

func (s *transportAuthStub) ValidateCSRF(authentication.Session, string) error {
	s.csrfCalls++
	return s.csrfError
}

func (s *transportAuthStub) ReserveMFASession(
	current *authentication.Session,
	method mfa.SessionAuthenticationMethod,
) (authentication.MFASessionReservation, error) {
	s.reserveCalls++
	if current != nil {
		copyValue := *current
		s.reserveCurrent = &copyValue
	}
	s.reserveMethod = method
	return s.reserveResult, s.reserveError
}

func (s *transportAuthStub) ReserveMFASessionAt(
	current *authentication.Session,
	method mfa.SessionAuthenticationMethod,
	issuedAt time.Time,
) (authentication.MFASessionReservation, error) {
	s.reserveIssuedAt = issuedAt
	return s.ReserveMFASession(current, method)
}

func (s *transportAuthStub) BootstrapStatus(context.Context) (bool, error) {
	return true, nil
}

func (s *transportAuthStub) StartPasswordLogin(
	context.Context,
	string,
	string,
	authentication.EventContext,
) (authentication.MFAChallenge, error) {
	s.startLoginCalls++
	return authentication.MFAChallenge{}, s.loginError
}

func (s *transportAuthStub) Logout(
	context.Context,
	string,
	string,
	authentication.EventContext,
) error {
	s.logoutCalls++
	return nil
}

func (s *transportAuthStub) CurrentSession(_ context.Context, token string) (authentication.SessionCredential, error) {
	s.currentTokenMu.Lock()
	s.currentToken = token
	s.currentTokenMu.Unlock()
	return s.currentResult, s.currentError
}

func (s *transportAuthStub) SwitchTenant(
	context.Context,
	string,
	string,
	uuid.UUID,
	authentication.EventContext,
) (authentication.SessionCredential, error) {
	s.switchCalls++
	return s.switchResult, s.switchError
}

func (s *transportAuthStub) Sessions(
	_ context.Context,
	_ string,
	after *uuid.UUID,
	limit int,
) (authentication.SessionPage, error) {
	s.sessionAfter = after
	s.sessionLimit = limit
	return s.sessionPage, s.sessionError
}

func (s *transportAuthStub) TenantMemberships(
	_ context.Context,
	_ string,
	after *uuid.UUID,
	limit int,
) (authentication.TenantMembershipPage, error) {
	s.membershipAfter = after
	s.membershipLimit = limit
	return s.membershipPage, s.membershipError
}

type transportPlatformStub struct{ *platform.Service }

type transportAuthorizationStub struct{ *authorization.Service }

type transportMFAStub struct{ *mfaauth.PublicService }

func TestAnonymousSessionIsDenied(t *testing.T) {
	router := newApplicationTestRouter(t, &transportAuthStub{}, "test", nil)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusUnauthorized, "authentication_failed")
}

func TestBootstrapStatusCannotBeCached(t *testing.T) {
	router := newApplicationTestRouter(t, &transportAuthStub{}, "test", nil)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap/status", nil)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if cacheControl := response.Header().Get("Cache-Control"); cacheControl != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cacheControl)
	}
}

func TestLoginFailuresAreEnumerationResistant(t *testing.T) {
	auth := &transportAuthStub{loginError: authentication.ErrInvalidAuthentication}
	router := newApplicationTestRouter(t, auth, "test", nil)
	wantRequestID := uuid.Must(uuid.NewV7()).String()

	responses := make([]map[string]any, 0, 2)
	for _, email := range []string{"missing@example.test", "known@example.test"} {
		body := `{"email":"` + email + `","password":"wrong password value"}`
		request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set(requestIDHeader, wantRequestID)
		request.RemoteAddr = "198.51.100.20:4421"
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
		}
		var problem map[string]any
		if err := json.NewDecoder(response.Body).Decode(&problem); err != nil {
			t.Fatalf("decode problem: %v", err)
		}
		responses = append(responses, problem)
	}
	first, _ := json.Marshal(responses[0])
	second, _ := json.Marshal(responses[1])
	if bytes.Contains(first, []byte("missing@example.test")) || bytes.Contains(second, []byte("known@example.test")) {
		t.Fatal("a generic login failure leaked a login identifier")
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("unknown and known login failures differ:\n%s\n%s", first, second)
	}
}

func TestCookieMutationRequiresOriginBeforeAuthentication(t *testing.T) {
	auth := &transportAuthStub{}
	router := newApplicationTestRouter(t, auth, "test", nil)
	token := strings.Repeat("A", 43)

	for name, origin := range map[string]string{
		"missing": "",
		"foreign": "https://attacker.example",
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/session", nil)
			request.AddCookie(&http.Cookie{Name: developmentCookie, Value: token})
			request.Header.Set(csrfTokenHeader, strings.Repeat("B", 43))
			if origin != "" {
				request.Header.Set("Origin", origin)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			assertProblem(t, response, http.StatusForbidden, "forbidden")
		})
	}
	if auth.logoutCalls != 0 {
		t.Fatalf("Logout calls = %d before origin validation", auth.logoutCalls)
	}

	request := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/session", nil)
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: token})
	request.Header.Set(csrfTokenHeader, strings.Repeat("B", 43))
	request.Header.Set("Origin", "http://localhost:8081")
	request.RemoteAddr = "198.51.100.30:5500"
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusNoContent, response.Body.String())
	}
	if auth.logoutCalls != 1 {
		t.Fatalf("Logout calls = %d, want 1", auth.logoutCalls)
	}
}

func TestLogoutReturnsOnlyOpaqueSameOriginContinuationThenServerRedirects(t *testing.T) {
	auth := &transportAuthStub{}
	continuationID := uuid.Must(uuid.NewV7())
	secret := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32)))
	continuation, err := sessionlogout.NewBrowserContinuation(
		identity.EntityID(continuationID), secret,
		time.Now().UTC().Truncate(time.Microsecond).Add(time.Minute),
	)
	if err != nil {
		t.Fatalf("NewBrowserContinuation() error = %v", err)
	}
	upstream := "https://idp.example.test/end-session?id_token_hint=header.payload.signature&post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A8081%2Fsigned-out&state=opaque-state"
	logout := &transportSessionLogoutStub{
		result:      sessionlogout.Result{LocalRevoked: true, Continuation: continuation},
		continueURL: upstream,
	}
	router := newApplicationTestRouterWithSessionLogout(t, auth, logout, "test", nil)
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/session", nil)
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: strings.Repeat("A", 43)})
	request.Header.Set(csrfTokenHeader, strings.Repeat("B", 43))
	request.Header.Set("Origin", "http://localhost:8081")
	request.RemoteAddr = "198.51.100.30:5500"
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Referrer-Policy") != "no-referrer" ||
		len(response.Header().Values("Set-Cookie")) != 2 {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	var body struct {
		ContinuationURL string `json:"continuationUrl"`
	}
	wantPath := logoutContinuationPath(identity.EntityID(continuationID))
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil || body.ContinuationURL != wantPath ||
		strings.Contains(response.Body.String(), "id_token_hint") {
		t.Fatalf("logout result = %#v, %v", body, err)
	}
	var proofCookie *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == developmentLogoutContinuationCookie {
			proofCookie = cookie
		}
	}
	if proofCookie == nil || proofCookie.Value != string(secret) || proofCookie.Path != wantPath ||
		!proofCookie.HttpOnly || proofCookie.Secure || proofCookie.SameSite != http.SameSiteStrictMode ||
		proofCookie.MaxAge < 1 || proofCookie.MaxAge > 120 {
		t.Fatalf("continuation cookie = %#v", proofCookie)
	}

	claim := httptest.NewRequest(http.MethodGet, body.ContinuationURL, nil)
	claim.AddCookie(proofCookie)
	claim.Header.Set("Forwarded", "host=evil.example;proto=https")
	claim.Header.Set("X-Forwarded-Host", "evil.example")
	claimResponse := httptest.NewRecorder()
	router.ServeHTTP(claimResponse, claim)
	if claimResponse.Code != http.StatusSeeOther || claimResponse.Body.Len() != 0 ||
		claimResponse.Header().Get("Location") != upstream ||
		claimResponse.Header().Get("Cache-Control") != "no-store" ||
		claimResponse.Header().Get("Referrer-Policy") != "no-referrer" || logout.continueCalls != 1 ||
		logout.continuationID != identity.EntityID(continuationID) ||
		!bytes.Equal(logout.continuationSecret, secret) {
		t.Fatalf("claim status=%d headers=%v body=%s calls=%d id=%s", claimResponse.Code, claimResponse.Header(), claimResponse.Body.String(), logout.continueCalls, uuid.UUID(logout.continuationID))
	}
	cleared := claimResponse.Result().Cookies()
	if len(cleared) != 1 || cleared[0].Name != developmentLogoutContinuationCookie ||
		cleared[0].Path != wantPath || cleared[0].MaxAge >= 0 {
		t.Fatalf("claim deletion cookies = %#v", cleared)
	}
}

func TestContinueLogoutUsesGeneratedContinuationParameter(t *testing.T) {
	continuationID := uuid.Must(uuid.NewV7())
	credential := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x4d}, 32))
	upstream := "https://idp.example.test/end-session?state=opaque-state"
	logout := &transportSessionLogoutStub{continueURL: upstream}
	handler := &Handler{
		sessionLogout:            logout,
		logoutContinuationCookie: sessionCookiePolicy{name: developmentLogoutContinuationCookie},
		publicOrigin:             "http://localhost:8081",
	}
	request := httptest.NewRequest(http.MethodGet, "/generated-wrapper-supplies-the-parameter", nil)
	request.SetPathValue("continuationId", uuid.Must(uuid.NewV7()).String())
	request.AddCookie(&http.Cookie{Name: developmentLogoutContinuationCookie, Value: credential})
	response := httptest.NewRecorder()

	handler.ContinueLogout(response, request, contract.LogoutContinuationId(continuationID.String()))

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != upstream ||
		logout.continueCalls != 1 || logout.continuationID != identity.EntityID(continuationID) ||
		!bytes.Equal(logout.continuationSecret, []byte(credential)) {
		t.Fatalf("continuation status=%d location=%q calls=%d id=%s",
			response.Code, response.Header().Get("Location"), logout.continueCalls, uuid.UUID(logout.continuationID))
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Path != logoutContinuationPath(identity.EntityID(continuationID)) ||
		cookies[0].MaxAge >= 0 {
		t.Fatalf("continuation deletion cookies = %#v", cookies)
	}
}

func TestContinueLogoutRejectsNonCanonicalContinuationParameter(t *testing.T) {
	canonicalID := uuid.Must(uuid.NewV7()).String()
	credential := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x4e}, 32))
	for name, continuationID := range map[string]string{
		"uppercase": strings.ToUpper(canonicalID),
		"URN":       "urn:uuid:" + canonicalID,
		"raw hex":   strings.ReplaceAll(canonicalID, "-", ""),
		"braced":    "{" + canonicalID + "}",
	} {
		t.Run(name, func(t *testing.T) {
			logout := &transportSessionLogoutStub{continueURL: "https://idp.example.test/end-session"}
			router := newApplicationTestRouterWithSessionLogout(t, &transportAuthStub{}, logout, "test", nil)
			request := httptest.NewRequest(
				http.MethodGet,
				logoutContinuationPathPrefix+continuationID,
				nil,
			)
			request.AddCookie(&http.Cookie{Name: developmentLogoutContinuationCookie, Value: credential})
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			if response.Code != http.StatusSeeOther ||
				response.Header().Get("Location") != "http://localhost:8081/signed-out" ||
				response.Header().Get("Cache-Control") != "no-store" ||
				response.Header().Get("Referrer-Policy") != "no-referrer" || response.Body.Len() != 0 {
				t.Fatalf("status=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
			}
			if logout.continueCalls != 0 {
				t.Fatalf("Continue calls = %d for non-canonical locator", logout.continueCalls)
			}
		})
	}
}

func TestContinueLogoutFailsClosedWithoutOneValidProofCookie(t *testing.T) {
	continuationID := identity.EntityID(uuid.Must(uuid.NewV7()))
	path := logoutContinuationPath(continuationID)
	validCredential := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x4f}, 32))
	tests := []struct {
		name    string
		cookies []*http.Cookie
	}{
		{name: "missing"},
		{name: "malformed", cookies: []*http.Cookie{{Name: developmentLogoutContinuationCookie, Value: "not-a-handle"}}},
		{name: "duplicate", cookies: []*http.Cookie{
			{Name: developmentLogoutContinuationCookie, Value: validCredential},
			{Name: developmentLogoutContinuationCookie, Value: validCredential},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := &transportAuthStub{}
			logout := &transportSessionLogoutStub{continueURL: "https://idp.example.test/end-session"}
			router := newApplicationTestRouterWithSessionLogout(t, auth, logout, "test", nil)
			request := httptest.NewRequest(http.MethodGet, path, nil)
			request.AddCookie(&http.Cookie{Name: developmentCookie, Value: strings.Repeat("S", 43)})
			for _, cookie := range test.cookies {
				request.AddCookie(cookie)
			}
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			if response.Code != http.StatusSeeOther ||
				response.Header().Get("Location") != "http://localhost:8081/signed-out" ||
				response.Header().Get("Cache-Control") != "no-store" ||
				response.Header().Get("Referrer-Policy") != "no-referrer" || response.Body.Len() != 0 {
				t.Fatalf("status=%d headers=%v body=%q", response.Code, response.Header(), response.Body.String())
			}
			if logout.continueCalls != 0 || auth.authenticateCalls != 0 {
				t.Fatalf("Continue calls = %d, authentication calls = %d", logout.continueCalls, auth.authenticateCalls)
			}
			cookies := response.Result().Cookies()
			if len(cookies) != 1 || cookies[0].Name != developmentLogoutContinuationCookie ||
				cookies[0].Path != path || cookies[0].MaxAge >= 0 || !cookies[0].HttpOnly ||
				cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode {
				t.Fatalf("continuation deletion cookies = %#v", cookies)
			}
		})
	}
}

func TestLogoutContinuationCookieUsesDatabaseLifetimeAcrossClockSkew(t *testing.T) {
	applicationNow := time.Now().UTC().Truncate(time.Second)
	credential := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5c}, 32)))
	for _, offset := range []time.Duration{-299 * time.Second, 299 * time.Second} {
		t.Run(offset.String(), func(t *testing.T) {
			databaseObservedAt := applicationNow.Add(offset)
			recorder := httptest.NewRecorder()
			if err := setLogoutContinuationCookie(
				recorder,
				sessionCookiePolicy{name: developmentLogoutContinuationCookie},
				identity.EntityID(uuid.Must(uuid.NewV7())),
				credential,
				databaseObservedAt.Add(time.Minute),
				time.Minute,
				applicationNow,
			); err != nil {
				t.Fatalf("setLogoutContinuationCookie(%s) error = %v", offset, err)
			}
			cookies := recorder.Result().Cookies()
			if len(cookies) != 1 || cookies[0].MaxAge != 60 ||
				!cookies[0].Expires.Equal(applicationNow.Add(time.Minute)) {
				t.Fatalf("cookie at DB offset %s = %#v", offset, cookies)
			}
		})
	}
}

func TestLogoutContinuationPreservesBoundedSAMLRedirectAboveEightKiB(t *testing.T) {
	auth := &transportAuthStub{}
	continuationID := identity.EntityID(uuid.Must(uuid.NewV7()))
	secret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x7c}, 32))
	upstream := "https://idp.example.test/saml/logout?SAMLRequest=" + strings.Repeat("A", 9*1024)
	if len(upstream) <= 8*1024 || len(upstream) >= maximumSAMLRedirectBytes {
		t.Fatalf("invalid regression fixture length %d", len(upstream))
	}
	logout := &transportSessionLogoutStub{continueURL: upstream}
	router := newApplicationTestRouterWithSessionLogout(t, auth, logout, "test", nil)
	path := logoutContinuationPath(continuationID)
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.AddCookie(&http.Cookie{
		Name: developmentLogoutContinuationCookie, Value: secret, Path: path,
	})
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != upstream ||
		logout.continueCalls != 1 || logout.continuationID != continuationID ||
		!bytes.Equal(logout.continuationSecret, []byte(secret)) {
		t.Fatalf("claim status=%d location length=%d calls=%d id=%s",
			response.Code, len(response.Header().Get("Location")), logout.continueCalls,
			uuid.UUID(logout.continuationID))
	}
}

func TestLogoutContinuationIgnoresForwardedHostAndFallsBackOnMalformedDisposition(t *testing.T) {
	auth := &transportAuthStub{}
	continuationID := uuid.Must(uuid.NewV7())
	secret := []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x6b}, 32)))
	continuation, err := sessionlogout.NewBrowserContinuation(
		identity.EntityID(continuationID), secret,
		time.Now().UTC().Truncate(time.Microsecond).Add(time.Minute),
	)
	if err != nil {
		t.Fatalf("NewBrowserContinuation() error = %v", err)
	}
	logout := &transportSessionLogoutStub{
		result:      sessionlogout.Result{LocalRevoked: true, Continuation: continuation},
		continueURL: "http://evil.example/end-session?id_token_hint=secret",
	}
	router := newApplicationTestRouterWithSessionLogout(t, auth, logout, "production", nil)
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/session", nil)
	request.AddCookie(&http.Cookie{Name: productionCookie, Value: strings.Repeat("A", 43)})
	request.Header.Set(csrfTokenHeader, strings.Repeat("B", 43))
	request.Header.Set("Origin", "https://localhost:8443")
	request.Header.Set("Forwarded", "host=evil.example;proto=https")
	request.Header.Set("X-Forwarded-Host", "evil.example")
	request.RemoteAddr = "198.51.100.31:5500"
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
	var body struct {
		ContinuationURL string `json:"continuationUrl"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var proofCookie *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == productionLogoutContinuationCookie {
			proofCookie = cookie
		}
	}
	if proofCookie == nil || !proofCookie.Secure || proofCookie.Path != body.ContinuationURL {
		t.Fatalf("production proof cookie = %#v", proofCookie)
	}
	claim := httptest.NewRequest(http.MethodGet, body.ContinuationURL, nil)
	claim.AddCookie(proofCookie)
	claim.Header.Set("Forwarded", "host=evil.example;proto=https")
	claim.Header.Set("X-Forwarded-Host", "evil.example")
	claimResponse := httptest.NewRecorder()
	router.ServeHTTP(claimResponse, claim)
	if claimResponse.Code != http.StatusSeeOther ||
		claimResponse.Header().Get("Location") != "https://localhost:8443/signed-out" ||
		strings.Contains(claimResponse.Header().Get("Location"), "evil.example") || claimResponse.Body.Len() != 0 {
		t.Fatalf("claim status=%d headers=%v body=%s", claimResponse.Code, claimResponse.Header(), claimResponse.Body.String())
	}
}

func TestSameOriginComparisonCanonicalizesBrowserEquivalentOrigins(t *testing.T) {
	handler := &Handler{publicOrigin: "https://example.com"}
	for name, header := range map[string]string{
		"origin":               "https://EXAMPLE.COM:443",
		"leading-zero origin":  "https://EXAMPLE.COM:0443",
		"referer":              "https://EXAMPLE.COM:443/settings/security",
		"leading-zero referer": "https://EXAMPLE.COM:0443/settings/security",
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/session", nil)
			if strings.Contains(name, "origin") {
				request.Header.Set("Origin", header)
			} else {
				request.Header.Set("Referer", header)
			}
			if err := handler.requireSameOrigin(request); err != nil {
				t.Fatalf("requireSameOrigin() error = %v", err)
			}
		})
	}

	request := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/session", nil)
	request.Header.Set("Origin", "https://example.com:")
	if err := handler.requireSameOrigin(request); !errors.Is(err, authentication.ErrForbidden) {
		t.Fatalf("requireSameOrigin() error = %v, want forbidden for empty port", err)
	}

	handler.publicOrigin = "https://[::1]"
	request = httptest.NewRequest(http.MethodDelete, "/api/v1/auth/session", nil)
	request.Header.Set("Origin", "https://[0:0:0:0:0:0:0:1]")
	if err := handler.requireSameOrigin(request); err != nil {
		t.Fatalf("requireSameOrigin() rejected browser-equivalent IPv6: %v", err)
	}
}

func TestExpiredOrRevokedSessionCannotDeleteAConcurrentlyRotatedCookie(t *testing.T) {
	auth := &transportAuthStub{currentError: authentication.ErrInvalidAuthentication}
	router := newApplicationTestRouter(t, auth, "production", nil)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
	request.AddCookie(&http.Cookie{Name: productionCookie, Value: strings.Repeat("A", 43)})
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusUnauthorized, "authentication_failed")
	if setCookie := response.Header().Get("Set-Cookie"); setCookie != "" {
		t.Fatalf("stale current-session response emitted cookie deletion: %q", setCookie)
	}
}

func TestMissingOrDuplicateSessionCookieCannotTriggerCookieDeletion(t *testing.T) {
	router := newApplicationTestRouter(t, &transportAuthStub{}, "production", nil)
	for name, cookies := range map[string][]*http.Cookie{
		"missing": nil,
		"duplicate": {
			{Name: productionCookie, Value: strings.Repeat("A", 43)},
			{Name: productionCookie, Value: strings.Repeat("B", 43)},
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
			for _, cookie := range cookies {
				request.AddCookie(cookie)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			assertProblem(t, response, http.StatusUnauthorized, "authentication_failed")
			if setCookie := response.Header().Get("Set-Cookie"); setCookie != "" {
				t.Fatalf("unauthenticated request emitted cookie deletion: %q", setCookie)
			}
		})
	}
}

func TestLogoutWithMissingOrDuplicateCookieCannotTriggerCookieDeletion(t *testing.T) {
	router := newApplicationTestRouter(t, &transportAuthStub{}, "production", nil)
	for name, cookies := range map[string][]*http.Cookie{
		"missing": nil,
		"duplicate": {
			{Name: productionCookie, Value: strings.Repeat("A", 43)},
			{Name: productionCookie, Value: strings.Repeat("B", 43)},
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodDelete, "/api/v1/auth/session", nil)
			request.Header.Set("Origin", "https://localhost:8443")
			for _, cookie := range cookies {
				request.AddCookie(cookie)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			assertProblem(t, response, http.StatusUnauthorized, "authentication_failed")
			if setCookie := response.Header().Get("Set-Cookie"); setCookie != "" {
				t.Fatalf("ambiguous logout request emitted cookie deletion: %q", setCookie)
			}
		})
	}
}

func TestCurrentSessionDatabaseOutagePreservesCookie(t *testing.T) {
	auth := &transportAuthStub{currentError: authentication.ErrUnavailable}
	router := newApplicationTestRouter(t, auth, "production", nil)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
	request.AddCookie(&http.Cookie{Name: productionCookie, Value: strings.Repeat("A", 43)})
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
	if setCookie := response.Header().Get("Set-Cookie"); setCookie != "" {
		t.Fatalf("transient outage cleared a live cookie: %q", setCookie)
	}
}

func TestConcurrentCurrentSessionReadsDoNotRotateOrClearCookie(t *testing.T) {
	now := time.Now().UTC()
	credential := authentication.SessionCredential{
		Session: authentication.Session{
			ID: uuid.Must(uuid.NewV7()),
			User: authentication.User{
				ID: uuid.Must(uuid.NewV7()), Email: testStringPointer("admin@example.test"), DisplayName: "Admin",
			},
			CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
			AuthenticationMethod: "totp",
		},
		SessionToken: strings.Repeat("A", 43), CSRFToken: strings.Repeat("B", 43),
	}
	router := newApplicationTestRouter(t, &transportAuthStub{currentResult: credential}, "test", nil)

	responses := make([]*httptest.ResponseRecorder, 2)
	var group sync.WaitGroup
	for index := range responses {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			request := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
			request.AddCookie(&http.Cookie{Name: developmentCookie, Value: credential.SessionToken})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			responses[index] = response
		}(index)
	}
	group.Wait()
	for index, response := range responses {
		if response.Code != http.StatusOK {
			t.Fatalf("response %d status = %d: %s", index, response.Code, response.Body.String())
		}
		if setCookie := response.Header().Get("Set-Cookie"); setCookie != "" {
			t.Fatalf("response %d rotated or cleared cookie: %q", index, setCookie)
		}
	}
}

func TestSessionAndMembershipPaginationParametersReachTheUseCase(t *testing.T) {
	afterSession := uuid.Must(uuid.NewV7())
	nextSession := uuid.Must(uuid.NewV7())
	afterMembership := uuid.Must(uuid.NewV7())
	nextMembership := uuid.Must(uuid.NewV7())
	auth := &transportAuthStub{
		sessionPage:    authentication.SessionPage{NextCursor: &nextSession},
		membershipPage: authentication.TenantMembershipPage{NextCursor: &nextMembership},
	}
	router := newApplicationTestRouter(t, auth, "test", nil)

	for _, requestPath := range []string{
		"/api/v1/auth/sessions?after=" + afterSession.String() + "&limit=37",
		"/api/v1/auth/tenant-memberships?after=" + afterMembership.String() + "&limit=41",
	} {
		request := httptest.NewRequest(http.MethodGet, requestPath, nil)
		request.AddCookie(&http.Cookie{Name: developmentCookie, Value: strings.Repeat("A", 43)})
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s status = %d: %s", requestPath, response.Code, response.Body.String())
		}
		var body struct {
			NextCursor *uuid.UUID `json:"nextCursor"`
		}
		if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
			t.Fatalf("decode %s response: %v", requestPath, err)
		}
		if body.NextCursor == nil {
			t.Fatalf("%s omitted nextCursor", requestPath)
		}
	}
	if auth.sessionAfter == nil || *auth.sessionAfter != afterSession || auth.sessionLimit != 37 {
		t.Fatalf("session pagination = after %v limit %d", auth.sessionAfter, auth.sessionLimit)
	}
	if auth.membershipAfter == nil || *auth.membershipAfter != afterMembership || auth.membershipLimit != 41 {
		t.Fatalf("membership pagination = after %v limit %d", auth.membershipAfter, auth.membershipLimit)
	}
}

func TestInvalidPaginationCursorIsBadRequestWithoutClearingSession(t *testing.T) {
	auth := &transportAuthStub{membershipError: authentication.ErrInvalidInput}
	router := newApplicationTestRouter(t, auth, "production", nil)
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/auth/tenant-memberships?after="+uuid.Must(uuid.NewV7()).String(),
		nil,
	)
	request.AddCookie(&http.Cookie{Name: productionCookie, Value: strings.Repeat("A", 43)})
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusBadRequest, "invalid_request")
	if setCookie := response.Header().Get("Set-Cookie"); setCookie != "" {
		t.Fatalf("invalid cursor cleared session cookie: %q", setCookie)
	}
}

func TestSameTenantSwitchDoesNotRewriteSessionCookie(t *testing.T) {
	now := time.Now().UTC()
	token := strings.Repeat("A", 43)
	tenantID := uuid.Must(uuid.NewV7())
	auth := &transportAuthStub{switchResult: authentication.SessionCredential{
		Session: authentication.Session{
			ID: uuid.Must(uuid.NewV7()), User: authentication.User{
				ID: uuid.Must(uuid.NewV7()), Email: testStringPointer("admin@example.test"), DisplayName: "Admin",
			},
			ActiveTenantID: &tenantID, CreatedAt: now, LastSeenAt: now,
			IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
			AuthenticationMethod: "totp",
		},
		SessionToken: token, CSRFToken: strings.Repeat("B", 43),
	}}
	router := newApplicationTestRouter(t, auth, "test", nil)
	request := httptest.NewRequest(
		http.MethodPut, "/api/v1/auth/session/tenant", strings.NewReader(`{"tenantId":"`+tenantID.String()+`"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.Header.Set(csrfTokenHeader, strings.Repeat("B", 43))
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: token})
	request.RemoteAddr = "198.51.100.20:4242"
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if setCookie := response.Header().Get("Set-Cookie"); setCookie != "" {
		t.Fatalf("same-tenant switch rewrote cookie: %q", setCookie)
	}
	if auth.switchCalls != 1 {
		t.Fatalf("SwitchTenant calls = %d, want 1", auth.switchCalls)
	}
}

func TestTenantSwitchThrottleUsesRetryAfterProblem(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	auth := &transportAuthStub{switchError: &authentication.RateLimitError{RetryAfter: 90 * time.Second}}
	router := newApplicationTestRouter(t, auth, "test", nil)
	request := httptest.NewRequest(
		http.MethodPut, "/api/v1/auth/session/tenant", strings.NewReader(`{"tenantId":"`+tenantID.String()+`"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.Header.Set(csrfTokenHeader, strings.Repeat("B", 43))
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: strings.Repeat("A", 43)})
	request.RemoteAddr = "198.51.100.20:4242"
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusTooManyRequests, "rate_limited")
	if retryAfter := response.Header().Get("Retry-After"); retryAfter != "90" {
		t.Fatalf("Retry-After = %q, want 90", retryAfter)
	}
}

func TestSessionCookieNamesAreValidForEnvironment(t *testing.T) {
	expires := time.Now().Add(time.Hour)
	for _, test := range []struct {
		name         string
		environment  string
		publicOrigin string
		cookieName   string
		secure       bool
	}{
		{name: "production HTTPS", environment: "production", publicOrigin: "https://periapsis.example.com", cookieName: productionCookie, secure: true},
		{name: "development HTTPS", environment: "development", publicOrigin: "https://localhost:8443", cookieName: productionCookie, secure: true},
		{name: "development HTTP", environment: "development", publicOrigin: "http://localhost:8081", cookieName: developmentCookie, secure: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy, err := newSessionCookiePolicy(test.environment, test.publicOrigin)
			if err != nil {
				t.Fatalf("newSessionCookiePolicy() error = %v", err)
			}
			handler := &Handler{cookie: policy}
			response := httptest.NewRecorder()
			handler.setSessionCookie(response, strings.Repeat("A", 43), expires)
			cookies := response.Result().Cookies()
			if len(cookies) != 1 || cookies[0].Name != test.cookieName || cookies[0].Secure != test.secure {
				t.Fatalf("cookies = %#v", cookies)
			}
			if strings.HasPrefix(cookies[0].Name, "__Host-") && !cookies[0].Secure {
				t.Fatal("an invalid insecure __Host- cookie was emitted")
			}
		})
	}
	if _, err := newSessionCookiePolicy("production", "http://localhost:8081"); err == nil {
		t.Fatal("production accepted an insecure public origin")
	}
	for _, test := range []struct {
		name    string
		factory func() (sessionCookiePolicy, error)
		want    string
	}{
		{name: "MFA", factory: func() (sessionCookiePolicy, error) {
			return newMFACookiePolicy("development", "https://localhost:8443")
		}, want: productionMFACookie},
		{name: "federated continuation", factory: func() (sessionCookiePolicy, error) {
			return newFederatedContinuationCookiePolicy("development", "https://localhost:8443")
		}, want: productionFederatedContinuationCookie},
	} {
		policy, err := test.factory()
		if err != nil || policy.name != test.want || !policy.secure {
			t.Fatalf("development HTTPS %s cookie policy = %#v, %v", test.name, policy, err)
		}
	}
}

func TestResolveClientAddressTrustBoundary(t *testing.T) {
	trusted := []netip.Prefix{
		netip.MustParsePrefix("172.30.240.3/32"),
		netip.MustParsePrefix("10.20.0.0/16"),
	}

	direct := httptest.NewRequest(http.MethodPost, "/", nil)
	direct.RemoteAddr = "198.51.100.40:1234"
	direct.Header.Set("X-Forwarded-For", "203.0.113.99")
	address, err := resolveClientAddress(direct, trusted)
	if err != nil || address.String() != "198.51.100.40" {
		t.Fatalf("untrusted direct address = %v, err = %v", address, err)
	}

	proxied := httptest.NewRequest(http.MethodPost, "/", nil)
	proxied.RemoteAddr = "172.30.240.3:40000"
	proxied.Header.Set("X-Forwarded-For", "203.0.113.50")
	address, err = resolveClientAddress(proxied, trusted)
	if err != nil || address.String() != "203.0.113.50" {
		t.Fatalf("trusted proxy address = %v, err = %v", address, err)
	}

	chain := httptest.NewRequest(http.MethodPost, "/", nil)
	chain.RemoteAddr = "172.30.240.3:40000"
	chain.Header.Set("X-Forwarded-For", "198.51.100.60, 10.20.3.4")
	address, err = resolveClientAddress(chain, trusted)
	if err != nil || address.String() != "198.51.100.60" {
		t.Fatalf("trusted proxy chain address = %v, err = %v", address, err)
	}

	malformed := httptest.NewRequest(http.MethodPost, "/", nil)
	malformed.RemoteAddr = "172.30.240.3:40000"
	malformed.Header.Set("X-Forwarded-For", "203.0.113.50, not-an-address")
	if _, err := resolveClientAddress(malformed, trusted); err == nil {
		t.Fatal("malformed trusted proxy chain was accepted")
	}

	duplicate := httptest.NewRequest(http.MethodPost, "/", nil)
	duplicate.RemoteAddr = "172.30.240.3:40000"
	duplicate.Header.Add("X-Forwarded-For", "203.0.113.50")
	duplicate.Header.Add("X-Forwarded-For", "203.0.113.50")
	if _, err := resolveClientAddress(duplicate, trusted); err == nil {
		t.Fatal("duplicate forwarding headers were accepted")
	}
}

func newApplicationTestRouter(
	t *testing.T,
	auth AuthenticationService,
	environment string,
	trusted []netip.Prefix,
) http.Handler {
	logout := &transportSessionLogoutStub{result: sessionlogout.Result{
		LocalRevoked: true,
	}}
	if concrete, ok := auth.(*transportAuthStub); ok {
		logout.auth = concrete
	}
	return newApplicationTestRouterWithSessionLogout(t, auth, logout, environment, trusted)
}

func newApplicationTestRouterWithSessionLogout(
	t *testing.T,
	auth AuthenticationService,
	logout SessionLogoutService,
	environment string,
	trusted []netip.Prefix,
) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	publicOrigin := "http://localhost:8081"
	if environment == "production" {
		publicOrigin = "https://localhost:8443"
	}
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, logger, "test", time.Second,
		ApplicationOptions{
			Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: auth, SessionLogout: logout, Authorization: &transportAuthorizationStub{},
			Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{},
			Environment: environment, IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{}, MFA: &transportMFAStub{}, Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{},
			PublicOrigin: publicOrigin, ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{}, Ticketing: &transportTicketingStub{}, WorkflowAdministration: &transportWorkflowAdministrationStub{}, TrustedProxyCIDRs: trusted,
		},
	)
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}

func TestMapSessionOmitsUnavailableFederatedEmail(t *testing.T) {
	now := time.Now().UTC()
	mapped, err := mapSession(authentication.Session{
		ID: uuid.Must(uuid.NewV7()),
		User: authentication.User{
			ID:          uuid.Must(uuid.NewV7()),
			DisplayName: "Federated Responder",
		},
		CreatedAt: now, LastSeenAt: now,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
		AuthenticationMethod: "totp",
	}, "csrf-token")
	if err != nil {
		t.Fatalf("mapSession() error = %v", err)
	}
	if mapped.User.Email != nil {
		t.Fatalf("mapped email = %q, want omitted", *mapped.User.Email)
	}
	if mapped.User.DisplayName != "Federated Responder" {
		t.Fatalf("mapped display name = %q", mapped.User.DisplayName)
	}
}

func TestMapSessionProjectsOnlyCanonicalFederatedAuthenticationMethods(t *testing.T) {
	now := time.Now().UTC()
	for _, method := range []string{"oidc", "saml"} {
		t.Run(method, func(t *testing.T) {
			mapped, err := mapSession(authentication.Session{
				ID: uuid.Must(uuid.NewV7()),
				User: authentication.User{
					ID: uuid.Must(uuid.NewV7()), DisplayName: "Federated Responder",
				},
				CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now.Add(time.Hour),
				AbsoluteExpiresAt: now.Add(8 * time.Hour), AuthenticationMethod: method,
			}, "csrf-token")
			if err != nil || string(mapped.AuthenticationMethod) != method {
				t.Fatalf("mapSession(%q) = %#v, %v", method, mapped, err)
			}
		})
	}
	if _, err := mapSession(authentication.Session{
		ID:                   uuid.Must(uuid.NewV7()),
		User:                 authentication.User{ID: uuid.Must(uuid.NewV7()), DisplayName: "Responder"},
		AuthenticationMethod: "kerberos",
	}, "csrf-token"); err == nil {
		t.Fatal("mapSession() accepted an unknown authentication method")
	}
}

func assertProblem(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d, want %d: %s", response.Code, status, response.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if body.Code != code {
		t.Fatalf("problem code = %q, want %q", body.Code, code)
	}
}

func testStringPointer(value string) *string {
	return &value
}
