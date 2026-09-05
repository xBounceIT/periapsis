package httpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

type platformOIDCBrowserAuthenticationStub struct {
	readyCalls      int
	readyError      error
	starts          []PlatformOIDCBrowserStartRequest
	completions     []platformoidcauth.CompleteDirectOIDCRequest
	totpStarts      []platformoidcauth.StartDirectTOTPCommand
	totpCompletions []platformoidcauth.CompleteDirectTOTPCommand
	start           func(PlatformOIDCBrowserStartRequest) (FederatedBrowserStart, error)
	complete        func(platformoidcauth.CompleteDirectOIDCRequest) (platformoidcauth.DirectOIDCBrowserOutcome, error)
	totpStart       func(platformoidcauth.StartDirectTOTPCommand) (PlatformOIDCTOTPStart, error)
	totpComplete    func(platformoidcauth.CompleteDirectTOTPCommand) (platformoidcauth.DirectTOTPCompletionOutcome, error)
}

func (stub *platformOIDCBrowserAuthenticationStub) Ready(context.Context) error {
	stub.readyCalls++
	return stub.readyError
}

func (stub *platformOIDCBrowserAuthenticationStub) Start(
	_ context.Context,
	request PlatformOIDCBrowserStartRequest,
) (FederatedBrowserStart, error) {
	request.Receipt = append([]byte(nil), request.Receipt...)
	request.BrowserCapability = append([]byte(nil), request.BrowserCapability...)
	request.PreviousBrowserHandle = append([]byte(nil), request.PreviousBrowserHandle...)
	stub.starts = append(stub.starts, request)
	if stub.start == nil {
		return FederatedBrowserStart{}, platformoidcauth.ErrDirectAuthenticationDenied
	}
	return stub.start(request)
}

func (stub *platformOIDCBrowserAuthenticationStub) Complete(
	_ context.Context,
	request platformoidcauth.CompleteDirectOIDCRequest,
) (platformoidcauth.DirectOIDCBrowserOutcome, error) {
	request.BrowserHandle = append([]byte(nil), request.BrowserHandle...)
	request.BrowserCapability = append([]byte(nil), request.BrowserCapability...)
	stub.completions = append(stub.completions, request)
	if stub.complete == nil {
		return platformoidcauth.DirectOIDCBrowserOutcome{}, platformoidcauth.ErrDirectAuthenticationDenied
	}
	return stub.complete(request)
}

func (stub *platformOIDCBrowserAuthenticationStub) StartTOTP(
	_ context.Context,
	command platformoidcauth.StartDirectTOTPCommand,
) (PlatformOIDCTOTPStart, error) {
	stub.totpStarts = append(stub.totpStarts, command)
	if stub.totpStart == nil {
		return PlatformOIDCTOTPStart{}, platformoidcauth.ErrDirectAuthenticationDenied
	}
	return stub.totpStart(command)
}

func (stub *platformOIDCBrowserAuthenticationStub) CompleteTOTP(
	_ context.Context,
	command platformoidcauth.CompleteDirectTOTPCommand,
) (platformoidcauth.DirectTOTPCompletionOutcome, error) {
	command.BrowserHandle = append([]byte(nil), command.BrowserHandle...)
	command.Code = append([]byte(nil), command.Code...)
	stub.totpCompletions = append(stub.totpCompletions, command)
	if stub.totpComplete == nil {
		return platformoidcauth.DirectTOTPCompletionOutcome{}, platformoidcauth.ErrDirectAuthenticationDenied
	}
	return stub.totpComplete(command)
}

func TestPlatformOIDCStartBindsCompositeCookieAndExactAudit(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	operationID := uuid.Must(uuid.NewV7())
	oldTransactionRaw := repeatedPlatformOIDCSecret(0x21)
	oldTransaction := []byte(base64.RawURLEncoding.EncodeToString(oldTransactionRaw))
	oldBrowser := repeatedPlatformOIDCSecret(0x22)
	newTransactionRaw := repeatedPlatformOIDCSecret(0x31)
	newTransaction := []byte(base64.RawURLEncoding.EncodeToString(newTransactionRaw))
	receipt := repeatedPlatformOIDCSecret(0x41)
	browser := repeatedPlatformOIDCSecret(0x42)
	stub := &platformOIDCBrowserAuthenticationStub{}
	stub.start = func(request PlatformOIDCBrowserStartRequest) (FederatedBrowserStart, error) {
		return FederatedBrowserStart{
			RedirectURL:   "https://idp.example.test/authorize?state=direct",
			BrowserHandle: append([]byte(nil), newTransaction...), ExpiresAt: now.Add(5 * time.Minute),
		}, nil
	}
	handler, router := newPlatformOIDCTestRouter(t, stub, &transportAuthStub{})
	handler.federated.random = bytes.NewReader(append(append([]byte(nil), receipt...), browser...))
	handler.federated.newID = func() (uuid.UUID, error) { return operationID, nil }
	handler.federated.now = func() time.Time { return now }
	previousRecorder := httptest.NewRecorder()
	if err := setPlatformOIDCTransactionCookie(
		previousRecorder, handler.federated.platformOIDCCookie,
		oldTransaction, oldBrowser, now.Add(4*time.Minute), now,
	); err != nil {
		t.Fatalf("previous direct cookie: %v", err)
	}
	previousCookie := findPositiveResponseCookie(
		previousRecorder.Result().Cookies(), developmentPlatformOIDCTransactionCookie,
	)
	request := federatedStartRequest(
		"/api/v1/auth/platform/oidc/corp_oidc/start", "/alerts?queue=mine",
	)
	request.Header.Set("User-Agent", "periapsis-direct-http-test")
	request.RemoteAddr = "192.0.2.44:43210"
	request.AddCookie(previousCookie)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") !=
		"https://idp.example.test/authorize?state=direct" {
		t.Fatalf("start = %d location=%q body=%s", response.Code, response.Header().Get("Location"), response.Body)
	}
	if stub.readyCalls != 1 || len(stub.starts) != 1 {
		t.Fatalf("ready/start calls = %d/%d", stub.readyCalls, len(stub.starts))
	}
	captured := stub.starts[0]
	if captured.OperationRunID != identity.EntityID(operationID) || captured.ProviderKey != "corp_oidc" ||
		captured.NetworkAddress != "192.0.2.44" || captured.ReturnPath != "/alerts?queue=mine" ||
		captured.HasAuthenticatedSession || !bytes.Equal(captured.Receipt, receipt) ||
		!bytes.Equal(captured.BrowserCapability, browser) ||
		!bytes.Equal(captured.PreviousBrowserHandle, oldTransaction) ||
		captured.Audit.UserAgent != "periapsis-direct-http-test" ||
		captured.Audit.RequestID == (identity.EntityID{}) ||
		captured.Audit.CorrelationID != captured.Audit.RequestID {
		t.Fatalf("captured start = %s", captured.String())
	}
	responseCookie := findPositiveResponseCookie(
		response.Result().Cookies(), developmentPlatformOIDCTransactionCookie,
	)
	if responseCookie == nil {
		t.Fatal("direct transaction cookie was not emitted")
	}
	callback := httptest.NewRequest(http.MethodGet, "/api/v1/auth/platform/oidc/callback", nil)
	callback.AddCookie(responseCookie)
	decoded, err := platformOIDCTransactionCookie(callback, handler.federated.platformOIDCCookie, true)
	if err != nil {
		t.Fatalf("decode response cookie: %v", err)
	}
	defer decoded.destroy()
	if !bytes.Equal(decoded.transactionHandle, newTransaction) ||
		!bytes.Equal(decoded.browserCapability, browser) {
		t.Fatalf("response cookie = %s", decoded.String())
	}
}

func TestPlatformOIDCCallbackCreatesOnlyTenantlessOIDCSession(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	fixture := newDirectPlatformSessionFixture(t, now, "/alerts", 0x61)
	auth := &transportAuthStub{currentResult: fixture.current}
	stub := &platformOIDCBrowserAuthenticationStub{}
	stub.complete = func(platformoidcauth.CompleteDirectOIDCRequest) (platformoidcauth.DirectOIDCBrowserOutcome, error) {
		return fixture.outcome, nil
	}
	handler, router := newPlatformOIDCTestRouter(t, stub, auth)
	handler.federated.now = func() time.Time { return now }
	transactionRaw := repeatedPlatformOIDCSecret(0x51)
	browser := repeatedPlatformOIDCSecret(0x52)
	request := platformOIDCCallbackRequest(t, handler, now, transactionRaw, browser)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/alerts" ||
		auth.currentToken != fixture.token {
		t.Fatalf("callback = %d location=%q current=%q body=%s", response.Code, response.Header().Get("Location"), auth.currentToken, response.Body)
	}
	if len(stub.completions) != 1 || stub.completions[0].RawQuery != "code=opaque&state=opaque" ||
		!bytes.Equal(stub.completions[0].BrowserHandle, []byte(base64.RawURLEncoding.EncodeToString(transactionRaw))) ||
		!bytes.Equal(stub.completions[0].BrowserCapability, browser) {
		t.Fatalf("complete request = %s", stub.completions[0].String())
	}
	assertFederatedTransactionCookie(
		t, response.Result().Cookies(), developmentPlatformOIDCTransactionCookie, "", true,
	)
	if findPositiveResponseCookie(response.Result().Cookies(), developmentCookie) == nil ||
		findPositiveResponseCookie(response.Result().Cookies(), developmentFederatedContinuationCookie) != nil {
		t.Fatalf("completion cookies = %#v", response.Result().Cookies())
	}
}

func TestPlatformOIDCCallbackEmitsOnlyV2DirectContinuation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	fixture := newDirectPlatformContinuationFixture(t, now, "/alerts", 0x71)
	stub := &platformOIDCBrowserAuthenticationStub{}
	stub.complete = func(platformoidcauth.CompleteDirectOIDCRequest) (platformoidcauth.DirectOIDCBrowserOutcome, error) {
		return fixture.outcome, nil
	}
	handler, router := newPlatformOIDCTestRouter(t, stub, &transportAuthStub{})
	handler.federated.now = func() time.Time { return now }
	request := platformOIDCCallbackRequest(
		t, handler, now, repeatedPlatformOIDCSecret(0x72), repeatedPlatformOIDCSecret(0x73),
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != federatedContinuationPath {
		t.Fatalf("callback = %d location=%q body=%s", response.Code, response.Header().Get("Location"), response.Body)
	}
	if findPositiveResponseCookie(response.Result().Cookies(), developmentCookie) != nil {
		t.Fatal("direct continuation emitted a session cookie")
	}
	continuationCookie := findPositiveResponseCookie(
		response.Result().Cookies(), developmentFederatedContinuationCookie,
	)
	if continuationCookie == nil {
		t.Fatal("direct continuation cookie missing")
	}
	decodeRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	decodeRequest.AddCookie(continuationCookie)
	capability, err := federatedContinuationCapabilityCookie(
		decodeRequest, handler.federatedContinuationCookie,
	)
	if err != nil {
		t.Fatalf("decode direct continuation: %v", err)
	}
	defer capability.destroy()
	if capability.authority != federatedauth.ContinuationAuthorityDirectPlatformOIDC ||
		identity.EntityID(capability.continuationID) != fixture.outcome.ContinuationID ||
		!bytes.Equal(capability.receipt, fixture.receipt) {
		t.Fatalf("continuation capability = %#v", capability)
	}
}

func TestDirectPlatformContinuationUsesOnlyDirectTOTPPath(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	continuationID := identity.EntityID(uuid.Must(uuid.NewV7()))
	factorID := identity.EntityID(uuid.Must(uuid.NewV7()))
	challengeID := platformoidcauth.DirectTOTPChallengeID(sha256.Sum256([]byte("direct-totp-challenge")))
	browserHandle := federatedOpaque(0x81)
	receipt := federatedOpaque(0x82)
	stub := &platformOIDCBrowserAuthenticationStub{}
	stub.totpStart = func(command platformoidcauth.StartDirectTOTPCommand) (PlatformOIDCTOTPStart, error) {
		return PlatformOIDCTOTPStart{
			ChallengeID: challengeID, BrowserHandle: append([]byte(nil), browserHandle...),
			FactorID: factorID, ExpiresAt: now.Add(5 * time.Minute),
		}, nil
	}
	handler, router := newPlatformOIDCTestRouter(t, stub, &transportAuthStub{})
	handler.federated.now = func() time.Time { return now }
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/federated/mfa/step-up", nil)
	request.Header.Set("Origin", "http://localhost:8081")
	request.Header.Set("User-Agent", "periapsis-direct-totp-test")
	request.RemoteAddr = "192.0.2.80:45000"
	addDirectContinuationCookie(t, request, handler, continuationID, receipt, now)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || len(stub.totpStarts) != 1 {
		t.Fatalf("direct TOTP start = %d calls=%d body=%s", response.Code, len(stub.totpStarts), response.Body)
	}
	wantDigest, err := federatedauth.ContinuationReceiptDigest(
		federatedauth.ContinuationAuthorityDirectPlatformOIDC, continuationID, receipt,
	)
	if err != nil || stub.totpStarts[0].Authority != federatedauth.ContinuationAuthorityDirectPlatformOIDC ||
		stub.totpStarts[0].ContinuationID != continuationID || stub.totpStarts[0].ReceiptDigest != wantDigest {
		t.Fatalf("direct TOTP command = %s, digest error=%v", stub.totpStarts[0].String(), err)
	}
	var body contract.MfaStepUpChallenge
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil ||
		body.ChallengeId != encodeChallengeID(mfa.ChallengeID(challengeID)) ||
		len(body.Methods) != 1 || body.Methods[0] != contract.MfaStepUpMethodTotp ||
		len(body.TotpFactorIds) != 1 || body.TotpFactorIds[0] != uuid.UUID(factorID) {
		t.Fatalf("direct TOTP response = %#v, %v", body, err)
	}
	if cookie := findPositiveResponseCookie(response.Result().Cookies(), developmentMFACookie); cookie == nil ||
		cookie.Value != string(browserHandle) {
		t.Fatalf("MFA cookie = %#v", cookie)
	}
}

func TestDirectPlatformTOTPCompletionRevalidatesTenantlessSession(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	continuationID := identity.EntityID(uuid.Must(uuid.NewV7()))
	factorID := identity.EntityID(uuid.Must(uuid.NewV7()))
	challengeID := platformoidcauth.DirectTOTPChallengeID(sha256.Sum256([]byte("direct-totp-complete")))
	browserHandle := federatedOpaque(0x91)
	receipt := federatedOpaque(0x92)
	fixture := newDirectPlatformSessionFixture(t, now, "/unused", 0x93)
	auth := &transportAuthStub{currentResult: fixture.current}
	stub := &platformOIDCBrowserAuthenticationStub{}
	stub.totpComplete = func(platformoidcauth.CompleteDirectTOTPCommand) (platformoidcauth.DirectTOTPCompletionOutcome, error) {
		return platformoidcauth.DirectTOTPCompletionOutcome{
			SessionID: fixture.outcome.SessionID, UserID: fixture.outcome.UserID,
			FactorID: factorID, Counter: 42, Credential: fixture.outcome.Credential,
		}, nil
	}
	handler, router := newPlatformOIDCTestRouter(t, stub, auth)
	handler.federated.now = func() time.Time { return now }
	target := "/api/v1/auth/federated/mfa/step-up/" +
		encodeChallengeID(mfa.ChallengeID(challengeID)) + "/totp"
	body := `{"factorId":"` + uuid.UUID(factorID).String() + `","code":"123456"}`
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.Header.Set("User-Agent", "periapsis-direct-totp-test")
	request.RemoteAddr = "192.0.2.81:45001"
	addDirectContinuationCookie(t, request, handler, continuationID, receipt, now)
	request.AddCookie(&http.Cookie{Name: developmentMFACookie, Value: string(browserHandle)})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || len(stub.totpCompletions) != 1 ||
		auth.currentToken != fixture.token {
		t.Fatalf("direct TOTP completion = %d calls=%d token=%q body=%s", response.Code, len(stub.totpCompletions), auth.currentToken, response.Body)
	}
	captured := stub.totpCompletions[0]
	if captured.ChallengeID != challengeID || captured.FactorID != factorID ||
		captured.ContinuationID != continuationID ||
		captured.Authority != federatedauth.ContinuationAuthorityDirectPlatformOIDC ||
		!bytes.Equal(captured.BrowserHandle, browserHandle) || string(captured.Code) != "123456" ||
		captured.Audit.UserAgent != "periapsis-direct-totp-test" {
		t.Fatalf("direct TOTP completion request = %s", captured.String())
	}
	wantReceiptDigest, err := federatedauth.ContinuationReceiptDigest(
		federatedauth.ContinuationAuthorityDirectPlatformOIDC, continuationID, receipt,
	)
	if err != nil || captured.ReceiptDigest != wantReceiptDigest {
		t.Fatalf("direct TOTP completion receipt binding = %x, %v", captured.ReceiptDigest, err)
	}
	var mapped contract.Session
	if err := json.Unmarshal(response.Body.Bytes(), &mapped); err != nil || mapped.ActiveTenantId != nil ||
		mapped.Id != uuid.UUID(fixture.outcome.SessionID) || mapped.AuthenticationMethod != contract.SessionAuthenticationMethodOidc {
		t.Fatalf("mapped direct session = %#v, %v", mapped, err)
	}
	if findPositiveResponseCookie(response.Result().Cookies(), developmentCookie) == nil ||
		findPositiveResponseCookie(response.Result().Cookies(), developmentMFACookie) != nil ||
		findPositiveResponseCookie(response.Result().Cookies(), developmentFederatedContinuationCookie) != nil {
		t.Fatalf("completion cookies = %#v", response.Result().Cookies())
	}
}

func TestDirectPlatformTOTPCommittedMalformedOutcomeClearsDeadCapabilities(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	continuationID := identity.EntityID(uuid.Must(uuid.NewV7()))
	factorID := identity.EntityID(uuid.Must(uuid.NewV7()))
	challengeID := platformoidcauth.DirectTOTPChallengeID(sha256.Sum256([]byte("direct-totp-malformed")))
	receipt := federatedOpaque(0x9a)
	stub := &platformOIDCBrowserAuthenticationStub{}
	stub.totpComplete = func(platformoidcauth.CompleteDirectTOTPCommand) (platformoidcauth.DirectTOTPCompletionOutcome, error) {
		// Nil error represents a committed apply; the deliberately malformed
		// delivery projection must not leave either dead browser capability.
		return platformoidcauth.DirectTOTPCompletionOutcome{}, nil
	}
	handler, router := newPlatformOIDCTestRouter(t, stub, &transportAuthStub{})
	target := "/api/v1/auth/federated/mfa/step-up/" +
		encodeChallengeID(mfa.ChallengeID(challengeID)) + "/totp"
	body := `{"factorId":"` + uuid.UUID(factorID).String() + `","code":"123456"}`
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.Header.Set("User-Agent", "periapsis-direct-malformed-test")
	addDirectContinuationCookie(t, request, handler, continuationID, receipt, now)
	request.AddCookie(&http.Cookie{Name: developmentMFACookie, Value: string(federatedOpaque(0x9b))})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || len(stub.totpCompletions) != 1 {
		t.Fatalf("malformed committed outcome = %d calls=%d body=%s", response.Code, len(stub.totpCompletions), response.Body)
	}
	assertClearedStrictCookie(t, response.Result().Cookies(), developmentMFACookie)
	assertClearedStrictCookie(t, response.Result().Cookies(), developmentFederatedContinuationCookie)
}

func TestDirectPlatformContinuationRejectsTenantRecoveryPasskeyAndEnrollment(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	continuationID := identity.EntityID(uuid.Must(uuid.NewV7()))
	receipt := federatedOpaque(0xa1)
	browserHandle := federatedOpaque(0xa2)
	stub := &platformOIDCBrowserAuthenticationStub{}
	handler, router := newPlatformOIDCTestRouter(t, stub, &transportAuthStub{})
	tests := []struct {
		name        string
		method      string
		target      string
		ceremony    bool
		contentType bool
		body        string
	}{
		{name: "recovery", method: http.MethodPost, target: "/api/v1/auth/federated/mfa/step-up/" + string(federatedOpaque(0xa3)) + "/recovery", ceremony: true, contentType: true, body: `{"code":"recovery"}`},
		{name: "passkey start", method: http.MethodPost, target: "/api/v1/auth/federated/mfa/passkeys/options"},
		{name: "passkey complete", method: http.MethodPost, target: "/api/v1/auth/federated/mfa/passkeys/verify", ceremony: true, contentType: true, body: `{}`},
		{name: "TOTP enrollment", method: http.MethodPost, target: "/api/v1/auth/federated/mfa/totp/enrollments"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.target, strings.NewReader(test.body))
			request.Header.Set("Origin", "http://localhost:8081")
			request.Header.Set("User-Agent", "periapsis-direct-negative-test")
			if test.contentType {
				request.Header.Set("Content-Type", "application/json")
			}
			addDirectContinuationCookie(t, request, handler, continuationID, receipt, now)
			if test.ceremony {
				request.AddCookie(&http.Cookie{Name: developmentMFACookie, Value: string(browserHandle)})
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusForbidden {
				t.Fatalf("unsupported direct factor = %d body=%s", response.Code, response.Body)
			}
		})
	}
}

type directPlatformSessionFixture struct {
	outcome platformoidcauth.DirectOIDCBrowserOutcome
	current authentication.SessionCredential
	token   string
}

func newDirectPlatformSessionFixture(
	t testing.TB,
	now time.Time,
	returnPath string,
	fill byte,
) directPlatformSessionFixture {
	t.Helper()
	sessionID := identity.EntityID(uuid.Must(uuid.NewV7()))
	familyID := identity.EntityID(uuid.Must(uuid.NewV7()))
	userID := identity.EntityID(uuid.Must(uuid.NewV7()))
	token := federatedOpaque(fill)
	csrf := federatedOpaque(fill + 1)
	reservation, err := mfa.NewSessionReservation(mfa.SessionMaterial{
		SessionID: sessionID, FamilyID: familyID,
		TokenDigest: sha256.Sum256(token), CSRFDigest: sha256.Sum256(csrf),
		AuthenticationMethod: mfa.SessionAuthenticationOIDC,
		IdleExpiresAt:        now.Add(time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("direct session reservation: %v", err)
	}
	owned, err := federatedauth.NewSessionApplyCredentialReservation(reservation, token, csrf)
	if err != nil {
		t.Fatalf("direct browser credential: %v", err)
	}
	credential, released := owned.ReleaseBrowserCredential(sessionID, identity.EntityID{})
	if !released {
		t.Fatal("release direct browser credential")
	}
	return directPlatformSessionFixture{
		outcome: platformoidcauth.DirectOIDCBrowserOutcome{
			Disposition: platformoidcauth.DirectAuthenticationImmediateSession,
			UserID:      userID, SessionID: sessionID, ReturnPath: returnPath, Credential: credential,
		},
		current: authentication.SessionCredential{
			Session: authentication.Session{
				ID: uuid.UUID(sessionID), RotationFamilyID: uuid.UUID(familyID),
				User:      authentication.User{ID: uuid.UUID(userID), DisplayName: "Direct operator"},
				CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now.Add(time.Hour),
				AbsoluteExpiresAt: now.Add(8 * time.Hour), AuthenticationMethod: string(federatedauth.AuthenticationMethodOIDC),
			},
			SessionToken: string(token), CSRFToken: string(csrf),
		},
		token: string(token),
	}
}

type directPlatformContinuationFixture struct {
	outcome platformoidcauth.DirectOIDCBrowserOutcome
	receipt []byte
}

func newDirectPlatformContinuationFixture(
	t testing.TB,
	now time.Time,
	returnPath string,
	fill byte,
) directPlatformContinuationFixture {
	t.Helper()
	continuationID := identity.EntityID(uuid.Must(uuid.NewV7()))
	userID := identity.EntityID(uuid.Must(uuid.NewV7()))
	receipt := federatedOpaque(fill)
	digest, err := federatedauth.ContinuationReceiptDigest(
		federatedauth.ContinuationAuthorityDirectPlatformOIDC, continuationID, receipt,
	)
	if err != nil {
		t.Fatalf("direct continuation digest: %v", err)
	}
	reservation, err := federatedauth.NewPostPrimaryContinuationReservation(
		federatedauth.PostPrimaryContinuationMaterial{
			ContinuationID: continuationID,
			Authority:      federatedauth.ContinuationAuthorityDirectPlatformOIDC,
			ReceiptDigest:  digest, ExpiresAt: now.Add(5 * time.Minute),
		},
		now,
	)
	if err != nil {
		t.Fatalf("direct continuation reservation: %v", err)
	}
	owned, err := federatedauth.NewContinuationApplyCredentialReservation(reservation, receipt)
	if err != nil {
		t.Fatalf("direct continuation credential: %v", err)
	}
	credential, released := owned.ReleaseBrowserCredential(identity.EntityID{}, continuationID)
	if !released {
		t.Fatal("release direct continuation credential")
	}
	return directPlatformContinuationFixture{
		outcome: platformoidcauth.DirectOIDCBrowserOutcome{
			Disposition: platformoidcauth.DirectAuthenticationTOTPContinuation,
			UserID:      userID, ContinuationID: continuationID,
			ReturnPath: returnPath, Credential: credential,
		},
		receipt: append([]byte(nil), receipt...),
	}
}

func newPlatformOIDCTestRouter(
	t testing.TB,
	service PlatformOIDCBrowserAuthentication,
	auth AuthenticationService,
) (*Handler, http.Handler) {
	t.Helper()
	options := completeFederatedApplicationOptions(auth)
	options.PlatformOIDCBrowser = service
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, testDiscardLogger(), "test", time.Second, options,
	)
	if err != nil {
		t.Fatalf("NewApplicationHandler: %v", err)
	}
	return handler, Router(handler, testDiscardLogger(), false)
}

func platformOIDCCallbackRequest(
	t testing.TB,
	handler *Handler,
	now time.Time,
	transactionRaw []byte,
	browserCapability []byte,
) *http.Request {
	t.Helper()
	transactionHandle := []byte(base64.RawURLEncoding.EncodeToString(transactionRaw))
	recorder := httptest.NewRecorder()
	if err := setPlatformOIDCTransactionCookie(
		recorder, handler.federated.platformOIDCCookie, transactionHandle,
		browserCapability, now.Add(5*time.Minute), now,
	); err != nil {
		t.Fatalf("set callback cookie: %v", err)
	}
	cookie := findPositiveResponseCookie(
		recorder.Result().Cookies(), developmentPlatformOIDCTransactionCookie,
	)
	request := httptest.NewRequest(
		http.MethodGet, "/api/v1/auth/platform/oidc/callback?code=opaque&state=opaque", nil,
	)
	request.Header.Set("User-Agent", "periapsis-direct-callback-test")
	request.RemoteAddr = "192.0.2.55:44000"
	request.AddCookie(cookie)
	return request
}

func addDirectContinuationCookie(
	t testing.TB,
	request *http.Request,
	handler *Handler,
	continuationID identity.EntityID,
	receipt []byte,
	now time.Time,
) {
	t.Helper()
	recorder := httptest.NewRecorder()
	if err := setFederatedContinuationCookieForAuthorityWithPolicy(
		recorder, handler.federatedContinuationCookie,
		federatedauth.ContinuationAuthorityDirectPlatformOIDC,
		uuid.UUID(continuationID), receipt, now.Add(5*time.Minute), now,
	); err != nil {
		t.Fatalf("set direct continuation cookie: %v", err)
	}
	cookie := findPositiveResponseCookie(
		recorder.Result().Cookies(), developmentFederatedContinuationCookie,
	)
	if cookie == nil {
		t.Fatal("direct continuation cookie missing")
	}
	request.AddCookie(cookie)
}

func testDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
