package httpserver

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamladapter"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

type platformSAMLBrowserAuthenticationStub struct {
	readyCalls   int
	readyError   error
	starts       []PlatformSAMLBrowserStartRequest
	completions  []platformsamlauth.CompleteRequest
	metadataKeys []string
	start        func(PlatformSAMLBrowserStartRequest) (platformsamladapter.RedirectResponse, error)
	complete     func(platformsamlauth.CompleteRequest, platformsamladapter.BrowserDeliverySink) error
	metadata     func(string) (platformsamladapter.DirectSAMLMetadataDocument, error)
}

type platformSAMLContinuationServiceStub struct {
	readyCalls  int
	readyError  error
	starts      []PlatformSAMLStartTOTPCommand
	completions []PlatformSAMLCompleteTOTPCommand
	start       func(PlatformSAMLStartTOTPCommand) (PlatformSAMLTOTPStart, error)
	complete    func(PlatformSAMLCompleteTOTPCommand) (PlatformSAMLTOTPOutcome, error)
}

type platformSAMLMetadataSourceStub struct {
	projection platformsamladapter.DirectSAMLMetadataProjection
	found      bool
	err        error
}

func (stub *platformSAMLMetadataSourceStub) LoadDirectPlatformSAMLMetadata(
	context.Context,
	string,
) (platformsamladapter.DirectSAMLMetadataProjection, bool, error) {
	return stub.projection, stub.found, stub.err
}

type platformSAMLTOTPDeliveryFinalizerStub struct {
	confirmCalls    int
	compensateCalls int
	confirmError    error
	compensateError error
}

func (stub *platformSAMLTOTPDeliveryFinalizerStub) ConfirmBrowserDelivery() error {
	stub.confirmCalls++
	return stub.confirmError
}

func (stub *platformSAMLTOTPDeliveryFinalizerStub) CompensateBrowserDelivery(context.Context) error {
	stub.compensateCalls++
	return stub.compensateError
}

type platformSAMLSessionCredentialStub struct {
	material   platformsamlauth.BrowserCredentialMaterial
	consumable bool
	destroyed  bool
}

func (stub *platformSAMLSessionCredentialStub) Consume() (platformsamlauth.BrowserCredentialMaterial, bool) {
	if stub == nil || !stub.consumable {
		return platformsamlauth.BrowserCredentialMaterial{}, false
	}
	stub.consumable = false
	material := platformsamlauth.BrowserCredentialMaterial{
		Kind: stub.material.Kind, SessionID: stub.material.SessionID,
		ContinuationID: stub.material.ContinuationID, ExpiresAt: stub.material.ExpiresAt,
		SessionToken: append([]byte(nil), stub.material.SessionToken...),
		CSRFToken:    append([]byte(nil), stub.material.CSRFToken...),
		Receipt:      append([]byte(nil), stub.material.Receipt...),
	}
	stub.material.Destroy()
	return material, true
}

func (stub *platformSAMLSessionCredentialStub) Destroy() {
	if stub == nil {
		return
	}
	stub.material.Destroy()
	stub.destroyed = true
}

func (stub *platformSAMLContinuationServiceStub) Ready(context.Context) error {
	stub.readyCalls++
	return stub.readyError
}

func (stub *platformSAMLContinuationServiceStub) StartTOTP(
	_ context.Context,
	command PlatformSAMLStartTOTPCommand,
) (PlatformSAMLTOTPStart, error) {
	stub.starts = append(stub.starts, command)
	if stub.start == nil {
		return PlatformSAMLTOTPStart{}, platformsamlauth.ErrAuthenticationDenied
	}
	return stub.start(command)
}

func (stub *platformSAMLContinuationServiceStub) CompleteTOTP(
	_ context.Context,
	command PlatformSAMLCompleteTOTPCommand,
) (PlatformSAMLTOTPOutcome, error) {
	command.BrowserHandle = append([]byte(nil), command.BrowserHandle...)
	command.Code = append([]byte(nil), command.Code...)
	stub.completions = append(stub.completions, command)
	if stub.complete == nil {
		return PlatformSAMLTOTPOutcome{}, platformsamlauth.ErrAuthenticationDenied
	}
	return stub.complete(command)
}

func (stub *platformSAMLBrowserAuthenticationStub) Ready(context.Context) error {
	stub.readyCalls++
	return stub.readyError
}

func (stub *platformSAMLBrowserAuthenticationStub) Start(
	_ context.Context,
	request PlatformSAMLBrowserStartRequest,
) (platformsamladapter.RedirectResponse, error) {
	request.Receipt = append([]byte(nil), request.Receipt...)
	request.PreviousBrowserHandle = append([]byte(nil), request.PreviousBrowserHandle...)
	stub.starts = append(stub.starts, request)
	if stub.start == nil {
		return platformsamladapter.RedirectResponse{}, platformsamlauth.ErrAuthenticationDenied
	}
	return stub.start(request)
}

func (stub *platformSAMLBrowserAuthenticationStub) Complete(
	_ context.Context,
	request platformsamlauth.CompleteRequest,
	sink platformsamladapter.BrowserDeliverySink,
) error {
	request.RawForm = append([]byte(nil), request.RawForm...)
	request.BrowserHandle = append([]byte(nil), request.BrowserHandle...)
	stub.completions = append(stub.completions, request)
	if stub.complete == nil {
		return platformsamlauth.ErrAuthenticationDenied
	}
	return stub.complete(request, sink)
}

func (stub *platformSAMLBrowserAuthenticationStub) Metadata(
	_ context.Context,
	providerKey string,
) (platformsamladapter.DirectSAMLMetadataDocument, error) {
	stub.metadataKeys = append(stub.metadataKeys, providerKey)
	if stub.metadata == nil {
		return platformsamladapter.DirectSAMLMetadataDocument{}, errPlatformSAMLMetadataNotFound
	}
	return stub.metadata(providerKey)
}

func TestPlatformSAMLStartBindsDedicatedSameSiteNoneCookie(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	operationID := uuid.Must(uuid.NewV7())
	receipt := bytes.Repeat([]byte{0x41}, platformSAMLStartReceiptBytes)
	previous := federatedOpaque(0x42)
	created := federatedOpaque(0x43)
	stub := &platformSAMLBrowserAuthenticationStub{}
	stub.start = func(PlatformSAMLBrowserStartRequest) (platformsamladapter.RedirectResponse, error) {
		return platformsamladapter.RedirectResponse{
			StatusCode: http.StatusSeeOther, Location: "https://idp.example.test/sso?SAMLRequest=signed",
			CacheControl:   platformsamladapter.CacheControlNoStore,
			ReferrerPolicy: platformsamladapter.ReferrerPolicyNoReferrer,
			Cookies: []platformsamladapter.CookieDirective{{
				Name: developmentPlatformSAMLTransactionCookie, Value: append([]byte(nil), created...),
				Path: "/", Expires: now.Add(5 * time.Minute), MaxAge: 300,
				Secure: true, HTTPOnly: true, HostOnly: true, SameSite: platformsamladapter.SameSiteNone,
			}},
		}, nil
	}
	handler, router := newPlatformSAMLTestRouter(t, stub, &transportAuthStub{})
	handler.federated.now = func() time.Time { return now }
	handler.federated.newID = func() (uuid.UUID, error) { return operationID, nil }
	handler.federated.random = bytes.NewReader(receipt)
	request := federatedStartRequest(
		"/api/v1/auth/platform/saml/workforce_saml/start", "/alerts?queue=mine",
	)
	request.Header.Set("User-Agent", "periapsis-platform-saml-test")
	request.RemoteAddr = "192.0.2.88:443"
	request.AddCookie(&http.Cookie{Name: developmentPlatformSAMLTransactionCookie, Value: string(previous)})
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != "https://idp.example.test/sso?SAMLRequest=signed" {
		t.Fatalf("start = %d location=%q body=%s", response.Code, response.Header().Get("Location"), response.Body)
	}
	assertFederatedNoStore(t, response)
	if stub.readyCalls != 1 || len(stub.starts) != 1 {
		t.Fatalf("ready/start calls = %d/%d", stub.readyCalls, len(stub.starts))
	}
	captured := stub.starts[0]
	if captured.OperationRunID != identity.EntityID(operationID) || captured.ProviderKey != "workforce_saml" ||
		captured.NetworkAddress != "192.0.2.88" || captured.ReturnPath != "/alerts?queue=mine" ||
		!bytes.Equal(captured.Receipt, receipt) || !bytes.Equal(captured.PreviousBrowserHandle, previous) ||
		captured.Audit.UserAgent != "periapsis-platform-saml-test" ||
		captured.Audit.RequestID == (identity.EntityID{}) ||
		captured.Audit.CorrelationID != captured.Audit.RequestID {
		t.Fatalf("captured start = %s", captured.String())
	}
	cookie := findPositiveResponseCookie(response.Result().Cookies(), developmentPlatformSAMLTransactionCookie)
	if cookie == nil || cookie.Value != string(created) || !cookie.Secure || !cookie.HttpOnly ||
		cookie.SameSite != http.SameSiteNoneMode || cookie.Path != "/" || cookie.Domain != "" {
		t.Fatalf("transaction cookie = %#v", cookie)
	}
}

func TestPlatformSAMLStartRejectsAmbientAuthorityAndCrossOriginBeforeReadiness(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "bearer", mutate: func(request *http.Request) {
			request.Header.Set("Authorization", "Bearer attacker")
		}},
		{name: "session", mutate: func(request *http.Request) {
			request.AddCookie(&http.Cookie{Name: developmentCookie, Value: string(federatedOpaque(0x45))})
		}},
		{name: "MFA capability", mutate: func(request *http.Request) {
			request.AddCookie(&http.Cookie{Name: developmentMFACookie, Value: string(federatedOpaque(0x46))})
		}},
		{name: "federated continuation", mutate: func(request *http.Request) {
			request.AddCookie(&http.Cookie{Name: developmentFederatedContinuationCookie, Value: string(federatedOpaque(0x47))})
		}},
		{name: "CSRF substitute", mutate: func(request *http.Request) {
			request.Header.Set(csrfTokenHeader, "attacker")
		}},
		{name: "cross origin", mutate: func(request *http.Request) {
			request.Header.Set("Origin", "https://attacker.example")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			stub := &platformSAMLBrowserAuthenticationStub{}
			_, router := newPlatformSAMLTestRouter(t, stub, &transportAuthStub{})
			request := federatedStartRequest(
				"/api/v1/auth/platform/saml/workforce_saml/start", "/",
			)
			test.mutate(request)
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			if response.Code != http.StatusUnauthorized || stub.readyCalls != 0 || len(stub.starts) != 0 {
				t.Fatalf("start = %d ready=%d calls=%d body=%s", response.Code, stub.readyCalls, len(stub.starts), response.Body)
			}
			assertFederatedNoStore(t, response)
		})
	}
}

func TestPlatformSAMLACSRejectsNonCanonicalEnvelopeBeforeApplicationAndAlwaysClears(t *testing.T) {
	validRelay := string(federatedOpaque(0x51))
	validResponse := base64.StdEncoding.EncodeToString([]byte("<samlp:Response/>"))
	tests := map[string]struct {
		media string
		body  string
	}{
		"duplicate response":    {"application/x-www-form-urlencoded", "SAMLResponse=" + validResponse + "&SAMLResponse=" + validResponse + "&RelayState=" + validRelay},
		"unknown member":        {"application/x-www-form-urlencoded", "SAMLResponse=" + validResponse + "&RelayState=" + validRelay + "&ReturnTo=%2Fsecret"},
		"short relay":           {"application/x-www-form-urlencoded", "SAMLResponse=" + validResponse + "&RelayState=short"},
		"noncanonical response": {"application/x-www-form-urlencoded", "SAMLResponse=YWJjZA&RelayState=" + validRelay},
		"wrong media":           {"multipart/form-data", "SAMLResponse=" + validResponse + "&RelayState=" + validRelay},
		"semicolon separator":   {"application/x-www-form-urlencoded", "SAMLResponse=" + validResponse + ";RelayState=" + validRelay},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			stub := &platformSAMLBrowserAuthenticationStub{}
			_, router := newPlatformSAMLTestRouter(t, stub, &transportAuthStub{})
			request := platformSAMLACSRequest(test.media, test.body, federatedOpaque(0x52))
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			if response.Code != http.StatusUnauthorized || len(stub.completions) != 0 {
				t.Fatalf("ACS = %d calls=%d body=%s", response.Code, len(stub.completions), response.Body)
			}
			assertFederatedNoStore(t, response)
			assertCookieCleared(t, response, developmentPlatformSAMLTransactionCookie, http.SameSiteNoneMode)
		})
	}
}

func TestPlatformSAMLACSUsesExactKernelBodyCeiling(t *testing.T) {
	if maximumPlatformSAMLCallbackBodyBytes != 3145882 {
		t.Fatalf("callback ceiling = %d", maximumPlatformSAMLCallbackBodyBytes)
	}
	limits := federatedsaml.DefaultLimits()
	encodedResponse := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, limits.MaxDecodedResponseBytes))
	relayState := string(federatedOpaque(0x59))
	raw := "SAMLResponse=" + percentEscapePlatformSAMLFormValue(encodedResponse) +
		"&RelayState=" + percentEscapePlatformSAMLFormValue(relayState)
	if len(encodedResponse) != limits.MaxEncodedResponseBytes ||
		len(raw) != maximumPlatformSAMLCallbackBodyBytes {
		t.Fatalf("boundary response=%d raw=%d", len(encodedResponse), len(raw))
	}
	if err := validatePlatformSAMLPOSTFormEnvelope("application/x-www-form-urlencoded", []byte(raw)); err != nil {
		t.Fatalf("boundary envelope validation: %v", err)
	}
	stub := &platformSAMLBrowserAuthenticationStub{
		complete: func(platformsamlauth.CompleteRequest, platformsamladapter.BrowserDeliverySink) error {
			return platformsamlauth.ErrAuthenticationDenied
		},
	}
	_, router := newPlatformSAMLTestRouter(t, stub, &transportAuthStub{})
	request := platformSAMLACSRequest("application/x-www-form-urlencoded", raw, federatedOpaque(0x5a))
	request.Header.Set("User-Agent", "periapsis-platform-saml-boundary")
	request.RemoteAddr = "192.0.2.90:443"
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized || len(stub.completions) != 1 ||
		len(stub.completions[0].RawForm) != maximumPlatformSAMLCallbackBodyBytes {
		t.Fatalf("boundary ACS = %d ready=%d calls=%d body=%s", response.Code, stub.readyCalls, len(stub.completions), response.Body)
	}
	assertCookieCleared(t, response, developmentPlatformSAMLTransactionCookie, http.SameSiteNoneMode)

	oversized := platformSAMLACSRequest(
		"application/x-www-form-urlencoded", raw+"A", federatedOpaque(0x5b),
	)
	oversized.Header.Set("User-Agent", "periapsis-platform-saml-boundary")
	oversized.RemoteAddr = "192.0.2.90:443"
	oversizedResponse := httptest.NewRecorder()
	router.ServeHTTP(oversizedResponse, oversized)
	if oversizedResponse.Code != http.StatusUnauthorized || len(stub.completions) != 1 {
		t.Fatalf(
			"oversized ACS = %d calls=%d body=%s",
			oversizedResponse.Code, len(stub.completions), oversizedResponse.Body,
		)
	}
	assertCookieCleared(t, oversizedResponse, developmentPlatformSAMLTransactionCookie, http.SameSiteNoneMode)
}

func TestPlatformSAMLACSForwardsExactRawFormAndRoutesSAMLContinuation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	handle := federatedOpaque(0x61)
	relay := string(federatedOpaque(0x62))
	raw := "RelayState=" + relay + "&SAMLResponse=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("<samlp:Response/>")))
	continuationID := identity.EntityID(uuid.Must(uuid.NewV7()))
	userID := identity.EntityID(uuid.Must(uuid.NewV7()))
	receipt := federatedOpaque(0x63)
	stub := &platformSAMLBrowserAuthenticationStub{}
	stub.complete = func(_ platformsamlauth.CompleteRequest, sink platformsamladapter.BrowserDeliverySink) error {
		delivery := &platformsamladapter.BrowserDelivery{
			StatusCode: http.StatusSeeOther, Location: federatedContinuationPath,
			CacheControl:     platformsamladapter.CacheControlNoStore,
			ReferrerPolicy:   platformsamladapter.ReferrerPolicyNoReferrer,
			ClearTransaction: platformSAMLClearDirective(),
			CookieSecurity: platformsamladapter.CredentialCookieRequirements{
				Path: "/", Secure: true, HTTPOnly: true, HostOnly: true,
				SameSite: platformsamladapter.SameSiteStrict,
			},
			Disposition: platformsamlauth.TOTPContinuation, UserID: userID,
			ContinuationID: continuationID, ExpiresAt: now.Add(5 * time.Minute),
			Receipt: append([]byte(nil), receipt...),
		}
		defer delivery.Destroy()
		return sink.DeliverDirectSAML(context.Background(), delivery)
	}
	handler, router := newPlatformSAMLTestRouter(t, stub, &transportAuthStub{})
	handler.federated.now = func() time.Time { return now }
	request := platformSAMLACSRequest(
		"application/x-www-form-urlencoded; charset=UTF-8", raw, handle,
	)
	request.Header.Set("User-Agent", "periapsis-platform-saml-acs")
	request.RemoteAddr = "192.0.2.99:443"
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != federatedContinuationPath ||
		len(stub.completions) != 1 {
		t.Fatalf("ACS = %d location=%q calls=%d body=%s", response.Code, response.Header().Get("Location"), len(stub.completions), response.Body)
	}
	assertFederatedNoStore(t, response)
	captured := stub.completions[0]
	if captured.MediaType != "application/x-www-form-urlencoded; charset=UTF-8" ||
		string(captured.RawForm) != raw || !bytes.Equal(captured.BrowserHandle, handle) ||
		captured.Audit.UserAgent != "periapsis-platform-saml-acs" {
		t.Fatalf("captured completion = %s", captured.String())
	}
	continuationCookie := findPositiveResponseCookie(
		response.Result().Cookies(), developmentFederatedContinuationCookie,
	)
	if continuationCookie == nil || continuationCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("continuation cookie = %#v", continuationCookie)
	}
	probe := httptest.NewRequest(http.MethodPost, "/api/v1/auth/federated/mfa/step-up", nil)
	probe.AddCookie(continuationCookie)
	capability, err := federatedContinuationCapabilityCookie(probe, handler.federatedContinuationCookie)
	if err != nil {
		t.Fatalf("decode continuation cookie: %v", err)
	}
	defer capability.destroy()
	if capability.authority != federatedauth.ContinuationAuthorityDirectPlatformSAML ||
		capability.continuationID != uuid.UUID(continuationID) {
		t.Fatalf("continuation capability = authority %q id %s", capability.authority, capability.continuationID)
	}
}

func TestPlatformSAMLACSDeliversOnlyARevalidatedStrictSAMLSession(t *testing.T) {
	fixture := newFederatedSessionFixture(t, federatedauth.AuthenticationMethodSAML, "/alerts", 0x68)
	auth := &transportAuthStub{currentResult: fixture.current}
	handle := federatedOpaque(0x69)
	relay := string(federatedOpaque(0x6a))
	raw := "SAMLResponse=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("<Response/>"))) +
		"&RelayState=" + relay
	stub := &platformSAMLBrowserAuthenticationStub{}
	stub.complete = func(_ platformsamlauth.CompleteRequest, sink platformsamladapter.BrowserDeliverySink) error {
		delivery := &platformsamladapter.BrowserDelivery{
			StatusCode: http.StatusSeeOther, Location: "/alerts",
			CacheControl:     platformsamladapter.CacheControlNoStore,
			ReferrerPolicy:   platformsamladapter.ReferrerPolicyNoReferrer,
			ClearTransaction: platformSAMLClearDirective(),
			CookieSecurity: platformsamladapter.CredentialCookieRequirements{
				Path: "/", Secure: true, HTTPOnly: true, HostOnly: true,
				SameSite: platformsamladapter.SameSiteStrict,
			},
			Disposition:  platformsamlauth.ImmediateSession,
			UserID:       identity.EntityID(fixture.current.Session.User.ID),
			SessionID:    identity.EntityID(fixture.current.Session.ID),
			SessionToken: []byte(fixture.current.SessionToken),
			CSRFToken:    []byte(fixture.current.CSRFToken),
		}
		defer delivery.Destroy()
		return sink.DeliverDirectSAML(context.Background(), delivery)
	}
	_, router := newPlatformSAMLTestRouter(t, stub, auth)
	request := platformSAMLACSRequest("application/x-www-form-urlencoded", raw, handle)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/alerts" ||
		auth.currentToken != fixture.current.SessionToken {
		t.Fatalf("ACS = %d location=%q token=%t body=%s", response.Code, response.Header().Get("Location"), auth.currentToken != "", response.Body)
	}
	assertSessionCookie(t, response.Result().Cookies(), developmentCookie, fixture.current.SessionToken)
	assertCookieCleared(t, response, developmentPlatformSAMLTransactionCookie, http.SameSiteNoneMode)
}

func TestPlatformSAMLACSCrossAuthorityCookieSwapFailsClosed(t *testing.T) {
	stub := &platformSAMLBrowserAuthenticationStub{}
	_, router := newPlatformSAMLTestRouter(t, stub, &transportAuthStub{})
	relay := string(federatedOpaque(0x71))
	raw := "SAMLResponse=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("<Response/>"))) + "&RelayState=" + relay
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/platform/saml/acs", strings.NewReader(raw))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: developmentPlatformOIDCTransactionCookie, Value: string(federatedOpaque(0x72))})
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized || len(stub.completions) != 0 {
		t.Fatalf("swapped ACS = %d calls=%d body=%s", response.Code, len(stub.completions), response.Body)
	}
	assertCookieCleared(t, response, developmentPlatformSAMLTransactionCookie, http.SameSiteNoneMode)
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == developmentPlatformOIDCTransactionCookie {
			t.Fatalf("SAML callback mutated OIDC cookie: %#v", cookie)
		}
	}
}

func TestPlatformSAMLMetadataIsProviderQualifiedAndNonOracular(t *testing.T) {
	tests := map[string]struct {
		path       string
		metadata   func(string) (platformsamladapter.DirectSAMLMetadataDocument, error)
		wantStatus int
		wantCalls  int
	}{
		"malformed key": {path: "/api/v1/auth/platform/saml/1bad/metadata", wantStatus: http.StatusBadRequest},
		"unknown":       {path: "/api/v1/auth/platform/saml/workforce_saml/metadata", wantStatus: http.StatusNotFound, wantCalls: 1},
		"disabled or unready": {
			path: "/api/v1/auth/platform/saml/workforce_saml/metadata", wantStatus: http.StatusNotFound, wantCalls: 1,
			metadata: func(string) (platformsamladapter.DirectSAMLMetadataDocument, error) {
				return platformsamladapter.DirectSAMLMetadataDocument{}, errPlatformSAMLMetadataNotFound
			},
		},
		"infrastructure": {
			path: "/api/v1/auth/platform/saml/workforce_saml/metadata", wantStatus: http.StatusServiceUnavailable, wantCalls: 1,
			metadata: func(string) (platformsamladapter.DirectSAMLMetadataDocument, error) {
				return platformsamladapter.DirectSAMLMetadataDocument{}, errFederatedTransportUnavailable
			},
		},
		"success": {
			path: "/api/v1/auth/platform/saml/workforce_saml/metadata", wantStatus: http.StatusOK, wantCalls: 1,
			metadata: func(key string) (platformsamladapter.DirectSAMLMetadataDocument, error) {
				if key != "workforce_saml" {
					return platformsamladapter.DirectSAMLMetadataDocument{}, errors.New("wrong provider")
				}
				return platformsamladapter.DirectSAMLMetadataDocument{
					ContentType: platformsamladapter.SAMLMetadataContentType,
					Document:    []byte("<EntityDescriptor/>")}, nil
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			stub := &platformSAMLBrowserAuthenticationStub{metadata: test.metadata}
			_, router := newPlatformSAMLTestRouter(t, stub, &transportAuthStub{})
			response := httptest.NewRecorder()

			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))

			if response.Code != test.wantStatus || len(stub.metadataKeys) != test.wantCalls {
				t.Fatalf("metadata = %d calls=%d body=%s", response.Code, len(stub.metadataKeys), response.Body)
			}
			assertFederatedNoStore(t, response)
			if test.wantStatus == http.StatusOK &&
				(response.Header().Get("Content-Type") != platformsamladapter.SAMLMetadataContentType ||
					response.Body.String() != "<EntityDescriptor/>") {
				t.Fatalf("metadata response = content-type %q body %q", response.Header().Get("Content-Type"), response.Body.String())
			}
			if test.wantStatus == http.StatusNotFound && strings.Contains(response.Body.String(), "disabled") {
				t.Fatalf("metadata response leaked lifecycle: %s", response.Body)
			}
		})
	}
}

func TestPlatformSAMLMetadataRuntimeRejectsCrossProviderProjection(t *testing.T) {
	service := &RuntimePlatformSAMLBrowserAuthentication{
		metadata: &platformSAMLMetadataSourceStub{
			projection: platformsamladapter.DirectSAMLMetadataProjection{ProviderKey: "provider_b"},
			found:      true,
		},
	}
	document, err := service.Metadata(context.Background(), "provider_a")
	defer clear(document.Document)
	if !errors.Is(err, errFederatedTransportUnavailable) || len(document.Document) != 0 {
		t.Fatalf("cross-provider metadata = %s, error %v", document.String(), err)
	}
}

func TestPlatformSAMLContinuationRoutesOnlyToDedicatedService(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	continuationID := identity.EntityID(uuid.Must(uuid.NewV7()))
	factorID := identity.EntityID(uuid.Must(uuid.NewV7()))
	receipt := federatedOpaque(0x81)
	browserHandle := federatedOpaque(0x82)
	challengeID := mfa.ChallengeID{}
	challengeID[0] = 0x83
	saml := &platformSAMLContinuationServiceStub{}
	saml.start = func(PlatformSAMLStartTOTPCommand) (PlatformSAMLTOTPStart, error) {
		return PlatformSAMLTOTPStart{
			ChallengeID: challengeID, BrowserHandle: append([]byte(nil), browserHandle...),
			FactorID: factorID, ExpiresAt: now.Add(5 * time.Minute),
		}, nil
	}
	oidc := &platformOIDCBrowserAuthenticationStub{}
	mfaService := &mfaTransportStub{}
	handler, router := newPlatformSAMLContinuationTestRouter(t, saml, oidc, mfaService)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/federated/mfa/step-up", nil)
	request.Header.Set("Origin", "http://localhost:8081")
	request.Header.Set("User-Agent", "periapsis-platform-saml-mfa")
	addPlatformSAMLContinuationCookie(t, request, handler, continuationID, receipt, now)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK || saml.readyCalls != 1 || len(saml.starts) != 1 ||
		len(oidc.totpStarts) != 0 || mfaService.admissionCalls != 0 {
		t.Fatalf("SAML route = %d saml ready/start=%d/%d oidc=%d admission=%d body=%s",
			response.Code, saml.readyCalls, len(saml.starts), len(oidc.totpStarts), mfaService.admissionCalls, response.Body)
	}
	command := saml.starts[0]
	digest, err := federatedauth.ContinuationReceiptDigest(
		federatedauth.ContinuationAuthorityDirectPlatformSAML, continuationID, receipt,
	)
	if err != nil || command.ContinuationID != continuationID || command.ReceiptDigest != digest ||
		command.Audit.UserAgent != "periapsis-platform-saml-mfa" {
		t.Fatalf("SAML continuation command = %#v, digest error %v", command, err)
	}
	if findPositiveResponseCookie(response.Result().Cookies(), developmentMFACookie) == nil {
		t.Fatalf("MFA ceremony cookie missing: %#v", response.Result().Cookies())
	}
}

func TestPlatformSAMLContinuationNeverFallsThroughToOIDCService(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	continuationID := identity.EntityID(uuid.Must(uuid.NewV7()))
	oidc := &platformOIDCBrowserAuthenticationStub{}
	oidc.totpStart = func(platformoidcauth.StartDirectTOTPCommand) (PlatformOIDCTOTPStart, error) {
		t.Fatal("SAML capability was routed to OIDC")
		return PlatformOIDCTOTPStart{}, nil
	}
	handler, router := newPlatformSAMLContinuationTestRouter(
		t, nil, oidc, &mfaTransportStub{},
	)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/federated/mfa/step-up", nil)
	request.Header.Set("Origin", "http://localhost:8081")
	addPlatformSAMLContinuationCookie(t, request, handler, continuationID, federatedOpaque(0x91), now)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable || len(oidc.totpStarts) != 0 {
		t.Fatalf("cross-authority route = %d oidc=%d body=%s", response.Code, len(oidc.totpStarts), response.Body)
	}
}

func TestPlatformSAMLTOTPCompletionFinalizesOrCompensatesCommittedSession(t *testing.T) {
	tests := map[string]struct {
		mutate         func(*PlatformSAMLTOTPOutcome, *platformSAMLSessionCredentialStub, *transportAuthStub)
		wantStatus     int
		wantConfirm    int
		wantCompensate int
	}{
		"success confirms delivery": {
			wantStatus: http.StatusOK, wantConfirm: 1,
		},
		"invalid projection compensates": {
			mutate: func(outcome *PlatformSAMLTOTPOutcome, _ *platformSAMLSessionCredentialStub, _ *transportAuthStub) {
				outcome.UserID = identity.EntityID{}
			},
			wantStatus: http.StatusServiceUnavailable, wantCompensate: 1,
		},
		"consumed credential compensates": {
			mutate: func(_ *PlatformSAMLTOTPOutcome, credential *platformSAMLSessionCredentialStub, _ *transportAuthStub) {
				credential.consumable = false
			},
			wantStatus: http.StatusServiceUnavailable, wantCompensate: 1,
		},
		"session revalidation failure compensates": {
			mutate: func(_ *PlatformSAMLTOTPOutcome, _ *platformSAMLSessionCredentialStub, auth *transportAuthStub) {
				auth.currentError = authentication.ErrUnavailable
			},
			wantStatus: http.StatusServiceUnavailable, wantCompensate: 1,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Millisecond)
			continuationID := identity.EntityID(uuid.Must(uuid.NewV7()))
			sessionID := identity.EntityID(uuid.Must(uuid.NewV7()))
			familyID := identity.EntityID(uuid.Must(uuid.NewV7()))
			userID := identity.EntityID(uuid.Must(uuid.NewV7()))
			factorID := identity.EntityID(uuid.Must(uuid.NewV7()))
			challengeID := mfa.ChallengeID{}
			challengeID[0] = 0xa3
			token := federatedOpaque(0xa4)
			csrf := federatedOpaque(0xa5)
			credential := &platformSAMLSessionCredentialStub{
				consumable: true,
				material: platformsamlauth.BrowserCredentialMaterial{
					Kind: platformsamlauth.BrowserSessionCredential, SessionID: sessionID,
					SessionToken: append([]byte(nil), token...), CSRFToken: append([]byte(nil), csrf...),
				},
			}
			finalizer := &platformSAMLTOTPDeliveryFinalizerStub{}
			outcome := PlatformSAMLTOTPOutcome{
				UserID: userID, SessionID: sessionID, FactorID: factorID,
				Credential: credential, Delivery: finalizer,
			}
			auth := &transportAuthStub{currentResult: authentication.SessionCredential{
				Session: authentication.Session{
					ID: uuid.UUID(sessionID), RotationFamilyID: uuid.UUID(familyID),
					User:      authentication.User{ID: uuid.UUID(userID), DisplayName: "SAML responder"},
					CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now.Add(time.Hour),
					AbsoluteExpiresAt:    now.Add(8 * time.Hour),
					AuthenticationMethod: string(federatedauth.AuthenticationMethodSAML),
				},
				SessionToken: string(token), CSRFToken: string(csrf),
			}}
			if test.mutate != nil {
				test.mutate(&outcome, credential, auth)
			}
			saml := &platformSAMLContinuationServiceStub{
				complete: func(PlatformSAMLCompleteTOTPCommand) (PlatformSAMLTOTPOutcome, error) {
					return outcome, nil
				},
			}
			handler, router := newPlatformSAMLContinuationTestRouter(
				t, saml, &platformOIDCBrowserAuthenticationStub{}, &mfaTransportStub{},
			)
			handler.authentication = auth
			handler.federated.now = func() time.Time { return now }
			target := "/api/v1/auth/federated/mfa/step-up/" + encodeChallengeID(challengeID) + "/totp"
			body := `{"factorId":"` + uuid.UUID(factorID).String() + `","code":"123456"}`
			request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", "http://localhost:8081")
			request.Header.Set("User-Agent", "periapsis-platform-saml-totp")
			addPlatformSAMLContinuationCookie(
				t, request, handler, continuationID, federatedOpaque(0xa6), now,
			)
			request.AddCookie(&http.Cookie{Name: developmentMFACookie, Value: string(federatedOpaque(0xa7))})
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			if response.Code != test.wantStatus || finalizer.confirmCalls != test.wantConfirm ||
				finalizer.compensateCalls != test.wantCompensate || !credential.destroyed {
				t.Fatalf(
					"completion = %d confirm=%d compensate=%d destroyed=%t body=%s",
					response.Code, finalizer.confirmCalls, finalizer.compensateCalls,
					credential.destroyed, response.Body,
				)
			}
			if test.wantStatus == http.StatusOK {
				assertSessionCookie(t, response.Result().Cookies(), developmentCookie, string(token))
			} else if findPositiveResponseCookie(response.Result().Cookies(), developmentCookie) != nil {
				t.Fatalf("failed delivery emitted a session cookie: %#v", response.Result().Cookies())
			}
			assertClearedStrictCookie(t, response.Result().Cookies(), developmentMFACookie)
			assertClearedStrictCookie(t, response.Result().Cookies(), developmentFederatedContinuationCookie)
		})
	}
}

func newPlatformSAMLTestRouter(
	t testing.TB,
	service PlatformSAMLBrowserAuthentication,
	auth AuthenticationService,
) (*Handler, http.Handler) {
	t.Helper()
	options := completeFederatedApplicationOptions(auth)
	options.PlatformSAMLBrowser = service
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, testDiscardLogger(), "test", time.Second, options,
	)
	if err != nil {
		t.Fatalf("NewApplicationHandler: %v", err)
	}
	return handler, Router(handler, testDiscardLogger(), false)
}

func newPlatformSAMLContinuationTestRouter(
	t testing.TB,
	saml PlatformSAMLContinuationService,
	oidc PlatformOIDCBrowserAuthentication,
	mfaService MFAService,
) (*Handler, http.Handler) {
	t.Helper()
	options := completeFederatedApplicationOptions(&transportAuthStub{})
	options.MFA = mfaService
	options.PlatformSAMLContinuation = saml
	options.PlatformOIDCBrowser = oidc
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, testDiscardLogger(), "test", time.Second, options,
	)
	if err != nil {
		t.Fatalf("NewApplicationHandler: %v", err)
	}
	return handler, Router(handler, testDiscardLogger(), false)
}

func addPlatformSAMLContinuationCookie(
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
		federatedauth.ContinuationAuthorityDirectPlatformSAML,
		uuid.UUID(continuationID), receipt, now.Add(5*time.Minute), now,
	); err != nil {
		t.Fatalf("set SAML continuation cookie: %v", err)
	}
	cookie := findPositiveResponseCookie(
		recorder.Result().Cookies(), developmentFederatedContinuationCookie,
	)
	if cookie == nil {
		t.Fatal("SAML continuation cookie not emitted")
	}
	request.AddCookie(cookie)
}

func platformSAMLACSRequest(mediaType, raw string, handle []byte) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/platform/saml/acs", strings.NewReader(raw))
	request.Header.Set("Content-Type", mediaType)
	request.AddCookie(&http.Cookie{Name: developmentPlatformSAMLTransactionCookie, Value: string(handle)})
	return request
}

func platformSAMLClearDirective() platformsamladapter.CookieDirective {
	return platformsamladapter.CookieDirective{
		Name: developmentPlatformSAMLTransactionCookie, Path: "/", Expires: time.Unix(1, 0).UTC(), MaxAge: -1,
		Secure: true, HTTPOnly: true, HostOnly: true, SameSite: platformsamladapter.SameSiteNone,
	}
}

func percentEscapePlatformSAMLFormValue(value string) string {
	const hexadecimal = "0123456789ABCDEF"
	var escaped strings.Builder
	escaped.Grow(3 * len(value))
	for index := 0; index < len(value); index++ {
		escaped.WriteByte('%')
		escaped.WriteByte(hexadecimal[value[index]>>4])
		escaped.WriteByte(hexadecimal[value[index]&0x0f])
	}
	return escaped.String()
}

func assertCookieCleared(t testing.TB, response *httptest.ResponseRecorder, name string, sameSite http.SameSite) {
	t.Helper()
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == name && cookie.Value == "" && cookie.MaxAge < 0 && cookie.HttpOnly && cookie.Secure &&
			cookie.SameSite == sameSite && cookie.Path == "/" && cookie.Domain == "" {
			return
		}
	}
	t.Fatalf("%s was not cleared with the exact host-only policy: %#v", name, response.Header().Values("Set-Cookie"))
}

var _ PlatformSAMLBrowserAuthentication = (*platformSAMLBrowserAuthenticationStub)(nil)
var _ PlatformSAMLContinuationService = (*platformSAMLContinuationServiceStub)(nil)
var _ AuthenticationService = (*transportAuthStub)(nil)
