package httpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

type transportFederatedAuthenticationStub struct {
	readyError   error
	readyCalls   int
	oidcStarts   []federatedauth.StartTenantOIDCLoginRequest
	samlStarts   []federatedauth.StartTenantSAMLLoginRequest
	oidcComplete []federatedauth.CompleteTenantOIDCLoginRequest
	samlComplete []federatedauth.CompleteTenantSAMLLoginRequest
	startOIDC    func(federatedauth.StartTenantOIDCLoginRequest) (FederatedBrowserStart, error)
	startSAML    func(federatedauth.StartTenantSAMLLoginRequest) (FederatedBrowserStart, error)
	completeOIDC func(federatedauth.CompleteTenantOIDCLoginRequest) (federatedauth.ApplyResult, error)
	completeSAML func(federatedauth.CompleteTenantSAMLLoginRequest) (federatedauth.ApplyResult, error)
}

func (stub *transportFederatedAuthenticationStub) Ready(context.Context) error {
	stub.readyCalls++
	return stub.readyError
}

func (stub *transportFederatedAuthenticationStub) StartOIDC(
	_ context.Context,
	request federatedauth.StartTenantOIDCLoginRequest,
) (FederatedBrowserStart, error) {
	request.PreviousBrowserHandle = append([]byte(nil), request.PreviousBrowserHandle...)
	stub.oidcStarts = append(stub.oidcStarts, request)
	if stub.startOIDC == nil {
		return FederatedBrowserStart{}, federatedauth.ErrAuthentication
	}
	return stub.startOIDC(request)
}

func (stub *transportFederatedAuthenticationStub) CompleteOIDC(
	_ context.Context,
	request federatedauth.CompleteTenantOIDCLoginRequest,
) (federatedauth.ApplyResult, error) {
	request.BrowserHandle = append([]byte(nil), request.BrowserHandle...)
	stub.oidcComplete = append(stub.oidcComplete, request)
	if stub.completeOIDC == nil {
		return federatedauth.ApplyResult{}, federatedauth.ErrAuthentication
	}
	return stub.completeOIDC(request)
}

func (stub *transportFederatedAuthenticationStub) StartSAML(
	_ context.Context,
	request federatedauth.StartTenantSAMLLoginRequest,
) (FederatedBrowserStart, error) {
	request.PreviousBrowserHandle = append([]byte(nil), request.PreviousBrowserHandle...)
	stub.samlStarts = append(stub.samlStarts, request)
	if stub.startSAML == nil {
		return FederatedBrowserStart{}, federatedauth.ErrAuthentication
	}
	return stub.startSAML(request)
}

func (stub *transportFederatedAuthenticationStub) CompleteSAML(
	_ context.Context,
	request federatedauth.CompleteTenantSAMLLoginRequest,
) (federatedauth.ApplyResult, error) {
	request.RawForm = append([]byte(nil), request.RawForm...)
	request.BrowserHandle = append([]byte(nil), request.BrowserHandle...)
	stub.samlComplete = append(stub.samlComplete, request)
	if stub.completeSAML == nil {
		return federatedauth.ApplyResult{}, federatedauth.ErrAuthentication
	}
	return stub.completeSAML(request)
}

type countingFederatedReader struct {
	value byte
	read  int
}

func (reader *countingFederatedReader) Read(destination []byte) (int, error) {
	for index := range destination {
		destination[index] = reader.value
	}
	reader.read += len(destination)
	return len(destination), nil
}

func TestFederatedOIDCStartUsesCanonicalMeteringAndReplacesPriorTransaction(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	oldHandle := federatedOpaque(0x31)
	newHandle := federatedOpaque(0x32)
	newHandleValue := string(newHandle)
	operationID := uuid.Must(uuid.NewV7())
	stub := &transportFederatedAuthenticationStub{}
	stub.startOIDC = func(federatedauth.StartTenantOIDCLoginRequest) (FederatedBrowserStart, error) {
		return FederatedBrowserStart{
			RedirectURL:   "https://idp.example.test/authorize?client_id=periapsis&state=opaque",
			BrowserHandle: newHandle,
			ExpiresAt:     now.Add(5 * time.Minute),
		}, nil
	}
	handler, router, oidcDigester, _ := newFederatedTestRouter(
		t, "test", stub, &transportAuthStub{}, []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	)
	reader := &countingFederatedReader{value: 0x44}
	handler.federated.random = reader
	handler.federated.newID = func() (uuid.UUID, error) { return operationID, nil }
	handler.federated.now = func() time.Time { return now }

	request := federatedStartRequest(
		"/api/v1/auth/federated/oidc/acme/primary_oidc/start", "/alerts?queue=mine",
	)
	request.RemoteAddr = "127.0.0.10:44000"
	request.Header.Set("X-Forwarded-For", "::ffff:192.0.2.55")
	request.AddCookie(&http.Cookie{Name: developmentOIDCTransactionCookie, Value: string(oldHandle)})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") !=
		"https://idp.example.test/authorize?client_id=periapsis&state=opaque" {
		t.Fatalf("start response = %d location=%q body=%s", response.Code, response.Header().Get("Location"), response.Body)
	}
	if len(stub.oidcStarts) != 1 {
		t.Fatalf("OIDC start calls = %d", len(stub.oidcStarts))
	}
	start := stub.oidcStarts[0]
	if start.ReturnPath != "/alerts?queue=mine" || !bytes.Equal(start.PreviousBrowserHandle, oldHandle) ||
		start.HasAuthenticatedSession {
		t.Fatalf("OIDC start request = %s", start.String())
	}
	expectedReceipt := bytes.Repeat([]byte{0x44}, federatedStartReceiptBytes)
	expectedLookup, err := oidcDigester.BuildLookup(
		identity.EntityID(operationID), expectedReceipt, "acme", "primary_oidc", "192.0.2.55",
	)
	if err != nil || start.Lookup != expectedLookup || reader.read != federatedStartReceiptBytes {
		t.Fatalf("lookup mismatch error=%v receipt_bytes=%d", err, reader.read)
	}
	assertFederatedTransactionCookie(
		t, response.Result().Cookies(), developmentOIDCTransactionCookie, newHandleValue, false,
	)
	assertFederatedNoStore(t, response)
}

func TestFederatedSAMLStartUsesProtocolSpecificRouteAndCookie(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	handle := federatedOpaque(0x35)
	handleValue := string(handle)
	stub := &transportFederatedAuthenticationStub{}
	stub.startSAML = func(federatedauth.StartTenantSAMLLoginRequest) (FederatedBrowserStart, error) {
		return FederatedBrowserStart{
			RedirectURL:   "https://sso.example.test/saml?SAMLRequest=signed&RelayState=opaque",
			BrowserHandle: handle,
			ExpiresAt:     now.Add(5 * time.Minute),
		}, nil
	}
	handler, router, _, _ := newFederatedTestRouter(t, "test", stub, &transportAuthStub{}, nil)
	handler.federated.now = func() time.Time { return now }
	response := httptest.NewRecorder()
	router.ServeHTTP(response, federatedStartRequest(
		"/api/v1/auth/federated/saml/acme/corporate_saml/start", "/cases",
	))
	if response.Code != http.StatusSeeOther || len(stub.samlStarts) != 1 || stub.samlStarts[0].ReturnPath != "/cases" {
		t.Fatalf("SAML start = status:%d calls:%d", response.Code, len(stub.samlStarts))
	}
	assertFederatedTransactionCookie(
		t, response.Result().Cookies(), developmentSAMLTransactionCookie, handleValue, false,
	)
}

func TestFederatedStartAcceptsNativeFormForTopLevelNavigation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	handle := federatedOpaque(0x3F)
	handleValue := string(handle)
	stub := &transportFederatedAuthenticationStub{}
	stub.startOIDC = func(request federatedauth.StartTenantOIDCLoginRequest) (FederatedBrowserStart, error) {
		if request.ReturnPath != "/alerts?status=new" {
			t.Fatalf("ReturnPath = %q", request.ReturnPath)
		}
		return FederatedBrowserStart{
			RedirectURL: "https://idp.example.test/authorize", BrowserHandle: handle,
			ExpiresAt: now.Add(5 * time.Minute),
		}, nil
	}
	handler, router, _, _ := newFederatedTestRouter(t, "test", stub, &transportAuthStub{}, nil)
	handler.federated.now = func() time.Time { return now }
	request := federatedFormStartRequest(
		"/api/v1/auth/federated/oidc/acme/primary_oidc/start", "/alerts?status=new",
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "https://idp.example.test/authorize" ||
		len(stub.oidcStarts) != 1 {
		t.Fatalf("native form start = status:%d location:%q calls:%d body:%s",
			response.Code, response.Header().Get("Location"), len(stub.oidcStarts), response.Body)
	}
	assertFederatedTransactionCookie(
		t, response.Result().Cookies(), developmentOIDCTransactionCookie, handleValue, false,
	)
}

func TestFederatedStartRejectsAmbiguousOrMalformedNativeForms(t *testing.T) {
	stub := &transportFederatedAuthenticationStub{}
	_, router, _, _ := newFederatedTestRouter(t, "test", stub, &transportAuthStub{}, nil)
	for _, testCase := range []struct {
		name string
		body string
	}{
		{name: "duplicate return path", body: "returnPath=%2Falerts&returnPath=%2Fcases"},
		{name: "unknown field", body: "returnPath=%2Falerts&tenant=other"},
		{name: "missing return path", body: "other=%2Falerts"},
		{name: "empty body"},
		{name: "invalid percent encoding", body: "returnPath=%ZZ"},
		{name: "semicolon separator", body: "returnPath=%2Falerts;other=value"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request := httptest.NewRequest(
				http.MethodPost, "/api/v1/auth/federated/oidc/acme/primary_oidc/start",
				strings.NewReader(testCase.body),
			)
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.Header.Set("Origin", "http://localhost:8081")
			request.RemoteAddr = "192.0.2.10:44000"
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized || len(stub.oidcStarts) != 0 {
				t.Fatalf("response=%d calls=%d body=%s", response.Code, len(stub.oidcStarts), response.Body)
			}
		})
	}
}

func TestFederatedStartRejectsAmbientAuthorityDuplicatesAndOpenRedirects(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	stub := &transportFederatedAuthenticationStub{}
	stub.startOIDC = func(federatedauth.StartTenantOIDCLoginRequest) (FederatedBrowserStart, error) {
		return FederatedBrowserStart{
			RedirectURL: "https://idp.example.test/authorize", BrowserHandle: federatedOpaque(0x40),
			ExpiresAt: now.Add(5 * time.Minute),
		}, nil
	}
	_, router, _, _ := newFederatedTestRouter(t, "test", stub, &transportAuthStub{}, nil)

	for _, testCase := range []struct {
		name      string
		readyCall int
		mutate    func(*http.Request)
	}{
		{name: "authorization", mutate: func(request *http.Request) { request.Header.Set("Authorization", "Bearer attacker") }},
		{name: "session", mutate: func(request *http.Request) {
			request.AddCookie(&http.Cookie{Name: developmentCookie, Value: string(federatedOpaque(0x41))})
		}},
		{name: "MFA continuation", mutate: func(request *http.Request) {
			request.AddCookie(&http.Cookie{Name: developmentMFACookie, Value: string(federatedOpaque(0x41))})
		}},
		{name: "csrf substitute", mutate: func(request *http.Request) { request.Header.Set(csrfTokenHeader, "attacker") }},
		{name: "wrong content type", mutate: func(request *http.Request) { request.Header.Set("Content-Type", "text/plain") }},
		{name: "duplicate content type", mutate: func(request *http.Request) { request.Header.Add("Content-Type", "application/json") }},
		{name: "duplicate transaction cookie", mutate: func(request *http.Request) {
			request.AddCookie(&http.Cookie{Name: developmentOIDCTransactionCookie, Value: string(federatedOpaque(0x42))})
			request.AddCookie(&http.Cookie{Name: developmentOIDCTransactionCookie, Value: string(federatedOpaque(0x43))})
		}},
		{name: "malformed transaction cookie", mutate: func(request *http.Request) {
			request.AddCookie(&http.Cookie{Name: developmentOIDCTransactionCookie, Value: "not-canonical"})
		}},
		{name: "noncanonical tenant locator", readyCall: 1, mutate: func(request *http.Request) {
			request.URL.Path = "/api/v1/auth/federated/oidc/Acme/primary_oidc/start"
		}},
		{name: "query on start", mutate: func(request *http.Request) { request.URL.RawQuery = "returnPath=https://evil.test" }},
		{name: "empty query marker on start", mutate: func(request *http.Request) { request.URL.ForceQuery = true }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			before := len(stub.oidcStarts)
			readyBefore := stub.readyCalls
			request := federatedStartRequest(
				"/api/v1/auth/federated/oidc/acme/primary_oidc/start", "/alerts",
			)
			testCase.mutate(request)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized || len(stub.oidcStarts) != before ||
				stub.readyCalls-readyBefore != testCase.readyCall {
				t.Fatalf(
					"response=%d calls=%d readiness=%d body=%s",
					response.Code, len(stub.oidcStarts)-before, stub.readyCalls-readyBefore, response.Body,
				)
			}
			if strings.Contains(testCase.name, "transaction cookie") {
				assertFederatedTransactionCookie(
					t, response.Result().Cookies(), developmentOIDCTransactionCookie, "", true,
				)
			}
			assertFederatedNoStore(t, response)
		})
	}

	stub.startOIDC = func(federatedauth.StartTenantOIDCLoginRequest) (FederatedBrowserStart, error) {
		return FederatedBrowserStart{
			RedirectURL:   "https://idp.example.test/authorize\r\nLocation: https://evil.test",
			BrowserHandle: federatedOpaque(0x44), ExpiresAt: now.Add(5 * time.Minute),
		}, nil
	}
	request := federatedStartRequest(
		"/api/v1/auth/federated/oidc/acme/primary_oidc/start", "/alerts",
	)
	request.AddCookie(&http.Cookie{Name: developmentOIDCTransactionCookie, Value: string(federatedOpaque(0x45))})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Location") != "" {
		t.Fatalf("unsafe redirect response = %d location=%q", response.Code, response.Header().Get("Location"))
	}
	assertFederatedTransactionCookie(t, response.Result().Cookies(), developmentOIDCTransactionCookie, "", true)
}

func TestFederatedCallbacksPassRawArtifactsAndClearExactCookie(t *testing.T) {
	stub := &transportFederatedAuthenticationStub{}
	stub.completeOIDC = func(federatedauth.CompleteTenantOIDCLoginRequest) (federatedauth.ApplyResult, error) {
		return federatedauth.ApplyResult{}, federatedauth.ErrAuthentication
	}
	stub.completeSAML = func(federatedauth.CompleteTenantSAMLLoginRequest) (federatedauth.ApplyResult, error) {
		return federatedauth.ApplyResult{}, federatedauth.ErrAuthentication
	}
	_, router, _, _ := newFederatedTestRouter(t, "test", stub, &transportAuthStub{}, nil)

	oidcHandle := federatedOpaque(0x50)
	oidc := httptest.NewRequest(http.MethodGet, "/api/v1/auth/federated/oidc/callback", nil)
	oidc.URL.RawQuery = "code=one&code=two&state=%ZZ"
	oidc.AddCookie(&http.Cookie{Name: developmentOIDCTransactionCookie, Value: string(oidcHandle)})
	oidcResponse := httptest.NewRecorder()
	router.ServeHTTP(oidcResponse, oidc)
	if oidcResponse.Code != http.StatusUnauthorized || len(stub.oidcComplete) != 1 ||
		stub.oidcComplete[0].RawQuery != oidc.URL.RawQuery ||
		!bytes.Equal(stub.oidcComplete[0].BrowserHandle, oidcHandle) {
		t.Fatalf("OIDC callback response=%d calls=%d", oidcResponse.Code, len(stub.oidcComplete))
	}
	assertFederatedTransactionCookie(t, oidcResponse.Result().Cookies(), developmentOIDCTransactionCookie, "", true)

	samlHandle := federatedOpaque(0x51)
	rawForm := "SAMLResponse=first&SAMLResponse=second&RelayState=" + string(federatedOpaque(0x52))
	saml := httptest.NewRequest(http.MethodPost, "/api/v1/auth/federated/saml/acs", strings.NewReader(rawForm))
	saml.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	saml.AddCookie(&http.Cookie{Name: developmentSAMLTransactionCookie, Value: string(samlHandle)})
	samlResponse := httptest.NewRecorder()
	router.ServeHTTP(samlResponse, saml)
	if samlResponse.Code != http.StatusUnauthorized || len(stub.samlComplete) != 1 ||
		string(stub.samlComplete[0].RawForm) != rawForm ||
		stub.samlComplete[0].MediaType != "application/x-www-form-urlencoded; charset=UTF-8" {
		t.Fatalf("SAML callback response=%d calls=%d", samlResponse.Code, len(stub.samlComplete))
	}
	assertFederatedTransactionCookie(t, samlResponse.Result().Cookies(), developmentSAMLTransactionCookie, "", true)
}

func TestFederatedCallbacksRejectDuplicateCookieAndAmbientAuthorityBeforeKernel(t *testing.T) {
	stub := &transportFederatedAuthenticationStub{}
	_, router, _, _ := newFederatedTestRouter(t, "test", stub, &transportAuthStub{}, nil)
	for _, testCase := range []struct {
		name   string
		path   string
		method string
		cookie string
		mutate func(*http.Request)
	}{
		{
			name: "OIDC duplicate cookie", path: "/api/v1/auth/federated/oidc/callback?code=x&state=y",
			method: http.MethodGet, cookie: developmentOIDCTransactionCookie,
			mutate: func(request *http.Request) {
				request.AddCookie(&http.Cookie{Name: developmentOIDCTransactionCookie, Value: string(federatedOpaque(0x60))})
			},
		},
		{
			name: "SAML authorization", path: "/api/v1/auth/federated/saml/acs",
			method: http.MethodPost, cookie: developmentSAMLTransactionCookie,
			mutate: func(request *http.Request) { request.Header.Set("Authorization", "Bearer attacker") },
		},
		{
			name: "SAML live session", path: "/api/v1/auth/federated/saml/acs",
			method: http.MethodPost, cookie: developmentSAMLTransactionCookie,
			mutate: func(request *http.Request) {
				request.AddCookie(&http.Cookie{Name: developmentCookie, Value: string(federatedOpaque(0x61))})
			},
		},
		{
			name: "OIDC MFA continuation", path: "/api/v1/auth/federated/oidc/callback?code=x&state=y",
			method: http.MethodGet, cookie: developmentOIDCTransactionCookie,
			mutate: func(request *http.Request) {
				request.AddCookie(&http.Cookie{Name: developmentMFACookie, Value: string(federatedOpaque(0x61))})
			},
		},
		{
			name: "OIDC request body", path: "/api/v1/auth/federated/oidc/callback?code=x&state=y",
			method: http.MethodGet, cookie: developmentOIDCTransactionCookie,
			mutate: func(request *http.Request) {
				request.Body = io.NopCloser(strings.NewReader("ignored=artifact"))
				request.ContentLength = int64(len("ignored=artifact"))
			},
		},
		{
			name: "SAML query artifact", path: "/api/v1/auth/federated/saml/acs?SAMLResponse=ignored",
			method: http.MethodPost, cookie: developmentSAMLTransactionCookie,
			mutate: func(*http.Request) {},
		},
		{
			name: "SAML empty query marker", path: "/api/v1/auth/federated/saml/acs?",
			method: http.MethodPost, cookie: developmentSAMLTransactionCookie,
			mutate: func(*http.Request) {},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			readyBefore := stub.readyCalls
			var body io.Reader
			if testCase.method == http.MethodPost {
				body = strings.NewReader("SAMLResponse=x&RelayState=y")
			}
			request := httptest.NewRequest(testCase.method, testCase.path, body)
			if body != nil {
				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			request.AddCookie(&http.Cookie{Name: testCase.cookie, Value: string(federatedOpaque(0x62))})
			testCase.mutate(request)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusUnauthorized || len(stub.oidcComplete) != 0 || len(stub.samlComplete) != 0 ||
				stub.readyCalls != readyBefore {
				t.Fatalf(
					"response=%d OIDC=%d SAML=%d readiness=%d",
					response.Code, len(stub.oidcComplete), len(stub.samlComplete), stub.readyCalls-readyBefore,
				)
			}
			assertFederatedTransactionCookie(t, response.Result().Cookies(), testCase.cookie, "", true)
		})
	}
}

func TestFederatedSessionCallbackRevalidatesBeforeSettingNormalCookie(t *testing.T) {
	fixture := newFederatedSessionFixture(t, federatedauth.AuthenticationMethodOIDC, "/alerts/active", 0x70)
	auth := &transportAuthStub{currentResult: fixture.current}
	stub := &transportFederatedAuthenticationStub{}
	stub.completeOIDC = func(federatedauth.CompleteTenantOIDCLoginRequest) (federatedauth.ApplyResult, error) {
		return fixture.result, nil
	}
	_, router, _, _ := newFederatedTestRouter(t, "test", stub, auth, nil)
	request := federatedOIDCCallbackRequest(federatedOpaque(0x71))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/alerts/active" ||
		auth.currentToken != fixture.token {
		t.Fatalf("callback = %d location=%q token_match=%t body=%s", response.Code, response.Header().Get("Location"), auth.currentToken == fixture.token, response.Body)
	}
	assertFederatedTransactionCookie(t, response.Result().Cookies(), developmentOIDCTransactionCookie, "", true)
	assertSessionCookie(t, response.Result().Cookies(), developmentCookie, fixture.token)
	assertClearedStrictCookie(t, response.Result().Cookies(), developmentMFACookie)
	if _, ok := fixture.result.Credential.Consume(); ok {
		t.Fatal("browser credential remained consumable after callback")
	}
}

func TestFederatedSessionCallbackRejectsCredentialAndRevalidationDrift(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*federatedSessionFixture, *transportAuthStub)
	}{
		{name: "result session id", mutate: func(fixture *federatedSessionFixture, _ *transportAuthStub) {
			fixture.result.SessionID = identity.EntityID(uuid.Must(uuid.NewV7()))
		}},
		{name: "result user id is not UUIDv7", mutate: func(fixture *federatedSessionFixture, _ *transportAuthStub) {
			fixture.result.UserID = identity.EntityID(uuid.New())
		}},
		{name: "revalidated session id", mutate: func(_ *federatedSessionFixture, auth *transportAuthStub) {
			auth.currentResult.Session.ID = uuid.Must(uuid.NewV7())
		}},
		{name: "revalidated user id", mutate: func(_ *federatedSessionFixture, auth *transportAuthStub) {
			auth.currentResult.Session.User.ID = uuid.Must(uuid.NewV7())
		}},
		{name: "revalidated token", mutate: func(_ *federatedSessionFixture, auth *transportAuthStub) {
			auth.currentResult.SessionToken = string(federatedOpaque(0x75))
		}},
		{name: "revalidated csrf", mutate: func(_ *federatedSessionFixture, auth *transportAuthStub) {
			auth.currentResult.CSRFToken = string(federatedOpaque(0x76))
		}},
		{name: "revalidated method", mutate: func(_ *federatedSessionFixture, auth *transportAuthStub) {
			auth.currentResult.Session.AuthenticationMethod = "saml"
		}},
		{name: "revalidation failure", mutate: func(_ *federatedSessionFixture, auth *transportAuthStub) {
			auth.currentError = authentication.ErrInvalidAuthentication
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newFederatedSessionFixture(t, federatedauth.AuthenticationMethodOIDC, "/alerts", 0x74)
			auth := &transportAuthStub{currentResult: fixture.current}
			testCase.mutate(&fixture, auth)
			stub := &transportFederatedAuthenticationStub{completeOIDC: func(federatedauth.CompleteTenantOIDCLoginRequest) (federatedauth.ApplyResult, error) {
				return fixture.result, nil
			}}
			_, router, _, _ := newFederatedTestRouter(t, "test", stub, auth, nil)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, federatedOIDCCallbackRequest(federatedOpaque(0x77)))
			if response.Code != http.StatusUnauthorized || findResponseCookie(response.Result().Cookies(), developmentCookie) != nil {
				t.Fatalf("response=%d session_cookie=%v body=%s", response.Code, findResponseCookie(response.Result().Cookies(), developmentCookie), response.Body)
			}
			if _, ok := fixture.result.Credential.Consume(); ok {
				t.Fatal("rejected browser credential remained consumable")
			}
		})
	}
}

func TestFederatedContinuationUsesFixedLocalMarkerAndExistingMFACookie(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	fixture := newFederatedContinuationFixture(t, "/cases/return", now, 0x80)
	auth := &transportAuthStub{}
	stub := &transportFederatedAuthenticationStub{completeSAML: func(federatedauth.CompleteTenantSAMLLoginRequest) (federatedauth.ApplyResult, error) {
		return fixture.result, nil
	}}
	handler, router, _, _ := newFederatedTestRouter(t, "test", stub, auth, nil)
	handler.federated.now = func() time.Time { return now }
	request := federatedSAMLCallbackRequest(federatedOpaque(0x81), "SAMLResponse=x&RelayState=y")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != federatedContinuationPath ||
		auth.currentToken != "" {
		t.Fatalf("continuation = %d location=%q current_token=%q", response.Code, response.Header().Get("Location"), auth.currentToken)
	}
	assertFederatedTransactionCookie(t, response.Result().Cookies(), developmentSAMLTransactionCookie, "", true)
	continuationCookie := findPositiveResponseCookie(
		response.Result().Cookies(), developmentFederatedContinuationCookie,
	)
	if continuationCookie == nil || continuationCookie.Value == fixture.receipt || continuationCookie.Path != "/" ||
		!continuationCookie.HttpOnly || continuationCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("continuation cookie = %#v", continuationCookie)
	}
	continuationRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	continuationRequest.AddCookie(continuationCookie)
	continuationID, receipt, err := federatedContinuationCookie(
		continuationRequest, handler.federatedContinuationCookie,
	)
	if err != nil || continuationID != uuid.UUID(fixture.result.ContinuationID) || string(receipt) != fixture.receipt {
		t.Fatalf("decoded continuation = %s receipt_match=%t error=%v", continuationID, string(receipt) == fixture.receipt, err)
	}
	clear(receipt)
	if findResponseCookie(response.Result().Cookies(), developmentCookie) != nil {
		t.Fatal("continuation emitted a session cookie")
	}
	if _, ok := fixture.result.Credential.Consume(); ok {
		t.Fatal("continuation browser credential remained consumable after callback")
	}
}

func TestFederatedContinuationRejectsWrongIDAndExternalReturnPath(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	for _, testCase := range []struct {
		name   string
		mutate func(*federatedauth.ApplyResult)
	}{
		{name: "wrong continuation id", mutate: func(result *federatedauth.ApplyResult) {
			result.ContinuationID = identity.EntityID(uuid.Must(uuid.NewV7()))
		}},
		{name: "external return path", mutate: func(result *federatedauth.ApplyResult) {
			result.ReturnPath = "https://evil.example.test/steal"
		}},
		{name: "scheme relative return path", mutate: func(result *federatedauth.ApplyResult) {
			result.ReturnPath = "//evil.example.test/steal"
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newFederatedContinuationFixture(t, "/cases", now, 0x84)
			testCase.mutate(&fixture.result)
			stub := &transportFederatedAuthenticationStub{completeSAML: func(federatedauth.CompleteTenantSAMLLoginRequest) (federatedauth.ApplyResult, error) {
				return fixture.result, nil
			}}
			handler, router, _, _ := newFederatedTestRouter(t, "test", stub, &transportAuthStub{}, nil)
			handler.federated.now = func() time.Time { return now }
			response := httptest.NewRecorder()
			router.ServeHTTP(response, federatedSAMLCallbackRequest(federatedOpaque(0x85), "SAMLResponse=x&RelayState=y"))
			if response.Code != http.StatusUnauthorized || response.Header().Get("Location") != "" ||
				findPositiveResponseCookie(response.Result().Cookies(), developmentMFACookie) != nil {
				t.Fatalf("response=%d location=%q", response.Code, response.Header().Get("Location"))
			}
			if _, ok := fixture.result.Credential.Consume(); ok {
				t.Fatal("rejected continuation credential remained consumable")
			}
		})
	}
}

func TestFederatedRoutesDefaultUnavailableAndCallbacksStillClearCookie(t *testing.T) {
	router := newApplicationTestRouter(t, &transportAuthStub{}, "test", nil)
	startResponse := httptest.NewRecorder()
	router.ServeHTTP(startResponse, federatedStartRequest(
		"/api/v1/auth/federated/oidc/acme/primary_oidc/start", "/alerts",
	))
	if startResponse.Code != http.StatusServiceUnavailable || startResponse.Header().Get("Location") != "" {
		t.Fatalf("unwired start = %d location=%q", startResponse.Code, startResponse.Header().Get("Location"))
	}
	callbackResponse := httptest.NewRecorder()
	router.ServeHTTP(callbackResponse, federatedOIDCCallbackRequest(federatedOpaque(0x90)))
	if callbackResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired callback = %d", callbackResponse.Code)
	}
	assertFederatedTransactionCookie(t, callbackResponse.Result().Cookies(), developmentOIDCTransactionCookie, "", true)
	assertFederatedNoStore(t, callbackResponse)

	platformStartResponse := httptest.NewRecorder()
	router.ServeHTTP(platformStartResponse, federatedStartRequest(
		"/api/v1/auth/platform/oidc/corp_oidc/start", "/alerts",
	))
	if platformStartResponse.Code != http.StatusServiceUnavailable ||
		platformStartResponse.Header().Get("Location") != "" {
		t.Fatalf("unwired platform start = %d location=%q", platformStartResponse.Code, platformStartResponse.Header().Get("Location"))
	}
	platformCallback := httptest.NewRequest(
		http.MethodGet, "/api/v1/auth/platform/oidc/callback?code=opaque&state=opaque", nil,
	)
	platformCallback.AddCookie(&http.Cookie{
		Name: developmentPlatformOIDCTransactionCookie, Value: platformOIDCCookieValue(1, 0x91, 0x92),
	})
	platformCallbackResponse := httptest.NewRecorder()
	router.ServeHTTP(platformCallbackResponse, platformCallback)
	if platformCallbackResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired platform callback = %d", platformCallbackResponse.Code)
	}
	assertFederatedTransactionCookie(
		t, platformCallbackResponse.Result().Cookies(),
		developmentPlatformOIDCTransactionCookie, "", true,
	)
	assertFederatedNoStore(t, platformCallbackResponse)
}

func TestFederatedBrowserOptionsAreAllOrNothingAndProductionCookiesAreHostOnly(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	options := completeFederatedApplicationOptions(&transportAuthStub{})
	options.Environment = "production"
	options.PublicOrigin = "https://periapsis.example.test"
	options.FederatedBrowser = &FederatedBrowserOptions{Authentication: &transportFederatedAuthenticationStub{}}
	if _, err := NewApplicationHandler(fixedChecker{ready: true}, logger, "test", time.Second, options); err == nil {
		t.Fatal("partial federated browser options were accepted")
	}
	oidcDigest, err := federatedauth.NewOIDCStartDigester(bytes.Repeat([]byte{0xa7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	samlDigest, err := federatedauth.NewSAMLStartDigester(bytes.Repeat([]byte{0xb8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	options.FederatedBrowser = &FederatedBrowserOptions{
		Authentication:  &transportFederatedAuthenticationStub{},
		OIDCStartDigest: oidcDigest,
		SAMLStartDigest: samlDigest,
	}
	if _, err := NewApplicationHandler(fixedChecker{ready: true}, logger, "test", time.Second, options); err == nil {
		t.Fatal("production federated composition accepted a nil tenant SAML metadata service")
	}
	oidc, err := newFederatedTransactionCookiePolicy("production", "https://periapsis.example.com", federatedProtocolOIDC)
	if err != nil || oidc.name != productionOIDCTransactionCookie || !strings.HasPrefix(oidc.name, "__Host-") {
		t.Fatalf("production OIDC cookie policy = %#v, %v", oidc, err)
	}
	saml, err := newFederatedTransactionCookiePolicy("production", "https://periapsis.example.com", federatedProtocolSAML)
	if err != nil || saml.name != productionSAMLTransactionCookie || !strings.HasPrefix(saml.name, "__Host-") {
		t.Fatalf("production SAML cookie policy = %#v, %v", saml, err)
	}
	platformOIDC, err := newFederatedTransactionCookiePolicy(
		"production", "https://periapsis.example.com", federatedProtocolPlatformOIDC,
	)
	if err != nil || platformOIDC.name != productionPlatformOIDCTransactionCookie ||
		!strings.HasPrefix(platformOIDC.name, "__Host-") || platformOIDC.sameSite != http.SameSiteLaxMode {
		t.Fatalf("production platform OIDC cookie policy = %#v, %v", platformOIDC, err)
	}
	platformSAML, err := newFederatedTransactionCookiePolicy(
		"production", "https://periapsis.example.com", federatedProtocolPlatformSAML,
	)
	if err != nil || platformSAML.name != productionPlatformSAMLTransactionCookie ||
		!strings.HasPrefix(platformSAML.name, "__Host-") || platformSAML.sameSite != http.SameSiteNoneMode {
		t.Fatalf("production platform SAML cookie policy = %#v, %v", platformSAML, err)
	}
	developmentTLS, err := newFederatedTransactionCookiePolicy(
		"development", "https://localhost:8443", federatedProtocolOIDC,
	)
	if err != nil || developmentTLS.name != productionOIDCTransactionCookie {
		t.Fatalf("development HTTPS OIDC cookie policy = %#v, %v", developmentTLS, err)
	}
}

func TestHTTPSDevelopmentApplicationUsesSecureHostOnlyCookieNamespace(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	options := completeFederatedApplicationOptions(&transportAuthStub{})
	options.Environment = "development"
	options.PublicOrigin = "https://localhost:8443"
	handler, err := NewApplicationHandler(fixedChecker{ready: true}, logger, "test", time.Second, options)
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	for name, policy := range map[string]sessionCookiePolicy{
		"session":                handler.cookie,
		"MFA":                    handler.mfaCookie,
		"federated continuation": handler.federatedContinuationCookie,
	} {
		if !policy.secure || !strings.HasPrefix(policy.name, "__Host-") {
			t.Fatalf("%s cookie policy = %#v", name, policy)
		}
	}
	for name, policy := range map[string]federatedTransactionCookiePolicy{
		"OIDC":          handler.federated.oidcCookie,
		"SAML":          handler.federated.samlCookie,
		"platform OIDC": handler.federated.platformOIDCCookie,
		"platform SAML": handler.federated.platformSAMLCookie,
	} {
		if !strings.HasPrefix(policy.name, "__Host-") {
			t.Fatalf("%s transaction cookie policy = %#v", name, policy)
		}
	}
}

func TestFederatedBrowserStartFormattingRedactsDeliveryArtifacts(t *testing.T) {
	const canary = "browser-delivery-canary"
	start := FederatedBrowserStart{
		RedirectURL:   "https://idp.example.test/authorize?state=" + canary,
		BrowserHandle: []byte(canary),
	}
	formatted := fmt.Sprintf("%v %#v", start, start)
	serialized, err := json.Marshal(start)
	if err != nil || strings.Contains(formatted, canary) || bytes.Contains(serialized, []byte(canary)) ||
		!strings.Contains(formatted, "[REDACTED]") {
		t.Fatalf("unsafe federated start formatting: %s", formatted)
	}
}

func TestFederatedSAMLCallbackBodyLimitFailsClosedBeforeKernel(t *testing.T) {
	stub := &transportFederatedAuthenticationStub{}
	_, router, _, _ := newFederatedTestRouter(t, "test", stub, &transportAuthStub{}, nil)
	request := federatedSAMLCallbackRequest(
		federatedOpaque(0x91), strings.Repeat("A", maximumSAMLCallbackBodyBytes+1),
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || len(stub.samlComplete) != 0 {
		t.Fatalf("oversized SAML callback = %d calls=%d", response.Code, len(stub.samlComplete))
	}
	assertFederatedNoStore(t, response)
}

type federatedSessionFixture struct {
	result  federatedauth.ApplyResult
	current authentication.SessionCredential
	token   string
}

func newFederatedSessionFixture(
	t testing.TB,
	method federatedauth.AuthenticationMethod,
	returnPath string,
	fill byte,
) federatedSessionFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	sessionID := identity.EntityID(uuid.Must(uuid.NewV7()))
	familyID := identity.EntityID(uuid.Must(uuid.NewV7()))
	token := federatedOpaque(fill)
	csrf := federatedOpaque(fill + 1)
	reservation, err := mfa.NewSessionReservation(mfa.SessionMaterial{
		SessionID: sessionID, FamilyID: familyID,
		TokenDigest: sha256.Sum256(token), CSRFDigest: sha256.Sum256(csrf),
		AuthenticationMethod: mfa.SessionAuthenticationMethod(method),
		IdleExpiresAt:        now.Add(time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
	}, now)
	if err != nil {
		t.Fatalf("session reservation: %v", err)
	}
	owned, err := federatedauth.NewSessionApplyCredentialReservation(reservation, token, csrf)
	if err != nil {
		t.Fatalf("browser session reservation: %v", err)
	}
	credential, ok := owned.ReleaseBrowserCredential(sessionID, identity.EntityID{})
	if !ok {
		t.Fatal("release browser session credential")
	}
	userID := uuid.Must(uuid.NewV7())
	return federatedSessionFixture{
		result: federatedauth.ApplyResult{
			Category: federatedauth.ApplySuccess, UserID: identity.EntityID(userID), SessionID: sessionID,
			ReturnPath: returnPath, Credential: credential,
		},
		current: authentication.SessionCredential{
			Session: authentication.Session{
				ID: uuid.UUID(sessionID), RotationFamilyID: uuid.UUID(familyID),
				User:      authentication.User{ID: userID, DisplayName: "Federated responder"},
				CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now.Add(time.Hour),
				AbsoluteExpiresAt: now.Add(8 * time.Hour), AuthenticationMethod: string(method),
			},
			SessionToken: string(token), CSRFToken: string(csrf),
		},
		token: string(token),
	}
}

type federatedContinuationFixture struct {
	result  federatedauth.ApplyResult
	receipt string
}

func newFederatedContinuationFixture(
	t testing.TB,
	returnPath string,
	now time.Time,
	fill byte,
) federatedContinuationFixture {
	t.Helper()
	continuationID := identity.EntityID(uuid.Must(uuid.NewV7()))
	receipt := federatedOpaque(fill)
	reservation, err := federatedauth.NewPostPrimaryContinuationReservation(
		federatedauth.PostPrimaryContinuationMaterial{
			ContinuationID: continuationID, ReceiptDigest: sha256.Sum256(receipt), ExpiresAt: now.Add(5 * time.Minute),
		},
		now,
	)
	if err != nil {
		t.Fatalf("continuation reservation: %v", err)
	}
	owned, err := federatedauth.NewContinuationApplyCredentialReservation(reservation, receipt)
	if err != nil {
		t.Fatalf("browser continuation reservation: %v", err)
	}
	credential, ok := owned.ReleaseBrowserCredential(identity.EntityID{}, continuationID)
	if !ok {
		t.Fatal("release browser continuation credential")
	}
	return federatedContinuationFixture{
		result: federatedauth.ApplyResult{
			Category: federatedauth.ApplySuccess, UserID: identity.EntityID(uuid.Must(uuid.NewV7())),
			ContinuationID: continuationID, ReturnPath: returnPath, Credential: credential,
		},
		receipt: string(receipt),
	}
}

func newFederatedTestRouter(
	t testing.TB,
	environment string,
	service FederatedAuthenticationService,
	auth AuthenticationService,
	trusted []netip.Prefix,
) (*Handler, http.Handler, *federatedauth.OIDCStartDigester, *federatedauth.SAMLStartDigester) {
	t.Helper()
	oidc, err := federatedauth.NewOIDCStartDigester(bytes.Repeat([]byte{0xa1}, 32))
	if err != nil {
		t.Fatalf("OIDC digester: %v", err)
	}
	saml, err := federatedauth.NewSAMLStartDigester(bytes.Repeat([]byte{0xb2}, 32))
	if err != nil {
		t.Fatalf("SAML digester: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	options := completeFederatedApplicationOptions(auth)
	options.Environment = environment
	options.TrustedProxyCIDRs = trusted
	options.FederatedBrowser = &FederatedBrowserOptions{
		Authentication: service, SAMLMetadata: unavailableTenantSAMLMetadataService{},
		OIDCStartDigest: oidc, SAMLStartDigest: saml,
	}
	handler, err := NewApplicationHandler(fixedChecker{ready: true}, logger, "test", time.Second, options)
	if err != nil {
		t.Fatalf("NewApplicationHandler: %v", err)
	}
	return handler, Router(handler, logger, false), oidc, saml
}

func completeFederatedApplicationOptions(auth AuthenticationService) ApplicationOptions {
	return ApplicationOptions{
		Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: auth,
		Authorization: &transportAuthorizationStub{}, Contacts: &transportContactStub{},
		CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{}, Environment: "test",
		IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{},
		MFA: &transportMFAStub{}, Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{},
		Platform: &transportPlatformStub{}, PublicOrigin: "http://localhost:8081",
		ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{}, Ticketing: &transportTicketingStub{},
		WorkflowAdministration: &transportWorkflowAdministrationStub{},
	}
}

func federatedStartRequest(target, returnPath string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(`{"returnPath":"`+returnPath+`"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.RemoteAddr = "192.0.2.10:44000"
	return request
}

func federatedFormStartRequest(target, returnPath string) *http.Request {
	values := url.Values{"returnPath": {returnPath}}
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://localhost:8081")
	request.RemoteAddr = "192.0.2.10:44000"
	return request
}

func federatedOIDCCallbackRequest(handle []byte) *http.Request {
	request := httptest.NewRequest(
		http.MethodGet, "/api/v1/auth/federated/oidc/callback?code=opaque&state=opaque", nil,
	)
	request.AddCookie(&http.Cookie{Name: developmentOIDCTransactionCookie, Value: string(handle)})
	return request
}

func federatedSAMLCallbackRequest(handle []byte, rawForm string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/federated/saml/acs", strings.NewReader(rawForm))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	request.AddCookie(&http.Cookie{Name: developmentSAMLTransactionCookie, Value: string(handle)})
	return request
}

func federatedOpaque(fill byte) []byte {
	raw := bytes.Repeat([]byte{fill}, sha256.Size)
	return []byte(base64.RawURLEncoding.EncodeToString(raw))
}

func assertFederatedNoStore(t testing.TB, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("sensitive response headers = Cache-Control:%q Referrer-Policy:%q", response.Header().Get("Cache-Control"), response.Header().Get("Referrer-Policy"))
	}
}

func assertFederatedTransactionCookie(
	t testing.TB,
	cookies []*http.Cookie,
	name string,
	wantValue string,
	cleared bool,
) {
	t.Helper()
	cookie := findResponseCookie(cookies, name)
	if cookie == nil {
		t.Fatalf("missing transaction cookie %q in %#v", name, cookies)
	}
	wantSameSite := http.SameSiteNoneMode
	if strings.Contains(name, "oidc") {
		wantSameSite = http.SameSiteLaxMode
	}
	if cookie.Value != wantValue || cookie.Path != "/" || cookie.Domain != "" || !cookie.HttpOnly || !cookie.Secure ||
		cookie.SameSite != wantSameSite || cleared && cookie.MaxAge >= 0 || !cleared && cookie.MaxAge <= 0 {
		t.Fatalf("transaction cookie = %#v, cleared=%t", cookie, cleared)
	}
}

func assertSessionCookie(t testing.TB, cookies []*http.Cookie, name, value string) {
	t.Helper()
	cookie := findPositiveResponseCookie(cookies, name)
	if cookie == nil || cookie.Value != value || cookie.Path != "/" || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie = %#v", cookie)
	}
}

func assertStrictCookie(t testing.TB, cookies []*http.Cookie, name, value string) {
	t.Helper()
	cookie := findPositiveResponseCookie(cookies, name)
	if cookie == nil || cookie.Value != value || cookie.Path != "/" || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("strict cookie = %#v", cookie)
	}
}

func assertClearedStrictCookie(t testing.TB, cookies []*http.Cookie, name string) {
	t.Helper()
	cookie := findResponseCookie(cookies, name)
	if cookie == nil || cookie.Value != "" || cookie.MaxAge >= 0 || cookie.Path != "/" ||
		!cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cleared strict cookie = %#v", cookie)
	}
}

func findResponseCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func findPositiveResponseCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name && cookie.MaxAge > 0 {
			return cookie
		}
	}
	return nil
}
