package httpserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

// transportIdentityProviderStub is fail-closed by default so unrelated HTTP
// tests satisfy the complete application boundary without accidentally making
// a tenant identity operation succeed.
type transportIdentityProviderStub struct {
	list           func(context.Context, authorization.Actor, uuid.UUID, identityprovider.ListInput) (identityprovider.ProviderPage, error)
	get            func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (identityprovider.Provider, error)
	create         func(context.Context, authorization.Actor, uuid.UUID, identityprovider.CreateInput) (identityprovider.CreateResult, error)
	update         func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.UpdateInput) (int64, error)
	archive        func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.ArchiveInput) (int64, error)
	rotate         func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.RotateBindSecretInput) (int64, error)
	clear          func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.ClearBindSecretInput) (int64, error)
	testConnection func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.TestInput) (identityprovider.TestResult, error)
	testBind       func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.TestInput) (identityprovider.TestResult, error)
}

func (s *transportIdentityProviderStub) List(ctx context.Context, actor authorization.Actor, tenantID uuid.UUID, input identityprovider.ListInput) (identityprovider.ProviderPage, error) {
	if s.list != nil {
		return s.list(ctx, actor, tenantID, input)
	}
	return identityprovider.ProviderPage{}, identityprovider.ErrUnavailable
}

func (s *transportIdentityProviderStub) Get(ctx context.Context, actor authorization.Actor, tenantID, providerID uuid.UUID) (identityprovider.Provider, error) {
	if s.get != nil {
		return s.get(ctx, actor, tenantID, providerID)
	}
	return identityprovider.Provider{}, identityprovider.ErrUnavailable
}

func (s *transportIdentityProviderStub) Create(ctx context.Context, actor authorization.Actor, tenantID uuid.UUID, input identityprovider.CreateInput) (identityprovider.CreateResult, error) {
	if s.create != nil {
		return s.create(ctx, actor, tenantID, input)
	}
	return identityprovider.CreateResult{}, identityprovider.ErrUnavailable
}

func (s *transportIdentityProviderStub) Update(ctx context.Context, actor authorization.Actor, tenantID, providerID uuid.UUID, input identityprovider.UpdateInput) (int64, error) {
	if s.update != nil {
		return s.update(ctx, actor, tenantID, providerID, input)
	}
	return 0, identityprovider.ErrUnavailable
}

func (s *transportIdentityProviderStub) Archive(ctx context.Context, actor authorization.Actor, tenantID, providerID uuid.UUID, input identityprovider.ArchiveInput) (int64, error) {
	if s.archive != nil {
		return s.archive(ctx, actor, tenantID, providerID, input)
	}
	return 0, identityprovider.ErrUnavailable
}

func (s *transportIdentityProviderStub) RotateBindSecret(ctx context.Context, actor authorization.Actor, tenantID, providerID uuid.UUID, input identityprovider.RotateBindSecretInput) (int64, error) {
	if s.rotate != nil {
		return s.rotate(ctx, actor, tenantID, providerID, input)
	}
	return 0, identityprovider.ErrUnavailable
}

func (s *transportIdentityProviderStub) ClearBindSecret(ctx context.Context, actor authorization.Actor, tenantID, providerID uuid.UUID, input identityprovider.ClearBindSecretInput) (int64, error) {
	if s.clear != nil {
		return s.clear(ctx, actor, tenantID, providerID, input)
	}
	return 0, identityprovider.ErrUnavailable
}

func (s *transportIdentityProviderStub) TestConnection(ctx context.Context, actor authorization.Actor, tenantID, providerID uuid.UUID, input identityprovider.TestInput) (identityprovider.TestResult, error) {
	if s.testConnection != nil {
		return s.testConnection(ctx, actor, tenantID, providerID, input)
	}
	return identityprovider.TestResult{}, identityprovider.ErrUnavailable
}

func (s *transportIdentityProviderStub) TestBind(ctx context.Context, actor authorization.Actor, tenantID, providerID uuid.UUID, input identityprovider.TestInput) (identityprovider.TestResult, error) {
	if s.testBind != nil {
		return s.testBind(ctx, actor, tenantID, providerID, input)
	}
	return identityprovider.TestResult{}, identityprovider.ErrUnavailable
}

func TestTransportIdentityProviderStubIsFailClosed(t *testing.T) {
	t.Parallel()
	if _, err := (&transportIdentityProviderStub{}).List(context.Background(), authorization.Actor{}, uuid.Nil, identityprovider.ListInput{}); err == nil {
		t.Fatal("transport identity-provider test boundary failed open")
	}
}

func TestTenantLDAPTransportWiresAllOperationsAndRedactsResponses(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	providerID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	testRunID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Millisecond)
	configuration, endpoints := validTenantLDAPDomainDocuments()
	summary := identityprovider.ProviderSummary{
		ID: providerID, TenantID: tenantID, Key: "corp", DisplayName: "Corporate directory",
		Description: "Directory", Template: identityprovider.ProviderTemplateCustom,
		BindSecretConfigured: true, EnabledEndpointCount: 1, Version: 7,
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}
	calls := make(map[string]int)
	service := &transportIdentityProviderStub{
		list: func(_ context.Context, _ authorization.Actor, got uuid.UUID, _ identityprovider.ListInput) (identityprovider.ProviderPage, error) {
			calls["list"]++
			if got != tenantID {
				t.Fatalf("list tenant = %s", got)
			}
			return identityprovider.ProviderPage{Items: []identityprovider.ProviderSummary{summary}}, nil
		},
		get: func(_ context.Context, _ authorization.Actor, gotTenant, gotProvider uuid.UUID) (identityprovider.Provider, error) {
			calls["get"]++
			if gotTenant != tenantID || gotProvider != providerID {
				t.Fatalf("get ids = %s/%s", gotTenant, gotProvider)
			}
			return identityprovider.Provider{ProviderSummary: summary, Configuration: configuration, Endpoints: endpoints}, nil
		},
		create: func(_ context.Context, _ authorization.Actor, got uuid.UUID, input identityprovider.CreateInput) (identityprovider.CreateResult, error) {
			calls["create"]++
			if got != tenantID || input.IdempotencyKey != "ldap-create-0123456789" || input.Audit.RequestID == uuid.Nil || input.Audit.CorrelationID == uuid.Nil {
				t.Fatalf("create tenant/input = %s/%#v", got, input)
			}
			return identityprovider.CreateResult{ProviderID: providerID, Version: 1, Replayed: calls["create"] > 1}, nil
		},
		update: func(_ context.Context, _ authorization.Actor, _, _ uuid.UUID, input identityprovider.UpdateInput) (int64, error) {
			calls["update"]++
			if input.ExpectedEntityTag == nil || *input.ExpectedEntityTag != `"v7"` || !input.Enabled {
				t.Fatalf("update input = %#v", input)
			}
			return 8, nil
		},
		archive: func(_ context.Context, _ authorization.Actor, _, _ uuid.UUID, input identityprovider.ArchiveInput) (int64, error) {
			calls["archive"]++
			if input.Reason != "retired" {
				t.Fatalf("archive input = %#v", input)
			}
			return 9, nil
		},
		rotate: func(_ context.Context, _ authorization.Actor, _, _ uuid.UUID, input identityprovider.RotateBindSecretInput) (int64, error) {
			calls["rotate"]++
			if string(input.Secret) != "p@ssword" {
				t.Fatalf("rotate secret mismatch")
			}
			return 10, nil
		},
		clear: func(_ context.Context, _ authorization.Actor, _, _ uuid.UUID, input identityprovider.ClearBindSecretInput) (int64, error) {
			calls["clear"]++
			if input.Reason != "credential retired" {
				t.Fatalf("clear input = %#v", input)
			}
			return 11, nil
		},
		testConnection: func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.TestInput) (identityprovider.TestResult, error) {
			calls["connection"]++
			priority := 10
			return identityprovider.TestResult{TestRunID: testRunID, Outcome: "success", Category: "success", EndpointPriority: &priority, Duration: 12 * time.Millisecond, CompletedAt: now}, nil
		},
		testBind: func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.TestInput) (identityprovider.TestResult, error) {
			calls["bind"]++
			return identityprovider.TestResult{TestRunID: testRunID, Outcome: "failure", Category: "bind_rejected", Duration: 13 * time.Millisecond, CompletedAt: now}, nil
		},
	}
	router := newIdentityProviderTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), service)
	base := "/api/v1/tenants/" + tenantID.String() + "/auth-providers"

	tests := []struct {
		name, method, path string
		body               []byte
		mutation           bool
		ifMatch            string
		wantStatus         int
		wantETag           string
	}{
		{name: "list", method: http.MethodGet, path: base, wantStatus: http.StatusOK},
		{name: "get", method: http.MethodGet, path: base + "/" + providerID.String(), wantStatus: http.StatusOK, wantETag: `"v7"`},
		{name: "create", method: http.MethodPost, path: base, body: validTenantLDAPWriteBody(t, true, nil), mutation: true, wantStatus: http.StatusCreated},
		{name: "create replay", method: http.MethodPost, path: base, body: validTenantLDAPWriteBody(t, true, nil), mutation: true, wantStatus: http.StatusCreated},
		{name: "update", method: http.MethodPut, path: base + "/" + providerID.String(), body: validTenantLDAPWriteBody(t, false, nil), mutation: true, ifMatch: `"v7"`, wantStatus: http.StatusNoContent, wantETag: `"v8"`},
		{name: "archive", method: http.MethodDelete, path: base + "/" + providerID.String(), body: []byte(`{"reason":"retired"}`), mutation: true, ifMatch: `"v8"`, wantStatus: http.StatusNoContent, wantETag: `"v9"`},
		{name: "rotate secret", method: http.MethodPut, path: base + "/" + providerID.String() + "/bind-secret", body: []byte(`{"secret":"p@ssword"}`), mutation: true, ifMatch: `"v9"`, wantStatus: http.StatusNoContent, wantETag: `"v10"`},
		{name: "clear secret", method: http.MethodDelete, path: base + "/" + providerID.String() + "/bind-secret", body: []byte(`{"reason":"credential retired"}`), mutation: true, ifMatch: `"v10"`, wantStatus: http.StatusNoContent, wantETag: `"v11"`},
		{name: "test connection", method: http.MethodPost, path: base + "/" + providerID.String() + "/tests/connection", mutation: true, wantStatus: http.StatusOK},
		{name: "test bind", method: http.MethodPost, path: base + "/" + providerID.String() + "/tests/bind", mutation: true, wantStatus: http.StatusOK},
	}
	locations := make([]string, 0, 2)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var body io.Reader
			if test.body != nil {
				body = bytes.NewReader(test.body)
			}
			request := httptest.NewRequest(test.method, test.path, body)
			prepareTenantLDAPTransportRequest(request, test.mutation)
			if test.body != nil {
				request.Header.Set("Content-Type", "application/json")
			}
			if strings.HasPrefix(test.name, "create") {
				request.Header.Set(idempotencyKeyHeader, "ldap-create-0123456789")
			}
			if test.ifMatch != "" {
				request.Header.Set(ifMatchHeader, test.ifMatch)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d: %s", response.Code, response.Body.String())
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
			}
			if response.Header().Get("ETag") != test.wantETag {
				t.Fatalf("ETag = %q, want %q", response.Header().Get("ETag"), test.wantETag)
			}
			if strings.HasPrefix(test.name, "create") {
				locations = append(locations, response.Header().Get("Location"))
				if response.Body.Len() != 0 {
					t.Fatalf("create body = %q", response.Body.String())
				}
			}
			if test.wantStatus == http.StatusNoContent && response.Body.Len() != 0 {
				t.Fatalf("204 body = %q", response.Body.String())
			}
			if test.name == "get" && strings.Contains(response.Body.String(), "ciphertext") || strings.Contains(response.Body.String(), "p@ssword") {
				t.Fatalf("secret material in response: %s", response.Body.String())
			}
		})
	}
	if len(locations) != 2 || locations[0] == "" || locations[0] != locations[1] {
		t.Fatalf("create replay locations = %#v", locations)
	}
	for _, operation := range []string{"list", "get", "create", "update", "archive", "rotate", "clear", "connection", "bind"} {
		want := 1
		if operation == "create" {
			want = 2
		}
		if calls[operation] != want {
			t.Fatalf("%s calls = %d, want %d", operation, calls[operation], want)
		}
	}
}

func TestTenantLDAPJSONRequiresExactNestedPresenceAndRejectsDuplicates(t *testing.T) {
	base := tenantLDAPWriteObject(true, nil)
	tests := []struct {
		name string
		body func() []byte
	}{
		{name: "missing nullable configuration", body: func() []byte {
			value := tenantLDAPWriteObject(true, nil)
			delete(value["configuration"].(map[string]any), "customCaPem")
			return marshalTenantLDAPTestBody(t, value)
		}},
		{name: "missing boolean configuration", body: func() []byte {
			value := tenantLDAPWriteObject(true, nil)
			delete(value["configuration"].(map[string]any), "verifyCertificate")
			return marshalTenantLDAPTestBody(t, value)
		}},
		{name: "missing zero configuration", body: func() []byte {
			value := tenantLDAPWriteObject(true, nil)
			delete(value["configuration"].(map[string]any), "maxReferralHops")
			return marshalTenantLDAPTestBody(t, value)
		}},
		{name: "missing const null configuration", body: func() []byte {
			value := tenantLDAPWriteObject(true, nil)
			delete(value["configuration"].(map[string]any), "syncIntervalSeconds")
			return marshalTenantLDAPTestBody(t, value)
		}},
		{name: "missing endpoint boolean", body: func() []byte {
			value := tenantLDAPWriteObject(true, nil)
			delete(value["endpoints"].([]any)[0].(map[string]any), "enabled")
			return marshalTenantLDAPTestBody(t, value)
		}},
		{name: "missing endpoint false", body: func() []byte {
			value := tenantLDAPWriteObject(true, nil)
			delete(value["endpoints"].([]any)[0].(map[string]any), "referralAllowed")
			return marshalTenantLDAPTestBody(t, value)
		}},
		{name: "duplicate top level", body: func() []byte {
			return bytes.Replace(marshalTenantLDAPTestBody(t, base), []byte(`"kind":`), []byte(`"kind":"ldap","kind":`), 1)
		}},
		{name: "duplicate configuration", body: func() []byte {
			return bytes.Replace(marshalTenantLDAPTestBody(t, base), []byte(`"template":`), []byte(`"template":"custom","template":`), 1)
		}},
		{name: "duplicate endpoint", body: func() []byte {
			return bytes.Replace(marshalTenantLDAPTestBody(t, base), []byte(`"enabled":`), []byte(`"enabled":false,"enabled":`), 1)
		}},
		{name: "unknown nested", body: func() []byte {
			value := tenantLDAPWriteObject(true, nil)
			value["configuration"].(map[string]any)["future"] = true
			return marshalTenantLDAPTestBody(t, value)
		}},
		{name: "trailing JSON", body: func() []byte { return append(marshalTenantLDAPTestBody(t, base), []byte(` {}`)...) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(test.body()))
			request.Header.Set("Content-Type", "application/json")
			var destination contract.TenantLDAPAuthProviderCreateRequest
			if err := decodeTenantLDAPCreateBody(request, &destination); err == nil {
				t.Fatal("invalid body was accepted")
			}
		})
	}
}

func TestTenantLDAPJSONScannerAcceptsMultilineCustomCAPEM(t *testing.T) {
	certificate := tenantLDAPTestCACertificate(t)
	request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(validTenantLDAPWriteBody(t, true, &certificate)))
	request.Header.Set("Content-Type", "application/json")
	var destination contract.TenantLDAPAuthProviderCreateRequest
	if err := decodeTenantLDAPCreateBody(request, &destination); err != nil {
		t.Fatalf("decode valid multiline CA: %v", err)
	}
	if destination.Configuration.CustomCaPem == nil || *destination.Configuration.CustomCaPem != certificate {
		t.Fatal("multiline CA was not preserved")
	}
}

func TestTenantLDAPBindSecretDecoderIsStrictBoundedAndClearsOwnedBuffers(t *testing.T) {
	source := []byte(`{"secret":"p\u0040ss\nword"}`)
	document := make([]byte, len(source), 128)
	copy(document, source)
	for index := len(document); index < cap(document); index++ {
		document[:cap(document)][index] = 0xA5
	}
	secret, err := decodeTenantLDAPBindSecretDocument(document)
	if err != nil {
		t.Fatalf("decode secret document: %v", err)
	}
	if string(secret) != "p@ss\nword" {
		t.Fatalf("secret = %q", secret)
	}
	if !allTenantLDAPBytesZero(document[:cap(document)]) {
		t.Fatal("owned raw document capacity was not cleared")
	}
	clear(secret)

	tests := []struct {
		name string
		body []byte
	}{
		{name: "extra key", body: []byte(`{"secret":"x","extra":true}`)},
		{name: "duplicate secret", body: []byte(`{"secret":"x","secret":"y"}`)},
		{name: "invalid escape", body: []byte(`{"secret":"x\q"}`)},
		{name: "lone high surrogate", body: []byte(`{"secret":"\uD800"}`)},
		{name: "lone low surrogate", body: []byte(`{"secret":"\uDC00"}`)},
		{name: "invalid UTF-8", body: append([]byte(`{"secret":"`), 0xff, '"', '}')},
		{name: "empty", body: []byte(`{"secret":""}`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := make([]byte, len(test.body), len(test.body)+16)
			copy(raw, test.body)
			if _, err := decodeTenantLDAPBindSecretDocument(raw); err == nil {
				t.Fatal("invalid secret document was accepted")
			}
			if !allTenantLDAPBytesZero(raw[:cap(raw)]) {
				t.Fatal("rejected raw document was not cleared")
			}
		})
	}

	chunked := &tenantLDAPChunkedReader{source: []byte(`{"secret":"chunked"}`), maximum: 1}
	request := httptest.NewRequest(http.MethodPut, "/", chunked)
	request.Header.Set("Content-Type", "application/json")
	secret, err = decodeTenantLDAPBindSecret(request)
	if err != nil || string(secret) != "chunked" {
		t.Fatalf("chunked decode = %q, %v", secret, err)
	}
	clear(secret)

	oversize := bytes.Repeat([]byte{'x'}, maximumTenantLDAPSecretBodyBytes+1)
	request = httptest.NewRequest(http.MethodPut, "/", &tenantLDAPChunkedReader{source: oversize, maximum: 127})
	request.Header.Set("Content-Type", "application/json")
	if _, err := decodeTenantLDAPBindSecret(request); err == nil {
		t.Fatal("oversize body was accepted")
	}

	request = httptest.NewRequest(http.MethodPut, "/", &tenantLDAPReadErrorReader{})
	request.Header.Set("Content-Type", "application/json")
	if _, err := decodeTenantLDAPBindSecret(request); err == nil {
		t.Fatal("read error was accepted")
	}
}

func TestTenantLDAPBindSecretHandlerClearsPlaintextOnSuccessAndError(t *testing.T) {
	for _, test := range []struct {
		name         string
		serviceError error
	}{{name: "success"}, {name: "service error", serviceError: identityprovider.ErrConflict}} {
		t.Run(test.name, func(t *testing.T) {
			tenantID, providerID, userID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
			var captured []byte
			service := &transportIdentityProviderStub{rotate: func(_ context.Context, _ authorization.Actor, _, _ uuid.UUID, input identityprovider.RotateBindSecretInput) (int64, error) {
				captured = input.Secret
				return 2, test.serviceError
			}}
			request := tenantLDAPMutationRequest(http.MethodPut, "/api/v1/tenants/"+tenantID.String()+"/auth-providers/"+providerID.String()+"/bind-secret", []byte(`{"secret":"owned-secret"}`))
			request.Header.Set(ifMatchHeader, `"v1"`)
			response := httptest.NewRecorder()
			newIdentityProviderTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), service).ServeHTTP(response, request)
			if len(captured) == 0 || !allTenantLDAPBytesZero(captured) {
				t.Fatalf("plaintext not cleared: %v", captured)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
			}
		})
	}
}

func TestRequireTenantLDAPBodyAbsentRequiresExactEOF(t *testing.T) {
	tests := []struct {
		name      string
		body      io.ReadCloser
		wantError bool
	}{
		{name: "exact EOF", body: io.NopCloser(bytes.NewReader(nil))},
		{name: "staged no progress", body: &tenantLDAPStagedReader{}, wantError: true},
		{name: "read failure", body: io.NopCloser(&tenantLDAPReadErrorReader{}), wantError: true},
		{name: "byte", body: io.NopCloser(strings.NewReader("x")), wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/", nil)
			request.Body = test.body
			request.ContentLength = 0
			err := requireTenantLDAPBodyAbsent(request)
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError %t", err, test.wantError)
			}
		})
	}
}

func TestTenantLDAPGeneratedRequestFailuresAreNeverCached(t *testing.T) {
	tenantID, providerID, userID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	router := newIdentityProviderTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), &transportIdentityProviderStub{})
	tests := []struct {
		name, method, path string
		mutation           bool
	}{
		{name: "malformed provider id", method: http.MethodGet, path: "/api/v1/tenants/" + tenantID.String() + "/auth-providers/not-a-uuid"},
		{name: "missing If-Match", method: http.MethodDelete, path: "/api/v1/tenants/" + tenantID.String() + "/auth-providers/" + providerID.String(), mutation: true},
		{name: "malformed query", method: http.MethodGet, path: "/api/v1/tenants/" + tenantID.String() + "/auth-providers?limit=not-an-integer"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			prepareTenantLDAPTransportRequest(request, test.mutation)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code < 400 {
				t.Fatalf("status = %d", response.Code)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
			}
		})
	}
}

func newIdentityProviderTestRouter(
	t *testing.T,
	auth AuthenticationService,
	service IdentityProviderService,
) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, logger, "test", time.Second,
		ApplicationOptions{
			Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: auth, Authorization: &transportAuthorizationStub{},
			Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{},
			Environment: "test", IdentityProviders: service, LDAPAdministration: &transportLDAPAdministrationStub{}, MFA: &transportMFAStub{}, Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{},
			Platform: &transportPlatformStub{}, PublicOrigin: "http://localhost:8081",
			ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{}, Ticketing: &transportTicketingStub{}, WorkflowAdministration: &transportWorkflowAdministrationStub{},
		},
	)
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}

func tenantLDAPTransportAuthentication(tenantID, userID uuid.UUID) *transportAuthStub {
	return &transportAuthStub{authenticateResult: authentication.Session{
		ID: uuid.Must(uuid.NewV7()), User: authentication.User{ID: userID}, ActiveTenantID: &tenantID,
		AuthenticationMethod: "totp",
	}}
}

func prepareTenantLDAPTransportRequest(request *http.Request, mutation bool) {
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	request.RemoteAddr = "198.51.100.42:4123"
	if mutation {
		request.Header.Set("Origin", "http://localhost:8081")
		request.Header.Set(csrfTokenHeader, "csrf-value")
	}
}

func tenantLDAPMutationRequest(method, path string, body []byte) *http.Request {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	prepareTenantLDAPTransportRequest(request, true)
	request.Header.Set("Content-Type", "application/json")
	return request
}

func validTenantLDAPWriteBody(t *testing.T, create bool, customCAPEM *string) []byte {
	t.Helper()
	return marshalTenantLDAPTestBody(t, tenantLDAPWriteObject(create, customCAPEM))
}

func tenantLDAPWriteObject(create bool, customCAPEM *string) map[string]any {
	configuration := map[string]any{
		"template": "custom", "verifyCertificate": true, "customCaPem": customCAPEM,
		"connectTimeoutMs": 1000, "operationTimeoutMs": 2000,
		"bindDn": "cn=bind,dc=example,dc=com", "userBaseDn": "ou=users,dc=example,dc=com",
		"groupBaseDn": nil, "userSearchFilter": "(uid={username})", "groupSearchFilter": nil,
		"userDnTemplate": nil, "pageSize": 100, "maxPages": 10, "maxEntries": 1000,
		"maxResponseBytes": 1048576, "referralMode": "disabled", "maxReferralHops": 0,
		"nestedGroupMode": "disabled", "maxNestedGroupDepth": 0, "maxGroups": 100,
		"firstNameAttribute": "givenName", "lastNameAttribute": "sn", "displayNameAttribute": "displayName",
		"usernameAttribute": "uid", "alternateUsernameAttribute": nil, "emailAttribute": nil,
		"immutableSubjectAttribute": "entryUUID", "immutableSubjectFormat": "entry_uuid",
		"groupMembershipAttribute": nil, "posixMemberUidAttribute": nil, "posixGidNumberAttribute": nil,
		"accountStatusMode": "none", "accountStatusAttribute": nil, "accountDisabledValue": nil,
		"jitMode": "disabled", "noMatchPolicy": "deny", "deprovisionMode": "retain",
		"deprovisionGraceSeconds": 0, "syncIntervalSeconds": nil,
	}
	endpoint := map[string]any{
		"priority": 10, "host": "ldap.example.com", "port": 636, "transport": "ldaps",
		"tlsServerName": "ldap.example.com", "referralAllowed": false, "enabled": true,
	}
	result := map[string]any{
		"key": "corp", "displayName": "Corporate directory", "description": "Directory",
		"configuration": configuration, "endpoints": []any{endpoint},
	}
	if create {
		result["kind"] = "ldap"
	} else {
		result["enabled"] = true
	}
	return result
}

func marshalTenantLDAPTestBody(t *testing.T, value any) []byte {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal LDAP request fixture: %v", err)
	}
	return document
}

func validTenantLDAPDomainDocuments() (identityprovider.Configuration, []identityprovider.Endpoint) {
	return identityprovider.Configuration{
			Template: identityprovider.ProviderTemplateCustom, VerifyCertificate: true,
			ConnectTimeoutMS: 1000, OperationTimeoutMS: 2000, BindDN: "cn=bind,dc=example,dc=com",
			UserBaseDN: "ou=users,dc=example,dc=com", UserSearchFilter: "(uid={username})",
			PageSize: 100, MaxPages: 10, MaxEntries: 1000, MaxResponseBytes: 1048576,
			ReferralMode: identityprovider.ReferralModeDisabled, NestedGroupMode: identityprovider.NestedGroupModeDisabled,
			MaxGroups: 100, FirstNameAttribute: "givenName", LastNameAttribute: "sn",
			DisplayNameAttribute: "displayName", UsernameAttribute: "uid", ImmutableSubjectAttribute: "entryUUID",
			ImmutableSubjectFormat: identityprovider.SubjectFormatEntryUUID, AccountStatusMode: identityprovider.AccountStatusModeNone,
			JITMode: identityprovider.JITModeDisabled, NoMatchPolicy: identityprovider.NoMatchPolicyDeny,
			DeprovisionMode: identityprovider.DeprovisionModeRetain,
		}, []identityprovider.Endpoint{{
			Priority: 10, Host: "ldap.example.com", Port: 636, Transport: "ldaps",
			TLSServerName: "ldap.example.com", Enabled: true,
		}}
}

func tenantLDAPTestCACertificate(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Periapsis LDAP test CA"},
		NotBefore: time.Unix(1, 0), NotAfter: time.Unix(4102444800, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}))
}

func allTenantLDAPBytesZero(value []byte) bool {
	for _, character := range value {
		if character != 0 {
			return false
		}
	}
	return true
}

type tenantLDAPChunkedReader struct {
	source          []byte
	offset, maximum int
}

func (r *tenantLDAPChunkedReader) Read(destination []byte) (int, error) {
	if r.offset >= len(r.source) {
		return 0, io.EOF
	}
	limit := r.maximum
	if limit < 1 || limit > len(destination) {
		limit = len(destination)
	}
	remaining := len(r.source) - r.offset
	if limit > remaining {
		limit = remaining
	}
	copy(destination[:limit], r.source[r.offset:r.offset+limit])
	r.offset += limit
	return limit, nil
}

type tenantLDAPReadErrorReader struct{}

func (*tenantLDAPReadErrorReader) Read([]byte) (int, error) {
	return 0, errors.New("fixture read failure")
}

type tenantLDAPStagedReader struct{ stage int }

func (r *tenantLDAPStagedReader) Read(destination []byte) (int, error) {
	if r.stage == 0 {
		r.stage++
		return 0, nil
	}
	if r.stage == 1 {
		r.stage++
		destination[0] = 'x'
		return 1, nil
	}
	return 0, io.EOF
}
func (*tenantLDAPStagedReader) Close() error { return nil }
