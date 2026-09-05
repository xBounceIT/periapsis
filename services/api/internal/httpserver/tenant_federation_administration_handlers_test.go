package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

func TestTenantFederationTransportWiresSafeCRUDAndWriteOnlySecret(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	providerID := uuid.Must(uuid.NewV7())
	bindingID := uuid.Must(uuid.NewV7())
	ruleID := uuid.Must(uuid.NewV7())
	groupID := uuid.Must(uuid.NewV7())
	roleID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	provider := tenantFederationHTTPProvider(tenantID, providerID, bindingID)
	calls := make(map[string]int)
	var retainedSecret []byte
	service := &transportTenantFederationStub{
		list: func(_ context.Context, _ authorization.Actor, got uuid.UUID, input identityprovider.FederationListInput) (identityprovider.FederationProviderPage, error) {
			calls["list"]++
			if got != tenantID || !input.IncludeArchived {
				t.Fatalf("list input = %s %#v", got, input)
			}
			return identityprovider.FederationProviderPage{Items: []identityprovider.FederationProviderSummary{provider.FederationProviderSummary}}, nil
		},
		get: func(_ context.Context, _ authorization.Actor, gotTenant, gotProvider uuid.UUID) (identityprovider.FederationProvider, error) {
			calls["get"]++
			if gotTenant != tenantID || gotProvider != providerID {
				t.Fatalf("get ids = %s/%s", gotTenant, gotProvider)
			}
			return provider, nil
		},
		create: func(_ context.Context, _ authorization.Actor, got uuid.UUID, input identityprovider.FederationCreateInput) (identityprovider.FederationCreateResult, error) {
			calls["create"]++
			if got != tenantID || input.Kind != identityprovider.FederationProviderOIDC ||
				input.IdempotencyKey != "tenant-federation-create-001" || input.OIDC == nil ||
				input.Audit.RequestID == uuid.Nil {
				t.Fatalf("create input = %#v", input)
			}
			return identityprovider.FederationCreateResult{Provider: provider}, nil
		},
		update: func(_ context.Context, _ authorization.Actor, _, _ uuid.UUID, input identityprovider.FederationUpdateInput) (identityprovider.FederationProvider, error) {
			calls["update"]++
			if input.ExpectedEntityTag == nil || *input.ExpectedEntityTag != `"v4"` || !input.Enabled || input.OIDC == nil {
				t.Fatalf("update input = %#v", input)
			}
			next := provider
			next.Version, next.Enabled, next.Binding.Enabled = 5, true, true
			return next, nil
		},
		archive: func(_ context.Context, _ authorization.Actor, _, _ uuid.UUID, input identityprovider.FederationArchiveInput) (int64, error) {
			calls["archive"]++
			if input.Reason != "retired provider" || input.ExpectedEntityTag == nil {
				t.Fatalf("archive input = %#v", input)
			}
			return 5, nil
		},
		replace: func(_ context.Context, _ authorization.Actor, _, _ uuid.UUID, input identityprovider.FederationReplaceOIDCSecretInput) (identityprovider.FederationSecretMutationReceipt, error) {
			calls["replace"]++
			if string(input.Secret) != "one-time-secret" || input.Reason != "rotate credential" {
				t.Fatalf("replace input = %s/%q", input.String(), input.Reason)
			}
			retainedSecret = input.Secret
			return identityprovider.FederationSecretMutationReceipt{ProviderID: providerID, ProviderVersion: 5, SecretRevision: 2}, nil
		},
		clear: func(_ context.Context, _ authorization.Actor, _, _ uuid.UUID, input identityprovider.FederationClearOIDCSecretInput) (identityprovider.FederationSecretMutationReceipt, error) {
			calls["clear"]++
			if input.Reason != "retire credential" {
				t.Fatalf("clear input = %#v", input)
			}
			return identityprovider.FederationSecretMutationReceipt{ProviderID: providerID, ProviderVersion: 6, SecretRevision: 3}, nil
		},
		refreshTrust: func(_ context.Context, _ authorization.Actor, _, _ uuid.UUID, input identityprovider.FederationOIDCTrustDocumentsInput) (identityprovider.FederationOIDCTrustDocumentsReceipt, error) {
			calls["refresh trust"]++
			if input.Reason != "refresh trust" || input.ExpectedEntityTag == nil || *input.ExpectedEntityTag != `"v4"` {
				t.Fatalf("refresh trust input = %#v", input)
			}
			return identityprovider.FederationOIDCTrustDocumentsReceipt{
				ProviderID: providerID, ProviderVersion: 5, DiscoveryRevision: 2, JWKSRevision: 2, KeyCount: 3,
			}, nil
		},
		getMapping: func(_ context.Context, _ authorization.Actor, _, _ uuid.UUID) (identityprovider.FederationMappingPolicy, error) {
			calls["get mapping"]++
			return tenantFederationHTTPMappingPolicy(tenantID, providerID, ruleID, groupID, roleID), nil
		},
		replaceMapping: func(_ context.Context, _ authorization.Actor, _, _ uuid.UUID, input identityprovider.FederationReplaceMappingPolicyInput) (identityprovider.FederationPolicyMutationReceipt, error) {
			calls["replace mapping"]++
			if input.Kind != identityprovider.FederationProviderOIDC || len(input.OIDCClaimRules) != 3 ||
				len(input.Rules) != 1 || input.ExpectedEntityTag == nil || *input.ExpectedEntityTag != `"v4"` {
				t.Fatalf("mapping input = %#v", input)
			}
			return identityprovider.FederationPolicyMutationReceipt{
				ProviderID: providerID, ProviderVersion: 5, MappingRevision: 2,
			}, nil
		},
		getAssurance: func(_ context.Context, _ authorization.Actor, _, _ uuid.UUID) (identityprovider.FederationAssurancePolicy, error) {
			calls["get assurance"]++
			return tenantFederationHTTPAssurancePolicy(tenantID, providerID, ruleID), nil
		},
		replaceAssurance: func(_ context.Context, _ authorization.Actor, _, _ uuid.UUID, input identityprovider.FederationReplaceAssurancePolicyInput) (identityprovider.FederationPolicyMutationReceipt, error) {
			calls["replace assurance"]++
			if input.Kind != identityprovider.FederationProviderOIDC || len(input.Rules) != 1 ||
				input.ExpectedEntityTag == nil || *input.ExpectedEntityTag != `"v4"` {
				t.Fatalf("assurance input = %#v", input)
			}
			return identityprovider.FederationPolicyMutationReceipt{
				ProviderID: providerID, ProviderVersion: 5, AssurancePolicyRevision: 2,
			}, nil
		},
	}
	router := newTenantFederationTestRouter(t, tenantFederationHTTPAuthentication(tenantID, userID), service)
	base := "/api/v1/tenants/" + tenantID.String() + "/federated-auth-providers"
	tests := []struct {
		name, method, path string
		body               any
		mutation           bool
		headers            map[string]string
		wantStatus         int
	}{
		{name: "list", method: http.MethodGet, path: base + "?includeArchived=true", wantStatus: http.StatusOK},
		{name: "get", method: http.MethodGet, path: base + "/" + providerID.String(), wantStatus: http.StatusOK},
		{name: "create", method: http.MethodPost, path: base, body: tenantFederationOIDCCreateDocument(), mutation: true,
			headers: map[string]string{"Idempotency-Key": "tenant-federation-create-001"}, wantStatus: http.StatusCreated},
		{name: "update", method: http.MethodPut, path: base + "/" + providerID.String(), body: tenantFederationOIDCUpdateDocument(), mutation: true,
			headers: map[string]string{"If-Match": `"v4"`}, wantStatus: http.StatusOK},
		{name: "archive", method: http.MethodDelete, path: base + "/" + providerID.String(), body: map[string]any{"reason": "retired provider"}, mutation: true,
			headers: map[string]string{"If-Match": `"v4"`}, wantStatus: http.StatusNoContent},
		{name: "replace secret", method: http.MethodPut, path: base + "/" + providerID.String() + "/oidc/client-secret",
			body: map[string]any{"clientSecret": "one-time-secret", "reason": "rotate credential"}, mutation: true,
			headers: map[string]string{"If-Match": `"v4"`}, wantStatus: http.StatusNoContent},
		{name: "clear secret", method: http.MethodDelete, path: base + "/" + providerID.String() + "/oidc/client-secret",
			body: map[string]any{"reason": "retire credential"}, mutation: true,
			headers: map[string]string{"If-Match": `"v5"`}, wantStatus: http.StatusNoContent},
		{name: "refresh trust", method: http.MethodPut, path: base + "/" + providerID.String() + "/oidc/trust-documents",
			body: map[string]any{"clientAuthentication": "client_secret_basic", "signingAlgorithms": []string{"RS256"}, "reason": "refresh trust"}, mutation: true,
			headers: map[string]string{"If-Match": `"v4"`}, wantStatus: http.StatusNoContent},
		{name: "get mapping", method: http.MethodGet, path: base + "/" + providerID.String() + "/mapping-policy", wantStatus: http.StatusOK},
		{name: "replace mapping", method: http.MethodPut, path: base + "/" + providerID.String() + "/mapping-policy",
			body: tenantFederationOIDCMappingDocument(ruleID, groupID, roleID), mutation: true,
			headers: map[string]string{"If-Match": `"v4"`}, wantStatus: http.StatusNoContent},
		{name: "get assurance", method: http.MethodGet, path: base + "/" + providerID.String() + "/assurance-policy", wantStatus: http.StatusOK},
		{name: "replace assurance", method: http.MethodPut, path: base + "/" + providerID.String() + "/assurance-policy",
			body: tenantFederationOIDCAssuranceDocument(ruleID), mutation: true,
			headers: map[string]string{"If-Match": `"v4"`}, wantStatus: http.StatusNoContent},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var body []byte
			if test.body != nil {
				var err error
				body, err = json.Marshal(test.body)
				if err != nil {
					t.Fatalf("marshal request: %v", err)
				}
			}
			request := httptest.NewRequest(test.method, test.path, bytes.NewReader(body))
			prepareTenantLDAPTransportRequest(request, test.mutation)
			if test.body != nil {
				request.Header.Set("Content-Type", "application/json")
			}
			for name, value := range test.headers {
				request.Header.Set(name, value)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
			}
			if test.wantStatus == http.StatusOK || test.wantStatus == http.StatusCreated {
				var projected map[string]any
				if err := json.Unmarshal(response.Body.Bytes(), &projected); err != nil {
					t.Fatalf("decode response: %v", err)
				}
				assertTenantFederationResponseHasNoRawMaterial(t, projected)
			}
		})
	}
	for _, name := range []string{"list", "get", "create", "update", "archive", "replace", "clear", "refresh trust",
		"get mapping", "replace mapping", "get assurance", "replace assurance"} {
		if calls[name] != 1 {
			t.Fatalf("%s calls = %d", name, calls[name])
		}
	}
	if len(retainedSecret) == 0 {
		t.Fatal("secret buffer was not observed")
	}
	for index, value := range retainedSecret {
		if value != 0 {
			t.Fatalf("secret buffer[%d] was not cleared", index)
		}
	}
}

func TestTenantFederationOIDCProjectionPreservesCompleteConfiguration(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	providerID := uuid.Must(uuid.NewV7())
	bindingID := uuid.Must(uuid.NewV7())
	mapped, err := mapTenantFederationProvider(tenantFederationHTTPProvider(tenantID, providerID, bindingID))
	if err != nil {
		t.Fatalf("mapTenantFederationProvider() error = %v", err)
	}
	typed, err := mapped.ValueByDiscriminator()
	if err != nil {
		t.Fatalf("ValueByDiscriminator() error = %v", err)
	}
	oidc, ok := typed.(contract.TenantFederationOIDCAuthProvider)
	if !ok || oidc.Kind != contract.TenantFederationOIDCAuthProviderKindOidc ||
		oidc.Configuration.RedirectUri != "https://soc.example.com/api/v1/auth/federated/oidc/callback" {
		t.Fatalf("typed OIDC provider = %#v", typed)
	}
	wire, err := json.Marshal(mapped)
	if err != nil {
		t.Fatalf("marshal provider: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(wire, &document); err != nil {
		t.Fatalf("decode provider: %v", err)
	}
	configuration, ok := document["configuration"].(map[string]any)
	if !ok {
		t.Fatalf("configuration = %#v", document["configuration"])
	}
	if len(configuration) != 11 ||
		configuration["issuer"] != "https://id.example.com" ||
		configuration["clientId"] != "periapsis-tenant" ||
		configuration["redirectUri"] != "https://soc.example.com/api/v1/auth/federated/oidc/callback" ||
		configuration["postLogoutRedirectUri"] != "https://soc.example.com/signed-out" ||
		configuration["allowRefreshToken"] != true || configuration["useUserInfo"] != false ||
		configuration["clientSecretPresent"] != true || configuration["clientSecretRevision"] != float64(2) ||
		configuration["discoveryRevision"] != float64(2) || configuration["jwksRevision"] != float64(2) {
		t.Fatalf("OIDC configuration = %#v", configuration)
	}
	scopes, ok := configuration["extraScopes"].([]any)
	if !ok || len(scopes) != 2 || scopes[0] != "email" || scopes[1] != "profile" {
		t.Fatalf("OIDC extra scopes = %#v", configuration["extraScopes"])
	}

	emptyScopesProvider := tenantFederationHTTPProvider(tenantID, providerID, bindingID)
	emptyScopesProvider.OIDC.ExtraScopes = nil
	emptyScopesProvider.OIDC.AllowRefreshToken = false
	emptyScopes, err := mapTenantFederationProvider(emptyScopesProvider)
	if err != nil {
		t.Fatalf("map provider with empty scopes: %v", err)
	}
	wire, err = json.Marshal(emptyScopes)
	if err != nil {
		t.Fatalf("marshal provider with empty scopes: %v", err)
	}
	document = nil
	if err := json.Unmarshal(wire, &document); err != nil {
		t.Fatalf("decode provider with empty scopes: %v", err)
	}
	configuration, ok = document["configuration"].(map[string]any)
	if !ok {
		t.Fatalf("empty-scope configuration = %#v", document["configuration"])
	}
	scopes, ok = configuration["extraScopes"].([]any)
	if !ok || len(scopes) != 0 {
		t.Fatalf("empty OIDC extra scopes = %#v", configuration["extraScopes"])
	}
}

func TestTenantFederationBodiesRejectUnknownDuplicateAndOversizeSecretFields(t *testing.T) {
	t.Parallel()

	valid := tenantFederationOIDCCreateDocument()
	valid["unexpected"] = true
	request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(mustJSON(t, valid)))
	request.Header.Set("Content-Type", "application/json")
	if _, err := decodeTenantFederationCreateBody(request); err == nil {
		t.Fatal("unknown create field was accepted")
	}

	request = httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(`{"clientSecret":"first","reason":"approved","clientSecret":"second"}`))
	request.Header.Set("Content-Type", "application/json")
	secret, _, err := decodeTenantFederationOIDCSecretBody(request)
	clear(secret)
	if err == nil {
		t.Fatal("duplicate secret field was accepted")
	}

	document := `{"clientSecret":"` + string(bytes.Repeat([]byte{'x'}, 8193)) + `","reason":"approved"}`
	request = httptest.NewRequest(http.MethodPut, "/", bytes.NewBufferString(document))
	request.Header.Set("Content-Type", "application/json")
	secret, _, err = decodeTenantFederationOIDCSecretBody(request)
	clear(secret)
	if err == nil {
		t.Fatal("oversize secret was accepted")
	}
}

func TestTenantFederationSAMLDurationBoundsAreCheckedBeforeConversion(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	providerID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	service := &transportTenantFederationStub{
		create: func(context.Context, authorization.Actor, uuid.UUID, identityprovider.FederationCreateInput) (identityprovider.FederationCreateResult, error) {
			t.Fatal("invalid SAML create reached the service")
			return identityprovider.FederationCreateResult{}, nil
		},
		update: func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FederationUpdateInput) (identityprovider.FederationProvider, error) {
			t.Fatal("invalid SAML update reached the service")
			return identityprovider.FederationProvider{}, nil
		},
	}
	router := newTenantFederationTestRouter(t, tenantFederationHTTPAuthentication(tenantID, userID), service)
	base := "/api/v1/tenants/" + tenantID.String() + "/federated-auth-providers"
	const wrapsToSixtySeconds = int64(1<<55) + 60
	const wrapsToTwoMinutes = int64(1<<55) + 120
	tests := []struct {
		name   string
		field  string
		value  int64
		update bool
	}{
		{name: "create clock above maximum", field: "clockSkewSeconds", value: 301},
		{name: "create maximum age above maximum", field: "maxAuthenticationAgeSeconds", value: 86_401},
		{name: "create maximum age duration overflow", field: "maxAuthenticationAgeSeconds", value: wrapsToSixtySeconds},
		{name: "update clock above maximum", field: "clockSkewSeconds", value: 301, update: true},
		{name: "update maximum age above maximum", field: "maxAuthenticationAgeSeconds", value: 86_401, update: true},
		{name: "update clock duration overflow", field: "clockSkewSeconds", value: wrapsToTwoMinutes, update: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := tenantFederationSAMLCreateDocument()
			document["configuration"].(map[string]any)[test.field] = test.value
			if test.update {
				delete(document, "key")
				delete(document, "loginKey")
				document["enabled"] = false
			}
			method, path := http.MethodPost, base
			if test.update {
				method, path = http.MethodPut, base+"/"+providerID.String()
			}
			request := httptest.NewRequest(method, path, bytes.NewReader(mustJSON(t, document)))
			prepareTenantLDAPTransportRequest(request, true)
			request.Header.Set("Content-Type", "application/json")
			if test.update {
				request.Header.Set("If-Match", `"v4"`)
			} else {
				request.Header.Set("Idempotency-Key", "tenant-federation-invalid-duration")
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
		})
	}
}

type transportTenantFederationStub struct {
	list             func(context.Context, authorization.Actor, uuid.UUID, identityprovider.FederationListInput) (identityprovider.FederationProviderPage, error)
	get              func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (identityprovider.FederationProvider, error)
	create           func(context.Context, authorization.Actor, uuid.UUID, identityprovider.FederationCreateInput) (identityprovider.FederationCreateResult, error)
	update           func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FederationUpdateInput) (identityprovider.FederationProvider, error)
	archive          func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FederationArchiveInput) (int64, error)
	replace          func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FederationReplaceOIDCSecretInput) (identityprovider.FederationSecretMutationReceipt, error)
	clear            func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FederationClearOIDCSecretInput) (identityprovider.FederationSecretMutationReceipt, error)
	refreshTrust     func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FederationOIDCTrustDocumentsInput) (identityprovider.FederationOIDCTrustDocumentsReceipt, error)
	getMapping       func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (identityprovider.FederationMappingPolicy, error)
	replaceMapping   func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FederationReplaceMappingPolicyInput) (identityprovider.FederationPolicyMutationReceipt, error)
	getAssurance     func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (identityprovider.FederationAssurancePolicy, error)
	replaceAssurance func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FederationReplaceAssurancePolicyInput) (identityprovider.FederationPolicyMutationReceipt, error)
}

func (stub *transportTenantFederationStub) List(ctx context.Context, actor authorization.Actor, tenantID uuid.UUID, input identityprovider.FederationListInput) (identityprovider.FederationProviderPage, error) {
	return stub.list(ctx, actor, tenantID, input)
}
func (stub *transportTenantFederationStub) Get(ctx context.Context, actor authorization.Actor, tenantID, providerID uuid.UUID) (identityprovider.FederationProvider, error) {
	return stub.get(ctx, actor, tenantID, providerID)
}
func (stub *transportTenantFederationStub) Create(ctx context.Context, actor authorization.Actor, tenantID uuid.UUID, input identityprovider.FederationCreateInput) (identityprovider.FederationCreateResult, error) {
	return stub.create(ctx, actor, tenantID, input)
}
func (stub *transportTenantFederationStub) Update(ctx context.Context, actor authorization.Actor, tenantID, providerID uuid.UUID, input identityprovider.FederationUpdateInput) (identityprovider.FederationProvider, error) {
	return stub.update(ctx, actor, tenantID, providerID, input)
}
func (stub *transportTenantFederationStub) Archive(ctx context.Context, actor authorization.Actor, tenantID, providerID uuid.UUID, input identityprovider.FederationArchiveInput) (int64, error) {
	return stub.archive(ctx, actor, tenantID, providerID, input)
}
func (stub *transportTenantFederationStub) ReplaceOIDCClientSecret(ctx context.Context, actor authorization.Actor, tenantID, providerID uuid.UUID, input identityprovider.FederationReplaceOIDCSecretInput) (identityprovider.FederationSecretMutationReceipt, error) {
	return stub.replace(ctx, actor, tenantID, providerID, input)
}
func (stub *transportTenantFederationStub) ClearOIDCClientSecret(ctx context.Context, actor authorization.Actor, tenantID, providerID uuid.UUID, input identityprovider.FederationClearOIDCSecretInput) (identityprovider.FederationSecretMutationReceipt, error) {
	return stub.clear(ctx, actor, tenantID, providerID, input)
}
func (stub *transportTenantFederationStub) RefreshOIDCTrustDocuments(ctx context.Context, actor authorization.Actor, tenantID, providerID uuid.UUID, input identityprovider.FederationOIDCTrustDocumentsInput) (identityprovider.FederationOIDCTrustDocumentsReceipt, error) {
	return stub.refreshTrust(ctx, actor, tenantID, providerID, input)
}
func (stub *transportTenantFederationStub) GetMappingPolicy(ctx context.Context, actor authorization.Actor, tenantID, providerID uuid.UUID) (identityprovider.FederationMappingPolicy, error) {
	return stub.getMapping(ctx, actor, tenantID, providerID)
}
func (stub *transportTenantFederationStub) ReplaceMappingPolicy(ctx context.Context, actor authorization.Actor, tenantID, providerID uuid.UUID, input identityprovider.FederationReplaceMappingPolicyInput) (identityprovider.FederationPolicyMutationReceipt, error) {
	return stub.replaceMapping(ctx, actor, tenantID, providerID, input)
}
func (stub *transportTenantFederationStub) GetAssurancePolicy(ctx context.Context, actor authorization.Actor, tenantID, providerID uuid.UUID) (identityprovider.FederationAssurancePolicy, error) {
	return stub.getAssurance(ctx, actor, tenantID, providerID)
}
func (stub *transportTenantFederationStub) ReplaceAssurancePolicy(ctx context.Context, actor authorization.Actor, tenantID, providerID uuid.UUID, input identityprovider.FederationReplaceAssurancePolicyInput) (identityprovider.FederationPolicyMutationReceipt, error) {
	return stub.replaceAssurance(ctx, actor, tenantID, providerID, input)
}

func newTenantFederationTestRouter(t *testing.T, auth AuthenticationService, service TenantFederationAdministrationService) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, logger, "test", time.Second,
		ApplicationOptions{
			Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: auth, Authorization: &transportAuthorizationStub{},
			Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{},
			Environment: "test", IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{},
			MFA: &transportMFAStub{}, Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{},
			Platform: &transportPlatformStub{}, PublicOrigin: "http://localhost:8081", TenantFederation: service,
			ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{}, Ticketing: &transportTicketingStub{}, WorkflowAdministration: &transportWorkflowAdministrationStub{},
		},
	)
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}

func tenantFederationHTTPAuthentication(tenantID, userID uuid.UUID) *transportAuthStub {
	return &transportAuthStub{authenticateResult: authentication.Session{
		ID: uuid.Must(uuid.NewV7()), User: authentication.User{ID: userID}, ActiveTenantID: &tenantID,
		AuthenticationMethod: "totp",
	}}
}

func tenantFederationHTTPProvider(tenantID, providerID, bindingID uuid.UUID) identityprovider.FederationProvider {
	now := time.Now().UTC().Truncate(time.Millisecond)
	return identityprovider.FederationProvider{
		FederationProviderSummary: identityprovider.FederationProviderSummary{
			ID: providerID, TenantID: tenantID, Key: "workforce_oidc", DisplayName: "Workforce SSO",
			Description: "Tenant workforce", Kind: identityprovider.FederationProviderOIDC, Enabled: false, Configured: true,
			Binding: identityprovider.FederationBinding{ID: bindingID, LoginKey: "workforce", Version: 4, UpdatedAt: now},
			Version: 4, CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
		},
		ConfigurationRevision: 2, SecurityRevision: 2, PlanRevision: 1, AssurancePolicyRevision: 1,
		JITMode: identityprovider.JITModeDisabled, NoMatchPolicy: identityprovider.NoMatchPolicyDeny,
		OIDC: &identityprovider.FederationOIDCConfiguration{
			Issuer: "https://id.example.com", ClientID: "periapsis-tenant",
			RedirectURI:           "https://soc.example.com/api/v1/auth/federated/oidc/callback",
			PostLogoutRedirectURI: "https://soc.example.com/signed-out", ExtraScopes: []string{"email", "profile"},
			AllowRefreshToken: true, ClientSecretPresent: true, ClientSecretRevision: 2,
			DiscoveryRevision: 2, JWKSRevision: 2,
		},
	}
}

func tenantFederationOIDCCreateDocument() map[string]any {
	return map[string]any{
		"kind": "oidc", "key": "workforce_oidc", "loginKey": "workforce", "displayName": "Workforce SSO",
		"description": "Tenant workforce", "jitMode": "disabled", "noMatchPolicy": "deny", "reason": "approved change",
		"configuration": map[string]any{
			"issuer": "https://id.example.com", "clientId": "periapsis-tenant",
			"postLogoutRedirectUri": "https://soc.example.com/signed-out", "extraScopes": []string{"email", "profile"},
			"allowRefreshToken": true, "useUserInfo": false,
		},
	}
}

func tenantFederationOIDCUpdateDocument() map[string]any {
	value := tenantFederationOIDCCreateDocument()
	delete(value, "key")
	delete(value, "loginKey")
	value["enabled"] = true
	return value
}

func tenantFederationSAMLCreateDocument() map[string]any {
	return map[string]any{
		"kind": "saml", "key": "workforce_saml", "loginKey": "workforce", "displayName": "Workforce SAML",
		"description": "Tenant workforce", "jitMode": "disabled", "noMatchPolicy": "deny", "reason": "approved change",
		"configuration": map[string]any{
			"expectedEntityId":           "https://id.example.com/saml/metadata",
			"redirectSignatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
			"signaturePolicy":            "both", "encryptionPolicy": "disabled",
			"requestedAuthnContexts": []string{"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"},
			"subjectSource":          "persistent_nameid", "subjectAttributeName": nil, "subjectAttributeNameFormat": nil,
			"clockSkewSeconds": 120, "maxAuthenticationAgeSeconds": 3600,
		},
	}
}

func tenantFederationOIDCMappingDocument(ruleID, groupID, roleID uuid.UUID) map[string]any {
	return map[string]any{
		"kind": "oidc",
		"oidcClaimRules": []map[string]any{
			{"source": "id_token", "kind": "profile", "claimName": "preferred_username", "profileField": "username", "required": true},
			{"source": "id_token", "kind": "groups", "claimName": "roles", "required": false},
			{"source": "id_token", "kind": "amr", "claimName": "amr", "required": false},
		},
		"rules": []map[string]any{{
			"ruleId": ruleID, "priority": 10, "matcherKind": "group_equals", "matcherValue": "analyst",
			"reconciliationMode": "authoritative", "tenantSecurityGroupId": groupID,
			"roleIds": []uuid.UUID{roleID}, "enabled": true,
		}},
		"reason": "replace mapping",
	}
}

func tenantFederationHTTPMappingPolicy(tenantID, providerID, ruleID, groupID, roleID uuid.UUID) identityprovider.FederationMappingPolicy {
	username := "username"
	return identityprovider.FederationMappingPolicy{
		TenantID: tenantID, ProviderID: providerID, Kind: identityprovider.FederationProviderOIDC,
		ProviderVersion: 4, MappingRevision: 1,
		OIDCClaimRules: []identityprovider.FederationOIDCClaimRule{
			{Source: "id_token", Kind: "profile", ClaimName: "preferred_username", ProfileField: &username, Required: true},
			{Source: "id_token", Kind: "groups", ClaimName: "roles"},
			{Source: "id_token", Kind: "amr", ClaimName: "amr"},
		},
		Rules: []identityprovider.FederationMappingRule{{
			RuleID: ruleID, Priority: 10, MatcherKind: "group_equals", MatcherValue: "analyst",
			ReconciliationMode: "authoritative", TenantSecurityGroupID: groupID,
			RoleIDs: []uuid.UUID{roleID}, Enabled: true,
		}},
	}
}

func tenantFederationOIDCAssuranceDocument(ruleID uuid.UUID) map[string]any {
	return map[string]any{
		"kind": "oidc",
		"rules": []map[string]any{{
			"ruleId": ruleID, "enabled": true, "level": "mfa", "exactValue": nil,
			"requiredValues": []string{"otp", "pwd"}, "maximumAuthenticationAgeSeconds": 3600,
		}},
		"reason": "replace assurance",
	}
}

func tenantFederationHTTPAssurancePolicy(tenantID, providerID, ruleID uuid.UUID) identityprovider.FederationAssurancePolicy {
	return identityprovider.FederationAssurancePolicy{
		TenantID: tenantID, ProviderID: providerID, Kind: identityprovider.FederationProviderOIDC,
		ProviderVersion: 4, AssurancePolicyRevision: 1,
		Rules: []identityprovider.FederationAssuranceRule{{
			RuleID: ruleID, Enabled: true, Level: "mfa", RequiredValues: []string{"otp", "pwd"},
			MaximumAuthenticationAgeSeconds: 3600,
		}},
	}
}

func assertTenantFederationResponseHasNoRawMaterial(t *testing.T, value any) {
	t.Helper()
	forbidden := map[string]struct{}{
		"clientSecret": {}, "ciphertext": {}, "privateKey": {}, "assertion": {}, "claims": {}, "token": {},
	}
	var visit func(any)
	visit = func(current any) {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				if _, denied := forbidden[key]; denied {
					t.Fatalf("raw material field %q was exposed", key)
				}
				visit(child)
			}
		case []any:
			for _, child := range typed {
				visit(child)
			}
		}
	}
	visit(value)
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	return document
}
