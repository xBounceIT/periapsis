package httpserver

import (
	"context"
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

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/platformidentityprovider"
)

type platformIdentityProviderHTTPStub struct {
	listCalls                int
	listInput                platformidentityprovider.ListInput
	listResult               platformidentityprovider.ProviderPage
	listError                error
	getCalls                 int
	getProviderID            uuid.UUID
	getResult                platformidentityprovider.Provider
	getError                 error
	createCalls              int
	createInput              platformidentityprovider.CreateInput
	createResult             platformidentityprovider.CreateResult
	createError              error
	updateCalls              int
	updateInput              platformidentityprovider.UpdateInput
	updateResult             platformidentityprovider.UpdateResult
	updateError              error
	archiveCalls             int
	archiveInput             platformidentityprovider.ArchiveInput
	archiveResult            platformidentityprovider.MutationReceipt
	archiveError             error
	secretCalls              int
	secretInput              platformidentityprovider.ReplaceOIDCClientSecretInput
	secretResult             platformidentityprovider.SecretMutationReceipt
	secretError              error
	samlMetadataCalls        int
	samlMetadataProvider     uuid.UUID
	samlMetadataInput        platformidentityprovider.ReplaceSAMLMetadataInput
	samlMetadataBuffer       []byte
	samlMetadataResult       platformidentityprovider.SAMLMaterialMutationReceipt
	samlMetadataError        error
	samlSPKeyCalls           int
	samlSPKeyProvider        uuid.UUID
	samlSPKeyInput           platformidentityprovider.ReplaceSAMLSPKeyInput
	samlSPKeyPrivateBuffer   []byte
	samlSPKeyCertBuffers     [][]byte
	samlSPKeyResult          platformidentityprovider.SAMLMaterialMutationReceipt
	samlSPKeyError           error
	samlSPKeyClearCalls      int
	samlSPKeyClearProvider   uuid.UUID
	samlSPKeyClearInput      platformidentityprovider.ClearSAMLSPKeyInput
	samlSPKeyClearResult     platformidentityprovider.SAMLMaterialMutationReceipt
	samlSPKeyClearError      error
	activateCalls            int
	activateProvider         uuid.UUID
	activateInput            platformidentityprovider.ActivateInput
	activateResult           platformidentityprovider.UpdateResult
	activateError            error
	deactivateCalls          int
	deactivateProvider       uuid.UUID
	deactivateInput          platformidentityprovider.DeactivateInput
	deactivateResult         platformidentityprovider.UpdateResult
	deactivateError          error
	directActivateCalls      int
	directActivateProvider   uuid.UUID
	directActivateInput      platformidentityprovider.DirectLoginInput
	directActivateResult     platformidentityprovider.UpdateResult
	directActivateError      error
	directDeactivateCalls    int
	directDeactivateProvider uuid.UUID
	directDeactivateInput    platformidentityprovider.DirectLoginInput
	directDeactivateResult   platformidentityprovider.UpdateResult
	directDeactivateError    error
}

func (stub *platformIdentityProviderHTTPStub) List(
	_ context.Context,
	_ authentication.Session,
	input platformidentityprovider.ListInput,
) (platformidentityprovider.ProviderPage, error) {
	stub.listCalls++
	stub.listInput = input
	return stub.listResult, stub.listError
}

func (stub *platformIdentityProviderHTTPStub) Get(
	_ context.Context,
	_ authentication.Session,
	providerID uuid.UUID,
) (platformidentityprovider.Provider, error) {
	stub.getCalls++
	stub.getProviderID = providerID
	return stub.getResult, stub.getError
}

func (stub *platformIdentityProviderHTTPStub) Create(
	_ context.Context,
	_ authentication.Session,
	input platformidentityprovider.CreateInput,
) (platformidentityprovider.CreateResult, error) {
	stub.createCalls++
	stub.createInput = input
	return stub.createResult, stub.createError
}

func (stub *platformIdentityProviderHTTPStub) Update(
	_ context.Context,
	_ authentication.Session,
	_ uuid.UUID,
	input platformidentityprovider.UpdateInput,
) (platformidentityprovider.UpdateResult, error) {
	stub.updateCalls++
	stub.updateInput = input
	return stub.updateResult, stub.updateError
}

func (stub *platformIdentityProviderHTTPStub) Archive(
	_ context.Context,
	_ authentication.Session,
	_ uuid.UUID,
	input platformidentityprovider.ArchiveInput,
) (platformidentityprovider.MutationReceipt, error) {
	stub.archiveCalls++
	stub.archiveInput = input
	return stub.archiveResult, stub.archiveError
}

func (stub *platformIdentityProviderHTTPStub) ReplaceOIDCClientSecret(
	_ context.Context,
	_ authentication.Session,
	_ uuid.UUID,
	input platformidentityprovider.ReplaceOIDCClientSecretInput,
) (platformidentityprovider.SecretMutationReceipt, error) {
	stub.secretCalls++
	stub.secretInput = input
	stub.secretInput.Secret = append([]byte(nil), input.Secret...)
	return stub.secretResult, stub.secretError
}

func (stub *platformIdentityProviderHTTPStub) ReplaceSAMLMetadata(
	_ context.Context,
	_ authentication.Session,
	providerID uuid.UUID,
	input platformidentityprovider.ReplaceSAMLMetadataInput,
) (platformidentityprovider.SAMLMaterialMutationReceipt, error) {
	stub.samlMetadataCalls++
	stub.samlMetadataProvider = providerID
	stub.samlMetadataBuffer = input.MetadataXML
	stub.samlMetadataInput = input
	stub.samlMetadataInput.MetadataXML = append([]byte(nil), input.MetadataXML...)
	return stub.samlMetadataResult, stub.samlMetadataError
}

func (stub *platformIdentityProviderHTTPStub) ReplaceSAMLSPKey(
	_ context.Context,
	_ authentication.Session,
	providerID uuid.UUID,
	input platformidentityprovider.ReplaceSAMLSPKeyInput,
) (platformidentityprovider.SAMLMaterialMutationReceipt, error) {
	stub.samlSPKeyCalls++
	stub.samlSPKeyProvider = providerID
	stub.samlSPKeyPrivateBuffer = input.PrivateKeyPKCS8
	stub.samlSPKeyCertBuffers = append([][]byte(nil), input.CertificateDER...)
	stub.samlSPKeyInput = input
	stub.samlSPKeyInput.PrivateKeyPKCS8 = append([]byte(nil), input.PrivateKeyPKCS8...)
	stub.samlSPKeyInput.CertificateDER = make([][]byte, len(input.CertificateDER))
	for index := range input.CertificateDER {
		stub.samlSPKeyInput.CertificateDER[index] = append([]byte(nil), input.CertificateDER[index]...)
	}
	return stub.samlSPKeyResult, stub.samlSPKeyError
}

func (stub *platformIdentityProviderHTTPStub) ClearSAMLSPKey(
	_ context.Context,
	_ authentication.Session,
	providerID uuid.UUID,
	input platformidentityprovider.ClearSAMLSPKeyInput,
) (platformidentityprovider.SAMLMaterialMutationReceipt, error) {
	stub.samlSPKeyClearCalls++
	stub.samlSPKeyClearProvider = providerID
	stub.samlSPKeyClearInput = input
	return stub.samlSPKeyClearResult, stub.samlSPKeyClearError
}

func (stub *platformIdentityProviderHTTPStub) Activate(
	_ context.Context,
	_ authentication.Session,
	providerID uuid.UUID,
	input platformidentityprovider.ActivateInput,
) (platformidentityprovider.UpdateResult, error) {
	stub.activateCalls++
	stub.activateProvider = providerID
	stub.activateInput = input
	return stub.activateResult, stub.activateError
}

func (stub *platformIdentityProviderHTTPStub) Deactivate(
	_ context.Context,
	_ authentication.Session,
	providerID uuid.UUID,
	input platformidentityprovider.DeactivateInput,
) (platformidentityprovider.UpdateResult, error) {
	stub.deactivateCalls++
	stub.deactivateProvider = providerID
	stub.deactivateInput = input
	return stub.deactivateResult, stub.deactivateError
}

func (stub *platformIdentityProviderHTTPStub) ActivateDirectLogin(
	_ context.Context,
	_ authentication.Session,
	providerID uuid.UUID,
	input platformidentityprovider.DirectLoginInput,
) (platformidentityprovider.UpdateResult, error) {
	stub.directActivateCalls++
	stub.directActivateProvider = providerID
	stub.directActivateInput = input
	return stub.directActivateResult, stub.directActivateError
}

func (stub *platformIdentityProviderHTTPStub) DeactivateDirectLogin(
	_ context.Context,
	_ authentication.Session,
	providerID uuid.UUID,
	input platformidentityprovider.DirectLoginInput,
) (platformidentityprovider.UpdateResult, error) {
	stub.directDeactivateCalls++
	stub.directDeactivateProvider = providerID
	stub.directDeactivateInput = input
	return stub.directDeactivateResult, stub.directDeactivateError
}

func TestPlatformIdentityProviderCreateReturnsCurrentSafeProjection(t *testing.T) {
	provider := platformOIDCHTTPProvider(t, 1, false)
	result, err := platformidentityprovider.RestoreCreateResult(
		platformidentityprovider.CreateResultInput{
			ProviderID: provider.ID, Version: 1, Provider: provider,
		},
	)
	if err != nil {
		t.Fatalf("RestoreCreateResult() error = %v", err)
	}
	service := &platformIdentityProviderHTTPStub{createResult: result}
	router := newPlatformIdentityProviderTestRouter(t, service)

	request := platformIdentityProviderMutationRequest(
		http.MethodPost,
		"/api/v1/platform/auth-providers",
		`{"kind":"oidc","key":"corp_oidc","displayName":"Corporate OIDC","configuration":{"issuer":"https://id.example.test","clientId":"periapsis","redirectUri":"https://app.example.test/api/v1/auth/platform/oidc/callback","tenantRedirectUri":"https://app.example.test/api/v1/auth/federated/oidc/callback","postLogoutRedirectUri":"https://app.example.test/signed-out","extraScopes":["email"],"allowRefreshToken":false,"useUserInfo":true}}`,
	)
	request.Header.Set(idempotencyKeyHeader, "create-corp-oidc-01")
	request.Header.Set("X-Audit-Reason", "Provision corporate SSO")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"v1"` ||
		response.Header().Get("Location") != platformAuthProviderLocation(provider.ID) ||
		!strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("create response = %d, headers=%#v, body=%s", response.Code, response.Header(), response.Body.String())
	}
	if service.listCalls != 0 || service.createCalls != 1 || service.getCalls != 0 {
		t.Fatalf("calls list/create/get = %d/%d/%d", service.listCalls, service.createCalls, service.getCalls)
	}
	if service.createInput.Reason != "Provision corporate SSO" ||
		service.createInput.IdempotencyKey != "create-corp-oidc-01" {
		t.Fatalf("create input = %#v", service.createInput)
	}
	configuration, ok := service.createInput.Configuration.(platformidentityprovider.OIDCCreateConfiguration)
	if !ok || configuration.ClientID != "periapsis" || len(configuration.ExtraScopes) != 1 {
		t.Fatalf("create configuration = %#v", service.createInput.Configuration)
	}
	if strings.Contains(response.Body.String(), `"clientSecret":`) {
		t.Fatalf("safe response contains secret field: %s", response.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body["enabled"] != false ||
		body["platformLoginEnabled"] != false || body["platformLoginActivationAvailable"] != false {
		t.Fatalf("safe body = %#v, error=%v", body, err)
	}
}

func TestPlatformIdentityProviderCreateReplayUsesCurrentProjectionVersionWithoutSeparateRead(t *testing.T) {
	provider := platformOIDCHTTPProvider(t, 5, true)
	result, err := platformidentityprovider.RestoreCreateResult(
		platformidentityprovider.CreateResultInput{
			ProviderID: provider.ID, Version: 1, Replayed: true, Provider: provider,
		},
	)
	if err != nil {
		t.Fatalf("RestoreCreateResult() error = %v", err)
	}
	service := &platformIdentityProviderHTTPStub{createResult: result}
	router := newPlatformIdentityProviderTestRouter(t, service)
	request := platformIdentityProviderMutationRequest(
		http.MethodPost,
		"/api/v1/platform/auth-providers",
		`{"kind":"oidc","key":"corp_oidc","displayName":"Corporate OIDC","configuration":{"issuer":"https://id.example.test","clientId":"periapsis","redirectUri":"https://app.example.test/api/v1/auth/platform/oidc/callback","tenantRedirectUri":"https://app.example.test/api/v1/auth/federated/oidc/callback","postLogoutRedirectUri":"https://app.example.test/signed-out","extraScopes":["email"],"allowRefreshToken":false,"useUserInfo":true}}`,
	)
	request.Header.Set(idempotencyKeyHeader, "create-corp-oidc-01")
	request.Header.Set("X-Audit-Reason", "Provision corporate SSO")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusCreated || response.Header().Get("ETag") != `"v5"` ||
		service.createCalls != 1 || service.listCalls != 0 || service.getCalls != 0 {
		t.Fatalf(
			"replay response=%d ETag=%q calls list/create/get=%d/%d/%d body=%s",
			response.Code, response.Header().Get("ETag"), service.listCalls, service.createCalls,
			service.getCalls, response.Body.String(),
		)
	}
}

func TestPlatformIdentityProviderUpdateRejectsVersionMismatchBeforeMutation(t *testing.T) {
	provider := platformOIDCHTTPProvider(t, 5, false)
	service := &platformIdentityProviderHTTPStub{getResult: provider}
	router := newPlatformIdentityProviderTestRouter(t, service)
	request := platformIdentityProviderMutationRequest(
		http.MethodPut,
		platformAuthProviderLocation(provider.ID),
		`{"key":"corp_oidc","displayName":"Corporate OIDC","description":"updated","expectedVersion":6}`,
	)
	request.Header.Set(ifMatchHeader, `"v5"`)
	request.Header.Set("X-Audit-Reason", "Correct display metadata")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || service.getCalls != 0 || service.updateCalls != 0 {
		t.Fatalf("mismatch response=%d get/update=%d/%d body=%s", response.Code, service.getCalls, service.updateCalls, response.Body.String())
	}
	assertPlatformIdentityProviderProblem(t, response, "invalid_request")
}

func TestPlatformIdentityProviderMutationsRejectTerminalVersionBeforeServiceCall(t *testing.T) {
	provider := platformOIDCHTTPProvider(t, maximumResourceVersion, false)
	tests := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{
			name:   "metadata",
			method: http.MethodPut,
			path:   platformAuthProviderLocation(provider.ID),
			body:   `{"key":"corp_oidc","displayName":"Corporate OIDC","description":"updated","expectedVersion":2147483647}`,
		},
		{
			name:   "archive",
			method: http.MethodDelete,
			path:   platformAuthProviderLocation(provider.ID),
			body:   `{"expectedVersion":2147483647}`,
		},
		{
			name:   "oidc secret",
			method: http.MethodPut,
			path:   platformAuthProviderLocation(provider.ID) + "/oidc-client-secret",
			body:   `{"clientSecret":"write-only","expectedVersion":2147483647}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &platformIdentityProviderHTTPStub{}
			router := newPlatformIdentityProviderTestRouter(t, service)
			request := platformIdentityProviderMutationRequest(test.method, test.path, test.body)
			request.Header.Set(ifMatchHeader, `"v2147483647"`)
			request.Header.Set("X-Audit-Reason", "Reject terminal version")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest || service.updateCalls != 0 ||
				service.archiveCalls != 0 || service.secretCalls != 0 {
				t.Fatalf(
					"response=%d update/archive/secret=%d/%d/%d body=%s",
					response.Code, service.updateCalls, service.archiveCalls,
					service.secretCalls, response.Body.String(),
				)
			}
			assertPlatformIdentityProviderProblem(t, response, "invalid_request")
		})
	}
}

func TestPlatformIdentityProviderBodiesRejectExplicitNullBeforeServiceCall(t *testing.T) {
	providerID := uuid.Must(uuid.NewV7())
	oidcPrefix := `{"kind":"oidc","key":"corp_oidc","displayName":"Corporate OIDC",`
	oidcConfigurationPrefix := `"configuration":{"issuer":"https://id.example.test","clientId":"periapsis","redirectUri":"https://app.example.test/api/v1/auth/platform/oidc/callback","tenantRedirectUri":"https://app.example.test/api/v1/auth/federated/oidc/callback","postLogoutRedirectUri":"https://app.example.test/signed-out",`
	samlBase := `{"kind":"saml","key":"corp_saml","displayName":"Corporate SAML","configuration":{"expectedEntityId":"https://id.example.test/saml","spEntityId":"https://app.example.test/api/v1/auth/platform/saml/corp_saml/metadata","acsUrl":"https://app.example.test/api/v1/auth/platform/saml/acs","redirectSignatureAlgorithm":"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256","signaturePolicy":"both","encryptionPolicy":"disabled","requestedAuthnContexts":["urn:example:loa:2"],"subjectSource":"persistent_nameid","clockSkewNanoseconds":0,"maxAuthenticationAgeNanoseconds":3600000000000}}`
	tests := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{
			name: "create description null", method: http.MethodPost,
			path: "/api/v1/platform/auth-providers",
			body: oidcPrefix + `"description":null,` + oidcConfigurationPrefix + `"extraScopes":[],"allowRefreshToken":false,"useUserInfo":false}}`,
		},
		{
			name: "OIDC scopes null", method: http.MethodPost,
			path: "/api/v1/platform/auth-providers",
			body: oidcPrefix + oidcConfigurationPrefix + `"extraScopes":null,"allowRefreshToken":false,"useUserInfo":false}}`,
		},
		{
			name: "OIDC refresh flag null", method: http.MethodPost,
			path: "/api/v1/platform/auth-providers",
			body: oidcPrefix + oidcConfigurationPrefix + `"extraScopes":[],"allowRefreshToken":null,"useUserInfo":false}}`,
		},
		{
			name: "OIDC userinfo flag null", method: http.MethodPost,
			path: "/api/v1/platform/auth-providers",
			body: oidcPrefix + oidcConfigurationPrefix + `"extraScopes":[],"allowRefreshToken":false,"useUserInfo":null}}`,
		},
		{
			name: "SAML clock skew null", method: http.MethodPost,
			path: "/api/v1/platform/auth-providers",
			body: strings.Replace(samlBase, `"clockSkewNanoseconds":0`, `"clockSkewNanoseconds":null`, 1),
		},
		{
			name: "SAML forbidden persistent attribute null", method: http.MethodPost,
			path: "/api/v1/platform/auth-providers",
			body: strings.Replace(samlBase, `"clockSkewNanoseconds":0`, `"subjectAttributeName":null,"clockSkewNanoseconds":0`, 1),
		},
		{
			name: "SAML required immutable attribute null", method: http.MethodPost,
			path: "/api/v1/platform/auth-providers",
			body: strings.Replace(
				strings.Replace(samlBase, `"subjectSource":"persistent_nameid"`, `"subjectSource":"immutable_attribute","subjectAttributeName":null,"subjectAttributeNameFormat":"urn:example:format"`, 1),
				`"clockSkewNanoseconds":0`, `"clockSkewNanoseconds":0`, 1,
			),
		},
		{
			name: "update required description null", method: http.MethodPut,
			path: platformAuthProviderLocation(providerID),
			body: `{"key":"corp_oidc","displayName":"Corporate OIDC","description":null,"expectedVersion":1}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &platformIdentityProviderHTTPStub{}
			router := newPlatformIdentityProviderTestRouter(t, service)
			request := platformIdentityProviderMutationRequest(test.method, test.path, test.body)
			request.Header.Set("X-Audit-Reason", "Reject contract-invalid null")
			if test.method == http.MethodPost {
				request.Header.Set(idempotencyKeyHeader, "reject-null-create-01")
			} else {
				request.Header.Set(ifMatchHeader, `"v1"`)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest || service.createCalls != 0 ||
				service.updateCalls != 0 || service.archiveCalls != 0 || service.secretCalls != 0 {
				t.Fatalf(
					"response=%d create/update/archive/secret=%d/%d/%d/%d body=%s",
					response.Code, service.createCalls, service.updateCalls,
					service.archiveCalls, service.secretCalls, response.Body.String(),
				)
			}
			assertPlatformIdentityProviderProblem(t, response, "invalid_request")
		})
	}
}

func TestPlatformIdentityProviderAuditReasonRejectsNonTransportValuesBeforeServiceCall(t *testing.T) {
	for _, reason := range []string{"Motivazione approvata — SSO", "one,two"} {
		t.Run(reason, func(t *testing.T) {
			service := &platformIdentityProviderHTTPStub{}
			router := newPlatformIdentityProviderTestRouter(t, service)
			request := platformIdentityProviderMutationRequest(
				http.MethodPost,
				"/api/v1/platform/auth-providers",
				`{"kind":"oidc","key":"corp_oidc","displayName":"Corporate OIDC","configuration":{"issuer":"https://id.example.test","clientId":"periapsis","redirectUri":"https://app.example.test/api/v1/auth/platform/oidc/callback","tenantRedirectUri":"https://app.example.test/api/v1/auth/federated/oidc/callback","postLogoutRedirectUri":"https://app.example.test/signed-out","extraScopes":[],"allowRefreshToken":false,"useUserInfo":false}}`,
			)
			request.Header.Set(idempotencyKeyHeader, "reject-audit-reason-01")
			request.Header["X-Audit-Reason"] = []string{reason}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest || service.createCalls != 0 {
				t.Fatalf("response=%d calls=%d body=%s", response.Code, service.createCalls, response.Body.String())
			}
			assertPlatformIdentityProviderProblem(t, response, "invalid_request")
		})
	}
}

func TestPlatformIdentityProviderMapsCASSeparatelyFromStateConflict(t *testing.T) {
	provider := platformOIDCHTTPProvider(t, 5, false)
	service := &platformIdentityProviderHTTPStub{updateError: platformidentityprovider.ErrPreconditionFailed}
	router := newPlatformIdentityProviderTestRouter(t, service)
	request := platformIdentityProviderMutationRequest(
		http.MethodPut,
		platformAuthProviderLocation(provider.ID),
		`{"key":"corp_oidc","displayName":"Corporate OIDC","description":"updated","expectedVersion":5}`,
	)
	request.Header.Set(ifMatchHeader, `"v5"`)
	request.Header.Set("X-Audit-Reason", "Correct display metadata")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusPreconditionFailed || service.getCalls != 0 || service.updateCalls != 1 {
		t.Fatalf("CAS response=%d get/update=%d/%d body=%s", response.Code, service.getCalls, service.updateCalls, response.Body.String())
	}
	assertPlatformIdentityProviderProblem(t, response, "precondition_failed")

	service = &platformIdentityProviderHTTPStub{updateError: authentication.ErrConflict}
	router = newPlatformIdentityProviderTestRouter(t, service)
	request = platformIdentityProviderMutationRequest(
		http.MethodPut,
		platformAuthProviderLocation(provider.ID),
		`{"key":"corp_oidc","displayName":"Corporate OIDC","description":"updated","expectedVersion":5}`,
	)
	request.Header.Set(ifMatchHeader, `"v5"`)
	request.Header.Set("X-Audit-Reason", "Correct display metadata")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("state conflict response=%d body=%s", response.Code, response.Body.String())
	}
}

func TestPlatformIdentityProviderUpdateUsesTransactionalProjectionWithoutSeparateReads(t *testing.T) {
	provider := platformOIDCHTTPProvider(t, 6, false)
	provider.Description = "updated"
	result, err := platformidentityprovider.RestoreUpdateResult(
		platformidentityprovider.UpdateResultInput{
			ProviderID: provider.ID, Version: provider.Version, Provider: provider,
		},
	)
	if err != nil {
		t.Fatalf("RestoreUpdateResult() error = %v", err)
	}
	service := &platformIdentityProviderHTTPStub{updateResult: result}
	router := newPlatformIdentityProviderTestRouter(t, service)
	request := platformIdentityProviderMutationRequest(
		http.MethodPut,
		platformAuthProviderLocation(provider.ID),
		`{"key":"corp_oidc","displayName":"Corporate OIDC","description":"updated","expectedVersion":5}`,
	)
	request.Header.Set(ifMatchHeader, `"v5"`)
	request.Header.Set("X-Audit-Reason", "Correct display metadata")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"v6"` ||
		service.updateCalls != 1 || service.getCalls != 0 || service.listCalls != 0 {
		t.Fatalf(
			"update response=%d ETag=%q calls list/update/get=%d/%d/%d body=%s",
			response.Code, response.Header().Get("ETag"), service.listCalls, service.updateCalls,
			service.getCalls, response.Body.String(),
		)
	}
}

func TestPlatformIdentityProviderContextErrorsAreHandledDeliberately(t *testing.T) {
	handler := &Handler{}

	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()
	canceledRequest := httptest.NewRequest(http.MethodGet, "/api/v1/platform/auth-providers", nil).
		WithContext(canceledContext)
	canceledResponse := httptest.NewRecorder()
	handler.writePlatformIdentityProviderError(canceledResponse, canceledRequest, context.Canceled)
	if canceledResponse.Body.Len() != 0 || len(canceledResponse.Header()) != 0 {
		t.Fatalf("canceled request wrote response: headers=%#v body=%q", canceledResponse.Header(), canceledResponse.Body.String())
	}

	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "detached cancellation", err: context.Canceled},
		{name: "deadline", err: context.DeadlineExceeded},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/v1/platform/auth-providers", nil)
			response := httptest.NewRecorder()
			handler.writePlatformIdentityProviderError(response, request, test.err)
			if response.Code != http.StatusServiceUnavailable || response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("response=%d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
			}
			assertPlatformIdentityProviderProblem(t, response, "service_unavailable")
		})
	}
}

func TestPlatformIdentityProviderNotFoundUsesTheDeclaredNonSecretProblem(t *testing.T) {
	handler := &Handler{}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/platform/auth-providers/missing", nil)
	response := httptest.NewRecorder()
	handler.writePlatformIdentityProviderError(response, request, authentication.ErrNotFound)
	if response.Code != http.StatusNotFound || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response=%d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
	assertPlatformIdentityProviderProblem(t, response, "not_found")
	if strings.Contains(response.Body.String(), "database") {
		t.Fatalf("not-found response leaked an internal diagnostic: %s", response.Body.String())
	}
}

func TestPlatformOIDCClientSecretIsWriteOnlyAndVersionBound(t *testing.T) {
	provider := platformOIDCHTTPProvider(t, 1, false)
	receipt, err := platformidentityprovider.RestoreSecretMutationReceipt(
		platformidentityprovider.SecretMutationReceiptInput{
			ProviderID: provider.ID, Version: 2, SecretRevision: 2,
		},
	)
	if err != nil {
		t.Fatalf("RestoreSecretMutationReceipt() error = %v", err)
	}
	service := &platformIdentityProviderHTTPStub{secretResult: receipt}
	router := newPlatformIdentityProviderTestRouter(t, service)
	request := platformIdentityProviderMutationRequest(
		http.MethodPut,
		platformAuthProviderLocation(provider.ID)+"/oidc-client-secret",
		`{"clientSecret":"never-return-this","expectedVersion":1}`,
	)
	request.Header.Set(ifMatchHeader, `"v1"`)
	request.Header.Set("X-Audit-Reason", "Rotate upstream credential")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent || response.Header().Get("ETag") != `"v2"` ||
		service.secretCalls != 1 || string(service.secretInput.Secret) != "never-return-this" ||
		service.secretInput.ExpectedEntityTag == nil || *service.secretInput.ExpectedEntityTag != `"v1"` {
		t.Fatalf("secret response=%d headers=%#v calls=%d input=%#v", response.Code, response.Header(), service.secretCalls, service.secretInput)
	}
	if response.Body.Len() != 0 || strings.Contains(response.Body.String(), "never-return-this") {
		t.Fatalf("secret response leaked material: %q", response.Body.String())
	}
}

func TestPlatformSAMLMetadataIsWriteOnlyVersionBoundAndRevisionExplicit(t *testing.T) {
	providerID := uuid.Must(uuid.NewV7())
	receipt, err := platformidentityprovider.RestoreSAMLMaterialMutationReceipt(
		platformidentityprovider.SAMLMaterialMutationReceiptInput{
			ProviderID: providerID, Version: 2, MaterialRevision: 2,
		},
	)
	if err != nil {
		t.Fatalf("RestoreSAMLMaterialMutationReceipt() error = %v", err)
	}
	service := &platformIdentityProviderHTTPStub{samlMetadataResult: receipt}
	router := newPlatformIdentityProviderTestRouter(t, service)
	metadata := `<EntityDescriptor entityID="https://idp.example.test">never-return-this</EntityDescriptor>`
	request := platformIdentityProviderMutationRequest(
		http.MethodPut,
		platformAuthProviderLocation(providerID)+"/saml/metadata",
		`{"source":"xml","expectedVersion":1,"metadataXml":`+mustJSONText(t, metadata)+`,"approveTrustReset":false}`,
	)
	request.Header.Set(ifMatchHeader, `"v1"`)
	request.Header.Set("X-Audit-Reason", "Stage reviewed IdP metadata")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent || response.Header().Get("ETag") != `"v2"` ||
		response.Header().Get("X-Periapsis-SAML-Material-Revision") != "2" ||
		response.Header().Get("Cache-Control") != "no-store" || service.samlMetadataCalls != 1 ||
		service.samlMetadataProvider != providerID || string(service.samlMetadataInput.MetadataXML) != metadata ||
		service.samlMetadataInput.MetadataURL != nil || service.samlMetadataInput.ApproveTrustReset ||
		service.samlMetadataInput.ExpectedEntityTag == nil || *service.samlMetadataInput.ExpectedEntityTag != `"v1"` ||
		service.samlMetadataInput.Reason != "Stage reviewed IdP metadata" {
		t.Fatalf("metadata response=%d headers=%#v input=%#v", response.Code, response.Header(), service.samlMetadataInput)
	}
	if response.Body.Len() != 0 || strings.Contains(response.Body.String(), "never-return-this") {
		t.Fatalf("metadata response leaked protected material: %q", response.Body.String())
	}
	if !allPlatformSAMLBytesCleared(service.samlMetadataBuffer) {
		t.Fatal("HTTP transport retained metadata XML after the service call")
	}
}

func TestPlatformSAMLMetadataURLCarriesExplicitProtectedApproval(t *testing.T) {
	providerID := uuid.Must(uuid.NewV7())
	receipt, err := platformidentityprovider.RestoreSAMLMaterialMutationReceipt(
		platformidentityprovider.SAMLMaterialMutationReceiptInput{
			ProviderID: providerID, Version: 8, MaterialRevision: 5,
		},
	)
	if err != nil {
		t.Fatalf("RestoreSAMLMaterialMutationReceipt() error = %v", err)
	}
	service := &platformIdentityProviderHTTPStub{samlMetadataResult: receipt}
	router := newPlatformIdentityProviderTestRouter(t, service)
	request := platformIdentityProviderMutationRequest(
		http.MethodPut,
		platformAuthProviderLocation(providerID)+"/saml/metadata",
		`{"approveTrustReset":true,"metadataUrl":"https://idp.example.test/metadata","expectedVersion":7,"source":"url"}`,
	)
	request.Header.Set(ifMatchHeader, `"v7"`)
	request.Header.Set("X-Audit-Reason", "Approve verified IdP trust rollover")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	input := service.samlMetadataInput
	if response.Code != http.StatusNoContent || service.samlMetadataCalls != 1 ||
		input.MetadataURL == nil || *input.MetadataURL != "https://idp.example.test/metadata" ||
		len(input.MetadataXML) != 0 || !input.ApproveTrustReset {
		t.Fatalf("metadata URL response=%d input=%#v body=%s", response.Code, input, response.Body.String())
	}
}

func TestPlatformSAMLSPKeyIsDecodedWriteOnlyClearedAndVersionBound(t *testing.T) {
	providerID := uuid.Must(uuid.NewV7())
	receipt, err := platformidentityprovider.RestoreSAMLMaterialMutationReceipt(
		platformidentityprovider.SAMLMaterialMutationReceiptInput{
			ProviderID: providerID, Version: 3, MaterialRevision: 9,
		},
	)
	if err != nil {
		t.Fatalf("RestoreSAMLMaterialMutationReceipt() error = %v", err)
	}
	service := &platformIdentityProviderHTTPStub{samlSPKeyResult: receipt}
	router := newPlatformIdentityProviderTestRouter(t, service)
	privateKey := []byte("private-key-material")
	certificate := []byte("certificate-material")
	request := platformIdentityProviderMutationRequest(
		http.MethodPut,
		platformAuthProviderLocation(providerID)+"/saml/sp-key",
		`{"certificates":["`+base64.StdEncoding.EncodeToString(certificate)+`"],"expectedVersion":2,"privateKeyPkcs8":"`+base64.StdEncoding.EncodeToString(privateKey)+`"}`,
	)
	request.Header.Set(ifMatchHeader, `"v2"`)
	request.Header.Set("X-Audit-Reason", "Rotate reviewed SAML signing key")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent || response.Header().Get("ETag") != `"v3"` ||
		response.Header().Get("X-Periapsis-SAML-Material-Revision") != "9" || service.samlSPKeyCalls != 1 ||
		service.samlSPKeyProvider != providerID || string(service.samlSPKeyInput.PrivateKeyPKCS8) != string(privateKey) ||
		len(service.samlSPKeyInput.CertificateDER) != 1 || string(service.samlSPKeyInput.CertificateDER[0]) != string(certificate) ||
		service.samlSPKeyInput.ExpectedEntityTag == nil || *service.samlSPKeyInput.ExpectedEntityTag != `"v2"` ||
		service.samlSPKeyInput.Reason != "Rotate reviewed SAML signing key" {
		t.Fatalf("SP-key response=%d headers=%#v input=%#v", response.Code, response.Header(), service.samlSPKeyInput)
	}
	if !allPlatformSAMLBytesCleared(service.samlSPKeyPrivateBuffer) ||
		len(service.samlSPKeyCertBuffers) != 1 || !allPlatformSAMLBytesCleared(service.samlSPKeyCertBuffers[0]) {
		t.Fatal("HTTP transport retained decoded SP-key material after the service call")
	}
	if response.Body.Len() != 0 || strings.Contains(response.Body.String(), base64.StdEncoding.EncodeToString(privateKey)) {
		t.Fatalf("SP-key response leaked protected material: %q", response.Body.String())
	}
}

func TestPlatformSAMLSPKeyClearIsAuditedAndAdvancesSemanticRevision(t *testing.T) {
	providerID := uuid.Must(uuid.NewV7())
	receipt, err := platformidentityprovider.RestoreSAMLMaterialMutationReceipt(
		platformidentityprovider.SAMLMaterialMutationReceiptInput{
			ProviderID: providerID, Version: 6, MaterialRevision: 12,
		},
	)
	if err != nil {
		t.Fatalf("RestoreSAMLMaterialMutationReceipt() error = %v", err)
	}
	service := &platformIdentityProviderHTTPStub{samlSPKeyClearResult: receipt}
	router := newPlatformIdentityProviderTestRouter(t, service)
	request := platformIdentityProviderMutationRequest(
		http.MethodDelete, platformAuthProviderLocation(providerID)+"/saml/sp-key",
		`{"expectedVersion":5}`,
	)
	request.Header.Set(ifMatchHeader, `"v5"`)
	request.Header.Set("X-Audit-Reason", "Retire compromised SAML signing key")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusNoContent || response.Header().Get("ETag") != `"v6"` ||
		response.Header().Get("X-Periapsis-SAML-Material-Revision") != "12" ||
		service.samlSPKeyClearCalls != 1 || service.samlSPKeyClearProvider != providerID ||
		service.samlSPKeyClearInput.ExpectedEntityTag == nil || *service.samlSPKeyClearInput.ExpectedEntityTag != `"v5"` ||
		service.samlSPKeyClearInput.Reason != "Retire compromised SAML signing key" {
		t.Fatalf("SP-key clear response=%d headers=%#v input=%#v", response.Code, response.Header(), service.samlSPKeyClearInput)
	}
}

func TestPlatformSAMLTrustApprovalConflictIsStableAndNonOracular(t *testing.T) {
	providerID := uuid.Must(uuid.NewV7())
	service := &platformIdentityProviderHTTPStub{samlMetadataError: platformidentityprovider.ErrSAMLTrustApprovalRequired}
	router := newPlatformIdentityProviderTestRouter(t, service)
	request := platformIdentityProviderMutationRequest(
		http.MethodPut,
		platformAuthProviderLocation(providerID)+"/saml/metadata",
		`{"source":"xml","expectedVersion":4,"metadataXml":"<EntityDescriptor>protected-material</EntityDescriptor>","approveTrustReset":false}`,
	)
	request.Header.Set(ifMatchHeader, `"v4"`)
	request.Header.Set("X-Audit-Reason", "Review IdP metadata rollover")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusConflict || service.samlMetadataCalls != 1 {
		t.Fatalf("trust response=%d calls=%d body=%s", response.Code, service.samlMetadataCalls, response.Body.String())
	}
	assertPlatformIdentityProviderProblem(t, response, "saml_trust_approval_required")
	if strings.Contains(response.Body.String(), "protected-material") {
		t.Fatalf("trust conflict leaked metadata: %s", response.Body.String())
	}
}

func TestPlatformSAMLAdministrationRejectsAmbiguousOrNonCanonicalBodiesBeforeService(t *testing.T) {
	providerID := uuid.Must(uuid.NewV7())
	certificate := base64.StdEncoding.EncodeToString([]byte("certificate"))
	tests := []struct {
		method string
		path   string
		body   string
	}{
		{method: http.MethodPut, path: "/saml/metadata", body: `{"source":"url","expectedVersion":1,"metadataUrl":"https://idp.example.test/metadata","metadataXml":"<xml/>","approveTrustReset":false}`},
		{method: http.MethodPut, path: "/saml/metadata", body: `{"source":"xml","source":"xml","expectedVersion":1,"metadataXml":"<xml/>","approveTrustReset":false}`},
		{method: http.MethodPut, path: "/saml/sp-key", body: `{"expectedVersion":1,"privateKeyPkcs8":"a2V5\n","certificates":["` + certificate + `"]}`},
		{method: http.MethodPut, path: "/saml/sp-key", body: `{"expectedVersion":1,"privateKeyPkcs8":"a2V5","certificates":["` + certificate + `","` + certificate + `"]}`},
		{method: http.MethodDelete, path: "/saml/sp-key", body: `{"expectedVersion":1,"extra":true}`},
	}
	for _, test := range tests {
		service := &platformIdentityProviderHTTPStub{}
		router := newPlatformIdentityProviderTestRouter(t, service)
		request := platformIdentityProviderMutationRequest(
			test.method, platformAuthProviderLocation(providerID)+test.path, test.body,
		)
		request.Header.Set(ifMatchHeader, `"v1"`)
		request.Header.Set("X-Audit-Reason", "Reject unsafe SAML administration input")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || service.samlMetadataCalls != 0 ||
			service.samlSPKeyCalls != 0 || service.samlSPKeyClearCalls != 0 {
			t.Fatalf("%s %s response=%d calls=%d/%d/%d body=%s", test.method, test.path, response.Code, service.samlMetadataCalls, service.samlSPKeyCalls, service.samlSPKeyClearCalls, response.Body.String())
		}
	}
}

func TestPlatformSAMLAdministrationRequiresExactCASAndAuditReason(t *testing.T) {
	providerID := uuid.Must(uuid.NewV7())
	tests := []struct {
		name           string
		ifMatch        string
		reason         string
		expectedStatus int
	}{
		{name: "missing If-Match", reason: "Replace reviewed SAML metadata", expectedStatus: http.StatusPreconditionRequired},
		{name: "body and If-Match mismatch", ifMatch: `"v2"`, reason: "Replace reviewed SAML metadata", expectedStatus: http.StatusBadRequest},
		{name: "foldable audit reason", ifMatch: `"v1"`, reason: "unsafe,fold", expectedStatus: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &platformIdentityProviderHTTPStub{}
			router := newPlatformIdentityProviderTestRouter(t, service)
			request := platformIdentityProviderMutationRequest(
				http.MethodPut,
				platformAuthProviderLocation(providerID)+"/saml/metadata",
				`{"source":"xml","expectedVersion":1,"metadataXml":"<xml/>","approveTrustReset":false}`,
			)
			if test.ifMatch != "" {
				request.Header.Set(ifMatchHeader, test.ifMatch)
			}
			request.Header.Set("X-Audit-Reason", test.reason)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			if response.Code != test.expectedStatus || service.samlMetadataCalls != 0 {
				t.Fatalf("response=%d calls=%d body=%s", response.Code, service.samlMetadataCalls, response.Body.String())
			}
		})
	}
}

func TestPlatformSAMLAdministrationEnforcesDecodedMaterialBounds(t *testing.T) {
	metadataDocument := []byte(
		`{"source":"xml","expectedVersion":1,"metadataXml":` +
			mustJSONText(t, strings.Repeat("x", maximumPlatformSAMLMetadataBytes+1)) +
			`,"approveTrustReset":false}`,
	)
	metadataSource := append(make([]byte, 0, len(metadataDocument)+32), metadataDocument...)
	if _, err := decodePlatformSAMLMetadataDocument(metadataSource); err == nil {
		t.Fatal("oversized decoded metadata XML was accepted")
	}
	if !allPlatformSAMLBytesCleared(metadataSource) {
		t.Fatal("oversized metadata parser retained its source buffer")
	}

	oversizedKey := base64.StdEncoding.EncodeToString(make([]byte, maximumPlatformSAMLPrivateKeyBytes+1))
	keyDocument := []byte(
		`{"expectedVersion":1,"privateKeyPkcs8":"` + oversizedKey + `","certificates":["Y2VydA=="]}`,
	)
	keySource := append(make([]byte, 0, len(keyDocument)+32), keyDocument...)
	if _, _, _, err := decodePlatformSAMLSPKeyDocument(keySource); err == nil {
		t.Fatal("oversized decoded private key was accepted")
	}
	if !allPlatformSAMLBytesCleared(keySource) {
		t.Fatal("oversized SP-key parser retained its source buffer")
	}
}

func TestPlatformSAMLProtectedDocumentParsersClearSourceBuffers(t *testing.T) {
	metadataDocument := []byte(`{"source":"xml","expectedVersion":1,"metadataXml":"<xml/>","approveTrustReset":false}`)
	metadataSource := append(make([]byte, 0, len(metadataDocument)+32), metadataDocument...)
	metadata, err := decodePlatformSAMLMetadataDocument(metadataSource)
	if err != nil {
		t.Fatalf("decodePlatformSAMLMetadataDocument() error = %v", err)
	}
	defer metadata.destroy()
	if !allPlatformSAMLBytesCleared(metadataSource[:cap(metadataSource)]) {
		t.Fatal("metadata parser retained the source JSON buffer")
	}

	keyDocument := []byte(`{"expectedVersion":1,"privateKeyPkcs8":"a2V5","certificates":["Y2VydA=="]}`)
	keySource := append(make([]byte, 0, len(keyDocument)+32), keyDocument...)
	privateKey, certificates, _, err := decodePlatformSAMLSPKeyDocument(keySource)
	if err != nil {
		t.Fatalf("decodePlatformSAMLSPKeyDocument() error = %v", err)
	}
	defer clear(privateKey)
	defer clearPlatformSAMLByteSlices(certificates)
	if !allPlatformSAMLBytesCleared(keySource[:cap(keySource)]) {
		t.Fatal("SP-key parser retained the source JSON buffer")
	}
}

func TestPlatformOIDCTenantExecutionLifecycleUsesExactCASAndPreservesDisabledDirectLogin(t *testing.T) {
	active := platformOIDCHTTPProvider(t, 2, true)
	active.Enabled = true
	active.PlatformLoginActivationAvailable = true
	active.AccountMode = platformidentityprovider.AccountModeCreate
	active.OIDC.ClientSecretRevision = 2
	active.UpdatedAt = active.UpdatedAt.Add(time.Microsecond)
	activation, err := platformidentityprovider.RestoreUpdateResult(
		platformidentityprovider.UpdateResultInput{
			ProviderID: active.ID, Version: active.Version, Provider: active,
		},
	)
	if err != nil {
		t.Fatalf("RestoreUpdateResult(activation) error = %v", err)
	}
	service := &platformIdentityProviderHTTPStub{activateResult: activation}
	router := newPlatformIdentityProviderTestRouter(t, service)
	request := platformIdentityProviderMutationRequest(
		http.MethodPost, platformAuthProviderLocation(active.ID)+"/activate",
		`{"accountMode":"create","expectedVersion":1}`,
	)
	request.Header.Set(ifMatchHeader, `"v1"`)
	request.Header.Set("X-Audit-Reason", "Enable tenant execution")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"v2"` ||
		!strings.Contains(response.Header().Get("Cache-Control"), "no-store") ||
		service.activateCalls != 1 || service.activateProvider != active.ID ||
		service.activateInput.AccountMode != platformidentityprovider.AccountModeCreate ||
		service.activateInput.ExpectedEntityTag == nil || *service.activateInput.ExpectedEntityTag != `"v1"` ||
		service.activateInput.Reason != "Enable tenant execution" {
		t.Fatalf("activate response=%d headers=%#v input=%#v body=%s", response.Code, response.Header(), service.activateInput, response.Body.String())
	}
	var activated contract.PlatformAuthProvider
	decodeErr := json.Unmarshal(response.Body.Bytes(), &activated)
	oidc, projectionErr := activated.AsPlatformOIDCAuthProvider()
	if decodeErr != nil || projectionErr != nil || !oidc.Enabled || bool(oidc.PlatformLoginEnabled) ||
		!bool(oidc.PlatformLoginActivationAvailable) ||
		oidc.AccountMode != contract.PlatformOIDCAuthProviderAccountModeCreate {
		t.Fatalf(
			"activated projection=%#v decode_error=%v projection_error=%v",
			oidc, decodeErr, projectionErr,
		)
	}

	disabled := active
	disabled.Version = 3
	disabled.Enabled = false
	disabled.PlatformLoginActivationAvailable = false
	disabled.ActivationAvailable = true
	disabled.AccountMode = platformidentityprovider.AccountModeDisabled
	disabled.UpdatedAt = disabled.UpdatedAt.Add(time.Microsecond)
	deactivation, err := platformidentityprovider.RestoreUpdateResult(
		platformidentityprovider.UpdateResultInput{
			ProviderID: disabled.ID, Version: disabled.Version, Provider: disabled,
		},
	)
	if err != nil {
		t.Fatalf("RestoreUpdateResult(deactivation) error = %v", err)
	}
	service = &platformIdentityProviderHTTPStub{deactivateResult: deactivation}
	router = newPlatformIdentityProviderTestRouter(t, service)
	request = platformIdentityProviderMutationRequest(
		http.MethodPost, platformAuthProviderLocation(disabled.ID)+"/deactivate",
		`{"expectedVersion":2}`,
	)
	request.Header.Set(ifMatchHeader, `"v2"`)
	request.Header.Set("X-Audit-Reason", "Suspend tenant execution")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"v3"` ||
		service.deactivateCalls != 1 || service.deactivateProvider != disabled.ID ||
		service.deactivateInput.ExpectedEntityTag == nil || *service.deactivateInput.ExpectedEntityTag != `"v2"` ||
		service.deactivateInput.Reason != "Suspend tenant execution" {
		t.Fatalf("deactivate response=%d headers=%#v input=%#v body=%s", response.Code, response.Header(), service.deactivateInput, response.Body.String())
	}
}

func TestPlatformOIDCDirectLoginLifecycleUsesExactCASAndPreservesTenantMode(t *testing.T) {
	active := platformOIDCHTTPProvider(t, 2, true)
	active.Enabled = true
	active.PlatformLoginEnabled = true
	active.PlatformLoginActivationAvailable = false
	active.AccountMode = platformidentityprovider.AccountModeCreate
	active.OIDC.ClientSecretRevision = 2
	active.UpdatedAt = active.UpdatedAt.Add(time.Microsecond)
	activation, err := platformidentityprovider.RestoreUpdateResult(
		platformidentityprovider.UpdateResultInput{
			ProviderID: active.ID, Version: active.Version, Provider: active,
		},
	)
	if err != nil {
		t.Fatalf("RestoreUpdateResult(activation) error = %v", err)
	}
	service := &platformIdentityProviderHTTPStub{directActivateResult: activation}
	router := newPlatformIdentityProviderTestRouter(t, service)
	request := platformIdentityProviderMutationRequest(
		http.MethodPost, platformAuthProviderLocation(active.ID)+"/direct-login/activate",
		`{"expectedVersion":1}`,
	)
	request.Header.Set(ifMatchHeader, `"v1"`)
	request.Header.Set("X-Audit-Reason", "Enable direct login")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"v2"` ||
		!strings.Contains(response.Header().Get("Cache-Control"), "no-store") ||
		service.directActivateCalls != 1 || service.directActivateProvider != active.ID ||
		service.directActivateInput.ExpectedEntityTag == nil || *service.directActivateInput.ExpectedEntityTag != `"v1"` ||
		service.directActivateInput.Reason != "Enable direct login" {
		t.Fatalf("activate response=%d headers=%#v input=%#v body=%s", response.Code, response.Header(), service.directActivateInput, response.Body.String())
	}
	var activated contract.PlatformAuthProvider
	decodeErr := json.Unmarshal(response.Body.Bytes(), &activated)
	oidc, projectionErr := activated.AsPlatformOIDCAuthProvider()
	if decodeErr != nil || projectionErr != nil || !oidc.Enabled || !oidc.PlatformLoginEnabled ||
		oidc.PlatformLoginActivationAvailable ||
		oidc.AccountMode != contract.PlatformOIDCAuthProviderAccountModeCreate {
		t.Fatalf("activated projection=%#v decode_error=%v projection_error=%v", oidc, decodeErr, projectionErr)
	}

	disabled := active
	disabled.Version = 3
	disabled.PlatformLoginEnabled = false
	disabled.PlatformLoginActivationAvailable = true
	disabled.UpdatedAt = disabled.UpdatedAt.Add(time.Microsecond)
	deactivation, err := platformidentityprovider.RestoreUpdateResult(
		platformidentityprovider.UpdateResultInput{
			ProviderID: disabled.ID, Version: disabled.Version, Provider: disabled,
		},
	)
	if err != nil {
		t.Fatalf("RestoreUpdateResult(deactivation) error = %v", err)
	}
	service = &platformIdentityProviderHTTPStub{directDeactivateResult: deactivation}
	router = newPlatformIdentityProviderTestRouter(t, service)
	request = platformIdentityProviderMutationRequest(
		http.MethodPost, platformAuthProviderLocation(disabled.ID)+"/direct-login/deactivate",
		`{"expectedVersion":2}`,
	)
	request.Header.Set(ifMatchHeader, `"v2"`)
	request.Header.Set("X-Audit-Reason", "Disable direct login")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"v3"` ||
		service.directDeactivateCalls != 1 || service.directDeactivateProvider != disabled.ID ||
		service.directDeactivateInput.ExpectedEntityTag == nil || *service.directDeactivateInput.ExpectedEntityTag != `"v2"` ||
		service.directDeactivateInput.Reason != "Disable direct login" {
		t.Fatalf("deactivate response=%d headers=%#v input=%#v body=%s", response.Code, response.Header(), service.directDeactivateInput, response.Body.String())
	}
	var deactivated contract.PlatformAuthProvider
	decodeErr = json.Unmarshal(response.Body.Bytes(), &deactivated)
	oidc, projectionErr = deactivated.AsPlatformOIDCAuthProvider()
	if decodeErr != nil || projectionErr != nil || !oidc.Enabled || oidc.PlatformLoginEnabled ||
		!oidc.PlatformLoginActivationAvailable ||
		oidc.AccountMode != contract.PlatformOIDCAuthProviderAccountModeCreate {
		t.Fatalf("deactivated projection=%#v decode_error=%v projection_error=%v", oidc, decodeErr, projectionErr)
	}
}

func TestPlatformOIDCDirectLoginCommandsRejectUnsafeBodiesAndPathsBeforeService(t *testing.T) {
	providerID := uuid.Must(uuid.NewV7())
	invalidVersionID := uuid.New()
	tests := []struct {
		name       string
		path       string
		body       string
		ifMatch    string
		wantStatus int
	}{
		{name: "duplicate", path: platformAuthProviderLocation(providerID) + "/direct-login/activate", body: `{"expectedVersion":1,"expectedVersion":1}`, ifMatch: `"v1"`, wantStatus: http.StatusBadRequest},
		{name: "unknown", path: platformAuthProviderLocation(providerID) + "/direct-login/activate", body: `{"expectedVersion":1,"accountMode":"existing_identity"}`, ifMatch: `"v1"`, wantStatus: http.StatusBadRequest},
		{name: "trailing", path: platformAuthProviderLocation(providerID) + "/direct-login/deactivate", body: `{"expectedVersion":1}{}`, ifMatch: `"v1"`, wantStatus: http.StatusBadRequest},
		{name: "mismatched body version", path: platformAuthProviderLocation(providerID) + "/direct-login/deactivate", body: `{"expectedVersion":2}`, ifMatch: `"v1"`, wantStatus: http.StatusBadRequest},
		{name: "missing precondition", path: platformAuthProviderLocation(providerID) + "/direct-login/activate", body: `{"expectedVersion":1}`, wantStatus: http.StatusPreconditionRequired},
		{name: "non v7 provider", path: platformAuthProviderLocation(invalidVersionID) + "/direct-login/activate", body: `{"expectedVersion":1}`, ifMatch: `"v1"`, wantStatus: http.StatusBadRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &platformIdentityProviderHTTPStub{}
			router := newPlatformIdentityProviderTestRouter(t, service)
			request := platformIdentityProviderMutationRequest(http.MethodPost, test.path, test.body)
			if test.ifMatch != "" {
				request.Header.Set(ifMatchHeader, test.ifMatch)
			}
			request.Header.Set("X-Audit-Reason", "Reject unsafe direct login command")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.wantStatus || service.directActivateCalls != 0 || service.directDeactivateCalls != 0 {
				t.Fatalf("response=%d activate/deactivate=%d/%d body=%s", response.Code, service.directActivateCalls, service.directDeactivateCalls, response.Body.String())
			}
		})
	}
}

func TestPlatformOIDCTenantExecutionActivationRejectsUnsafeDocumentsBeforeService(t *testing.T) {
	provider := platformOIDCHTTPProvider(t, 1, true)
	for _, body := range []string{
		`{"accountMode":"disabled","expectedVersion":1}`,
		`{"accountMode":"create","accountMode":"existing_identity","expectedVersion":1}`,
		`{"accountMode":"create","expectedVersion":1,"platformLoginEnabled":true}`,
		`{"accountMode":"create","expectedVersion":2}`,
	} {
		service := &platformIdentityProviderHTTPStub{}
		router := newPlatformIdentityProviderTestRouter(t, service)
		request := platformIdentityProviderMutationRequest(
			http.MethodPost, platformAuthProviderLocation(provider.ID)+"/activate", body,
		)
		request.Header.Set(ifMatchHeader, `"v1"`)
		request.Header.Set("X-Audit-Reason", "Reject unsafe activation")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || service.activateCalls != 0 {
			t.Fatalf("body=%s response=%d calls=%d payload=%s", body, response.Code, service.activateCalls, response.Body.String())
		}
		assertPlatformIdentityProviderProblem(t, response, "invalid_request")
	}
}

func TestPlatformOIDCSecretParserRejectsDuplicateAndTrailingMembers(t *testing.T) {
	for _, document := range []string{
		`{"clientSecret":"a","clientSecret":"b","expectedVersion":1}`,
		`{"clientSecret":"a","expectedVersion":1,}`,
		`{"clientSecret":"a","expectedVersion":1,"extra":true}`,
	} {
		secret, _, err := decodePlatformOIDCClientSecretDocument([]byte(document))
		if err == nil || secret != nil {
			t.Fatalf("decodePlatformOIDCClientSecretDocument(%q) = %q, %v", document, secret, err)
		}
	}
}

func newPlatformIdentityProviderTestRouter(
	t *testing.T,
	service PlatformIdentityProviderService,
) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	userID := uuid.Must(uuid.NewV7())
	auth := groupTransportAuthentication(uuid.Must(uuid.NewV7()), userID)
	auth.authenticateResult.ActiveTenantID = nil
	auth.authenticateResult.Permissions = []authorization.Permission{
		authorization.PermissionPlatformIdentityProviderRead,
		authorization.PermissionPlatformIdentityProviderManage,
	}
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, logger, "test", time.Second,
		ApplicationOptions{
			Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: auth, Authorization: &transportAuthorizationStub{},
			Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{},
			Environment: "test", IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{}, MFA: &transportMFAStub{}, Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{},
			PlatformIdentityProviders: service, PublicOrigin: "http://localhost:8081", ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{}, Ticketing: &transportTicketingStub{}, WorkflowAdministration: &transportWorkflowAdministrationStub{},
		},
	)
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}

func platformIdentityProviderMutationRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.Header.Set(csrfTokenHeader, "csrf-value")
	request.Header.Set("User-Agent", "periapsis-platform-provider-test")
	return request
}

func mustJSONText(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return string(encoded)
}

func allPlatformSAMLBytesCleared(value []byte) bool {
	for _, item := range value[:cap(value)] {
		if item != 0 {
			return false
		}
	}
	return true
}

func platformOIDCHTTPProvider(t *testing.T, version int64, secretPresent bool) platformidentityprovider.Provider {
	t.Helper()
	providerID := uuid.Must(uuid.NewV7())
	createdAt := time.Date(2026, time.August, 27, 12, 0, 0, 0, time.UTC)
	return platformidentityprovider.Provider{
		ProviderSummary: platformidentityprovider.ProviderSummary{
			ID: providerID, Key: "corp_oidc", DisplayName: "Corporate OIDC",
			Description: "", Kind: platformidentityprovider.ProviderKindOIDC,
			Configured: true, SecretPresent: secretPresent, Version: version,
			CreatedAt: createdAt, UpdatedAt: createdAt,
		},
		ConfigurationRevision: 1, SecurityRevision: 1, PlanRevision: 1,
		AssurancePolicyRevision: 1, AccountMode: platformidentityprovider.AccountModeDisabled,
		OIDC: &platformidentityprovider.OIDCConfiguration{
			Issuer: "https://id.example.test", ClientID: "periapsis",
			RedirectURI:           "https://app.example.test/api/v1/auth/platform/oidc/callback",
			TenantRedirectURI:     "https://app.example.test/api/v1/auth/federated/oidc/callback",
			PostLogoutRedirectURI: "https://app.example.test/signed-out", ExtraScopes: []string{"email"},
			UseUserInfo: true, ClientSecretRevision: 1, ClientSecretPresent: secretPresent,
			DiscoveryRevision: 1, JWKSRevision: 1,
		},
	}
}

func assertPlatformIdentityProviderProblem(
	t *testing.T,
	response *httptest.ResponseRecorder,
	code string,
) {
	t.Helper()
	if !strings.Contains(response.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("problem Cache-Control = %q", response.Header().Get("Cache-Control"))
	}
	var problem contract.Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil || problem.Code != code {
		t.Fatalf("problem = %#v, error=%v, want code=%q", problem, err, code)
	}
}

var _ PlatformIdentityProviderService = (*platformIdentityProviderHTTPStub)(nil)
