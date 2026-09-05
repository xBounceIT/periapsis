package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

func (stub *transportTenantFederationStub) ReplaceSAMLMetadata(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
	identityprovider.FederationReplaceSAMLMetadataInput,
) (identityprovider.FederationSAMLMaterialMutationReceipt, error) {
	return identityprovider.FederationSAMLMaterialMutationReceipt{}, identityprovider.ErrUnavailable
}

func (stub *transportTenantFederationStub) ReplaceSAMLSPCredential(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
	identityprovider.FederationReplaceSAMLSPCredentialInput,
) (identityprovider.FederationSAMLMaterialMutationReceipt, error) {
	return identityprovider.FederationSAMLMaterialMutationReceipt{}, identityprovider.ErrUnavailable
}

func (stub *transportTenantFederationStub) ClearSAMLSPCredential(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
	identityprovider.FederationClearSAMLSPCredentialInput,
) (identityprovider.FederationSAMLMaterialMutationReceipt, error) {
	return identityprovider.FederationSAMLMaterialMutationReceipt{}, identityprovider.ErrUnavailable
}

type tenantFederationSAMLHTTPStub struct {
	unavailableTenantFederationAdministrationService
	replaceMetadata func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FederationReplaceSAMLMetadataInput) (identityprovider.FederationSAMLMaterialMutationReceipt, error)
	replaceKey      func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FederationReplaceSAMLSPCredentialInput) (identityprovider.FederationSAMLMaterialMutationReceipt, error)
	clearKey        func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FederationClearSAMLSPCredentialInput) (identityprovider.FederationSAMLMaterialMutationReceipt, error)
}

func (stub *tenantFederationSAMLHTTPStub) ReplaceSAMLMetadata(ctx context.Context, actor authorization.Actor, tenantID, providerID uuid.UUID, input identityprovider.FederationReplaceSAMLMetadataInput) (identityprovider.FederationSAMLMaterialMutationReceipt, error) {
	return stub.replaceMetadata(ctx, actor, tenantID, providerID, input)
}

func (stub *tenantFederationSAMLHTTPStub) ReplaceSAMLSPCredential(ctx context.Context, actor authorization.Actor, tenantID, providerID uuid.UUID, input identityprovider.FederationReplaceSAMLSPCredentialInput) (identityprovider.FederationSAMLMaterialMutationReceipt, error) {
	return stub.replaceKey(ctx, actor, tenantID, providerID, input)
}

func (stub *tenantFederationSAMLHTTPStub) ClearSAMLSPCredential(ctx context.Context, actor authorization.Actor, tenantID, providerID uuid.UUID, input identityprovider.FederationClearSAMLSPCredentialInput) (identityprovider.FederationSAMLMaterialMutationReceipt, error) {
	return stub.clearKey(ctx, actor, tenantID, providerID, input)
}

func TestTenantFederationSAMLAdministrationRoutesAreWriteOnlyAndVersioned(t *testing.T) {
	tenantID, providerID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	calls := make(map[string]int)
	var retainedMetadata []byte
	service := &tenantFederationSAMLHTTPStub{}
	service.replaceMetadata = func(_ context.Context, _ authorization.Actor, gotTenant, gotProvider uuid.UUID, input identityprovider.FederationReplaceSAMLMetadataInput) (identityprovider.FederationSAMLMaterialMutationReceipt, error) {
		calls["metadata"]++
		if gotTenant != tenantID || gotProvider != providerID || input.MetadataURL != nil ||
			string(input.MetadataXML) != "<EntityDescriptor/>" || !input.ApproveTrustReset ||
			input.Reason != "verified out of band" || input.ExpectedEntityTag == nil || *input.ExpectedEntityTag != `"v4"` ||
			input.Audit.RequestID == uuid.Nil {
			t.Fatalf("metadata input = %s %#v", input.String(), input)
		}
		retainedMetadata = input.MetadataXML
		return identityprovider.FederationSAMLMaterialMutationReceipt{ProviderID: providerID, ProviderVersion: 5, MaterialRevision: 3}, nil
	}
	service.replaceKey = func(_ context.Context, _ authorization.Actor, gotTenant, gotProvider uuid.UUID, input identityprovider.FederationReplaceSAMLSPCredentialInput) (identityprovider.FederationSAMLMaterialMutationReceipt, error) {
		calls["replace key"]++
		if gotTenant != tenantID || gotProvider != providerID || input.Reason != "rotate disabled provider" || input.ExpectedEntityTag == nil || *input.ExpectedEntityTag != `"v5"` {
			t.Fatalf("replace key input = %#v", input)
		}
		return identityprovider.FederationSAMLMaterialMutationReceipt{ProviderID: providerID, ProviderVersion: 6, MaterialRevision: 2}, nil
	}
	service.clearKey = func(_ context.Context, _ authorization.Actor, gotTenant, gotProvider uuid.UUID, input identityprovider.FederationClearSAMLSPCredentialInput) (identityprovider.FederationSAMLMaterialMutationReceipt, error) {
		calls["clear key"]++
		if gotTenant != tenantID || gotProvider != providerID || input.Reason != "retire disabled provider" || input.ExpectedEntityTag == nil || *input.ExpectedEntityTag != `"v6"` {
			t.Fatalf("clear key input = %#v", input)
		}
		return identityprovider.FederationSAMLMaterialMutationReceipt{ProviderID: providerID, ProviderVersion: 7, MaterialRevision: 3}, nil
	}
	router := newTenantFederationTestRouter(t, tenantFederationHTTPAuthentication(tenantID, userID), service)
	base := "/api/v1/tenants/" + tenantID.String() + "/federated-auth-providers/" + providerID.String() + "/saml"
	tests := []struct {
		name, method, path, entityTag string
		body                          map[string]any
		wantVersion, wantRevision     string
	}{
		{name: "metadata", method: http.MethodPut, path: base + "/metadata", entityTag: `"v4"`,
			body: map[string]any{"source": "xml", "metadataXml": "<EntityDescriptor/>", "approveTrustReset": true, "reason": "verified out of band"}, wantVersion: `"v5"`, wantRevision: "3"},
		{name: "replace key", method: http.MethodPut, path: base + "/sp-credential", entityTag: `"v5"`,
			body: map[string]any{"reason": "rotate disabled provider"}, wantVersion: `"v6"`, wantRevision: "2"},
		{name: "clear key", method: http.MethodDelete, path: base + "/sp-credential", entityTag: `"v6"`,
			body: map[string]any{"reason": "retire disabled provider"}, wantVersion: `"v7"`, wantRevision: "3"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document, _ := json.Marshal(test.body)
			request := httptest.NewRequest(test.method, test.path, bytes.NewReader(document))
			prepareTenantLDAPTransportRequest(request, true)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("If-Match", test.entityTag)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusNoContent || response.Body.Len() != 0 ||
				response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("ETag") != test.wantVersion ||
				response.Header().Get("X-Periapsis-SAML-Material-Revision") != test.wantRevision {
				t.Fatalf("response = %d headers=%#v body=%q", response.Code, response.Header(), response.Body.String())
			}
			if strings.Contains(response.Body.String(), "PRIVATE") || strings.Contains(response.Body.String(), "CERTIFICATE") {
				t.Fatalf("material leaked in response: %q", response.Body.String())
			}
		})
	}
	for name, count := range calls {
		if count != 1 {
			t.Fatalf("%s calls = %d", name, count)
		}
	}
	for index, value := range retainedMetadata {
		if value != 0 {
			t.Fatalf("metadata input[%d] was not cleared", index)
		}
	}
}

func TestTenantFederationSAMLAdministrationRejectsImportOverlapAndTrustResetIsStable(t *testing.T) {
	invalid := []string{
		`{"source":"url","metadataUrl":"https://idp.example.test/metadata","metadataXml":"<xml/>","approveTrustReset":false,"reason":"replace"}`,
		`{"source":"xml","metadataXml":"<xml/>","approveTrustReset":false,"reason":"replace","reason":"again"}`,
		`{"source":"xml","metadataXml":"","approveTrustReset":false,"reason":"replace"}`,
		`{"reason":"rotate","privateKeyPkcs8":"PRIVATE"}`,
		`{"reason":"rotate","certificateChainDer":["CERTIFICATE"]}`,
	}
	for index, document := range invalid {
		request := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(document))
		request.Header.Set("Content-Type", "application/json")
		if index < 3 {
			body, err := decodeTenantFederationSAMLMetadataBody(request)
			body.destroy()
			if err == nil {
				t.Fatalf("invalid metadata body %d was accepted", index)
			}
		} else if _, err := decodeTenantFederationSAMLSPCredentialBody(request); err == nil {
			t.Fatalf("credential import body %d was accepted", index)
		}
	}

	tenantID, providerID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	service := &tenantFederationSAMLHTTPStub{}
	service.replaceMetadata = func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FederationReplaceSAMLMetadataInput) (identityprovider.FederationSAMLMaterialMutationReceipt, error) {
		return identityprovider.FederationSAMLMaterialMutationReceipt{}, identityprovider.ErrFederationSAMLTrustApprovalRequired
	}
	router := newTenantFederationTestRouter(t, tenantFederationHTTPAuthentication(tenantID, uuid.Must(uuid.NewV7())), service)
	body := `{"source":"url","metadataUrl":"https://idp.example.test/metadata","approveTrustReset":false,"reason":"replace"}`
	request := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/"+tenantID.String()+"/federated-auth-providers/"+providerID.String()+"/saml/metadata", strings.NewReader(body))
	prepareTenantLDAPTransportRequest(request, true)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-Match", `"v4"`)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || response.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(response.Body.String(), `"code":"saml_trust_approval_required"`) {
		t.Fatalf("trust conflict = %d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
}

func TestTenantFederationSAMLMetadataReasonUsesTheContractCodePointBoundary(t *testing.T) {
	t.Parallel()

	for _, source := range []string{"url", "xml"} {
		t.Run(source, func(t *testing.T) {
			for _, count := range []int{500, 501} {
				reason := strings.Repeat("😀", count)
				body := map[string]any{
					"source": source, "approveTrustReset": false, "reason": reason,
				}
				if source == "url" {
					body["metadataUrl"] = "https://idp.example.test/metadata"
				} else {
					body["metadataXml"] = "<EntityDescriptor/>"
				}
				document, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := decodeTenantFederationSAMLMetadataDocument(document)
				if count == 500 {
					if err != nil || utf8.RuneCountInString(decoded.reason) != count {
						t.Fatalf("%s %d-code-point reason = (%d, %v)", source, count, utf8.RuneCountInString(decoded.reason), err)
					}
					decoded.destroy()
				} else if err == nil {
					decoded.destroy()
					t.Fatalf("%s %d-code-point reason was accepted", source, count)
				}
			}
		})
	}
}

func TestTenantFederationSAMLAdministrationRequiresCurrentIfMatchBeforeBody(t *testing.T) {
	tenantID, providerID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	service := &tenantFederationSAMLHTTPStub{
		replaceKey: func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, identityprovider.FederationReplaceSAMLSPCredentialInput) (identityprovider.FederationSAMLMaterialMutationReceipt, error) {
			t.Fatal("service called without If-Match")
			return identityprovider.FederationSAMLMaterialMutationReceipt{}, errors.New("unreachable")
		},
	}
	router := newTenantFederationTestRouter(t, tenantFederationHTTPAuthentication(tenantID, uuid.Must(uuid.NewV7())), service)
	request := httptest.NewRequest(http.MethodPut, "/api/v1/tenants/"+tenantID.String()+"/federated-auth-providers/"+providerID.String()+"/saml/sp-credential", strings.NewReader(`{"reason":"rotate"}`))
	prepareTenantLDAPTransportRequest(request, true)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusPreconditionRequired || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response = %d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
}
