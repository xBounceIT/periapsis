package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/periapsis-im/periapsis/services/api/internal/platformsamladapter"
)

type tenantSAMLMetadataHTTPStub struct {
	tenantSlug string
	loginKey   string
	document   platformsamladapter.TenantSAMLMetadataDocument
	err        error
	calls      int
}

type tenantSAMLMetadataSourceStub struct {
	projection platformsamladapter.TenantSAMLMetadataProjection
	found      bool
	err        error
}

func (stub tenantSAMLMetadataSourceStub) LoadTenantSAMLMetadata(
	context.Context,
	string,
	string,
) (platformsamladapter.TenantSAMLMetadataProjection, bool, error) {
	return stub.projection, stub.found, stub.err
}

func (stub *tenantSAMLMetadataHTTPStub) Metadata(
	_ context.Context,
	tenantSlug string,
	loginKey string,
) (platformsamladapter.TenantSAMLMetadataDocument, error) {
	stub.calls++
	stub.tenantSlug, stub.loginKey = tenantSlug, loginKey
	return stub.document, stub.err
}

func TestTenantSAMLMetadataRouteIsExactCertificateOnlyAndNoStore(t *testing.T) {
	service := &tenantSAMLMetadataHTTPStub{document: platformsamladapter.TenantSAMLMetadataDocument{
		ContentType: platformsamladapter.SAMLMetadataContentType,
		Document:    []byte(`<?xml version="1.0"?><EntityDescriptor><X509Certificate>PUBLIC-CERTIFICATE</X509Certificate></EntityDescriptor>`),
	}}
	handler, router, _, _ := newFederatedTestRouter(t, "test", &transportFederatedAuthenticationStub{}, &transportAuthStub{}, nil)
	handler.federated.samlMetadata = service

	request := httptest.NewRequest(
		http.MethodGet, "/api/v1/auth/federated/saml/acme-eu/workforce/metadata", nil,
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || service.calls != 1 || service.tenantSlug != "acme-eu" ||
		service.loginKey != "workforce" {
		t.Fatalf("metadata response = %d calls=%d locator=%q/%q body=%s", response.Code, service.calls, service.tenantSlug, service.loginKey, response.Body.String())
	}
	if response.Header().Get("Content-Type") != platformsamladapter.SAMLMetadataContentType ||
		response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Referrer-Policy") != "no-referrer" ||
		!strings.Contains(response.Body.String(), "PUBLIC-CERTIFICATE") ||
		strings.Contains(strings.ToLower(response.Body.String()), "private") {
		t.Fatalf("unsafe metadata response headers/body = %#v %q", response.Header(), response.Body.String())
	}
	for index, value := range service.document.Document {
		if value != 0 {
			t.Fatalf("metadata response buffer[%d] was not cleared", index)
		}
	}
}

func TestTenantSAMLMetadataRouteFailsClosedWithoutProviderOracle(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		err        error
		wantStatus int
		wantCalls  int
	}{
		{name: "malformed slug", path: "/api/v1/auth/federated/saml/Bad_Slug/workforce/metadata", wantStatus: http.StatusBadRequest},
		{name: "malformed login", path: "/api/v1/auth/federated/saml/acme/UPPER/metadata", wantStatus: http.StatusBadRequest},
		{name: "missing or disabled", path: "/api/v1/auth/federated/saml/acme/workforce/metadata", err: errTenantSAMLMetadataNotFound, wantStatus: http.StatusNotFound, wantCalls: 1},
		{name: "dependency unavailable", path: "/api/v1/auth/federated/saml/acme/workforce/metadata", err: errors.New("database unavailable"), wantStatus: http.StatusServiceUnavailable, wantCalls: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &tenantSAMLMetadataHTTPStub{err: test.err}
			handler, router, _, _ := newFederatedTestRouter(t, "test", &transportFederatedAuthenticationStub{}, &transportAuthStub{}, nil)
			handler.federated.samlMetadata = service
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
			if response.Code != test.wantStatus || service.calls != test.wantCalls ||
				response.Header().Get("Cache-Control") != "no-store" ||
				response.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Fatalf("response = %d calls=%d headers=%#v body=%s", response.Code, service.calls, response.Header(), response.Body.String())
			}
		})
	}
}

func TestTenantSAMLMetadataRouteHidesFoundButUnpublishableProjection(t *testing.T) {
	service, err := NewRuntimeTenantSAMLMetadata(
		tenantSAMLMetadataSourceStub{
			found: true,
			// A source-visible projection whose lifecycle or certificate is no
			// longer publishable must remain indistinguishable from an unknown
			// locator at the anonymous boundary.
			projection: platformsamladapter.TenantSAMLMetadataProjection{
				TenantSlug: "acme", LoginKey: "workforce",
			},
		},
		"https://soc.example.invalid",
	)
	if err != nil {
		t.Fatal(err)
	}
	handler, router, _, _ := newFederatedTestRouter(
		t, "test", &transportFederatedAuthenticationStub{}, &transportAuthStub{}, nil,
	)
	handler.federated.samlMetadata = service
	response := httptest.NewRecorder()
	router.ServeHTTP(
		response,
		httptest.NewRequest(
			http.MethodGet,
			"/api/v1/auth/federated/saml/acme/workforce/metadata",
			nil,
		),
	)
	if response.Code != http.StatusNotFound ||
		response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Referrer-Policy") != "no-referrer" ||
		strings.Contains(strings.ToLower(response.Body.String()), "certificate") {
		t.Fatalf("unpublishable projection response = %d headers=%#v body=%s", response.Code, response.Header(), response.Body.String())
	}
}
