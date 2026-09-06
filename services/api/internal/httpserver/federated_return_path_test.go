package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

func TestFederatedReturnPathsRejectRedirectAndDecodedControlVectors(t *testing.T) {
	for _, value := range []string{
		"//evil.example", `/\evil.example`, "https://evil.example", "/%2Fevil.example",
		"/%5Cevil.example", "/%00evil.example", "/%0Devil.example", "/%0Aevil.example",
		"/a/%2e%2e/b", "/a\\b", "/a\r\nb", "/a#fragment",
	} {
		t.Run(value, func(t *testing.T) {
			if validFederatedReturnPath(value) {
				t.Fatalf("accepted unsafe return path %q", value)
			}
		})
	}
}

func TestFederatedStartRejectsUnsafeReturnPathsBeforeApplication(t *testing.T) {
	for _, value := range []string{"//evil.example", `/\evil.example`, "/%5Cevil.example", "/%0Aevil.example"} {
		for _, requestBuilder := range []struct {
			name  string
			build func(string, string) *http.Request
		}{
			{name: "json", build: federatedStartRequest},
			{name: "form", build: federatedFormStartRequest},
		} {
			t.Run(requestBuilder.name+value, func(t *testing.T) {
				stub := &transportFederatedAuthenticationStub{}
				_, router, _, _ := newFederatedTestRouter(t, "test", stub, &transportAuthStub{}, nil)
				response := httptest.NewRecorder()
				router.ServeHTTP(response, requestBuilder.build("/api/v1/auth/federated/oidc/acme/primary_oidc/start", value))
				if response.Code != http.StatusUnauthorized || len(stub.oidcStarts) != 0 || response.Header().Get("Location") != "" {
					t.Fatalf("unsafe start status=%d calls=%d location=%q", response.Code, len(stub.oidcStarts), response.Header().Get("Location"))
				}
			})
		}
	}
}

func TestFederatedCallbackRejectsUnsafeStoredReturnPaths(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	for _, value := range []string{"//evil.example", `/\evil.example`, "/%5Cevil.example", "/%0Aevil.example"} {
		t.Run(value, func(t *testing.T) {
			fixture := newFederatedContinuationFixture(t, "/cases", now, 0x84)
			fixture.result.ReturnPath = value
			stub := &transportFederatedAuthenticationStub{completeSAML: func(federatedauth.CompleteTenantSAMLLoginRequest) (federatedauth.ApplyResult, error) {
				return fixture.result, nil
			}}
			handler, router, _, _ := newFederatedTestRouter(t, "test", stub, &transportAuthStub{}, nil)
			handler.federated.now = func() time.Time { return now }
			response := httptest.NewRecorder()
			router.ServeHTTP(response, federatedSAMLCallbackRequest(federatedOpaque(0x85), "SAMLResponse=x&RelayState=y"))
			if response.Code != http.StatusUnauthorized || response.Header().Get("Location") != "" ||
				findPositiveResponseCookie(response.Result().Cookies(), developmentMFACookie) != nil ||
				findPositiveResponseCookie(response.Result().Cookies(), developmentCookie) != nil {
				t.Fatalf("unsafe callback status=%d location=%q", response.Code, response.Header().Get("Location"))
			}
			if _, ok := fixture.result.Credential.Consume(); ok {
				t.Fatal("rejected return path retained a consumable credential")
			}
		})
	}
}
