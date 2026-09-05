package federatedoidc

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
)

func TestNewFreezesValidOptions(t *testing.T) {
	compiler := newCompiler(t)
	limits := DefaultLimits()
	client, err := New(Options{HTTP: compiler, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	if client == nil || client.http == nil || client.limits != limits {
		t.Fatal("client did not freeze valid options")
	}
	if _, err = New(Options{Limits: limits}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("nil HTTP boundary: %v", err)
	}
	if _, err = newClient(nil, limits); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("nil internal boundary: %v", err)
	}
}

func TestNewRejectsEveryInvalidLimitClass(t *testing.T) {
	tests := map[string]func(*Limits){
		"discovery bytes":      func(value *Limits) { value.MaxDiscoveryBytes = minimumDiscoveryBytes - 1 },
		"jwks bytes":           func(value *Limits) { value.MaxJWKSBytes = maximumJWKSBytes + 1 },
		"depth":                func(value *Limits) { value.MaxJSONDepth = maximumJSONDepth + 1 },
		"values":               func(value *Limits) { value.MaxJSONValues = minimumJSONValues - 1 },
		"object members":       func(value *Limits) { value.MaxJSONObjectMembers = maximumJSONObjectMembers + 1 },
		"array items":          func(value *Limits) { value.MaxJSONArrayItems = minimumJSONArrayItems - 1 },
		"string bytes":         func(value *Limits) { value.MaxJSONStringBytes = maximumJSONStringBytes + 1 },
		"keys":                 func(value *Limits) { value.MaxKeys = 0 },
		"certificates":         func(value *Limits) { value.MaxCertificates = maximumCertificates + 1 },
		"certificates per key": func(value *Limits) { value.MaxCertificatesPerKey = maximumCertificatesPerKey + 1 },
		"certificate relation": func(value *Limits) { value.MaxCertificates = 1; value.MaxCertificatesPerKey = 2 },
		"certificate bytes":    func(value *Limits) { value.MaxCertificateBytes = minimumCertificateBytes - 1 },
		"key id bytes":         func(value *Limits) { value.MaxKeyIDBytes = maximumKeyIDBytes + 1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			limits := DefaultLimits()
			mutate(&limits)
			if _, err := newClient(&fakeTrustHTTP{compiler: newCompiler(t)}, limits); !errors.Is(err, ErrInvalidOptions) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestFetchDiscoveryBuildsImmutableExactSnapshot(t *testing.T) {
	document := validDiscoveryDocument(t)
	client, fake := newTrustTestClient(t, []federatedhttp.Result{
		successfulResult(federatedhttp.DocumentOIDCDiscovery, document),
	}, nil)
	request := validDiscoveryRequest()
	snapshot, err := client.FetchDiscovery(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.Policy.SigningAlgorithms[0] = SigningPS512

	if snapshot.Revision() != testDiscoveryRev || snapshot.Issuer() != testIssuer {
		t.Fatalf("unexpected snapshot identity: %d %q", snapshot.Revision(), snapshot.Issuer())
	}
	if snapshot.Digest() != sha256.Sum256(document) || snapshot.Cache().RetrievedAt != testRetrievedAt {
		t.Fatal("snapshot did not pin document digest and cache metadata")
	}
	if snapshot.Endpoints() != (Endpoints{
		Authorization: testAuthorization,
		Token:         testToken,
		JWKS:          testJWKS,
		UserInfo:      testUserInfo,
		Revocation:    testRevocation,
		EndSession:    testEndSession,
	}) {
		t.Fatalf("unexpected endpoints: %v", snapshot.Endpoints())
	}
	wantAlgorithms := []SigningAlgorithm{SigningES256, SigningEdDSA, SigningRS256}
	algorithms := snapshot.SigningAlgorithms()
	if !slices.Equal(algorithms, wantAlgorithms) {
		t.Fatalf("algorithms = %v, want %v", algorithms, wantAlgorithms)
	}
	algorithms[0] = SigningPS512
	if !slices.Equal(snapshot.SigningAlgorithms(), wantAlgorithms) {
		t.Fatal("signing algorithm accessor exposed mutable snapshot storage")
	}

	if snapshot.ClientAuthentication() != ClientSecretBasic {
		t.Fatalf("unexpected client authentication: %s", snapshot.ClientAuthentication())
	}
	for kind, wantURL := range map[EndpointKind]string{
		EndpointToken: testToken, EndpointUserInfo: testUserInfo,
		EndpointRevocation: testRevocation, EndpointEndSession: testEndSession,
	} {
		pinned, pinErr := snapshot.PinnedEndpoint(kind)
		if pinErr != nil || pinned.Kind() != kind || pinned.URL() != wantURL ||
			pinned.Target() == (federatedhttp.Target{}) {
			t.Fatalf("PinnedEndpoint(%q) = %v, %v", kind, pinned, pinErr)
		}
	}
	wantCompiled := []string{
		testIssuer,
		testIssuer + "/.well-known/openid-configuration",
		testAuthorization,
		testToken,
		testJWKS,
		testUserInfo,
		testRevocation,
		testEndSession,
	}
	if !slices.Equal(fake.compileURLs, wantCompiled) {
		t.Fatalf("compiled URLs = %q, want %q", fake.compileURLs, wantCompiled)
	}
	if fake.fetchCalls != 1 || !slices.Equal(fake.results[0].Body, document) {
		t.Fatal("fetch ownership did not preserve the fake's source fixture")
	}
}

func TestFetchDiscoveryAcceptsProtocolDefaultsAndClientSecretPost(t *testing.T) {
	object := validDiscoveryObject()
	delete(object, "response_modes_supported")
	delete(object, "grant_types_supported")
	delete(object, "scopes_supported")
	delete(object, "userinfo_endpoint")
	delete(object, "revocation_endpoint")
	delete(object, "end_session_endpoint")
	document := marshalJSON(t, object)
	client, fake := newTrustTestClient(t, []federatedhttp.Result{
		successfulResult(federatedhttp.DocumentOIDCDiscovery, document),
	}, nil)
	request := validDiscoveryRequest()
	request.Policy.ClientAuthentication = ClientSecretPost
	snapshot, err := client.FetchDiscovery(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Endpoints().UserInfo != "" || snapshot.Endpoints().Revocation != "" ||
		snapshot.Endpoints().EndSession != "" {
		t.Fatal("absent optional endpoints were not preserved as absent")
	}
	if snapshot.ClientAuthentication() != ClientSecretPost {
		t.Fatalf("client authentication = %s", snapshot.ClientAuthentication())
	}
	if len(fake.compileURLs) != 5 {
		t.Fatalf("optional endpoints unexpectedly compiled: %v", fake.compileURLs)
	}
	if _, err := snapshot.PinnedEndpoint(EndpointRevocation); !errors.Is(err, ErrUpstreamArtifactRejected) {
		t.Fatalf("absent optional endpoint = %v", err)
	}
}

func TestFetchDiscoveryRejectsInvalidRequestsBeforeNetwork(t *testing.T) {
	valid := validDiscoveryRequest()
	tests := map[string]struct {
		ctx     context.Context
		request DiscoveryRequest
	}{
		"nil context":       {ctx: nil, request: valid},
		"zero revision":     {ctx: context.Background(), request: func() DiscoveryRequest { value := valid; value.Revision = 0; return value }()},
		"invalid issuer":    {ctx: context.Background(), request: func() DiscoveryRequest { value := valid; value.Issuer = "http://provider.example"; return value }()},
		"missing auth mode": {ctx: context.Background(), request: func() DiscoveryRequest { value := valid; value.Policy.ClientAuthentication = ""; return value }()},
		"duplicate alg": {ctx: context.Background(), request: func() DiscoveryRequest {
			value := valid
			value.Policy.SigningAlgorithms = []SigningAlgorithm{SigningRS256, SigningRS256}
			return value
		}()},
		"unsupported alg": {ctx: context.Background(), request: func() DiscoveryRequest {
			value := valid
			value.Policy.SigningAlgorithms = []SigningAlgorithm{"none"}
			return value
		}()},
		"missing alg": {ctx: context.Background(), request: func() DiscoveryRequest { value := valid; value.Policy.SigningAlgorithms = nil; return value }()},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			client, fake := newTrustTestClient(t, nil, nil)
			if _, err := client.FetchDiscovery(test.ctx, test.request); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("got %v", err)
			}
			if fake.fetchCalls != 0 {
				t.Fatal("invalid request reached network boundary")
			}
		})
	}
}

func TestFetchDiscoverySanitizesFetchFailures(t *testing.T) {
	client, fake := newTrustTestClient(t, nil, nil)
	fake.fetchErrors = []error{errors.New(testHostileSentinel)}
	_, err := client.FetchDiscovery(context.Background(), validDiscoveryRequest())
	if !errors.Is(err, ErrDiscoveryFetch) {
		t.Fatalf("got %v", err)
	}
	var failure FetchFailure
	if !errors.As(err, &failure) || failure.Category() != federatedhttp.CategoryResponseFailed {
		t.Fatalf("unexpected fetch failure: %v", err)
	}
	if strings.Contains(err.Error(), testHostileSentinel) || strings.Contains(failure.String(), testHostileSentinel) {
		t.Fatal("fetch error leaked upstream detail")
	}

	client, _ = newTrustTestClient(t, []federatedhttp.Result{{
		Category: federatedhttp.CategoryDNSFailed,
		Kind:     federatedhttp.DocumentOIDCDiscovery,
	}}, nil)
	_, err = client.FetchDiscovery(context.Background(), validDiscoveryRequest())
	if !errors.Is(err, ErrDiscoveryFetch) || !errors.As(err, &failure) ||
		failure.Category() != federatedhttp.CategoryDNSFailed {
		t.Fatalf("unexpected categorized failure: %v", err)
	}

	client, _ = newTrustTestClient(t, []federatedhttp.Result{{
		Category: federatedhttp.Category(testHostileSentinel),
		Kind:     federatedhttp.DocumentOIDCDiscovery,
	}}, nil)
	_, err = client.FetchDiscovery(context.Background(), validDiscoveryRequest())
	if !errors.As(err, &failure) || failure.Category() != federatedhttp.CategoryResponseFailed {
		t.Fatalf("unknown category was not sanitized: %v", err)
	}
}

func TestFetchDiscoveryRejectsMalformedBoundaryProjection(t *testing.T) {
	document := validDiscoveryDocument(t)
	valid := successfulResult(federatedhttp.DocumentOIDCDiscovery, document)
	tests := map[string]func(*federatedhttp.Result){
		"wrong kind":    func(value *federatedhttp.Result) { value.Kind = federatedhttp.DocumentOIDCJWKS },
		"empty body":    func(value *federatedhttp.Result) { value.Body = nil; value.Digest = sha256.Sum256(nil) },
		"wrong digest":  func(value *federatedhttp.Result) { value.Digest = [sha256.Size]byte{} },
		"missing cache": func(value *federatedhttp.Result) { value.Cache = federatedhttp.CacheMetadata{} },
		"cache before retrieval": func(value *federatedhttp.Result) {
			value.Cache.FreshUntil = value.Cache.RetrievedAt.Add(-time.Second)
		},
		"cache beyond cap": func(value *federatedhttp.Result) {
			value.Cache.FreshUntil = value.Cache.RetrievedAt.Add(8 * 24 * time.Hour)
		},
		"inconsistent no-store cache": func(value *federatedhttp.Result) {
			value.Cache.Cacheable = false
			value.Cache.MustRevalidate = false
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			result := valid
			result.Body = append([]byte(nil), valid.Body...)
			mutate(&result)
			client, _ := newTrustTestClient(t, []federatedhttp.Result{result}, nil)
			if _, err := client.FetchDiscovery(context.Background(), validDiscoveryRequest()); !errors.Is(err, ErrDiscoveryRejected) {
				t.Fatalf("got %v", err)
			}
		})
	}
}
