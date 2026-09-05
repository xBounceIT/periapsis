package federatedoidc

import (
	"context"
	"testing"

	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
)

func TestSnapshotsPreserveValidNoStoreCacheDecision(t *testing.T) {
	discoveryResult := successfulResult(
		federatedhttp.DocumentOIDCDiscovery,
		validDiscoveryDocument(t),
	)
	discoveryResult.Cache.Cacheable = false
	discoveryResult.Cache.MustRevalidate = true
	discoveryResult.Cache.FreshUntil = discoveryResult.Cache.RetrievedAt
	jwksResult := successfulResult(
		federatedhttp.DocumentOIDCJWKS,
		validJWKSDocument(t),
	)
	jwksResult.Cache.Cacheable = false
	jwksResult.Cache.MustRevalidate = true
	jwksResult.Cache.FreshUntil = jwksResult.Cache.RetrievedAt

	client, _ := newTrustTestClient(t, []federatedhttp.Result{discoveryResult, jwksResult}, nil)
	discovery, err := client.FetchDiscovery(context.Background(), validDiscoveryRequest())
	if err != nil {
		t.Fatal(err)
	}
	if discovery.Cache() != discoveryResult.Cache {
		t.Fatalf("discovery cache = %v, want %v", discovery.Cache(), discoveryResult.Cache)
	}
	jwks, err := client.FetchJWKS(context.Background(), discovery, testJWKSRev)
	if err != nil {
		t.Fatal(err)
	}
	if jwks.Cache() != jwksResult.Cache {
		t.Fatalf("JWKS cache = %v, want %v", jwks.Cache(), jwksResult.Cache)
	}
}
