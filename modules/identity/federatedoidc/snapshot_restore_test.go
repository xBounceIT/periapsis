package federatedoidc

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
)

func TestRestoreTrustSnapshotsReparsesPinnedDocumentsWithoutNetwork(t *testing.T) {
	discoveryDocument := validDiscoveryDocument(t)
	jwksDocument := validJWKSDocument(t)
	client, boundary := newTrustTestClient(t, nil, nil)
	cache := federatedhttp.CacheMetadata{
		RetrievedAt: testRetrievedAt, FreshUntil: testRetrievedAt.Add(10 * time.Minute), Cacheable: true,
	}
	discovery, err := client.RestoreDiscovery(DiscoverySnapshotRecord{
		Request: validDiscoveryRequest(), Document: discoveryDocument,
		Digest: sha256.Sum256(discoveryDocument), Cache: cache,
	})
	if err != nil {
		t.Fatalf("RestoreDiscovery() error = %v", err)
	}
	keys, err := client.RestoreJWKS(JWKSSnapshotRecord{
		Revision: testJWKSRev, Document: jwksDocument, Digest: sha256.Sum256(jwksDocument),
		Cache: cache, Discovery: discovery,
	})
	if err != nil {
		t.Fatalf("RestoreJWKS() error = %v", err)
	}
	if boundary.fetchCalls != 0 || discovery.Revision() != testDiscoveryRev ||
		discovery.Digest() != sha256.Sum256(discoveryDocument) || keys.Revision() != testJWKSRev ||
		keys.DiscoveryRevision() != discovery.Revision() || keys.DiscoveryDigest() != discovery.Digest() ||
		keys.Digest() != sha256.Sum256(jwksDocument) || keys.KeyCount() != 3 {
		t.Fatalf("restored snapshots mismatch: discovery=%s keys=%s fetches=%d", discovery, keys, boundary.fetchCalls)
	}
	if len(boundary.compileURLs) != 7 {
		t.Fatalf("compiled issuer/endpoint count = %d, want 7", len(boundary.compileURLs))
	}

	discoveryDocument[0] ^= 0xff
	jwksDocument[0] ^= 0xff
	if discovery.Issuer() != testIssuer || keys.KeyCount() != 3 {
		t.Fatal("restored snapshots retained mutable document storage")
	}
}

func TestRestoreTrustSnapshotsRejectsTamperDriftAndHostileDocuments(t *testing.T) {
	discoveryDocument := validDiscoveryDocument(t)
	jwksDocument := validJWKSDocument(t)
	client, _ := newTrustTestClient(t, nil, nil)
	cache := federatedhttp.CacheMetadata{
		RetrievedAt: testRetrievedAt, FreshUntil: testRetrievedAt.Add(10 * time.Minute), Cacheable: true,
	}
	validDiscovery := DiscoverySnapshotRecord{
		Request: validDiscoveryRequest(), Document: discoveryDocument,
		Digest: sha256.Sum256(discoveryDocument), Cache: cache,
	}
	discovery, err := client.RestoreDiscovery(validDiscovery)
	if err != nil {
		t.Fatal(err)
	}

	discoveryCases := map[string]func(*DiscoverySnapshotRecord){
		"digest mismatch": func(value *DiscoverySnapshotRecord) { value.Digest[0] ^= 0xff },
		"issuer mismatch": func(value *DiscoverySnapshotRecord) {
			value.Request.Issuer = "https://other.example/tenant"
		},
		"duplicate member": func(value *DiscoverySnapshotRecord) {
			value.Document = []byte(`{"issuer":"https://provider.example/tenant","issuer":"https://provider.example/tenant"}`)
			value.Digest = sha256.Sum256(value.Document)
		},
		"invalid cache": func(value *DiscoverySnapshotRecord) { value.Cache.FreshUntil = time.Time{} },
		"zero revision": func(value *DiscoverySnapshotRecord) { value.Request.Revision = 0 },
	}
	for name, mutate := range discoveryCases {
		t.Run("discovery/"+name, func(t *testing.T) {
			candidate := validDiscovery
			candidate.Document = append([]byte(nil), validDiscovery.Document...)
			mutate(&candidate)
			if restored, restoreErr := client.RestoreDiscovery(candidate); restoreErr == nil ||
				restored.Revision() != 0 || strings.Contains(restoreErr.Error(), testIssuer) {
				t.Fatalf("RestoreDiscovery() = %s, %v", restored, restoreErr)
			}
		})
	}

	validKeys := JWKSSnapshotRecord{
		Revision: testJWKSRev, Document: jwksDocument, Digest: sha256.Sum256(jwksDocument),
		Cache: cache, Discovery: discovery,
	}
	keyCases := map[string]func(*JWKSSnapshotRecord){
		"digest mismatch": func(value *JWKSSnapshotRecord) { value.Digest[0] ^= 0xff },
		"duplicate kid": func(value *JWKSSnapshotRecord) {
			value.Document = []byte(`{"keys":[{"kid":"same"},{"kid":"same"}]}`)
			value.Digest = sha256.Sum256(value.Document)
		},
		"zero revision":     func(value *JWKSSnapshotRecord) { value.Revision = 0 },
		"invalid discovery": func(value *JWKSSnapshotRecord) { value.Discovery = DiscoverySnapshot{} },
	}
	for name, mutate := range keyCases {
		t.Run("jwks/"+name, func(t *testing.T) {
			candidate := validKeys
			candidate.Document = append([]byte(nil), validKeys.Document...)
			mutate(&candidate)
			if restored, restoreErr := client.RestoreJWKS(candidate); restoreErr == nil ||
				restored.Revision() != 0 || strings.Contains(restoreErr.Error(), "same") {
				t.Fatalf("RestoreJWKS() = %s, %v", restored, restoreErr)
			}
		})
	}
}
