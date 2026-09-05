package federatedoidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
)

func TestFetchJWKSBuildsImmutablePinnedSnapshot(t *testing.T) {
	discoveryDocument := validDiscoveryDocument(t)
	jwksDocument := validJWKSDocument(t)
	client, fake := newTrustTestClient(t, []federatedhttp.Result{
		successfulResult(federatedhttp.DocumentOIDCDiscovery, discoveryDocument),
		successfulResult(federatedhttp.DocumentOIDCJWKS, jwksDocument),
	}, nil)
	discovery := fetchValidDiscovery(t, client)
	compileCount := len(fake.compileURLs)
	snapshot, err := client.FetchJWKS(context.Background(), discovery, testJWKSRev)
	if err != nil {
		t.Fatal(err)
	}

	if snapshot.Revision() != testJWKSRev || snapshot.DiscoveryRevision() != testDiscoveryRev ||
		snapshot.DiscoveryDigest() != sha256.Sum256(discoveryDocument) ||
		snapshot.Digest() != sha256.Sum256(jwksDocument) || snapshot.Cache().RetrievedAt != testRetrievedAt {
		t.Fatal("JWKS snapshot did not pin its own and discovery revisions")
	}
	if snapshot.KeyCount() != 3 || len(snapshot.keys) != 3 {
		t.Fatalf("key count = %d", snapshot.KeyCount())
	}
	summaries := snapshot.KeySummaries()
	wantIDs := []string{"key-ec-primary", "key-ed25519-primary", "key-rsa-primary"}
	gotIDs := []string{summaries[0].KeyID, summaries[1].KeyID, summaries[2].KeyID}
	if !slices.Equal(gotIDs, wantIDs) {
		t.Fatalf("key order = %q, want %q", gotIDs, wantIDs)
	}
	if summaries[0].Type != KeyTypeEC || summaries[0].Curve != "P-256" || summaries[0].Bits != 256 ||
		summaries[1].Type != KeyTypeEd25519 || summaries[1].Curve != "Ed25519" || summaries[1].Bits != 256 ||
		summaries[1].CertificateCount != 1 || summaries[2].Type != KeyTypeRSA || summaries[2].Bits != 2048 {
		t.Fatalf("unexpected safe summaries: %v", summaries)
	}
	for _, summary := range summaries {
		if summary.ThumbprintSHA256 == ([sha256.Size]byte{}) {
			t.Fatal("missing key thumbprint")
		}
	}
	summaries[0].KeyID = testHostileSentinel
	if snapshot.KeySummaries()[0].KeyID != wantIDs[0] {
		t.Fatal("key summary accessor exposed mutable snapshot storage")
	}
	if len(fake.compileURLs) != compileCount {
		t.Fatal("JWKS fetch recompiled or rediscovered its pinned target")
	}
	if fake.fetchCalls != 2 || !slices.Equal(fake.results[1].Body, jwksDocument) {
		t.Fatal("JWKS fetch did not preserve caller-owned fixture storage")
	}
}

func TestParseJWKSAdmitsEveryConfiguredAsymmetricAlgorithm(t *testing.T) {
	tests := []struct {
		algorithm SigningAlgorithm
		key       func() map[string]any
		typeWant  KeyType
		bitsWant  int
	}{
		{SigningRS256, func() map[string]any { return rsaJWK("rsa-rs256", SigningRS256) }, KeyTypeRSA, 2048},
		{SigningRS384, func() map[string]any { return rsaJWK("rsa-rs384", SigningRS384) }, KeyTypeRSA, 2048},
		{SigningRS512, func() map[string]any { return rsaJWK("rsa-rs512", SigningRS512) }, KeyTypeRSA, 2048},
		{SigningPS256, func() map[string]any { return rsaJWK("rsa-ps256", SigningPS256) }, KeyTypeRSA, 2048},
		{SigningPS384, func() map[string]any { return rsaJWK("rsa-ps384", SigningPS384) }, KeyTypeRSA, 2048},
		{SigningPS512, func() map[string]any { return rsaJWK("rsa-ps512", SigningPS512) }, KeyTypeRSA, 2048},
		{SigningES256, func() map[string]any { return ecJWK("ec-es256", SigningES256) }, KeyTypeEC, 256},
		{SigningES384, func() map[string]any { return ecJWK("ec-es384", SigningES384) }, KeyTypeEC, 384},
		{SigningES512, func() map[string]any { return ecJWK("ec-es512", SigningES512) }, KeyTypeEC, 521},
		{SigningEdDSA, func() map[string]any { return ed25519JWK("okp-eddsa") }, KeyTypeEd25519, 256},
	}
	client, _ := newTrustTestClient(t, nil, nil)
	for _, test := range tests {
		t.Run(string(test.algorithm), func(t *testing.T) {
			document := jwksDocumentFromKeys(t, test.key())
			summaries, keys, err := client.parseJWKS(document, []SigningAlgorithm{test.algorithm})
			if err != nil {
				t.Fatal(err)
			}
			if len(summaries) != 1 || len(keys) != 1 || summaries[0].Algorithm != test.algorithm ||
				summaries[0].Type != test.typeWant || summaries[0].Bits != test.bitsWant {
				t.Fatalf("unexpected parsed key: %v", summaries)
			}
		})
	}
}

func TestFetchJWKSRejectsInvalidSnapshotAndRequestBeforeNetwork(t *testing.T) {
	client, fake := newTrustTestClient(t, nil, nil)
	invalidSnapshots := map[string]DiscoverySnapshot{
		"zero":            {},
		"flag":            {valid: true},
		"unsupported alg": validDiscoverySnapshotForUnit(t, func(value *DiscoverySnapshot) { value.signingAlgorithms = []SigningAlgorithm{"none"} }),
		"duplicate alg": validDiscoverySnapshotForUnit(t, func(value *DiscoverySnapshot) {
			value.signingAlgorithms = []SigningAlgorithm{SigningRS256, SigningRS256}
		}),
		"unsorted alg": validDiscoverySnapshotForUnit(t, func(value *DiscoverySnapshot) {
			value.signingAlgorithms = []SigningAlgorithm{SigningRS256, SigningES256}
		}),
		"missing digest": validDiscoverySnapshotForUnit(t, func(value *DiscoverySnapshot) {
			value.digest = [sha256.Size]byte{}
		}),
		"expired cache cap": validDiscoverySnapshotForUnit(t, func(value *DiscoverySnapshot) {
			value.cache.FreshUntil = value.cache.RetrievedAt.Add(8 * 24 * time.Hour)
		}),
	}
	for name, snapshot := range invalidSnapshots {
		t.Run(name, func(t *testing.T) {
			_, err := client.FetchJWKS(context.Background(), snapshot, testJWKSRev)
			if !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("got %v", err)
			}
		})
	}
	valid := validDiscoverySnapshotForUnit(t, nil)
	if _, err := client.FetchJWKS(nil, valid, testJWKSRev); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("nil context: %v", err)
	}
	if _, err := client.FetchJWKS(context.Background(), valid, 0); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("zero revision: %v", err)
	}
	if fake.fetchCalls != 0 {
		t.Fatal("invalid JWKS request reached network boundary")
	}
}

func TestFetchJWKSSanitizesFetchFailures(t *testing.T) {
	client, fake := newTrustTestClient(t, []federatedhttp.Result{
		successfulResult(federatedhttp.DocumentOIDCDiscovery, validDiscoveryDocument(t)),
	}, nil)
	discovery := fetchValidDiscovery(t, client)
	fake.fetchErrors = []error{nil, errors.New(testHostileSentinel)}
	_, err := client.FetchJWKS(context.Background(), discovery, testJWKSRev)
	if !errors.Is(err, ErrJWKSFetch) {
		t.Fatalf("got %v", err)
	}
	var failure FetchFailure
	if !errors.As(err, &failure) || failure.Category() != federatedhttp.CategoryResponseFailed ||
		strings.Contains(err.Error(), testHostileSentinel) || strings.Contains(failure.String(), testHostileSentinel) {
		t.Fatalf("unsafe fetch failure: %v", err)
	}

	client, _ = newTrustTestClient(t, []federatedhttp.Result{
		successfulResult(federatedhttp.DocumentOIDCDiscovery, validDiscoveryDocument(t)),
		{Category: federatedhttp.CategoryDestinationBlocked, Kind: federatedhttp.DocumentOIDCJWKS},
	}, nil)
	discovery = fetchValidDiscovery(t, client)
	_, err = client.FetchJWKS(context.Background(), discovery, testJWKSRev)
	if !errors.Is(err, ErrJWKSFetch) || !errors.As(err, &failure) ||
		failure.Category() != federatedhttp.CategoryDestinationBlocked {
		t.Fatalf("unexpected categorized failure: %v", err)
	}
}

func TestFetchJWKSRejectsMalformedBoundaryProjection(t *testing.T) {
	discoveryDocument := validDiscoveryDocument(t)
	jwksDocument := validJWKSDocument(t)
	valid := successfulResult(federatedhttp.DocumentOIDCJWKS, jwksDocument)
	tests := map[string]func(*federatedhttp.Result){
		"wrong kind":    func(value *federatedhttp.Result) { value.Kind = federatedhttp.DocumentOIDCDiscovery },
		"empty body":    func(value *federatedhttp.Result) { value.Body = nil; value.Digest = sha256.Sum256(nil) },
		"wrong digest":  func(value *federatedhttp.Result) { value.Digest = [sha256.Size]byte{} },
		"missing cache": func(value *federatedhttp.Result) { value.Cache = federatedhttp.CacheMetadata{} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			result := valid
			result.Body = append([]byte(nil), valid.Body...)
			mutate(&result)
			client, _ := newTrustTestClient(t, []federatedhttp.Result{
				successfulResult(federatedhttp.DocumentOIDCDiscovery, discoveryDocument),
				result,
			}, nil)
			discovery := fetchValidDiscovery(t, client)
			if _, err := client.FetchJWKS(context.Background(), discovery, testJWKSRev); !errors.Is(err, ErrJWKSRejected) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func validDiscoverySnapshotForUnit(t *testing.T, mutate func(*DiscoverySnapshot)) DiscoverySnapshot {
	t.Helper()
	client, _ := newTrustTestClient(t, []federatedhttp.Result{
		successfulResult(federatedhttp.DocumentOIDCDiscovery, validDiscoveryDocument(t)),
	}, nil)
	snapshot := fetchValidDiscovery(t, client)
	if mutate != nil {
		mutate(&snapshot)
	}
	return snapshot
}

func jwksDocumentFromKeys(t *testing.T, keys ...any) []byte {
	t.Helper()
	return marshalJSON(t, map[string]any{"keys": keys})
}

func rawJWKSWithKey(t *testing.T, key []byte) []byte {
	t.Helper()
	return []byte(`{"keys":[` + string(key) + `]}`)
}

func encodedExponent(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}
