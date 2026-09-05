package federatedoidc

import (
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
)

const (
	testIssuer          = "https://provider.example/tenant"
	testAuthorization   = "https://provider.example/tenant/authorize"
	testToken           = "https://provider.example/tenant/token"
	testJWKS            = "https://keys.example/tenant/jwks"
	testUserInfo        = "https://provider.example/tenant/userinfo"
	testRevocation      = "https://provider.example/tenant/revoke"
	testEndSession      = "https://provider.example/tenant/logout"
	testDiscoveryRev    = uint64(41)
	testJWKSRev         = uint64(77)
	testHostileSentinel = "hostile-secret-canary.example/private"
)

var testRetrievedAt = time.Date(2026, time.August, 25, 10, 30, 0, 0, time.UTC)

type testResolver struct{}

func (testResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, nil
}

type testDialer struct{}

func (testDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("test dial disabled")
}

type fakeTrustHTTP struct {
	compiler    *federatedhttp.Client
	results     []federatedhttp.Result
	fetchErrors []error
	compileURLs []string
	fetchCalls  int
}

func (fake *fakeTrustHTTP) CompileTarget(
	kind federatedhttp.DocumentKind,
	rawURL string,
) (federatedhttp.Target, error) {
	fake.compileURLs = append(fake.compileURLs, rawURL)
	return fake.compiler.CompileTarget(kind, rawURL)
}

func (fake *fakeTrustHTTP) Fetch(
	ctx context.Context,
	target federatedhttp.Target,
	authorization []byte,
) (federatedhttp.Result, error) {
	if ctx == nil || len(authorization) != 0 || target.String() == "" {
		return federatedhttp.Result{}, errors.New("invalid fake fetch")
	}
	index := fake.fetchCalls
	fake.fetchCalls++
	if index < len(fake.fetchErrors) && fake.fetchErrors[index] != nil {
		return federatedhttp.Result{}, fake.fetchErrors[index]
	}
	if index >= len(fake.results) {
		return federatedhttp.Result{}, errors.New("unexpected fake fetch")
	}
	result := fake.results[index]
	result.Body = append([]byte(nil), result.Body...)
	return result, nil
}

func newCompiler(t *testing.T) *federatedhttp.Client {
	t.Helper()
	policy, err := federatedhttp.NewDeploymentEgressPolicy(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := federatedhttp.New(federatedhttp.Options{
		Resolver:      testResolver{},
		Dialer:        testDialer{},
		EgressPolicy:  policy,
		RootCAs:       x509.NewCertPool(),
		Limits:        federatedhttp.DefaultLimits(),
		MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func newTrustTestClient(
	t *testing.T,
	results []federatedhttp.Result,
	mutateLimits func(*Limits),
) (*Client, *fakeTrustHTTP) {
	t.Helper()
	limits := DefaultLimits()
	if mutateLimits != nil {
		mutateLimits(&limits)
	}
	fake := &fakeTrustHTTP{compiler: newCompiler(t), results: results}
	client, err := newClient(fake, limits)
	if err != nil {
		t.Fatal(err)
	}
	return client, fake
}

func successfulResult(kind federatedhttp.DocumentKind, body []byte) federatedhttp.Result {
	return federatedhttp.Result{
		Category: federatedhttp.CategorySuccess,
		Kind:     kind,
		Body:     append([]byte(nil), body...),
		Digest:   sha256.Sum256(body),
		Cache: federatedhttp.CacheMetadata{
			RetrievedAt: testRetrievedAt,
			FreshUntil:  testRetrievedAt.Add(10 * time.Minute),
			Cacheable:   true,
		},
	}
}

func validDiscoveryObject() map[string]any {
	return map[string]any{
		"issuer":                                testIssuer,
		"authorization_endpoint":                testAuthorization,
		"token_endpoint":                        testToken,
		"jwks_uri":                              testJWKS,
		"userinfo_endpoint":                     testUserInfo,
		"revocation_endpoint":                   testRevocation,
		"end_session_endpoint":                  testEndSession,
		"response_types_supported":              []string{ResponseTypeCode},
		"response_modes_supported":              []string{ResponseModeQuery},
		"grant_types_supported":                 []string{GrantAuthorizationCode},
		"code_challenge_methods_supported":      []string{CodeChallengeS256},
		"token_endpoint_auth_methods_supported": []string{string(ClientSecretBasic), string(ClientSecretPost)},
		"subject_types_supported":               []string{"public", "pairwise"},
		"scopes_supported":                      []string{RequiredScopeOpenID, "profile"},
		"id_token_signing_alg_values_supported": []string{string(SigningRS256), string(SigningES256), string(SigningEdDSA)},
	}
}

func marshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func validDiscoveryDocument(t *testing.T) []byte {
	t.Helper()
	return marshalJSON(t, validDiscoveryObject())
}

func validDiscoveryRequest() DiscoveryRequest {
	return DiscoveryRequest{
		Issuer:   testIssuer,
		Revision: testDiscoveryRev,
		Policy: TrustPolicy{
			ClientAuthentication: ClientSecretBasic,
			SigningAlgorithms:    []SigningAlgorithm{SigningEdDSA, SigningRS256, SigningES256},
		},
	}
}

func rsaJWK(keyID string, algorithm SigningAlgorithm) map[string]any {
	modulus := make([]byte, minimumRSAKeyBits/8)
	modulus[0] = 0x80
	modulus[len(modulus)-1] = 0x01
	return map[string]any{
		"kty": "RSA",
		"kid": keyID,
		"use": "sig",
		"alg": string(algorithm),
		"n":   base64.RawURLEncoding.EncodeToString(modulus),
		"e":   "AQAB",
	}
}

func ecJWK(keyID string, algorithm SigningAlgorithm) map[string]any {
	curve := elliptic.P256()
	curveName := "P-256"
	coordinateBytes := 32
	switch algorithm {
	case SigningES384:
		curve = elliptic.P384()
		curveName = "P-384"
		coordinateBytes = 48
	case SigningES512:
		curve = elliptic.P521()
		curveName = "P-521"
		coordinateBytes = 66
	}
	return map[string]any{
		"kty": "EC",
		"kid": keyID,
		"use": "sig",
		"alg": string(algorithm),
		"crv": curveName,
		"x":   base64.RawURLEncoding.EncodeToString(curve.Params().Gx.FillBytes(make([]byte, coordinateBytes))),
		"y":   base64.RawURLEncoding.EncodeToString(curve.Params().Gy.FillBytes(make([]byte, coordinateBytes))),
	}
}

func ed25519Material() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte("federatedoidc deterministic test key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func ed25519JWK(keyID string) map[string]any {
	publicKey, _ := ed25519Material()
	return map[string]any{
		"kty": "OKP",
		"kid": keyID,
		"use": "sig",
		"alg": string(SigningEdDSA),
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(publicKey),
	}
}

func ed25519Certificate(t *testing.T) string {
	t.Helper()
	publicKey, privateKey := ed25519Material()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		Subject: pkix.Name{
			CommonName:   "federatedoidc test signing key",
			Organization: []string{"Periapsis deterministic test fixture"},
		},
		DNSNames:              []string{"provider.example"},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(nil, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func validJWKSDocument(t *testing.T) []byte {
	t.Helper()
	edKey := ed25519JWK("key-ed25519-primary")
	edKey["key_ops"] = []string{"verify"}
	edKey["x5c"] = []string{ed25519Certificate(t)}
	return marshalJSON(t, map[string]any{
		"keys": []any{
			rsaJWK("key-rsa-primary", SigningRS256),
			ecJWK("key-ec-primary", SigningES256),
			edKey,
		},
	})
}

func fetchValidDiscovery(t *testing.T, client *Client) DiscoverySnapshot {
	t.Helper()
	snapshot, err := client.FetchDiscovery(context.Background(), validDiscoveryRequest())
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}
