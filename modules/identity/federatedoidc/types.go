// Package federatedoidc builds immutable, bounded OIDC trust snapshots and a
// deny-by-default Authorization Code with S256 PKCE ceremony kernel. Network,
// secret protection, and persistence effects remain behind narrow
// deployment-owned ports.
package federatedoidc

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
)

const (
	minimumDiscoveryBytes = 512
	maximumDiscoveryBytes = 1024 * 1024
	minimumJWKSBytes      = 512
	maximumJWKSBytes      = 4 * 1024 * 1024

	minimumJSONDepth         = 2
	maximumJSONDepth         = 16
	minimumJSONValues        = 16
	maximumJSONValues        = 32 * 1024
	minimumJSONObjectMembers = 8
	maximumJSONObjectMembers = 16 * 1024
	minimumJSONArrayItems    = 8
	maximumJSONArrayItems    = 16 * 1024
	minimumJSONStringBytes   = 128
	maximumJSONStringBytes   = 1024 * 1024

	minimumKeys                = 1
	maximumKeys                = 128
	maximumCertificates        = 256
	maximumCertificatesPerKey  = 8
	minimumCertificateBytes    = 256
	maximumCertificateBytes    = 64 * 1024
	minimumKeyIDBytes          = 16
	maximumKeyIDBytes          = 512
	maximumMetadataArrayItems  = 64
	maximumMetadataStringBytes = 4096
	maximumRSAKeyBits          = 8192
	minimumRSAKeyBits          = 2048
)

var (
	ErrInvalidOptions    = errors.New("invalid OIDC trust-document options")
	ErrInvalidRequest    = errors.New("invalid OIDC trust-document request")
	ErrDiscoveryFetch    = errors.New("OIDC discovery fetch failed")
	ErrDiscoveryRejected = errors.New("OIDC discovery document rejected")
	ErrIssuerMismatch    = errors.New("OIDC discovery issuer mismatch")
	ErrJWKSFetch         = errors.New("OIDC JWKS fetch failed")
	ErrJWKSRejected      = errors.New("OIDC JWKS document rejected")
	ErrInvalidSnapshot   = errors.New("invalid OIDC trust snapshot")
)

// ClientAuthenticationMode is the closed confidential-client profile.
type ClientAuthenticationMode string

const (
	ClientSecretBasic ClientAuthenticationMode = "client_secret_basic"
	ClientSecretPost  ClientAuthenticationMode = "client_secret_post"
)

// SigningAlgorithm is the closed asymmetric ID-token signature set admitted
// by go-oidc v3.20.0 and go-jose v4.1.4. Its zero value is invalid.
type SigningAlgorithm string

const (
	SigningRS256 SigningAlgorithm = oidc.RS256
	SigningRS384 SigningAlgorithm = oidc.RS384
	SigningRS512 SigningAlgorithm = oidc.RS512
	SigningPS256 SigningAlgorithm = oidc.PS256
	SigningPS384 SigningAlgorithm = oidc.PS384
	SigningPS512 SigningAlgorithm = oidc.PS512
	SigningES256 SigningAlgorithm = oidc.ES256
	SigningES384 SigningAlgorithm = oidc.ES384
	SigningES512 SigningAlgorithm = oidc.ES512
	SigningEdDSA SigningAlgorithm = oidc.EdDSA
)

const (
	ResponseTypeCode       = "code"
	ResponseModeQuery      = "query"
	GrantAuthorizationCode = "authorization_code"
	CodeChallengeS256      = "S256"
	RequiredScopeOpenID    = oidc.ScopeOpenID
)

// KeyType is a safe summary category, never public-key material.
type KeyType string

const (
	KeyTypeRSA     KeyType = "RSA"
	KeyTypeEC      KeyType = "EC"
	KeyTypeEd25519 KeyType = "OKP"
)

// Limits are deployment-owned parsing ceilings applied after the independent
// federated HTTP byte/decompression boundary.
type Limits struct {
	MaxDiscoveryBytes     int
	MaxJWKSBytes          int
	MaxJSONDepth          int
	MaxJSONValues         int
	MaxJSONObjectMembers  int
	MaxJSONArrayItems     int
	MaxJSONStringBytes    int
	MaxKeys               int
	MaxCertificates       int
	MaxCertificatesPerKey int
	MaxCertificateBytes   int
	MaxKeyIDBytes         int
}

// DefaultLimits returns conservative discovery and JWKS parser ceilings.
func DefaultLimits() Limits {
	return Limits{
		MaxDiscoveryBytes:     64 * 1024,
		MaxJWKSBytes:          512 * 1024,
		MaxJSONDepth:          8,
		MaxJSONValues:         4096,
		MaxJSONObjectMembers:  2048,
		MaxJSONArrayItems:     2048,
		MaxJSONStringBytes:    64 * 1024,
		MaxKeys:               32,
		MaxCertificates:       32,
		MaxCertificatesPerKey: 4,
		MaxCertificateBytes:   16 * 1024,
		MaxKeyIDBytes:         128,
	}
}

// Options accepts only the concrete deployment-owned federated HTTP client;
// callers cannot inject a tenant-specific transport or resolver.
type Options struct {
	HTTP   *federatedhttp.Client
	Limits Limits
}

// TrustPolicy is provider configuration pinned into a discovery snapshot.
type TrustPolicy struct {
	ClientAuthentication ClientAuthenticationMode
	SigningAlgorithms    []SigningAlgorithm
}

// DiscoveryRequest identifies one exact configured issuer and immutable
// provider/configuration revision.
type DiscoveryRequest struct {
	Issuer   string
	Revision uint64
	Policy   TrustPolicy
}

// Endpoints are exact canonical strings already compiled by federatedhttp.
// Optional endpoints are empty when discovery did not advertise them.
type Endpoints struct {
	Authorization string
	Token         string
	JWKS          string
	UserInfo      string
	Revocation    string
	EndSession    string
}

// DiscoverySnapshot is immutable after construction. Slice-valued data stays
// private and accessors return defensive copies.
type DiscoverySnapshot struct {
	revision             uint64
	digest               [sha256.Size]byte
	cache                federatedhttp.CacheMetadata
	issuer               string
	endpoints            Endpoints
	clientAuthentication ClientAuthenticationMode
	signingAlgorithms    []SigningAlgorithm
	targets              discoveryEndpointTargets
	valid                bool
}

type discoveryEndpointTargets struct {
	authorization federatedhttp.Target
	token         federatedhttp.Target
	jwks          federatedhttp.Target
	userinfo      federatedhttp.Target
	revocation    federatedhttp.Target
	endSession    federatedhttp.Target
	count         int
}

func (snapshot DiscoverySnapshot) Revision() uint64                   { return snapshot.revision }
func (snapshot DiscoverySnapshot) Digest() [sha256.Size]byte          { return snapshot.digest }
func (snapshot DiscoverySnapshot) Cache() federatedhttp.CacheMetadata { return snapshot.cache }
func (snapshot DiscoverySnapshot) Issuer() string                     { return snapshot.issuer }
func (snapshot DiscoverySnapshot) Endpoints() Endpoints               { return snapshot.endpoints }
func (snapshot DiscoverySnapshot) ClientAuthentication() ClientAuthenticationMode {
	return snapshot.clientAuthentication
}
func (snapshot DiscoverySnapshot) SigningAlgorithms() []SigningAlgorithm {
	return append([]SigningAlgorithm(nil), snapshot.signingAlgorithms...)
}

// PinnedEndpoint returns one endpoint together with its already compiled
// resolver/DNS/TLS target. It is the only supported reconstruction path for
// persistent application jobs such as refresh and logout retries.
func (snapshot DiscoverySnapshot) PinnedEndpoint(kind EndpointKind) (PinnedEndpoint, error) {
	if !snapshot.validSnapshot() {
		return PinnedEndpoint{}, ErrInvalidSnapshot
	}
	var rawURL string
	var target federatedhttp.Target
	switch kind {
	case EndpointToken:
		rawURL, target = snapshot.endpoints.Token, snapshot.targets.token
	case EndpointUserInfo:
		rawURL, target = snapshot.endpoints.UserInfo, snapshot.targets.userinfo
	case EndpointRevocation:
		rawURL, target = snapshot.endpoints.Revocation, snapshot.targets.revocation
	case EndpointEndSession:
		rawURL, target = snapshot.endpoints.EndSession, snapshot.targets.endSession
	default:
		return PinnedEndpoint{}, ErrUpstreamArtifactRejected
	}
	if rawURL == "" || target == (federatedhttp.Target{}) {
		return PinnedEndpoint{}, ErrUpstreamArtifactRejected
	}
	return newPinnedEndpoint(kind, rawURL, target), nil
}

// KeySummary contains only bounded identifiers and public-key metadata.
type KeySummary struct {
	KeyID            string
	Algorithm        SigningAlgorithm
	Type             KeyType
	Curve            string
	Bits             int
	CertificateCount int
	ThumbprintSHA256 [sha256.Size]byte
}

// JWKSSnapshot pins parsed public verification keys to one discovery snapshot.
// Raw JSON and endpoint URLs are not retained.
type JWKSSnapshot struct {
	revision          uint64
	discoveryRevision uint64
	discoveryDigest   [sha256.Size]byte
	digest            [sha256.Size]byte
	cache             federatedhttp.CacheMetadata
	summaries         []KeySummary
	keys              []jose.JSONWebKey
	valid             bool
}

func (snapshot JWKSSnapshot) Revision() uint64                   { return snapshot.revision }
func (snapshot JWKSSnapshot) DiscoveryRevision() uint64          { return snapshot.discoveryRevision }
func (snapshot JWKSSnapshot) DiscoveryDigest() [sha256.Size]byte { return snapshot.discoveryDigest }
func (snapshot JWKSSnapshot) Digest() [sha256.Size]byte          { return snapshot.digest }
func (snapshot JWKSSnapshot) Cache() federatedhttp.CacheMetadata { return snapshot.cache }
func (snapshot JWKSSnapshot) KeySummaries() []KeySummary {
	return append([]KeySummary(nil), snapshot.summaries...)
}
func (snapshot JWKSSnapshot) KeyCount() int { return len(snapshot.summaries) }

func (snapshot JWKSSnapshot) validSnapshot() bool {
	if !snapshot.valid || snapshot.revision == 0 || snapshot.discoveryRevision == 0 ||
		snapshot.discoveryDigest == ([sha256.Size]byte{}) || snapshot.digest == ([sha256.Size]byte{}) ||
		!validCache(snapshot.cache) || len(snapshot.summaries) == 0 ||
		len(snapshot.summaries) != len(snapshot.keys) {
		return false
	}
	for index, summary := range snapshot.summaries {
		if summary.KeyID == "" || !supportedSigningAlgorithm(summary.Algorithm) ||
			summary.ThumbprintSHA256 == ([sha256.Size]byte{}) || index > 0 &&
			snapshot.summaries[index-1].KeyID >= summary.KeyID || !snapshot.keys[index].Valid() ||
			!snapshot.keys[index].IsPublic() || snapshot.keys[index].KeyID != summary.KeyID ||
			snapshot.keys[index].Algorithm != string(summary.Algorithm) {
			return false
		}
	}
	return true
}

// FetchFailure exposes only a stable document class and federatedhttp category.
type FetchFailure struct {
	document fetchDocument
	category federatedhttp.Category
}

type fetchDocument uint8

const (
	fetchDiscovery fetchDocument = iota + 1
	fetchJWKS
)

func (failure FetchFailure) Error() string                    { return "OIDC trust document fetch failed" }
func (failure FetchFailure) Category() federatedhttp.Category { return failure.category }
func (failure FetchFailure) Is(target error) bool {
	return failure.document == fetchDiscovery && target == ErrDiscoveryFetch ||
		failure.document == fetchJWKS && target == ErrJWKSFetch
}

type trustHTTP interface {
	CompileTarget(federatedhttp.DocumentKind, string) (federatedhttp.Target, error)
	Fetch(context.Context, federatedhttp.Target, []byte) (federatedhttp.Result, error)
}

// Client owns one concrete SSRF boundary and immutable parsing limits.
type Client struct {
	http   trustHTTP
	limits Limits
}

func (snapshot DiscoverySnapshot) validSnapshot() bool {
	zeroTarget := federatedhttp.Target{}
	optionalCount := 0
	for _, optional := range []struct {
		url    string
		target federatedhttp.Target
	}{
		{snapshot.endpoints.UserInfo, snapshot.targets.userinfo},
		{snapshot.endpoints.Revocation, snapshot.targets.revocation},
		{snapshot.endpoints.EndSession, snapshot.targets.endSession},
	} {
		if (optional.url == "") != (optional.target == zeroTarget) {
			return false
		}
		if optional.url != "" {
			optionalCount++
		}
	}
	return snapshot.valid && snapshot.revision != 0 && snapshot.digest != ([sha256.Size]byte{}) &&
		validCache(snapshot.cache) && snapshot.issuer != "" && validClientAuthentication(snapshot.clientAuthentication) &&
		validSnapshotAlgorithms(snapshot.signingAlgorithms) && snapshot.endpoints.Authorization != "" &&
		snapshot.endpoints.Token != "" && snapshot.endpoints.JWKS != "" &&
		snapshot.targets.authorization != zeroTarget && snapshot.targets.token != zeroTarget &&
		snapshot.targets.jwks != zeroTarget && snapshot.targets.count == 3+optionalCount
}

func validSnapshotAlgorithms(algorithms []SigningAlgorithm) bool {
	if len(algorithms) == 0 || len(algorithms) > 10 {
		return false
	}
	for index, algorithm := range algorithms {
		if !supportedSigningAlgorithm(algorithm) || index > 0 && algorithms[index-1] >= algorithm {
			return false
		}
	}
	return true
}

func validCache(cache federatedhttp.CacheMetadata) bool {
	if cache.RetrievedAt.IsZero() || cache.FreshUntil.IsZero() ||
		cache.FreshUntil.Before(cache.RetrievedAt) ||
		cache.FreshUntil.After(cache.RetrievedAt.Add(7*24*time.Hour)) {
		return false
	}
	return cache.Cacheable || (cache.MustRevalidate && cache.FreshUntil.Equal(cache.RetrievedAt))
}

func validClientAuthentication(mode ClientAuthenticationMode) bool {
	return mode == ClientSecretBasic || mode == ClientSecretPost
}
