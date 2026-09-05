package federatedoidc

import (
	"crypto/sha256"

	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
)

// DiscoverySnapshotRecord is the bounded public trust document persisted for
// one immutable discovery revision. Document contains no credential material;
// callers retain ownership and the compiler does not retain the supplied
// slice. Digest and Cache are independently checked before a snapshot is
// reconstructed.
type DiscoverySnapshotRecord struct {
	Request  DiscoveryRequest
	Document []byte `json:"-"`
	Digest   [sha256.Size]byte
	Cache    federatedhttp.CacheMetadata
}

// JWKSSnapshotRecord is the bounded public key document persisted for one
// immutable JWKS revision. Discovery must be the exact reconstructed parent
// snapshot selected by the authentication transaction.
type JWKSSnapshotRecord struct {
	Revision  uint64
	Document  []byte `json:"-"`
	Digest    [sha256.Size]byte
	Cache     federatedhttp.CacheMetadata
	Discovery DiscoverySnapshot
}

// RestoreDiscovery reconstructs an immutable snapshot from a previously
// accepted document without network I/O. It re-runs every parser, issuer,
// endpoint, algorithm, SSRF target, digest, cache, and size check; persisted
// summaries are never trusted as executable configuration.
func (client *Client) RestoreDiscovery(record DiscoverySnapshotRecord) (DiscoverySnapshot, error) {
	if client == nil || client.http == nil || record.Request.Revision == 0 ||
		len(record.Document) == 0 || len(record.Document) > client.limits.MaxDiscoveryBytes ||
		record.Digest == ([sha256.Size]byte{}) || record.Digest != sha256.Sum256(record.Document) ||
		!validCache(record.Cache) {
		return DiscoverySnapshot{}, ErrInvalidSnapshot
	}
	policy, err := normalizeTrustPolicy(record.Request.Policy)
	if err != nil {
		return DiscoverySnapshot{}, ErrInvalidSnapshot
	}
	if _, err = client.http.CompileTarget(federatedhttp.DocumentOIDCDiscovery, record.Request.Issuer); err != nil {
		return DiscoverySnapshot{}, ErrInvalidSnapshot
	}
	parsed, err := client.parseDiscovery(record.Document, record.Request.Issuer, policy)
	if err != nil {
		return DiscoverySnapshot{}, ErrInvalidSnapshot
	}
	return DiscoverySnapshot{
		revision: record.Request.Revision, digest: record.Digest, cache: record.Cache,
		issuer: record.Request.Issuer, endpoints: parsed.endpoints,
		clientAuthentication: policy.ClientAuthentication,
		signingAlgorithms:    append([]SigningAlgorithm(nil), parsed.signingAlgorithms...),
		targets:              parsed.targets,
		valid:                true,
	}, nil
}

// RestoreJWKS reconstructs one exact verification-key snapshot without
// network I/O. The document is parsed afresh against the parent discovery
// algorithm allowlist and is never retained by the returned snapshot.
func (client *Client) RestoreJWKS(record JWKSSnapshotRecord) (JWKSSnapshot, error) {
	if client == nil || client.http == nil || record.Revision == 0 ||
		!record.Discovery.validSnapshot() || len(record.Document) == 0 ||
		len(record.Document) > client.limits.MaxJWKSBytes ||
		record.Digest == ([sha256.Size]byte{}) || record.Digest != sha256.Sum256(record.Document) ||
		!validCache(record.Cache) {
		return JWKSSnapshot{}, ErrInvalidSnapshot
	}
	summaries, keys, err := client.parseJWKS(record.Document, record.Discovery.signingAlgorithms)
	if err != nil {
		return JWKSSnapshot{}, ErrInvalidSnapshot
	}
	return JWKSSnapshot{
		revision: record.Revision, discoveryRevision: record.Discovery.revision,
		discoveryDigest: record.Discovery.digest, digest: record.Digest, cache: record.Cache,
		summaries: summaries, keys: keys, valid: true,
	}, nil
}
