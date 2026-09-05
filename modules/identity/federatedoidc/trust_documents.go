package federatedoidc

import (
	"context"
	"crypto/sha256"
	"slices"

	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
)

// TrustDocumentRecords is the exact, already validated discovery/JWKS pair
// that an administration writer may persist. The caller owns both document
// buffers and must clear them after the database commit. No credential or
// provider response outside these bounded public documents is exposed.
type TrustDocumentRecords struct {
	Discovery DiscoverySnapshotRecord
	JWKS      JWKSSnapshotRecord
	KeyCount  int
}

// ValidateTrustDocumentRecords replays the complete restore path over a
// fetcher's output and attests every parent/revision/policy binding before the
// records cross a persistence boundary. The returned key count is derived
// from the reparsed JWKS; callers must not trust the transport-reported count.
func (client *Client) ValidateTrustDocumentRecords(
	records TrustDocumentRecords,
	expected DiscoveryRequest,
	expectedJWKSRevision uint64,
) (int, error) {
	if client == nil || expected.Revision == 0 || expectedJWKSRevision == 0 {
		return 0, ErrInvalidSnapshot
	}
	expectedPolicy, err := normalizeTrustPolicy(expected.Policy)
	if err != nil {
		return 0, ErrInvalidSnapshot
	}
	recordPolicy, err := normalizeTrustPolicy(records.Discovery.Request.Policy)
	if err != nil || records.Discovery.Request.Issuer != expected.Issuer ||
		records.Discovery.Request.Revision != expected.Revision ||
		records.Discovery.Request.Policy.ClientAuthentication != expectedPolicy.ClientAuthentication ||
		!slices.Equal(records.Discovery.Request.Policy.SigningAlgorithms, expectedPolicy.SigningAlgorithms) ||
		recordPolicy.ClientAuthentication != expectedPolicy.ClientAuthentication ||
		!slices.Equal(recordPolicy.SigningAlgorithms, expectedPolicy.SigningAlgorithms) ||
		records.JWKS.Revision != expectedJWKSRevision {
		return 0, ErrInvalidSnapshot
	}
	discovery, err := client.RestoreDiscovery(records.Discovery)
	if err != nil || !sameDiscoverySnapshot(discovery, records.JWKS.Discovery) {
		return 0, ErrInvalidSnapshot
	}
	jwks, err := client.RestoreJWKS(records.JWKS)
	if err != nil || jwks.Revision() != expectedJWKSRevision ||
		jwks.DiscoveryRevision() != discovery.Revision() ||
		jwks.DiscoveryDigest() != discovery.Digest() ||
		jwks.Digest() != records.JWKS.Digest || jwks.Cache() != records.JWKS.Cache {
		return 0, ErrInvalidSnapshot
	}
	keyCount := jwks.KeyCount()
	if keyCount < 1 || records.KeyCount != keyCount {
		return 0, ErrInvalidSnapshot
	}
	return keyCount, nil
}

func sameDiscoverySnapshot(left, right DiscoverySnapshot) bool {
	return left.validSnapshot() && right.validSnapshot() &&
		left.revision == right.revision && left.digest == right.digest && left.cache == right.cache &&
		left.issuer == right.issuer && left.endpoints == right.endpoints &&
		left.clientAuthentication == right.clientAuthentication &&
		slices.Equal(left.signingAlgorithms, right.signingAlgorithms) && left.targets == right.targets
}

// FetchTrustDocuments obtains and validates one coherent discovery/JWKS pair
// through the deployment-owned SSRF/TLS boundary. Unlike the authentication
// snapshot methods, this administration seam returns the public source bytes
// so the exact accepted artifacts can be committed transactionally.
func (client *Client) FetchTrustDocuments(
	ctx context.Context,
	request DiscoveryRequest,
	jwksRevision uint64,
) (TrustDocumentRecords, error) {
	if client == nil || client.http == nil || ctx == nil || request.Revision == 0 || jwksRevision == 0 {
		return TrustDocumentRecords{}, ErrInvalidRequest
	}
	policy, err := normalizeTrustPolicy(request.Policy)
	if err != nil {
		return TrustDocumentRecords{}, ErrInvalidRequest
	}
	request.Policy = policy
	discoveryURL := stringsTrimIssuer(request.Issuer) + "/.well-known/openid-configuration"
	discoveryTarget, err := client.http.CompileTarget(federatedhttp.DocumentOIDCDiscovery, discoveryURL)
	if err != nil {
		return TrustDocumentRecords{}, ErrInvalidRequest
	}
	discoveryResult, fetchErr := client.http.Fetch(ctx, discoveryTarget, nil)
	if fetchErr != nil {
		return TrustDocumentRecords{}, FetchFailure{document: fetchDiscovery, category: federatedhttp.CategoryResponseFailed}
	}
	if discoveryResult.Category != federatedhttp.CategorySuccess {
		return TrustDocumentRecords{}, FetchFailure{document: fetchDiscovery, category: sanitizedFetchCategory(discoveryResult.Category)}
	}
	if !validFetchedDocument(discoveryResult, federatedhttp.DocumentOIDCDiscovery, client.limits.MaxDiscoveryBytes) {
		clear(discoveryResult.Body)
		return TrustDocumentRecords{}, ErrDiscoveryRejected
	}
	parsed, err := client.parseDiscovery(discoveryResult.Body, request.Issuer, policy)
	if err != nil {
		clear(discoveryResult.Body)
		return TrustDocumentRecords{}, err
	}
	discovery := DiscoverySnapshot{
		revision: request.Revision, digest: discoveryResult.Digest, cache: discoveryResult.Cache,
		issuer: request.Issuer, endpoints: parsed.endpoints,
		clientAuthentication: policy.ClientAuthentication,
		signingAlgorithms:    append([]SigningAlgorithm(nil), parsed.signingAlgorithms...),
		targets:              parsed.targets, valid: true,
	}
	jwksResult, fetchErr := client.http.Fetch(ctx, discovery.targets.jwks, nil)
	if fetchErr != nil {
		clear(discoveryResult.Body)
		return TrustDocumentRecords{}, FetchFailure{document: fetchJWKS, category: federatedhttp.CategoryResponseFailed}
	}
	if jwksResult.Category != federatedhttp.CategorySuccess {
		clear(discoveryResult.Body)
		return TrustDocumentRecords{}, FetchFailure{document: fetchJWKS, category: sanitizedFetchCategory(jwksResult.Category)}
	}
	if !validFetchedDocument(jwksResult, federatedhttp.DocumentOIDCJWKS, client.limits.MaxJWKSBytes) {
		clear(discoveryResult.Body)
		clear(jwksResult.Body)
		return TrustDocumentRecords{}, ErrJWKSRejected
	}
	summaries, keys, err := client.parseJWKS(jwksResult.Body, discovery.signingAlgorithms)
	if err != nil {
		clear(discoveryResult.Body)
		clear(jwksResult.Body)
		return TrustDocumentRecords{}, err
	}
	jwks := JWKSSnapshot{
		revision: jwksRevision, discoveryRevision: discovery.revision,
		discoveryDigest: discovery.digest, digest: jwksResult.Digest, cache: jwksResult.Cache,
		summaries: summaries, keys: keys, valid: true,
	}
	if !discovery.validSnapshot() || !jwks.validSnapshot() ||
		discoveryResult.Digest != sha256.Sum256(discoveryResult.Body) ||
		jwksResult.Digest != sha256.Sum256(jwksResult.Body) {
		clear(discoveryResult.Body)
		clear(jwksResult.Body)
		return TrustDocumentRecords{}, ErrInvalidSnapshot
	}
	return TrustDocumentRecords{
		Discovery: DiscoverySnapshotRecord{
			Request: request, Document: discoveryResult.Body,
			Digest: discoveryResult.Digest, Cache: discoveryResult.Cache,
		},
		JWKS: JWKSSnapshotRecord{
			Revision: jwksRevision, Document: jwksResult.Body,
			Digest: jwksResult.Digest, Cache: jwksResult.Cache, Discovery: discovery,
		},
		KeyCount: len(summaries),
	}, nil
}

func stringsTrimIssuer(value string) string {
	for len(value) > 0 && value[len(value)-1] == '/' {
		value = value[:len(value)-1]
	}
	return value
}
