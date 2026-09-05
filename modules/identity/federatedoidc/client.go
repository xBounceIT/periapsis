package federatedoidc

import (
	"context"
	"crypto/sha256"
	"slices"
	"strings"

	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
)

// New freezes the concrete SSRF-safe HTTP boundary and parser limits.
func New(options Options) (*Client, error) {
	if options.HTTP == nil {
		return nil, ErrInvalidOptions
	}
	return newClient(options.HTTP, options.Limits)
}

func newClient(boundary trustHTTP, limits Limits) (*Client, error) {
	if boundary == nil || !validLimits(limits) {
		return nil, ErrInvalidOptions
	}
	return &Client{http: boundary, limits: limits}, nil
}

func validLimits(limits Limits) bool {
	return limits.MaxDiscoveryBytes >= minimumDiscoveryBytes &&
		limits.MaxDiscoveryBytes <= maximumDiscoveryBytes &&
		limits.MaxJWKSBytes >= minimumJWKSBytes && limits.MaxJWKSBytes <= maximumJWKSBytes &&
		limits.MaxJSONDepth >= minimumJSONDepth && limits.MaxJSONDepth <= maximumJSONDepth &&
		limits.MaxJSONValues >= minimumJSONValues && limits.MaxJSONValues <= maximumJSONValues &&
		limits.MaxJSONObjectMembers >= minimumJSONObjectMembers &&
		limits.MaxJSONObjectMembers <= maximumJSONObjectMembers &&
		limits.MaxJSONArrayItems >= minimumJSONArrayItems &&
		limits.MaxJSONArrayItems <= maximumJSONArrayItems &&
		limits.MaxJSONStringBytes >= minimumJSONStringBytes &&
		limits.MaxJSONStringBytes <= maximumJSONStringBytes &&
		limits.MaxKeys >= minimumKeys && limits.MaxKeys <= maximumKeys &&
		limits.MaxCertificates >= 0 && limits.MaxCertificates <= maximumCertificates &&
		limits.MaxCertificatesPerKey >= 0 &&
		limits.MaxCertificatesPerKey <= maximumCertificatesPerKey &&
		limits.MaxCertificatesPerKey <= limits.MaxCertificates &&
		limits.MaxCertificateBytes >= minimumCertificateBytes &&
		limits.MaxCertificateBytes <= maximumCertificateBytes &&
		limits.MaxKeyIDBytes >= minimumKeyIDBytes && limits.MaxKeyIDBytes <= maximumKeyIDBytes
}

// FetchDiscovery retrieves, parses, and freezes one exact discovery revision.
func (client *Client) FetchDiscovery(
	ctx context.Context,
	request DiscoveryRequest,
) (DiscoverySnapshot, error) {
	if client == nil || client.http == nil || ctx == nil || request.Revision == 0 {
		return DiscoverySnapshot{}, ErrInvalidRequest
	}
	policy, err := normalizeTrustPolicy(request.Policy)
	if err != nil {
		return DiscoverySnapshot{}, ErrInvalidRequest
	}
	if _, err = client.http.CompileTarget(federatedhttp.DocumentOIDCDiscovery, request.Issuer); err != nil {
		return DiscoverySnapshot{}, ErrInvalidRequest
	}
	discoveryURL := strings.TrimSuffix(request.Issuer, "/") + "/.well-known/openid-configuration"
	target, err := client.http.CompileTarget(federatedhttp.DocumentOIDCDiscovery, discoveryURL)
	if err != nil {
		return DiscoverySnapshot{}, ErrInvalidRequest
	}
	result, fetchErr := client.http.Fetch(ctx, target, nil)
	if fetchErr != nil {
		return DiscoverySnapshot{}, FetchFailure{document: fetchDiscovery, category: federatedhttp.CategoryResponseFailed}
	}
	if result.Category != federatedhttp.CategorySuccess {
		return DiscoverySnapshot{}, FetchFailure{
			document: fetchDiscovery,
			category: sanitizedFetchCategory(result.Category),
		}
	}
	defer clear(result.Body)
	if !validFetchedDocument(result, federatedhttp.DocumentOIDCDiscovery, client.limits.MaxDiscoveryBytes) {
		return DiscoverySnapshot{}, ErrDiscoveryRejected
	}

	parsed, err := client.parseDiscovery(result.Body, request.Issuer, policy)
	if err != nil {
		return DiscoverySnapshot{}, err
	}
	return DiscoverySnapshot{
		revision: request.Revision, digest: result.Digest, cache: result.Cache,
		issuer: request.Issuer, endpoints: parsed.endpoints,
		clientAuthentication: policy.ClientAuthentication,
		signingAlgorithms:    append([]SigningAlgorithm(nil), parsed.signingAlgorithms...),
		targets:              parsed.targets,
		valid:                true,
	}, nil
}

// FetchJWKS retrieves and freezes public verification keys for one exact
// discovery snapshot. It never refreshes or replaces the supplied snapshot.
func (client *Client) FetchJWKS(
	ctx context.Context,
	discovery DiscoverySnapshot,
	revision uint64,
) (JWKSSnapshot, error) {
	if client == nil || client.http == nil || ctx == nil || revision == 0 || !discovery.validSnapshot() {
		return JWKSSnapshot{}, ErrInvalidSnapshot
	}
	result, fetchErr := client.http.Fetch(ctx, discovery.targets.jwks, nil)
	if fetchErr != nil {
		return JWKSSnapshot{}, FetchFailure{document: fetchJWKS, category: federatedhttp.CategoryResponseFailed}
	}
	if result.Category != federatedhttp.CategorySuccess {
		return JWKSSnapshot{}, FetchFailure{
			document: fetchJWKS,
			category: sanitizedFetchCategory(result.Category),
		}
	}
	defer clear(result.Body)
	if !validFetchedDocument(result, federatedhttp.DocumentOIDCJWKS, client.limits.MaxJWKSBytes) {
		return JWKSSnapshot{}, ErrJWKSRejected
	}
	summaries, keys, err := client.parseJWKS(result.Body, discovery.signingAlgorithms)
	if err != nil {
		return JWKSSnapshot{}, err
	}
	return JWKSSnapshot{
		revision: revision, discoveryRevision: discovery.revision,
		discoveryDigest: discovery.digest, digest: result.Digest, cache: result.Cache,
		summaries: summaries, keys: keys, valid: true,
	}, nil
}

func sanitizedFetchCategory(category federatedhttp.Category) federatedhttp.Category {
	if category == federatedhttp.CategorySuccess || category.String() == "unknown" {
		return federatedhttp.CategoryResponseFailed
	}
	return category
}

func validFetchedDocument(result federatedhttp.Result, kind federatedhttp.DocumentKind, maximum int) bool {
	return result.Category == federatedhttp.CategorySuccess && result.Kind == kind &&
		len(result.Body) > 0 && len(result.Body) <= maximum &&
		result.Digest == sha256.Sum256(result.Body) && validCache(result.Cache)
}

func normalizeTrustPolicy(policy TrustPolicy) (TrustPolicy, error) {
	if !validClientAuthentication(policy.ClientAuthentication) ||
		len(policy.SigningAlgorithms) == 0 || len(policy.SigningAlgorithms) > 10 {
		return TrustPolicy{}, ErrInvalidRequest
	}
	result := TrustPolicy{ClientAuthentication: policy.ClientAuthentication}
	seen := make(map[SigningAlgorithm]struct{}, len(policy.SigningAlgorithms))
	for _, algorithm := range policy.SigningAlgorithms {
		if !supportedSigningAlgorithm(algorithm) {
			return TrustPolicy{}, ErrInvalidRequest
		}
		if _, duplicate := seen[algorithm]; duplicate {
			return TrustPolicy{}, ErrInvalidRequest
		}
		seen[algorithm] = struct{}{}
		result.SigningAlgorithms = append(result.SigningAlgorithms, algorithm)
	}
	slices.Sort(result.SigningAlgorithms)
	return result, nil
}

func supportedSigningAlgorithm(algorithm SigningAlgorithm) bool {
	switch algorithm {
	case SigningRS256, SigningRS384, SigningRS512,
		SigningPS256, SigningPS384, SigningPS512,
		SigningES256, SigningES384, SigningES512, SigningEdDSA:
		return true
	default:
		return false
	}
}
