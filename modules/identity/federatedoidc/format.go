package federatedoidc

import (
	"crypto/sha256"
	"strconv"
)

func (mode ClientAuthenticationMode) String() string   { return safeClientAuthentication(mode) }
func (mode ClientAuthenticationMode) GoString() string { return mode.String() }

func (algorithm SigningAlgorithm) String() string   { return safeSigningAlgorithm(algorithm) }
func (algorithm SigningAlgorithm) GoString() string { return algorithm.String() }

func (keyType KeyType) String() string   { return safeKeyType(keyType) }
func (keyType KeyType) GoString() string { return keyType.String() }

func (limits Limits) String() string {
	return "federatedoidc.Limits{" +
		"document_bounds=" + strconv.FormatBool(limits.MaxDiscoveryBytes > 0 && limits.MaxJWKSBytes > 0) +
		",json_bounds=" + strconv.FormatBool(
		limits.MaxJSONDepth > 0 && limits.MaxJSONValues > 0 &&
			limits.MaxJSONObjectMembers > 0 && limits.MaxJSONArrayItems > 0 &&
			limits.MaxJSONStringBytes > 0,
	) +
		",key_bounds=" + strconv.FormatBool(
		limits.MaxKeys > 0 && limits.MaxCertificates >= 0 &&
			limits.MaxCertificatesPerKey >= 0 && limits.MaxCertificateBytes > 0 && limits.MaxKeyIDBytes > 0,
	) +
		"}"
}

func (limits Limits) GoString() string { return limits.String() }

func (options Options) String() string {
	return "federatedoidc.Options{" +
		"http=" + strconv.FormatBool(options.HTTP != nil) +
		",limits=" + strconv.Quote(options.Limits.String()) +
		"}"
}

func (options Options) GoString() string { return options.String() }

func (policy TrustPolicy) String() string {
	return "federatedoidc.TrustPolicy{" +
		"client_authentication=" + safeClientAuthentication(policy.ClientAuthentication) +
		",signing_algorithms=" + strconv.Itoa(len(policy.SigningAlgorithms)) +
		"}"
}

func (policy TrustPolicy) GoString() string { return policy.String() }

func (request DiscoveryRequest) String() string {
	return "federatedoidc.DiscoveryRequest{" +
		"issuer_present=" + strconv.FormatBool(request.Issuer != "") +
		",revision=" + strconv.FormatBool(request.Revision != 0) +
		",policy=" + strconv.Quote(request.Policy.String()) +
		"}"
}

func (request DiscoveryRequest) GoString() string { return request.String() }

func (endpoints Endpoints) String() string {
	return "federatedoidc.Endpoints{" +
		"authorization=" + strconv.FormatBool(endpoints.Authorization != "") +
		",token=" + strconv.FormatBool(endpoints.Token != "") +
		",jwks=" + strconv.FormatBool(endpoints.JWKS != "") +
		",userinfo=" + strconv.FormatBool(endpoints.UserInfo != "") +
		",revocation=" + strconv.FormatBool(endpoints.Revocation != "") +
		",end_session=" + strconv.FormatBool(endpoints.EndSession != "") +
		"}"
}

func (endpoints Endpoints) GoString() string { return endpoints.String() }

func (snapshot DiscoverySnapshot) String() string {
	return "federatedoidc.DiscoverySnapshot{" +
		"valid=" + strconv.FormatBool(snapshot.valid) +
		",revision=" + strconv.FormatBool(snapshot.revision != 0) +
		",digest=" + strconv.FormatBool(snapshot.digest != ([sha256.Size]byte{})) +
		",issuer_present=" + strconv.FormatBool(snapshot.issuer != "") +
		",endpoints=" + strconv.Quote(snapshot.endpoints.String()) +
		",signing_algorithms=" + strconv.Itoa(len(snapshot.signingAlgorithms)) +
		"}"
}

func (snapshot DiscoverySnapshot) GoString() string { return snapshot.String() }

func (summary KeySummary) String() string {
	return "federatedoidc.KeySummary{" +
		"kid_present=" + strconv.FormatBool(summary.KeyID != "") +
		",algorithm=" + safeSigningAlgorithm(summary.Algorithm) +
		",type=" + safeKeyType(summary.Type) +
		",curve_present=" + strconv.FormatBool(summary.Curve != "") +
		",bits=" + strconv.Itoa(summary.Bits) +
		",certificates=" + strconv.Itoa(summary.CertificateCount) +
		",thumbprint=" + strconv.FormatBool(summary.ThumbprintSHA256 != ([sha256.Size]byte{})) +
		"}"
}

func (summary KeySummary) GoString() string { return summary.String() }

func (snapshot JWKSSnapshot) String() string {
	return "federatedoidc.JWKSSnapshot{" +
		"valid=" + strconv.FormatBool(snapshot.valid) +
		",revision=" + strconv.FormatBool(snapshot.revision != 0) +
		",discovery_revision=" + strconv.FormatBool(snapshot.discoveryRevision != 0) +
		",discovery_digest=" + strconv.FormatBool(snapshot.discoveryDigest != ([sha256.Size]byte{})) +
		",digest=" + strconv.FormatBool(snapshot.digest != ([sha256.Size]byte{})) +
		",keys=" + strconv.Itoa(len(snapshot.summaries)) +
		"}"
}

func (snapshot JWKSSnapshot) GoString() string { return snapshot.String() }

func (failure FetchFailure) String() string {
	return "federatedoidc.FetchFailure{" +
		"document=" + safeFetchDocument(failure.document) +
		",category=" + failure.category.String() +
		"}"
}

func (failure FetchFailure) GoString() string { return failure.String() }

func (client *Client) String() string {
	return "federatedoidc.Client{" +
		"configured=" + strconv.FormatBool(client != nil && client.http != nil) +
		"}"
}

func (client *Client) GoString() string { return client.String() }

func safeClientAuthentication(mode ClientAuthenticationMode) string {
	if validClientAuthentication(mode) {
		return string(mode)
	}
	return "unknown"
}

func safeSigningAlgorithm(algorithm SigningAlgorithm) string {
	if supportedSigningAlgorithm(algorithm) {
		return string(algorithm)
	}
	return "unknown"
}

func safeKeyType(keyType KeyType) string {
	switch keyType {
	case KeyTypeRSA, KeyTypeEC, KeyTypeEd25519:
		return string(keyType)
	default:
		return "unknown"
	}
}

func safeFetchDocument(document fetchDocument) string {
	switch document {
	case fetchDiscovery:
		return "discovery"
	case fetchJWKS:
		return "jwks"
	default:
		return "unknown"
	}
}
