package federatedoidc

import (
	"unicode"

	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
)

type parsedDiscovery struct {
	endpoints         Endpoints
	signingAlgorithms []SigningAlgorithm
	targets           discoveryEndpointTargets
}

func (client *Client) parseDiscovery(
	document []byte,
	expectedIssuer string,
	policy TrustPolicy,
) (parsedDiscovery, error) {
	if validateBoundedJSONObject(document, client.limits.MaxDiscoveryBytes, client.limits) != nil {
		return parsedDiscovery{}, ErrDiscoveryRejected
	}
	object, err := decodeObject(document)
	if err != nil {
		return parsedDiscovery{}, ErrDiscoveryRejected
	}
	issuer, _, err := decodeStringMember(object, "issuer", true, maximumMetadataStringBytes)
	if err != nil {
		return parsedDiscovery{}, ErrDiscoveryRejected
	}
	if issuer != expectedIssuer {
		return parsedDiscovery{}, ErrIssuerMismatch
	}

	authorization, _, err := decodeStringMember(object, "authorization_endpoint", true, maximumMetadataStringBytes)
	if err != nil {
		return parsedDiscovery{}, ErrDiscoveryRejected
	}
	token, _, err := decodeStringMember(object, "token_endpoint", true, maximumMetadataStringBytes)
	if err != nil {
		return parsedDiscovery{}, ErrDiscoveryRejected
	}
	jwksURL, _, err := decodeStringMember(object, "jwks_uri", true, maximumMetadataStringBytes)
	if err != nil {
		return parsedDiscovery{}, ErrDiscoveryRejected
	}
	userinfo, _, err := decodeStringMember(object, "userinfo_endpoint", false, maximumMetadataStringBytes)
	if err != nil {
		return parsedDiscovery{}, ErrDiscoveryRejected
	}
	revocation, _, err := decodeStringMember(object, "revocation_endpoint", false, maximumMetadataStringBytes)
	if err != nil {
		return parsedDiscovery{}, ErrDiscoveryRejected
	}
	endSession, _, err := decodeStringMember(object, "end_session_endpoint", false, maximumMetadataStringBytes)
	if err != nil {
		return parsedDiscovery{}, ErrDiscoveryRejected
	}

	responseTypes, _, err := decodeStringArrayMember(
		object, "response_types_supported", true, maximumMetadataArrayItems, 128,
	)
	if err != nil || !validMetadataValues(responseTypes) || !containsString(responseTypes, ResponseTypeCode) {
		return parsedDiscovery{}, ErrDiscoveryRejected
	}
	responseModes, responseModesPresent, err := decodeStringArrayMember(
		object, "response_modes_supported", false, maximumMetadataArrayItems, 128,
	)
	if err != nil || responseModesPresent &&
		(!validMetadataValues(responseModes) || !containsString(responseModes, ResponseModeQuery)) {
		return parsedDiscovery{}, ErrDiscoveryRejected
	}
	grantTypes, grantTypesPresent, err := decodeStringArrayMember(
		object, "grant_types_supported", false, maximumMetadataArrayItems, 128,
	)
	if err != nil || grantTypesPresent &&
		(!validMetadataValues(grantTypes) || !containsString(grantTypes, GrantAuthorizationCode)) {
		return parsedDiscovery{}, ErrDiscoveryRejected
	}
	challengeMethods, _, err := decodeStringArrayMember(
		object, "code_challenge_methods_supported", true, maximumMetadataArrayItems, 128,
	)
	if err != nil || !validMetadataValues(challengeMethods) || !containsString(challengeMethods, CodeChallengeS256) {
		return parsedDiscovery{}, ErrDiscoveryRejected
	}
	authenticationMethods, _, err := decodeStringArrayMember(
		object, "token_endpoint_auth_methods_supported", true, maximumMetadataArrayItems, 128,
	)
	if err != nil || !validMetadataValues(authenticationMethods) ||
		!containsString(authenticationMethods, string(policy.ClientAuthentication)) {
		return parsedDiscovery{}, ErrDiscoveryRejected
	}
	subjectTypes, _, err := decodeStringArrayMember(
		object, "subject_types_supported", true, maximumMetadataArrayItems, 128,
	)
	if err != nil || !validSubjectTypes(subjectTypes) {
		return parsedDiscovery{}, ErrDiscoveryRejected
	}
	scopes, scopesPresent, err := decodeStringArrayMember(
		object, "scopes_supported", false, maximumMetadataArrayItems, 128,
	)
	if err != nil || scopesPresent && (!validMetadataValues(scopes) || !containsString(scopes, RequiredScopeOpenID)) {
		return parsedDiscovery{}, ErrDiscoveryRejected
	}
	advertisedAlgorithms, _, err := decodeStringArrayMember(
		object, "id_token_signing_alg_values_supported", true, maximumMetadataArrayItems, 128,
	)
	if err != nil || !validMetadataValues(advertisedAlgorithms) {
		return parsedDiscovery{}, ErrDiscoveryRejected
	}
	signingAlgorithms := allowedAlgorithmIntersection(policy.SigningAlgorithms, advertisedAlgorithms)
	if len(signingAlgorithms) == 0 {
		return parsedDiscovery{}, ErrDiscoveryRejected
	}

	endpoints := Endpoints{
		Authorization: authorization, Token: token, JWKS: jwksURL,
		UserInfo: userinfo, Revocation: revocation, EndSession: endSession,
	}
	authorizationTarget, err := client.http.CompileTarget(federatedhttp.DocumentOIDCDiscovery, authorization)
	if err != nil {
		return parsedDiscovery{}, ErrDiscoveryRejected
	}
	tokenTarget, err := client.http.CompileTarget(federatedhttp.DocumentOIDCDiscovery, token)
	if err != nil {
		return parsedDiscovery{}, ErrDiscoveryRejected
	}
	jwksTarget, err := client.http.CompileTarget(federatedhttp.DocumentOIDCJWKS, jwksURL)
	if err != nil {
		return parsedDiscovery{}, ErrDiscoveryRejected
	}
	targets := discoveryEndpointTargets{
		authorization: authorizationTarget,
		token:         tokenTarget,
		jwks:          jwksTarget,
		count:         3,
	}
	for index, optional := range []string{userinfo, revocation, endSession} {
		if optional == "" {
			continue
		}
		target, compileErr := client.http.CompileTarget(federatedhttp.DocumentOIDCDiscovery, optional)
		if compileErr != nil {
			return parsedDiscovery{}, ErrDiscoveryRejected
		}
		switch index {
		case 0:
			targets.userinfo = target
		case 1:
			targets.revocation = target
		case 2:
			targets.endSession = target
		}
		targets.count++
	}
	return parsedDiscovery{
		endpoints: endpoints, signingAlgorithms: signingAlgorithms,
		targets: targets,
	}, nil
}

func validMetadataValues(values []string) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		if value == "" {
			return false
		}
		for _, character := range value {
			if unicode.IsControl(character) {
				return false
			}
		}
	}
	return true
}

func validSubjectTypes(values []string) bool {
	if !validMetadataValues(values) {
		return false
	}
	for _, value := range values {
		if value != "public" && value != "pairwise" {
			return false
		}
	}
	return true
}

func allowedAlgorithmIntersection(
	allowed []SigningAlgorithm,
	advertised []string,
) []SigningAlgorithm {
	result := make([]SigningAlgorithm, 0, len(allowed))
	for _, algorithm := range allowed {
		if containsString(advertised, string(algorithm)) {
			result = append(result, algorithm)
		}
	}
	return result
}
