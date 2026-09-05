package federatedoidc

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strconv"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

const (
	maximumJWTHeaderBytes    = 8 * 1024
	maximumJWTSignatureBytes = 16 * 1024
	maximumAudienceCount     = 16
	maximumSubjectBytes      = 1024
	maximumNumericDate       = int64(253402300799)
)

type parsedCompactToken struct {
	payload    map[string]json.RawMessage
	payloadRaw []byte
	algorithm  SigningAlgorithm
	keyID      string
}

func (flow *Flow) VerifyIDToken(
	ctx context.Context,
	claimed *ClaimedAuthorization,
	bundle *TokenBundle,
	claimPolicy ClaimExtractionPolicy,
) (*VerifiedAuthentication, error) {
	if flow == nil || claimed == nil || claimed.owner != flow ||
		!bundle.matchesTransaction(flow, claimed.record.ID) ||
		!bundle.matchesConfiguration(flow, claimed.configuration) {
		return nil, ErrIDTokenRejected
	}
	if _, err := flow.normalizeClaimPolicy(claimPolicy); err != nil {
		return nil, ErrClaimExtractionRejected
	}
	if !claimed.stage.CompareAndSwap(claimedStageExchanged, claimedStageVerifying) {
		return nil, ErrIDTokenRejected
	}
	now, ok := flow.currentTime()
	if !ok {
		flow.verificationFailed(ctx, claimed, bundle, now)
		return nil, ErrIDTokenRejected
	}
	operationCtx, cancel, err := flow.operationContext(ctx)
	if err != nil {
		flow.verificationFailed(ctx, claimed, bundle, now)
		return nil, ErrIDTokenRejected
	}
	defer cancel()
	idTokenBytes, accessToken, refreshToken, ok := bundle.material()
	clear(refreshToken)
	if !ok {
		flow.verificationFailed(operationCtx, claimed, bundle, now)
		return nil, ErrIDTokenRejected
	}
	defer clear(idTokenBytes)
	defer clear(accessToken)
	parsed, err := flow.parseCompactToken(idTokenBytes)
	if err != nil {
		flow.verificationFailed(operationCtx, claimed, bundle, now)
		return nil, ErrIDTokenRejected
	}
	defer clear(parsed.payloadRaw)
	publicKey, keyFound, algorithmMatch := pinnedPublicKey(
		claimed.configuration.JWKS,
		parsed.keyID,
		parsed.algorithm,
	)
	if !keyFound {
		flow.verificationFailed(operationCtx, claimed, bundle, now)
		return nil, ErrJWKSRevisionRestart
	}
	if !algorithmMatch || publicKey == nil ||
		!slices.Contains(claimed.configuration.Discovery.signingAlgorithms, parsed.algorithm) {
		flow.verificationFailed(operationCtx, claimed, bundle, now)
		return nil, ErrIDTokenRejected
	}
	keySet := &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{publicKey}}
	verifier := oidc.NewVerifier(claimed.configuration.Discovery.issuer, keySet, &oidc.Config{
		ClientID:             claimed.record.ClientID,
		SupportedSigningAlgs: []string{string(parsed.algorithm)},
		Now:                  func() time.Time { return libraryVerificationTime(now, flow.policy.ClockSkew, parsed.payload) },
	})
	verifiedByLibrary, libraryErr := verifier.Verify(operationCtx, string(idTokenBytes))
	if libraryErr != nil {
		flow.verificationFailed(operationCtx, claimed, bundle, now)
		return nil, ErrIDTokenRejected
	}
	claims, localErr := flow.validateLocalClaims(
		parsed.payload,
		claimed,
		now,
	)
	if localErr != nil {
		flow.verificationFailed(operationCtx, claimed, bundle, now)
		return nil, ErrIDTokenRejected
	}
	if _, atHashPresent := parsed.payload["at_hash"]; atHashPresent {
		if len(accessToken) == 0 || verifiedByLibrary.VerifyAccessToken(string(accessToken)) != nil {
			flow.verificationFailed(operationCtx, claimed, bundle, now)
			return nil, ErrIDTokenRejected
		}
	}
	extracted, extractErr := flow.extractClaims(parsed.payload, claimPolicy)
	if extractErr != nil {
		flow.verificationFailed(operationCtx, claimed, bundle, now)
		return nil, ErrClaimExtractionRejected
	}
	claimed.stage.Store(claimedStageVerified)
	audience := append([]string(nil), claims.audience...)
	slices.Sort(audience)
	return &VerifiedAuthentication{
		issuer:          claimed.configuration.Discovery.issuer,
		subject:         claims.subject,
		audience:        audience,
		issuedAt:        claims.issuedAt,
		expiresAt:       claims.expiresAt,
		authenticatedAt: claims.authenticatedAt,
		claims:          extracted,
		completion: TransactionCompletion{
			ID: claimed.record.ID, MaterialID: claimed.record.MaterialID, ExpectedVersion: claimed.record.Version,
			Pins: claimed.record.Pins, CompletedAt: now, ReturnPath: claimed.record.ReturnPath,
		},
		valid: true,
	}, nil
}

func (flow *Flow) parseCompactToken(raw []byte) (parsedCompactToken, error) {
	if flow == nil || len(raw) < 5 || len(raw) > flow.policy.Limits.MaxCompactTokenBytes {
		return parsedCompactToken{}, ErrIDTokenRejected
	}
	segments := bytes.Split(raw, []byte{'.'})
	if len(segments) != 3 {
		return parsedCompactToken{}, ErrIDTokenRejected
	}
	header, err := decodeCompactSegment(segments[0], maximumJWTHeaderBytes)
	if err != nil {
		return parsedCompactToken{}, ErrIDTokenRejected
	}
	defer clear(header)
	payload, err := decodeCompactSegment(segments[1], flow.policy.Limits.MaxCompactTokenBytes)
	if err != nil {
		return parsedCompactToken{}, ErrIDTokenRejected
	}
	signature, err := decodeCompactSegment(segments[2], maximumJWTSignatureBytes)
	if err != nil || len(signature) == 0 {
		clear(payload)
		clear(signature)
		return parsedCompactToken{}, ErrIDTokenRejected
	}
	clear(signature)
	if validateBoundedJSONObject(header, maximumJWTHeaderBytes, flow.trust.limits) != nil ||
		validateBoundedJSONObject(payload, flow.policy.Limits.MaxCompactTokenBytes, flow.trust.limits) != nil {
		clear(payload)
		return parsedCompactToken{}, ErrIDTokenRejected
	}
	headerObject, err := decodeObject(header)
	if err != nil {
		clear(payload)
		return parsedCompactToken{}, ErrIDTokenRejected
	}
	payloadObject, err := decodeObject(payload)
	if err != nil {
		clear(payload)
		return parsedCompactToken{}, ErrIDTokenRejected
	}
	algorithmText, _, err := decodeStringMember(headerObject, "alg", true, 16)
	algorithm := SigningAlgorithm(algorithmText)
	if err != nil || !supportedSigningAlgorithm(algorithm) {
		clear(payload)
		return parsedCompactToken{}, ErrIDTokenRejected
	}
	keyID, _, err := decodeStringMember(headerObject, "kid", true, flow.trust.limits.MaxKeyIDBytes)
	if err != nil || !validKeyID(keyID) {
		clear(payload)
		return parsedCompactToken{}, ErrIDTokenRejected
	}
	if tokenType, present, typeErr := decodeStringMember(headerObject, "typ", false, 16); typeErr != nil ||
		present && tokenType != "JWT" {
		clear(payload)
		return parsedCompactToken{}, ErrIDTokenRejected
	}
	for _, forbidden := range []string{"crit", "jku", "jwk", "x5u", "b64", "zip", "cty"} {
		if _, present := headerObject[forbidden]; present {
			clear(payload)
			return parsedCompactToken{}, ErrIDTokenRejected
		}
	}
	return parsedCompactToken{
		payload: payloadObject, payloadRaw: payload,
		algorithm: algorithm, keyID: keyID,
	}, nil
}

func decodeCompactSegment(encoded []byte, maximum int) ([]byte, error) {
	if len(encoded) == 0 || bytes.IndexByte(encoded, '=') >= 0 ||
		base64.RawURLEncoding.DecodedLen(len(encoded)) > maximum {
		return nil, ErrIDTokenRejected
	}
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(encoded)))
	count, err := base64.RawURLEncoding.Strict().Decode(decoded, encoded)
	decoded = decoded[:count]
	if err != nil || count == 0 || !bytes.Equal(
		encoded,
		[]byte(base64.RawURLEncoding.EncodeToString(decoded)),
	) {
		clear(decoded)
		return nil, ErrIDTokenRejected
	}
	return decoded, nil
}

func pinnedPublicKey(
	snapshot JWKSSnapshot,
	keyID string,
	algorithm SigningAlgorithm,
) (crypto.PublicKey, bool, bool) {
	for index, summary := range snapshot.summaries {
		if summary.KeyID != keyID {
			continue
		}
		if summary.Algorithm != algorithm || index >= len(snapshot.keys) {
			return nil, true, false
		}
		return snapshot.keys[index].Key, true, true
	}
	return nil, false, false
}

type localIDTokenClaims struct {
	subject         string
	audience        []string
	issuedAt        time.Time
	expiresAt       time.Time
	authenticatedAt time.Time
}

func (flow *Flow) validateLocalClaims(
	object map[string]json.RawMessage,
	claimed *ClaimedAuthorization,
	now time.Time,
) (localIDTokenClaims, error) {
	issuer, _, err := decodeStringMember(object, "iss", true, maximumMetadataStringBytes)
	if err != nil || issuer != claimed.configuration.Discovery.issuer {
		return localIDTokenClaims{}, ErrIDTokenRejected
	}
	subject, _, err := decodeStringMember(object, "sub", true, maximumSubjectBytes)
	if err != nil || !validClaimValue(subject, maximumSubjectBytes) {
		return localIDTokenClaims{}, ErrIDTokenRejected
	}
	audience, err := decodeAudience(object)
	if err != nil || !slices.Contains(audience, claimed.record.ClientID) {
		return localIDTokenClaims{}, ErrIDTokenRejected
	}
	authorizedParty, azpPresent, err := decodeStringMember(object, "azp", false, maximumClientIDBytes)
	if err != nil || len(audience) > 1 && !azpPresent || azpPresent && authorizedParty != claimed.record.ClientID {
		return localIDTokenClaims{}, ErrIDTokenRejected
	}
	nonce, _, err := decodeStringMember(object, "nonce", true, 128)
	if err != nil || !validOpaque([]byte(nonce)) ||
		!equalDigest(sha256.Sum256([]byte(nonce)), claimed.record.NonceDigest) {
		return localIDTokenClaims{}, ErrIDTokenRejected
	}
	expiresAt, _, err := decodeNumericDate(object, "exp", true)
	if err != nil {
		return localIDTokenClaims{}, ErrIDTokenRejected
	}
	issuedAt, _, err := decodeNumericDate(object, "iat", true)
	if err != nil {
		return localIDTokenClaims{}, ErrIDTokenRejected
	}
	notBefore, nbfPresent, err := decodeNumericDate(object, "nbf", false)
	if err != nil {
		return localIDTokenClaims{}, ErrIDTokenRejected
	}
	authenticatedAt, _, err := decodeNumericDate(object, "auth_time", true)
	if err != nil || !validTokenTimes(
		now, claimed.record.CreatedAt, claimed.record.ExpiresAt,
		issuedAt, expiresAt, notBefore, nbfPresent, authenticatedAt, flow.policy,
	) {
		return localIDTokenClaims{}, ErrIDTokenRejected
	}
	if _, _, hashErr := decodeStringMember(object, "at_hash", false, 512); hashErr != nil {
		return localIDTokenClaims{}, ErrIDTokenRejected
	}
	return localIDTokenClaims{
		subject: subject, audience: audience, issuedAt: issuedAt,
		expiresAt: expiresAt, authenticatedAt: authenticatedAt,
	}, nil
}

// coreos/go-oidc applies a fixed five-minute nbf allowance. Its clock is
// shifted only enough to let the stricter local configured skew be decisive,
// while retaining the library's expiry and nbf validation.
func libraryVerificationTime(
	now time.Time,
	skew time.Duration,
	object map[string]json.RawMessage,
) time.Time {
	verificationTime := now.Add(-skew)
	notBefore, present, err := decodeNumericDate(object, "nbf", false)
	if err == nil && present && notBefore.After(verificationTime.Add(5*time.Minute)) {
		verificationTime = notBefore.Add(-5 * time.Minute)
	}
	return verificationTime
}

func decodeAudience(object map[string]json.RawMessage) ([]string, error) {
	raw, present := object["aud"]
	if !present {
		return nil, ErrIDTokenRejected
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, ErrIDTokenRejected
	}
	if trimmed[0] == '"' {
		value, _, err := decodeStringMember(object, "aud", true, maximumClientIDBytes)
		if err != nil || !validClientID(value) {
			return nil, ErrIDTokenRejected
		}
		return []string{value}, nil
	}
	values, _, err := decodeStringArrayMember(
		object, "aud", true, maximumAudienceCount, maximumClientIDBytes,
	)
	if err != nil {
		return nil, ErrIDTokenRejected
	}
	for _, value := range values {
		if !validClientID(value) {
			return nil, ErrIDTokenRejected
		}
	}
	return values, nil
}

func decodeNumericDate(
	object map[string]json.RawMessage,
	name string,
	required bool,
) (time.Time, bool, error) {
	raw, present := object[name]
	if !present {
		if required {
			return time.Time{}, false, ErrIDTokenRejected
		}
		return time.Time{}, false, nil
	}
	trimmed := bytes.TrimSpace(raw)
	seconds, err := strconv.ParseInt(string(trimmed), 10, 64)
	if err != nil || seconds < 0 || seconds > maximumNumericDate ||
		strconv.FormatInt(seconds, 10) != string(trimmed) {
		return time.Time{}, false, ErrIDTokenRejected
	}
	return time.Unix(seconds, 0).UTC(), true, nil
}

func validTokenTimes(
	now time.Time,
	transactionCreated time.Time,
	transactionExpires time.Time,
	issuedAt time.Time,
	expiresAt time.Time,
	notBefore time.Time,
	hasNotBefore bool,
	authenticatedAt time.Time,
	policy FlowPolicy,
) bool {
	if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > policy.MaxTokenLifetime ||
		!now.Before(expiresAt.Add(policy.ClockSkew)) || issuedAt.After(now.Add(policy.ClockSkew)) ||
		issuedAt.Before(transactionCreated.Add(-policy.ClockSkew)) ||
		issuedAt.After(transactionExpires.Add(policy.ClockSkew)) ||
		now.After(issuedAt) && now.Sub(issuedAt) > policy.MaxTokenAge ||
		hasNotBefore && notBefore.After(now.Add(policy.ClockSkew)) ||
		hasNotBefore && !expiresAt.After(notBefore) ||
		authenticatedAt.After(now.Add(policy.ClockSkew)) ||
		authenticatedAt.After(issuedAt.Add(policy.ClockSkew)) {
		return false
	}
	return !now.After(authenticatedAt) || now.Sub(authenticatedAt) <= policy.MaxAuthenticationAge+policy.ClockSkew
}

func (flow *Flow) verificationFailed(
	ctx context.Context,
	claimed *ClaimedAuthorization,
	bundle *TokenBundle,
	now time.Time,
) {
	if claimed == nil {
		return
	}
	claimed.stage.Store(claimedStageFailed)
	if bundle != nil {
		bundle.Destroy()
	}
	flow.failTransaction(ctx, claimed.record, claimed.audit, now, FailureTokenValidation, TransactionFailed)
}
