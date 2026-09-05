package webauthn

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

// CompileRelyingParty accepts only canonical production HTTPS origins whose
// hostname is the RP ID or one of its DNS descendants.
func CompileRelyingParty(id string, origins []string, revision uint64) (RelyingParty, error) {
	if !validRPID(id) || !validVersionAsInt64(revision) || len(origins) == 0 || len(origins) > maximumOrigins {
		return RelyingParty{}, ErrInvalidOptions
	}
	compiled := make([]string, 0, len(origins))
	seen := make(map[string]struct{}, len(origins))
	for _, origin := range origins {
		if !validOrigin(origin, id) {
			return RelyingParty{}, ErrInvalidOptions
		}
		if _, duplicate := seen[origin]; duplicate {
			return RelyingParty{}, ErrInvalidOptions
		}
		seen[origin] = struct{}{}
		compiled = append(compiled, origin)
	}
	slices.Sort(compiled)
	return RelyingParty{id: id, origins: compiled, revision: revision}, nil
}

func validRPID(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) ||
		strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") || net.ParseIP(value) != nil {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := range label {
			character := label[index]
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func validOrigin(value, rpID string) bool {
	if value == "" || len(value) > 2048 || !utf8.ValidString(value) {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Host == "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.String() != value {
		return false
	}
	hostname := parsed.Hostname()
	if hostname == "" || hostname != strings.ToLower(hostname) || net.ParseIP(hostname) != nil ||
		(hostname != rpID && !strings.HasSuffix(hostname, "."+rpID)) {
		return false
	}
	port := parsed.Port()
	if port != "" {
		return false
	}
	return parsed.Host == hostname
}

func validLimits(value Limits) bool {
	return value.MaxResponseBytes >= minimumResponseBytes && value.MaxResponseBytes <= maximumResponseBytes &&
		value.MaxCredentialIDBytes >= minimumCredentialIDBytes &&
		value.MaxCredentialIDBytes <= maximumCredentialIDBytes &&
		value.MaxPublicKeyBytes >= minimumPublicKeyBytes && value.MaxPublicKeyBytes <= maximumPublicKeyBytes &&
		value.MaxAllowedCredentials >= 1 && value.MaxAllowedCredentials <= maximumAllowedCredentials
}

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%int(time.Microsecond) == 0
}

func validDeadline(value time.Time) bool {
	return validInstant(value) && value.Nanosecond()%int(time.Millisecond) == 0
}

func validRP(value RelyingParty) bool {
	compiled, err := CompileRelyingParty(value.id, value.origins, value.revision)
	return err == nil && compiled.id == value.id && slices.Equal(compiled.origins, value.origins)
}

func validBinding(now time.Time, value CeremonyBinding, mode AuthenticationMode) bool {
	zero := identity.EntityID{}
	if value.TenantID == zero || !validAction(value.Action) || !validAction(value.Audience) ||
		identity.EvaluateAssurance(now, value.Requirement, nil, false) == identity.AssuranceDenied ||
		!validBaselineEvidence(now, value.BaselineEvidence) {
		return false
	}
	if value.AnchorRecoveryRestricted && !hasLiveRecoveryEvidence(now, value.BaselineEvidence) {
		return false
	}
	switch value.Purpose {
	case PurposeRegistration:
		if value.UserID == zero || !validVersionAsInt64(value.IdentityEpoch) || mode != 0 ||
			len(value.BaselineEvidence) == 0 || !validDeadline(value.AnchorExpiresAt) ||
			!value.AnchorExpiresAt.After(now) || !validVersionAsInt64(value.AnchorVersion) {
			return false
		}
		sessionAnchor := value.SessionID != zero && value.SessionFamilyID != zero && value.ContinuationID == zero
		continuationAnchor := value.SessionID == zero && value.SessionFamilyID == zero && value.ContinuationID != zero
		if !sessionAnchor && !continuationAnchor {
			return false
		}
		decision := identity.EvaluateAssurance(now, value.Requirement, value.BaselineEvidence, true)
		return decision == identity.AssuranceSatisfied && value.Requirement.Level >= identity.AssuranceMFA ||
			continuationAnchor && !value.AnchorRecoveryRestricted && decision == identity.AssuranceEnrollmentOnly ||
			sessionAnchor && value.AnchorRecoveryRestricted &&
				decision == identity.AssuranceStepUpRequired && hasLiveRecoveryEvidence(now, value.BaselineEvidence)
	case PurposePrimaryAuthentication:
		if value.SessionID != zero || value.SessionFamilyID != zero || value.ContinuationID != zero ||
			value.AnchorRecoveryRestricted ||
			value.AnchorVersion != 0 || !value.AnchorExpiresAt.IsZero() || len(value.BaselineEvidence) != 0 {
			return false
		}
		return mode == AuthenticationKnownUser && value.UserID != zero && validVersionAsInt64(value.IdentityEpoch) ||
			mode == AuthenticationDiscoverable && value.UserID == zero && value.IdentityEpoch == 0
	case PurposeContinuationAuthentication:
		return mode == AuthenticationKnownUser && value.UserID != zero && validVersionAsInt64(value.IdentityEpoch) &&
			!value.AnchorRecoveryRestricted &&
			value.SessionID == zero && value.SessionFamilyID == zero && value.ContinuationID != zero &&
			validVersionAsInt64(value.AnchorVersion) && validDeadline(value.AnchorExpiresAt) &&
			value.AnchorExpiresAt.After(now) &&
			len(value.BaselineEvidence) > 0
	case PurposeStepUpAuthentication:
		return mode == AuthenticationKnownUser && value.UserID != zero && validVersionAsInt64(value.IdentityEpoch) &&
			value.SessionID != zero && value.SessionFamilyID != zero && value.ContinuationID == zero &&
			validVersionAsInt64(value.AnchorVersion) && validDeadline(value.AnchorExpiresAt) &&
			value.AnchorExpiresAt.After(now) &&
			len(value.BaselineEvidence) > 0
	default:
		return false
	}
}

func hasLiveRecoveryEvidence(now time.Time, values []identity.AssuranceEvidence) bool {
	for _, value := range values {
		if value.Kind == identity.AssuranceEvidenceRecovery && value.Source.Local &&
			!value.AuthenticatedAt.After(now) && (value.ExpiresAt == nil || value.ExpiresAt.After(now)) {
			return true
		}
	}
	return false
}

func validBaselineEvidence(now time.Time, values []identity.AssuranceEvidence) bool {
	if len(values) > 1_024 {
		return false
	}
	for _, value := range values {
		if value.AuthenticatedAt.After(now) {
			return false
		}
	}
	requirement := identity.EffectiveAssuranceRequirement{
		Level:           identity.AssurancePrimary,
		PolicyRevisions: []identity.AssurancePolicyRevision{{PolicyID: identity.EntityID{1}, Revision: 1}},
	}
	return identity.EvaluateAssurance(now, requirement, values, false) != identity.AssuranceDenied
}

func validAction(value string) bool {
	if value == "" || len(value) > maximumActionBytes || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}

func validPolicy(value CeremonyPolicy, purpose CeremonyPurpose, requirement identity.EffectiveAssuranceRequirement) bool {
	if !value.RequireUserPresence ||
		(value.UserVerification != UserVerificationPreferred && value.UserVerification != UserVerificationRequired) ||
		(value.ResidentKey != ResidentKeyPreferred && value.ResidentKey != ResidentKeyRequired) {
		return false
	}
	switch value.Attestation {
	case AttestationNone:
		if value.MetadataRevision != 0 {
			return false
		}
	case AttestationDirect, AttestationEnterprise:
		if !validVersionAsInt64(value.MetadataRevision) {
			return false
		}
	default:
		return false
	}
	if purpose == PurposeRegistration && value.UserVerification != UserVerificationRequired {
		return false
	}
	if (requirement.Level >= identity.AssurancePhishingResistant ||
		purpose == PurposePrimaryAuthentication && requirement.Level > identity.AssurancePrimary) &&
		value.UserVerification != UserVerificationRequired {
		return false
	}
	if purpose != PurposeRegistration && (value.Attestation != AttestationNone || value.MetadataRevision != 0) {
		return false
	}
	return true
}

func normalizeCredentialIDs(values [][]byte, limits Limits, allowEmpty bool) ([][]byte, bool) {
	if len(values) > limits.MaxAllowedCredentials || !allowEmpty && len(values) == 0 {
		return nil, false
	}
	result := make([][]byte, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if len(value) < minimumCredentialIDBytes || len(value) > limits.MaxCredentialIDBytes {
			return nil, false
		}
		key := string(value)
		if _, duplicate := seen[key]; duplicate {
			return nil, false
		}
		seen[key] = struct{}{}
		result = append(result, append([]byte(nil), value...))
	}
	slices.SortFunc(result, bytes.Compare)
	return result, true
}

func normalizeTransports(values []CredentialTransport) ([]CredentialTransport, bool) {
	if len(values) > 16 {
		return nil, false
	}
	result := append([]CredentialTransport(nil), values...)
	slices.Sort(result)
	for index, value := range result {
		switch value {
		case TransportUSB, TransportNFC, TransportBLE, TransportInternal, TransportHybrid, TransportSmartCard:
		default:
			return nil, false
		}
		if index > 0 && value == result[index-1] {
			return nil, false
		}
	}
	return result, true
}

func validOpaqueArtifact(value []byte) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(artifactEntropyBytes) {
		return false
	}
	decoded := make([]byte, artifactEntropyBytes)
	count, err := base64.RawURLEncoding.Strict().Decode(decoded, value)
	valid := err == nil && count == artifactEntropyBytes && !allZeroBytes(decoded) &&
		base64.RawURLEncoding.EncodeToString(decoded) == string(value)
	clear(decoded)
	return valid
}

func totalWithin(limit int, values ...[]byte) bool {
	total := 0
	for _, value := range values {
		if len(value) > limit-total {
			return false
		}
		total += len(value)
	}
	return total <= limit
}

func validUserHandle(value []byte) bool {
	return len(value) == stableUserHandleBytes && !allZeroBytes(value)
}

func validCredentialProjection(value Credential, claimed ClaimedCeremony, response AuthenticationResponse, limits Limits) bool {
	zero := identity.EntityID{}
	if value.Status != CredentialActive || !validVersionAsInt64(value.Version) ||
		!validVersionAsInt64(value.SecurityRevision) || value.SecurityRevision > value.Version || value.TenantID == zero ||
		value.UserID == zero || !validVersionAsInt64(value.IdentityEpoch) ||
		len(value.ID) < minimumCredentialIDBytes || len(value.ID) > limits.MaxCredentialIDBytes ||
		len(value.PublicKey) < minimumPublicKeyBytes || len(value.PublicKey) > limits.MaxPublicKeyBytes ||
		!bytes.Equal(value.ID, response.CredentialID) || value.RPID != claimed.RP.id ||
		value.RPRevision != claimed.RP.revision || value.TenantID != claimed.Binding.TenantID ||
		value.BackedUp && !value.BackupEligible {
		return false
	}
	if _, ok := normalizeTransports(value.Transports); !ok {
		return false
	}
	if claimed.Mode == AuthenticationDiscoverable {
		return claimed.UserHandleDigest == ([sha256.Size]byte{}) && value.Discoverable &&
			validUserHandle(response.UserHandle) &&
			sha256.Sum256(response.UserHandle) == value.UserHandleDigest
	}
	if claimed.UserHandleDigest == ([sha256.Size]byte{}) || value.UserHandleDigest != claimed.UserHandleDigest ||
		claimed.Binding.UserID != value.UserID || claimed.Binding.IdentityEpoch != value.IdentityEpoch ||
		!credentialAllowed(response.CredentialID, claimed.AllowedCredentialIDs) {
		return false
	}
	return len(response.UserHandle) == 0 ||
		validUserHandle(response.UserHandle) && sha256.Sum256(response.UserHandle) == value.UserHandleDigest
}

func credentialAllowed(id []byte, allowed [][]byte) bool {
	index, found := slices.BinarySearchFunc(allowed, id, bytes.Compare)
	return found && index >= 0
}

func validProofCommon(challenge [sha256.Size]byte, origin string, rp RelyingParty, rpHash [sha256.Size]byte,
	userPresent, userVerified, crossOrigin bool, policy CeremonyPolicy,
) bool {
	if challenge == ([sha256.Size]byte{}) || !slices.Contains(rp.origins, origin) ||
		rpHash != sha256.Sum256([]byte(rp.id)) || crossOrigin || !userPresent {
		return false
	}
	return policy.UserVerification != UserVerificationRequired || userVerified
}

// EvaluateSignCount follows ADR-0010 exactly: an always-zero authenticator is
// usable, while any non-increasing value after a nonzero counter is clone risk.
func EvaluateSignCount(stored, observed uint32) CounterDisposition {
	if stored == 0 && observed == 0 {
		return CounterUnsupported
	}
	if observed > stored {
		return CounterAdvance
	}
	return CounterCloneSuspected
}

func validCounterResult(request AuthenticationCompletion, result AuthenticationApplyResult) bool {
	expectedSecurityRevision, ok := authenticationSecurityRevision(request)
	if !ok || result.CredentialVersion != request.ExpectedCredentialVersion+1 ||
		result.SecurityRevision != expectedSecurityRevision || result.SecurityRevision > result.CredentialVersion ||
		result.BackedUp && !result.BackupEligible ||
		result.BackupEligible != request.BackupEligible || result.BackedUp != request.BackedUp {
		return false
	}
	switch request.CounterDisposition {
	case CounterUnsupported:
		return request.ExpectedSignCount == 0 && result.Status == CredentialActive && result.SignCount == 0
	case CounterAdvance:
		return result.Status == CredentialActive && result.SignCount == request.ObservedSignCount
	case CounterCloneSuspected:
		return result.Status == CredentialCloneSuspected && result.SignCount == request.ExpectedSignCount
	default:
		return false
	}
}

func authenticationSecurityRevision(request AuthenticationCompletion) (uint64, bool) {
	if !validVersionAsInt64(request.ExpectedCredentialVersion) ||
		!validVersionAsInt64(request.ExpectedSecurityRevision) ||
		request.ExpectedSecurityRevision > request.ExpectedCredentialVersion ||
		request.BackedUp && !request.BackupEligible ||
		request.ExpectedBackedUp && !request.ExpectedBackupEligible {
		return 0, false
	}
	result := request.ExpectedSecurityRevision
	if request.CounterDisposition == CounterCloneSuspected ||
		request.ExpectedBackupEligible != request.BackupEligible || request.ExpectedBackedUp != request.BackedUp {
		result++
	}
	return result, validVersionAsInt64(result) && result <= request.ExpectedCredentialVersion+1
}

func validAttestationFormat(value string) bool {
	switch value {
	case "none", "packed", "tpm", "android-key", "android-safetynet", "fido-u2f", "apple":
		return true
	default:
		return false
	}
}

func validVersionAsInt64(value uint64) bool { return value > 0 && value <= maximumJSONSafeRevision }

func cloneRP(value RelyingParty) RelyingParty {
	return RelyingParty{id: value.id, origins: append([]string(nil), value.origins...), revision: value.revision}
}

func cloneBinding(value CeremonyBinding) CeremonyBinding {
	value.Requirement.PolicyRevisions = append([]identity.AssurancePolicyRevision(nil), value.Requirement.PolicyRevisions...)
	if value.Requirement.EnrollmentDeadline != nil {
		deadline := *value.Requirement.EnrollmentDeadline
		value.Requirement.EnrollmentDeadline = &deadline
	}
	value.BaselineEvidence = cloneAssuranceEvidence(value.BaselineEvidence)
	return value
}

func cloneAssuranceEvidence(values []identity.AssuranceEvidence) []identity.AssuranceEvidence {
	result := append([]identity.AssuranceEvidence(nil), values...)
	for index := range result {
		if result[index].ExpiresAt != nil {
			copyValue := *result[index].ExpiresAt
			result[index].ExpiresAt = &copyValue
		}
		if result[index].FactorRevision != nil {
			copyValue := *result[index].FactorRevision
			result[index].FactorRevision = &copyValue
		}
		if result[index].TrustRuleRevision != nil {
			copyValue := *result[index].TrustRuleRevision
			result[index].TrustRuleRevision = &copyValue
		}
	}
	return result
}

func cloneBytes2D(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = append([]byte(nil), values[index]...)
	}
	return result
}
