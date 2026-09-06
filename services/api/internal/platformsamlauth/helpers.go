package platformsamlauth

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/returnpath"
)

const (
	maximumExactRevision       = uint64(9_007_199_254_740_991)
	maximumUUIDMilliseconds    = uint64(253_402_300_799_999)
	maximumAuditUserAgentBytes = 512
	maximumPublicTextBytes     = 4 * 1_024
	maximumSubjectBytes        = 16 * 1_024
	maximumSessionFieldBytes   = 16 * 1_024
)

var loginKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)

func validUUIDv7(value identity.EntityID) bool {
	if value == (identity.EntityID{}) || value[6]>>4 != 7 || value[8]&0xc0 != 0x80 {
		return false
	}
	milliseconds := uint64(value[0])<<40 | uint64(value[1])<<32 | uint64(value[2])<<24 |
		uint64(value[3])<<16 | uint64(value[4])<<8 | uint64(value[5])
	return milliseconds <= maximumUUIDMilliseconds && binary.BigEndian.Uint64(value[8:]) != 0
}

func validRevision(value uint64) bool { return value > 0 && value <= maximumExactRevision }

func validSuccessorRevision(value uint64) bool { return value > 0 && value < maximumExactRevision }

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%int(time.Microsecond) == 0
}

func validText(value string, maximum int, allowEmpty bool) bool {
	if (!allowEmpty && value == "") || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || directionalControl(character) {
			return false
		}
	}
	return true
}

func directionalControl(character rune) bool {
	return character == '\u200e' || character == '\u200f' ||
		character >= '\u202a' && character <= '\u202e' ||
		character >= '\u2066' && character <= '\u2069'
}

func validAuditContext(audit AuditContext) bool {
	return validUUIDv7(audit.RequestID) && validUUIDv7(audit.CorrelationID) &&
		audit.RemoteAddress.IsValid() && audit.RemoteAddress.Zone() == "" &&
		audit.RemoteAddress == audit.RemoteAddress.Unmap() &&
		validText(audit.UserAgent, maximumAuditUserAgentBytes, false)
}

func validReturnPath(value string) bool {
	return returnpath.Valid(value)
}

func validStartLookup(lookup StartLookup) bool {
	begin := lookup.Begin
	receipt := [sha256.Size]byte(begin.ReceiptDigest)
	network := [sha256.Size]byte(begin.NetworkDigest)
	account := [sha256.Size]byte(begin.AccountDigest)
	provider := [sha256.Size]byte(begin.ProviderDigest)
	return validUUIDv7(begin.OperationRunID) && loginKeyPattern.MatchString(lookup.LoginKey) &&
		receipt != ([sha256.Size]byte{}) && network != ([sha256.Size]byte{}) &&
		account != ([sha256.Size]byte{}) && provider != ([sha256.Size]byte{}) &&
		receipt != network && receipt != account && receipt != provider &&
		network != account && network != provider && account != provider
}

func validCallbackConfigurationLookup(lookup CallbackConfigurationLookup) bool {
	transaction := lookup.Transaction
	return transaction.TransactionID != (federatedsaml.TransactionID{}) &&
		validSuccessorRevision(transaction.ExpectedVersion) && validDirectProtocolPins(transaction.Pins)
}

func validDirectProvider(provider identity.ProviderContext) bool {
	return provider.Scope == identity.PlatformProviderScope && provider.TenantID == (identity.EntityID{}) &&
		validUUIDv7(provider.ProviderID)
}

func validDirectSAMLPins(pins DirectSAMLPins) bool {
	return validDirectProtocolPins(pins.Protocol) && validUUIDv7(pins.PlatformFloorPolicyID) &&
		validRevision(pins.PlatformFloorPolicyRevision)
}

func validDirectProtocolPins(protocol federatedsaml.TransactionPins) bool {
	return protocol.Authority == federatedsaml.DirectPlatformCeremonyAuthority &&
		validDirectProvider(protocol.Provider) && protocol.BindingID == (identity.EntityID{}) &&
		validRevision(protocol.ProviderRevision) && protocol.BindingRevision == 0 &&
		validRevision(protocol.PlatformLoginRevision) && validRevision(protocol.ConfigurationRevision) &&
		validRevision(protocol.SecurityRevision) && validRevision(protocol.PlanRevision) &&
		protocol.MappingRevision == 0 && protocol.AuthorizationRevision == 0 &&
		validRevision(protocol.AssurancePolicyRevision) && validRevision(protocol.MetadataRevision) &&
		protocol.MetadataDigest != ([sha256.Size]byte{}) && validRevision(protocol.SPKeyRevision) &&
		protocol.ConfigurationDigest != ([sha256.Size]byte{})
}

func validConfigurationSnapshot(snapshot ConfigurationSnapshot, observedAt time.Time) bool {
	configuration := snapshot.Authentication
	protocol := snapshot.Pins.Protocol
	return snapshot.ProviderKind == ProviderKindSAML && validDirectSAMLPins(snapshot.Pins) &&
		configuration.Authority == federatedsaml.DirectPlatformCeremonyAuthority &&
		configuration.Provider == protocol.Provider && configuration.BindingID == (identity.EntityID{}) &&
		configuration.ProviderRevision == protocol.ProviderRevision && configuration.BindingRevision == 0 &&
		configuration.PlatformLoginRevision == protocol.PlatformLoginRevision &&
		configuration.ConfigurationRevision == protocol.ConfigurationRevision &&
		configuration.SecurityRevision == protocol.SecurityRevision && configuration.PlanRevision == protocol.PlanRevision &&
		configuration.MappingRevision == 0 && configuration.AuthorizationRevision == 0 &&
		configuration.AssurancePolicyRevision == protocol.AssurancePolicyRevision &&
		configuration.Metadata.Revision() == protocol.MetadataRevision &&
		configuration.Metadata.Digest() == protocol.MetadataDigest && configuration.SPKeyRevision == protocol.SPKeyRevision &&
		validDirectACSURL(configuration.ACSURL) && validText(configuration.SPEntityID, maximumPublicTextBytes, false) &&
		validText(configuration.Metadata.EntityID(), maximumPublicTextBytes, false) &&
		len(configuration.Mapping.Scalars) == 0 && len(configuration.Mapping.Profiles) == 0 && configuration.Mapping.Groups == nil &&
		federatedsaml.ValidatePinnedConfiguration(configuration, protocol, observedAt) == nil
}

func validDirectACSURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.Path == DirectSAMLACSURL && parsed.RawPath == "" && parsed.RawQuery == "" && parsed.Fragment == "" &&
		parsed.String() == value
}

func authenticationProofFromJIT(authentication federatedsaml.JITAuthentication) AuthenticationProof {
	return AuthenticationProof{
		Issuer: authentication.Issuer(), SubjectSource: authentication.SubjectSource(),
		SubjectName: authentication.SubjectName(), SubjectFormat: authentication.SubjectFormat(),
		SubjectValue: authentication.SubjectValue(), Scalars: authentication.Scalars(),
		Profiles: authentication.Profiles(), Groups: authentication.Groups(),
		AuthnContext: authentication.AuthnContextClassRef(), AuthenticatedAt: authentication.AuthenticatedAt(),
		ValidUntil: authentication.ValidUntil(), SessionMaterial: authentication.SessionMaterial(),
	}
}

func validProofShape(proof AuthenticationProof) bool {
	if !validText(proof.Issuer, maximumPublicTextBytes, false) ||
		!validText(proof.SubjectValue, maximumSubjectBytes, false) ||
		!validText(proof.AuthnContext, maximumPublicTextBytes, false) ||
		!validInstant(proof.AuthenticatedAt) || !validInstant(proof.ValidUntil) ||
		!proof.ValidUntil.After(proof.AuthenticatedAt) || len(proof.Scalars) != 0 ||
		len(proof.Profiles) != 0 || len(proof.Groups) != 0 || !validSessionMaterial(proof.SessionMaterial) {
		return false
	}
	switch proof.SubjectSource {
	case federatedsaml.SubjectPersistentNameID:
		return proof.SubjectName == "NameID" && proof.SubjectFormat == federatedsaml.PersistentNameIDFormat
	case federatedsaml.SubjectImmutableAttribute:
		return validText(proof.SubjectName, 512, false) && validText(proof.SubjectFormat, 512, false)
	default:
		return false
	}
}

func validProofForConfiguration(proof AuthenticationProof, configuration federatedsaml.Configuration) bool {
	if !validProofShape(proof) || proof.Issuer != configuration.Metadata.EntityID() ||
		proof.SubjectSource != configuration.Subject.Source {
		return false
	}
	if proof.SubjectSource == federatedsaml.SubjectPersistentNameID {
		return configuration.Subject.AttributeName == "" && configuration.Subject.AttributeNameFormat == ""
	}
	return proof.SubjectName == configuration.Subject.AttributeName &&
		proof.SubjectFormat == configuration.Subject.AttributeNameFormat
}

func validSessionMaterial(material federatedsaml.SessionMaterial) bool {
	if material == (federatedsaml.SessionMaterial{}) {
		return true
	}
	if (material.NameID == "") != (material.NameIDFormat == "") ||
		material.NameID != "" && (material.NameIDFormat != federatedsaml.PersistentNameIDFormat ||
			!validText(material.NameID, maximumSessionFieldBytes, false)) ||
		material.SessionIndex != "" && !validText(material.SessionIndex, 2*1024, false) {
		return false
	}
	return true
}

func sameProof(left, right AuthenticationProof) bool {
	return left.Issuer == right.Issuer && left.SubjectSource == right.SubjectSource &&
		left.SubjectName == right.SubjectName && left.SubjectFormat == right.SubjectFormat &&
		left.SubjectValue == right.SubjectValue && slices.Equal(left.Scalars, right.Scalars) &&
		slices.Equal(left.Profiles, right.Profiles) && slices.Equal(left.Groups, right.Groups) &&
		left.AuthnContext == right.AuthnContext && left.AuthenticatedAt.Equal(right.AuthenticatedAt) &&
		left.ValidUntil.Equal(right.ValidUntil) && left.SessionMaterial == right.SessionMaterial
}

func validConsumptionShape(consumption Consumption) bool {
	sessionIndex := consumption.HasSessionIndex == (consumption.SessionIndexDigest != ([sha256.Size]byte{}))
	return consumption.TransactionID != (federatedsaml.TransactionID{}) && validUUIDv7(consumption.MaterialID) &&
		validSuccessorRevision(consumption.ExpectedVersion) && validDirectProtocolPins(consumption.Pins) &&
		validText(consumption.ResponseID, 1024, false) &&
		validText(consumption.AssertionID, 1024, false) && consumption.ResponseID != consumption.AssertionID &&
		validInstant(consumption.ConsumedAt) && validReturnPath(consumption.ReturnPath) && sessionIndex &&
		consumption.HasSessionIndex == (consumption.Authentication.SessionMaterial.SessionIndex != "") &&
		validProofShape(consumption.Authentication)
}

func validConsumptionAuthority(authority ConsumptionAuthority) bool {
	sessionIndex := authority.HasSessionIndex == (authority.SessionIndexDigest != ([sha256.Size]byte{}))
	return authority.TransactionID != (federatedsaml.TransactionID{}) && validUUIDv7(authority.MaterialID) &&
		validSuccessorRevision(authority.ExpectedVersion) && validDirectProtocolPins(authority.Pins) &&
		validText(authority.ResponseID, 1024, false) && validText(authority.AssertionID, 1024, false) &&
		authority.ResponseID != authority.AssertionID && validInstant(authority.ConsumedAt) &&
		validReturnPath(authority.ReturnPath) && sessionIndex
}

func validConsumptionForConfiguration(
	consumption Consumption,
	pins DirectSAMLPins,
	configuration federatedsaml.Configuration,
	observedAt time.Time,
) bool {
	return validConsumptionShape(consumption) && validDirectSAMLPins(pins) && consumption.Pins == pins.Protocol &&
		validConfigurationSnapshot(ConfigurationSnapshot{
			Pins: pins, ProviderKind: ProviderKindSAML, Authentication: configuration,
		}, observedAt) && validProofForConfiguration(consumption.Authentication, configuration) &&
		!consumption.ConsumedAt.After(observedAt) && consumption.Authentication.ValidUntil.After(observedAt)
}

func callbackProof(callback *ValidatedCallback) AuthenticationProof {
	if callback == nil {
		return AuthenticationProof{}
	}
	return cloneProof(callback.proof)
}

func cloneProof(value AuthenticationProof) AuthenticationProof {
	value.Scalars = append([]federatedsaml.NamedScalar(nil), value.Scalars...)
	value.Profiles = append([]federatedsaml.ProfileValue(nil), value.Profiles...)
	value.Groups = append([]string(nil), value.Groups...)
	return value
}

func cloneConfiguration(value federatedsaml.Configuration) federatedsaml.Configuration {
	value.DecryptionKeyVersions = append([]uint32(nil), value.DecryptionKeyVersions...)
	value.DirectPlatformDecryptionKeyRevisions = append([]uint64(nil), value.DirectPlatformDecryptionKeyRevisions...)
	value.RequestedAuthnContexts = append([]string(nil), value.RequestedAuthnContexts...)
	value.Mapping.Scalars = append([]federatedsaml.ScalarAttributeRule(nil), value.Mapping.Scalars...)
	value.Mapping.Profiles = append([]federatedsaml.ProfileAttributeRule(nil), value.Mapping.Profiles...)
	if value.Mapping.Groups != nil {
		copyValue := *value.Mapping.Groups
		value.Mapping.Groups = &copyValue
	}
	value.TrustRules = append([]federatedsaml.AuthnContextTrustRule(nil), value.TrustRules...)
	return value
}

func cloneConfigurationSnapshot(value ConfigurationSnapshot) ConfigurationSnapshot {
	value.Authentication = cloneConfiguration(value.Authentication)
	return value
}

func clonePlanningLookup(value PlanningLookup) PlanningLookup {
	value.SubjectAliases = append([]identity.SubjectAlias(nil), value.SubjectAliases...)
	return value
}

func clonePlanningState(value PlanningState) PlanningState {
	value.Matches = append([]IdentityMatch(nil), value.Matches...)
	value.TrustRules = append([]TrustRule(nil), value.TrustRules...)
	value.PlatformFloor = cloneRequirement(value.PlatformFloor)
	value.LiveConfirmedTOTPFactors = cloneTOTPFactors(value.LiveConfirmedTOTPFactors)
	return value
}

func cloneRequirement(value identity.EffectiveAssuranceRequirement) identity.EffectiveAssuranceRequirement {
	value.PolicyRevisions = append([]identity.AssurancePolicyRevision(nil), value.PolicyRevisions...)
	if value.EnrollmentDeadline != nil {
		copyValue := *value.EnrollmentDeadline
		value.EnrollmentDeadline = &copyValue
	}
	return value
}

func cloneTOTPFactors(values []TOTPFactor) []TOTPFactor {
	result := append([]TOTPFactor(nil), values...)
	for index := range result {
		if values[index].ConfirmedAt != nil {
			copyValue := *values[index].ConfirmedAt
			result[index].ConfirmedAt = &copyValue
		}
	}
	return result
}

func cloneEvidence(values []identity.AssuranceEvidence) []identity.AssuranceEvidence {
	result := append([]identity.AssuranceEvidence(nil), values...)
	for index := range result {
		if values[index].ExpiresAt != nil {
			copyValue := *values[index].ExpiresAt
			result[index].ExpiresAt = &copyValue
		}
		if values[index].FactorRevision != nil {
			copyValue := *values[index].FactorRevision
			result[index].FactorRevision = &copyValue
		}
		if values[index].TrustRuleRevision != nil {
			copyValue := *values[index].TrustRuleRevision
			result[index].TrustRuleRevision = &copyValue
		}
	}
	return result
}

func cloneSelectedAssurance(value SelectedAssurance) SelectedAssurance {
	if value.TrustRuleID != nil {
		copyValue := *value.TrustRuleID
		value.TrustRuleID = &copyValue
	}
	if value.TrustRuleRevision != nil {
		copyValue := *value.TrustRuleRevision
		value.TrustRuleRevision = &copyValue
	}
	return value
}

func cloneSubjectObservation(value SubjectObservation) SubjectObservation {
	value.Aliases = append([]identity.SubjectAlias(nil), value.Aliases...)
	value.Envelope.Ciphertext = append([]byte(nil), value.Envelope.Ciphertext...)
	return value
}

func clonePlan(value AuthenticationPlan) AuthenticationPlan {
	value.Provenance.SelectedAssurance = cloneSelectedAssurance(value.Provenance.SelectedAssurance)
	value.Subject = cloneSubjectObservation(value.Subject)
	value.Evidence = cloneEvidence(value.Evidence)
	value.PlatformFloor = cloneRequirement(value.PlatformFloor)
	if value.TOTP != nil {
		copyValue := *value.TOTP
		value.TOTP = &copyValue
	}
	return value
}

func cloneConsumption(value Consumption) Consumption {
	value.Authentication = cloneProof(value.Authentication)
	return value
}

func cloneProtectedMaterial(value ProtectedSessionMaterial) ProtectedSessionMaterial {
	value.Envelope.Ciphertext = append([]byte(nil), value.Envelope.Ciphertext...)
	return value
}

func cloneAuthorizationStart(value AuthorizationStart) AuthorizationStart {
	return value
}

func cloneApplyRequest(value ApplyRequest) ApplyRequest {
	value.Plan = clonePlan(value.Plan)
	value.ProtectedSessionMaterial = cloneProtectedMaterial(value.ProtectedSessionMaterial)
	return value
}

func consumptionAuthority(value Consumption) ConsumptionAuthority {
	return ConsumptionAuthority{
		TransactionID: value.TransactionID, MaterialID: value.MaterialID,
		ExpectedVersion: value.ExpectedVersion, Pins: value.Pins,
		ResponseID: value.ResponseID, AssertionID: value.AssertionID,
		SessionIndexDigest: value.SessionIndexDigest, HasSessionIndex: value.HasSessionIndex,
		HasSessionMaterial: value.Authentication.SessionMaterial != (federatedsaml.SessionMaterial{}),
		ConsumedAt:         value.ConsumedAt, ReturnPath: value.ReturnPath,
	}
}

var sessionMaterialPrefix = [...]byte{'P', 'D', 'S', 'M', 1}

func protectSessionMaterial(
	keyring identity.Keyring,
	consumption Consumption,
) (ProtectedSessionMaterial, error) {
	material := consumption.Authentication.SessionMaterial
	if material == (federatedsaml.SessionMaterial{}) {
		return ProtectedSessionMaterial{}, nil
	}
	plaintext, ok := encodeSessionMaterial(material)
	if !ok {
		return ProtectedSessionMaterial{}, ErrAuthenticationDenied
	}
	defer clear(plaintext)
	envelope, err := keyring.EncryptDirectPlatformSAMLSessionMaterial(
		identity.DirectPlatformSAMLSessionMaterialContext{
			Provider: consumption.Pins.Provider, MaterialID: consumption.MaterialID,
			PlatformLoginRevision: consumption.Pins.PlatformLoginRevision,
		},
		plaintext,
	)
	if err != nil {
		clear(envelope.Nonce[:])
		clear(envelope.Ciphertext)
		return ProtectedSessionMaterial{}, ErrAuthenticationUnavailable
	}
	return ProtectedSessionMaterial{Envelope: envelope}, nil
}

func encodeSessionMaterial(material federatedsaml.SessionMaterial) ([]byte, bool) {
	if material == (federatedsaml.SessionMaterial{}) || !validSessionMaterial(material) {
		return nil, false
	}
	length := len(sessionMaterialPrefix) + 12 + len(material.NameID) + len(material.NameIDFormat) + len(material.SessionIndex)
	if length > maximumSessionFieldBytes {
		return nil, false
	}
	document := make([]byte, 0, length)
	document = append(document, sessionMaterialPrefix[:]...)
	document = appendMaterialField(document, material.NameID)
	document = appendMaterialField(document, material.NameIDFormat)
	document = appendMaterialField(document, material.SessionIndex)
	return document, true
}

func appendMaterialField(destination []byte, value string) []byte {
	length := [4]byte{}
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	destination = append(destination, length[:]...)
	return append(destination, value...)
}

func validProtectedMaterial(value ProtectedSessionMaterial, authority ConsumptionAuthority) bool {
	expected := authority.HasSessionMaterial
	present := value.Envelope.KeyVersion > 0 || value.Envelope.Nonce != ([12]byte{}) || len(value.Envelope.Ciphertext) > 0
	return expected == present && (!present || value.Envelope.KeyVersion > 0 &&
		value.Envelope.Nonce != ([12]byte{}) && len(value.Envelope.Ciphertext) > 16 &&
		len(value.Envelope.Ciphertext) <= maximumSessionFieldBytes)
}

func validAuthenticationPlan(plan AuthenticationPlan, consumption Consumption, now time.Time) bool {
	return plan.Provenance.Issuer == consumption.Authentication.Issuer &&
		plan.Provenance.AuthnContext == consumption.Authentication.AuthnContext &&
		plan.Provenance.AuthenticatedAt.Equal(consumption.Authentication.AuthenticatedAt) &&
		plan.Provenance.ValidUntil.Equal(consumption.Authentication.ValidUntil) &&
		validAuthenticationPlanForApply(plan, consumptionAuthority(consumption), now)
}

func validAuthenticationPlanForApply(plan AuthenticationPlan, authority ConsumptionAuthority, now time.Time) bool {
	if plan.Pins.Protocol != authority.Pins || !validDirectSAMLPins(plan.Pins) ||
		plan.Provenance.Provider != plan.Pins.Protocol.Provider || plan.Provenance.ProviderKind != ProviderKindSAML ||
		!validUUIDv7(plan.Provenance.ExternalIdentityID) || !validUUIDv7(plan.Provenance.UserID) ||
		!validRevision(plan.Provenance.IdentityRevision) || !validRevision(plan.Provenance.UserAuthenticationRevision) ||
		!validUUIDv7(plan.Provenance.PlatformAuthorityID) || !validRevision(plan.Provenance.PlatformAuthorityRevision) ||
		plan.Provenance.MatchedAliasKeyVersion < 1 || !validText(plan.Provenance.Issuer, maximumPublicTextBytes, false) ||
		!validText(plan.Provenance.AuthnContext, maximumPublicTextBytes, false) ||
		!validInstant(plan.Provenance.AuthenticatedAt) || !validInstant(plan.Provenance.ValidUntil) ||
		!plan.Provenance.ValidUntil.After(now) ||
		!validSelectedAssurance(plan.Provenance.SelectedAssurance) ||
		plan.Subject.ExternalIdentityID != plan.Provenance.ExternalIdentityID ||
		plan.Subject.SubjectFormat != identity.UTF8ExactSubject || !validSubjectAliases(plan.Subject.Aliases) ||
		!subjectAliasKeyVersionPresent(plan.Subject.Aliases, plan.Provenance.MatchedAliasKeyVersion) ||
		plan.Subject.Envelope.KeyVersion < 1 || plan.Subject.Envelope.Format != identity.UTF8ExactSubject ||
		len(plan.Subject.Envelope.Ciphertext) <= 16 || !validPinnedFloor(plan.PlatformFloor, plan.Pins) ||
		!validPlanEvidence(plan) {
		return false
	}
	decision := identity.EvaluateAssurance(now, plan.PlatformFloor, plan.Evidence, false)
	switch plan.Disposition {
	case ImmediateSession:
		return plan.TOTP == nil && decision == identity.AssuranceSatisfied
	case TOTPContinuation:
		return plan.TOTP != nil && validUUIDv7(plan.TOTP.FactorID) && validRevision(plan.TOTP.Revision) &&
			decision == identity.AssuranceStepUpRequired
	default:
		return false
	}
}

func validPlanEvidence(plan AuthenticationPlan) bool {
	if len(plan.Evidence) < 1 || len(plan.Evidence) > 2 {
		return false
	}
	for _, evidence := range plan.Evidence {
		if evidence.Kind != identity.AssuranceEvidenceFactor || evidence.Source.Local ||
			!evidence.Source.DirectPlatform || evidence.Source.ProviderID != plan.Pins.Protocol.Provider.ProviderID ||
			evidence.Source.BindingID != (identity.EntityID{}) || evidence.FactorRevision != nil ||
			evidence.TrustRuleRevision == nil || *evidence.TrustRuleRevision < 1 ||
			!evidence.AuthenticatedAt.Equal(plan.Provenance.AuthenticatedAt) || evidence.ExpiresAt == nil ||
			!evidence.ExpiresAt.After(evidence.AuthenticatedAt) || evidence.ExpiresAt.After(plan.Provenance.ValidUntil) {
			return false
		}
	}
	primary := plan.Evidence[0]
	if primary.Level != identity.AssurancePrimary || *primary.TrustRuleRevision != int64(plan.Pins.Protocol.SecurityRevision) ||
		!primary.ExpiresAt.Equal(plan.Provenance.ValidUntil) {
		return false
	}
	selected := plan.Provenance.SelectedAssurance
	if selected.Level == identity.AssurancePrimary {
		return len(plan.Evidence) == 1 && selected.AuthenticatedAt.Equal(primary.AuthenticatedAt)
	}
	if len(plan.Evidence) != 2 || selected.TrustRuleRevision == nil || selected.TrustRuleID == nil {
		return false
	}
	elevated := plan.Evidence[1]
	return elevated.Level == selected.Level && uint64(*elevated.TrustRuleRevision) == *selected.TrustRuleRevision &&
		selected.AuthenticatedAt.Equal(elevated.AuthenticatedAt)
}

func subjectAliasKeyVersionPresent(aliases []identity.SubjectAlias, version int16) bool {
	for _, alias := range aliases {
		if alias.KeyVersion == version {
			return true
		}
	}
	return false
}

func validApplyRequest(request ApplyRequest) bool {
	if !validConsumptionAuthority(request.Authority) || !validInstant(request.AppliedAt) ||
		request.AppliedAt.Before(request.Authority.ConsumedAt) ||
		request.SessionAudience != SessionAudience || request.RecoveryRestricted || !validAuditContext(request.Audit) ||
		!validAuthenticationPlanForApply(request.Plan, request.Authority, request.AppliedAt) ||
		!validProtectedMaterial(request.ProtectedSessionMaterial, request.Authority) {
		return false
	}
	switch request.Plan.Disposition {
	case ImmediateSession:
		if request.Session.IsZero() || request.Session.AuthenticationMethod() != mfa.SessionAuthenticationSAML ||
			!request.Session.ValidAt(request.AppliedAt.Truncate(time.Millisecond)) || !request.Continuation.IsZero() {
			return false
		}
	case TOTPContinuation:
		if !request.Session.IsZero() || request.Continuation.IsZero() || !request.Continuation.ValidAt(request.AppliedAt) ||
			request.Plan.TOTP == nil || request.Continuation.FactorID() != request.Plan.TOTP.FactorID ||
			request.Continuation.FactorRevision() != request.Plan.TOTP.Revision {
			return false
		}
	default:
		return false
	}
	digest := applyProofDigest(request)
	return digest != ([sha256.Size]byte{}) && subtle.ConstantTimeCompare(digest[:], request.ProofDigest[:]) == 1
}

func validApplyResult(result ApplyResult, request ApplyRequest) bool {
	if result.Category != ApplySuccess && result.Category != ApplyAlreadyApplied {
		return false
	}
	return validExactApplyResultProjection(result, request)
}

func validApplyFailureResult(result ApplyResult, request ApplyRequest) bool {
	switch result.Category {
	case ApplyProtocolReplay, ApplyStale, ApplyCollision, ApplyDenied:
		return validExactApplyResultProjection(result, request)
	default:
		return false
	}
}

func validExactApplyResultProjection(result ApplyResult, request ApplyRequest) bool {
	return result.TransactionID == request.Authority.TransactionID && result.ProofDigest == request.ProofDigest &&
		result.UserID == request.Plan.Provenance.UserID && result.ReturnPath == request.Authority.ReturnPath &&
		result.AppliedAt.Equal(request.AppliedAt) &&
		(request.Plan.Disposition == ImmediateSession && result.SessionID == request.Session.SessionID() &&
			result.ContinuationID == (identity.EntityID{}) ||
			request.Plan.Disposition == TOTPContinuation && result.SessionID == (identity.EntityID{}) &&
				result.ContinuationID == request.Continuation.ContinuationID())
}

func applyResultForRequest(request ApplyRequest, category ApplyCategory) ApplyResult {
	result := ApplyResult{
		Category: category, TransactionID: request.Authority.TransactionID,
		ProofDigest: request.ProofDigest, UserID: request.Plan.Provenance.UserID,
		ReturnPath: request.Authority.ReturnPath, AppliedAt: request.AppliedAt,
	}
	if request.Plan.Disposition == ImmediateSession {
		result.SessionID = request.Session.SessionID()
	} else {
		result.ContinuationID = request.Continuation.ContinuationID()
	}
	return result
}

func validCleanupRequest(request CleanupRequest) bool {
	result := request.Result
	if result.Category != ApplySuccess && result.Category != ApplyAlreadyApplied ||
		result.TransactionID == (federatedsaml.TransactionID{}) || result.ProofDigest == ([sha256.Size]byte{}) ||
		!validUUIDv7(result.UserID) || !validReturnPath(result.ReturnPath) || !validInstant(result.AppliedAt) ||
		!validInstant(request.CleanedUpAt) || request.CleanedUpAt.Before(result.AppliedAt) ||
		!validAuditContext(request.Audit) {
		return false
	}
	if request.Reason != CleanupCredentialReleaseFailed && request.Reason != CleanupProtocolFailed &&
		request.Reason != CleanupInvalidOutcome && request.Reason != CleanupDeliveryFailed {
		return false
	}
	return validUUIDv7(result.SessionID) && result.ContinuationID == (identity.EntityID{}) ||
		result.SessionID == (identity.EntityID{}) && validUUIDv7(result.ContinuationID)
}

func applyProofDigest(request ApplyRequest) [sha256.Size]byte {
	digest := sha256.New()
	writeDigestField(digest, []byte("periapsis/platform-saml/apply-proof/v1"))
	writeDigestField(digest, request.Authority.TransactionID[:])
	writeDigestField(digest, request.Authority.MaterialID[:])
	writeDigestUint64(digest, request.Authority.ExpectedVersion)
	writePinsDigest(digest, request.Plan.Pins)
	writeDigestField(digest, []byte(request.Authority.ResponseID))
	writeDigestField(digest, []byte(request.Authority.AssertionID))
	writeDigestBool(digest, request.Authority.HasSessionIndex)
	writeDigestField(digest, request.Authority.SessionIndexDigest[:])
	writeDigestBool(digest, request.Authority.HasSessionMaterial)
	writeDigestTime(digest, request.Authority.ConsumedAt)
	writeDigestField(digest, []byte(request.Authority.ReturnPath))
	writeDigestField(digest, []byte(request.Plan.Disposition))
	provenance := request.Plan.Provenance
	writeProviderDigest(digest, provenance.Provider)
	writeDigestField(digest, []byte(provenance.ProviderKind))
	writeDigestField(digest, provenance.ExternalIdentityID[:])
	writeDigestField(digest, provenance.UserID[:])
	writeDigestUint64(digest, provenance.IdentityRevision)
	writeDigestUint64(digest, provenance.UserAuthenticationRevision)
	writeDigestField(digest, provenance.PlatformAuthorityID[:])
	writeDigestUint64(digest, provenance.PlatformAuthorityRevision)
	writeDigestUint64(digest, uint64(provenance.MatchedAliasKeyVersion))
	writeDigestField(digest, []byte(provenance.Issuer))
	writeDigestField(digest, []byte(provenance.AuthnContext))
	writeDigestTime(digest, provenance.AuthenticatedAt)
	writeDigestTime(digest, provenance.ValidUntil)
	writeSelectedAssuranceDigest(digest, provenance.SelectedAssurance)
	writeDigestField(digest, request.Plan.Subject.ExternalIdentityID[:])
	writeDigestUint64(digest, uint64(request.Plan.Subject.SubjectFormat))
	writeDigestUint64(digest, uint64(len(request.Plan.Subject.Aliases)))
	for _, alias := range request.Plan.Subject.Aliases {
		writeDigestUint64(digest, uint64(alias.KeyVersion))
		writeDigestField(digest, alias.Digest[:])
	}
	writeDigestUint64(digest, uint64(request.Plan.Subject.Envelope.KeyVersion))
	writeDigestUint64(digest, uint64(request.Plan.Subject.Envelope.Format))
	writeDigestField(digest, request.Plan.Subject.Envelope.Nonce[:])
	writeDigestField(digest, request.Plan.Subject.Envelope.Ciphertext)
	writeDigestUint64(digest, uint64(len(request.Plan.Evidence)))
	for _, evidence := range request.Plan.Evidence {
		writeEvidenceDigest(digest, evidence)
	}
	writeRequirementDigest(digest, request.Plan.PlatformFloor)
	if request.Plan.TOTP == nil {
		writeDigestBool(digest, false)
	} else {
		writeDigestBool(digest, true)
		writeDigestField(digest, request.Plan.TOTP.FactorID[:])
		writeDigestUint64(digest, request.Plan.TOTP.Revision)
	}
	writeSessionDigest(digest, request.Session)
	writeContinuationDigest(digest, request.Continuation)
	writeDigestField(digest, []byte(request.SessionAudience))
	writeDigestBool(digest, request.RecoveryRestricted)
	writeDigestUint64(digest, uint64(request.ProtectedSessionMaterial.Envelope.KeyVersion))
	writeDigestField(digest, request.ProtectedSessionMaterial.Envelope.Nonce[:])
	writeDigestField(digest, request.ProtectedSessionMaterial.Envelope.Ciphertext)
	writeDigestTime(digest, request.AppliedAt)
	writeDigestField(digest, request.Audit.RequestID[:])
	writeDigestField(digest, request.Audit.CorrelationID[:])
	writeDigestField(digest, request.Audit.RemoteAddress.AsSlice())
	writeDigestField(digest, []byte(request.Audit.UserAgent))
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func writePinsDigest(digest hash.Hash, pins DirectSAMLPins) {
	protocol := pins.Protocol
	writeDigestUint64(digest, uint64(protocol.Authority))
	writeProviderDigest(digest, protocol.Provider)
	writeDigestField(digest, protocol.BindingID[:])
	writeDigestUint64(digest, protocol.ProviderRevision)
	writeDigestUint64(digest, protocol.BindingRevision)
	writeDigestUint64(digest, protocol.PlatformLoginRevision)
	writeDigestUint64(digest, protocol.ConfigurationRevision)
	writeDigestUint64(digest, protocol.SecurityRevision)
	writeDigestUint64(digest, protocol.PlanRevision)
	writeDigestUint64(digest, protocol.MappingRevision)
	writeDigestUint64(digest, protocol.AuthorizationRevision)
	writeDigestUint64(digest, protocol.AssurancePolicyRevision)
	writeDigestUint64(digest, protocol.MetadataRevision)
	writeDigestField(digest, protocol.MetadataDigest[:])
	writeDigestUint64(digest, protocol.SPKeyRevision)
	writeDigestField(digest, protocol.ConfigurationDigest[:])
	writeDigestField(digest, pins.PlatformFloorPolicyID[:])
	writeDigestUint64(digest, pins.PlatformFloorPolicyRevision)
}

func writeProviderDigest(digest hash.Hash, provider identity.ProviderContext) {
	writeDigestUint64(digest, uint64(provider.Scope))
	writeDigestField(digest, provider.TenantID[:])
	writeDigestField(digest, provider.ProviderID[:])
}

func writeSelectedAssuranceDigest(digest hash.Hash, value SelectedAssurance) {
	writeDigestUint64(digest, uint64(value.Level))
	writeDigestTime(digest, value.AuthenticatedAt)
	writeOptionalEntityDigest(digest, value.TrustRuleID)
	writeOptionalUint64Digest(digest, value.TrustRuleRevision)
}

func writeEvidenceDigest(digest hash.Hash, value identity.AssuranceEvidence) {
	writeDigestUint64(digest, uint64(value.Level))
	writeDigestUint64(digest, uint64(value.Kind))
	writeDigestBool(digest, value.Source.Local)
	writeDigestBool(digest, value.Source.DirectPlatform)
	writeDigestField(digest, value.Source.ProviderID[:])
	writeDigestField(digest, value.Source.BindingID[:])
	writeDigestTime(digest, value.AuthenticatedAt)
	writeOptionalTimeDigest(digest, value.ExpiresAt)
	if value.FactorRevision == nil {
		writeDigestBool(digest, false)
	} else {
		writeDigestBool(digest, true)
		writeDigestUint64(digest, uint64(*value.FactorRevision))
	}
	if value.TrustRuleRevision == nil {
		writeDigestBool(digest, false)
	} else {
		writeDigestBool(digest, true)
		writeDigestUint64(digest, uint64(*value.TrustRuleRevision))
	}
}

func writeRequirementDigest(digest hash.Hash, value identity.EffectiveAssuranceRequirement) {
	writeDigestUint64(digest, uint64(value.Level))
	writeDigestBool(digest, value.LocalRequired)
	writeDigestUint64(digest, uint64(value.Freshness))
	writeOptionalTimeDigest(digest, value.EnrollmentDeadline)
	writeDigestUint64(digest, uint64(len(value.PolicyRevisions)))
	for _, revision := range value.PolicyRevisions {
		writeDigestField(digest, revision.PolicyID[:])
		writeDigestUint64(digest, uint64(revision.Revision))
	}
}

func writeSessionDigest(digest hash.Hash, reservation mfa.SessionReservation) {
	writeDigestBool(digest, !reservation.IsZero())
	if reservation.IsZero() {
		return
	}
	sessionID := reservation.SessionID()
	familyID := reservation.FamilyID()
	tokenDigest := reservation.TokenDigest()
	csrfDigest := reservation.CSRFDigest()
	writeDigestField(digest, sessionID[:])
	writeDigestField(digest, familyID[:])
	writeDigestField(digest, tokenDigest[:])
	writeDigestField(digest, csrfDigest[:])
	writeDigestField(digest, []byte(reservation.AuthenticationMethod()))
	writeDigestTime(digest, reservation.IdleExpiresAt())
	writeDigestTime(digest, reservation.AbsoluteExpiresAt())
}

func writeContinuationDigest(digest hash.Hash, reservation ContinuationReservation) {
	writeDigestBool(digest, !reservation.IsZero())
	if reservation.IsZero() {
		return
	}
	id := reservation.ContinuationID()
	factorID := reservation.FactorID()
	receiptDigest := reservation.ReceiptDigest()
	writeDigestField(digest, id[:])
	writeDigestField(digest, factorID[:])
	writeDigestUint64(digest, reservation.FactorRevision())
	writeDigestField(digest, receiptDigest[:])
	writeDigestTime(digest, reservation.ExpiresAt())
}

func writeOptionalEntityDigest(digest hash.Hash, value *identity.EntityID) {
	writeDigestBool(digest, value != nil)
	if value != nil {
		writeDigestField(digest, value[:])
	}
}

func writeOptionalUint64Digest(digest hash.Hash, value *uint64) {
	writeDigestBool(digest, value != nil)
	if value != nil {
		writeDigestUint64(digest, *value)
	}
}

func writeOptionalTimeDigest(digest hash.Hash, value *time.Time) {
	writeDigestBool(digest, value != nil)
	if value != nil {
		writeDigestTime(digest, *value)
	}
}

func writeDigestTime(digest hash.Hash, value time.Time) {
	writeDigestUint64(digest, uint64(value.UnixMicro()))
}

func writeDigestBool(digest hash.Hash, value bool) {
	if value {
		writeDigestField(digest, []byte{1})
	} else {
		writeDigestField(digest, []byte{0})
	}
}

func writeDigestUint64(digest hash.Hash, value uint64) {
	encoded := [8]byte{}
	binary.BigEndian.PutUint64(encoded[:], value)
	writeDigestField(digest, encoded[:])
}

func writeDigestField(digest hash.Hash, value []byte) {
	length := [8]byte{}
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = digest.Write(length[:])
	_, _ = digest.Write(value)
}

func canonicalBrowserHandle(value []byte) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(sha256.Size) {
		return false
	}
	var decoded [sha256.Size]byte
	written, err := base64.RawURLEncoding.Strict().Decode(decoded[:], value)
	canonical := make([]byte, base64.RawURLEncoding.EncodedLen(len(decoded)))
	base64.RawURLEncoding.Encode(canonical, decoded[:])
	valid := err == nil && written == len(decoded) && bytes.Equal(canonical, value)
	clear(decoded[:])
	clear(canonical)
	return valid
}
