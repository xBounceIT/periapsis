package webhookurlpolicy

import (
	"crypto/sha256"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
)

const maximumProjectionClockSkew = time.Minute

func normalizeDraft(input PolicyDraft) (PolicyDraft, [sha256.Size]byte, error) {
	rules, err := canonicalRules(input.Rules)
	if err != nil {
		return PolicyDraft{}, [sha256.Size]byte{}, ErrInvalidInput
	}
	normalized := PolicyDraft{Rules: ruleInputs(rules)}
	parts := []string{"periapsis.webhook-url-policy-semantics.v1", "https", "deny"}
	for _, rule := range rules {
		parts = append(parts, canonicalRuleRecord(rule))
	}
	return normalized, framedDigest(parts...), nil
}

func validStoredPolicy(policy Policy, tenantID uuid.UUID, now time.Time) bool {
	return validUUIDv7(tenantID) && validPolicy(policy) && policy.tenantID == tenantID &&
		!policy.publishedAt.After(now.Add(maximumProjectionClockSkew))
}

func validPublishResult(
	result PublishResult,
	tenantID uuid.UUID,
	expectedVersion int64,
	semanticDigest [sha256.Size]byte,
	publisherMembershipID uuid.UUID,
	command CommandBinding,
	now time.Time,
) bool {
	return expectedVersion >= 0 && expectedVersion < MaximumPolicyVersion &&
		validStoredPolicy(result.Policy, tenantID, now) && result.Policy.version == expectedVersion+1 &&
		result.Policy.semanticDigest == semanticDigest && result.Policy.publishedByMembershipID == publisherMembershipID &&
		result.Command == command
}

func validSession(session authentication.Session, tenantID uuid.UUID, now time.Time) bool {
	return validUUIDv7(tenantID) && validUUIDv7(session.ID) && validUUIDv7(session.User.ID) &&
		session.ActiveTenantID != nil && *session.ActiveTenantID == tenantID &&
		validAuthenticationMethod(session.AuthenticationMethod) && session.RevokedAt == nil &&
		session.IdleExpiresAt.After(now) && session.AbsoluteExpiresAt.After(now)
}

func validAuthenticationMethod(value string) bool {
	return slices.Contains(
		[]string{"bootstrap_totp", "totp", "recovery_code", "ldap", "oidc", "saml", "passkey"}, value,
	)
}

func normalizePublishInput(input PublishInput) (PublishInput, [sha256.Size]byte, error) {
	if !safeText(input.Reason) {
		return PublishInput{}, [sha256.Size]byte{}, ErrInvalidInput
	}
	input.Event.RemoteAddress = input.Event.RemoteAddress.Unmap()
	normalized, semanticDigest, err := normalizeDraft(input.Policy)
	if err != nil || input.ExpectedVersion < 0 || input.ExpectedVersion >= MaximumPolicyVersion ||
		!validIdempotencyKey(input.IdempotencyKey) || !validBoundedReason(input.Reason) || !validEvent(input.Event) {
		return PublishInput{}, [sha256.Size]byte{}, ErrInvalidInput
	}
	input.Policy = normalized
	return input, semanticDigest, nil
}

func validEvent(value authentication.EventContext) bool {
	return validUUIDv7(value.RequestID) && validUUIDv7(value.CorrelationID) &&
		value.RemoteAddress.IsValid() && value.RemoteAddress.Zone() == "" &&
		validBoundedText(value.UserAgent, 512, false, false)
}

func validIdempotencyKey(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if isASCIIAlphaNumeric(character) || strings.ContainsRune("._~-", rune(character)) {
			continue
		}
		return false
	}
	return true
}

func validBoundedText(value string, maximum int, optional, requireTrimmed bool) bool {
	if value == "" {
		return optional
	}
	if len(value) > maximum || requireTrimmed && strings.TrimSpace(value) != value || !safeText(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%int(time.Millisecond) == 0
}

func validClockInstant(value time.Time) bool {
	return validInstant(value) && value.Year() >= 2000 && value.Year() <= 9999
}

func validRemoteAddress(value netip.Addr) bool {
	return value.IsValid() && value.Zone() == ""
}
