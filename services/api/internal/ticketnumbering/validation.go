package ticketnumbering

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
)

const maximumProjectionClockSkew = time.Minute

func normalizeDraft(input PolicyDraft) (PolicyDraft, kernel.NumberingPolicySpec, error) {
	if !safeText(input.Prefix) || !safeText(input.Separator) {
		return PolicyDraft{}, kernel.NumberingPolicySpec{}, ErrInvalidInput
	}
	input.Prefix = strings.ToUpper(strings.TrimSpace(input.Prefix))
	input.Separator = strings.TrimSpace(input.Separator)
	spec, err := kernel.NewNumberingPolicySpec(
		input.Prefix, input.Separator, input.Period, input.Width, input.Start,
	)
	if err != nil {
		return PolicyDraft{}, kernel.NumberingPolicySpec{}, ErrInvalidInput
	}
	return input, spec, nil
}

func draftFromSpec(spec kernel.NumberingPolicySpec) PolicyDraft {
	return PolicyDraft{
		Prefix: spec.Prefix(), Separator: spec.Separator(), Period: spec.Period(),
		Width: spec.Width(), Start: spec.Start(),
	}
}

func validStoredPolicy(
	policy kernel.NumberingPolicy,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	now time.Time,
) bool {
	tenant, ok := entityID(tenantID)
	return ok && kernel.SameNumberingPolicy(policy, policy) && policy.Tenant() == tenant &&
		policy.Kind() == kind && policy.Version() >= 1 && policy.Version() <= MaximumRevision &&
		validInstant(policy.PublishedAt()) &&
		!policy.PublishedAt().After(now.Add(maximumProjectionClockSkew))
}

func validPreview(
	value Preview,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	draft PolicyDraft,
	at time.Time,
) bool {
	if value.TenantID != tenantID || value.Kind != kind || value.Prefix != draft.Prefix ||
		value.Separator != draft.Separator || value.Period != draft.Period ||
		value.Width != draft.Width || value.Start != draft.Start || !value.At.Equal(at) {
		return false
	}
	spec, err := kernel.NewNumberingPolicySpec(
		value.Prefix, value.Separator, value.Period, value.Width, value.Start,
	)
	if err != nil || value.MaximumSequence != spec.MaximumSequence() {
		return false
	}
	period, periodErr := spec.PeriodKey(value.At)
	example, exampleErr := spec.Render(value.Start, value.At)
	return periodErr == nil && exampleErr == nil && value.PeriodKey == period && value.Example == example
}

func validReplaceResult(
	result ReplaceResult,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	expectedVersion uint64,
	draft PolicyDraft,
	publisher kernel.EntityID,
	now time.Time,
) bool {
	if expectedVersion < 1 || expectedVersion >= MaximumRevision ||
		!validStoredPolicy(result.Policy, tenantID, kind, now) ||
		result.Policy.Version() != expectedVersion+1 || draftFromSpec(result.Policy.Spec()) != draft {
		return false
	}
	return result.Policy.PublishedBy() == publisher
}

func validSession(session authentication.Session, tenantID uuid.UUID, now time.Time) bool {
	return validUUIDv7(tenantID) && validUUIDv7(session.ID) && validUUIDv7(session.User.ID) &&
		session.ActiveTenantID != nil && *session.ActiveTenantID == tenantID &&
		validAuthenticationMethod(session.AuthenticationMethod) && session.RevokedAt == nil &&
		session.IdleExpiresAt.After(now) && session.AbsoluteExpiresAt.After(now)
}

func validAuthenticationMethod(value string) bool {
	switch value {
	case "bootstrap_totp", "totp", "recovery_code", "ldap", "oidc", "saml", "passkey":
		return true
	default:
		return false
	}
}

func normalizeReplaceInput(input ReplaceInput) (ReplaceInput, kernel.NumberingPolicySpec, error) {
	if !safeText(input.Reason) {
		return ReplaceInput{}, kernel.NumberingPolicySpec{}, ErrInvalidInput
	}
	input.Reason = strings.TrimSpace(input.Reason)
	input.Event.RemoteAddress = input.Event.RemoteAddress.Unmap()
	normalized, spec, err := normalizeDraft(input.Policy)
	if err != nil || input.ExpectedVersion < 1 || input.ExpectedVersion >= MaximumRevision ||
		!validIdempotencyKey(input.IdempotencyKey) || !validReason(input.Reason) ||
		!validEvent(input.Event) {
		return ReplaceInput{}, kernel.NumberingPolicySpec{}, ErrInvalidInput
	}
	input.Policy = normalized
	return input, spec, nil
}

func validEvent(value authentication.EventContext) bool {
	return validUUIDv7(value.RequestID) && validUUIDv7(value.CorrelationID) &&
		value.RemoteAddress.IsValid() && value.RemoteAddress.Zone() == "" &&
		validBoundedText(value.UserAgent, 512, false, false)
}

func validReason(value string) bool {
	return validBoundedText(value, MaximumReasonLen, false, true)
}

func validIdempotencyKey(value string) bool {
	if len(value) < 16 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._~-", rune(character)) {
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
	if len(value) > maximum || !utf8.ValidString(value) || requireTrimmed && strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}

func safeText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}

func validAggregateKind(kind kernel.AggregateKind) bool {
	return kind == kernel.AggregateAlert || kind == kernel.AggregateCase
}

func entityID(value uuid.UUID) (kernel.EntityID, bool) {
	if !validUUIDv7(value) {
		return kernel.EntityID{}, false
	}
	id, err := kernel.NewEntityID([16]byte(value))
	return id, err == nil
}

func uuidFromEntity(value kernel.EntityID) uuid.UUID {
	return uuid.UUID(value.Bytes())
}

func validUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%1_000 == 0
}
