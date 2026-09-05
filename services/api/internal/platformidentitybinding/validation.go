package platformidentitybinding

import (
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
)

const (
	defaultPageSize               = 50
	maximumPageSize               = 100
	maximumProfilePriority        = 1_000_000
	maximumReasonBytes            = 2 * 1024
	maximumResourceVersion  int64 = 2_147_483_647
	maximumMutationVersion  int64 = maximumResourceVersion - 1
	maximumInternalRevision int64 = 9_007_199_254_740_991
)

var (
	bindingKeyPattern     = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)
	idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{16,128}$`)
	tenantSlugPattern     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

func normalizeList(providerID uuid.UUID, input ListInput) (ListInput, error) {
	if input.Limit == 0 {
		input.Limit = defaultPageSize
	}
	if !validUUIDv7(providerID) || input.Limit < 1 || input.Limit > maximumPageSize ||
		input.After != nil && !validUUIDv7(*input.After) {
		return ListInput{}, authentication.ErrInvalidInput
	}
	if input.After != nil {
		value := *input.After
		input.After = &value
	}
	return input, nil
}

func normalizeCreate(
	providerID uuid.UUID,
	input CreateInput,
) (CreateInput, [sha256.Size]byte, error) {
	input.Reason = strings.TrimSpace(input.Reason)
	if !validUUIDv7(providerID) || !validUUIDv7(input.TenantID) ||
		!bindingKeyPattern.MatchString(input.LoginKey) ||
		input.ProfilePriority < 0 || input.ProfilePriority > maximumProfilePriority ||
		!validReason(input.Reason) || !idempotencyKeyPattern.MatchString(input.IdempotencyKey) ||
		!validEvent(input.Event) {
		return CreateInput{}, [sha256.Size]byte{}, authentication.ErrInvalidInput
	}
	digest, err := bindingCreateRequestDigest(providerID, input)
	if err != nil {
		return CreateInput{}, [sha256.Size]byte{}, authentication.ErrInvalidInput
	}
	return input, digest, nil
}

func normalizeUpdate(
	providerID, bindingID uuid.UUID,
	input UpdateInput,
) (UpdateInput, int64, int64, error) {
	version, tenantVersion, err := normalizeVersioned(
		providerID, bindingID, input.ExpectedEntityTag, input.Event,
	)
	if err != nil {
		return UpdateInput{}, 0, 0, err
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if !bindingKeyPattern.MatchString(input.LoginKey) ||
		input.ProfilePriority < 0 || input.ProfilePriority > maximumProfilePriority ||
		!validReason(input.Reason) {
		return UpdateInput{}, 0, 0, authentication.ErrInvalidInput
	}
	return input, version, tenantVersion, nil
}

func normalizeArchive(
	providerID, bindingID uuid.UUID,
	input ArchiveInput,
) (ArchiveInput, int64, int64, error) {
	version, tenantVersion, err := normalizeVersioned(
		providerID, bindingID, input.ExpectedEntityTag, input.Event,
	)
	if err != nil {
		return ArchiveInput{}, 0, 0, err
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if !validReason(input.Reason) {
		return ArchiveInput{}, 0, 0, authentication.ErrInvalidInput
	}
	return input, version, tenantVersion, nil
}

func normalizeActivate(
	providerID, bindingID uuid.UUID,
	input ActivateInput,
) (ActivateInput, int64, int64, error) {
	version, tenantVersion, err := normalizeVersioned(
		providerID, bindingID, input.ExpectedEntityTag, input.Event,
	)
	if err != nil {
		return ActivateInput{}, 0, 0, err
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if !validJITMode(input.JITMode) || !validNoMatchPolicy(input.NoMatchPolicy) ||
		!validReason(input.Reason) {
		return ActivateInput{}, 0, 0, authentication.ErrInvalidInput
	}
	return input, version, tenantVersion, nil
}

func normalizeDeactivate(
	providerID, bindingID uuid.UUID,
	input DeactivateInput,
) (DeactivateInput, int64, int64, error) {
	version, tenantVersion, err := normalizeVersioned(
		providerID, bindingID, input.ExpectedEntityTag, input.Event,
	)
	if err != nil {
		return DeactivateInput{}, 0, 0, err
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if !validReason(input.Reason) {
		return DeactivateInput{}, 0, 0, authentication.ErrInvalidInput
	}
	return input, version, tenantVersion, nil
}

func normalizeVersioned(
	providerID, bindingID uuid.UUID,
	entityTag *string,
	event authentication.EventContext,
) (int64, int64, error) {
	if !validUUIDv7(providerID) || !validUUIDv7(bindingID) || entityTag == nil || !validEvent(event) {
		return 0, 0, authentication.ErrInvalidInput
	}
	version, tenantVersion, err := ParseEntityTag(*entityTag)
	if err != nil || version > maximumMutationVersion {
		return 0, 0, authentication.ErrInvalidInput
	}
	return version, tenantVersion, nil
}

func bindingCreateRequestDigest(
	providerID uuid.UUID,
	input CreateInput,
) ([sha256.Size]byte, error) {
	document := struct {
		Schema          string    `json:"schema"`
		ProviderID      uuid.UUID `json:"providerId"`
		TenantID        uuid.UUID `json:"tenantId"`
		LoginKey        string    `json:"loginKey"`
		ProfilePriority int       `json:"profilePriority"`
		Reason          string    `json:"reason"`
	}{
		Schema:     "periapsis/platform-identity-provider-tenant-binding-create/v1",
		ProviderID: providerID, TenantID: input.TenantID, LoginKey: input.LoginKey,
		ProfilePriority: input.ProfilePriority, Reason: input.Reason,
	}
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) < 1 || len(encoded) > 16*1024 {
		clear(encoded)
		return [sha256.Size]byte{}, authentication.ErrInvalidInput
	}
	digest := sha256.Sum256(encoded)
	clear(encoded)
	return digest, nil
}

func validBinding(value Binding) bool {
	if !validUUIDv7(value.ID) || !validUUIDv7(value.ProviderID) || !validTenant(value.Tenant) ||
		!bindingKeyPattern.MatchString(value.LoginKey) ||
		value.ProfilePriority < 0 || value.ProfilePriority > maximumProfilePriority ||
		!validJITMode(value.JITMode) || !validNoMatchPolicy(value.NoMatchPolicy) ||
		value.Enabled != (value.CurrentAccessEpochID != nil) ||
		value.ActivationAvailable && (value.Enabled || value.ArchivedAt != nil) ||
		!validInternalRevision(value.AuthRevision) || !validInternalRevision(value.MappingRevision) ||
		!validResourceVersion(value.Version) || !validInstant(value.CreatedAt) || !validInstant(value.UpdatedAt) ||
		value.UpdatedAt.Before(value.CreatedAt) {
		return false
	}
	if value.ArchivedAt != nil && (!validInstant(*value.ArchivedAt) ||
		value.ArchivedAt.Before(value.CreatedAt) || value.ArchivedAt.After(value.UpdatedAt)) {
		return false
	}
	if value.CurrentAccessEpochID != nil && !validUUIDv7(*value.CurrentAccessEpochID) {
		return false
	}
	return true
}

func initialBindingProjection(value Binding) bool {
	return value.Version == 1 && value.AuthRevision == 1 && value.MappingRevision == 1 &&
		value.JITMode == JITModeDisabled && value.NoMatchPolicy == NoMatchPolicyDeny &&
		!value.Enabled && value.CurrentAccessEpochID == nil &&
		value.ArchivedAt == nil && value.CreatedAt.Equal(value.UpdatedAt)
}

func validJITMode(value JITMode) bool {
	return value == JITModeDisabled || value == JITModeCreate
}

func validNoMatchPolicy(value NoMatchPolicy) bool {
	return value == NoMatchPolicyDeny || value == NoMatchPolicyProviderAccessOnly
}

func validTenant(value TenantSummary) bool {
	return validUUIDv7(value.ID) && tenantSlugPattern.MatchString(value.Slug) &&
		validText(value.Name, 1, 160) && validResourceVersion(value.Version) &&
		(value.Status == TenantStatusActive || value.Status == TenantStatusSuspended)
}

func validSession(session authentication.Session) bool {
	return validUUIDv7(session.User.ID) && validUUIDv7(session.ID) &&
		validAuthenticationMethod(session.AuthenticationMethod)
}

func validAuthenticationMethod(value string) bool {
	switch value {
	case "bootstrap_totp", "oidc", "passkey", "recovery_code", "saml", "totp":
		return true
	default:
		return false
	}
}

func validEvent(value authentication.EventContext) bool {
	if !validUUIDv7(value.RequestID) || !validUUIDv7(value.CorrelationID) ||
		!validRemoteAddress(value.RemoteAddress) || len(value.UserAgent) < 1 || len(value.UserAgent) > 512 ||
		!utf8.ValidString(value.UserAgent) {
		return false
	}
	for _, character := range value.UserAgent {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}

func validRemoteAddress(value netip.Addr) bool {
	return value.IsValid() && value.Zone() == ""
}

func validReason(value string) bool {
	return len(value) >= 1 && len(value) <= maximumReasonBytes && validText(value, 1, maximumReasonBytes)
}

func validText(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) < minimum ||
		utf8.RuneCountInString(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}

func validUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validResourceVersion(value int64) bool {
	return value > 0 && value <= maximumResourceVersion
}

func validInternalRevision(value int64) bool {
	return value > 0 && value <= maximumInternalRevision
}

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Year() >= 1970 && value.Year() <= 9999 &&
		value.Nanosecond()%1_000 == 0
}

func cloneBinding(value Binding) Binding {
	if value.CurrentAccessEpochID != nil {
		current := *value.CurrentAccessEpochID
		value.CurrentAccessEpochID = &current
	}
	if value.ArchivedAt != nil {
		archivedAt := *value.ArchivedAt
		value.ArchivedAt = &archivedAt
	}
	return value
}
