package platformlocalaccount

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/mail"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/modules/identity/localaccount"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
)

const (
	defaultPageSize              = 50
	maximumPageSize              = 100
	maximumReasonBytes           = 500
	minimumPasswordBytes         = 14
	maximumPasswordBytes         = 1024
	maximumPersistentRevision    = uint64(9_007_199_254_740_991)
	maximumIncrementableRevision = maximumPersistentRevision - 1
	ceremonyLifetime             = 30 * time.Minute
)

var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{16,128}$`)

func normalizeList(input ListInput) (ListInput, error) {
	if input.Limit == 0 {
		input.Limit = defaultPageSize
	}
	if input.Limit < 1 || input.Limit > maximumPageSize || input.After != nil && !validUUIDv7(*input.After) {
		return ListInput{}, authentication.ErrInvalidInput
	}
	if input.After != nil {
		value := *input.After
		input.After = &value
	}
	return input, nil
}

func normalizeInvite(input InviteInput) (InviteInput, error) {
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.LoginIdentifier = strings.ToLower(strings.TrimSpace(input.LoginIdentifier))
	input.Reason = strings.TrimSpace(input.Reason)
	address, err := mail.ParseAddress(input.LoginIdentifier)
	if err != nil || address.Address != input.LoginIdentifier || address.Name != "" ||
		!validText(input.DisplayName, 1, 160) || !validCanonicalEmail(input.LoginIdentifier) ||
		!validReason(input.Reason) || !idempotencyKeyPattern.MatchString(input.IdempotencyKey) ||
		!validEvent(input.Event) {
		return InviteInput{}, authentication.ErrInvalidInput
	}
	return input, nil
}

func normalizeTransition(accountID uuid.UUID, action localaccount.Action, input TransitionInput) (TransitionInput, uint64, error) {
	if !validUUIDv7(accountID) || input.ExpectedEntityTag == nil || !validEvent(input.Event) ||
		action == localaccount.ActionActivate {
		return TransitionInput{}, 0, authentication.ErrInvalidInput
	}
	version, err := ParseEntityTag(*input.ExpectedEntityTag)
	if err != nil || version > maximumIncrementableRevision {
		return TransitionInput{}, 0, authentication.ErrInvalidInput
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if !validReason(input.Reason) || !idempotencyKeyPattern.MatchString(input.IdempotencyKey) {
		return TransitionInput{}, 0, authentication.ErrInvalidInput
	}
	return input, version, nil
}

func normalizeActivation(accountID uuid.UUID, input ActivationInput) (ActivationInput, uint64, error) {
	if !validUUIDv7(accountID) || input.ExpectedEntityTag == nil || !validEvent(input.Event) ||
		!validOpaqueToken(input.CeremonyToken) || !validPassword(input.NewPassword) || !validFactorProof(input.FactorProof) {
		return ActivationInput{}, 0, authentication.ErrInvalidInput
	}
	version, err := ParseEntityTag(*input.ExpectedEntityTag)
	if err != nil || version > maximumIncrementableRevision {
		return ActivationInput{}, 0, authentication.ErrInvalidInput
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if !validReason(input.Reason) || !idempotencyKeyPattern.MatchString(input.IdempotencyKey) {
		return ActivationInput{}, 0, authentication.ErrInvalidInput
	}
	return input, version, nil
}

func normalizePasswordTransition(accountID uuid.UUID, input PasswordTransitionInput) (PasswordTransitionInput, uint64, error) {
	if !validUUIDv7(accountID) || input.ExpectedEntityTag == nil || !validEvent(input.Event) ||
		!validPassword(input.NewPassword) {
		return PasswordTransitionInput{}, 0, authentication.ErrInvalidInput
	}
	version, err := ParseEntityTag(*input.ExpectedEntityTag)
	if err != nil || version > maximumIncrementableRevision {
		return PasswordTransitionInput{}, 0, authentication.ErrInvalidInput
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if !validReason(input.Reason) || !idempotencyKeyPattern.MatchString(input.IdempotencyKey) {
		return PasswordTransitionInput{}, 0, authentication.ErrInvalidInput
	}
	return input, version, nil
}

func publicRequestDigest(generator secretGenerator, document any, password []byte) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) == 0 || len(encoded) > 16*1024 {
		clear(encoded)
		return [sha256.Size]byte{}, authentication.ErrInvalidInput
	}
	digest := generator.digest("request", encoded, password)
	clear(encoded)
	return digest, nil
}

func EntityTag(revision uint64) (string, error) {
	if revision == 0 || revision > maximumPersistentRevision {
		return "", authentication.ErrInvalidInput
	}
	return `"v` + strconv.FormatUint(revision, 10) + `"`, nil
}

func ParseEntityTag(value string) (uint64, error) {
	if len(value) < 4 || value[:2] != `"v` || value[len(value)-1] != '"' {
		return 0, authentication.ErrInvalidInput
	}
	revision, err := strconv.ParseUint(value[2:len(value)-1], 10, 64)
	if err != nil || revision == 0 || revision > maximumPersistentRevision {
		return 0, authentication.ErrInvalidInput
	}
	canonical, _ := EntityTag(revision)
	if value != canonical {
		return 0, authentication.ErrInvalidInput
	}
	return revision, nil
}

func validAccount(value Account) bool {
	if !validUUIDv7(value.ID) || !validUUIDv7(value.UserID) || value.ID == value.UserID ||
		!validText(value.DisplayName, 1, 160) ||
		!validCanonicalEmail(value.LoginIdentifier) || value.Revision == 0 || value.Revision > maximumPersistentRevision ||
		value.IdentityEpoch == 0 || value.IdentityEpoch > maximumPersistentRevision ||
		value.CredentialVersion > maximumPersistentRevision || !validInstant(value.InvitedAt) ||
		!validInstant(value.UpdatedAt) || value.UpdatedAt.Before(value.InvitedAt) ||
		!validOptionalInstant(value.ActivatedAt, value.InvitedAt, value.UpdatedAt) ||
		!validOptionalInstant(value.DisabledAt, value.InvitedAt, value.UpdatedAt) ||
		!validOptionalInstant(value.RecoveryStartedAt, value.InvitedAt, value.UpdatedAt) {
		return false
	}
	switch value.Status {
	case StatusInvited:
		return value.LoginIdentifierStatus == LoginIdentifierPending &&
			value.CredentialStatus == CredentialPending && value.CredentialVersion == 0 &&
			value.ConfirmedAcceptableFactors == 0 && value.ActivatedAt == nil &&
			value.DisabledAt == nil && value.RecoveryStartedAt == nil
	case StatusActive:
		return value.LoginIdentifierStatus == LoginIdentifierVerified &&
			value.CredentialStatus == CredentialActive && value.CredentialVersion > 0 &&
			value.ConfirmedAcceptableFactors > 0 && value.ActivatedAt != nil && value.DisabledAt == nil
	case StatusDisabled:
		return value.LoginIdentifierStatus != LoginIdentifierPending &&
			value.CredentialStatus == CredentialDisabled && value.CredentialVersion > 0 &&
			value.ActivatedAt != nil && value.DisabledAt != nil
	case StatusRecoveryRestricted:
		return value.LoginIdentifierStatus == LoginIdentifierVerified &&
			value.CredentialStatus == CredentialPending && value.CredentialVersion > 0 &&
			value.ConfirmedAcceptableFactors == 0 && value.ActivatedAt != nil &&
			value.RecoveryStartedAt != nil && value.DisabledAt == nil
	default:
		return false
	}
}

// ValidAccountProjection lets transports fail closed before serializing a
// repository-backed administration view. It validates lifecycle coherence as
// well as the individual bounded fields.
func ValidAccountProjection(value Account) bool {
	return validAccount(value)
}

func validCanonicalEmail(value string) bool {
	return len(value) >= 3 && len(value) <= 320 && strings.ToLower(value) == value && strings.TrimSpace(value) == value &&
		strings.IndexByte(value, '@') > 0 && validText(value, 3, 320)
}

func validPassword(value []byte) bool {
	return len(value) >= minimumPasswordBytes && len(value) <= maximumPasswordBytes && utf8.Valid(value)
}

func validFactorProof(value []byte) bool {
	if len(value) != 6 && len(value) != 8 {
		return false
	}
	for _, item := range value {
		if item < '0' || item > '9' {
			return false
		}
	}
	return true
}

func validReason(value string) bool { return validText(value, 1, maximumReasonBytes) }

func validText(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) || len(value) < minimum || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}

func validEvent(value authentication.EventContext) bool {
	return validUUIDv7(value.RequestID) && validUUIDv7(value.CorrelationID) && value.RemoteAddress.IsValid() &&
		value.RemoteAddress.Zone() == "" && validText(value.UserAgent, 1, 512)
}

func validSession(value authentication.Session) bool {
	if !validUUIDv7(value.ID) || !validUUIDv7(value.User.ID) {
		return false
	}
	switch value.AuthenticationMethod {
	case "bootstrap_totp", "oidc", "passkey", "recovery_code", "saml", "totp":
		return true
	default:
		return false
	}
}

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Year() >= 1970 && value.Year() <= 9999 &&
		value.Nanosecond()%int(time.Millisecond) == 0
}

func validOptionalInstant(value *time.Time, lower, upper time.Time) bool {
	return value == nil || validInstant(*value) && !value.Before(lower) && !value.After(upper)
}

func validUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func cloneAccount(value Account) Account {
	value.ActivatedAt = cloneTime(value.ActivatedAt)
	value.DisabledAt = cloneTime(value.DisabledAt)
	value.RecoveryStartedAt = cloneTime(value.RecoveryStartedAt)
	return value
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func mapPlannerStatus(value Status) (localaccount.Status, error) {
	switch value {
	case StatusInvited:
		return localaccount.StatusInvited, nil
	case StatusActive:
		return localaccount.StatusActive, nil
	case StatusDisabled:
		return localaccount.StatusDisabled, nil
	case StatusRecoveryRestricted:
		return localaccount.StatusRecoveryRestricted, nil
	default:
		return 0, errors.New("invalid local account status")
	}
}

func plannerSnapshot(account Account) (localaccount.Snapshot, error) {
	status, err := mapPlannerStatus(account.Status)
	if err != nil || !validAccount(account) {
		return localaccount.Snapshot{}, authentication.ErrUnavailable
	}
	identifier := map[LoginIdentifierStatus]localaccount.LoginIdentifierStatus{
		LoginIdentifierPending:  localaccount.LoginIdentifierPending,
		LoginIdentifierVerified: localaccount.LoginIdentifierVerified,
		LoginIdentifierDisabled: localaccount.LoginIdentifierDisabled,
	}[account.LoginIdentifierStatus]
	credential := map[CredentialStatus]localaccount.CredentialStatus{
		CredentialPending:  localaccount.CredentialPending,
		CredentialActive:   localaccount.CredentialActive,
		CredentialDisabled: localaccount.CredentialDisabled,
	}[account.CredentialStatus]
	if identifier == localaccount.LoginIdentifierAbsent || credential == localaccount.CredentialAbsent {
		return localaccount.Snapshot{}, authentication.ErrUnavailable
	}
	return localaccount.Snapshot{
		AccountID: plannerID(account.ID), UserID: plannerID(account.UserID), Revision: account.Revision,
		IdentityEpoch: account.IdentityEpoch, Status: status, LoginIdentifier: identifier,
		Credential: credential, ConfirmedAcceptableFactors: account.ConfirmedAcceptableFactors,
		ProtectedRecoveryPrincipal: account.ProtectedRecoveryPrincipal,
	}, nil
}
