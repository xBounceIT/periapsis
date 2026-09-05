package serviceaccount

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

const (
	defaultPageSize            = 50
	maximumPageSize            = 100
	maximumResourceVersion     = 2_147_483_647
	maximumCredentialCIDRs     = 32
	maximumCredentialGrants    = 100
	maximumCredentialAge       = 90 * 24 * time.Hour
	credentialRequestVersion   = "v1"
	credentialLabelMaxRunes    = 120
	accountDisplayMaxRunes     = 120
	accountDescriptionMaxRunes = 500
)

var (
	accountKeyPattern     = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)
	sourceKeyPattern      = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,126}[a-z0-9]$`)
	idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{16,128}$`)
)

func normalizedPage(input PageInput) (PageInput, error) {
	if input.Limit == 0 {
		input.Limit = defaultPageSize
	}
	if input.Limit < 1 || input.Limit > maximumPageSize {
		return PageInput{}, ErrInvalidInput
	}
	if input.After != nil {
		if !validUUIDv7(*input.After) {
			return PageInput{}, ErrInvalidInput
		}
		cursor := *input.After
		input.After = &cursor
	}
	return input, nil
}

func normalizeCreateAccount(input CreateAccountInput) (CreateAccountInput, error) {
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.Description = strings.TrimSpace(input.Description)
	if !accountKeyPattern.MatchString(input.Key) ||
		!validText(input.DisplayName, 1, accountDisplayMaxRunes) ||
		!validText(input.Description, 0, accountDescriptionMaxRunes) ||
		!validAudit(input.Audit) {
		return CreateAccountInput{}, ErrInvalidInput
	}
	return input, nil
}

func normalizeUpdateAccount(serviceAccountID uuid.UUID, input UpdateAccountInput) (UpdateAccountInput, int64, error) {
	version, err := validateVersioned(serviceAccountID, input.ExpectedVersion, input.Audit)
	if err != nil {
		return UpdateAccountInput{}, 0, err
	}
	if input.DisplayName == nil && input.Description == nil {
		return UpdateAccountInput{}, 0, ErrInvalidInput
	}
	if input.DisplayName != nil {
		value := strings.TrimSpace(*input.DisplayName)
		if !validText(value, 1, accountDisplayMaxRunes) {
			return UpdateAccountInput{}, 0, ErrInvalidInput
		}
		input.DisplayName = &value
	}
	if input.Description != nil {
		value := strings.TrimSpace(*input.Description)
		if !validText(value, 0, accountDescriptionMaxRunes) {
			return UpdateAccountInput{}, 0, ErrInvalidInput
		}
		input.Description = &value
	}
	return input, version, nil
}

func normalizeArchiveAccount(serviceAccountID uuid.UUID, input ArchiveAccountInput) (ArchiveAccountInput, int64, error) {
	version, err := validateVersioned(serviceAccountID, input.ExpectedVersion, input.Audit)
	if err != nil {
		return ArchiveAccountInput{}, 0, err
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if !validText(input.Reason, 1, 500) {
		return ArchiveAccountInput{}, 0, ErrInvalidInput
	}
	return input, version, nil
}

func normalizeGrantRole(serviceAccountID uuid.UUID, input GrantRoleInput) (GrantRoleInput, error) {
	if !validUUIDv7(serviceAccountID) || !validUUIDv7(input.RoleID) || !validAudit(input.Audit) {
		return GrantRoleInput{}, ErrInvalidInput
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if !validText(input.Reason, 1, 500) {
		return GrantRoleInput{}, ErrInvalidInput
	}
	expiresAt, err := normalizeInstantPointer(input.ExpiresAt)
	if err != nil {
		return GrantRoleInput{}, err
	}
	input.ExpiresAt = expiresAt
	return input, nil
}

func normalizeRevokeRoleGrant(serviceAccountID, grantID uuid.UUID, input RevokeRoleGrantInput) (RevokeRoleGrantInput, int64, error) {
	if !validUUIDv7(serviceAccountID) || !validUUIDv7(grantID) || !validAudit(input.Audit) {
		return RevokeRoleGrantInput{}, 0, ErrInvalidInput
	}
	if input.ExpectedEntityTag == nil {
		return RevokeRoleGrantInput{}, 0, ErrPreconditionRequired
	}
	version, err := authorization.ParseEdgeEntityTag(*input.ExpectedEntityTag)
	if err != nil {
		return RevokeRoleGrantInput{}, 0, ErrInvalidInput
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if !validText(input.Reason, 1, 500) {
		return RevokeRoleGrantInput{}, 0, ErrInvalidInput
	}
	return input, version, nil
}

func normalizeIssueCredential(serviceAccountID uuid.UUID, input IssueCredentialInput) (IssueCredentialInput, error) {
	if !validUUIDv7(serviceAccountID) || !idempotencyKeyPattern.MatchString(input.IdempotencyKey) || !validAudit(input.Audit) {
		return IssueCredentialInput{}, ErrInvalidInput
	}
	input.Label = strings.TrimSpace(input.Label)
	if !validText(input.Label, 1, credentialLabelMaxRunes) {
		return IssueCredentialInput{}, ErrInvalidInput
	}
	expiresAt, err := normalizeInstant(input.ExpiresAt)
	if err != nil {
		return IssueCredentialInput{}, err
	}
	input.ExpiresAt = expiresAt
	input.Permissions, err = normalizeCredentialPermissions(input.Permissions)
	if err != nil {
		return IssueCredentialInput{}, err
	}
	input.Networks, err = normalizeCredentialNetworks(input.Networks)
	if err != nil {
		return IssueCredentialInput{}, err
	}
	return input, nil
}

func normalizeRotateCredential(serviceAccountID, credentialID uuid.UUID, input RotateCredentialInput) (RotateCredentialInput, int64, error) {
	if !validUUIDv7(credentialID) {
		return RotateCredentialInput{}, 0, ErrInvalidInput
	}
	version, err := validateVersioned(credentialID, input.ExpectedVersion, input.Audit)
	if err != nil {
		return RotateCredentialInput{}, 0, err
	}
	issue, err := normalizeIssueCredential(serviceAccountID, IssueCredentialInput{
		Label: input.Label, ExpiresAt: input.ExpiresAt, Permissions: input.Permissions,
		Networks: input.Networks, IdempotencyKey: input.IdempotencyKey, Audit: input.Audit,
	})
	if err != nil {
		return RotateCredentialInput{}, 0, err
	}
	input.Label, input.ExpiresAt, input.Permissions, input.Networks = issue.Label, issue.ExpiresAt, issue.Permissions, issue.Networks
	input.Reason = strings.TrimSpace(input.Reason)
	if !validText(input.Reason, 1, 500) {
		return RotateCredentialInput{}, 0, ErrInvalidInput
	}
	return input, version, nil
}

func normalizeRevokeCredential(serviceAccountID, credentialID uuid.UUID, input RevokeCredentialInput) (RevokeCredentialInput, int64, error) {
	if !validUUIDv7(serviceAccountID) {
		return RevokeCredentialInput{}, 0, ErrInvalidInput
	}
	version, err := validateVersioned(credentialID, input.ExpectedVersion, input.Audit)
	if err != nil {
		return RevokeCredentialInput{}, 0, err
	}
	input.Reason = strings.TrimSpace(input.Reason)
	if !validText(input.Reason, 1, 500) {
		return RevokeCredentialInput{}, 0, ErrInvalidInput
	}
	return input, version, nil
}

func normalizeCredentialPermissions(values []authorization.ScopedPermission) ([]authorization.ScopedPermission, error) {
	if len(values) < 1 || len(values) > maximumCredentialGrants {
		return nil, ErrInvalidInput
	}
	result := append([]authorization.ScopedPermission(nil), values...)
	slices.SortFunc(result, func(left, right authorization.ScopedPermission) int {
		if compared := strings.Compare(string(left.Permission), string(right.Permission)); compared != 0 {
			return compared
		}
		return strings.Compare(string(left.Scope), string(right.Scope))
	})
	for index, permission := range result {
		if permission.Permission != authorization.TenantPermissionAlertCreate || permission.Scope != authorization.ScopeTenant ||
			index > 0 && result[index-1] == permission {
			return nil, ErrInvalidInput
		}
	}
	return result, nil
}

func normalizeCredentialNetworks(values []netip.Prefix) ([]netip.Prefix, error) {
	if len(values) > maximumCredentialCIDRs {
		return nil, ErrInvalidInput
	}
	result := make([]netip.Prefix, len(values))
	for index, value := range values {
		if !value.IsValid() || value.Addr().Is4In6() {
			return nil, ErrInvalidInput
		}
		result[index] = value.Masked()
	}
	slices.SortFunc(result, CompareCredentialNetworks)
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, ErrInvalidInput
		}
	}
	return result, nil
}

// CompareCredentialNetworks orders canonical prefixes exactly like PostgreSQL
// cidr values: IPv4 before IPv6, then network address, then prefix length. For
// canonical CIDRs this is equivalent to PostgreSQL's common-network-bits,
// mask-length, and full-address comparison and keeps database request-shape
// validation independent of textual IP formatting.
func CompareCredentialNetworks(left, right netip.Prefix) int {
	leftAddress, rightAddress := left.Addr(), right.Addr()
	if leftAddress.Is4() != rightAddress.Is4() {
		if leftAddress.Is4() {
			return -1
		}
		return 1
	}
	if compared := leftAddress.Compare(rightAddress); compared != 0 {
		return compared
	}
	if left.Bits() < right.Bits() {
		return -1
	}
	if left.Bits() > right.Bits() {
		return 1
	}
	return 0
}

func validateVersioned(resourceID uuid.UUID, expected *int64, audit authorization.AuditContext) (int64, error) {
	if !validUUIDv7(resourceID) || !validAudit(audit) {
		return 0, ErrInvalidInput
	}
	if expected == nil {
		return 0, ErrPreconditionRequired
	}
	if *expected < 1 || *expected > maximumResourceVersion {
		return 0, ErrInvalidInput
	}
	return *expected, nil
}

func normalizeInstantPointer(value *time.Time) (*time.Time, error) {
	if value == nil {
		return nil, nil
	}
	normalized, err := normalizeInstant(*value)
	if err != nil {
		return nil, err
	}
	return &normalized, nil
}

func normalizeInstant(value time.Time) (time.Time, error) {
	if value.IsZero() || value.Nanosecond()%int(time.Microsecond) != 0 {
		return time.Time{}, ErrInvalidInput
	}
	value = value.UTC()
	if _, err := value.MarshalJSON(); err != nil {
		return time.Time{}, ErrInvalidInput
	}
	return value, nil
}

func validAudit(value authorization.AuditContext) bool {
	if value.RequestID != uuid.Nil && value.RequestID.Variant() != uuid.RFC4122 {
		return false
	}
	if value.CorrelationID != uuid.Nil && value.CorrelationID.Variant() != uuid.RFC4122 {
		return false
	}
	return validText(value.UserAgent, 0, 1024)
}

func validText(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	length := utf8.RuneCountInString(value)
	return length >= minimum && length <= maximum
}

func validUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func boundedPage[T any](rows []T, after *uuid.UUID, limit int, cursor func(T) uuid.UUID) ([]T, *uuid.UUID, error) {
	if len(rows) > limit+1 {
		return nil, nil, ErrUnavailable
	}
	var previous uuid.UUID
	hasPrevious := false
	if after != nil {
		previous, hasPrevious = *after, true
	}
	for _, row := range rows {
		value := cursor(row)
		if !validUUIDv7(value) || hasPrevious && bytes.Compare(value[:], previous[:]) <= 0 {
			return nil, nil, ErrUnavailable
		}
		previous, hasPrevious = value, true
	}
	visible := len(rows)
	var next *uuid.UUID
	if visible > limit {
		visible = limit
		value := cursor(rows[visible-1])
		next = &value
	}
	items := append([]T(nil), rows[:visible]...)
	return items, next, nil
}

func digestCredentialIdempotencyKey(value string) [32]byte {
	return sha256.Sum256(append([]byte("periapsis/service-account/credential/idempotency/v1\x00"), value...))
}

func digestCredentialRequest(operation string, serviceAccountID, previousCredentialID uuid.UUID, expectedVersion int64, label string, expiresAt time.Time, permissions []authorization.ScopedPermission, networks []netip.Prefix, reason string) [32]byte {
	hash := sha256.New()
	writeDigestField(hash, credentialRequestVersion)
	writeDigestField(hash, operation)
	writeDigestField(hash, serviceAccountID.String())
	writeDigestField(hash, previousCredentialID.String())
	writeDigestField(hash, strconv.FormatInt(expectedVersion, 10))
	writeDigestField(hash, label)
	writeDigestField(hash, expiresAt.UTC().Format(time.RFC3339Nano))
	writeDigestField(hash, strconv.Itoa(len(permissions)))
	for _, permission := range permissions {
		writeDigestField(hash, string(permission.Permission))
		writeDigestField(hash, string(permission.Scope))
	}
	writeDigestField(hash, strconv.Itoa(len(networks)))
	for _, network := range networks {
		writeDigestField(hash, network.String())
	}
	writeDigestField(hash, reason)
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

type digestWriter interface {
	Write([]byte) (int, error)
}

func writeDigestField(writer digestWriter, value string) {
	length := [4]byte{}
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write([]byte(value))
}

func equalPermissions(left, right []authorization.ScopedPermission) bool {
	return slices.Equal(left, right)
}

func equalNetworks(left, right []netip.Prefix) bool {
	return slices.Equal(left, right)
}
