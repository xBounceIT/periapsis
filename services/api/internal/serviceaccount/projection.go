package serviceaccount

import (
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

func validStoredTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%int(time.Microsecond) == 0
}

func validAccount(value Account, tenantID uuid.UUID) bool {
	if !validUUIDv7(value.ID) || value.TenantID != tenantID ||
		!accountKeyPattern.MatchString(value.Key) ||
		value.DisplayName != strings.TrimSpace(value.DisplayName) ||
		value.Description != strings.TrimSpace(value.Description) ||
		!validText(value.DisplayName, 1, accountDisplayMaxRunes) ||
		!validText(value.Description, 0, accountDescriptionMaxRunes) ||
		!validUUIDv7(value.CreatedByMembershipID) ||
		value.Version < 1 || value.Version > maximumResourceVersion ||
		!validStoredTime(value.CreatedAt) || !validStoredTime(value.UpdatedAt) || value.UpdatedAt.Before(value.CreatedAt) {
		return false
	}
	switch value.State {
	case AccountStateActive:
		return value.ArchivedAt == nil && value.ArchivedByMembershipID == nil && value.ArchiveReason == nil
	case AccountStateArchived:
		if value.ArchivedAt == nil || value.ArchivedByMembershipID == nil || value.ArchiveReason == nil ||
			!validUUIDv7(*value.ArchivedByMembershipID) || !validStoredTime(*value.ArchivedAt) ||
			value.ArchivedAt.Before(value.CreatedAt) ||
			value.UpdatedAt.Before(*value.ArchivedAt) {
			return false
		}
		reason := strings.TrimSpace(*value.ArchiveReason)
		return reason == *value.ArchiveReason && validText(reason, 1, 500)
	default:
		return false
	}
}

func validRoleSummary(value RoleSummary) bool {
	return validUUIDv7(value.ID) && accountKeyPattern.MatchString(value.Key) &&
		value.DisplayName == strings.TrimSpace(value.DisplayName) &&
		validText(value.DisplayName, 1, 120)
}

func validRoleGrant(value RoleGrant, tenantID, serviceAccountID uuid.UUID) bool {
	if !validUUIDv7(value.ID) || value.TenantID != tenantID || value.ServiceAccountID != serviceAccountID ||
		!validRoleSummary(value.Role) || !validUUIDv7(value.SourceID) ||
		!validAuthorizationSourceKind(value.SourceKind) || !sourceKeyPattern.MatchString(value.SourceKey) ||
		!validUUIDv7(value.GrantedByMembershipID) || !validUUIDv7(value.GrantedByUserID) || !validStoredTime(value.GrantedAt) ||
		value.GrantReason != strings.TrimSpace(value.GrantReason) || !validText(value.GrantReason, 1, 500) ||
		value.ExpiresAt != nil && (!validStoredTime(*value.ExpiresAt) || !value.ExpiresAt.After(value.GrantedAt)) ||
		value.Version < 1 || value.Version > maximumResourceVersion || !validStoredTime(value.UpdatedAt) ||
		value.UpdatedAt.Before(value.GrantedAt) {
		return false
	}
	if value.SourceRetiredAt != nil && !validStoredTime(*value.SourceRetiredAt) {
		return false
	}
	managed := value.SourceKind == authorization.AuthorizationSourceManual &&
		value.SourceKey == "manual" && !value.SourceAuthoritative && value.SourceRetiredAt == nil
	if value.ManagedByServiceAccountAPI != managed {
		return false
	}
	switch value.State {
	case RoleGrantStateActive:
		return value.SourceRetiredAt == nil && value.RevokedAt == nil && value.RevokedByMembershipID == nil &&
			value.RevokedByUserID == nil && value.RevokeReason == nil
	case RoleGrantStateExpired:
		return value.RevokedAt == nil && value.RevokedByMembershipID == nil &&
			value.RevokedByUserID == nil && value.RevokeReason == nil
	case RoleGrantStateRevoked:
		if value.RevokedAt == nil || value.RevokedByMembershipID == nil || value.RevokedByUserID == nil || value.RevokeReason == nil ||
			!validUUIDv7(*value.RevokedByMembershipID) || !validUUIDv7(*value.RevokedByUserID) ||
			!validStoredTime(*value.RevokedAt) || value.RevokedAt.Before(value.GrantedAt) ||
			value.UpdatedAt.Before(*value.RevokedAt) {
			return false
		}
		reason := strings.TrimSpace(*value.RevokeReason)
		return reason == *value.RevokeReason && validText(reason, 1, 500)
	default:
		return false
	}
}

func validAuthorizationSourceKind(value authorization.AuthorizationSourceKind) bool {
	switch value {
	case authorization.AuthorizationSourceSystem,
		authorization.AuthorizationSourceTenantCreation,
		authorization.AuthorizationSourceManual,
		authorization.AuthorizationSourceIdentityMapping,
		authorization.AuthorizationSourcePlatformRecovery:
		return true
	default:
		return false
	}
}

func validCredential(value CredentialMetadata, tenantID, serviceAccountID uuid.UUID) bool {
	if !validUUIDv7(value.ID) || value.TenantID != tenantID || value.ServiceAccountID != serviceAccountID ||
		value.Label != strings.TrimSpace(value.Label) || !validText(value.Label, 1, credentialLabelMaxRunes) ||
		value.FormatVersion != int16(credentialFormatVersion) || value.KeyVersion < 1 ||
		!validUUIDv7(value.IssuedByMembershipID) || !validStoredTime(value.IssuedAt) || !validStoredTime(value.ExpiresAt) ||
		!value.ExpiresAt.After(value.IssuedAt) || value.ExpiresAt.After(value.IssuedAt.Add(maximumCredentialAge)) ||
		value.Version < 1 || value.Version > maximumResourceVersion || !validStoredTime(value.UpdatedAt) ||
		value.UpdatedAt.Before(value.IssuedAt) {
		return false
	}
	permissions, err := normalizeCredentialPermissions(value.Permissions)
	if err != nil || !equalPermissions(permissions, value.Permissions) {
		return false
	}
	networks, err := normalizeCredentialNetworks(value.Networks)
	if err != nil || !equalNetworks(networks, value.Networks) {
		return false
	}
	if value.RotatedFromCredentialID != nil &&
		(!validUUIDv7(*value.RotatedFromCredentialID) || *value.RotatedFromCredentialID == value.ID) {
		return false
	}
	if (value.LastUsedAt == nil) != (value.LastUsedIP == nil) ||
		value.LastUsedAt != nil && (!validStoredTime(*value.LastUsedAt) || value.LastUsedAt.Before(value.IssuedAt) || value.LastUsedAt.After(value.ExpiresAt) ||
			value.LastUsedAt.After(value.UpdatedAt) ||
			!value.LastUsedIP.IsValid() || value.LastUsedIP.Zone() != "" || value.LastUsedIP.Is4In6()) {
		return false
	}
	switch value.State {
	case CredentialStateActive, CredentialStateExpired:
		return value.RevokedAt == nil && value.RevokedByMembershipID == nil &&
			value.RevokedByUserID == nil && value.RevokeReason == nil
	case CredentialStateRevoked:
		if value.RevokedAt == nil || value.RevokedByMembershipID == nil || value.RevokedByUserID == nil || value.RevokeReason == nil ||
			!validUUIDv7(*value.RevokedByMembershipID) || !validUUIDv7(*value.RevokedByUserID) ||
			!validStoredTime(*value.RevokedAt) || value.RevokedAt.Before(value.IssuedAt) ||
			value.UpdatedAt.Before(*value.RevokedAt) || value.LastUsedAt != nil && value.LastUsedAt.After(*value.RevokedAt) {
			return false
		}
		reason := strings.TrimSpace(*value.RevokeReason)
		return reason == *value.RevokeReason && validText(reason, 1, 500)
	default:
		return false
	}
}
