package serviceaccount

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

// RoleGrantEntityTag returns a strong validator for the complete public role-
// grant representation, including server-derived mutation ownership.
func RoleGrantEntityTag(value RoleGrant) (string, error) {
	if value.Version < 1 || value.Version > maximumResourceVersion {
		return "", errors.New("role-grant resource version must be positive")
	}
	type publicRoleReference struct {
		ID            uuid.UUID
		Key           string
		Name          string
		PrincipalKind authorization.PrincipalKind
		System        bool
	}
	type publicProvenance struct {
		SourceKind      authorization.AuthorizationSourceKind
		SourceID        uuid.UUID
		Authoritative   bool
		RetiredAt       *time.Time
		GrantedByUserID uuid.UUID
		GrantedAt       time.Time
		Reason          string
		ExpiresAt       *time.Time
	}
	projection := struct {
		ID                         uuid.UUID
		TenantID                   uuid.UUID
		ServiceAccountID           uuid.UUID
		Role                       publicRoleReference
		Provenance                 publicProvenance
		State                      RoleGrantState
		ManagedByServiceAccountAPI bool
		RevokedAt                  *time.Time
		RevokedByUserID            *uuid.UUID
		RevokeReason               *string
		Version                    int64
		UpdatedAt                  time.Time
	}{
		ID: value.ID, TenantID: value.TenantID, ServiceAccountID: value.ServiceAccountID,
		Role: publicRoleReference{
			ID: value.Role.ID, Key: value.Role.Key, Name: value.Role.DisplayName,
			PrincipalKind: authorization.PrincipalKindServiceAccount, System: value.Role.System,
		},
		Provenance: publicProvenance{
			SourceKind: value.SourceKind, SourceID: value.SourceID,
			Authoritative: value.SourceAuthoritative, RetiredAt: value.SourceRetiredAt,
			GrantedByUserID: value.GrantedByUserID, GrantedAt: value.GrantedAt,
			Reason: value.GrantReason, ExpiresAt: value.ExpiresAt,
		},
		State: value.State, ManagedByServiceAccountAPI: value.ManagedByServiceAccountAPI,
		RevokedAt: value.RevokedAt, RevokedByUserID: value.RevokedByUserID,
		RevokeReason: value.RevokeReason, Version: value.Version, UpdatedAt: value.UpdatedAt,
	}
	payload, err := json.Marshal(struct {
		Schema string `json:"schema"`
		Value  any    `json:"value"`
	}{Schema: "service-account-role-grant/v2", Value: projection})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return "\"v" + strconv.FormatInt(value.Version, 10) + "-" +
		base64.RawURLEncoding.EncodeToString(digest[:]) + "\"", nil
}
