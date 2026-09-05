package authorization

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const edgeEntityTagDigestSize = sha256.Size

// TenantMembershipLifecycleEntityTag is the deliberately narrow strong
// validator for the membership status revision. No unrelated profile update
// invalidates a lifecycle command precondition.
func TenantMembershipLifecycleEntityTag(revision int64) (string, error) {
	if revision < 1 || revision > maximumResourceVersion {
		return "", errors.New("membership lifecycle revision must be positive")
	}
	return "\"v" + strconv.FormatInt(revision, 10) + "\"", nil
}

// DirectUserRoleGrantEntityTag returns a strong validator for the complete
// current direct-grant representation, including its live role and provenance
// summaries. The schema label makes validators type- and format-specific.
func DirectUserRoleGrantEntityTag(value DirectUserRoleGrant) (string, error) {
	// Keep the v1 validator tied to the public grant representation. Repository-
	// only ownership facts must not make old and new replicas disagree about the
	// same resource during a rolling deployment.
	projection := struct {
		ID              uuid.UUID
		TenantID        uuid.UUID
		UserID          uuid.UUID
		Role            TenantRoleSummary
		Provenance      RoleGrantProvenance
		PathType        RoleGrantPathType
		State           DirectRoleGrantState
		RevokedAt       *time.Time
		RevokedByUserID *uuid.UUID
		RevokeReason    *string
		Version         int64
		UpdatedAt       time.Time
	}{
		ID: value.ID, TenantID: value.TenantID, UserID: value.UserID,
		Role: value.Role, Provenance: value.Provenance, PathType: value.PathType,
		State: value.State, RevokedAt: value.RevokedAt,
		RevokedByUserID: value.RevokedByUserID, RevokeReason: value.RevokeReason,
		Version: value.Version, UpdatedAt: value.UpdatedAt,
	}
	return edgeEntityTag("direct-user-role-grant/v1", value.Version, projection)
}

// TenantSecurityGroupMembershipEntityTag returns a strong validator for the
// complete current membership-edge representation.
func TenantSecurityGroupMembershipEntityTag(value TenantSecurityGroupMembership) (string, error) {
	// The ownership hint is repository-only metadata added during a rolling
	// deployment. Keep validators stable across replicas that do and do not
	// project it yet.
	projection := struct {
		ID              uuid.UUID
		TenantID        uuid.UUID
		Group           TenantSecurityGroup
		Member          TenantUserSummary
		Provenance      AuthorizationEdgeProvenance
		State           AuthorizationEdgeState
		RevokedAt       *time.Time
		RevokedByUserID *uuid.UUID
		RevokeReason    *string
		Version         int64
		UpdatedAt       time.Time
	}{
		ID: value.ID, TenantID: value.TenantID, Group: value.Group,
		Member: value.Member, Provenance: value.Provenance, State: value.State,
		RevokedAt: value.RevokedAt, RevokedByUserID: value.RevokedByUserID,
		RevokeReason: value.RevokeReason, Version: value.Version, UpdatedAt: value.UpdatedAt,
	}
	return edgeEntityTag("tenant-security-group-membership/v1", value.Version, projection)
}

// TenantSecurityGroupRoleGrantEntityTag returns a strong validator for the
// complete current group-role-grant representation.
func TenantSecurityGroupRoleGrantEntityTag(value TenantSecurityGroupRoleGrant) (string, error) {
	projection := struct {
		ID              uuid.UUID
		TenantID        uuid.UUID
		Group           TenantSecurityGroup
		Role            TenantRoleSummary
		Provenance      AuthorizationEdgeProvenance
		State           AuthorizationEdgeState
		RevokedAt       *time.Time
		RevokedByUserID *uuid.UUID
		RevokeReason    *string
		Version         int64
		UpdatedAt       time.Time
	}{
		ID: value.ID, TenantID: value.TenantID, Group: value.Group,
		Role: value.Role, Provenance: value.Provenance, State: value.State,
		RevokedAt: value.RevokedAt, RevokedByUserID: value.RevokedByUserID,
		RevokeReason: value.RevokeReason, Version: value.Version, UpdatedAt: value.UpdatedAt,
	}
	return edgeEntityTag("tenant-security-group-role-grant/v1", value.Version, projection)
}

// ParseEdgeEntityTag validates the deliberately narrow opaque edge-validator
// shape and returns the numeric edge version needed by the database's atomic
// optimistic-lock check.
func ParseEdgeEntityTag(value string) (int64, error) {
	if len(value) < len("\"v1-\"")+base64.RawURLEncoding.EncodedLen(edgeEntityTagDigestSize) ||
		value[0] != '"' || value[len(value)-1] != '"' || !strings.HasPrefix(value, "\"v") {
		return 0, errors.New("edge entity tag is invalid")
	}
	body := value[2 : len(value)-1]
	separator := strings.IndexByte(body, '-')
	if separator < 1 {
		return 0, errors.New("edge entity tag is invalid")
	}
	versionText := body[:separator]
	if versionText[0] == '0' {
		return 0, errors.New("edge entity tag version is invalid")
	}
	for _, character := range versionText {
		if character < '0' || character > '9' {
			return 0, errors.New("edge entity tag version is invalid")
		}
	}
	version, err := strconv.ParseInt(versionText, 10, 64)
	if err != nil || version < 1 || version > maximumResourceVersion {
		return 0, errors.New("edge entity tag version is invalid")
	}
	digestText := body[separator+1:]
	if len(digestText) != base64.RawURLEncoding.EncodedLen(edgeEntityTagDigestSize) {
		return 0, errors.New("edge entity tag digest is invalid")
	}
	digest, err := base64.RawURLEncoding.DecodeString(digestText)
	if err != nil || len(digest) != edgeEntityTagDigestSize ||
		base64.RawURLEncoding.EncodeToString(digest) != digestText {
		return 0, errors.New("edge entity tag digest is invalid")
	}
	return version, nil
}

func edgeEntityTag[T any](schema string, version int64, value T) (string, error) {
	if version < 1 || version > maximumResourceVersion {
		return "", errors.New("edge resource version must be positive")
	}
	payload, err := json.Marshal(struct {
		Schema string `json:"schema"`
		Value  T      `json:"value"`
	}{Schema: schema, Value: value})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return "\"v" + strconv.FormatInt(version, 10) + "-" +
		base64.RawURLEncoding.EncodeToString(digest[:]) + "\"", nil
}
