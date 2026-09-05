package operatorteam

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

// RosterEntryEntityTag returns a strong validator for the complete public
// exact-epoch roster representation. Repository-only mutation ownership is
// deliberately excluded so rolling replicas agree on the same public state.
func RosterEntryEntityTag(value RosterEntry) (string, error) {
	projection := struct {
		ID                uuid.UUID
		TenantID          uuid.UUID
		OperatorTeamID    uuid.UUID
		AssignmentEpochID uuid.UUID
		Member            TenantMember
		Provenance        authorization.AuthorizationEdgeProvenance
		State             RosterEntryState
		RevokedAt         *time.Time
		RevokedByUserID   *uuid.UUID
		RevokeReason      *string
		Version           int64
		UpdatedAt         time.Time
	}{
		ID: value.ID, TenantID: value.TenantID, OperatorTeamID: value.OperatorTeamID,
		AssignmentEpochID: value.AssignmentEpochID, Member: value.Member,
		Provenance: value.Provenance, State: value.State, RevokedAt: value.RevokedAt,
		RevokedByUserID: value.RevokedByUserID, RevokeReason: value.RevokeReason,
		Version: value.Version, UpdatedAt: value.UpdatedAt,
	}
	return rosterEntityTag("operator-team-roster-entry/v1", value.Version, projection)
}

func rosterEntityTag[T any](schema string, version int64, value T) (string, error) {
	if version < 1 || version > maximumResourceVersion {
		return "", errors.New("roster entry version must be positive")
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
