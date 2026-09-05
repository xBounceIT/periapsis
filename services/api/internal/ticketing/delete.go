package ticketing

import (
	"context"
	"crypto/sha256"
	"encoding/json"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

// DeleteAlert applies a versioned tombstone. The underlying Alert and its
// append-only history remain available only to retention/audit internals; all
// ordinary ticket projections must exclude the tombstone.
func (service *Service) DeleteAlert(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	alertID uuid.UUID,
	input DeleteAlertInput,
) (DeleteAlertReceipt, error) {
	if !validMutationActor(actor, tenantID) {
		return DeleteAlertReceipt{}, ErrForbidden
	}
	if _, err := entityID(alertID); err != nil || input.ExpectedVersion == 0 ||
		input.ExpectedVersion >= maxResourceVersion || !validText(input.Reason, 2_000, true) ||
		!validIdempotencyKey(input.IdempotencyKey) {
		return DeleteAlertReceipt{}, ErrInvalidInput
	}
	fingerprint, err := alertDeleteFingerprint(tenantID, actor.UserID, alertID, input)
	if err != nil {
		return DeleteAlertReceipt{}, err
	}
	keyHash := sha256.Sum256([]byte(input.IdempotencyKey))
	access, err := service.access(ctx, actor, tenantID, CapabilityAlertDelete)
	if err != nil {
		return DeleteAlertReceipt{}, err
	}
	if access.Authority.Principal() != kernel.PrincipalOperator {
		return DeleteAlertReceipt{}, ErrForbidden
	}
	replay, found, err := service.repository.LookupAlertDeleteReplay(ctx, DeleteAlertReplayQuery{
		Actor: actor, TenantID: tenantID, AlertID: alertID, KeyHash: keyHash, Fingerprint: fingerprint,
	})
	if err != nil {
		return DeleteAlertReceipt{}, repositoryError(err)
	}
	if found {
		replay.Replayed = true
		if !validDeleteAlertReceipt(replay, tenantID, alertID, input.ExpectedVersion) {
			return DeleteAlertReceipt{}, ErrUnavailable
		}
		return replay, nil
	}
	view, err := service.getAuthorized(ctx, tenantID, kernel.AggregateAlert, alertID, access)
	if err != nil {
		return DeleteAlertReceipt{}, err
	}
	if view.Projection != ProjectionOperator {
		return DeleteAlertReceipt{}, ErrForbidden
	}
	if view.Record.Snapshot.Version() != input.ExpectedVersion {
		return DeleteAlertReceipt{}, ErrPreconditionFailed
	}
	receipt, err := service.repository.DeleteAlert(ctx, DeleteAlertWrite{
		Actor: actor, Current: view.Record, Input: input, KeyHash: keyHash,
		Fingerprint: fingerprint, Audit: actor.Audit,
	})
	if err != nil {
		return DeleteAlertReceipt{}, repositoryError(err)
	}
	if !validDeleteAlertReceipt(receipt, tenantID, alertID, input.ExpectedVersion) {
		return DeleteAlertReceipt{}, ErrUnavailable
	}
	return receipt, nil
}

func alertDeleteFingerprint(
	tenantID uuid.UUID,
	actorID uuid.UUID,
	alertID uuid.UUID,
	input DeleteAlertInput,
) ([sha256.Size]byte, error) {
	document := struct {
		SchemaVersion   int       `json:"schemaVersion"`
		TenantID        uuid.UUID `json:"tenantId"`
		ActorID         uuid.UUID `json:"actorId"`
		AlertID         uuid.UUID `json:"alertId"`
		ExpectedVersion uint64    `json:"expectedVersion"`
		Reason          string    `json:"reason"`
	}{1, tenantID, actorID, alertID, input.ExpectedVersion, input.Reason}
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) > 4_096 {
		return [sha256.Size]byte{}, ErrInvalidInput
	}
	return sha256.Sum256(encoded), nil
}

func validDeleteAlertReceipt(
	receipt DeleteAlertReceipt,
	tenantID uuid.UUID,
	alertID uuid.UUID,
	expectedVersion uint64,
) bool {
	return receipt.TenantID == tenantID && receipt.AlertID == alertID &&
		receipt.PreviousVersion == expectedVersion && receipt.TombstoneVersion == expectedVersion+1 &&
		validStoredInstant(receipt.DeletedAt)
}
