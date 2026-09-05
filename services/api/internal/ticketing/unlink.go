package ticketing

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

// UnlinkInput is an explicit two-aggregate command. ExpectedVersion belongs to
// the path Alert and is also bound to If-Match by the HTTP adapter;
// ExpectedCaseVersion independently protects the linked Case.
type UnlinkInput struct {
	CaseID              uuid.UUID
	ExpectedVersion     uint64
	ExpectedCaseVersion uint64
	Reason              string
	IdempotencyKey      string
}

// UnlinkReceipt proves the immutable retraction and both committed version
// transitions. It deliberately contains no copied fields or free-form reason.
type UnlinkReceipt struct {
	TenantID             uuid.UUID
	AlertID              uuid.UUID
	CaseID               uuid.UUID
	LinkID               uuid.UUID
	PreviousAlertVersion uint64
	AlertVersion         uint64
	PreviousCaseVersion  uint64
	CaseVersion          uint64
	RetractedAt          time.Time
	Replayed             bool
}

// Unlink retracts one live Alert/Case relationship without deleting or
// rewriting its provenance. Authorization and optimistic versions are checked
// at this boundary and again by the database commit ABI.
func (service *Service) Unlink(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	alertID uuid.UUID,
	input UnlinkInput,
) (UnlinkReceipt, error) {
	if !validMutationActor(actor, tenantID) {
		return UnlinkReceipt{}, ErrForbidden
	}
	if err := validateUnlinkInput(alertID, input); err != nil {
		return UnlinkReceipt{}, err
	}
	fingerprint, err := unlinkFingerprint(tenantID, actor.UserID, alertID, input)
	if err != nil {
		return UnlinkReceipt{}, err
	}
	keyHash := sha256.Sum256([]byte(input.IdempotencyKey))

	alertAccess, err := service.access(ctx, actor, tenantID, CapabilityAlertEscalate)
	if err != nil {
		return UnlinkReceipt{}, err
	}
	caseAccess, err := service.access(ctx, actor, tenantID, CapabilityCaseUpdate)
	if err != nil {
		return UnlinkReceipt{}, err
	}
	if alertAccess.Authority.Principal() != kernel.PrincipalOperator ||
		!sameAuthority(alertAccess.Authority, caseAccess.Authority) {
		return UnlinkReceipt{}, ErrForbidden
	}

	replay, found, err := service.repository.LookupUnlinkReplay(ctx, UnlinkReplayQuery{
		Actor: actor, TenantID: tenantID, AlertID: alertID, CaseID: input.CaseID,
		KeyHash: keyHash, Fingerprint: fingerprint,
	})
	if err != nil {
		return UnlinkReceipt{}, repositoryError(err)
	}
	if found {
		replay.Replayed = true
		if !validUnlinkReceipt(replay, tenantID, alertID, input) {
			return UnlinkReceipt{}, ErrUnavailable
		}
		return replay, nil
	}

	alert, err := service.getAuthorized(ctx, tenantID, kernel.AggregateAlert, alertID, alertAccess)
	if err != nil {
		return UnlinkReceipt{}, err
	}
	caseView, err := service.getAuthorized(ctx, tenantID, kernel.AggregateCase, input.CaseID, caseAccess)
	if err != nil {
		return UnlinkReceipt{}, err
	}
	if alert.Projection != ProjectionOperator || caseView.Projection != ProjectionOperator {
		return UnlinkReceipt{}, ErrForbidden
	}
	if alert.Record.Snapshot.Version() != input.ExpectedVersion ||
		caseView.Record.Snapshot.Version() != input.ExpectedCaseVersion {
		return UnlinkReceipt{}, ErrPreconditionFailed
	}

	lifecycle, err := service.repository.ResolveLinkLifecycle(
		ctx, actor.UserID, tenantID, alertID, input.CaseID,
	)
	if err != nil {
		return UnlinkReceipt{}, repositoryError(err)
	}
	if lifecycle.Retracted {
		return UnlinkReceipt{}, ErrConflict
	}
	linkID, err := entityID(lifecycle.LinkID)
	if err != nil {
		return UnlinkReceipt{}, ErrUnavailable
	}
	plan, err := planUnlink(
		service.clock().UTC().Truncate(time.Microsecond), tenantID, linkID,
		alert.Record, caseView.Record, input, alertAccess.Authority,
	)
	if err != nil {
		return UnlinkReceipt{}, err
	}
	alertPlans := plan.AlertMutations()
	if len(alertPlans) != 1 {
		return UnlinkReceipt{}, ErrUnavailable
	}
	alertPlan, casePlan := alertPlans[0], plan.CaseMutation()
	expectedAlert, alertErr := kernel.ApplyMutationPlan(
		alert.Record.Workflow, alert.Record.Snapshot, alertPlan,
	)
	expectedCase, caseErr := kernel.ApplyMutationPlan(
		caseView.Record.Workflow, caseView.Record.Snapshot, casePlan,
	)
	if alertErr != nil || caseErr != nil {
		return UnlinkReceipt{}, ErrUnavailable
	}
	effects := effectsForLinkLifecyclePlans([]kernel.MutationPlan{alertPlan, casePlan})
	receipt, err := service.repository.CommitUnlink(ctx, UnlinkWrite{
		Actor: actor, Alert: alert.Record, Case: caseView.Record,
		AlertPlan: alertPlan, CasePlan: casePlan, LinkID: lifecycle.LinkID,
		Input: input, KeyHash: keyHash, Fingerprint: fingerprint,
		Effects: effects, Audit: actor.Audit,
	})
	if err != nil {
		return UnlinkReceipt{}, repositoryError(err)
	}
	if expectedAlert.Version() != receipt.AlertVersion ||
		expectedCase.Version() != receipt.CaseVersion ||
		!validUnlinkReceipt(receipt, tenantID, alertID, input) {
		return UnlinkReceipt{}, ErrUnavailable
	}
	return receipt, nil
}

func validateUnlinkInput(alertID uuid.UUID, input UnlinkInput) error {
	if _, err := entityID(alertID); err != nil {
		return ErrInvalidInput
	}
	if _, err := entityID(input.CaseID); err != nil {
		return ErrInvalidInput
	}
	if input.ExpectedVersion == 0 || input.ExpectedVersion >= maxResourceVersion ||
		input.ExpectedCaseVersion == 0 || input.ExpectedCaseVersion >= maxResourceVersion ||
		!validText(input.Reason, 2_000, true) || !validIdempotencyKey(input.IdempotencyKey) {
		return ErrInvalidInput
	}
	return nil
}

func planUnlink(
	now time.Time,
	tenantID uuid.UUID,
	linkID kernel.EntityID,
	alert Record,
	caseRecord Record,
	input UnlinkInput,
	authority kernel.AuthorizationSnapshot,
) (kernel.EscalationPlan, error) {
	tenant, tenantErr := entityID(tenantID)
	key, keyErr := kernel.NewIdempotencyKey(input.IdempotencyKey)
	reason, reasonErr := kernel.NewEscalationReason(input.Reason)
	source, sourceErr := kernel.NewEscalationSource(
		alert.Workflow, linkID, alert.Snapshot, input.ExpectedVersion,
		nil, nil, nil, nil,
	)
	binding, bindingErr := kernel.NewEscalationSourceWorkflow(
		alert.Snapshot.ID(), alert.Workflow,
	)
	target, targetErr := kernel.NewExistingCaseTarget(
		caseRecord.Workflow, caseRecord.Snapshot, input.ExpectedCaseVersion,
	)
	if tenantErr != nil || keyErr != nil || reasonErr != nil || sourceErr != nil ||
		bindingErr != nil || targetErr != nil {
		return kernel.EscalationPlan{}, ErrInvalidInput
	}
	command, err := kernel.NewEscalationCommand(
		tenant, key, now, kernel.RelationCorrelation, reason, target,
		[]kernel.EscalationSource{source},
	)
	if err != nil {
		return kernel.EscalationPlan{}, ErrInvalidInput
	}
	return escalationPlan(kernel.PlanEscalation(
		[]kernel.EscalationSourceWorkflow{binding}, caseRecord.Workflow, command, authority,
	))
}

func unlinkFingerprint(
	tenantID uuid.UUID,
	actorID uuid.UUID,
	alertID uuid.UUID,
	input UnlinkInput,
) ([sha256.Size]byte, error) {
	document := struct {
		SchemaVersion       int       `json:"schemaVersion"`
		Operation           string    `json:"operation"`
		TenantID            uuid.UUID `json:"tenantId"`
		ActorID             uuid.UUID `json:"actorId"`
		AlertID             uuid.UUID `json:"alertId"`
		CaseID              uuid.UUID `json:"caseId"`
		ExpectedVersion     uint64    `json:"expectedVersion"`
		ExpectedCaseVersion uint64    `json:"expectedCaseVersion"`
		Reason              string    `json:"reason"`
	}{
		SchemaVersion: 1, Operation: "alert.unlink", TenantID: tenantID,
		ActorID: actorID, AlertID: alertID, CaseID: input.CaseID,
		ExpectedVersion:     input.ExpectedVersion,
		ExpectedCaseVersion: input.ExpectedCaseVersion, Reason: input.Reason,
	}
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) > 4_096 {
		return [sha256.Size]byte{}, ErrInvalidInput
	}
	return sha256.Sum256(encoded), nil
}

func validUnlinkReceipt(
	receipt UnlinkReceipt,
	tenantID uuid.UUID,
	alertID uuid.UUID,
	input UnlinkInput,
) bool {
	if receipt.TenantID != tenantID || receipt.AlertID != alertID ||
		receipt.CaseID != input.CaseID ||
		receipt.PreviousAlertVersion != input.ExpectedVersion ||
		receipt.AlertVersion != input.ExpectedVersion+1 ||
		receipt.PreviousCaseVersion != input.ExpectedCaseVersion ||
		receipt.CaseVersion != input.ExpectedCaseVersion+1 ||
		!validStoredInstant(receipt.RetractedAt) {
		return false
	}
	_, err := entityID(receipt.LinkID)
	return err == nil
}
