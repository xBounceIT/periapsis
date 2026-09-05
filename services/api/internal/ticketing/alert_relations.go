package ticketing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

type AlertRelationType string

const (
	AlertRelationDuplicateOf AlertRelationType = "duplicate_of"
	AlertRelationCorrelation AlertRelationType = "correlation"
)

type AlertRelationDirection string

const (
	AlertRelationOutgoing  AlertRelationDirection = "outgoing"
	AlertRelationIncoming  AlertRelationDirection = "incoming"
	AlertRelationSymmetric AlertRelationDirection = "symmetric"
)

type AlertRelationRetraction struct {
	Reason                string
	PreviousSourceVersion uint64
	SourceVersion         uint64
	PreviousTargetVersion uint64
	TargetVersion         uint64
	RetractedAt           time.Time
}

type AlertRelation struct {
	ID                    uuid.UUID
	TenantID              uuid.UUID
	SourceAlertID         uuid.UUID
	TargetAlertID         uuid.UUID
	Type                  AlertRelationType
	Reason                string
	PreviousSourceVersion uint64
	SourceVersion         uint64
	PreviousTargetVersion uint64
	TargetVersion         uint64
	LinkedAt              time.Time
	Retraction            *AlertRelationRetraction
}

type AlertRelationRecord struct {
	Relation  AlertRelation
	Related   Record
	Direction AlertRelationDirection
}

type StoredAlertRelationPage struct {
	Items      []AlertRelationRecord
	NextCursor *uuid.UUID
}

type AlertRelationPage struct {
	Items      []AlertRelationRecord
	NextCursor *uuid.UUID
}

type AlertRelationCreateInput struct {
	TargetAlertID         uuid.UUID
	RelationType          AlertRelationType
	ExpectedVersion       uint64
	ExpectedTargetVersion uint64
	Reason                string
	IdempotencyKey        string
}

type AlertRelationRetractionInput struct {
	RelatedAlertID              uuid.UUID
	ExpectedVersion             uint64
	ExpectedRelatedAlertVersion uint64
	Reason                      string
	IdempotencyKey              string
}

type AlertRelationMutationReceipt struct {
	TenantID                    uuid.UUID
	AlertID                     uuid.UUID
	RelatedAlertID              uuid.UUID
	RelationID                  uuid.UUID
	RelationType                AlertRelationType
	PreviousAlertVersion        uint64
	AlertVersion                uint64
	PreviousRelatedAlertVersion uint64
	RelatedAlertVersion         uint64
	OccurredAt                  time.Time
	Replayed                    bool
}

type AlertRelationReplayQuery struct {
	Actor          Actor
	TenantID       uuid.UUID
	AlertID        uuid.UUID
	RelatedAlertID uuid.UUID
	RelationID     uuid.UUID
	KeyHash        [sha256.Size]byte
	Fingerprint    [sha256.Size]byte
}

type AlertRelationCreateWrite struct {
	Actor       Actor
	Source      Record
	Target      Record
	Plan        kernel.AlertRelationPlan
	Input       AlertRelationCreateInput
	KeyHash     [sha256.Size]byte
	Fingerprint [sha256.Size]byte
	Audit       AuditContext
}

type AlertRelationRetractionWrite struct {
	Actor       Actor
	Alert       Record
	Related     Record
	Relation    AlertRelation
	Plan        kernel.AlertRelationPlan
	Input       AlertRelationRetractionInput
	KeyHash     [sha256.Size]byte
	Fingerprint [sha256.Size]byte
	Audit       AuditContext
}

func (service *Service) AlertRelations(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	alertID uuid.UUID,
	pageInput CursorPageInput,
) (AlertRelationPage, error) {
	access, err := service.access(ctx, actor, tenantID, CapabilityAlertRelationManage)
	if err != nil {
		return AlertRelationPage{}, err
	}
	if access.Authority.Principal() != kernel.PrincipalOperator {
		return AlertRelationPage{}, ErrForbidden
	}
	source, err := service.getAuthorized(ctx, tenantID, kernel.AggregateAlert, alertID, access)
	if err != nil {
		return AlertRelationPage{}, err
	}
	pageInput, err = validateCursorPage(pageInput)
	if err != nil {
		return AlertRelationPage{}, err
	}
	page, err := service.repository.ListAlertRelations(ctx, actor.UserID, tenantID, alertID, pageInput, access)
	if err != nil {
		return AlertRelationPage{}, repositoryError(err)
	}
	if len(page.Items) > pageInput.Limit || !validOptionalCursor(page.NextCursor) {
		return AlertRelationPage{}, ErrUnavailable
	}
	seen := make(map[uuid.UUID]struct{}, len(page.Items))
	var previous uuid.UUID
	for index, item := range page.Items {
		if !validAlertRelationRecord(item, source.Record, tenantID, access) {
			return AlertRelationPage{}, ErrUnavailable
		}
		if _, duplicate := seen[item.Relation.ID]; duplicate {
			return AlertRelationPage{}, ErrUnavailable
		}
		if index > 0 && bytes.Compare(previous[:], item.Relation.ID[:]) <= 0 {
			return AlertRelationPage{}, ErrUnavailable
		}
		seen[item.Relation.ID] = struct{}{}
		previous = item.Relation.ID
	}
	if page.NextCursor != nil &&
		(len(page.Items) != pageInput.Limit || *page.NextCursor != page.Items[len(page.Items)-1].Relation.ID) {
		return AlertRelationPage{}, ErrUnavailable
	}
	return AlertRelationPage{Items: page.Items, NextCursor: page.NextCursor}, nil
}

func (service *Service) CreateAlertRelation(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	alertID uuid.UUID,
	input AlertRelationCreateInput,
) (AlertRelationMutationReceipt, error) {
	kind, reason, fingerprint, keyHash, err := prepareAlertRelationCreate(actor, tenantID, alertID, input)
	if err != nil {
		return AlertRelationMutationReceipt{}, err
	}
	access, err := service.access(ctx, actor, tenantID, CapabilityAlertRelationManage)
	if err != nil {
		return AlertRelationMutationReceipt{}, err
	}
	if access.Authority.Principal() != kernel.PrincipalOperator {
		return AlertRelationMutationReceipt{}, ErrForbidden
	}
	replayQuery := AlertRelationReplayQuery{
		Actor: actor, TenantID: tenantID, AlertID: alertID,
		RelatedAlertID: input.TargetAlertID, KeyHash: keyHash, Fingerprint: fingerprint,
	}
	if replay, found, lookupErr := service.repository.LookupAlertRelationCreateReplay(ctx, replayQuery); lookupErr != nil {
		return AlertRelationMutationReceipt{}, repositoryError(lookupErr)
	} else if found {
		replay.Replayed = true
		if !validAlertRelationReceipt(replay, tenantID, alertID, input.TargetAlertID, uuid.Nil, input.ExpectedVersion, input.ExpectedTargetVersion, input.RelationType) {
			return AlertRelationMutationReceipt{}, ErrUnavailable
		}
		return replay, nil
	}

	source, target, err := service.authorizedAlertRelationPair(ctx, tenantID, alertID, input.TargetAlertID, access)
	if err != nil {
		return AlertRelationMutationReceipt{}, err
	}
	if source.Record.Snapshot.Version() != input.ExpectedVersion ||
		target.Record.Snapshot.Version() != input.ExpectedTargetVersion {
		return AlertRelationMutationReceipt{}, ErrPreconditionFailed
	}
	plan, err := kernel.PlanAlertRelation(
		source.Record.Snapshot.Tenant(), access.Authority.Actor(),
		source.Record.Snapshot.ID(), target.Record.Snapshot.ID(), kind, reason,
		input.ExpectedVersion, input.ExpectedTargetVersion, access.Authority,
	)
	if err != nil {
		return AlertRelationMutationReceipt{}, ErrForbidden
	}
	receipt, err := service.repository.CommitAlertRelationCreate(ctx, AlertRelationCreateWrite{
		Actor: actor, Source: source.Record, Target: target.Record, Plan: plan,
		Input: input, KeyHash: keyHash, Fingerprint: fingerprint, Audit: actor.Audit,
	})
	if err != nil {
		return AlertRelationMutationReceipt{}, repositoryError(err)
	}
	if !validAlertRelationReceipt(receipt, tenantID, alertID, input.TargetAlertID, uuid.Nil, input.ExpectedVersion, input.ExpectedTargetVersion, input.RelationType) {
		return AlertRelationMutationReceipt{}, ErrUnavailable
	}
	return receipt, nil
}

func (service *Service) RetractAlertRelation(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	alertID uuid.UUID,
	relationID uuid.UUID,
	input AlertRelationRetractionInput,
) (AlertRelationMutationReceipt, error) {
	reason, fingerprint, keyHash, err := prepareAlertRelationRetraction(actor, tenantID, alertID, relationID, input)
	if err != nil {
		return AlertRelationMutationReceipt{}, err
	}
	access, err := service.access(ctx, actor, tenantID, CapabilityAlertRelationManage)
	if err != nil {
		return AlertRelationMutationReceipt{}, err
	}
	if access.Authority.Principal() != kernel.PrincipalOperator {
		return AlertRelationMutationReceipt{}, ErrForbidden
	}
	replayQuery := AlertRelationReplayQuery{
		Actor: actor, TenantID: tenantID, AlertID: alertID,
		RelatedAlertID: input.RelatedAlertID, RelationID: relationID,
		KeyHash: keyHash, Fingerprint: fingerprint,
	}
	if replay, found, lookupErr := service.repository.LookupAlertRelationRetractionReplay(ctx, replayQuery); lookupErr != nil {
		return AlertRelationMutationReceipt{}, repositoryError(lookupErr)
	} else if found {
		replay.Replayed = true
		if !validAlertRelationReceipt(replay, tenantID, alertID, input.RelatedAlertID, relationID, input.ExpectedVersion, input.ExpectedRelatedAlertVersion, replay.RelationType) {
			return AlertRelationMutationReceipt{}, ErrUnavailable
		}
		return replay, nil
	}

	path, related, err := service.authorizedAlertRelationPair(ctx, tenantID, alertID, input.RelatedAlertID, access)
	if err != nil {
		return AlertRelationMutationReceipt{}, err
	}
	if path.Record.Snapshot.Version() != input.ExpectedVersion ||
		related.Record.Snapshot.Version() != input.ExpectedRelatedAlertVersion {
		return AlertRelationMutationReceipt{}, ErrPreconditionFailed
	}
	record, err := service.repository.GetAlertRelation(ctx, actor.UserID, tenantID, alertID, relationID, access)
	if err != nil {
		return AlertRelationMutationReceipt{}, repositoryError(err)
	}
	if !validAlertRelationRecord(record, path.Record, tenantID, access) ||
		uuidFromEntity(record.Related.Snapshot.ID()) != input.RelatedAlertID {
		return AlertRelationMutationReceipt{}, ErrUnavailable
	}
	if record.Relation.Retraction != nil {
		return AlertRelationMutationReceipt{}, ErrConflict
	}
	kind, parseErr := kernel.ParseAlertRelationKind(string(record.Relation.Type))
	if parseErr != nil {
		return AlertRelationMutationReceipt{}, ErrUnavailable
	}
	plan, planErr := kernel.PlanAlertRelation(
		path.Record.Snapshot.Tenant(), access.Authority.Actor(),
		path.Record.Snapshot.ID(), related.Record.Snapshot.ID(), kind, reason,
		input.ExpectedVersion, input.ExpectedRelatedAlertVersion, access.Authority,
	)
	if planErr != nil {
		return AlertRelationMutationReceipt{}, ErrForbidden
	}
	receipt, err := service.repository.CommitAlertRelationRetraction(ctx, AlertRelationRetractionWrite{
		Actor: actor, Alert: path.Record, Related: related.Record,
		Relation: record.Relation, Plan: plan, Input: input,
		KeyHash: keyHash, Fingerprint: fingerprint, Audit: actor.Audit,
	})
	if err != nil {
		return AlertRelationMutationReceipt{}, repositoryError(err)
	}
	if !validAlertRelationReceipt(receipt, tenantID, alertID, input.RelatedAlertID, relationID, input.ExpectedVersion, input.ExpectedRelatedAlertVersion, record.Relation.Type) {
		return AlertRelationMutationReceipt{}, ErrUnavailable
	}
	return receipt, nil
}

func (service *Service) authorizedAlertRelationPair(
	ctx context.Context,
	tenantID uuid.UUID,
	alertID uuid.UUID,
	relatedAlertID uuid.UUID,
	access LiveAccess,
) (View, View, error) {
	path, err := service.getAuthorized(ctx, tenantID, kernel.AggregateAlert, alertID, access)
	if err != nil {
		return View{}, View{}, err
	}
	related, err := service.getAuthorized(ctx, tenantID, kernel.AggregateAlert, relatedAlertID, access)
	if err != nil {
		return View{}, View{}, err
	}
	if path.Projection != ProjectionOperator || related.Projection != ProjectionOperator ||
		!alertRelationCommonScope(path.Record, related.Record, access) {
		return View{}, View{}, ErrForbidden
	}
	return path, related, nil
}

func prepareAlertRelationCreate(
	actor Actor,
	tenantID uuid.UUID,
	alertID uuid.UUID,
	input AlertRelationCreateInput,
) (kernel.AlertRelationKind, kernel.AlertRelationReason, [sha256.Size]byte, [sha256.Size]byte, error) {
	if !validMutationActor(actor, tenantID) || alertID == input.TargetAlertID ||
		input.ExpectedVersion == 0 || input.ExpectedVersion >= maxResourceVersion ||
		input.ExpectedTargetVersion == 0 || input.ExpectedTargetVersion >= maxResourceVersion ||
		!validIdempotencyKey(input.IdempotencyKey) {
		return 0, kernel.AlertRelationReason{}, [sha256.Size]byte{}, [sha256.Size]byte{}, ErrInvalidInput
	}
	if _, err := entityID(alertID); err != nil {
		return 0, kernel.AlertRelationReason{}, [sha256.Size]byte{}, [sha256.Size]byte{}, ErrInvalidInput
	}
	if _, err := entityID(input.TargetAlertID); err != nil {
		return 0, kernel.AlertRelationReason{}, [sha256.Size]byte{}, [sha256.Size]byte{}, ErrInvalidInput
	}
	kind, err := kernel.ParseAlertRelationKind(string(input.RelationType))
	if err != nil {
		return 0, kernel.AlertRelationReason{}, [sha256.Size]byte{}, [sha256.Size]byte{}, ErrInvalidInput
	}
	reason, err := kernel.NewAlertRelationReason(input.Reason)
	if err != nil {
		return 0, kernel.AlertRelationReason{}, [sha256.Size]byte{}, [sha256.Size]byte{}, ErrInvalidInput
	}
	fingerprint, err := alertRelationFingerprint("create", tenantID, actor.UserID, alertID, input.TargetAlertID, uuid.Nil, input.ExpectedVersion, input.ExpectedTargetVersion, input.RelationType, input.Reason)
	if err != nil {
		return 0, kernel.AlertRelationReason{}, [sha256.Size]byte{}, [sha256.Size]byte{}, err
	}
	return kind, reason, fingerprint, sha256.Sum256([]byte(input.IdempotencyKey)), nil
}

func prepareAlertRelationRetraction(
	actor Actor,
	tenantID uuid.UUID,
	alertID uuid.UUID,
	relationID uuid.UUID,
	input AlertRelationRetractionInput,
) (kernel.AlertRelationReason, [sha256.Size]byte, [sha256.Size]byte, error) {
	if !validMutationActor(actor, tenantID) || alertID == input.RelatedAlertID ||
		input.ExpectedVersion == 0 || input.ExpectedVersion >= maxResourceVersion ||
		input.ExpectedRelatedAlertVersion == 0 || input.ExpectedRelatedAlertVersion >= maxResourceVersion ||
		!validIdempotencyKey(input.IdempotencyKey) {
		return kernel.AlertRelationReason{}, [sha256.Size]byte{}, [sha256.Size]byte{}, ErrInvalidInput
	}
	for _, id := range []uuid.UUID{alertID, input.RelatedAlertID, relationID} {
		if _, err := entityID(id); err != nil {
			return kernel.AlertRelationReason{}, [sha256.Size]byte{}, [sha256.Size]byte{}, ErrInvalidInput
		}
	}
	reason, err := kernel.NewAlertRelationReason(input.Reason)
	if err != nil {
		return kernel.AlertRelationReason{}, [sha256.Size]byte{}, [sha256.Size]byte{}, ErrInvalidInput
	}
	fingerprint, err := alertRelationFingerprint("retract", tenantID, actor.UserID, alertID, input.RelatedAlertID, relationID, input.ExpectedVersion, input.ExpectedRelatedAlertVersion, "", input.Reason)
	if err != nil {
		return kernel.AlertRelationReason{}, [sha256.Size]byte{}, [sha256.Size]byte{}, err
	}
	return reason, fingerprint, sha256.Sum256([]byte(input.IdempotencyKey)), nil
}

func alertRelationFingerprint(
	operation string,
	tenantID uuid.UUID,
	actorID uuid.UUID,
	alertID uuid.UUID,
	relatedAlertID uuid.UUID,
	relationID uuid.UUID,
	expectedVersion uint64,
	expectedRelatedVersion uint64,
	relationType AlertRelationType,
	reason string,
) ([sha256.Size]byte, error) {
	document := struct {
		SchemaVersion          int               `json:"schemaVersion"`
		Operation              string            `json:"operation"`
		TenantID               uuid.UUID         `json:"tenantId"`
		ActorID                uuid.UUID         `json:"actorId"`
		AlertID                uuid.UUID         `json:"alertId"`
		RelatedAlertID         uuid.UUID         `json:"relatedAlertId"`
		RelationID             uuid.UUID         `json:"relationId,omitempty"`
		ExpectedVersion        uint64            `json:"expectedVersion"`
		ExpectedRelatedVersion uint64            `json:"expectedRelatedVersion"`
		RelationType           AlertRelationType `json:"relationType,omitempty"`
		Reason                 string            `json:"reason"`
	}{
		SchemaVersion: 1, Operation: operation, TenantID: tenantID,
		ActorID: actorID, AlertID: alertID, RelatedAlertID: relatedAlertID,
		RelationID: relationID, ExpectedVersion: expectedVersion,
		ExpectedRelatedVersion: expectedRelatedVersion,
		RelationType:           relationType, Reason: reason,
	}
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) > 4_096 {
		return [sha256.Size]byte{}, ErrInvalidInput
	}
	return sha256.Sum256(encoded), nil
}

func alertRelationCommonScope(left Record, right Record, access LiveAccess) bool {
	return slices.ContainsFunc(access.Scopes, func(scope Scope) bool {
		return alertRelationScopeAllows(left, access, scope) && alertRelationScopeAllows(right, access, scope)
	})
}

func alertRelationScopeAllows(record Record, access LiveAccess, scope Scope) bool {
	actor := access.Authority.Actor()
	assignment := record.Snapshot.Assignment()
	team, hasTeam := assignment.Team()
	assignee, hasAssignee := assignment.Assignee()
	claimant, hasClaimant := assignment.Claimant()
	switch scope {
	case ScopeTenant:
		return true
	case ScopeOwn:
		return record.Creator.UserID != nil && *record.Creator.UserID == uuidFromEntity(actor)
	case ScopeAssigned:
		return hasAssignee && assignee == actor || hasClaimant && claimant == actor
	case ScopeOperatorTeam:
		return hasTeam && slices.Contains(access.OperatorTeams, team)
	default:
		return false
	}
}

func validAlertRelationRecord(record AlertRelationRecord, path Record, tenantID uuid.UUID, access LiveAccess) bool {
	relation := record.Relation
	if relation.TenantID != tenantID || validateRecord(record.Related, tenantID, kernel.AggregateAlert) != nil ||
		!alertRelationCommonScope(path, record.Related, access) || !canAccess(record.Related, access) ||
		!validAlertRelationType(relation.Type) || !validAlertRelationReason(relation.Reason) ||
		relation.SourceAlertID == relation.TargetAlertID ||
		relation.PreviousSourceVersion == 0 || relation.PreviousSourceVersion >= maxResourceVersion ||
		relation.SourceVersion != relation.PreviousSourceVersion+1 ||
		relation.PreviousTargetVersion == 0 || relation.PreviousTargetVersion >= maxResourceVersion ||
		relation.TargetVersion != relation.PreviousTargetVersion+1 ||
		!validStoredInstant(relation.LinkedAt) {
		return false
	}
	for _, id := range []uuid.UUID{relation.ID, relation.SourceAlertID, relation.TargetAlertID} {
		if _, err := entityID(id); err != nil {
			return false
		}
	}
	pathID := uuidFromEntity(path.Snapshot.ID())
	relatedID := uuidFromEntity(record.Related.Snapshot.ID())
	pathVersion, relatedVersion := path.Snapshot.Version(), record.Related.Snapshot.Version()
	pathUpdatedAt, relatedUpdatedAt := path.UpdatedAt, record.Related.UpdatedAt
	pathFloor, relatedFloor := relation.TargetVersion, relation.SourceVersion
	if relation.Type == AlertRelationCorrelation {
		if record.Direction != AlertRelationSymmetric {
			return false
		}
	} else if relation.SourceAlertID == pathID {
		pathFloor, relatedFloor = relation.SourceVersion, relation.TargetVersion
		if record.Direction != AlertRelationOutgoing || relation.TargetAlertID != relatedID {
			return false
		}
	} else if record.Direction != AlertRelationIncoming || relation.TargetAlertID != pathID || relation.SourceAlertID != relatedID {
		return false
	}
	if relation.Type == AlertRelationCorrelation &&
		!((relation.SourceAlertID == pathID && relation.TargetAlertID == relatedID) ||
			(relation.TargetAlertID == pathID && relation.SourceAlertID == relatedID)) {
		return false
	}
	if relation.Type == AlertRelationCorrelation && relation.SourceAlertID == pathID {
		pathFloor, relatedFloor = relation.SourceVersion, relation.TargetVersion
	}
	if relation.Retraction != nil {
		retraction := relation.Retraction
		if !validAlertRelationReason(retraction.Reason) ||
			retraction.PreviousSourceVersion == 0 || retraction.PreviousSourceVersion >= maxResourceVersion ||
			retraction.SourceVersion != retraction.PreviousSourceVersion+1 ||
			retraction.PreviousTargetVersion == 0 || retraction.PreviousTargetVersion >= maxResourceVersion ||
			retraction.TargetVersion != retraction.PreviousTargetVersion+1 ||
			retraction.PreviousSourceVersion < relation.SourceVersion ||
			retraction.PreviousTargetVersion < relation.TargetVersion ||
			!validStoredInstant(retraction.RetractedAt) || retraction.RetractedAt.Before(relation.LinkedAt) {
			return false
		}
		if relation.SourceAlertID == pathID {
			pathFloor, relatedFloor = retraction.SourceVersion, retraction.TargetVersion
		} else {
			pathFloor, relatedFloor = retraction.TargetVersion, retraction.SourceVersion
		}
		if pathUpdatedAt.Before(retraction.RetractedAt) || relatedUpdatedAt.Before(retraction.RetractedAt) {
			return false
		}
	} else if pathUpdatedAt.Before(relation.LinkedAt) || relatedUpdatedAt.Before(relation.LinkedAt) {
		return false
	}
	return pathVersion >= pathFloor && relatedVersion >= relatedFloor
}

func validAlertRelationReceipt(
	receipt AlertRelationMutationReceipt,
	tenantID uuid.UUID,
	alertID uuid.UUID,
	relatedAlertID uuid.UUID,
	relationID uuid.UUID,
	expectedVersion uint64,
	expectedRelatedVersion uint64,
	relationType AlertRelationType,
) bool {
	if receipt.TenantID != tenantID || receipt.AlertID != alertID ||
		receipt.RelatedAlertID != relatedAlertID ||
		relationID != uuid.Nil && receipt.RelationID != relationID ||
		!validAlertRelationType(receipt.RelationType) ||
		relationType != "" && receipt.RelationType != relationType ||
		receipt.PreviousAlertVersion != expectedVersion || receipt.AlertVersion != expectedVersion+1 ||
		receipt.PreviousRelatedAlertVersion != expectedRelatedVersion ||
		receipt.RelatedAlertVersion != expectedRelatedVersion+1 || !validStoredInstant(receipt.OccurredAt) {
		return false
	}
	_, err := entityID(receipt.RelationID)
	return err == nil
}

func validAlertRelationType(value AlertRelationType) bool {
	return value == AlertRelationDuplicateOf || value == AlertRelationCorrelation
}

func validAlertRelationReason(value string) bool {
	_, err := kernel.NewAlertRelationReason(value)
	return err == nil
}
