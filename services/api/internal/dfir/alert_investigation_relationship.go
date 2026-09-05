package dfir

import (
	"context"
	"slices"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

func (service *AlertInvestigationService) CreateRelationship(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command AlertRelationshipCreateCommand,
) (MutationResult[kernel.AlertRelationship], error) {
	command.Input.Metadata = slices.Clone(command.Input.Metadata)
	if len(command.Input.Metadata) == 0 {
		command.Input.Metadata = nil
	}
	access, actorID, err := service.authorizeMutation(
		ctx, actor, tenantID, command.AlertID, CapabilityRelationshipManage, command.Envelope,
	)
	if err != nil {
		return MutationResult[kernel.AlertRelationship]{}, err
	}
	tenant, _, conversionErr := actorEntities(actor)
	if conversionErr != nil {
		return MutationResult[kernel.AlertRelationship]{}, ErrForbidden
	}
	now, err := service.currentTime()
	if err != nil {
		return MutationResult[kernel.AlertRelationship]{}, err
	}
	relationship, err := kernel.NewAlertRelationship(kernel.AlertRelationshipState{
		ID: command.Input.ID, TenantID: tenant, AlertID: command.AlertID,
		Source: command.Input.Source, Target: command.Input.Target,
		RelationshipType: command.Input.RelationshipType, Metadata: command.Input.Metadata,
		CreatedBy: actorID, CreatedAt: now, Version: 1,
	})
	if err != nil {
		return MutationResult[kernel.AlertRelationship]{}, ErrInvalidInput
	}
	contract, err := newAlertMutationContract(
		actor, command.AlertID, command.Envelope, access, CapabilityRelationshipManage,
		operationAlertRelationshipCreate, "Alert DFIR relationship created",
		alertRelationshipCreateRequestFingerprint(relationship),
	)
	if err != nil {
		return MutationResult[kernel.AlertRelationship]{}, err
	}
	if err := ctx.Err(); err != nil {
		return MutationResult[kernel.AlertRelationship]{}, err
	}
	result, err := service.repository.CommitAlertRelationship(ctx, AlertRelationshipCreateWrite{
		Contract: contract, Relationship: relationship,
	})
	if err != nil {
		return MutationResult[kernel.AlertRelationship]{}, alertInvestigationMutationError(err)
	}
	if err := ctx.Err(); err != nil {
		return MutationResult[kernel.AlertRelationship]{}, err
	}
	if !validAlertRelationshipResult(result.Resource, tenant, command.AlertID, command.Input.ID, 1) ||
		!sameFingerprint(
			alertRelationshipCreateRequestFingerprint(result.Resource),
			alertRelationshipCreateRequestFingerprint(relationship),
		) || !result.Replayed && !sameFingerprint(
		alertRelationshipFingerprint(result.Resource, 0), alertRelationshipFingerprint(relationship, 0),
	) {
		return MutationResult[kernel.AlertRelationship]{}, ErrUnavailable
	}
	return result, nil
}

func (service *AlertInvestigationService) RetractRelationship(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command AlertRelationshipRetractCommand,
) (MutationResult[kernel.AlertRelationship], error) {
	access, actorID, err := service.authorizeMutation(
		ctx, actor, tenantID, command.AlertID, CapabilityRelationshipManage, command.Envelope,
	)
	if err != nil {
		return MutationResult[kernel.AlertRelationship]{}, err
	}
	if !validAlertMutationVersion(command.ExpectedVersion) || command.RelationshipID == (kernel.EntityID{}) ||
		command.RetractionID == (kernel.EntityID{}) ||
		!validAlertSingleLineText(command.Reason, 2_000, false) {
		return MutationResult[kernel.AlertRelationship]{}, ErrInvalidInput
	}
	now, err := service.currentTime()
	if err != nil {
		return MutationResult[kernel.AlertRelationship]{}, err
	}
	retraction := kernel.AlertRelationshipRetractionInput{
		ID: command.RetractionID, ActorID: actorID, Reason: command.Reason, OccurredAt: now,
	}
	contract, err := newAlertMutationContract(
		actor, command.AlertID, command.Envelope, access, CapabilityRelationshipManage,
		operationAlertRelationshipRetract, command.Reason,
		alertRelationshipRetractionRequestFingerprint(command, actorID),
	)
	if err != nil {
		return MutationResult[kernel.AlertRelationship]{}, err
	}
	if err := ctx.Err(); err != nil {
		return MutationResult[kernel.AlertRelationship]{}, err
	}
	var applied alertCallbackCapture[kernel.AlertRelationship]
	result, err := service.repository.MutateAlertRelationship(ctx, AlertRelationshipMutationWrite{
		Contract: contract, RelationshipID: command.RelationshipID, ExpectedVersion: command.ExpectedVersion,
		Apply: func(current kernel.AlertRelationship) (kernel.AlertRelationship, error) {
			applied.begin()
			if err := ctx.Err(); err != nil {
				return kernel.AlertRelationship{}, err
			}
			if current.TenantID().String() != tenantID.String() || current.AlertID() != command.AlertID ||
				current.ID() != command.RelationshipID || !validAlertRelationshipProjection(current) ||
				now.Before(current.CreatedAt()) {
				return kernel.AlertRelationship{}, ErrUnavailable
			}
			updated, applyErr := current.Retract(command.ExpectedVersion, retraction)
			if applyErr == nil {
				applied.complete(updated)
			}
			return updated, applyErr
		},
	})
	if err != nil {
		return MutationResult[kernel.AlertRelationship]{}, alertInvestigationMutationError(err)
	}
	if err := ctx.Err(); err != nil {
		return MutationResult[kernel.AlertRelationship]{}, err
	}
	tenant, _, conversionErr := actorEntities(actor)
	if conversionErr != nil || !validAlertRelationshipResult(
		result.Resource, tenant, command.AlertID, command.RelationshipID, command.ExpectedVersion+1,
	) {
		return MutationResult[kernel.AlertRelationship]{}, ErrUnavailable
	}
	retractions := result.Resource.Retractions()
	if len(retractions) != 1 {
		return MutationResult[kernel.AlertRelationship]{}, ErrUnavailable
	}
	last := retractions[0]
	if last.ID != command.RetractionID || last.ActorID != actorID || last.Reason != command.Reason ||
		last.RelationshipID != command.RelationshipID || last.TenantID != tenant {
		return MutationResult[kernel.AlertRelationship]{}, ErrUnavailable
	}
	appliedRelationship, applyCalls := applied.snapshot()
	if result.Replayed && applyCalls != 0 || !result.Replayed &&
		(applyCalls != 1 || !sameFingerprint(
			alertRelationshipFingerprint(result.Resource, 0),
			alertRelationshipFingerprint(appliedRelationship, 0),
		)) {
		return MutationResult[kernel.AlertRelationship]{}, ErrUnavailable
	}
	return result, nil
}

func validAlertRelationshipResult(
	relationship kernel.AlertRelationship,
	tenant kernel.EntityID,
	alertID kernel.EntityID,
	relationshipID kernel.EntityID,
	version uint64,
) bool {
	return relationship.TenantID() == tenant && relationship.AlertID() == alertID &&
		relationship.ID() == relationshipID && relationship.Version() == version &&
		validAlertRelationshipProjection(relationship)
}
