package dfir

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

// RetractRelationship appends the sole terminal retraction record. The
// repository owns live authorization, endpoint validation, caller-ID binding,
// exact replay, row locking, CAS, and all journal effects.
func (service *Service) RetractRelationship(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	command RelationshipRetractCommand,
) (MutationResult[kernel.Relationship], error) {
	if err := service.authorizeMutation(
		ctx, actor, tenantID, CapabilityRelationshipManage, command.CaseID, command.Envelope,
	); err != nil {
		return MutationResult[kernel.Relationship]{}, err
	}
	if command.RelationshipID == (kernel.EntityID{}) || command.RetractionID == (kernel.EntityID{}) ||
		command.ExpectedVersion == 0 || command.ExpectedVersion >= kernel.MaximumResourceVersion ||
		!validSingleLine(command.Reason, 2_000, false) || !utf8.ValidString(command.Reason) ||
		strings.ContainsAny(command.Reason, "\u2028\u2029") {
		return MutationResult[kernel.Relationship]{}, ErrInvalidInput
	}
	tenant, actorID, err := actorEntities(actor)
	if err != nil {
		return MutationResult[kernel.Relationship]{}, ErrForbidden
	}
	now := service.now()
	input := kernel.RelationshipRetractionInput{
		ID: command.RetractionID, ActorID: actorID, Reason: command.Reason, OccurredAt: now,
	}
	base, err := baseWrite(
		actor, command.CaseID, command.Envelope, operationRelationshipRetract,
		relationshipRetractionRequestFingerprint(command, actorID),
	)
	if err != nil {
		return MutationResult[kernel.Relationship]{}, err
	}
	if err := ctx.Err(); err != nil {
		return MutationResult[kernel.Relationship]{}, err
	}
	var applied alertCallbackCapture[kernel.Relationship]
	result, err := service.repository.MutateRelationship(ctx, RelationshipMutationWrite{
		BaseWrite: base, RelationshipID: command.RelationshipID, RetractionID: command.RetractionID,
		ExpectedVersion: command.ExpectedVersion,
		Apply: func(current kernel.Relationship) (kernel.Relationship, error) {
			applied.begin()
			if err := ctx.Err(); err != nil {
				return kernel.Relationship{}, err
			}
			if current.TenantID() != tenant || current.ID() != command.RelationshipID ||
				!validCaseRelationshipProjection(current) || now.Before(current.CreatedAt()) {
				return kernel.Relationship{}, ErrUnavailable
			}
			updated, applyErr := current.Retract(command.ExpectedVersion, input)
			if applyErr == nil {
				applied.complete(updated)
			}
			return updated, applyErr
		},
	})
	if err != nil {
		return MutationResult[kernel.Relationship]{}, caseRelationshipMutationError(err)
	}
	if err := ctx.Err(); err != nil {
		return MutationResult[kernel.Relationship]{}, err
	}
	if result.Resource.TenantID() != tenant || result.Resource.ID() != command.RelationshipID ||
		result.Resource.Version() != command.ExpectedVersion+1 || result.Resource.Active() {
		return MutationResult[kernel.Relationship]{}, ErrUnavailable
	}
	retractions := result.Resource.Retractions()
	if len(retractions) != 1 {
		return MutationResult[kernel.Relationship]{}, ErrUnavailable
	}
	retraction := retractions[0]
	if retraction.ID != command.RetractionID || retraction.TenantID != tenant ||
		retraction.RelationshipID != command.RelationshipID || retraction.Sequence != 1 ||
		retraction.ActorID != actorID || retraction.Reason != command.Reason {
		return MutationResult[kernel.Relationship]{}, ErrUnavailable
	}
	appliedRelationship, applyCalls := applied.snapshot()
	if result.Replayed && applyCalls != 0 || !result.Replayed &&
		(applyCalls != 1 || !sameFingerprint(
			relationshipFingerprint(result.Resource), relationshipFingerprint(appliedRelationship),
		)) {
		return MutationResult[kernel.Relationship]{}, ErrUnavailable
	}
	return result, nil
}

func validCaseRelationshipProjection(value kernel.Relationship) bool {
	if value.ID() == (kernel.EntityID{}) || value.TenantID() == (kernel.EntityID{}) ||
		value.CreatedBy() == (kernel.EntityID{}) || value.Version() == 0 ||
		value.Version() > kernel.MaximumResourceVersion || value.CreatedAt().IsZero() {
		return false
	}
	if _, err := kernel.NewRelationship(kernel.RelationshipInput{
		ID: value.ID(), TenantID: value.TenantID(), Source: value.Source(), Target: value.Target(),
		RelationshipType: value.RelationshipType(), Metadata: value.Metadata(),
		CreatedBy: value.CreatedBy(), CreatedAt: value.CreatedAt(), Version: value.Version(),
		Retractions: value.Retractions(),
	}); err != nil {
		return false
	}
	return true
}

func caseRelationshipMutationError(err error) error {
	switch {
	case errors.Is(err, kernel.ErrRelationshipConflict):
		return ErrPreconditionFailed
	case errors.Is(err, kernel.ErrInvalidRelationship):
		return ErrInvalidInput
	default:
		return repositoryError(err)
	}
}
