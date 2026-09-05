package notification

import (
	"context"
	"slices"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

func (s *Service) ListDeliveries(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input DeliveryListInput,
) (DeliveryPage, error) {
	page, err := normalizePage(input.PageInput)
	if err != nil {
		return DeliveryPage{}, err
	}
	statuses, err := normalizeDeliveryStatuses(input.Statuses)
	if err != nil {
		return DeliveryPage{}, err
	}
	human, err := s.requireTenant(ctx, actor, tenantID)
	if err != nil {
		return DeliveryPage{}, err
	}
	result, err := s.repository.ListDeliveries(ctx, ListDeliveriesParams{
		Human: human, After: page.After, Limit: int32(page.Limit), Statuses: statuses,
	})
	if err != nil {
		return DeliveryPage{}, mapRepositoryError(err)
	}
	if !validDeliveryPage(result, tenantID, page.Limit) {
		return DeliveryPage{}, ErrUnavailable
	}
	return result, nil
}

func (s *Service) GetDelivery(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, deliveryID uuid.UUID,
) (Delivery, error) {
	if !validUUIDv7(deliveryID) {
		return Delivery{}, ErrInvalidInput
	}
	human, err := s.requireTenant(ctx, actor, tenantID)
	if err != nil {
		return Delivery{}, err
	}
	result, err := s.repository.GetDelivery(ctx, GetDeliveryParams{Human: human, DeliveryID: deliveryID})
	if err != nil {
		return Delivery{}, mapRepositoryError(err)
	}
	if result.ID != deliveryID || !validDelivery(result, tenantID, true) {
		return Delivery{}, ErrUnavailable
	}
	return result, nil
}

func (s *Service) RetryDelivery(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, sourceDeliveryID uuid.UUID,
	input ManualRetryInput,
) (Delivery, error) {
	reason, reasonOK := normalizedText(input.Reason, 1, 1_000, false)
	if !validUUIDv7(sourceDeliveryID) || input.ExpectedAttempt < 1 || input.ExpectedAttempt > 100 || !reasonOK ||
		!validCommonMutation(input.IdempotencyKey, input.Audit) {
		return Delivery{}, ErrInvalidInput
	}
	human, err := s.requireTenant(ctx, actor, tenantID)
	if err != nil {
		return Delivery{}, err
	}
	mutation, err := s.tenantMutation(human, input.IdempotencyKey, input.Audit)
	if err != nil {
		return Delivery{}, err
	}
	deliveryID, err := s.nextID()
	if err != nil {
		return Delivery{}, err
	}
	result, err := s.repository.CreateManualRetry(ctx, CreateManualRetryParams{
		Mutation: mutation, SourceDeliveryID: sourceDeliveryID, DeliveryID: deliveryID,
		ExpectedAttempt:                input.ExpectedAttempt,
		AcknowledgeUncertainSubmission: input.AcknowledgeUncertainSubmission,
		Reason:                         reason,
	})
	if err != nil {
		return Delivery{}, mapRepositoryError(err)
	}
	value := result.Value
	if !validDelivery(value, tenantID, false) || value.ParentDeliveryID == nil || *value.ParentDeliveryID != sourceDeliveryID ||
		!result.Replayed && value.ID != deliveryID {
		return Delivery{}, ErrUnavailable
	}
	return value, nil
}

func normalizeDeliveryStatuses(input []DeliveryStatus) ([]DeliveryStatus, error) {
	if len(input) > 8 {
		return nil, ErrInvalidInput
	}
	statuses := append([]DeliveryStatus(nil), input...)
	slices.Sort(statuses)
	for index, status := range statuses {
		if !validDeliveryStatus(status) || index > 0 && statuses[index-1] == status {
			return nil, ErrInvalidInput
		}
	}
	return statuses, nil
}

func validDeliveryPage(page DeliveryPage, tenantID uuid.UUID, limit int) bool {
	if len(page.Items) > limit || !validNextCursor(page.NextCursor, len(page.Items), limit) {
		return false
	}
	seen := make(map[uuid.UUID]struct{}, len(page.Items))
	for _, item := range page.Items {
		if !validDelivery(item, tenantID, false) {
			return false
		}
		if _, duplicate := seen[item.ID]; duplicate {
			return false
		}
		seen[item.ID] = struct{}{}
	}
	return true
}
