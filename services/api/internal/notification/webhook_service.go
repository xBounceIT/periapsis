package notification

import (
	"context"
	"strings"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

func (s *Service) ListWebhooks(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input PageInput,
) (WebhookPage, error) {
	page, err := normalizePage(input)
	if err != nil {
		return WebhookPage{}, err
	}
	human, err := s.requireTenant(ctx, actor, tenantID)
	if err != nil {
		return WebhookPage{}, err
	}
	result, err := s.repository.ListWebhooks(ctx, ListWebhooksParams{
		Human: human, After: page.After, Limit: int32(page.Limit),
	})
	if err != nil {
		return WebhookPage{}, mapRepositoryError(err)
	}
	if !validWebhookPage(result, tenantID, page.Limit) {
		return WebhookPage{}, ErrUnavailable
	}
	return result, nil
}

func (s *Service) GetWebhook(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, webhookID uuid.UUID,
) (WebhookConfiguration, error) {
	if !validUUIDv7(webhookID) {
		return WebhookConfiguration{}, ErrInvalidInput
	}
	human, err := s.requireTenant(ctx, actor, tenantID)
	if err != nil {
		return WebhookConfiguration{}, err
	}
	result, err := s.repository.GetWebhook(ctx, GetWebhookParams{Human: human, WebhookID: webhookID})
	if err != nil {
		return WebhookConfiguration{}, mapRepositoryError(err)
	}
	if result.ID != webhookID || !validWebhook(result, tenantID) {
		return WebhookConfiguration{}, ErrUnavailable
	}
	return result, nil
}

func (s *Service) CreateWebhook(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input WebhookWriteInput,
) (WebhookConfiguration, error) {
	normalized, err := normalizeWebhookWrite(input, s.allowPlainLocal)
	if err != nil || normalized.ExpectedVersion != nil || normalized.SigningKey == nil ||
		!validCommonMutation(input.IdempotencyKey, input.Audit) {
		return WebhookConfiguration{}, ErrInvalidInput
	}
	human, err := s.requireTenant(ctx, actor, tenantID)
	if err != nil {
		return WebhookConfiguration{}, err
	}
	write, err := s.protectWebhookWrite(tenantID, normalized, true)
	if err != nil {
		return WebhookConfiguration{}, err
	}
	defer clearProtectedSecret(write.SigningKey)
	mutation, err := s.tenantMutation(human, normalized.IdempotencyKey, normalized.Audit)
	if err != nil {
		return WebhookConfiguration{}, err
	}
	webhookID, err := s.nextID()
	if err != nil {
		return WebhookConfiguration{}, err
	}
	result, err := s.repository.CreateWebhook(ctx, CreateWebhookParams{
		Mutation: mutation, WebhookID: webhookID, Write: write,
	})
	if err != nil {
		return WebhookConfiguration{}, mapRepositoryError(err)
	}
	if !validWebhookCreateResult(result, tenantID, webhookID, actor.UserID) {
		return WebhookConfiguration{}, ErrUnavailable
	}
	return result.Value, nil
}

func (s *Service) VersionWebhook(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, webhookID uuid.UUID,
	input WebhookWriteInput,
) (WebhookConfiguration, error) {
	if !validUUIDv7(webhookID) {
		return WebhookConfiguration{}, ErrInvalidInput
	}
	normalized, err := normalizeWebhookWrite(input, s.allowPlainLocal)
	if err != nil {
		return WebhookConfiguration{}, err
	}
	if normalized.ExpectedVersion == nil {
		return WebhookConfiguration{}, ErrPreconditionRequired
	}
	expected := *normalized.ExpectedVersion
	if expected < 1 || expected >= maximumResourceVersion || !validCommonMutation(input.IdempotencyKey, input.Audit) {
		return WebhookConfiguration{}, ErrInvalidInput
	}
	human, err := s.requireTenant(ctx, actor, tenantID)
	if err != nil {
		return WebhookConfiguration{}, err
	}
	write, err := s.protectWebhookWrite(tenantID, normalized, false)
	if err != nil {
		return WebhookConfiguration{}, err
	}
	defer clearProtectedSecret(write.SigningKey)
	mutation, err := s.tenantMutation(human, normalized.IdempotencyKey, normalized.Audit)
	if err != nil {
		return WebhookConfiguration{}, err
	}
	result, err := s.repository.VersionWebhook(ctx, VersionWebhookParams{
		Mutation: mutation, WebhookID: webhookID, ExpectedVersion: expected, Write: write,
	})
	if err != nil {
		return WebhookConfiguration{}, mapRepositoryError(err)
	}
	if !validWebhookVersionResult(result, tenantID, webhookID, expected+1, actor.UserID) {
		return WebhookConfiguration{}, ErrUnavailable
	}
	return result.Value, nil
}

func (s *Service) TestWebhook(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, webhookID uuid.UUID,
	input WebhookTestInput,
) (Delivery, error) {
	reason, reasonOK := normalizedText(input.Reason, 1, 1_000, false)
	context, contextErr := normalizeContext(input.Context)
	if !validUUIDv7(webhookID) || input.ConfigurationVersion < 1 || input.ConfigurationVersion > maximumResourceVersion ||
		!reasonOK || contextErr != nil || !validCommonMutation(input.IdempotencyKey, input.Audit) {
		return Delivery{}, ErrInvalidInput
	}
	if _, supported := eventTypes[input.EventType]; !supported {
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
	result, err := s.repository.EnqueueWebhookTest(ctx, EnqueueWebhookTestParams{
		Mutation: mutation, WebhookID: webhookID, ConfigurationVersion: input.ConfigurationVersion,
		DeliveryID: deliveryID, EventType: input.EventType, Context: context, Reason: reason,
	})
	if err != nil {
		return Delivery{}, mapRepositoryError(err)
	}
	value := result.Value
	if !validDelivery(value, tenantID, false) || value.Channel != ChannelWebhook ||
		value.WebhookConfigurationID == nil || *value.WebhookConfigurationID != webhookID ||
		value.WebhookConfigurationVersion == nil || *value.WebhookConfigurationVersion != input.ConfigurationVersion ||
		!result.Replayed && value.ID != deliveryID {
		return Delivery{}, ErrUnavailable
	}
	return value, nil
}

func (s *Service) protectWebhookWrite(tenantID uuid.UUID, input WebhookWriteInput, creating bool) (WebhookPersistedWrite, error) {
	write := WebhookPersistedWrite{
		Name: input.Name, EndpointURL: input.EndpointURL, EventTypes: append([]EventType(nil), input.EventTypes...),
		AllowPlainLocalExemption: s.allowPlainLocal && strings.HasPrefix(input.EndpointURL, "http://"),
		Audience:                 input.Audience, TimeoutMS: input.TimeoutMS, Enabled: input.Enabled,
	}
	if input.SigningKey == nil {
		if creating {
			return WebhookPersistedWrite{}, ErrInvalidInput
		}
		write.RetainSigningKey = true
		return write, nil
	}
	secret, err := s.protectSecret(&tenantID, SecretKindWebhookSigningKey, *input.SigningKey)
	if err != nil {
		return WebhookPersistedWrite{}, err
	}
	write.SigningKey = &secret
	return write, nil
}

func validWebhookPage(page WebhookPage, tenantID uuid.UUID, limit int) bool {
	if len(page.Items) > limit || !validNextCursor(page.NextCursor, len(page.Items), limit) {
		return false
	}
	seen := make(map[uuid.UUID]struct{}, len(page.Items))
	for _, item := range page.Items {
		if !validWebhook(item, tenantID) {
			return false
		}
		if _, duplicate := seen[item.ID]; duplicate {
			return false
		}
		seen[item.ID] = struct{}{}
	}
	return true
}

func validWebhookCreateResult(result IdempotentResult[WebhookConfiguration], tenantID, freshID, actorID uuid.UUID) bool {
	value := result.Value
	if !validWebhook(value, tenantID) {
		return false
	}
	if result.Replayed {
		return true
	}
	return value.ID == freshID && value.Version == 1 && value.CreatedBy == actorID
}

func validWebhookVersionResult(
	result IdempotentResult[WebhookConfiguration],
	tenantID, webhookID uuid.UUID,
	freshVersion int64,
	actorID uuid.UUID,
) bool {
	value := result.Value
	if !validWebhook(value, tenantID) || value.ID != webhookID {
		return false
	}
	if result.Replayed {
		return true
	}
	return value.Version == freshVersion && value.CreatedBy == actorID
}
