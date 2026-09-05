package notification

import (
	"context"
	"strings"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

func (s *Service) ListTemplates(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input PageInput,
) (TemplatePage, error) {
	page, err := normalizePage(input)
	if err != nil {
		return TemplatePage{}, err
	}
	human, err := s.requireTenant(ctx, actor, tenantID)
	if err != nil {
		return TemplatePage{}, err
	}
	result, err := s.repository.ListTemplates(ctx, ListTemplatesParams{
		Human: human, After: page.After, Limit: int32(page.Limit),
	})
	if err != nil {
		return TemplatePage{}, mapRepositoryError(err)
	}
	if !validTemplatePage(result, tenantID, page.Limit) {
		return TemplatePage{}, ErrUnavailable
	}
	return result, nil
}

func (s *Service) GetTemplate(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, templateID uuid.UUID,
	version *int64,
) (Template, error) {
	if !validUUIDv7(templateID) || !validOptionalVersion(version) {
		return Template{}, ErrInvalidInput
	}
	human, err := s.requireTenant(ctx, actor, tenantID)
	if err != nil {
		return Template{}, err
	}
	result, err := s.repository.GetTemplate(ctx, GetTemplateParams{
		Human: human, TemplateID: templateID, Version: cloneInt64(version),
	})
	if err != nil {
		return Template{}, mapRepositoryError(err)
	}
	if result.ID != templateID || version != nil && result.Version != *version || !validTemplate(result, tenantID) {
		return Template{}, ErrUnavailable
	}
	return result, nil
}

func (s *Service) CreateTemplate(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input TemplateWriteInput,
) (Template, error) {
	fields, err := normalizeTemplateFields(input.Fields)
	if err != nil || input.ExpectedVersion != nil || !validCommonMutation(input.IdempotencyKey, input.Audit) {
		return Template{}, ErrInvalidInput
	}
	human, err := s.requireTenant(ctx, actor, tenantID)
	if err != nil {
		return Template{}, err
	}
	mutation, err := s.tenantMutation(human, input.IdempotencyKey, input.Audit)
	if err != nil {
		return Template{}, err
	}
	templateID, err := s.nextID()
	if err != nil {
		return Template{}, err
	}
	result, err := s.repository.CreateTemplate(ctx, CreateTemplateParams{
		Mutation: mutation, TemplateID: templateID, Fields: fields,
	})
	if err != nil {
		return Template{}, mapRepositoryError(err)
	}
	if !validTemplateCreateResult(result, tenantID, templateID, actor.UserID) {
		return Template{}, ErrUnavailable
	}
	return result.Value, nil
}

func (s *Service) VersionTemplate(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, templateID uuid.UUID,
	input TemplateWriteInput,
) (Template, error) {
	if !validUUIDv7(templateID) {
		return Template{}, ErrInvalidInput
	}
	fields, err := normalizeTemplateFields(input.Fields)
	if err != nil {
		return Template{}, err
	}
	if input.ExpectedVersion == nil {
		return Template{}, ErrPreconditionRequired
	}
	expected := *input.ExpectedVersion
	if expected < 1 || expected >= maximumResourceVersion || !validCommonMutation(input.IdempotencyKey, input.Audit) {
		return Template{}, ErrInvalidInput
	}
	human, err := s.requireTenant(ctx, actor, tenantID)
	if err != nil {
		return Template{}, err
	}
	mutation, err := s.tenantMutation(human, input.IdempotencyKey, input.Audit)
	if err != nil {
		return Template{}, err
	}
	result, err := s.repository.VersionTemplate(ctx, VersionTemplateParams{
		Mutation: mutation, TemplateID: templateID, ExpectedVersion: expected, Fields: fields,
	})
	if err != nil {
		return Template{}, mapRepositoryError(err)
	}
	if !validTemplateVersionResult(result, tenantID, templateID, expected+1, actor.UserID) {
		return Template{}, ErrUnavailable
	}
	return result.Value, nil
}

func (s *Service) PreviewTemplate(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	audience Audience,
	fields TemplateFields,
	inputContext map[string]any,
) (Preview, error) {
	normalizedFields, err := normalizeTemplateFields(fields)
	if err != nil {
		return Preview{}, err
	}
	context, err := normalizeContext(inputContext)
	if err != nil {
		return Preview{}, err
	}
	context, err = contextForAudience(audience, context)
	if err != nil {
		return Preview{}, err
	}
	if _, err := s.requireTenant(ctx, actor, tenantID); err != nil {
		return Preview{}, err
	}
	result, err := s.previewer.Preview(ctx, tenantID, audience, normalizedFields, context)
	if err != nil {
		return Preview{}, mapRepositoryError(err)
	}
	if !validPreview(result) {
		return Preview{}, ErrUnavailable
	}
	return result, nil
}

func (s *Service) DuplicateTemplate(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, sourceTemplateID uuid.UUID,
	input TemplateDuplicateInput,
) (Template, error) {
	key := strings.TrimSpace(input.Key)
	name, nameOK := normalizedText(input.Name, 1, 160, false)
	if !validUUIDv7(sourceTemplateID) || input.SourceVersion < 1 || input.SourceVersion > maximumResourceVersion ||
		!keyPattern.MatchString(key) || !nameOK || !validCommonMutation(input.IdempotencyKey, input.Audit) {
		return Template{}, ErrInvalidInput
	}
	human, err := s.requireTenant(ctx, actor, tenantID)
	if err != nil {
		return Template{}, err
	}
	mutation, err := s.tenantMutation(human, input.IdempotencyKey, input.Audit)
	if err != nil {
		return Template{}, err
	}
	templateID, err := s.nextID()
	if err != nil {
		return Template{}, err
	}
	result, err := s.repository.DuplicateTemplate(ctx, DuplicateTemplateParams{
		Mutation: mutation, SourceTemplateID: sourceTemplateID, SourceVersion: input.SourceVersion,
		TemplateID: templateID, Key: key, Name: name,
	})
	if err != nil {
		return Template{}, mapRepositoryError(err)
	}
	if !validTemplateCreateResult(result, tenantID, templateID, actor.UserID) || result.Value.Key != key {
		return Template{}, ErrUnavailable
	}
	return result.Value, nil
}

func (s *Service) RollbackTemplate(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, templateID uuid.UUID,
	input TemplateRollbackInput,
) (Template, error) {
	reason, reasonOK := normalizedText(input.Reason, 1, 1_000, false)
	if !validUUIDv7(templateID) || input.SourceVersion < 1 || input.SourceVersion > maximumResourceVersion || !reasonOK ||
		!validCommonMutation(input.IdempotencyKey, input.Audit) {
		return Template{}, ErrInvalidInput
	}
	if input.ExpectedVersion == nil {
		return Template{}, ErrPreconditionRequired
	}
	expected := *input.ExpectedVersion
	if expected < 1 || expected >= maximumResourceVersion {
		return Template{}, ErrInvalidInput
	}
	human, err := s.requireTenant(ctx, actor, tenantID)
	if err != nil {
		return Template{}, err
	}
	mutation, err := s.tenantMutation(human, input.IdempotencyKey, input.Audit)
	if err != nil {
		return Template{}, err
	}
	result, err := s.repository.RollbackTemplate(ctx, RollbackTemplateParams{
		Mutation: mutation, TemplateID: templateID, SourceVersion: input.SourceVersion,
		ExpectedVersion: expected, Reason: reason,
	})
	if err != nil {
		return Template{}, mapRepositoryError(err)
	}
	if !validTemplateVersionResult(result, tenantID, templateID, expected+1, actor.UserID) {
		return Template{}, ErrUnavailable
	}
	return result.Value, nil
}

func (s *Service) TestSendTemplate(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, templateID uuid.UUID,
	input TemplateTestSendInput,
) (Delivery, error) {
	recipient, recipientOK := canonicalEmail(input.Recipient)
	reason, reasonOK := normalizedText(input.Reason, 1, 1_000, false)
	context, contextErr := normalizeContext(input.Context)
	if !validUUIDv7(templateID) || input.Version < 1 || input.Version > maximumResourceVersion || !recipientOK || !reasonOK ||
		contextErr != nil || !validCommonMutation(input.IdempotencyKey, input.Audit) {
		return Delivery{}, ErrInvalidInput
	}
	context, err := contextForAudience(input.Audience, context)
	if err != nil {
		return Delivery{}, err
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
	result, err := s.repository.EnqueueTemplateTest(ctx, EnqueueTemplateTestParams{
		Mutation: mutation, TemplateID: templateID, Version: input.Version, DeliveryID: deliveryID,
		Recipient: recipient, Audience: input.Audience, Context: context, Reason: reason,
	})
	if err != nil {
		return Delivery{}, mapRepositoryError(err)
	}
	value := result.Value
	if !validDelivery(value, tenantID, false) || value.Channel != ChannelEmail || value.TemplateID == nil ||
		*value.TemplateID != templateID || value.TemplateVersion == nil || *value.TemplateVersion != input.Version ||
		!result.Replayed && value.ID != deliveryID {
		return Delivery{}, ErrUnavailable
	}
	return value, nil
}

func contextForAudience(audience Audience, context map[string]any) (map[string]any, error) {
	switch audience {
	case AudienceOperator:
		return context, nil
	case AudienceCustomer:
		customer, ok := context["customer"].(map[string]any)
		if !ok {
			return nil, ErrInvalidInput
		}
		return normalizeContext(customer)
	default:
		return nil, ErrInvalidInput
	}
}

func validPreview(value Preview) bool {
	return validBody(value.Subject, 0, 998) && validBody(value.HTML, 0, 1_048_576) &&
		validBody(value.PlainText, 0, 1_048_576)
}

func validTemplatePage(page TemplatePage, tenantID uuid.UUID, limit int) bool {
	if len(page.Items) > limit || !validNextCursor(page.NextCursor, len(page.Items), limit) {
		return false
	}
	seen := make(map[uuid.UUID]struct{}, len(page.Items))
	for _, item := range page.Items {
		if !validTemplate(item, tenantID) {
			return false
		}
		if _, duplicate := seen[item.ID]; duplicate {
			return false
		}
		seen[item.ID] = struct{}{}
	}
	return true
}

func validTemplateCreateResult(result IdempotentResult[Template], tenantID, freshID, actorID uuid.UUID) bool {
	value := result.Value
	if !validTemplate(value, tenantID) {
		return false
	}
	if result.Replayed {
		return true
	}
	return value.ID == freshID && value.Version == 1 && value.CreatedBy == actorID
}

func validTemplateVersionResult(result IdempotentResult[Template], tenantID, templateID uuid.UUID, freshVersion int64, actorID uuid.UUID) bool {
	value := result.Value
	if !validTemplate(value, tenantID) || value.ID != templateID {
		return false
	}
	if result.Replayed {
		return true
	}
	return value.Version == freshVersion && value.CreatedBy == actorID
}
