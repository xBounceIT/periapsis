package httpserver

import (
	"context"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/notification"
)

// transportNotificationStub lets unrelated HTTP adapter tests opt into the
// notification boundary without weakening the production constructor. Tests
// for a notification operation embed this type and replace only that method.
type transportNotificationStub struct{}

func (*transportNotificationStub) ListRules(context.Context, authorization.Actor, uuid.UUID, notification.PageInput) (notification.RulePage, error) {
	return notification.RulePage{}, notification.ErrUnavailable
}
func (*transportNotificationStub) GetRule(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (notification.Rule, error) {
	return notification.Rule{}, notification.ErrUnavailable
}
func (*transportNotificationStub) CreateRule(context.Context, authorization.Actor, uuid.UUID, notification.RuleWriteInput) (notification.Rule, error) {
	return notification.Rule{}, notification.ErrUnavailable
}
func (*transportNotificationStub) VersionRule(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, notification.RuleWriteInput) (notification.Rule, error) {
	return notification.Rule{}, notification.ErrUnavailable
}
func (*transportNotificationStub) ListTemplates(context.Context, authorization.Actor, uuid.UUID, notification.PageInput) (notification.TemplatePage, error) {
	return notification.TemplatePage{}, notification.ErrUnavailable
}
func (*transportNotificationStub) GetTemplate(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, *int64) (notification.Template, error) {
	return notification.Template{}, notification.ErrUnavailable
}
func (*transportNotificationStub) CreateTemplate(context.Context, authorization.Actor, uuid.UUID, notification.TemplateWriteInput) (notification.Template, error) {
	return notification.Template{}, notification.ErrUnavailable
}
func (*transportNotificationStub) VersionTemplate(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, notification.TemplateWriteInput) (notification.Template, error) {
	return notification.Template{}, notification.ErrUnavailable
}
func (*transportNotificationStub) PreviewTemplate(context.Context, authorization.Actor, uuid.UUID, notification.Audience, notification.TemplateFields, map[string]any) (notification.Preview, error) {
	return notification.Preview{}, notification.ErrUnavailable
}
func (*transportNotificationStub) DuplicateTemplate(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, notification.TemplateDuplicateInput) (notification.Template, error) {
	return notification.Template{}, notification.ErrUnavailable
}
func (*transportNotificationStub) RollbackTemplate(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, notification.TemplateRollbackInput) (notification.Template, error) {
	return notification.Template{}, notification.ErrUnavailable
}
func (*transportNotificationStub) TestSendTemplate(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, notification.TemplateTestSendInput) (notification.Delivery, error) {
	return notification.Delivery{}, notification.ErrUnavailable
}
func (*transportNotificationStub) GetTenantSMTP(context.Context, authorization.Actor, uuid.UUID) (notification.SMTPConfiguration, error) {
	return notification.SMTPConfiguration{}, notification.ErrUnavailable
}
func (*transportNotificationStub) VersionTenantSMTP(context.Context, authorization.Actor, uuid.UUID, notification.SMTPWriteInput) (notification.SMTPConfiguration, error) {
	return notification.SMTPConfiguration{}, notification.ErrUnavailable
}
func (*transportNotificationStub) TestTenantSMTP(context.Context, authorization.Actor, uuid.UUID, notification.SMTPTestInput) (notification.SMTPHealth, error) {
	return notification.SMTPHealth{}, notification.ErrUnavailable
}
func (*transportNotificationStub) GetPlatformSMTP(context.Context, authentication.Session) (notification.SMTPConfiguration, error) {
	return notification.SMTPConfiguration{}, notification.ErrUnavailable
}
func (*transportNotificationStub) VersionPlatformSMTP(context.Context, authentication.Session, notification.SMTPWriteInput) (notification.SMTPConfiguration, error) {
	return notification.SMTPConfiguration{}, notification.ErrUnavailable
}
func (*transportNotificationStub) TestPlatformSMTP(context.Context, authentication.Session, notification.SMTPTestInput) (notification.SMTPHealth, error) {
	return notification.SMTPHealth{}, notification.ErrUnavailable
}
func (*transportNotificationStub) ListDeliveries(context.Context, authorization.Actor, uuid.UUID, notification.DeliveryListInput) (notification.DeliveryPage, error) {
	return notification.DeliveryPage{}, notification.ErrUnavailable
}
func (*transportNotificationStub) GetDelivery(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (notification.Delivery, error) {
	return notification.Delivery{}, notification.ErrUnavailable
}
func (*transportNotificationStub) RetryDelivery(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, notification.ManualRetryInput) (notification.Delivery, error) {
	return notification.Delivery{}, notification.ErrUnavailable
}
func (*transportNotificationStub) ListWebhooks(context.Context, authorization.Actor, uuid.UUID, notification.PageInput) (notification.WebhookPage, error) {
	return notification.WebhookPage{}, notification.ErrUnavailable
}
func (*transportNotificationStub) GetWebhook(context.Context, authorization.Actor, uuid.UUID, uuid.UUID) (notification.WebhookConfiguration, error) {
	return notification.WebhookConfiguration{}, notification.ErrUnavailable
}
func (*transportNotificationStub) CreateWebhook(context.Context, authorization.Actor, uuid.UUID, notification.WebhookWriteInput) (notification.WebhookConfiguration, error) {
	return notification.WebhookConfiguration{}, notification.ErrUnavailable
}
func (*transportNotificationStub) VersionWebhook(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, notification.WebhookWriteInput) (notification.WebhookConfiguration, error) {
	return notification.WebhookConfiguration{}, notification.ErrUnavailable
}
func (*transportNotificationStub) TestWebhook(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, notification.WebhookTestInput) (notification.Delivery, error) {
	return notification.Delivery{}, notification.ErrUnavailable
}
