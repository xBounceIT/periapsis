package httpserver

import (
	"context"
	"reflect"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/webhookurlpolicy"
)

// WebhookURLPolicyService is the session-only administration boundary for the
// tenant's immutable outbound-webhook URL policy.
type WebhookURLPolicyService interface {
	Get(context.Context, authentication.Session, uuid.UUID) (webhookurlpolicy.Policy, error)
	Publish(context.Context, authentication.Session, uuid.UUID, webhookurlpolicy.PublishInput) (webhookurlpolicy.PublishResult, error)
}

type unavailableWebhookURLPolicyService struct{}

func (unavailableWebhookURLPolicyService) Get(
	context.Context,
	authentication.Session,
	uuid.UUID,
) (webhookurlpolicy.Policy, error) {
	return webhookurlpolicy.Policy{}, webhookurlpolicy.ErrUnavailable
}

func (unavailableWebhookURLPolicyService) Publish(
	context.Context,
	authentication.Session,
	uuid.UUID,
	webhookurlpolicy.PublishInput,
) (webhookurlpolicy.PublishResult, error) {
	return webhookurlpolicy.PublishResult{}, webhookurlpolicy.ErrUnavailable
}

func webhookURLPolicyServiceIsNil(service WebhookURLPolicyService) bool {
	if service == nil {
		return true
	}
	value := reflect.ValueOf(service)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

var _ WebhookURLPolicyService = unavailableWebhookURLPolicyService{}
