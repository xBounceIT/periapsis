package notification

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type PlatformActor struct {
	UserID               uuid.UUID
	SessionID            uuid.UUID
	AuthenticationMethod string
}

type IdempotentResult[T any] struct {
	Value    T
	Replayed bool
}

type ProtectedSecret struct {
	ID       uuid.UUID
	Version  int64
	Kind     SecretKind
	Envelope SecretEnvelope
}

type SMTPPersistedWrite struct {
	Name                         string
	Host                         string
	Port                         int
	Security                     SMTPSecurity
	Username                     *string
	Password                     *ProtectedSecret
	RetainPassword               bool
	RemovePassword               bool
	FromName                     string
	FromEmail                    string
	ReplyToEmail                 *string
	TimeoutMS                    int
	MaximumConnections           int
	MaximumMessagesPerConnection int
	RateLimitPerSecond           int
	DKIMDomainName               *string
	DKIMSelector                 *string
	DKIMPrivateKey               *ProtectedSecret
	RetainDKIMPrivateKey         bool
	RemoveDKIM                   bool
	Enabled                      bool
}

type WebhookPersistedWrite struct {
	Name                     string
	EndpointURL              string
	AllowPlainLocalExemption bool
	EventTypes               []EventType
	Audience                 Audience
	SigningKey               *ProtectedSecret
	RetainSigningKey         bool
	TimeoutMS                int
	Enabled                  bool
}

// Repository is the only public-API persistence boundary for notification
// administration. Every implementation must re-resolve authority and perform
// resource mutation, immutable version insertion, idempotency binding, secret
// pin updates, audit append, and any outbox/test-job insertion atomically.
// Tenant methods constrain tenant_id in every predicate and use forced-RLS,
// bounded SECURITY DEFINER functions. Exact replays return the current safe
// representation without duplicating history, audit, or jobs.
type Repository interface {
	ResolveAuthority(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error)

	ListRules(context.Context, ListRulesParams) (RulePage, error)
	GetRule(context.Context, GetRuleParams) (Rule, error)
	CreateRule(context.Context, CreateRuleParams) (IdempotentResult[Rule], error)
	VersionRule(context.Context, VersionRuleParams) (IdempotentResult[Rule], error)

	ListTemplates(context.Context, ListTemplatesParams) (TemplatePage, error)
	GetTemplate(context.Context, GetTemplateParams) (Template, error)
	CreateTemplate(context.Context, CreateTemplateParams) (IdempotentResult[Template], error)
	VersionTemplate(context.Context, VersionTemplateParams) (IdempotentResult[Template], error)
	DuplicateTemplate(context.Context, DuplicateTemplateParams) (IdempotentResult[Template], error)
	RollbackTemplate(context.Context, RollbackTemplateParams) (IdempotentResult[Template], error)
	EnqueueTemplateTest(context.Context, EnqueueTemplateTestParams) (IdempotentResult[Delivery], error)

	GetTenantSMTP(context.Context, GetTenantSMTPParams) (SMTPConfiguration, error)
	VersionTenantSMTP(context.Context, VersionTenantSMTPParams) (IdempotentResult[SMTPConfiguration], error)
	TestTenantSMTP(context.Context, TestTenantSMTPParams) (IdempotentResult[SMTPProbePreflight], error)
	GetPlatformSMTP(context.Context, GetPlatformSMTPParams) (SMTPConfiguration, error)
	VersionPlatformSMTP(context.Context, VersionPlatformSMTPParams) (IdempotentResult[SMTPConfiguration], error)
	TestPlatformSMTP(context.Context, TestPlatformSMTPParams) (IdempotentResult[SMTPProbePreflight], error)

	ListDeliveries(context.Context, ListDeliveriesParams) (DeliveryPage, error)
	GetDelivery(context.Context, GetDeliveryParams) (Delivery, error)
	CreateManualRetry(context.Context, CreateManualRetryParams) (IdempotentResult[Delivery], error)

	ListWebhooks(context.Context, ListWebhooksParams) (WebhookPage, error)
	GetWebhook(context.Context, GetWebhookParams) (WebhookConfiguration, error)
	CreateWebhook(context.Context, CreateWebhookParams) (IdempotentResult[WebhookConfiguration], error)
	VersionWebhook(context.Context, VersionWebhookParams) (IdempotentResult[WebhookConfiguration], error)
	EnqueueWebhookTest(context.Context, EnqueueWebhookTestParams) (IdempotentResult[Delivery], error)
}

type HumanParams struct {
	Actor        authorization.Actor
	MembershipID uuid.UUID
	TenantID     uuid.UUID
}

type MutationParams struct {
	Human          HumanParams
	Audit          authorization.AuditContext
	OccurredAt     time.Time
	IdempotencyKey string
}

type ListRulesParams struct {
	Human HumanParams
	After *string
	Limit int32
}

type GetRuleParams struct {
	Human  HumanParams
	RuleID uuid.UUID
}

type CreateRuleParams struct {
	Mutation MutationParams
	RuleID   uuid.UUID
	Fields   RuleFields
}

type VersionRuleParams struct {
	Mutation        MutationParams
	RuleID          uuid.UUID
	ExpectedVersion int64
	Fields          RuleFields
}

type ListTemplatesParams struct {
	Human HumanParams
	After *string
	Limit int32
}

type GetTemplateParams struct {
	Human      HumanParams
	TemplateID uuid.UUID
	Version    *int64
}

type CreateTemplateParams struct {
	Mutation   MutationParams
	TemplateID uuid.UUID
	Fields     TemplateFields
}

type VersionTemplateParams struct {
	Mutation        MutationParams
	TemplateID      uuid.UUID
	ExpectedVersion int64
	Fields          TemplateFields
}

type DuplicateTemplateParams struct {
	Mutation         MutationParams
	SourceTemplateID uuid.UUID
	SourceVersion    int64
	TemplateID       uuid.UUID
	Key              string
	Name             string
}

type RollbackTemplateParams struct {
	Mutation        MutationParams
	TemplateID      uuid.UUID
	SourceVersion   int64
	ExpectedVersion int64
	Reason          string
}

type EnqueueTemplateTestParams struct {
	Mutation   MutationParams
	TemplateID uuid.UUID
	Version    int64
	DeliveryID uuid.UUID
	Recipient  string
	Audience   Audience
	Context    map[string]any
	Reason     string
}

type GetTenantSMTPParams struct{ Human HumanParams }

type VersionTenantSMTPParams struct {
	Mutation        MutationParams
	ConfigurationID uuid.UUID
	ExpectedVersion *int64
	Write           SMTPPersistedWrite
}

type TestTenantSMTPParams struct {
	Mutation             MutationParams
	ConfigurationVersion int64
	DeliveryID           *uuid.UUID
	Recipient            *string
	Reason               string
}

type GetPlatformSMTPParams struct{ Actor PlatformActor }

type PlatformMutationParams struct {
	Actor          PlatformActor
	Audit          authorization.AuditContext
	OccurredAt     time.Time
	IdempotencyKey string
}

type VersionPlatformSMTPParams struct {
	Mutation        PlatformMutationParams
	ConfigurationID uuid.UUID
	ExpectedVersion *int64
	Write           SMTPPersistedWrite
}

type TestPlatformSMTPParams struct {
	Mutation             PlatformMutationParams
	ConfigurationVersion int64
	DeliveryID           *uuid.UUID
	Recipient            *string
	Reason               string
}

type ListDeliveriesParams struct {
	Human    HumanParams
	After    *string
	Limit    int32
	Statuses []DeliveryStatus
}

type GetDeliveryParams struct {
	Human      HumanParams
	DeliveryID uuid.UUID
}

type CreateManualRetryParams struct {
	Mutation                       MutationParams
	SourceDeliveryID               uuid.UUID
	DeliveryID                     uuid.UUID
	ExpectedAttempt                int
	AcknowledgeUncertainSubmission bool
	Reason                         string
}

type ListWebhooksParams struct {
	Human HumanParams
	After *string
	Limit int32
}

type GetWebhookParams struct {
	Human     HumanParams
	WebhookID uuid.UUID
}

type CreateWebhookParams struct {
	Mutation  MutationParams
	WebhookID uuid.UUID
	Write     WebhookPersistedWrite
}

type VersionWebhookParams struct {
	Mutation        MutationParams
	WebhookID       uuid.UUID
	ExpectedVersion int64
	Write           WebhookPersistedWrite
}

type EnqueueWebhookTestParams struct {
	Mutation             MutationParams
	WebhookID            uuid.UUID
	ConfigurationVersion int64
	DeliveryID           uuid.UUID
	EventType            EventType
	Context              map[string]any
	Reason               string
}

type Previewer interface {
	Preview(context.Context, uuid.UUID, Audience, TemplateFields, map[string]any) (Preview, error)
}

type SMTPProber interface {
	ProbeSMTP(context.Context, SMTPProbeRequest) (SMTPProbeResult, error)
}

type NotifierClient interface {
	Previewer
	SMTPProber
}
