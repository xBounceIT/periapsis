package notification

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type EventType string

const (
	EventAlertCreated        EventType = "alert.created"
	EventAlertAssigned       EventType = "alert.assigned"
	EventAlertClaimed        EventType = "alert.claimed"
	EventAlertStatusChanged  EventType = "alert.status_changed"
	EventAlertEscalated      EventType = "alert.escalated"
	EventAlertWatcherAdded   EventType = "alert.watcher_added"
	EventAlertWatcherRemoved EventType = "alert.watcher_removed"
	EventCaseCreated         EventType = "case.created"
	EventCaseAssigned        EventType = "case.assigned"
	EventCaseClaimed         EventType = "case.claimed"
	EventCaseTransferred     EventType = "case.transferred"
	EventCaseStatusChanged   EventType = "case.status_changed"
	EventCaseWatcherAdded    EventType = "case.watcher_added"
	EventCaseWatcherRemoved  EventType = "case.watcher_removed"
	EventPublicCommentAdded  EventType = "comment.public_added"
	EventPrivateCommentAdded EventType = "comment.private_added"
	EventContactChanged      EventType = "contact.changed"
	EventSLAWarning          EventType = "sla.warning"
	EventSLABreached         EventType = "sla.breached"
	EventTaskAssigned        EventType = "task.assigned"
	EventEvidenceAdded       EventType = "evidence.added"
	EventCustomWebhook       EventType = "webhook.custom"
)

type ObjectType string

const (
	ObjectAlert    ObjectType = "alert"
	ObjectCase     ObjectType = "case"
	ObjectTask     ObjectType = "task"
	ObjectEvidence ObjectType = "evidence"
	ObjectContact  ObjectType = "contact"
)

type Audience string

const (
	AudienceOperator Audience = "operator"
	AudienceCustomer Audience = "customer"
)

type Channel string

const (
	ChannelEmail   Channel = "email"
	ChannelWebhook Channel = "webhook"
)

type ConditionKind string

const (
	ConditionAll       ConditionKind = "all"
	ConditionAny       ConditionKind = "any"
	ConditionNot       ConditionKind = "not"
	ConditionPredicate ConditionKind = "predicate"
)

type ConditionOperator string

const (
	OperatorEquals    ConditionOperator = "equals"
	OperatorNotEquals ConditionOperator = "not_equals"
	OperatorOneOf     ConditionOperator = "one_of"
	OperatorNoneOf    ConditionOperator = "none_of"
	OperatorContains  ConditionOperator = "contains"
	OperatorExists    ConditionOperator = "exists"
	OperatorNotExists ConditionOperator = "not_exists"
)

type Condition struct {
	Kind     ConditionKind     `json:"kind"`
	Children []Condition       `json:"children,omitempty"`
	Path     string            `json:"path,omitempty"`
	Operator ConditionOperator `json:"operator,omitempty"`
	Values   []json.RawMessage `json:"values,omitempty"`
}

type RecipientKind string

const (
	RecipientAssignee         RecipientKind = "assignee"
	RecipientPreviousAssignee RecipientKind = "previous_assignee"
	RecipientOperatorTeam     RecipientKind = "operator_team"
	RecipientWatcher          RecipientKind = "watcher"
	RecipientMentioned        RecipientKind = "mentioned"
	RecipientActor            RecipientKind = "actor"
	RecipientTenantAdmin      RecipientKind = "tenant_admin"
	RecipientPlatformGroup    RecipientKind = "platform_group"
	RecipientCustomerContacts RecipientKind = "customer_contacts"
	RecipientContactGroup     RecipientKind = "contact_group"
	RecipientContactTag       RecipientKind = "contact_tag"
	RecipientExplicitEmail    RecipientKind = "explicit_email"
	RecipientCustomEmailField RecipientKind = "custom_email_field"
)

type RecipientSelector struct {
	Kind       RecipientKind `json:"kind"`
	Value      *string       `json:"value,omitempty"`
	Authorized *bool         `json:"authorized,omitempty"`
	Audience   *Audience     `json:"audience,omitempty"`
}

type QuietHours struct {
	Timezone    string `json:"timezone"`
	StartMinute int    `json:"startMinute"`
	EndMinute   int    `json:"endMinute"`
	Weekdays    []int  `json:"weekdays,omitempty"`
}

type GroupingPolicy struct {
	Mode         string `json:"mode"`
	WindowMS     *int64 `json:"windowMs,omitempty"`
	MaximumItems *int   `json:"maximumItems,omitempty"`
}

type RetryPolicy struct {
	MaximumAttempts int     `json:"maximumAttempts"`
	InitialDelayMS  int64   `json:"initialDelayMs"`
	MaximumDelayMS  int64   `json:"maximumDelayMs"`
	Multiplier      float64 `json:"multiplier"`
	JitterPercent   int     `json:"jitterPercent"`
}

type RuleFields struct {
	Name                  string
	Description           string
	EventType             EventType
	ObjectType            ObjectType
	Condition             Condition
	Recipients            []RecipientSelector
	TemplateID            uuid.UUID
	TemplateVersion       int64
	Channel               Channel
	Priority              int
	DelayMS               int64
	QuietHours            *QuietHours
	DeduplicationWindowMS int64
	Grouping              GroupingPolicy
	Retry                 RetryPolicy
	Enabled               bool
	EffectiveFrom         time.Time
	EffectiveUntil        *time.Time
}

type Rule struct {
	RuleFields
	ID        uuid.UUID
	TenantID  uuid.UUID
	Version   int64
	CreatedAt time.Time
	CreatedBy uuid.UUID
}

type RulePage struct {
	Items      []Rule
	NextCursor *string
}

type TemplateFields struct {
	Key        string
	Name       string
	Language   string
	Subject    string
	HTML       string
	PlainText  *string
	CSS        *string
	SampleData map[string]any
}

type Template struct {
	TemplateFields
	ID           uuid.UUID
	TenantID     uuid.UUID
	Version      int64
	Placeholders []string
	CreatedAt    time.Time
	CreatedBy    uuid.UUID
}

type TemplatePage struct {
	Items      []Template
	NextCursor *string
}

type Preview struct {
	Subject   string
	HTML      string
	PlainText string
}

type SMTPSecurity string

const (
	SMTPTLS        SMTPSecurity = "tls"
	SMTPStartTLS   SMTPSecurity = "starttls"
	SMTPPlainLocal SMTPSecurity = "plain_local"
)

type DKIMConfiguration struct {
	DomainName           string
	Selector             string
	PrivateKeyConfigured bool
}

type SMTPConfigurationFields struct {
	Name                         string
	Host                         string
	Port                         int
	Security                     SMTPSecurity
	Username                     *string
	PasswordConfigured           bool
	FromName                     string
	FromEmail                    string
	ReplyToEmail                 *string
	TimeoutMS                    int
	MaximumConnections           int
	MaximumMessagesPerConnection int
	RateLimitPerSecond           int
	DKIM                         *DKIMConfiguration
	Enabled                      bool
}

type SMTPConfiguration struct {
	SMTPConfigurationFields
	ID                  uuid.UUID
	TenantID            *uuid.UUID
	InheritedFromGlobal bool
	Version             int64
	CreatedAt           time.Time
	CreatedBy           uuid.UUID
}

type DKIMWriteInput struct {
	DomainName string
	Selector   string
	PrivateKey *string
}

type SMTPWriteInput struct {
	Name                         string
	Host                         string
	Port                         int
	Security                     SMTPSecurity
	Username                     *string
	Password                     *string
	ClearPassword                bool
	FromName                     string
	FromEmail                    string
	ReplyToEmail                 *string
	TimeoutMS                    int
	MaximumConnections           int
	MaximumMessagesPerConnection int
	RateLimitPerSecond           int
	DKIM                         *DKIMWriteInput
	ClearDKIM                    bool
	Enabled                      bool
	ExpectedVersion              *int64
	IdempotencyKey               string
	Audit                        authorization.AuditContext
}

type SMTPHealthCheck struct {
	Kind       string
	Outcome    string
	ErrorClass *string
}

type SMTPHealth struct {
	ConfigurationID      uuid.UUID
	ConfigurationVersion int64
	Healthy              bool
	CheckedAt            time.Time
	Checks               []SMTPHealthCheck
	QueuedDeliveryID     *uuid.UUID
}

// SMTPProbePreflight is the safe database-authorized pin returned before the
// API asks the notifier to perform network I/O. It contains no host,
// destination, provider response, or secret material.
type SMTPProbePreflight struct {
	ConfigurationID      uuid.UUID
	ConfigurationVersion int64
	ConfigurationScope   SMTPConfigurationScope
	QueuedDeliveryID     *uuid.UUID
}

// SMTPProbeRequest and SMTPProbeResult form the fenced internal API-to-notifier
// protocol. The API accepts a result only when every identity field exactly
// matches the request and database-authorized preflight.
type SMTPProbeRequest struct {
	ProbeID              uuid.UUID
	FenceToken           uuid.UUID
	TenantID             *uuid.UUID
	ConfigurationScope   SMTPConfigurationScope
	ConfigurationID      uuid.UUID
	ConfigurationVersion int64
}

type SMTPProbeResult struct {
	SMTPProbeRequest
	Healthy   bool
	CheckedAt time.Time
	Checks    []SMTPHealthCheck
}

type SMTPTestInput struct {
	ConfigurationVersion int64
	Recipient            *string
	Reason               string
	IdempotencyKey       string
	Audit                authorization.AuditContext
}

type DeliveryStatus string

const (
	DeliveryQueued         DeliveryStatus = "queued"
	DeliveryLeased         DeliveryStatus = "leased"
	DeliveryReserved       DeliveryStatus = "reserved"
	DeliveryRetryScheduled DeliveryStatus = "retry_scheduled"
	DeliveryDelivered      DeliveryStatus = "delivered"
	DeliveryDeadLettered   DeliveryStatus = "dead_lettered"
)

type FailureClass string

const (
	FailureAuthentication      FailureClass = "authentication"
	FailureConnectivity        FailureClass = "connectivity"
	FailureRateLimited         FailureClass = "rate_limited"
	FailureRender              FailureClass = "render"
	FailureSecurity            FailureClass = "security"
	FailureTimeout             FailureClass = "timeout"
	FailureTLS                 FailureClass = "tls"
	FailureUnknown             FailureClass = "unknown"
	FailureSubmissionUncertain FailureClass = "submission_uncertain"
)

type ProviderReceipt struct {
	Provider      string
	ReceiptDigest string
	AcceptedCount *int
	RejectedCount *int
	ResponseClass *int
	StatusCode    *int
}

type DeliveryAttempt struct {
	Number          int
	StartedAt       time.Time
	CompletedAt     *time.Time
	Outcome         string
	FailureClass    *FailureClass
	ProviderReceipt *ProviderReceipt
}

type Delivery struct {
	ID                          uuid.UUID
	TenantID                    uuid.UUID
	EventID                     uuid.UUID
	ParentDeliveryID            *uuid.UUID
	RuleID                      *uuid.UUID
	RuleVersion                 *int64
	TemplateID                  *uuid.UUID
	TemplateVersion             *int64
	SMTPConfigurationID         *uuid.UUID
	SMTPConfigurationVersion    *int64
	SMTPConfigurationScope      *SMTPConfigurationScope
	WebhookConfigurationID      *uuid.UUID
	WebhookConfigurationVersion *int64
	WebhookSigningKeyVersion    *int64
	Channel                     Channel
	Audience                    Audience
	Status                      DeliveryStatus
	DestinationRedacted         string
	AttemptCount                int
	MaximumAttempts             int
	NextAttemptAt               *time.Time
	DeliveredAt                 *time.Time
	FailureAt                   *time.Time
	FailureClass                *FailureClass
	CreatedAt                   time.Time
	Attempts                    []DeliveryAttempt
}

type SMTPConfigurationScope string

const (
	SMTPConfigurationTenant   SMTPConfigurationScope = "tenant"
	SMTPConfigurationPlatform SMTPConfigurationScope = "platform"
)

type DeliveryPage struct {
	Items      []Delivery
	NextCursor *string
}

type DeliveryListInput struct {
	PageInput
	Statuses []DeliveryStatus
}

type ManualRetryInput struct {
	ExpectedAttempt                int
	AcknowledgeUncertainSubmission bool
	Reason                         string
	IdempotencyKey                 string
	Audit                          authorization.AuditContext
}

type WebhookFields struct {
	Name                 string
	EndpointURL          string
	EventTypes           []EventType
	Audience             Audience
	SigningKeyConfigured bool
	SigningKeyVersion    int64
	TimeoutMS            int
	Enabled              bool
}

type WebhookConfiguration struct {
	WebhookFields
	ID        uuid.UUID
	TenantID  uuid.UUID
	Version   int64
	CreatedAt time.Time
	CreatedBy uuid.UUID
}

type WebhookPage struct {
	Items      []WebhookConfiguration
	NextCursor *string
}

type WebhookWriteInput struct {
	Name            string
	EndpointURL     string
	EventTypes      []EventType
	Audience        Audience
	SigningKey      *string
	TimeoutMS       int
	Enabled         bool
	ExpectedVersion *int64
	IdempotencyKey  string
	Audit           authorization.AuditContext
}

type WebhookTestInput struct {
	ConfigurationVersion int64
	EventType            EventType
	Context              map[string]any
	Reason               string
	IdempotencyKey       string
	Audit                authorization.AuditContext
}

type PageInput struct {
	After *string
	Limit int
}

type RuleWriteInput struct {
	Fields          RuleFields
	ExpectedVersion *int64
	IdempotencyKey  string
	Audit           authorization.AuditContext
}

type TemplateWriteInput struct {
	Fields          TemplateFields
	ExpectedVersion *int64
	IdempotencyKey  string
	Audit           authorization.AuditContext
}

type TemplateDuplicateInput struct {
	SourceVersion  int64
	Key            string
	Name           string
	IdempotencyKey string
	Audit          authorization.AuditContext
}

type TemplateRollbackInput struct {
	SourceVersion   int64
	Reason          string
	ExpectedVersion *int64
	IdempotencyKey  string
	Audit           authorization.AuditContext
}

type TemplateTestSendInput struct {
	Version        int64
	Recipient      string
	Audience       Audience
	Context        map[string]any
	Reason         string
	IdempotencyKey string
	Audit          authorization.AuditContext
}
