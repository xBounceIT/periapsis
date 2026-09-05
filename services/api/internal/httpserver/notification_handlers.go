package httpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/notification"
)

const notificationJSONMediaType = "application/json"

var notificationRuleRequiredFields = []string{
	"name", "description", "eventType", "objectType", "condition", "recipients", "templateId",
	"templateVersion", "channel", "priority", "delayMs", "deduplicationWindowMs", "grouping",
	"retry", "enabled", "effectiveFrom",
}

type notificationRuleBody struct {
	Name                  string                           `json:"name"`
	Description           string                           `json:"description"`
	EventType             notification.EventType           `json:"eventType"`
	ObjectType            notification.ObjectType          `json:"objectType"`
	Condition             notification.Condition           `json:"condition"`
	Recipients            []notification.RecipientSelector `json:"recipients"`
	TemplateID            uuid.UUID                        `json:"templateId"`
	TemplateVersion       int64                            `json:"templateVersion"`
	Channel               notification.Channel             `json:"channel"`
	Priority              int                              `json:"priority"`
	DelayMS               int64                            `json:"delayMs"`
	QuietHours            *notification.QuietHours         `json:"quietHours,omitempty"`
	DeduplicationWindowMS int64                            `json:"deduplicationWindowMs"`
	Grouping              notification.GroupingPolicy      `json:"grouping"`
	Retry                 notification.RetryPolicy         `json:"retry"`
	Enabled               bool                             `json:"enabled"`
	EffectiveFrom         time.Time                        `json:"effectiveFrom"`
	EffectiveUntil        *time.Time                       `json:"effectiveUntil,omitempty"`
}

func (body notificationRuleBody) fields() notification.RuleFields {
	return notification.RuleFields{
		Name: body.Name, Description: body.Description, EventType: body.EventType, ObjectType: body.ObjectType,
		Condition: body.Condition, Recipients: body.Recipients, TemplateID: body.TemplateID,
		TemplateVersion: body.TemplateVersion, Channel: body.Channel, Priority: body.Priority, DelayMS: body.DelayMS,
		QuietHours: body.QuietHours, DeduplicationWindowMS: body.DeduplicationWindowMS, Grouping: body.Grouping,
		Retry: body.Retry, Enabled: body.Enabled, EffectiveFrom: body.EffectiveFrom, EffectiveUntil: body.EffectiveUntil,
	}
}

type notificationTemplateBody struct {
	Key        string         `json:"key"`
	Name       string         `json:"name"`
	Language   string         `json:"language"`
	Subject    string         `json:"subject"`
	HTML       string         `json:"html"`
	PlainText  *string        `json:"plainText,omitempty"`
	CSS        *string        `json:"css,omitempty"`
	SampleData map[string]any `json:"sampleData,omitempty"`
}

func (body notificationTemplateBody) fields() notification.TemplateFields {
	return notification.TemplateFields{
		Key: body.Key, Name: body.Name, Language: body.Language, Subject: body.Subject, HTML: body.HTML,
		PlainText: body.PlainText, CSS: body.CSS, SampleData: body.SampleData,
	}
}

type notificationTemplatePreviewBody struct {
	Audience notification.Audience    `json:"audience"`
	Template notificationTemplateBody `json:"template"`
	Context  map[string]any           `json:"context"`
}

type notificationTemplateDuplicateBody struct {
	SourceVersion int64  `json:"sourceVersion"`
	Key           string `json:"key"`
	Name          string `json:"name"`
}

type notificationTemplateRollbackBody struct {
	SourceVersion int64  `json:"sourceVersion"`
	Reason        string `json:"reason"`
}

type notificationTemplateTestBody struct {
	Version   int64                 `json:"version"`
	Recipient string                `json:"recipient"`
	Audience  notification.Audience `json:"audience"`
	Context   map[string]any        `json:"context"`
	Reason    string                `json:"reason"`
}

type notificationSMTPBody struct {
	Name                         string                       `json:"name"`
	Host                         string                       `json:"host"`
	Port                         int                          `json:"port"`
	Security                     notification.SMTPSecurity    `json:"security"`
	Username                     *string                      `json:"username"`
	Password                     *string                      `json:"password,omitempty"`
	ClearPassword                bool                         `json:"clearPassword"`
	FromName                     string                       `json:"fromName"`
	FromEmail                    string                       `json:"fromEmail"`
	ReplyToEmail                 *string                      `json:"replyToEmail"`
	TimeoutMS                    int                          `json:"timeoutMs"`
	MaximumConnections           int                          `json:"maximumConnections"`
	MaximumMessagesPerConnection int                          `json:"maximumMessagesPerConnection"`
	RateLimitPerSecond           int                          `json:"rateLimitPerSecond"`
	DKIM                         *notification.DKIMWriteInput `json:"dkim,omitempty"`
	ClearDKIM                    bool                         `json:"clearDkim"`
	Enabled                      bool                         `json:"enabled"`
}

var notificationSMTPRequiredFields = []string{
	"name", "host", "port", "security", "username", "clearPassword", "fromName", "fromEmail",
	"replyToEmail", "timeoutMs", "maximumConnections", "maximumMessagesPerConnection", "rateLimitPerSecond",
	"clearDkim", "enabled",
}

func (body notificationSMTPBody) input(version *int64, idempotencyKey string, audit authorization.AuditContext) notification.SMTPWriteInput {
	return notification.SMTPWriteInput{
		Name: body.Name, Host: body.Host, Port: body.Port, Security: body.Security, Username: body.Username,
		Password: body.Password, ClearPassword: body.ClearPassword, FromName: body.FromName, FromEmail: body.FromEmail,
		ReplyToEmail: body.ReplyToEmail, TimeoutMS: body.TimeoutMS, MaximumConnections: body.MaximumConnections,
		MaximumMessagesPerConnection: body.MaximumMessagesPerConnection, RateLimitPerSecond: body.RateLimitPerSecond,
		DKIM: body.DKIM, ClearDKIM: body.ClearDKIM, Enabled: body.Enabled, ExpectedVersion: version,
		IdempotencyKey: idempotencyKey, Audit: audit,
	}
}

type notificationSMTPTestBody struct {
	ConfigurationVersion int64   `json:"configurationVersion"`
	Recipient            *string `json:"recipient"`
	Reason               string  `json:"reason"`
}

type notificationSMTPHealthTestBody struct {
	ConfigurationVersion int64  `json:"configurationVersion"`
	Reason               string `json:"reason"`
}

type notificationDeliveryRetryBody struct {
	ExpectedAttempt                int    `json:"expectedAttempt"`
	AcknowledgeUncertainSubmission bool   `json:"acknowledgeUncertainSubmission"`
	Reason                         string `json:"reason"`
}

type notificationWebhookBody struct {
	Name        string                   `json:"name"`
	EndpointURL string                   `json:"endpointUrl"`
	EventTypes  []notification.EventType `json:"eventTypes"`
	Audience    notification.Audience    `json:"audience"`
	SigningKey  *string                  `json:"signingKey,omitempty"`
	TimeoutMS   int                      `json:"timeoutMs"`
	Enabled     bool                     `json:"enabled"`
}

func (body notificationWebhookBody) input(version *int64, idempotencyKey string, audit authorization.AuditContext) notification.WebhookWriteInput {
	return notification.WebhookWriteInput{
		Name: body.Name, EndpointURL: body.EndpointURL, EventTypes: body.EventTypes, Audience: body.Audience,
		SigningKey: body.SigningKey, TimeoutMS: body.TimeoutMS, Enabled: body.Enabled, ExpectedVersion: version,
		IdempotencyKey: idempotencyKey, Audit: audit,
	}
}

type notificationWebhookTestBody struct {
	ConfigurationVersion int64                  `json:"configurationVersion"`
	EventType            notification.EventType `json:"eventType"`
	Context              map[string]any         `json:"context"`
	Reason               string                 `json:"reason"`
}

func decodeNotificationBody(r *http.Request, destination any, requiredFields ...string) error {
	mediaType, err := requestMediaType(r)
	if err != nil || mediaType != notificationJSONMediaType {
		return notification.ErrInvalidInput
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if err != nil || len(body) == 0 || len(body) > 1<<20 || !utf8.Valid(body) {
		return notification.ErrInvalidInput
	}
	defer clear(body)
	if err := validateNotificationJSONTokens(body); err != nil {
		return notification.ErrInvalidInput
	}
	if err := validateNotificationJSONShape(body, reflect.TypeOf(destination), "", requiredFields); err != nil {
		return notification.ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return notification.ErrInvalidInput
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return notification.ErrInvalidInput
	}
	return nil
}

var (
	notificationRawMessageType = reflect.TypeOf(json.RawMessage{})
	notificationTimeType       = reflect.TypeOf(time.Time{})
	notificationUUIDType       = reflect.TypeOf(uuid.UUID{})
)

func validateNotificationJSONShape(
	raw json.RawMessage,
	destinationType reflect.Type,
	fieldName string,
	requiredFields []string,
) error {
	for destinationType.Kind() == reflect.Pointer {
		destinationType = destinationType.Elem()
	}
	trimmed := bytes.TrimSpace(raw)
	if bytes.Equal(trimmed, []byte("null")) {
		if fieldName == "username" || fieldName == "replyToEmail" || fieldName == "recipient" {
			return nil
		}
		return errors.New("request body contains a non-canonical null")
	}
	if destinationType == notificationRawMessageType || destinationType == notificationTimeType || destinationType == notificationUUIDType {
		return nil
	}
	switch destinationType.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &object); err != nil || object == nil {
			return errors.New("request body contains an invalid object")
		}
		for _, name := range requiredFields {
			if _, present := object[name]; !present {
				for _, item := range object {
					clear(item)
				}
				return errors.New("request body omits a required field")
			}
		}
		fields := make(map[string]reflect.Type, destinationType.NumField())
		for index := 0; index < destinationType.NumField(); index++ {
			field := destinationType.Field(index)
			if !field.IsExported() {
				continue
			}
			name := field.Tag.Get("json")
			if comma := bytes.IndexByte([]byte(name), ','); comma >= 0 {
				name = name[:comma]
			}
			if name == "" {
				name = field.Name
			}
			if name != "-" {
				fields[name] = field.Type
			}
		}
		for name, item := range object {
			fieldType, exists := fields[name]
			if !exists {
				clear(item)
				for otherName, other := range object {
					if otherName != name {
						clear(other)
					}
				}
				return errors.New("request body contains a non-canonical field name")
			}
			err := validateNotificationJSONShape(item, fieldType, name, nil)
			clear(item)
			if err != nil {
				for otherName, other := range object {
					if otherName != name {
						clear(other)
					}
				}
				return err
			}
		}
	case reflect.Array, reflect.Slice:
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return errors.New("request body contains an invalid array")
		}
		for index, item := range items {
			err := validateNotificationJSONShape(item, destinationType.Elem(), fieldName, nil)
			clear(item)
			if err != nil {
				for _, other := range items[index+1:] {
					clear(other)
				}
				return err
			}
		}
	case reflect.Map, reflect.Interface:
		// Context and sample-data maps deliberately accept arbitrary JSON below
		// their canonical top-level field name. Domain validation applies depth,
		// node, key, scalar, and encoded-size bounds before any use.
		return nil
	}
	return nil
}

func validateNotificationJSONTokens(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := scanNotificationJSONValue(decoder, true); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}

func scanNotificationJSONValue(decoder *json.Decoder, root bool) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		if root {
			return errors.New("request body contains null")
		}
		return nil
	}
	if text, ok := token.(string); ok && containsJSONControlCharacter(text) {
		return errors.New("request body contains a control character")
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			key, ok := keyToken.(string)
			if keyErr != nil || !ok || containsJSONControlCharacter(key) {
				return errors.New("request body contains an invalid object key")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("request body contains a duplicate object key")
			}
			seen[key] = struct{}{}
			if err := scanNotificationJSONValue(decoder, false); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim('}') {
			return errors.New("request body contains an unterminated object")
		}
	case '[':
		for decoder.More() {
			if err := scanNotificationJSONValue(decoder, false); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim(']') {
			return errors.New("request body contains an unterminated array")
		}
	default:
		return errors.New("request body contains an invalid delimiter")
	}
	return nil
}

func notificationPage(after *contract.NotificationAfterCursor, limit *contract.PageSize) (notification.PageInput, error) {
	input := notification.PageInput{}
	if after != nil {
		value := string(*after)
		input.After = &value
	}
	if limit != nil {
		if *limit < 1 || *limit > 100 {
			return notification.PageInput{}, notification.ErrInvalidInput
		}
		input.Limit = *limit
	}
	return input, nil
}

func notificationRequiredVersion(r *http.Request) (*int64, error) {
	version, present, err := strongVersionPrecondition(r)
	if err != nil {
		return nil, notification.ErrInvalidInput
	}
	if !present {
		return nil, notification.ErrPreconditionRequired
	}
	return &version, nil
}

func notificationOptionalVersion(r *http.Request) (*int64, error) {
	version, present, err := strongVersionPrecondition(r)
	if err != nil {
		return nil, notification.ErrInvalidInput
	}
	if !present {
		return nil, nil
	}
	return &version, nil
}

func notificationMutationKey(r *http.Request) (string, error) {
	value, err := requestIdempotencyKey(r)
	if err != nil {
		return "", notification.ErrInvalidInput
	}
	return value, nil
}

func validNotificationTransportUUID(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func (h *Handler) notificationTenantActor(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID) (authorization.Actor, bool) {
	actor, ok := h.tenantAuthorizationActor(w, r)
	if !ok {
		return authorization.Actor{}, false
	}
	if !validNotificationTransportUUID(tenantID) {
		writeDomainError(w, r, notification.ErrInvalidInput)
		return authorization.Actor{}, false
	}
	if actor.ActiveTenantID != tenantID {
		writeDomainError(w, r, notification.ErrForbidden)
		return authorization.Actor{}, false
	}
	return actor, true
}

func (h *Handler) notificationTenantMutation(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
) (authorization.Actor, authorization.AuditContext, bool) {
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return authorization.Actor{}, authorization.AuditContext{}, false
	}
	if !validNotificationTransportUUID(tenantID) {
		writeDomainError(w, r, notification.ErrInvalidInput)
		return authorization.Actor{}, authorization.AuditContext{}, false
	}
	if actor.ActiveTenantID != tenantID {
		writeDomainError(w, r, notification.ErrForbidden)
		return authorization.Actor{}, authorization.AuditContext{}, false
	}
	return actor, audit, true
}

func notificationRuleLocation(tenantID, ruleID uuid.UUID) string {
	return "/api/v1/tenants/" + tenantID.String() + "/notification-rules/" + ruleID.String()
}

func notificationTemplateLocation(tenantID, templateID uuid.UUID) string {
	return "/api/v1/tenants/" + tenantID.String() + "/notification-templates/" + templateID.String()
}

func notificationDeliveryLocation(tenantID, deliveryID uuid.UUID) string {
	return "/api/v1/tenants/" + tenantID.String() + "/notification-deliveries/" + deliveryID.String()
}

func notificationWebhookLocation(tenantID, webhookID uuid.UUID) string {
	return "/api/v1/tenants/" + tenantID.String() + "/webhooks/" + webhookID.String()
}

func notificationSMTPLocation(tenantID *uuid.UUID) string {
	if tenantID == nil {
		return "/api/v1/platform/smtp-configuration"
	}
	return "/api/v1/tenants/" + tenantID.String() + "/smtp-configuration"
}

func mapNotificationCondition(value notification.Condition) (contract.NotificationCondition, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return contract.NotificationCondition{}, err
	}
	var mapped contract.NotificationCondition
	if err := mapped.UnmarshalJSON(encoded); err != nil {
		return contract.NotificationCondition{}, err
	}
	return mapped, nil
}

func mapNotificationRule(value notification.Rule) (contract.NotificationRule, error) {
	condition, err := mapNotificationCondition(value.Condition)
	if err != nil {
		return contract.NotificationRule{}, err
	}
	recipients := make([]contract.NotificationRecipientSelector, len(value.Recipients))
	for index, recipient := range value.Recipients {
		mapped := contract.NotificationRecipientSelector{
			Kind: contract.NotificationRecipientSelectorKind(recipient.Kind), Value: recipient.Value, Authorized: recipient.Authorized,
		}
		if recipient.Audience == nil {
			return contract.NotificationRule{}, errors.New("notification recipient audience is absent")
		}
		mapped.Audience = contract.NotificationAudience(*recipient.Audience)
		recipients[index] = mapped
	}
	grouping := contract.NotificationGroupingPolicy{Mode: contract.NotificationGroupingPolicyMode(value.Grouping.Mode), WindowMs: value.Grouping.WindowMS, MaximumItems: value.Grouping.MaximumItems}
	retry := contract.NotificationRetryPolicy{
		MaximumAttempts: value.Retry.MaximumAttempts, InitialDelayMs: value.Retry.InitialDelayMS,
		MaximumDelayMs: value.Retry.MaximumDelayMS, Multiplier: float32(value.Retry.Multiplier), JitterPercent: value.Retry.JitterPercent,
	}
	var quiet *contract.NotificationQuietHours
	if value.QuietHours != nil {
		weekdays := append([]int(nil), value.QuietHours.Weekdays...)
		quiet = &contract.NotificationQuietHours{
			Timezone: value.QuietHours.Timezone, StartMinute: value.QuietHours.StartMinute,
			EndMinute: value.QuietHours.EndMinute, Weekdays: &weekdays,
		}
	}
	return contract.NotificationRule{
		Id: value.ID, TenantId: value.TenantID, Version: contract.ResourceVersion(value.Version),
		Name: value.Name, Description: value.Description, EventType: contract.NotificationEventType(value.EventType),
		ObjectType: contract.NotificationObjectType(value.ObjectType), Condition: condition, Recipients: recipients,
		TemplateId: value.TemplateID, TemplateVersion: contract.ResourceVersion(value.TemplateVersion),
		Channel: contract.NotificationRuleChannel(value.Channel), Priority: value.Priority, DelayMs: value.DelayMS,
		QuietHours: quiet, DeduplicationWindowMs: value.DeduplicationWindowMS, Grouping: grouping, Retry: retry,
		Enabled: value.Enabled, EffectiveFrom: value.EffectiveFrom, EffectiveUntil: value.EffectiveUntil,
		CreatedAt: value.CreatedAt, CreatedBy: value.CreatedBy,
	}, nil
}

func mapNotificationTemplate(value notification.Template) contract.NotificationTemplate {
	sample := contract.NotificationSampleData(value.SampleData)
	return contract.NotificationTemplate{
		Id: value.ID, TenantId: value.TenantID, Version: contract.ResourceVersion(value.Version), Key: value.Key,
		Name: value.Name, Language: value.Language, Subject: value.Subject, Html: value.HTML,
		PlainText: value.PlainText, Css: value.CSS, SampleData: &sample, Placeholders: append([]string(nil), value.Placeholders...),
		CreatedAt: value.CreatedAt, CreatedBy: value.CreatedBy,
	}
}

func mapNotificationSMTP(value notification.SMTPConfiguration) contract.SmtpConfiguration {
	var tenantID *openapi_types.UUID
	if value.TenantID != nil {
		mapped := openapi_types.UUID(*value.TenantID)
		tenantID = &mapped
	}
	var replyTo *openapi_types.Email
	if value.ReplyToEmail != nil {
		mapped := openapi_types.Email(*value.ReplyToEmail)
		replyTo = &mapped
	}
	var dkim *contract.SmtpDkimConfiguration
	if value.DKIM != nil {
		dkim = &contract.SmtpDkimConfiguration{
			DomainName: value.DKIM.DomainName, Selector: value.DKIM.Selector,
			PrivateKeyConfigured: value.DKIM.PrivateKeyConfigured,
		}
	}
	return contract.SmtpConfiguration{
		Id: value.ID, TenantId: tenantID, InheritedFromGlobal: value.InheritedFromGlobal, Name: value.Name,
		Host: value.Host, Port: value.Port, Security: contract.SmtpSecurityMode(value.Security), Username: value.Username,
		PasswordConfigured: value.PasswordConfigured, FromName: value.FromName, FromEmail: openapi_types.Email(value.FromEmail),
		ReplyToEmail: replyTo, TimeoutMs: value.TimeoutMS, MaximumConnections: value.MaximumConnections,
		MaximumMessagesPerConnection: value.MaximumMessagesPerConnection, RateLimitPerSecond: value.RateLimitPerSecond,
		Dkim: dkim, Enabled: value.Enabled, Version: contract.ResourceVersion(value.Version),
		CreatedAt: value.CreatedAt, CreatedBy: value.CreatedBy,
	}
}

func mapNotificationSMTPHealth(value notification.SMTPHealth) contract.SmtpConfigurationHealth {
	checks := make([]contract.SmtpHealthCheck, len(value.Checks))
	for index, check := range value.Checks {
		var failure *contract.SmtpHealthCheckErrorClass
		if check.ErrorClass != nil {
			mapped := contract.SmtpHealthCheckErrorClass(*check.ErrorClass)
			failure = &mapped
		}
		checks[index] = contract.SmtpHealthCheck{
			Kind: contract.SmtpHealthCheckKind(check.Kind), Outcome: contract.SmtpHealthCheckOutcome(check.Outcome), ErrorClass: failure,
		}
	}
	return contract.SmtpConfigurationHealth{
		ConfigurationId: value.ConfigurationID, ConfigurationVersion: contract.ResourceVersion(value.ConfigurationVersion),
		Healthy: value.Healthy, CheckedAt: value.CheckedAt, Checks: checks, QueuedDeliveryId: value.QueuedDeliveryID,
	}
}

func mapNotificationWebhook(value notification.WebhookConfiguration) contract.WebhookConfiguration {
	events := make([]contract.NotificationEventType, len(value.EventTypes))
	for index, event := range value.EventTypes {
		events[index] = contract.NotificationEventType(event)
	}
	return contract.WebhookConfiguration{
		Id: value.ID, TenantId: value.TenantID, Name: value.Name, EndpointUrl: value.EndpointURL,
		EventTypes: events, Audience: contract.NotificationAudience(value.Audience),
		SigningKeyConfigured: value.SigningKeyConfigured, SigningKeyVersion: contract.ResourceVersion(value.SigningKeyVersion),
		TimeoutMs: value.TimeoutMS, Enabled: value.Enabled, Version: contract.ResourceVersion(value.Version),
		CreatedAt: value.CreatedAt, CreatedBy: value.CreatedBy,
	}
}

func mapNotificationDeliveryFields(value notification.Delivery) (contract.NotificationDeliveryFields, error) {
	var failure *contract.NotificationDeliveryFailureClass
	if value.FailureClass != nil {
		mapped := contract.NotificationDeliveryFailureClass(*value.FailureClass)
		failure = &mapped
	}
	var smtpScope *contract.NotificationDeliveryFieldsSmtpConfigurationScope
	switch value.Channel {
	case notification.ChannelEmail:
		if value.SMTPConfigurationScope == nil ||
			*value.SMTPConfigurationScope != notification.SMTPConfigurationTenant &&
				*value.SMTPConfigurationScope != notification.SMTPConfigurationPlatform {
			return contract.NotificationDeliveryFields{}, errors.New("email delivery SMTP configuration scope is invalid")
		}
		mapped := contract.NotificationDeliveryFieldsSmtpConfigurationScope(*value.SMTPConfigurationScope)
		smtpScope = &mapped
	case notification.ChannelWebhook:
		if value.SMTPConfigurationScope != nil {
			return contract.NotificationDeliveryFields{}, errors.New("webhook delivery contains an SMTP configuration scope")
		}
	default:
		return contract.NotificationDeliveryFields{}, errors.New("notification delivery channel is unsupported")
	}
	return contract.NotificationDeliveryFields{
		Id: value.ID, TenantId: value.TenantID, EventId: value.EventID, ParentDeliveryId: value.ParentDeliveryID,
		RuleId: value.RuleID, RuleVersion: notificationVersion(value.RuleVersion), TemplateId: value.TemplateID,
		TemplateVersion: notificationVersion(value.TemplateVersion), SmtpConfigurationId: value.SMTPConfigurationID,
		SmtpConfigurationVersion:    notificationVersion(value.SMTPConfigurationVersion),
		SmtpConfigurationScope:      smtpScope,
		WebhookConfigurationId:      value.WebhookConfigurationID,
		WebhookConfigurationVersion: notificationVersion(value.WebhookConfigurationVersion),
		WebhookSigningKeyVersion:    notificationVersion(value.WebhookSigningKeyVersion),
		Channel:                     contract.NotificationDeliveryFieldsChannel(value.Channel), Audience: contract.NotificationAudience(value.Audience),
		Status: contract.NotificationDeliveryStatus(value.Status), DestinationRedacted: value.DestinationRedacted,
		AttemptCount: value.AttemptCount, MaximumAttempts: value.MaximumAttempts, NextAttemptAt: value.NextAttemptAt,
		DeliveredAt: value.DeliveredAt, FailureAt: value.FailureAt, FailureClass: failure, CreatedAt: value.CreatedAt,
	}, nil
}

func notificationVersion(value *int64) *contract.ResourceVersion {
	if value == nil {
		return nil
	}
	mapped := contract.ResourceVersion(*value)
	return &mapped
}

func mapNotificationDeliveryDetail(value notification.Delivery) (contract.NotificationDeliveryDetail, error) {
	fields, err := mapNotificationDeliveryFields(value)
	if err != nil {
		return contract.NotificationDeliveryDetail{}, err
	}
	attempts := make([]contract.NotificationDeliveryAttempt, len(value.Attempts))
	for index, attempt := range value.Attempts {
		var failure *contract.NotificationDeliveryFailureClass
		if attempt.FailureClass != nil {
			mapped := contract.NotificationDeliveryFailureClass(*attempt.FailureClass)
			failure = &mapped
		}
		var receipt *contract.NotificationProviderReceipt
		if attempt.ProviderReceipt != nil {
			mapped, err := mapNotificationProviderReceipt(*attempt.ProviderReceipt)
			if err != nil {
				return contract.NotificationDeliveryDetail{}, err
			}
			receipt = &mapped
		}
		attempts[index] = contract.NotificationDeliveryAttempt{
			Number: attempt.Number, StartedAt: attempt.StartedAt, CompletedAt: attempt.CompletedAt,
			Outcome: contract.NotificationDeliveryAttemptOutcome(attempt.Outcome), FailureClass: failure, ProviderReceipt: receipt,
		}
	}
	var smtpScope *contract.NotificationDeliveryDetailSmtpConfigurationScope
	if fields.SmtpConfigurationScope != nil {
		mapped := contract.NotificationDeliveryDetailSmtpConfigurationScope(*fields.SmtpConfigurationScope)
		smtpScope = &mapped
	}
	return contract.NotificationDeliveryDetail{
		Id: fields.Id, TenantId: fields.TenantId, EventId: fields.EventId, ParentDeliveryId: fields.ParentDeliveryId,
		RuleId: fields.RuleId, RuleVersion: fields.RuleVersion, TemplateId: fields.TemplateId,
		TemplateVersion: fields.TemplateVersion, SmtpConfigurationId: fields.SmtpConfigurationId,
		SmtpConfigurationVersion: fields.SmtpConfigurationVersion, SmtpConfigurationScope: smtpScope,
		WebhookConfigurationId:      fields.WebhookConfigurationId,
		WebhookConfigurationVersion: fields.WebhookConfigurationVersion, WebhookSigningKeyVersion: fields.WebhookSigningKeyVersion,
		Channel: contract.NotificationDeliveryDetailChannel(value.Channel), Audience: fields.Audience, Status: fields.Status,
		DestinationRedacted: fields.DestinationRedacted, AttemptCount: fields.AttemptCount,
		MaximumAttempts: fields.MaximumAttempts, NextAttemptAt: fields.NextAttemptAt, DeliveredAt: fields.DeliveredAt,
		FailureAt: fields.FailureAt, FailureClass: fields.FailureClass, CreatedAt: fields.CreatedAt, Attempts: attempts,
	}, nil
}

func mapNotificationProviderReceipt(value notification.ProviderReceipt) (contract.NotificationProviderReceipt, error) {
	var mapped contract.NotificationProviderReceipt
	switch value.Provider {
	case "smtp":
		if value.AcceptedCount == nil || value.RejectedCount == nil {
			return mapped, errors.New("SMTP receipt counters are absent")
		}
		err := mapped.FromNotificationProviderReceipt0(contract.NotificationProviderReceipt0{
			Provider: contract.NotificationProviderReceipt0Provider(value.Provider), ReceiptDigest: value.ReceiptDigest,
			AcceptedCount: *value.AcceptedCount, RejectedCount: *value.RejectedCount, ResponseClass: value.ResponseClass,
		})
		return mapped, err
	case "webhook":
		if value.StatusCode == nil {
			return mapped, errors.New("webhook receipt status is absent")
		}
		err := mapped.FromNotificationProviderReceipt1(contract.NotificationProviderReceipt1{
			Provider: contract.NotificationProviderReceipt1Provider(value.Provider), ReceiptDigest: value.ReceiptDigest,
			StatusCode: *value.StatusCode,
		})
		return mapped, err
	default:
		return mapped, errors.New("notification receipt provider is unsupported")
	}
}

func (h *Handler) writeNotificationRule(w http.ResponseWriter, r *http.Request, status int, value notification.Rule, location string) {
	mapped, err := mapNotificationRule(value)
	if err != nil || !setVersionETag(w, value.Version) {
		writeDomainError(w, r, notification.ErrUnavailable)
		return
	}
	if location != "" {
		w.Header().Set("Location", location)
	}
	writeSensitiveJSON(w, status, mapped)
}

func (h *Handler) writeNotificationTemplate(w http.ResponseWriter, r *http.Request, status int, value notification.Template, location string) {
	if !setVersionETag(w, value.Version) {
		writeDomainError(w, r, notification.ErrUnavailable)
		return
	}
	if location != "" {
		w.Header().Set("Location", location)
	}
	writeSensitiveJSON(w, status, mapNotificationTemplate(value))
}

func (h *Handler) writeNotificationSMTP(w http.ResponseWriter, r *http.Request, status int, value notification.SMTPConfiguration, location string) {
	if !setVersionETag(w, value.Version) {
		writeDomainError(w, r, notification.ErrUnavailable)
		return
	}
	if location != "" {
		w.Header().Set("Location", location)
	}
	writeSensitiveJSON(w, status, mapNotificationSMTP(value))
}

func (h *Handler) writeNotificationWebhook(w http.ResponseWriter, r *http.Request, status int, value notification.WebhookConfiguration, location string) {
	if !setVersionETag(w, value.Version) {
		writeDomainError(w, r, notification.ErrUnavailable)
		return
	}
	if location != "" {
		w.Header().Set("Location", location)
	}
	writeSensitiveJSON(w, status, mapNotificationWebhook(value))
}

func writeNotificationDelivery(w http.ResponseWriter, r *http.Request, status int, value notification.Delivery, location string) {
	mapped, err := mapNotificationDeliveryFields(value)
	if err != nil {
		writeDomainError(w, r, notification.ErrUnavailable)
		return
	}
	if location != "" {
		w.Header().Set("Location", location)
	}
	writeSensitiveJSON(w, status, mapped)
}

func notificationCreatedStatus(expectedVersion *int64) int {
	if expectedVersion == nil {
		return http.StatusCreated
	}
	return http.StatusOK
}

func (h *Handler) GetPlatformSmtpConfiguration(w http.ResponseWriter, r *http.Request) {
	session, ok := h.platformOperatorTeamSession(w, r)
	if !ok {
		return
	}
	result, err := h.notifications.GetPlatformSMTP(r.Context(), session)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeNotificationSMTP(w, r, http.StatusOK, result, "")
}

func (h *Handler) VersionPlatformSmtpConfiguration(
	w http.ResponseWriter,
	r *http.Request,
	_ contract.VersionPlatformSmtpConfigurationParams,
) {
	session, audit, ok := h.preparePlatformOperatorTeamMutation(w, r)
	if !ok {
		return
	}
	expected, err := notificationOptionalVersion(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	key, err := notificationMutationKey(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body notificationSMTPBody
	if err := decodeNotificationBody(r, &body, notificationSMTPRequiredFields...); err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.notifications.VersionPlatformSMTP(r.Context(), session, body.input(expected, key, audit))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	status := notificationCreatedStatus(expected)
	h.writeNotificationSMTP(w, r, status, result, "")
}

func (h *Handler) TestPlatformSmtpConfiguration(
	w http.ResponseWriter,
	r *http.Request,
	_ contract.TestPlatformSmtpConfigurationParams,
) {
	session, audit, ok := h.preparePlatformOperatorTeamMutation(w, r)
	if !ok {
		return
	}
	key, err := notificationMutationKey(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body notificationSMTPHealthTestBody
	if err := decodeNotificationBody(r, &body, "configurationVersion", "reason"); err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.notifications.TestPlatformSMTP(r.Context(), session, notification.SMTPTestInput{
		ConfigurationVersion: body.ConfigurationVersion, Reason: body.Reason,
		IdempotencyKey: key, Audit: audit,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if result.QueuedDeliveryID != nil {
		writeDomainError(w, r, notification.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapNotificationSMTPHealth(result))
}

func (h *Handler) ListTenantNotificationRules(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.ListTenantNotificationRulesParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.notificationTenantActor(w, r, tenant)
	if !ok {
		return
	}
	page, err := notificationPage(params.After, params.Limit)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.notifications.ListRules(r.Context(), actor, tenant, page)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	items := make([]contract.NotificationRule, len(result.Items))
	for index, item := range result.Items {
		mapped, mapErr := mapNotificationRule(item)
		if mapErr != nil {
			writeDomainError(w, r, notification.ErrUnavailable)
			return
		}
		items[index] = mapped
	}
	writeSensitiveJSON(w, http.StatusOK, contract.NotificationRuleList{Items: items, NextCursor: result.NextCursor})
}

func (h *Handler) CreateTenantNotificationRule(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	_ contract.CreateTenantNotificationRuleParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, audit, ok := h.notificationTenantMutation(w, r, tenant)
	if !ok {
		return
	}
	key, err := notificationMutationKey(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body notificationRuleBody
	if err := decodeNotificationBody(r, &body, notificationRuleRequiredFields...); err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.notifications.CreateRule(r.Context(), actor, tenant, notification.RuleWriteInput{
		Fields: body.fields(), IdempotencyKey: key, Audit: audit,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeNotificationRule(w, r, http.StatusCreated, result, notificationRuleLocation(tenant, result.ID))
}

func (h *Handler) GetTenantNotificationRule(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	ruleID contract.NotificationRuleId,
) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.notificationTenantActor(w, r, tenant)
	if !ok {
		return
	}
	result, err := h.notifications.GetRule(r.Context(), actor, tenant, uuid.UUID(ruleID))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeNotificationRule(w, r, http.StatusOK, result, "")
}

func (h *Handler) VersionTenantNotificationRule(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	ruleID contract.NotificationRuleId,
	_ contract.VersionTenantNotificationRuleParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, audit, ok := h.notificationTenantMutation(w, r, tenant)
	if !ok {
		return
	}
	expected, err := notificationRequiredVersion(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	key, err := notificationMutationKey(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body notificationRuleBody
	if err := decodeNotificationBody(r, &body, notificationRuleRequiredFields...); err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.notifications.VersionRule(r.Context(), actor, tenant, uuid.UUID(ruleID), notification.RuleWriteInput{
		Fields: body.fields(), ExpectedVersion: expected, IdempotencyKey: key, Audit: audit,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeNotificationRule(w, r, http.StatusOK, result, "")
}

func (h *Handler) ListTenantNotificationTemplates(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.ListTenantNotificationTemplatesParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.notificationTenantActor(w, r, tenant)
	if !ok {
		return
	}
	page, err := notificationPage(params.After, params.Limit)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.notifications.ListTemplates(r.Context(), actor, tenant, page)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	items := make([]contract.NotificationTemplate, len(result.Items))
	for index, item := range result.Items {
		items[index] = mapNotificationTemplate(item)
	}
	writeSensitiveJSON(w, http.StatusOK, contract.NotificationTemplateList{Items: items, NextCursor: result.NextCursor})
}

func (h *Handler) CreateTenantNotificationTemplate(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	_ contract.CreateTenantNotificationTemplateParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, audit, ok := h.notificationTenantMutation(w, r, tenant)
	if !ok {
		return
	}
	key, err := notificationMutationKey(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body notificationTemplateBody
	if err := decodeNotificationBody(r, &body, "key", "name", "language", "subject", "html"); err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.notifications.CreateTemplate(r.Context(), actor, tenant, notification.TemplateWriteInput{
		Fields: body.fields(), IdempotencyKey: key, Audit: audit,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeNotificationTemplate(w, r, http.StatusCreated, result, notificationTemplateLocation(tenant, result.ID))
}

func (h *Handler) PreviewTenantNotificationTemplate(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId) {
	tenant := uuid.UUID(tenantID)
	actor, _, ok := h.notificationTenantMutation(w, r, tenant)
	if !ok {
		return
	}
	var body notificationTemplatePreviewBody
	if err := decodeNotificationBody(r, &body, "audience", "template", "context"); err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.notifications.PreviewTemplate(r.Context(), actor, tenant, body.Audience, body.Template.fields(), body.Context)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, contract.NotificationTemplatePreview{
		Subject: result.Subject, Html: result.HTML, PlainText: result.PlainText,
	})
}

func (h *Handler) GetTenantNotificationTemplate(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	templateID contract.NotificationTemplateId,
) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.notificationTenantActor(w, r, tenant)
	if !ok {
		return
	}
	result, err := h.notifications.GetTemplate(r.Context(), actor, tenant, uuid.UUID(templateID), nil)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeNotificationTemplate(w, r, http.StatusOK, result, "")
}

func (h *Handler) VersionTenantNotificationTemplate(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	templateID contract.NotificationTemplateId,
	_ contract.VersionTenantNotificationTemplateParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, audit, ok := h.notificationTenantMutation(w, r, tenant)
	if !ok {
		return
	}
	expected, err := notificationRequiredVersion(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	key, err := notificationMutationKey(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body notificationTemplateBody
	if err := decodeNotificationBody(r, &body, "key", "name", "language", "subject", "html"); err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.notifications.VersionTemplate(r.Context(), actor, tenant, uuid.UUID(templateID), notification.TemplateWriteInput{
		Fields: body.fields(), ExpectedVersion: expected, IdempotencyKey: key, Audit: audit,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeNotificationTemplate(w, r, http.StatusOK, result, "")
}

func (h *Handler) DuplicateTenantNotificationTemplate(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	templateID contract.NotificationTemplateId,
	_ contract.DuplicateTenantNotificationTemplateParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, audit, ok := h.notificationTenantMutation(w, r, tenant)
	if !ok {
		return
	}
	key, err := notificationMutationKey(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body notificationTemplateDuplicateBody
	if err := decodeNotificationBody(r, &body, "sourceVersion", "key", "name"); err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.notifications.DuplicateTemplate(r.Context(), actor, tenant, uuid.UUID(templateID), notification.TemplateDuplicateInput{
		SourceVersion: body.SourceVersion, Key: body.Key, Name: body.Name, IdempotencyKey: key, Audit: audit,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeNotificationTemplate(w, r, http.StatusCreated, result, notificationTemplateLocation(tenant, result.ID))
}

func (h *Handler) RollbackTenantNotificationTemplate(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	templateID contract.NotificationTemplateId,
	_ contract.RollbackTenantNotificationTemplateParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, audit, ok := h.notificationTenantMutation(w, r, tenant)
	if !ok {
		return
	}
	expected, err := notificationRequiredVersion(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	key, err := notificationMutationKey(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body notificationTemplateRollbackBody
	if err := decodeNotificationBody(r, &body, "sourceVersion", "reason"); err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.notifications.RollbackTemplate(r.Context(), actor, tenant, uuid.UUID(templateID), notification.TemplateRollbackInput{
		SourceVersion: body.SourceVersion, Reason: body.Reason, ExpectedVersion: expected,
		IdempotencyKey: key, Audit: audit,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeNotificationTemplate(w, r, http.StatusOK, result, "")
}

func (h *Handler) TestSendTenantNotificationTemplate(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	templateID contract.NotificationTemplateId,
	_ contract.TestSendTenantNotificationTemplateParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, audit, ok := h.notificationTenantMutation(w, r, tenant)
	if !ok {
		return
	}
	key, err := notificationMutationKey(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body notificationTemplateTestBody
	if err := decodeNotificationBody(r, &body, "version", "recipient", "audience", "context", "reason"); err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.notifications.TestSendTemplate(r.Context(), actor, tenant, uuid.UUID(templateID), notification.TemplateTestSendInput{
		Version: body.Version, Recipient: body.Recipient, Audience: body.Audience, Context: body.Context,
		Reason: body.Reason, IdempotencyKey: key, Audit: audit,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeNotificationDelivery(w, r, http.StatusAccepted, result, notificationDeliveryLocation(tenant, result.ID))
}

func (h *Handler) GetTenantSmtpConfiguration(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.notificationTenantActor(w, r, tenant)
	if !ok {
		return
	}
	result, err := h.notifications.GetTenantSMTP(r.Context(), actor, tenant)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeNotificationSMTP(w, r, http.StatusOK, result, "")
}

func (h *Handler) VersionTenantSmtpConfiguration(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	_ contract.VersionTenantSmtpConfigurationParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, audit, ok := h.notificationTenantMutation(w, r, tenant)
	if !ok {
		return
	}
	expected, err := notificationOptionalVersion(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	key, err := notificationMutationKey(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body notificationSMTPBody
	if err := decodeNotificationBody(r, &body, notificationSMTPRequiredFields...); err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.notifications.VersionTenantSMTP(r.Context(), actor, tenant, body.input(expected, key, audit))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	status := notificationCreatedStatus(expected)
	location := ""
	if status == http.StatusCreated {
		location = notificationSMTPLocation(&tenant)
	}
	h.writeNotificationSMTP(w, r, status, result, location)
}

func (h *Handler) TestTenantSmtpConfiguration(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	_ contract.TestTenantSmtpConfigurationParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, audit, ok := h.notificationTenantMutation(w, r, tenant)
	if !ok {
		return
	}
	key, err := notificationMutationKey(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body notificationSMTPTestBody
	if err := decodeNotificationBody(r, &body, "configurationVersion", "recipient", "reason"); err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.notifications.TestTenantSMTP(r.Context(), actor, tenant, notification.SMTPTestInput{
		ConfigurationVersion: body.ConfigurationVersion, Recipient: body.Recipient, Reason: body.Reason,
		IdempotencyKey: key, Audit: audit,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	status := http.StatusOK
	if result.QueuedDeliveryID != nil {
		status = http.StatusAccepted
	}
	writeSensitiveJSON(w, status, mapNotificationSMTPHealth(result))
}

func (h *Handler) ListTenantNotificationDeliveries(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.ListTenantNotificationDeliveriesParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.notificationTenantActor(w, r, tenant)
	if !ok {
		return
	}
	page, err := notificationPage(params.After, params.Limit)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	statuses := make([]notification.DeliveryStatus, 0)
	if params.Status != nil {
		statuses = make([]notification.DeliveryStatus, len(*params.Status))
		for index, status := range *params.Status {
			statuses[index] = notification.DeliveryStatus(status)
		}
	}
	result, err := h.notifications.ListDeliveries(r.Context(), actor, tenant, notification.DeliveryListInput{
		PageInput: page, Statuses: statuses,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	items := make([]contract.NotificationDelivery, len(result.Items))
	for index, item := range result.Items {
		mapped, err := mapNotificationDeliveryFields(item)
		if err != nil {
			writeDomainError(w, r, notification.ErrUnavailable)
			return
		}
		items[index] = mapped
	}
	writeSensitiveJSON(w, http.StatusOK, contract.NotificationDeliveryList{Items: items, NextCursor: result.NextCursor})
}

func (h *Handler) GetTenantNotificationDelivery(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	deliveryID contract.NotificationDeliveryId,
) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.notificationTenantActor(w, r, tenant)
	if !ok {
		return
	}
	result, err := h.notifications.GetDelivery(r.Context(), actor, tenant, uuid.UUID(deliveryID))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapNotificationDeliveryDetail(result)
	if err != nil {
		writeDomainError(w, r, notification.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) RetryTenantNotificationDelivery(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	deliveryID contract.NotificationDeliveryId,
	_ contract.RetryTenantNotificationDeliveryParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, audit, ok := h.notificationTenantMutation(w, r, tenant)
	if !ok {
		return
	}
	key, err := notificationMutationKey(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body notificationDeliveryRetryBody
	if err := decodeNotificationBody(r, &body, "expectedAttempt", "acknowledgeUncertainSubmission", "reason"); err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.notifications.RetryDelivery(r.Context(), actor, tenant, uuid.UUID(deliveryID), notification.ManualRetryInput{
		ExpectedAttempt: body.ExpectedAttempt, AcknowledgeUncertainSubmission: body.AcknowledgeUncertainSubmission,
		Reason: body.Reason, IdempotencyKey: key, Audit: audit,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeNotificationDelivery(w, r, http.StatusCreated, result, notificationDeliveryLocation(tenant, result.ID))
}

func (h *Handler) ListTenantWebhookConfigurations(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.ListTenantWebhookConfigurationsParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.notificationTenantActor(w, r, tenant)
	if !ok {
		return
	}
	page, err := notificationPage(params.After, params.Limit)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.notifications.ListWebhooks(r.Context(), actor, tenant, page)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	items := make([]contract.WebhookConfiguration, len(result.Items))
	for index, item := range result.Items {
		items[index] = mapNotificationWebhook(item)
	}
	writeSensitiveJSON(w, http.StatusOK, contract.WebhookConfigurationList{Items: items, NextCursor: result.NextCursor})
}

func (h *Handler) CreateTenantWebhookConfiguration(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	_ contract.CreateTenantWebhookConfigurationParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, audit, ok := h.notificationTenantMutation(w, r, tenant)
	if !ok {
		return
	}
	key, err := notificationMutationKey(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body notificationWebhookBody
	if err := decodeNotificationBody(r, &body, "name", "endpointUrl", "eventTypes", "audience", "timeoutMs", "enabled"); err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.notifications.CreateWebhook(r.Context(), actor, tenant, body.input(nil, key, audit))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeNotificationWebhook(w, r, http.StatusCreated, result, notificationWebhookLocation(tenant, result.ID))
}

func (h *Handler) GetTenantWebhookConfiguration(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	webhookID contract.WebhookConfigurationId,
) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.notificationTenantActor(w, r, tenant)
	if !ok {
		return
	}
	result, err := h.notifications.GetWebhook(r.Context(), actor, tenant, uuid.UUID(webhookID))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeNotificationWebhook(w, r, http.StatusOK, result, "")
}

func (h *Handler) VersionTenantWebhookConfiguration(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	webhookID contract.WebhookConfigurationId,
	_ contract.VersionTenantWebhookConfigurationParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, audit, ok := h.notificationTenantMutation(w, r, tenant)
	if !ok {
		return
	}
	expected, err := notificationRequiredVersion(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	key, err := notificationMutationKey(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body notificationWebhookBody
	if err := decodeNotificationBody(r, &body, "name", "endpointUrl", "eventTypes", "audience", "timeoutMs", "enabled"); err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.notifications.VersionWebhook(r.Context(), actor, tenant, uuid.UUID(webhookID), body.input(expected, key, audit))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeNotificationWebhook(w, r, http.StatusOK, result, "")
}

func (h *Handler) TestTenantWebhookConfiguration(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	webhookID contract.WebhookConfigurationId,
	_ contract.TestTenantWebhookConfigurationParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, audit, ok := h.notificationTenantMutation(w, r, tenant)
	if !ok {
		return
	}
	key, err := notificationMutationKey(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body notificationWebhookTestBody
	if err := decodeNotificationBody(r, &body, "configurationVersion", "eventType", "context", "reason"); err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.notifications.TestWebhook(r.Context(), actor, tenant, uuid.UUID(webhookID), notification.WebhookTestInput{
		ConfigurationVersion: body.ConfigurationVersion, EventType: body.EventType, Context: body.Context,
		Reason: body.Reason, IdempotencyKey: key, Audit: audit,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeNotificationDelivery(w, r, http.StatusAccepted, result, "")
}
