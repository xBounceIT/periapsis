package notification

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

const (
	maximumPageSize            = 100
	maximumConditionDepth      = 8
	maximumConditionNodes      = 256
	maximumContextDepth        = 8
	maximumContextNodes        = 2_000
	maximumContextEncodedBytes = 256 * 1024
	maximumIdempotencyKeyBytes = 128
	maximumNotificationCursor  = 512
)

var (
	keyPattern           = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	conditionPathPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}(?:\.[A-Za-z][A-Za-z0-9_-]{0,63}){0,7}$`)
	languagePattern      = regexp.MustCompile(`^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$`)
	cursorPattern        = regexp.MustCompile(`^n1\.[A-Za-z0-9_-]{1,509}$`)
	hostLabelPattern     = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	dkimSelectorPattern  = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?$`)
	idempotencyPattern   = regexp.MustCompile(`^[A-Za-z0-9._~-]{16,128}$`)
)

var eventTypes = map[EventType]struct{}{
	EventAlertCreated: {}, EventAlertAssigned: {}, EventAlertClaimed: {}, EventAlertStatusChanged: {}, EventAlertEscalated: {},
	EventAlertWatcherAdded: {}, EventAlertWatcherRemoved: {},
	EventCaseCreated: {}, EventCaseAssigned: {}, EventCaseClaimed: {}, EventCaseTransferred: {}, EventCaseStatusChanged: {},
	EventCaseWatcherAdded: {}, EventCaseWatcherRemoved: {},
	EventPublicCommentAdded: {}, EventPrivateCommentAdded: {}, EventContactChanged: {}, EventSLAWarning: {}, EventSLABreached: {},
	EventTaskAssigned: {}, EventEvidenceAdded: {}, EventCustomWebhook: {},
}

func normalizePage(input PageInput) (PageInput, error) {
	if input.Limit == 0 {
		input.Limit = 50
	}
	if input.Limit < 1 || input.Limit > maximumPageSize {
		return PageInput{}, ErrInvalidInput
	}
	if input.After != nil && (len(*input.After) > maximumNotificationCursor || !cursorPattern.MatchString(*input.After)) {
		return PageInput{}, ErrInvalidInput
	}
	return input, nil
}

func normalizeRuleFields(input RuleFields) (RuleFields, error) {
	name, ok := normalizedText(input.Name, 1, 160, false)
	if !ok {
		return RuleFields{}, ErrInvalidInput
	}
	description, ok := normalizedText(input.Description, 0, 2048, true)
	if !ok || !validEventObject(input.EventType, input.ObjectType) || !validUUIDv7(input.TemplateID) ||
		input.TemplateVersion < 1 || input.TemplateVersion > 2_147_483_647 ||
		input.Channel != ChannelEmail && input.Channel != ChannelWebhook || input.Priority < 0 || input.Priority > 100 ||
		input.DelayMS < 0 || input.DelayMS > 2_592_000_000 ||
		input.DeduplicationWindowMS < 0 || input.DeduplicationWindowMS > 2_592_000_000 ||
		!validInstant(input.EffectiveFrom) || input.EffectiveUntil != nil &&
		(!validInstant(*input.EffectiveUntil) || !input.EffectiveUntil.After(input.EffectiveFrom)) {
		return RuleFields{}, ErrInvalidInput
	}
	condition, err := normalizeCondition(input.Condition)
	if err != nil {
		return RuleFields{}, err
	}
	recipients, err := normalizeRecipients(input.EventType, input.Recipients)
	if err != nil {
		return RuleFields{}, err
	}
	quietHours, err := normalizeQuietHours(input.QuietHours)
	if err != nil {
		return RuleFields{}, err
	}
	grouping, err := normalizeGrouping(input.Grouping)
	if err != nil {
		return RuleFields{}, err
	}
	retry, err := normalizeRetry(input.Retry)
	if err != nil {
		return RuleFields{}, err
	}
	return RuleFields{
		Name: name, Description: description, EventType: input.EventType, ObjectType: input.ObjectType,
		Condition: condition, Recipients: recipients, TemplateID: input.TemplateID, TemplateVersion: input.TemplateVersion,
		Channel: input.Channel, Priority: input.Priority, DelayMS: input.DelayMS, QuietHours: quietHours,
		DeduplicationWindowMS: input.DeduplicationWindowMS, Grouping: grouping, Retry: retry,
		Enabled: input.Enabled, EffectiveFrom: input.EffectiveFrom.UTC().Truncate(time.Microsecond),
		EffectiveUntil: normalizeOptionalInstant(input.EffectiveUntil),
	}, nil
}

func normalizeCondition(input Condition) (Condition, error) {
	nodes := 0
	var visit func(Condition, int) (Condition, error)
	visit = func(value Condition, depth int) (Condition, error) {
		nodes++
		if depth > maximumConditionDepth || nodes > maximumConditionNodes {
			return Condition{}, ErrInvalidInput
		}
		switch value.Kind {
		case ConditionAll, ConditionAny:
			if len(value.Children) < 1 || len(value.Children) > 64 || value.Path != "" || value.Operator != "" || len(value.Values) != 0 {
				return Condition{}, ErrInvalidInput
			}
			children := make([]Condition, len(value.Children))
			for index, child := range value.Children {
				normalized, err := visit(child, depth+1)
				if err != nil {
					return Condition{}, err
				}
				children[index] = normalized
			}
			return Condition{Kind: value.Kind, Children: children}, nil
		case ConditionNot:
			if len(value.Children) != 1 || value.Path != "" || value.Operator != "" || len(value.Values) != 0 {
				return Condition{}, ErrInvalidInput
			}
			child, err := visit(value.Children[0], depth+1)
			if err != nil {
				return Condition{}, err
			}
			return Condition{Kind: value.Kind, Children: []Condition{child}}, nil
		case ConditionPredicate:
			if len(value.Children) != 0 || len(value.Path) > 511 || !conditionPathPattern.MatchString(value.Path) ||
				unsafePath(value.Path) || !validConditionOperator(value.Operator, len(value.Values)) {
				return Condition{}, ErrInvalidInput
			}
			values := make([]json.RawMessage, len(value.Values))
			for index, literal := range value.Values {
				canonical, err := canonicalLiteral(literal)
				if err != nil {
					return Condition{}, err
				}
				values[index] = canonical
			}
			return Condition{Kind: value.Kind, Path: value.Path, Operator: value.Operator, Values: values}, nil
		default:
			return Condition{}, ErrInvalidInput
		}
	}
	return visit(input, 1)
}

func normalizeRecipients(event EventType, input []RecipientSelector) ([]RecipientSelector, error) {
	if len(input) < 1 || len(input) > 100 {
		return nil, ErrInvalidInput
	}
	result := make([]RecipientSelector, len(input))
	seen := make(map[string]struct{}, len(input))
	for index, selector := range input {
		if !validRecipientKind(selector.Kind) || selector.Audience == nil ||
			*selector.Audience != AudienceOperator && *selector.Audience != AudienceCustomer ||
			operatorOnlyEvent(event) && *selector.Audience != AudienceOperator {
			return nil, ErrInvalidInput
		}
		audience := *selector.Audience
		if requiredAudience, fixed := fixedRecipientAudience(selector.Kind); fixed {
			if audience != requiredAudience {
				return nil, ErrInvalidInput
			}
			audience = requiredAudience
		}
		normalized := RecipientSelector{Kind: selector.Kind, Audience: pointer(audience)}
		requiresValue := selector.Kind == RecipientOperatorTeam || selector.Kind == RecipientPlatformGroup ||
			selector.Kind == RecipientContactGroup || selector.Kind == RecipientContactTag ||
			selector.Kind == RecipientExplicitEmail || selector.Kind == RecipientCustomEmailField
		if requiresValue {
			if selector.Value == nil {
				return nil, ErrInvalidInput
			}
			value, ok := normalizedText(*selector.Value, 1, 320, false)
			if !ok {
				return nil, ErrInvalidInput
			}
			if selector.Kind == RecipientExplicitEmail {
				value, ok = canonicalEmail(value)
				if !ok || selector.Authorized == nil || !*selector.Authorized {
					return nil, ErrInvalidInput
				}
				normalized.Authorized = pointer(true)
			} else if selector.Authorized != nil {
				return nil, ErrInvalidInput
			}
			normalized.Value = &value
		} else if selector.Value != nil || selector.Authorized != nil {
			return nil, ErrInvalidInput
		}
		encoded, _ := json.Marshal(normalized)
		key := string(encoded)
		if _, duplicate := seen[key]; duplicate {
			return nil, ErrInvalidInput
		}
		seen[key] = struct{}{}
		result[index] = normalized
	}
	return result, nil
}

func normalizeQuietHours(input *QuietHours) (*QuietHours, error) {
	if input == nil {
		return nil, nil
	}
	zone, ok := normalizedText(input.Timezone, 1, 255, false)
	if !ok || input.StartMinute < 0 || input.StartMinute > 1439 || input.EndMinute < 0 || input.EndMinute > 1439 ||
		input.StartMinute == input.EndMinute {
		return nil, ErrInvalidInput
	}
	if _, err := time.LoadLocation(zone); err != nil {
		return nil, ErrInvalidInput
	}
	weekdays := append([]int(nil), input.Weekdays...)
	if len(weekdays) == 0 {
		weekdays = []int{0, 1, 2, 3, 4, 5, 6}
	}
	slices.Sort(weekdays)
	if len(weekdays) > 7 {
		return nil, ErrInvalidInput
	}
	for index, day := range weekdays {
		if day < 0 || day > 6 || index > 0 && weekdays[index-1] == day {
			return nil, ErrInvalidInput
		}
	}
	return &QuietHours{Timezone: zone, StartMinute: input.StartMinute, EndMinute: input.EndMinute, Weekdays: weekdays}, nil
}

func normalizeGrouping(input GroupingPolicy) (GroupingPolicy, error) {
	if input.Mode != "none" && input.Mode != "object" && input.Mode != "tenant" {
		return GroupingPolicy{}, ErrInvalidInput
	}
	if input.Mode == "none" {
		if input.WindowMS != nil && *input.WindowMS != 0 || input.MaximumItems != nil {
			return GroupingPolicy{}, ErrInvalidInput
		}
		zero := int64(0)
		return GroupingPolicy{Mode: "none", WindowMS: &zero}, nil
	}
	if input.WindowMS == nil || *input.WindowMS < 1_000 || *input.WindowMS > 2_592_000_000 ||
		input.MaximumItems == nil || *input.MaximumItems < 1 || *input.MaximumItems > 1_000 {
		return GroupingPolicy{}, ErrInvalidInput
	}
	return GroupingPolicy{Mode: input.Mode, WindowMS: pointer(*input.WindowMS), MaximumItems: pointer(*input.MaximumItems)}, nil
}

func normalizeRetry(input RetryPolicy) (RetryPolicy, error) {
	if input.MaximumAttempts < 1 || input.MaximumAttempts > 100 || input.InitialDelayMS < 1_000 ||
		input.InitialDelayMS > 86_400_000 || input.MaximumDelayMS < input.InitialDelayMS ||
		input.MaximumDelayMS > 604_800_000 || math.IsNaN(input.Multiplier) || math.IsInf(input.Multiplier, 0) ||
		input.Multiplier < 1 || input.Multiplier > 10 || input.JitterPercent < 0 || input.JitterPercent > 100 {
		return RetryPolicy{}, ErrInvalidInput
	}
	return input, nil
}

func normalizeTemplateFields(input TemplateFields) (TemplateFields, error) {
	key := strings.TrimSpace(input.Key)
	name, nameOK := normalizedText(input.Name, 1, 160, false)
	language := strings.TrimSpace(input.Language)
	if !keyPattern.MatchString(key) || !nameOK || len(language) > 35 || !languagePattern.MatchString(language) ||
		!validBody(input.Subject, 1, 998) || !validBody(input.HTML, 1, 262_144) ||
		input.PlainText != nil && !validBody(*input.PlainText, 0, 262_144) ||
		input.CSS != nil && !validBody(*input.CSS, 0, 65_536) {
		return TemplateFields{}, ErrInvalidInput
	}
	context, err := normalizeContext(input.SampleData)
	if err != nil {
		return TemplateFields{}, err
	}
	return TemplateFields{
		Key: key, Name: name, Language: language, Subject: input.Subject, HTML: input.HTML,
		PlainText: cloneString(input.PlainText), CSS: cloneString(input.CSS), SampleData: context,
	}, nil
}

func normalizeSMTPWrite(input SMTPWriteInput, allowPlainLocal bool) (SMTPWriteInput, error) {
	name, nameOK := normalizedText(input.Name, 1, 160, false)
	host, hostOK := canonicalSMTPHost(input.Host, input.Security == SMTPPlainLocal && allowPlainLocal)
	fromName, fromNameOK := normalizedText(input.FromName, 1, 160, false)
	fromEmail, fromEmailOK := canonicalEmail(input.FromEmail)
	if !nameOK || !hostOK || !fromNameOK || !fromEmailOK || input.Port < 1 || input.Port > 65_535 ||
		!validSMTPSecurity(input.Security) || input.Security == SMTPPlainLocal &&
		!allowPlainLocal || input.TimeoutMS < 1_000 || input.TimeoutMS > 120_000 ||
		input.MaximumConnections < 1 || input.MaximumConnections > 100 || input.MaximumMessagesPerConnection < 1 ||
		input.MaximumMessagesPerConnection > 10_000 || input.RateLimitPerSecond < 1 || input.RateLimitPerSecond > 10_000 ||
		input.ClearPassword && input.Password != nil || input.ClearDKIM && input.DKIM != nil ||
		input.ExpectedVersion != nil && (*input.ExpectedVersion < 1 || *input.ExpectedVersion > 2_147_483_647) ||
		!validIdempotency(input.IdempotencyKey) || !validAudit(input.Audit) {
		return SMTPWriteInput{}, ErrInvalidInput
	}
	username, err := normalizeOptionalText(input.Username, 1, 320, false)
	if err != nil || input.ClearPassword && username != nil || input.Password != nil && username == nil {
		return SMTPWriteInput{}, ErrInvalidInput
	}
	password, err := normalizeSecretString(input.Password, 1, 16_384)
	if err != nil {
		return SMTPWriteInput{}, err
	}
	replyTo, err := normalizeOptionalEmail(input.ReplyToEmail)
	if err != nil {
		return SMTPWriteInput{}, err
	}
	dkim, err := normalizeDKIM(input.DKIM)
	if err != nil {
		return SMTPWriteInput{}, err
	}
	return SMTPWriteInput{
		Name: name, Host: host, Port: input.Port, Security: input.Security, Username: username,
		Password: password, ClearPassword: input.ClearPassword, FromName: fromName, FromEmail: fromEmail,
		ReplyToEmail: replyTo, TimeoutMS: input.TimeoutMS, MaximumConnections: input.MaximumConnections,
		MaximumMessagesPerConnection: input.MaximumMessagesPerConnection, RateLimitPerSecond: input.RateLimitPerSecond,
		DKIM: dkim, ClearDKIM: input.ClearDKIM, Enabled: input.Enabled, ExpectedVersion: cloneInt64(input.ExpectedVersion),
		IdempotencyKey: input.IdempotencyKey, Audit: input.Audit,
	}, nil
}

func canonicalSMTPHost(input string, allowDevelopmentServiceName bool) (string, bool) {
	host, ok := canonicalHost(input)
	if ok {
		return host, true
	}
	host = strings.ToLower(strings.TrimSpace(input))
	if allowDevelopmentServiceName && len(host) <= 63 && hostLabelPattern.MatchString(host) {
		return host, true
	}
	return "", false
}

func normalizeWebhookWrite(input WebhookWriteInput, allowPlainLocal bool) (WebhookWriteInput, error) {
	name, nameOK := normalizedText(input.Name, 1, 160, false)
	endpoint, endpointOK := canonicalWebhookURL(input.EndpointURL, allowPlainLocal)
	if !nameOK || !endpointOK || len(input.EventTypes) < 1 || len(input.EventTypes) > len(eventTypes) ||
		input.Audience != AudienceOperator && input.Audience != AudienceCustomer || input.TimeoutMS < 1_000 ||
		input.TimeoutMS > 120_000 || input.ExpectedVersion != nil &&
		(*input.ExpectedVersion < 1 || *input.ExpectedVersion > 2_147_483_647) ||
		!validIdempotency(input.IdempotencyKey) || !validAudit(input.Audit) {
		return WebhookWriteInput{}, ErrInvalidInput
	}
	events := append([]EventType(nil), input.EventTypes...)
	slices.Sort(events)
	for index, event := range events {
		if _, ok := eventTypes[event]; !ok || index > 0 && events[index-1] == event ||
			operatorOnlyEvent(event) && input.Audience == AudienceCustomer {
			return WebhookWriteInput{}, ErrInvalidInput
		}
	}
	key, err := normalizeSecretString(input.SigningKey, 32, 4_096)
	if err != nil {
		return WebhookWriteInput{}, err
	}
	return WebhookWriteInput{
		Name: name, EndpointURL: endpoint, EventTypes: events, Audience: input.Audience, SigningKey: key,
		TimeoutMS: input.TimeoutMS, Enabled: input.Enabled, ExpectedVersion: cloneInt64(input.ExpectedVersion),
		IdempotencyKey: input.IdempotencyKey, Audit: input.Audit,
	}, nil
}

func normalizeContext(input map[string]any) (map[string]any, error) {
	if input == nil {
		return map[string]any{}, nil
	}
	nodes := 0
	var visit func(any, int) (any, error)
	visit = func(value any, depth int) (any, error) {
		nodes++
		if depth > maximumContextDepth || nodes > maximumContextNodes {
			return nil, ErrInvalidInput
		}
		switch typed := value.(type) {
		case nil, bool, string:
			if text, ok := typed.(string); ok && !validBody(text, 0, 8_192) {
				return nil, ErrInvalidInput
			}
			return typed, nil
		case float64:
			if math.IsNaN(typed) || math.IsInf(typed, 0) {
				return nil, ErrInvalidInput
			}
			return typed, nil
		case json.Number:
			if _, err := typed.Float64(); err != nil {
				return nil, ErrInvalidInput
			}
			return typed, nil
		case []any:
			if len(typed) > 1_000 {
				return nil, ErrInvalidInput
			}
			result := make([]any, len(typed))
			for index, item := range typed {
				normalized, err := visit(item, depth+1)
				if err != nil {
					return nil, err
				}
				result[index] = normalized
			}
			return result, nil
		case map[string]any:
			if len(typed) > 100 {
				return nil, ErrInvalidInput
			}
			result := make(map[string]any, len(typed))
			for key, item := range typed {
				if !validContextKey(key) {
					return nil, ErrInvalidInput
				}
				normalized, err := visit(item, depth+1)
				if err != nil {
					return nil, err
				}
				result[key] = normalized
			}
			return result, nil
		default:
			return nil, ErrInvalidInput
		}
	}
	normalized, err := visit(input, 1)
	if err != nil {
		return nil, err
	}
	result := normalized.(map[string]any)
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > maximumContextEncodedBytes {
		return nil, ErrInvalidInput
	}
	return result, nil
}

func validRule(value Rule, tenantID uuid.UUID) bool {
	if value.ID.Version() != 7 || value.TenantID != tenantID || value.Version < 1 || !validUUIDv7(value.CreatedBy) ||
		!validInstant(value.CreatedAt) {
		return false
	}
	_, err := normalizeRuleFields(value.RuleFields)
	return err == nil
}

func validTemplate(value Template, tenantID uuid.UUID) bool {
	if value.ID.Version() != 7 || value.TenantID != tenantID || value.Version < 1 || !validUUIDv7(value.CreatedBy) ||
		!validInstant(value.CreatedAt) || len(value.Placeholders) > 512 || !slices.IsSorted(value.Placeholders) {
		return false
	}
	for index, placeholder := range value.Placeholders {
		if len(placeholder) > 511 || !conditionPathPattern.MatchString(placeholder) || unsafePath(placeholder) ||
			index > 0 && value.Placeholders[index-1] == placeholder {
			return false
		}
	}
	_, err := normalizeTemplateFields(value.TemplateFields)
	return err == nil
}

func validSMTP(value SMTPConfiguration, tenantID *uuid.UUID) bool {
	if !validUUIDv7(value.ID) || value.Version < 1 || !validUUIDv7(value.CreatedBy) || !validInstant(value.CreatedAt) {
		return false
	}
	if tenantID == nil {
		if value.TenantID != nil || value.InheritedFromGlobal {
			return false
		}
	} else if value.InheritedFromGlobal {
		if value.TenantID != nil {
			return false
		}
	} else if value.TenantID == nil || *value.TenantID != *tenantID {
		return false
	}
	if (value.Username == nil) != !value.PasswordConfigured ||
		value.DKIM != nil && !value.DKIM.PrivateKeyConfigured {
		return false
	}
	_, err := normalizeSMTPWrite(SMTPWriteInput{
		Name: value.Name, Host: value.Host, Port: value.Port, Security: value.Security, Username: value.Username,
		FromName: value.FromName, FromEmail: value.FromEmail, ReplyToEmail: value.ReplyToEmail, TimeoutMS: value.TimeoutMS,
		MaximumConnections: value.MaximumConnections, MaximumMessagesPerConnection: value.MaximumMessagesPerConnection,
		RateLimitPerSecond: value.RateLimitPerSecond, Enabled: value.Enabled,
		DKIM: dkimProjectionAsWrite(value.DKIM), IdempotencyKey: "projection-valid", Audit: authorization.AuditContext{},
	}, value.Security == SMTPPlainLocal)
	return err == nil
}

func validWebhook(value WebhookConfiguration, tenantID uuid.UUID) bool {
	if !validUUIDv7(value.ID) || value.TenantID != tenantID || value.Version < 1 || value.SigningKeyVersion < 1 ||
		!value.SigningKeyConfigured || !validUUIDv7(value.CreatedBy) || !validInstant(value.CreatedAt) {
		return false
	}
	_, err := normalizeWebhookWrite(WebhookWriteInput{
		Name: value.Name, EndpointURL: value.EndpointURL, EventTypes: value.EventTypes, Audience: value.Audience,
		TimeoutMS: value.TimeoutMS, Enabled: value.Enabled, IdempotencyKey: "projection-valid",
	}, strings.HasPrefix(value.EndpointURL, "http://"))
	return err == nil
}

func validDelivery(value Delivery, tenantID uuid.UUID, includeAttempts bool) bool {
	if !validUUIDv7(value.ID) || value.TenantID != tenantID || !validUUIDv7(value.EventID) ||
		value.Channel != ChannelEmail && value.Channel != ChannelWebhook ||
		value.Audience != AudienceOperator && value.Audience != AudienceCustomer || !validDeliveryStatus(value.Status) ||
		!validRedactedDestination(value.DestinationRedacted) || value.AttemptCount < 0 || value.AttemptCount > 100 ||
		value.MaximumAttempts < 1 || value.MaximumAttempts > 100 || value.AttemptCount > value.MaximumAttempts ||
		!validInstant(value.CreatedAt) || !validOptionalInstant(value.NextAttemptAt) || !validOptionalInstant(value.DeliveredAt) ||
		!validOptionalInstant(value.FailureAt) || value.FailureClass != nil && !validFailureClass(*value.FailureClass) ||
		!validOptionalUUIDv7(value.ParentDeliveryID) || !validOptionalUUIDv7(value.RuleID) || !validOptionalUUIDv7(value.TemplateID) ||
		!validOptionalUUIDv7(value.SMTPConfigurationID) || !validOptionalUUIDv7(value.WebhookConfigurationID) ||
		!validOptionalVersion(value.RuleVersion) || !validOptionalVersion(value.TemplateVersion) ||
		!validOptionalVersion(value.SMTPConfigurationVersion) || !validOptionalVersion(value.WebhookConfigurationVersion) ||
		!validOptionalVersion(value.WebhookSigningKeyVersion) || !validDeliveryPins(value) || !validDeliveryLifecycle(value) {
		return false
	}
	if !includeAttempts {
		return len(value.Attempts) == 0
	}
	if len(value.Attempts) > 100 || len(value.Attempts) != value.AttemptCount {
		return false
	}
	for index, attempt := range value.Attempts {
		if attempt.Number != index+1 || !validInstant(attempt.StartedAt) || !validOptionalInstant(attempt.CompletedAt) ||
			!validAttemptOutcome(attempt.Outcome) || attempt.FailureClass != nil && !validFailureClass(*attempt.FailureClass) ||
			attempt.ProviderReceipt != nil && !validProviderReceipt(*attempt.ProviderReceipt) ||
			attempt.StartedAt.Before(value.CreatedAt) || attempt.CompletedAt != nil && attempt.CompletedAt.Before(attempt.StartedAt) {
			return false
		}
		if !validAttemptSemantics(value, attempt, index) {
			return false
		}
	}
	return true
}

func validAttemptSemantics(delivery Delivery, attempt DeliveryAttempt, index int) bool {
	switch attempt.Outcome {
	case "in_progress":
		return attempt.CompletedAt == nil && attempt.FailureClass == nil && attempt.ProviderReceipt == nil &&
			index == len(delivery.Attempts)-1 &&
			(delivery.Status == DeliveryLeased || delivery.Status == DeliveryReserved)
	case "delivered":
		return attempt.CompletedAt != nil && attempt.FailureClass == nil && attempt.ProviderReceipt != nil &&
			attempt.ProviderReceipt.Provider == deliveryReceiptProvider(delivery.Channel)
	case "replayed":
		return attempt.CompletedAt != nil && attempt.FailureClass == nil && attempt.ProviderReceipt == nil
	case "retried", "dead_lettered":
		return attempt.CompletedAt != nil && attempt.FailureClass != nil && *attempt.FailureClass != FailureSubmissionUncertain &&
			attempt.ProviderReceipt == nil
	case "uncertain":
		return attempt.CompletedAt != nil && attempt.FailureClass != nil && *attempt.FailureClass == FailureSubmissionUncertain &&
			attempt.ProviderReceipt == nil
	case "fenced":
		return attempt.CompletedAt != nil && attempt.ProviderReceipt == nil
	default:
		return false
	}
}

func deliveryReceiptProvider(channel Channel) string {
	if channel == ChannelEmail {
		return "smtp"
	}
	if channel == ChannelWebhook {
		return "webhook"
	}
	return ""
}

func validEventObject(event EventType, object ObjectType) bool {
	if _, ok := eventTypes[event]; !ok {
		return false
	}
	switch {
	case strings.HasPrefix(string(event), "alert."):
		return object == ObjectAlert
	case strings.HasPrefix(string(event), "case."):
		return object == ObjectCase
	case strings.HasPrefix(string(event), "comment."), strings.HasPrefix(string(event), "sla."):
		return object == ObjectAlert || object == ObjectCase
	case event == EventTaskAssigned:
		return object == ObjectTask
	case event == EventEvidenceAdded:
		return object == ObjectEvidence
	case event == EventContactChanged:
		return object == ObjectContact
	case event == EventCustomWebhook:
		return object == ObjectAlert || object == ObjectCase || object == ObjectTask || object == ObjectEvidence || object == ObjectContact
	default:
		return false
	}
}

func operatorOnlyEvent(event EventType) bool {
	switch event {
	case EventAlertWatcherAdded, EventAlertWatcherRemoved,
		EventCaseWatcherAdded, EventCaseWatcherRemoved,
		EventPrivateCommentAdded:
		return true
	default:
		return false
	}
}

func validConditionOperator(operator ConditionOperator, values int) bool {
	switch operator {
	case OperatorExists, OperatorNotExists:
		return values == 0
	case OperatorEquals, OperatorNotEquals, OperatorContains:
		return values == 1
	case OperatorOneOf, OperatorNoneOf:
		return values >= 1 && values <= 100
	default:
		return false
	}
}

func canonicalLiteral(input json.RawMessage) (json.RawMessage, error) {
	if len(input) == 0 || len(input) > 8_192 {
		return nil, ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, ErrInvalidInput
	}
	switch typed := value.(type) {
	case bool:
	case string:
		if !validBody(typed, 0, 8_192) {
			return nil, ErrInvalidInput
		}
	case json.Number:
		parsed, err := typed.Float64()
		if err != nil || math.IsInf(parsed, 0) || math.IsNaN(parsed) {
			return nil, ErrInvalidInput
		}
	default:
		return nil, ErrInvalidInput
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return encoded, nil
}

func canonicalEmail(input string) (string, bool) {
	input = strings.TrimSpace(input)
	if len(input) < 3 || len(input) > 320 || strings.ContainsAny(input, "\r\n") {
		return "", false
	}
	address, err := mail.ParseAddress(input)
	if err != nil || address.Name != "" || address.Address != input {
		return "", false
	}
	at := strings.LastIndexByte(input, '@')
	if at < 1 || at == len(input)-1 {
		return "", false
	}
	domain, ok := canonicalHost(input[at+1:])
	if !ok || net.ParseIP(domain) != nil {
		return "", false
	}
	return input[:at+1] + domain, true
}

func canonicalHost(input string) (string, bool) {
	input = strings.ToLower(strings.TrimSpace(input))
	if len(input) < 1 || len(input) > 253 || strings.HasSuffix(input, ".") || strings.ContainsAny(input, "\x00\r\n\t /@[]") {
		if address, err := netip.ParseAddr(input); err == nil {
			return address.Unmap().String(), true
		}
		return "", false
	}
	if address, err := netip.ParseAddr(input); err == nil {
		return address.Unmap().String(), true
	}
	labels := strings.Split(input, ".")
	if len(labels) < 2 {
		if input == "localhost" {
			return input, true
		}
		return "", false
	}
	for _, label := range labels {
		if !hostLabelPattern.MatchString(label) {
			return "", false
		}
	}
	return input, true
}

func canonicalWebhookURL(input string, allowPlainLocal bool) (string, bool) {
	if len(input) < 1 || len(input) > 2_048 || strings.ContainsAny(input, "\x00\r\n\t") {
		return "", false
	}
	parsed, err := url.Parse(input)
	if err != nil || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || parsed.Opaque != "" ||
		parsed.Hostname() == "" || parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", false
	}
	rawHost := strings.ToLower(parsed.Hostname())
	host, ok := canonicalHost(rawHost)
	if !ok || parsed.Scheme == "http" && (!allowPlainLocal || !isLoopbackHost(rawHost)) {
		return "", false
	}
	port := parsed.Port()
	if port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65_535 {
			return "", false
		}
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	parsed.Host = host
	if strings.Contains(host, ":") {
		parsed.Host = "[" + host + "]"
	}
	if port != "" {
		parsed.Host += ":" + port
	}
	return parsed.String(), true
}

func normalizeDKIM(input *DKIMWriteInput) (*DKIMWriteInput, error) {
	if input == nil {
		return nil, nil
	}
	domain, ok := canonicalHost(input.DomainName)
	selector, selectorOK := normalizedText(input.Selector, 1, 63, false)
	if !ok || !selectorOK || !dkimSelectorPattern.MatchString(selector) {
		return nil, ErrInvalidInput
	}
	privateKey, err := normalizeSecretString(input.PrivateKey, 1, 65_536)
	if err != nil {
		return nil, err
	}
	return &DKIMWriteInput{DomainName: domain, Selector: selector, PrivateKey: privateKey}, nil
}

func validRecipientKind(value RecipientKind) bool {
	switch value {
	case RecipientAssignee, RecipientPreviousAssignee, RecipientOperatorTeam, RecipientWatcher, RecipientMentioned, RecipientActor,
		RecipientTenantAdmin, RecipientPlatformGroup, RecipientCustomerContacts, RecipientContactGroup,
		RecipientContactTag, RecipientExplicitEmail, RecipientCustomEmailField:
		return true
	default:
		return false
	}
}

func fixedRecipientAudience(value RecipientKind) (Audience, bool) {
	switch value {
	case RecipientAssignee, RecipientPreviousAssignee, RecipientOperatorTeam, RecipientWatcher,
		RecipientMentioned, RecipientTenantAdmin, RecipientPlatformGroup:
		return AudienceOperator, true
	case RecipientCustomerContacts, RecipientContactGroup, RecipientContactTag:
		return AudienceCustomer, true
	default:
		return "", false
	}
}

func validSMTPSecurity(value SMTPSecurity) bool {
	return value == SMTPTLS || value == SMTPStartTLS || value == SMTPPlainLocal
}

func validIdempotency(value string) bool {
	return len(value) <= maximumIdempotencyKeyBytes && idempotencyPattern.MatchString(value)
}

func validAudit(value authorization.AuditContext) bool {
	return (value.RequestID == uuid.Nil || value.RequestID.Variant() == uuid.RFC4122) &&
		(value.CorrelationID == uuid.Nil || value.CorrelationID.Variant() == uuid.RFC4122) &&
		(!value.RemoteAddress.IsValid() || value.RemoteAddress.Zone() == "" && !value.RemoteAddress.Is4In6()) &&
		validText(value.UserAgent, 0, 1_024, false)
}

func validMutationAudit(value authorization.AuditContext) bool {
	return value.RequestID != uuid.Nil && value.CorrelationID != uuid.Nil && validAudit(value)
}

func validContextKey(value string) bool {
	return validText(value, 1, 128, false) && value != "__proto__" && value != "prototype" && value != "constructor"
}

func unsafePath(value string) bool {
	for _, part := range strings.Split(value, ".") {
		if part == "__proto__" || part == "prototype" || part == "constructor" {
			return true
		}
	}
	return false
}

func normalizedText(value string, minimum, maximum int, preserve bool) (string, bool) {
	if !preserve {
		value = strings.TrimSpace(value)
	}
	return value, validText(value, minimum, maximum, preserve)
}

func validText(value string, minimum, maximum int, allowNewlines bool) bool {
	if !utf8.ValidString(value) {
		return false
	}
	length := utf8.RuneCountInString(value)
	if length < minimum || length > maximum {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) && (!allowNewlines || character != '\n' && character != '\r' && character != '\t') {
			return false
		}
	}
	return true
}

func validBody(value string, minimum, maximum int) bool {
	return validText(value, minimum, maximum, true)
}

func normalizeOptionalText(value *string, minimum, maximum int, preserve bool) (*string, error) {
	if value == nil {
		return nil, nil
	}
	normalized, ok := normalizedText(*value, minimum, maximum, preserve)
	if !ok {
		return nil, ErrInvalidInput
	}
	return &normalized, nil
}

func normalizeOptionalEmail(value *string) (*string, error) {
	if value == nil {
		return nil, nil
	}
	normalized, ok := canonicalEmail(*value)
	if !ok {
		return nil, ErrInvalidInput
	}
	return &normalized, nil
}

func normalizeSecretString(value *string, minimum, maximum int) (*string, error) {
	if value == nil {
		return nil, nil
	}
	if !validBody(*value, minimum, maximum) {
		return nil, ErrInvalidInput
	}
	copy := strings.Clone(*value)
	return &copy, nil
}

func validInstant(value time.Time) bool {
	// PostgreSQL JSON uses +00:00, which Go may decode with a local or fixed
	// zero-offset location rather than the time.UTC pointer.
	_, offset := value.Zone()
	return !value.IsZero() && offset == 0 && value.Nanosecond()%1_000 == 0
}

func normalizeOptionalInstant(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	normalized := value.UTC().Truncate(time.Microsecond)
	return &normalized
}

func validOptionalInstant(value *time.Time) bool { return value == nil || validInstant(*value) }

func validUUIDv7(value uuid.UUID) bool {
	return value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validOptionalUUIDv7(value *uuid.UUID) bool { return value == nil || validUUIDv7(*value) }

func validOptionalVersion(value *int64) bool {
	return value == nil || *value >= 1 && *value <= 2_147_483_647
}

func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func dkimProjectionAsWrite(value *DKIMConfiguration) *DKIMWriteInput {
	if value == nil {
		return nil
	}
	return &DKIMWriteInput{DomainName: value.DomainName, Selector: value.Selector}
}

func validDeliveryStatus(value DeliveryStatus) bool {
	return value == DeliveryQueued || value == DeliveryLeased || value == DeliveryReserved ||
		value == DeliveryRetryScheduled || value == DeliveryDelivered || value == DeliveryDeadLettered
}

func validFailureClass(value FailureClass) bool {
	return value == FailureAuthentication || value == FailureConnectivity || value == FailureRateLimited ||
		value == FailureRender || value == FailureSecurity || value == FailureTimeout || value == FailureTLS ||
		value == FailureUnknown || value == FailureSubmissionUncertain
}

func validAttemptOutcome(value string) bool {
	return value == "in_progress" || value == "delivered" || value == "replayed" || value == "retried" || value == "dead_lettered" ||
		value == "uncertain" || value == "fenced"
}

func validProviderReceipt(value ProviderReceipt) bool {
	if len(value.ReceiptDigest) != 64 {
		return false
	}
	for _, character := range value.ReceiptDigest {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	if value.Provider == "smtp" {
		return value.AcceptedCount != nil && *value.AcceptedCount == 1 &&
			value.RejectedCount != nil && *value.RejectedCount == 0 && value.StatusCode == nil &&
			(value.ResponseClass == nil || *value.ResponseClass == 2)
	}
	return value.Provider == "webhook" && value.StatusCode != nil && *value.StatusCode >= 200 && *value.StatusCode <= 299 &&
		value.AcceptedCount == nil && value.RejectedCount == nil && value.ResponseClass == nil
}

func validDeliveryPins(value Delivery) bool {
	if (value.RuleID == nil) != (value.RuleVersion == nil) ||
		(value.TemplateID == nil) != (value.TemplateVersion == nil) ||
		value.ParentDeliveryID != nil && *value.ParentDeliveryID == value.ID {
		return false
	}
	if value.Channel == ChannelEmail {
		return value.SMTPConfigurationID != nil && value.SMTPConfigurationVersion != nil &&
			value.SMTPConfigurationScope != nil && (*value.SMTPConfigurationScope == SMTPConfigurationTenant || *value.SMTPConfigurationScope == SMTPConfigurationPlatform) &&
			value.WebhookConfigurationID == nil && value.WebhookConfigurationVersion == nil && value.WebhookSigningKeyVersion == nil
	}
	return value.WebhookConfigurationID != nil && value.WebhookConfigurationVersion != nil && value.WebhookSigningKeyVersion != nil &&
		value.SMTPConfigurationID == nil && value.SMTPConfigurationVersion == nil && value.SMTPConfigurationScope == nil
}

func validDeliveryLifecycle(value Delivery) bool {
	for _, instant := range []*time.Time{value.NextAttemptAt, value.DeliveredAt, value.FailureAt} {
		if instant != nil && instant.Before(value.CreatedAt) {
			return false
		}
	}
	switch value.Status {
	case DeliveryQueued, DeliveryLeased, DeliveryReserved:
		return value.DeliveredAt == nil && value.FailureAt == nil && value.FailureClass == nil
	case DeliveryRetryScheduled:
		return value.NextAttemptAt != nil && value.DeliveredAt == nil && value.FailureAt == nil && value.FailureClass == nil
	case DeliveryDelivered:
		return value.NextAttemptAt == nil && value.DeliveredAt != nil && value.FailureAt == nil && value.FailureClass == nil
	case DeliveryDeadLettered:
		return value.NextAttemptAt == nil && value.DeliveredAt == nil && value.FailureAt != nil && value.FailureClass != nil
	default:
		return false
	}
}

func validRedactedDestination(value string) bool {
	if !validText(value, 3, 320, false) || strings.Contains(value, "://") {
		return false
	}
	if strings.HasPrefix(value, "webhook:") {
		hint := strings.TrimSuffix(strings.TrimPrefix(value, "webhook:"), "…")
		return len(hint) == 8 && !strings.ContainsAny(hint, "@:/")
	}
	at := strings.LastIndexByte(value, '@')
	if at < 4 || at == len(value)-1 || !strings.HasSuffix(value[:at], "***") || utf8.RuneCountInString(value[:at]) != 4 {
		return false
	}
	domain, ok := canonicalHost(value[at+1:])
	return ok && net.ParseIP(domain) == nil && domain == value[at+1:]
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	copy := strings.Clone(*value)
	return &copy
}

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	return pointer(*value)
}

func pointer[T any](value T) *T { return &value }
