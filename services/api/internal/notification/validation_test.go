package notification

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCanonicalWebhookURLNormalizesRootAndRejectsUnsafeForms(t *testing.T) {
	got, ok := canonicalWebhookURL("https://Example.COM", false)
	if !ok || got != "https://example.com/" {
		t.Fatalf("canonicalWebhookURL() = %q, %v", got, ok)
	}

	for _, candidate := range []string{
		"http://example.com/",
		"https://user@example.com/",
		"https://example.com/?token=secret",
		"https://example.com/#fragment",
		"javascript:alert(1)",
	} {
		if value, accepted := canonicalWebhookURL(candidate, false); accepted {
			t.Fatalf("unsafe webhook URL accepted: %q as %q", candidate, value)
		}
	}

	if got, ok := canonicalWebhookURL("http://127.0.0.1:8080/hooks", true); !ok || got != "http://127.0.0.1:8080/hooks" {
		t.Fatalf("explicit loopback development URL = %q, %v", got, ok)
	}
	for _, candidate := range []string{
		"http://127.0.0.2:8080/hooks",
		"http://127.255.255.254:8080/hooks",
		"http://[0:0:0:0:0:0:0:1]:8080/hooks",
	} {
		if value, accepted := canonicalWebhookURL(candidate, true); accepted {
			t.Fatalf("non-canonical loopback alias accepted: %q as %q", candidate, value)
		}
	}
}

func TestNotificationConditionsAndContextFailClosed(t *testing.T) {
	condition, err := normalizeCondition(Condition{
		Kind: ConditionPredicate, Path: "alert.custom.severity", Operator: OperatorEquals,
		Values: []json.RawMessage{json.RawMessage(` 1.0 `)},
	})
	if err != nil || string(condition.Values[0]) != "1.0" {
		t.Fatalf("normalizeCondition() = %#v, %v", condition, err)
	}

	for _, candidate := range []Condition{
		{Kind: ConditionPredicate, Path: "alert.__proto__.value", Operator: OperatorExists},
		{Kind: ConditionPredicate, Path: "alert.id", Operator: OperatorExists, Values: []json.RawMessage{json.RawMessage(`true`)}},
		{Kind: ConditionPredicate, Path: "alert.id", Operator: OperatorEquals, Values: []json.RawMessage{json.RawMessage(`null`)}},
		{Kind: ConditionAll},
	} {
		if _, err := normalizeCondition(candidate); err == nil {
			t.Fatalf("invalid condition accepted: %#v", candidate)
		}
	}

	if _, err := normalizeContext(map[string]any{"constructor": "pollute"}); err == nil {
		t.Fatal("unsafe context key accepted")
	}
	if _, err := normalizeContext(map[string]any{"large": strings.Repeat("x", 8_193)}); err == nil {
		t.Fatal("oversized context value accepted")
	}
}

func TestOperatorOnlyEventRecipientsAndWebhooksRejectCustomerAudience(t *testing.T) {
	t.Parallel()

	operator := AudienceOperator
	customer := AudienceCustomer
	authorized := true
	email := "Security@Example.COM"

	for _, event := range []EventType{
		EventAlertWatcherAdded,
		EventAlertWatcherRemoved,
		EventCaseWatcherAdded,
		EventCaseWatcherRemoved,
		EventPrivateCommentAdded,
	} {
		got, err := normalizeRecipients(event, []RecipientSelector{{
			Kind: RecipientExplicitEmail, Value: &email, Authorized: &authorized, Audience: &operator,
		}})
		if err != nil || got[0].Value == nil || *got[0].Value != "Security@example.com" {
			t.Fatalf("normalizeRecipients(%q) = %#v, %v", event, got, err)
		}
		if _, err := normalizeRecipients(event, []RecipientSelector{{
			Kind: RecipientCustomerContacts, Audience: &customer,
		}}); err == nil {
			t.Fatalf("customer recipient accepted for operator-only event %q", event)
		}
		if _, err := normalizeWebhookWrite(webhookWriteFixture(t, event, AudienceCustomer), false); err == nil {
			t.Fatalf("customer webhook accepted for operator-only event %q", event)
		}
		if _, err := normalizeWebhookWrite(webhookWriteFixture(t, event, AudienceOperator), false); err != nil {
			t.Fatalf("operator webhook rejected for operator-only event %q: %v", event, err)
		}
	}

	if _, err := normalizeRecipients(EventPrivateCommentAdded, []RecipientSelector{{
		Kind: RecipientExplicitEmail, Value: &email, Audience: &operator,
	}}); err == nil {
		t.Fatal("unauthorized explicit email accepted")
	}
	if _, err := normalizeRecipients(EventPrivateCommentAdded, []RecipientSelector{{
		Kind: RecipientAssignee,
	}}); err == nil {
		t.Fatal("recipient without an audience accepted")
	}
}

func TestRecipientKindAudienceAndValueMatrix(t *testing.T) {
	t.Parallel()

	operator := AudienceOperator
	customer := AudienceCustomer
	value := "soc"
	for _, kind := range []RecipientKind{
		RecipientAssignee, RecipientPreviousAssignee, RecipientWatcher, RecipientMentioned,
		RecipientTenantAdmin, RecipientPlatformGroup,
	} {
		selector := RecipientSelector{Kind: kind, Audience: &operator}
		if kind == RecipientPlatformGroup {
			selector.Value = &value
		}
		if _, err := normalizeRecipients(EventPublicCommentAdded, []RecipientSelector{selector}); err != nil {
			t.Fatalf("operator recipient %q rejected: %v", kind, err)
		}
		selector.Audience = &customer
		if _, err := normalizeRecipients(EventPublicCommentAdded, []RecipientSelector{selector}); err == nil {
			t.Fatalf("operator recipient %q accepted customer audience", kind)
		}
	}
	for _, kind := range []RecipientKind{RecipientCustomerContacts, RecipientContactGroup, RecipientContactTag} {
		selector := RecipientSelector{Kind: kind, Audience: &customer}
		if kind != RecipientCustomerContacts {
			selector.Value = &value
		}
		if _, err := normalizeRecipients(EventPublicCommentAdded, []RecipientSelector{selector}); err != nil {
			t.Fatalf("customer recipient %q rejected: %v", kind, err)
		}
		selector.Audience = &operator
		if _, err := normalizeRecipients(EventPublicCommentAdded, []RecipientSelector{selector}); err == nil {
			t.Fatalf("customer recipient %q accepted operator audience", kind)
		}
	}
	if _, err := normalizeRecipients(EventPublicCommentAdded, []RecipientSelector{{
		Kind: RecipientOperatorTeam, Audience: &operator,
	}}); err == nil {
		t.Fatal("operator_team without value accepted")
	}
	if _, err := normalizeRecipients(EventPublicCommentAdded, []RecipientSelector{{
		Kind: RecipientMentioned, Audience: &operator, Value: &value,
	}}); err == nil {
		t.Fatal("mentioned with value accepted")
	}
}

func TestWatcherEventsAreBoundToTheirTicketKind(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		event  EventType
		object ObjectType
	}{
		{EventAlertWatcherAdded, ObjectAlert},
		{EventAlertWatcherRemoved, ObjectAlert},
		{EventCaseWatcherAdded, ObjectCase},
		{EventCaseWatcherRemoved, ObjectCase},
	} {
		if !validEventObject(test.event, test.object) {
			t.Fatalf("validEventObject(%q, %q) = false", test.event, test.object)
		}
		wrong := ObjectAlert
		if test.object == ObjectAlert {
			wrong = ObjectCase
		}
		if validEventObject(test.event, wrong) {
			t.Fatalf("validEventObject(%q, %q) crossed ticket kind", test.event, wrong)
		}
	}
}

func TestSanitizedSMTPProjectionHasExactScopeAndSecretFlags(t *testing.T) {
	tenantID := mustV7(t)
	configuration := validSMTPFixture(t)
	configuration.TenantID = &tenantID
	if !validSMTP(configuration, &tenantID) {
		t.Fatal("valid tenant SMTP projection rejected")
	}

	otherTenant := mustV7(t)
	if validSMTP(configuration, &otherTenant) || validSMTP(configuration, nil) {
		t.Fatal("tenant SMTP projection crossed scope")
	}

	global := validSMTPFixture(t)
	global.InheritedFromGlobal = true
	if !validSMTP(global, &tenantID) || validSMTP(global, nil) {
		t.Fatal("inherited global projection scope was not enforced")
	}
	global.InheritedFromGlobal = false
	if !validSMTP(global, nil) {
		t.Fatal("platform global SMTP projection rejected")
	}

	username := "mailer"
	configuration.Username = &username
	configuration.PasswordConfigured = false
	if validSMTP(configuration, &tenantID) {
		t.Fatal("username without a configured password accepted")
	}
	configuration.PasswordConfigured = true
	configuration.DKIM = &DKIMConfiguration{DomainName: "example.com", Selector: "mail", PrivateKeyConfigured: false}
	if validSMTP(configuration, &tenantID) {
		t.Fatal("DKIM projection without an encrypted private key accepted")
	}
}

func TestPlainSMTPRequiresExplicitDevelopmentOptIn(t *testing.T) {
	input := SMTPWriteInput{
		Name: "Mailpit", Host: "mailpit", Port: 1025, Security: SMTPPlainLocal,
		FromName: "Periapsis", FromEmail: "security@example.com", TimeoutMS: 5_000,
		MaximumConnections: 2, MaximumMessagesPerConnection: 10, RateLimitPerSecond: 20,
		Enabled: true, IdempotencyKey: "smtp-mailpit-test-01", Audit: serviceAudit(t),
	}
	if _, err := normalizeSMTPWrite(input, false); err == nil {
		t.Fatal("plaintext SMTP was accepted without the development opt-in")
	}
	if normalized, err := normalizeSMTPWrite(input, true); err != nil || normalized.Host != "mailpit" {
		t.Fatalf("explicit Mailpit configuration = %#v, %v", normalized, err)
	}
}

func TestSanitizedWebhookProjectionRequiresPinnedSigningKey(t *testing.T) {
	tenantID := mustV7(t)
	webhook := WebhookConfiguration{
		WebhookFields: WebhookFields{
			Name: "SIEM", EndpointURL: "https://example.com/", EventTypes: []EventType{EventAlertCreated},
			Audience: AudienceOperator, SigningKeyConfigured: true, SigningKeyVersion: 1, TimeoutMS: 5_000, Enabled: true,
		},
		ID: mustV7(t), TenantID: tenantID, Version: 1, CreatedAt: validInstantFixture(), CreatedBy: mustV7(t),
	}
	if !validWebhook(webhook, tenantID) {
		t.Fatal("valid webhook projection rejected")
	}
	webhook.SigningKeyConfigured = false
	if validWebhook(webhook, tenantID) {
		t.Fatal("webhook without a configured signing key accepted")
	}
}

func TestProviderReceiptBoundsAreClosed(t *testing.T) {
	digest := strings.Repeat("a", 64)
	accepted, rejected := 1, 0
	if !validProviderReceipt(ProviderReceipt{Provider: "smtp", ReceiptDigest: digest, AcceptedCount: &accepted, RejectedCount: &rejected}) {
		t.Fatal("successful SMTP receipt rejected")
	}
	accepted = 2
	if validProviderReceipt(ProviderReceipt{Provider: "smtp", ReceiptDigest: digest, AcceptedCount: &accepted, RejectedCount: &rejected}) {
		t.Fatal("multi-recipient SMTP receipt accepted")
	}
	status := 200
	if !validProviderReceipt(ProviderReceipt{Provider: "webhook", ReceiptDigest: digest, StatusCode: &status}) {
		t.Fatal("successful webhook receipt rejected")
	}
	status = 503
	if validProviderReceipt(ProviderReceipt{Provider: "webhook", ReceiptDigest: digest, StatusCode: &status}) {
		t.Fatal("failed webhook response accepted as a delivery receipt")
	}
}

func TestDeliveryDestinationProjectionIsRedactedButUseful(t *testing.T) {
	for _, value := range []string{"a***@example.com", "webhook:019c9878…"} {
		if !validRedactedDestination(value) {
			t.Fatalf("valid redacted destination rejected: %q", value)
		}
	}
	for _, value := range []string{
		"analyst@example.com",
		"***@example.com",
		"aa***@example.com",
		"webhook:https://hooks.example",
		"webhook:019c9878-1111",
	} {
		if validRedactedDestination(value) {
			t.Fatalf("unsafe destination hint accepted: %q", value)
		}
	}
}

func TestDeliveryAttemptProjectionIsOutcomeCoupled(t *testing.T) {
	delivery := validInProgressDeliveryFixture(t)
	if !validDelivery(delivery, delivery.TenantID, true) {
		t.Fatal("valid in-progress delivery rejected")
	}

	wrongStatus := delivery
	wrongStatus.Status = DeliveryQueued
	if validDelivery(wrongStatus, wrongStatus.TenantID, true) {
		t.Fatal("in-progress attempt accepted outside a leased or reserved delivery")
	}

	notLast := delivery
	completed := delivery.Attempts[0].StartedAt.Add(time.Second)
	notLast.AttemptCount = 2
	notLast.Attempts = []DeliveryAttempt{
		delivery.Attempts[0],
		{Number: 2, StartedAt: completed, CompletedAt: &completed, Outcome: "fenced"},
	}
	if validDelivery(notLast, notLast.TenantID, true) {
		t.Fatal("non-final in-progress attempt accepted")
	}

	digest := strings.Repeat("a", 64)
	accepted, rejected := 1, 0
	receipt := &ProviderReceipt{
		Provider: "smtp", ReceiptDigest: digest, AcceptedCount: &accepted, RejectedCount: &rejected,
	}
	delivered := delivery
	delivered.Status = DeliveryDelivered
	delivered.DeliveredAt = &completed
	delivered.Attempts = []DeliveryAttempt{{
		Number: 1, StartedAt: delivery.Attempts[0].StartedAt, CompletedAt: &completed,
		Outcome: "delivered", ProviderReceipt: receipt,
	}}
	if !validDelivery(delivered, delivered.TenantID, true) {
		t.Fatalf(
			"valid delivered attempt rejected: pins=%v lifecycle=%v receipt=%v attempt=%v destination=%v outcome=%q completed=%v failure=%v provider=%q channel=%q",
			validDeliveryPins(delivered), validDeliveryLifecycle(delivered), validProviderReceipt(*receipt),
			validAttemptSemantics(delivered, delivered.Attempts[0], 0), validRedactedDestination(delivered.DestinationRedacted),
			delivered.Attempts[0].Outcome, delivered.Attempts[0].CompletedAt != nil, delivered.Attempts[0].FailureClass,
			delivered.Attempts[0].ProviderReceipt.Provider, delivered.Channel,
		)
	}
	missingReceipt := delivered
	missingReceipt.Attempts = append([]DeliveryAttempt(nil), delivered.Attempts...)
	missingReceipt.Attempts[0].ProviderReceipt = nil
	if validDelivery(missingReceipt, missingReceipt.TenantID, true) {
		t.Fatal("delivered attempt without a receipt accepted")
	}
	wrongProvider := delivered
	wrongProvider.Attempts = append([]DeliveryAttempt(nil), delivered.Attempts...)
	status := 200
	wrongProvider.Attempts[0].ProviderReceipt = &ProviderReceipt{
		Provider: "webhook", ReceiptDigest: digest, StatusCode: &status,
	}
	if validDelivery(wrongProvider, wrongProvider.TenantID, true) {
		t.Fatal("delivery receipt from the wrong channel accepted")
	}

	failure := FailureTimeout
	retried := delivery
	retried.Status = DeliveryRetryScheduled
	nextAttempt := completed.Add(time.Minute)
	retried.NextAttemptAt = &nextAttempt
	retried.Attempts = []DeliveryAttempt{{
		Number: 1, StartedAt: delivery.Attempts[0].StartedAt, CompletedAt: &completed,
		Outcome: "retried", FailureClass: &failure,
	}}
	if !validDelivery(retried, retried.TenantID, true) {
		t.Fatal("valid retried attempt rejected")
	}
	retried.Attempts[0].FailureClass = nil
	if validDelivery(retried, retried.TenantID, true) {
		t.Fatal("retried attempt without failure evidence accepted")
	}

	uncertainFailure := FailureSubmissionUncertain
	uncertain := delivery
	uncertain.Status = DeliveryDeadLettered
	uncertain.FailureAt = &completed
	uncertain.FailureClass = &uncertainFailure
	uncertain.Attempts = []DeliveryAttempt{{
		Number: 1, StartedAt: delivery.Attempts[0].StartedAt, CompletedAt: &completed,
		Outcome: "uncertain", FailureClass: &uncertainFailure,
	}}
	if !validDelivery(uncertain, uncertain.TenantID, true) {
		t.Fatal("valid uncertain attempt rejected")
	}
	uncertain.Attempts[0].FailureClass = &failure
	if validDelivery(uncertain, uncertain.TenantID, true) {
		t.Fatal("uncertain attempt without submission-uncertain evidence accepted")
	}

	fenced := delivery.Attempts[0]
	fenced.CompletedAt = &completed
	fenced.Outcome = "fenced"
	fenced.ProviderReceipt = receipt
	if validAttemptSemantics(delivery, fenced, 0) {
		t.Fatal("fenced attempt with a provider receipt accepted")
	}
	replayed := fenced
	replayed.Outcome = "replayed"
	replayed.ProviderReceipt = nil
	if !validAttemptSemantics(delivery, replayed, 0) {
		t.Fatal("redacted replayed attempt rejected")
	}
	replayed.CompletedAt = nil
	if validAttemptSemantics(delivery, replayed, 0) {
		t.Fatal("terminal replayed attempt without completion accepted")
	}
}

func validInProgressDeliveryFixture(t *testing.T) Delivery {
	t.Helper()
	createdAt := validInstantFixture()
	startedAt := createdAt.Add(time.Second)
	smtpScope := SMTPConfigurationTenant
	version := int64(1)
	smtpID := mustV7(t)
	return Delivery{
		ID: mustV7(t), TenantID: mustV7(t), EventID: mustV7(t),
		SMTPConfigurationID: &smtpID, SMTPConfigurationVersion: &version, SMTPConfigurationScope: &smtpScope,
		Channel: ChannelEmail, Audience: AudienceOperator, Status: DeliveryLeased,
		DestinationRedacted: "a***@example.com", AttemptCount: 1, MaximumAttempts: 3, CreatedAt: createdAt,
		Attempts: []DeliveryAttempt{{Number: 1, StartedAt: startedAt, Outcome: "in_progress"}},
	}
}

func validSMTPFixture(t *testing.T) SMTPConfiguration {
	t.Helper()
	return SMTPConfiguration{
		SMTPConfigurationFields: SMTPConfigurationFields{
			Name: "Primary", Host: "smtp.example.com", Port: 465, Security: SMTPTLS,
			FromName: "Periapsis", FromEmail: "security@example.com", TimeoutMS: 5_000,
			MaximumConnections: 5, MaximumMessagesPerConnection: 100, RateLimitPerSecond: 20, Enabled: true,
		},
		ID: mustV7(t), Version: 1, CreatedAt: validInstantFixture(), CreatedBy: mustV7(t),
	}
}

func mustV7(t *testing.T) uuid.UUID {
	t.Helper()
	value, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func validInstantFixture() time.Time {
	return time.Date(2026, time.August, 25, 12, 0, 0, 123_000, time.UTC)
}

func TestNotificationInstantAcceptsEquivalentUTCRepresentations(t *testing.T) {
	instant := validInstantFixture()
	for name, value := range map[string]time.Time{
		"utc":                instant,
		"numeric UTC offset": instant.In(time.FixedZone("", 0)),
		"named zero offset":  instant.In(time.FixedZone("GMT", 0)),
	} {
		t.Run(name, func(t *testing.T) {
			if !validInstant(value) {
				t.Fatal("equivalent UTC instant rejected")
			}
		})
	}
	for _, value := range []time.Time{
		{}, instant.Add(time.Nanosecond), instant.In(time.FixedZone("east", 3600)),
		instant.In(time.FixedZone("west", -3600)),
	} {
		if validInstant(value) {
			t.Fatal("invalid notification instant accepted")
		}
	}
}

func webhookWriteFixture(t *testing.T, event EventType, audience Audience) WebhookWriteInput {
	t.Helper()
	key := strings.Repeat("k", 32)
	return WebhookWriteInput{
		Name: "SIEM", EndpointURL: "https://hooks.example.test/events", EventTypes: []EventType{event},
		Audience: audience, SigningKey: &key, TimeoutMS: 5_000, Enabled: true,
		IdempotencyKey: "webhook-audience-test-01", Audit: serviceAudit(t),
	}
}
