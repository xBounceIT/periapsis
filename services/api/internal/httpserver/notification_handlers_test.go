package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/notification"
)

type recordingNotificationService struct {
	*transportNotificationStub
	createRule        func(context.Context, authorization.Actor, uuid.UUID, notification.RuleWriteInput) (notification.Rule, error)
	testPlatformSMTP  func(context.Context, authentication.Session, notification.SMTPTestInput) (notification.SMTPHealth, error)
	versionTenantSMTP func(context.Context, authorization.Actor, uuid.UUID, notification.SMTPWriteInput) (notification.SMTPConfiguration, error)
}

func (service *recordingNotificationService) TestPlatformSMTP(
	ctx context.Context,
	session authentication.Session,
	input notification.SMTPTestInput,
) (notification.SMTPHealth, error) {
	if service.testPlatformSMTP == nil {
		return notification.SMTPHealth{}, notification.ErrUnavailable
	}
	return service.testPlatformSMTP(ctx, session, input)
}

func (service *recordingNotificationService) CreateRule(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input notification.RuleWriteInput,
) (notification.Rule, error) {
	if service.createRule == nil {
		return notification.Rule{}, notification.ErrUnavailable
	}
	return service.createRule(ctx, actor, tenantID, input)
}

func (service *recordingNotificationService) VersionTenantSMTP(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input notification.SMTPWriteInput,
) (notification.SMTPConfiguration, error) {
	if service.versionTenantSMTP == nil {
		return notification.SMTPConfiguration{}, notification.ErrUnavailable
	}
	return service.versionTenantSMTP(ctx, actor, tenantID, input)
}

func TestNotificationRuleTransportRequiresExactBodyAndWritesVersionHeaders(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	templateID := uuid.Must(uuid.NewV7())
	ruleID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	calls := 0
	service := &recordingNotificationService{
		transportNotificationStub: &transportNotificationStub{},
		createRule: func(_ context.Context, actor authorization.Actor, gotTenant uuid.UUID, input notification.RuleWriteInput) (notification.Rule, error) {
			calls++
			if gotTenant != tenantID || actor.UserID != userID || input.IdempotencyKey != "notification-key-0001" {
				t.Fatalf("forwarded identity/input = tenant %s actor %s key %q", gotTenant, actor.UserID, input.IdempotencyKey)
			}
			if input.Audit.RequestID == uuid.Nil || input.Audit.RemoteAddress.String() != "198.51.100.42" {
				t.Fatalf("audit context = %#v", input.Audit)
			}
			return notification.Rule{
				RuleFields: input.Fields, ID: ruleID, TenantID: tenantID, Version: 1,
				CreatedAt: now, CreatedBy: userID,
			}, nil
		},
	}
	router := newNotificationTestRouter(t, tenantID, userID, service)
	body := notificationRuleRequestBody(t, templateID, now)
	request := notificationMutationRequest(http.MethodPost, "/api/v1/tenants/"+tenantID.String()+"/notification-rules", body)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("ETag") != `"v1"` || response.Header().Get("Location") != notificationRuleLocation(tenantID, ruleID) {
		t.Fatalf("response headers = %#v", response.Header())
	}
	if response.Header().Get("Cache-Control") != "no-store" || calls != 1 {
		t.Fatalf("cache/calls = %q/%d", response.Header().Get("Cache-Control"), calls)
	}
	var decoded map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if decoded["id"] != ruleID.String() || decoded["enabled"] != false {
		t.Fatalf("response = %#v", decoded)
	}

	delete(body, "enabled")
	request = notificationMutationRequest(http.MethodPost, "/api/v1/tenants/"+tenantID.String()+"/notification-rules", body)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusBadRequest, "invalid_request")
	if calls != 1 {
		t.Fatalf("service called for missing required false field: %d", calls)
	}
}

func TestNotificationSMTPTransportDistinguishesRequiredNullFromOmissionAndRedactsSecrets(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	configurationID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	calls := 0
	service := &recordingNotificationService{
		transportNotificationStub: &transportNotificationStub{},
		versionTenantSMTP: func(_ context.Context, _ authorization.Actor, gotTenant uuid.UUID, input notification.SMTPWriteInput) (notification.SMTPConfiguration, error) {
			calls++
			if gotTenant != tenantID || input.Username != nil || input.ReplyToEmail != nil || input.ExpectedVersion != nil {
				t.Fatalf("SMTP input = %#v", input)
			}
			if input.Password == nil || *input.Password != "write-only-password" {
				t.Fatalf("password was not forwarded as write-only input")
			}
			return notification.SMTPConfiguration{
				SMTPConfigurationFields: notification.SMTPConfigurationFields{
					Name: input.Name, Host: input.Host, Port: input.Port, Security: input.Security,
					PasswordConfigured: true, FromName: input.FromName, FromEmail: input.FromEmail,
					TimeoutMS: input.TimeoutMS, MaximumConnections: input.MaximumConnections,
					MaximumMessagesPerConnection: input.MaximumMessagesPerConnection,
					RateLimitPerSecond:           input.RateLimitPerSecond, Enabled: input.Enabled,
				},
				ID: configurationID, TenantID: &tenantID, Version: 1, CreatedAt: now, CreatedBy: userID,
			}, nil
		},
	}
	router := newNotificationTestRouter(t, tenantID, userID, service)
	body := map[string]any{
		"name": "Primary SMTP", "host": "smtp.example.com", "port": 465, "security": "tls",
		"username": nil, "password": "write-only-password", "clearPassword": false,
		"fromName": "Periapsis", "fromEmail": "alerts@example.com", "replyToEmail": nil,
		"timeoutMs": 5000, "maximumConnections": 4, "maximumMessagesPerConnection": 100,
		"rateLimitPerSecond": 20, "clearDkim": false, "enabled": false,
	}
	request := notificationMutationRequest(http.MethodPut, "/api/v1/tenants/"+tenantID.String()+"/smtp-configuration", body)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("ETag") != `"v1"` || response.Header().Get("Location") != notificationSMTPLocation(&tenantID) {
		t.Fatalf("response headers = %#v", response.Header())
	}
	responseText := response.Body.String()
	for _, forbidden := range []string{"write-only-password", `"password"`, "privateKey"} {
		if strings.Contains(responseText, forbidden) {
			t.Fatalf("response leaked %q: %s", forbidden, responseText)
		}
	}
	if !strings.Contains(responseText, `"username":null`) || !strings.Contains(responseText, `"replyToEmail":null`) {
		t.Fatalf("required nullable response fields missing: %s", responseText)
	}

	delete(body, "replyToEmail")
	request = notificationMutationRequest(http.MethodPut, "/api/v1/tenants/"+tenantID.String()+"/smtp-configuration", body)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusBadRequest, "invalid_request")
	if calls != 1 {
		t.Fatalf("service called for omitted required nullable field: %d", calls)
	}
}

func TestPlatformSMTPTestTransportIsStrictlyHealthOnly(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	configurationID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	calls := 0
	queueUnexpectedly := false
	service := &recordingNotificationService{
		transportNotificationStub: &transportNotificationStub{},
		testPlatformSMTP: func(_ context.Context, session authentication.Session, input notification.SMTPTestInput) (notification.SMTPHealth, error) {
			calls++
			if session.User.ID != userID || input.ConfigurationVersion != 3 || input.Recipient != nil ||
				input.Reason != "bounded health check" || input.IdempotencyKey != "notification-key-0001" ||
				input.Audit.RequestID == uuid.Nil {
				t.Fatalf("platform SMTP test input = session %#v, input %#v", session, input)
			}
			result := notification.SMTPHealth{
				ConfigurationID: configurationID, ConfigurationVersion: 3, Healthy: true, CheckedAt: now,
				Checks: []notification.SMTPHealthCheck{{Kind: "dns", Outcome: "passed"}},
			}
			if queueUnexpectedly {
				deliveryID := uuid.Must(uuid.NewV7())
				result.QueuedDeliveryID = &deliveryID
			}
			return result, nil
		},
	}
	router := newNotificationTestRouter(t, tenantID, userID, service)
	request := notificationMutationRequest(
		http.MethodPost,
		"/api/v1/platform/smtp-configuration/test",
		map[string]any{"configurationVersion": 3, "reason": "bounded health check"},
	)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "queuedDeliveryId") {
		t.Fatalf("health-only response = %d %s", response.Code, response.Body.String())
	}

	request = notificationMutationRequest(
		http.MethodPost,
		"/api/v1/platform/smtp-configuration/test",
		map[string]any{"configurationVersion": 3, "recipient": nil, "reason": "bounded health check"},
	)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusBadRequest, "invalid_request")
	if calls != 1 {
		t.Fatalf("platform service calls after forbidden recipient field = %d", calls)
	}

	queueUnexpectedly = true
	request = notificationMutationRequest(
		http.MethodPost,
		"/api/v1/platform/smtp-configuration/test",
		map[string]any{"configurationVersion": 3, "reason": "bounded health check"},
	)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
}

func TestNotificationDeliveryMappingPreservesExactSMTPNamespaceAndOpenAttempt(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	deliveryID := uuid.Must(uuid.NewV7())
	eventID := uuid.Must(uuid.NewV7())
	smtpID := uuid.Must(uuid.NewV7())
	version := int64(3)
	scope := notification.SMTPConfigurationTenant
	now := time.Now().UTC().Truncate(time.Microsecond)
	value := notification.Delivery{
		ID: deliveryID, TenantID: tenantID, EventID: eventID,
		SMTPConfigurationID: &smtpID, SMTPConfigurationVersion: &version, SMTPConfigurationScope: &scope,
		Channel: notification.ChannelEmail, Audience: notification.AudienceOperator,
		Status: notification.DeliveryLeased, DestinationRedacted: "a***@example.com",
		AttemptCount: 1, MaximumAttempts: 3, CreatedAt: now,
		Attempts: []notification.DeliveryAttempt{{Number: 1, StartedAt: now, Outcome: "in_progress"}},
	}

	summary, err := mapNotificationDeliveryFields(value)
	if err != nil || summary.SmtpConfigurationScope == nil || string(*summary.SmtpConfigurationScope) != "tenant" {
		t.Fatalf("email delivery summary scope = %#v, %v", summary.SmtpConfigurationScope, err)
	}
	detail, err := mapNotificationDeliveryDetail(value)
	if err != nil || detail.SmtpConfigurationScope == nil || string(*detail.SmtpConfigurationScope) != "tenant" {
		t.Fatalf("email delivery detail scope = %#v, %v", detail.SmtpConfigurationScope, err)
	}
	if len(detail.Attempts) != 1 || string(detail.Attempts[0].Outcome) != "in_progress" ||
		detail.Attempts[0].CompletedAt != nil || detail.Attempts[0].FailureClass != nil || detail.Attempts[0].ProviderReceipt != nil {
		t.Fatalf("open attempt mapping = %#v", detail.Attempts)
	}

	value.Channel = notification.ChannelWebhook
	value.SMTPConfigurationScope = nil
	value.SMTPConfigurationID = nil
	value.SMTPConfigurationVersion = nil
	if summary, err = mapNotificationDeliveryFields(value); err != nil || summary.SmtpConfigurationScope != nil {
		t.Fatalf("webhook delivery summary scope = %#v, %v", summary.SmtpConfigurationScope, err)
	}
	value.SMTPConfigurationScope = &scope
	if _, err = mapNotificationDeliveryFields(value); err == nil {
		t.Fatal("webhook delivery with SMTP namespace was mapped")
	}
	value.Channel = notification.ChannelEmail
	value.SMTPConfigurationScope = nil
	if _, err = mapNotificationDeliveryFields(value); err == nil {
		t.Fatal("email delivery without SMTP namespace was mapped")
	}
}

func TestNotificationTransportRejectsCrossTenantBeforeParsingOrUseCase(t *testing.T) {
	pathTenantID := uuid.Must(uuid.NewV7())
	activeTenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	calls := 0
	service := &recordingNotificationService{
		transportNotificationStub: &transportNotificationStub{},
		createRule: func(context.Context, authorization.Actor, uuid.UUID, notification.RuleWriteInput) (notification.Rule, error) {
			calls++
			return notification.Rule{}, nil
		},
	}
	router := newNotificationTestRouter(t, activeTenantID, userID, service)
	request := notificationMutationRequest(http.MethodPost, "/api/v1/tenants/"+pathTenantID.String()+"/notification-rules", map[string]any{"not": "a rule"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusForbidden, "forbidden")
	if calls != 0 {
		t.Fatalf("cross-tenant use case calls = %d", calls)
	}
}

func newNotificationTestRouter(
	t *testing.T,
	tenantID uuid.UUID,
	userID uuid.UUID,
	service NotificationAdministrationService,
) http.Handler {
	t.Helper()
	auth := &transportAuthStub{authenticateResult: authentication.Session{
		ID: uuid.Must(uuid.NewV7()), User: authentication.User{ID: userID}, ActiveTenantID: &tenantID,
		AuthenticationMethod: "totp",
	}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewApplicationHandler(fixedChecker{ready: true}, logger, "test", time.Second, ApplicationOptions{
		Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: auth, Authorization: &transportAuthorizationStub{},
		Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{},
		Environment: "test", IdentityProviders: &transportIdentityProviderStub{},
		LDAPAdministration: &transportLDAPAdministrationStub{}, MFA: &transportMFAStub{}, Notifications: service,
		OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{},
		PublicOrigin: "http://localhost:8081", ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{}, Ticketing: &transportTicketingStub{}, WorkflowAdministration: &transportWorkflowAdministrationStub{},
	})
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}

func notificationMutationRequest(method, path string, body map[string]any) *http.Request {
	encoded, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	request := httptest.NewRequest(method, path, strings.NewReader(string(encoded)))
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	request.RemoteAddr = "198.51.100.42:4123"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.Header.Set(csrfTokenHeader, "csrf-value")
	request.Header.Set(idempotencyKeyHeader, "notification-key-0001")
	return request
}

func notificationRuleRequestBody(t *testing.T, templateID uuid.UUID, effectiveFrom time.Time) map[string]any {
	t.Helper()
	return map[string]any{
		"name": "High priority alert", "description": "Operator notification", "eventType": "alert.created",
		"objectType": "alert", "condition": map[string]any{
			"kind": "predicate", "path": "alert.id", "operator": "exists",
		},
		"recipients": []any{map[string]any{"kind": "assignee", "audience": "operator"}},
		"templateId": templateID.String(), "templateVersion": 1, "channel": "email", "priority": 0,
		"delayMs": 0, "deduplicationWindowMs": 0, "grouping": map[string]any{"mode": "none"},
		"retry": map[string]any{
			"maximumAttempts": 3, "initialDelayMs": 1000, "maximumDelayMs": 10000,
			"multiplier": 2, "jitterPercent": 0,
		},
		"enabled": false, "effectiveFrom": effectiveFrom.Format(time.RFC3339Nano),
	}
}
