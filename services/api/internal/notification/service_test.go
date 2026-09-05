package notification

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type serviceRepositoryStub struct {
	Repository
	resolveAuthorityFunc  func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error)
	listRulesFunc         func(context.Context, ListRulesParams) (RulePage, error)
	versionRuleFunc       func(context.Context, VersionRuleParams) (IdempotentResult[Rule], error)
	versionTenantSMTPFunc func(context.Context, VersionTenantSMTPParams) (IdempotentResult[SMTPConfiguration], error)
	testTenantSMTPFunc    func(context.Context, TestTenantSMTPParams) (IdempotentResult[SMTPProbePreflight], error)
	testPlatformSMTPFunc  func(context.Context, TestPlatformSMTPParams) (IdempotentResult[SMTPProbePreflight], error)
}

func (r *serviceRepositoryStub) ResolveAuthority(ctx context.Context, params authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
	return r.resolveAuthorityFunc(ctx, params)
}

func (r *serviceRepositoryStub) ListRules(ctx context.Context, params ListRulesParams) (RulePage, error) {
	return r.listRulesFunc(ctx, params)
}

func (r *serviceRepositoryStub) VersionRule(ctx context.Context, params VersionRuleParams) (IdempotentResult[Rule], error) {
	return r.versionRuleFunc(ctx, params)
}

func (r *serviceRepositoryStub) VersionTenantSMTP(ctx context.Context, params VersionTenantSMTPParams) (IdempotentResult[SMTPConfiguration], error) {
	return r.versionTenantSMTPFunc(ctx, params)
}

func (r *serviceRepositoryStub) TestTenantSMTP(ctx context.Context, params TestTenantSMTPParams) (IdempotentResult[SMTPProbePreflight], error) {
	return r.testTenantSMTPFunc(ctx, params)
}

func (r *serviceRepositoryStub) TestPlatformSMTP(ctx context.Context, params TestPlatformSMTPParams) (IdempotentResult[SMTPProbePreflight], error) {
	return r.testPlatformSMTPFunc(ctx, params)
}

type previewerStub struct {
	previewFunc func(context.Context, uuid.UUID, Audience, TemplateFields, map[string]any) (Preview, error)
	probeFunc   func(context.Context, SMTPProbeRequest) (SMTPProbeResult, error)
}

func (p previewerStub) ProbeSMTP(ctx context.Context, request SMTPProbeRequest) (SMTPProbeResult, error) {
	if p.probeFunc != nil {
		return p.probeFunc(ctx, request)
	}
	return SMTPProbeResult{
		SMTPProbeRequest: request,
		Healthy:          true,
		CheckedAt:        validInstantFixture(),
		Checks:           []SMTPHealthCheck{{Kind: "connect", Outcome: "passed"}},
	}, nil
}

func (p previewerStub) Preview(ctx context.Context, tenantID uuid.UUID, audience Audience, fields TemplateFields, context map[string]any) (Preview, error) {
	if p.previewFunc == nil {
		return Preview{Subject: "preview", HTML: "<p>preview</p>", PlainText: "preview"}, nil
	}
	return p.previewFunc(ctx, tenantID, audience, fields, context)
}

func TestNotificationServiceRequiresLiveExactTenantAuthority(t *testing.T) {
	tenantID, actor := serviceTenantActor(t)
	repository := &serviceRepositoryStub{}
	repository.resolveAuthorityFunc = func(_ context.Context, params authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		if params.Actor != actor || params.TenantID != tenantID {
			t.Fatalf("ResolveAuthority() params = %#v", params)
		}
		return serviceAuthority(t, tenantID, actor.UserID, true), nil
	}
	repository.listRulesFunc = func(_ context.Context, params ListRulesParams) (RulePage, error) {
		if params.Human.TenantID != tenantID || params.Human.Actor != actor || params.Limit != 50 {
			t.Fatalf("ListRules() params = %#v", params)
		}
		return RulePage{}, nil
	}
	service := newTestService(t, repository, previewerStub{})
	if _, err := service.ListRules(context.Background(), actor, tenantID, PageInput{}); err != nil {
		t.Fatalf("ListRules() error = %v", err)
	}

	wrongTenant := mustV7(t)
	if _, err := service.ListRules(context.Background(), actor, wrongTenant, PageInput{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross-tenant ListRules() error = %v", err)
	}

	repository.resolveAuthorityFunc = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return serviceAuthority(t, tenantID, actor.UserID, false), nil
	}
	if _, err := service.ListRules(context.Background(), actor, tenantID, PageInput{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ungranted ListRules() error = %v", err)
	}
}

func TestNotificationServiceProjectsCustomerPreviewContext(t *testing.T) {
	tenantID, actor := serviceTenantActor(t)
	repository := authorizedRepository(t, tenantID, actor.UserID)
	previewer := previewerStub{previewFunc: func(_ context.Context, previewTenantID uuid.UUID, audience Audience, _ TemplateFields, context map[string]any) (Preview, error) {
		if previewTenantID != tenantID {
			t.Fatalf("tenant ID = %s, want %s", previewTenantID, tenantID)
		}
		if audience != AudienceCustomer {
			t.Fatalf("audience = %q", audience)
		}
		if _, leaked := context["comment"]; leaked || len(context) != 1 {
			t.Fatalf("customer context leaked operator fields: %#v", context)
		}
		if _, ok := context["case"].(map[string]any); !ok {
			t.Fatalf("customer case context = %#v", context)
		}
		return Preview{Subject: "Customer update", HTML: "<p>safe</p>", PlainText: "safe"}, nil
	}}
	service := newTestService(t, repository, previewer)
	preview, err := service.PreviewTemplate(
		context.Background(), actor, tenantID, AudienceCustomer, serviceTemplateFields(),
		map[string]any{
			"comment":  map[string]any{"body": "operator-only"},
			"customer": map[string]any{"case": map[string]any{"number": "CASE-1"}},
		},
	)
	if err != nil || preview.Subject != "Customer update" {
		t.Fatalf("PreviewTemplate() = %#v, %v", preview, err)
	}
	if _, err := service.PreviewTemplate(
		context.Background(), actor, tenantID, AudienceCustomer, serviceTemplateFields(),
		map[string]any{"comment": map[string]any{"body": "private"}},
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing customer projection error = %v", err)
	}
}

func TestNotificationServiceEncryptsAndClearsSMTPSecretsBeforePersistenceReturns(t *testing.T) {
	tenantID, actor := serviceTenantActor(t)
	keyring := testKeyring(t)
	repository := authorizedRepository(t, tenantID, actor.UserID)
	var capturedPassword, capturedDKIM *ProtectedSecret
	repository.versionTenantSMTPFunc = func(_ context.Context, params VersionTenantSMTPParams) (IdempotentResult[SMTPConfiguration], error) {
		if params.Write.Password == nil || params.Write.DKIMPrivateKey == nil || params.Write.RetainPassword || params.Write.RemovePassword {
			t.Fatalf("protected SMTP write = %#v", params.Write)
		}
		capturedPassword = params.Write.Password
		capturedDKIM = params.Write.DKIMPrivateKey
		for _, candidate := range []struct {
			secret *ProtectedSecret
			kind   SecretKind
			want   string
		}{
			{params.Write.Password, SecretKindSMTPPassword, "correct horse battery staple"},
			{params.Write.DKIMPrivateKey, SecretKindSMTPDKIMPrivateKey, "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----"},
		} {
			if candidate.secret.Kind != candidate.kind || candidate.secret.Version != 1 ||
				bytes.Contains(candidate.secret.Envelope.Ciphertext, []byte(candidate.want)) {
				t.Fatalf("unsafe protected secret = %#v", candidate.secret)
			}
			plaintext, err := keyring.Unprotect(SecretContext{
				TenantID: &tenantID, SecretID: candidate.secret.ID, SecretVersion: 1, Kind: candidate.kind,
			}, candidate.secret.Envelope)
			if err != nil || string(plaintext) != candidate.want {
				t.Fatalf("Unprotect() = %q, %v", plaintext, err)
			}
			clear(plaintext)
		}
		username := "mailer"
		return IdempotentResult[SMTPConfiguration]{Value: SMTPConfiguration{
			SMTPConfigurationFields: SMTPConfigurationFields{
				Name: "Primary", Host: "smtp.example.com", Port: 465, Security: SMTPTLS,
				Username: &username, PasswordConfigured: true, FromName: "Periapsis", FromEmail: "security@example.com",
				TimeoutMS: 5_000, MaximumConnections: 5, MaximumMessagesPerConnection: 100,
				RateLimitPerSecond: 20, DKIM: &DKIMConfiguration{DomainName: "example.com", Selector: "mail", PrivateKeyConfigured: true}, Enabled: true,
			},
			ID: params.ConfigurationID, TenantID: &tenantID, Version: 1,
			CreatedAt: params.Mutation.OccurredAt, CreatedBy: actor.UserID,
		}}, nil
	}
	service, err := NewService(repository, keyring, previewerStub{}, ServiceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return validInstantFixture() }
	username := "mailer"
	password := "correct horse battery staple"
	dkimKey := "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----"
	configuration, err := service.VersionTenantSMTP(context.Background(), actor, tenantID, SMTPWriteInput{
		Name: "Primary", Host: "smtp.example.com", Port: 465, Security: SMTPTLS,
		Username: &username, Password: &password, FromName: "Periapsis", FromEmail: "security@example.com",
		TimeoutMS: 5_000, MaximumConnections: 5, MaximumMessagesPerConnection: 100, RateLimitPerSecond: 20,
		DKIM: &DKIMWriteInput{DomainName: "example.com", Selector: "mail", PrivateKey: &dkimKey}, Enabled: true,
		IdempotencyKey: "smtp-create-test-0001", Audit: serviceAudit(t),
	})
	if err != nil || !configuration.PasswordConfigured {
		t.Fatalf("VersionTenantSMTP() = %#v, %v", configuration, err)
	}
	for _, secret := range []*ProtectedSecret{capturedPassword, capturedDKIM} {
		if secret == nil || !allZero(secret.Envelope.Nonce) || !allZero(secret.Envelope.Ciphertext) {
			t.Fatalf("secret buffers were not cleared after persistence: %#v", secret)
		}
	}
}

func TestPlatformSMTPTestIsHealthOnly(t *testing.T) {
	repository := &serviceRepositoryStub{}
	configurationID := mustV7(t)
	called := false
	forgeFence := false
	forgeStages := false
	repository.testPlatformSMTPFunc = func(_ context.Context, params TestPlatformSMTPParams) (IdempotentResult[SMTPProbePreflight], error) {
		called = true
		if params.DeliveryID != nil || params.Recipient != nil {
			t.Fatalf("platform SMTP test attempted a tenant delivery: %#v", params)
		}
		return IdempotentResult[SMTPProbePreflight]{Value: SMTPProbePreflight{
			ConfigurationID: configurationID, ConfigurationVersion: params.ConfigurationVersion,
			ConfigurationScope: SMTPConfigurationPlatform,
		}}, nil
	}
	service := newTestService(t, repository, previewerStub{probeFunc: func(_ context.Context, request SMTPProbeRequest) (SMTPProbeResult, error) {
		if request.TenantID != nil || request.ConfigurationScope != SMTPConfigurationPlatform ||
			request.ConfigurationID != configurationID || request.ConfigurationVersion != 1 {
			t.Fatalf("ProbeSMTP() request = %#v", request)
		}
		if forgeFence {
			request.FenceToken = mustV7(t)
		}
		checks := []SMTPHealthCheck{{Kind: "dns", Outcome: "passed"}, {Kind: "connect", Outcome: "passed"}}
		if forgeStages {
			checks = []SMTPHealthCheck{{Kind: "authentication", Outcome: "passed"}}
		}
		return SMTPProbeResult{
			SMTPProbeRequest: request, Healthy: true, CheckedAt: validInstantFixture(),
			Checks: checks,
		}, nil
	}})
	session := authentication.Session{
		ID: mustV7(t), User: authentication.User{ID: mustV7(t)},
		Permissions:          []authorization.Permission{authorization.PermissionPlatformNotificationManage},
		AuthenticationMethod: "password+mfa",
	}
	recipient := "security@example.com"
	input := SMTPTestInput{
		ConfigurationVersion: 1, Recipient: &recipient, Reason: "platform health",
		IdempotencyKey: "platform-smtp-health-01", Audit: serviceAudit(t),
	}
	if _, err := service.TestPlatformSMTP(context.Background(), session, input); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("recipient-bearing platform test error = %v", err)
	}
	if called {
		t.Fatal("recipient-bearing platform test reached the repository")
	}
	input.Recipient = nil
	result, err := service.TestPlatformSMTP(context.Background(), session, input)
	if err != nil || result.QueuedDeliveryID != nil || !called {
		t.Fatalf("health-only platform test = %#v, %v; called=%v", result, err, called)
	}
	forgeFence = true
	input.IdempotencyKey = "platform-smtp-health-02"
	if _, err := service.TestPlatformSMTP(context.Background(), session, input); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("forged probe fence error = %v", err)
	}
	forgeFence = false
	forgeStages = true
	input.IdempotencyKey = "platform-smtp-health-03"
	if _, err := service.TestPlatformSMTP(context.Background(), session, input); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("forged probe stages error = %v", err)
	}
}

func TestVersionRuleRejectsARepositoryReplayForAnotherResource(t *testing.T) {
	tenantID, actor := serviceTenantActor(t)
	repository := authorizedRepository(t, tenantID, actor.UserID)
	repository.versionRuleFunc = func(_ context.Context, params VersionRuleParams) (IdempotentResult[Rule], error) {
		return IdempotentResult[Rule]{Replayed: true, Value: Rule{
			RuleFields: serviceRuleFields(t), ID: mustV7(t), TenantID: tenantID, Version: params.ExpectedVersion + 1,
			CreatedAt: params.Mutation.OccurredAt, CreatedBy: actor.UserID,
		}}, nil
	}
	service := newTestService(t, repository, previewerStub{})
	ruleID := mustV7(t)
	expected := int64(1)
	_, err := service.VersionRule(context.Background(), actor, tenantID, ruleID, RuleWriteInput{
		Fields: serviceRuleFields(t), ExpectedVersion: &expected,
		IdempotencyKey: "rule-version-test-01", Audit: serviceAudit(t),
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("forged replay error = %v", err)
	}
}

func newTestService(t *testing.T, repository Repository, notifier NotifierClient) *Service {
	t.Helper()
	service, err := NewService(repository, testKeyring(t), notifier, ServiceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return validInstantFixture() }
	return service
}

func authorizedRepository(t *testing.T, tenantID, actorID uuid.UUID) *serviceRepositoryStub {
	t.Helper()
	repository := &serviceRepositoryStub{}
	repository.resolveAuthorityFunc = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return serviceAuthority(t, tenantID, actorID, true), nil
	}
	return repository
}

func serviceAuthority(t *testing.T, tenantID, actorID uuid.UUID, granted bool) authorization.TenantAuthority {
	t.Helper()
	authority := authorization.TenantAuthority{
		TenantID: tenantID, Principal: authorization.TenantPrincipal{ID: actorID, Kind: authorization.PrincipalKindHuman},
		MembershipID: mustV7(t), MembershipStatus: authorization.MembershipStatusActive,
		LegacyRole: authorization.LegacyMembershipRoleTenantAdmin, EvaluatedAt: validInstantFixture(),
	}
	if granted {
		authority.Permissions = []authorization.ScopedPermission{{
			Permission: authorization.TenantPermissionNotificationManage, Scope: authorization.ScopeTenant,
		}}
	}
	return authority
}

func serviceTenantActor(t *testing.T) (uuid.UUID, authorization.Actor) {
	t.Helper()
	tenantID := mustV7(t)
	return tenantID, authorization.Actor{
		UserID: mustV7(t), SessionID: mustV7(t), ActiveTenantID: tenantID, AuthenticationMethod: "password+mfa",
	}
}

func serviceAudit(t *testing.T) authorization.AuditContext {
	t.Helper()
	return authorization.AuditContext{RequestID: mustV7(t), CorrelationID: mustV7(t), UserAgent: "notification-service-test"}
}

func serviceTemplateFields() TemplateFields {
	return TemplateFields{
		Key: "case.updated", Name: "Case updated", Language: "en", Subject: "Case update", HTML: "<p>Update</p>",
	}
}

func serviceRuleFields(t *testing.T) RuleFields {
	t.Helper()
	audience := AudienceOperator
	window := int64(300_000)
	items := 25
	return RuleFields{
		Name: "Alert created", EventType: EventAlertCreated, ObjectType: ObjectAlert,
		Condition:  Condition{Kind: ConditionPredicate, Path: "alert.severity", Operator: OperatorExists},
		Recipients: []RecipientSelector{{Kind: RecipientAssignee, Audience: &audience}},
		TemplateID: mustV7(t), TemplateVersion: 1, Channel: ChannelEmail, Priority: 50,
		Grouping: GroupingPolicy{Mode: "object", WindowMS: &window, MaximumItems: &items},
		Retry:    RetryPolicy{MaximumAttempts: 5, InitialDelayMS: 1_000, MaximumDelayMS: 60_000, Multiplier: 2, JitterPercent: 20},
		Enabled:  true, EffectiveFrom: validInstantFixture(),
	}
}

func testKeyring(t *testing.T) Keyring {
	t.Helper()
	keyring, err := NewKeyring(1, map[int16][]byte{1: bytes.Repeat([]byte{0x5a}, notificationRootKeyBytes)})
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}

func allZero(value []byte) bool {
	return bytes.Equal(value, make([]byte, len(value)))
}
