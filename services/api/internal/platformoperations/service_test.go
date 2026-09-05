package platformoperations

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

var platformOperationsTestNow = time.Date(2026, 9, 1, 20, 0, 0, 123_000_000, time.UTC)

func TestNewServiceRejectsNilRepository(t *testing.T) {
	var typedNil *platformOperationsRepositoryStub
	for name, repository := range map[string]Repository{
		"nil": nil, "typed nil": typedNil,
	} {
		t.Run(name, func(t *testing.T) {
			service, err := NewService(repository)
			if err == nil || service != nil {
				t.Fatalf("service = %#v, error = %v", service, err)
			}
		})
	}
}

func TestPlatformOperationsDependencyCancellationRemainsObservable(t *testing.T) {
	for name, dependencyError := range map[string]error{
		"canceled": context.Canceled,
		"deadline": context.DeadlineExceeded,
	} {
		t.Run(name, func(t *testing.T) {
			if got := mapDependencyError(dependencyError); !errors.Is(got, dependencyError) {
				t.Fatalf("mapDependencyError() = %v", got)
			}
		})
	}
}

func TestServiceRequiresLiveTenantlessExactPermission(t *testing.T) {
	repository := &platformOperationsRepositoryStub{}
	service := newPlatformOperationsTestService(t, repository)
	session := platformOperationsTestSession(authorization.PermissionPlatformOperationsRead)
	repository.getHealth = func(_ context.Context, params ReadHealthParams) (Health, error) {
		if params.Session.ID != session.ID || !validUUIDv7(params.AuditID) || params.Event != platformOperationsTestEvent() {
			t.Fatalf("params = %#v", params)
		}
		return params.Validate(platformOperationsHealth())
	}

	health, err := service.GetHealth(context.Background(), session, ReadInput{Event: platformOperationsTestEvent()})
	if err != nil || health.Status != "healthy" || repository.healthCalls != 1 {
		t.Fatalf("health = %#v, calls = %d, error = %v", health, repository.healthCalls, err)
	}
	if _, err := service.ListUsers(context.Background(), session, ListUsersInput{
		Limit: 20, Event: platformOperationsTestEvent(),
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("missing permission error = %v", err)
	}

	invalidSessions := map[string]authentication.Session{
		"tenant scoped": func() authentication.Session {
			value := session
			tenantID := platformOperationsTestID(9)
			value.ActiveTenantID = &tenantID
			return value
		}(),
		"recovery": func() authentication.Session {
			value := session
			value.AuthenticationMethod = "recovery_code"
			return value
		}(),
		"expired": func() authentication.Session {
			value := session
			value.IdleExpiresAt = platformOperationsTestNow
			return value
		}(),
		"revoked": func() authentication.Session {
			value := session
			revokedAt := platformOperationsTestNow.Add(-time.Second)
			value.RevokedAt = &revokedAt
			return value
		}(),
	}
	for name, invalid := range invalidSessions {
		t.Run(name, func(t *testing.T) {
			if _, err := service.GetHealth(context.Background(), invalid, ReadInput{
				Event: platformOperationsTestEvent(),
			}); !errors.Is(err, ErrForbidden) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if repository.healthCalls != 1 {
		t.Fatalf("invalid requests reached repository: %d", repository.healthCalls)
	}
}

func TestSettingsAndFeatureFlagMutationsNormalizeAndValidate(t *testing.T) {
	repository := &platformOperationsRepositoryStub{}
	service := newPlatformOperationsTestService(t, repository)
	session := platformOperationsTestSession(
		authorization.PermissionPlatformSettingsRead,
		authorization.PermissionPlatformSettingsManage,
		authorization.PermissionPlatformFeatureFlagRead,
		authorization.PermissionPlatformFeatureFlagManage,
	)
	supportURL := " https://support.example.invalid/help "
	repository.updateSettings = func(_ context.Context, params UpdateSettingsParams) (GlobalSettings, error) {
		if params.ExpectedVersion != 1 || params.PlatformName != "Periapsis Control" ||
			params.DefaultLocale != "it-IT" || params.DefaultTimezone != "Europe/Rome" ||
			params.SupportURL == nil || *params.SupportURL != "https://support.example.invalid/help" ||
			params.Reason != "Apply approved platform defaults." {
			t.Fatalf("params = %#v", params)
		}
		return params.Validate(GlobalSettings{
			PlatformName: params.PlatformName, DefaultLocale: params.DefaultLocale,
			DefaultTimezone: params.DefaultTimezone, SupportURL: params.SupportURL,
			Version: 2, UpdatedAt: platformOperationsTestNow,
		})
	}
	settings, err := service.UpdateSettings(context.Background(), session, UpdateSettingsInput{
		ExpectedVersion: 1, PlatformName: " Periapsis Control ", DefaultLocale: " it-IT ",
		DefaultTimezone: " Europe/Rome ", SupportURL: &supportURL,
		Reason: " Apply approved platform defaults. ", Event: platformOperationsTestEvent(),
	})
	if err != nil || settings.Version != 2 {
		t.Fatalf("settings = %#v, error = %v", settings, err)
	}

	repository.updateFlag = func(_ context.Context, params UpdateFeatureFlagParams) (FeatureFlag, error) {
		if params.Key != FlagPlatformFailedNotificationsView || params.ExpectedVersion != 4 ||
			params.Enabled || params.Reason != "Pause the redacted failed delivery view." {
			t.Fatalf("params = %#v", params)
		}
		return params.Validate(FeatureFlag{
			Key: params.Key, Enabled: params.Enabled, Version: 5, UpdatedAt: platformOperationsTestNow,
		})
	}
	flag, err := service.UpdateFeatureFlag(context.Background(), session, UpdateFeatureFlagInput{
		Key: " platform_failed_notifications_view ", ExpectedVersion: 4,
		Enabled: false, Reason: " Pause the redacted failed delivery view. ",
		Event: platformOperationsTestEvent(),
	})
	if err != nil || flag.Enabled || flag.Version != 5 {
		t.Fatalf("flag = %#v, error = %v", flag, err)
	}
}

func TestServiceRejectsUnsafeMutationsAndMalformedProjections(t *testing.T) {
	repository := &platformOperationsRepositoryStub{}
	service := newPlatformOperationsTestService(t, repository)
	session := platformOperationsTestSession(
		authorization.PermissionPlatformSettingsRead,
		authorization.PermissionPlatformSettingsManage,
		authorization.PermissionPlatformOperationsRead,
	)
	valid := UpdateSettingsInput{
		ExpectedVersion: 1, PlatformName: "Periapsis", DefaultLocale: "en",
		DefaultTimezone: "UTC", Reason: "Apply approved platform defaults.",
		Event: platformOperationsTestEvent(),
	}
	for name, mutate := range map[string]func(*UpdateSettingsInput){
		"format character": func(input *UpdateSettingsInput) { input.PlatformName = "Periapsis\u202e" },
		"unknown timezone": func(input *UpdateSettingsInput) { input.DefaultTimezone = "Mars/Olympus" },
		"http support URL": func(input *UpdateSettingsInput) {
			value := "http://support.example.invalid"
			input.SupportURL = &value
		},
		"credentialed URL": func(input *UpdateSettingsInput) {
			value := "https://user@example.invalid/help"
			input.SupportURL = &value
		},
		"control reason": func(input *UpdateSettingsInput) { input.Reason = "unsafe\nreason" },
	} {
		t.Run(name, func(t *testing.T) {
			input := valid
			mutate(&input)
			if _, err := service.UpdateSettings(context.Background(), session, input); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if repository.updateSettingsCalls != 0 {
		t.Fatalf("unsafe settings reached repository: %d", repository.updateSettingsCalls)
	}

	repository.getHealth = func(_ context.Context, params ReadHealthParams) (Health, error) {
		health := platformOperationsHealth()
		health.Status = "healthy"
		health.Checks[1].Status = "degraded"
		return params.Validate(health)
	}
	if _, err := service.GetHealth(context.Background(), session, ReadInput{
		Event: platformOperationsTestEvent(),
	}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("malformed health error = %v", err)
	}
}

func TestUserQueueAndFailureProjectionsRemainBoundedAndRedacted(t *testing.T) {
	repository := &platformOperationsRepositoryStub{}
	service := newPlatformOperationsTestService(t, repository)
	session := platformOperationsTestSession(
		authorization.PermissionPlatformUserRead,
		authorization.PermissionPlatformOperationsRead,
	)
	userID := platformOperationsTestID(20)
	tenantID := platformOperationsTestID(21)
	email := "operator@example.invalid"
	repository.listUsers = func(_ context.Context, params ListUsersParams) (UserPage, error) {
		return params.Validate(UserPage{ProjectionVersion: 1, Items: []User{{
			ID: userID, Email: &email, DisplayName: "Operator", Active: true,
			PlatformRoles: []string{"platform_super_admin"}, ActiveTenantMembershipCount: 1,
			TotalTenantMembershipCount:         2,
			LiveSessionsByAuthenticationMethod: []LiveSessionSummary{{Method: "totp", LiveSessionCount: 1}},
		}}})
	}
	users, err := service.ListUsers(context.Background(), session, ListUsersInput{
		Limit: 50, Event: platformOperationsTestEvent(),
	})
	if err != nil || len(users.Items) != 1 || users.Items[0].TotalTenantMembershipCount != 2 {
		t.Fatalf("users = %#v, error = %v", users, err)
	}

	repository.listFailed = func(_ context.Context, params ListFailedNotificationsParams) (FailedNotificationPage, error) {
		return params.Validate(FailedNotificationPage{ProjectionVersion: 1, Items: []FailedNotification{{
			ID: platformOperationsTestID(30), TenantID: tenantID, Channel: "email",
			FailureClass: "connectivity", FailureCode: "unknown",
			FailureAt: platformOperationsTestNow.Add(-time.Minute),
			CreatedAt: platformOperationsTestNow.Add(-time.Hour),
			UpdatedAt: platformOperationsTestNow.Add(-time.Minute), AttemptCount: 3,
		}}})
	}
	failed, err := service.ListFailedNotifications(context.Background(), session, ListFailedNotificationsInput{
		Limit: 25, Event: platformOperationsTestEvent(),
	})
	if err != nil || failed.Items[0].FailureCode != "unknown" {
		t.Fatalf("failed = %#v, error = %v", failed, err)
	}
}

func TestUserProjectionAcceptsEveryStoredAuthenticationMethodWithoutWeakeningActorSessions(t *testing.T) {
	methods := []string{
		"bootstrap_totp", "ldap", "oidc", "passkey", "recovery_code", "saml", "totp",
	}
	summaries := make([]LiveSessionSummary, 0, len(methods))
	for _, method := range methods {
		summaries = append(summaries, LiveSessionSummary{Method: method, LiveSessionCount: 1})
		session := platformOperationsTestSession(authorization.PermissionPlatformUserRead)
		session.AuthenticationMethod = method
		wantLive := method != "recovery_code"
		if got := validPlatformSession(session, platformOperationsTestNow); got != wantLive {
			t.Fatalf("validPlatformSession(%q) = %t, want %t", method, got, wantLive)
		}
	}
	userID := platformOperationsTestID(60)
	page, err := validateUserPage(UserPage{
		ProjectionVersion: ProjectionVersion,
		Items: []User{{
			ID: userID, DisplayName: "Recovery-capable operator",
			LiveSessionsByAuthenticationMethod: summaries,
		}},
		NextCursor: &userID,
	})
	if err != nil || len(page.Items) != 1 || len(page.Items[0].LiveSessionsByAuthenticationMethod) != len(methods) {
		t.Fatalf("page = %#v, error = %v", page, err)
	}
}

func TestUserProjectionRequiresCanonicalOrderAndCursorProgress(t *testing.T) {
	firstID := platformOperationsTestID(61)
	lastID := platformOperationsTestID(62)
	valid := UserPage{
		ProjectionVersion: ProjectionVersion,
		Items: []User{
			{ID: firstID, DisplayName: "First", PlatformRoles: []string{"platform_auditor", "platform_super_admin"},
				LiveSessionsByAuthenticationMethod: []LiveSessionSummary{{Method: "ldap", LiveSessionCount: 1}, {Method: "totp", LiveSessionCount: 1}}},
			{ID: lastID, DisplayName: "Last"},
		},
		NextCursor: &lastID,
	}
	if _, err := validateUserPage(valid); err != nil {
		t.Fatalf("valid page error = %v", err)
	}

	tests := map[string]func(*UserPage){
		"user replay": func(page *UserPage) { page.Items[1].ID = firstID },
		"user reverse order": func(page *UserPage) {
			page.Items[0].ID, page.Items[1].ID = page.Items[1].ID, page.Items[0].ID
		},
		"role duplicate": func(page *UserPage) {
			page.Items[0].PlatformRoles = []string{"platform_auditor", "platform_auditor"}
		},
		"role reverse order": func(page *UserPage) {
			page.Items[0].PlatformRoles = []string{"platform_super_admin", "platform_auditor"}
		},
		"method duplicate": func(page *UserPage) {
			page.Items[0].LiveSessionsByAuthenticationMethod = []LiveSessionSummary{{Method: "ldap", LiveSessionCount: 1}, {Method: "ldap", LiveSessionCount: 2}}
		},
		"method reverse order": func(page *UserPage) {
			page.Items[0].LiveSessionsByAuthenticationMethod = []LiveSessionSummary{{Method: "totp", LiveSessionCount: 1}, {Method: "ldap", LiveSessionCount: 1}}
		},
		"cursor not last": func(page *UserPage) { page.NextCursor = &firstID },
		"cursor on empty": func(page *UserPage) {
			page.Items = nil
			page.NextCursor = &firstID
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			page := cloneUserPage(valid)
			mutate(&page)
			if _, err := validateUserPage(page); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestFailedNotificationProjectionRequiresDescendingOrderAndExactCursor(t *testing.T) {
	firstID := platformOperationsTestID(72)
	lastID := platformOperationsTestID(71)
	failureAt := platformOperationsTestNow.Add(-time.Minute)
	valid := FailedNotificationPage{
		ProjectionVersion: ProjectionVersion,
		Items: []FailedNotification{
			platformOperationsFailedNotification(firstID, failureAt),
			platformOperationsFailedNotification(lastID, failureAt),
		},
		NextCursor: &FailedNotificationCursor{ID: lastID, FailureAt: failureAt},
	}
	if _, err := validateFailedNotificationPage(valid, platformOperationsTestNow); err != nil {
		t.Fatalf("valid page error = %v", err)
	}

	tests := map[string]func(*FailedNotificationPage){
		"tuple replay": func(page *FailedNotificationPage) { page.Items[1] = page.Items[0] },
		"uuid reverse order": func(page *FailedNotificationPage) {
			page.Items[0], page.Items[1] = page.Items[1], page.Items[0]
		},
		"time reverse order": func(page *FailedNotificationPage) {
			page.Items[1].FailureAt = page.Items[0].FailureAt.Add(time.Second)
		},
		"cursor id mismatch": func(page *FailedNotificationPage) { page.NextCursor.ID = firstID },
		"cursor time mismatch": func(page *FailedNotificationPage) {
			page.NextCursor.FailureAt = page.NextCursor.FailureAt.Add(-time.Nanosecond)
		},
		"created after failure": func(page *FailedNotificationPage) {
			page.Items[0].CreatedAt = page.Items[0].FailureAt.Add(time.Nanosecond)
		},
		"failure after update": func(page *FailedNotificationPage) {
			page.Items[0].UpdatedAt = page.Items[0].FailureAt.Add(-time.Nanosecond)
		},
		"cursor on empty": func(page *FailedNotificationPage) { page.Items = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			page := valid
			page.Items = append([]FailedNotification(nil), valid.Items...)
			cursor := *valid.NextCursor
			page.NextCursor = &cursor
			mutate(&page)
			if _, err := validateFailedNotificationPage(page, platformOperationsTestNow); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestHealthProjectionRequiresExactMetricShape(t *testing.T) {
	valid := platformOperationsHealth()
	if _, err := validateHealth(valid, platformOperationsTestNow); err != nil {
		t.Fatalf("valid health error = %v", err)
	}

	negative := int64(-1)
	zero := int64(0)
	tests := map[string]func(*Health){
		"database exposes count": func(health *Health) {
			health.Checks[0].PendingCount = &zero
		},
		"audit chain exposes age": func(health *Health) {
			health.Checks[1].OldestPendingSeconds = &zero
		},
		"backlog missing pending": func(health *Health) {
			health.Checks[2].PendingCount = nil
		},
		"backlog exposes failure": func(health *Health) {
			health.Checks[2].FailedCount = &zero
		},
		"backlog negative age": func(health *Health) {
			health.Checks[2].OldestPendingSeconds = &negative
		},
		"failures missing count": func(health *Health) {
			health.Checks[3].FailedCount = nil
		},
		"failures exposes pending": func(health *Health) {
			health.Checks[3].PendingCount = &zero
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			health := valid
			health.Checks = append([]HealthCheck(nil), valid.Checks...)
			mutate(&health)
			if _, err := validateHealth(health, platformOperationsTestNow); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func platformOperationsFailedNotification(id uuid.UUID, failureAt time.Time) FailedNotification {
	return FailedNotification{
		ID: id, TenantID: platformOperationsTestID(73), Channel: "email",
		FailureClass: "connectivity", FailureCode: "unknown", FailureAt: failureAt,
		CreatedAt: failureAt.Add(-time.Hour), UpdatedAt: failureAt, AttemptCount: 2,
	}
}

type platformOperationsRepositoryStub struct {
	healthCalls         int
	updateSettingsCalls int
	getHealth           func(context.Context, ReadHealthParams) (Health, error)
	updateSettings      func(context.Context, UpdateSettingsParams) (GlobalSettings, error)
	updateFlag          func(context.Context, UpdateFeatureFlagParams) (FeatureFlag, error)
	listUsers           func(context.Context, ListUsersParams) (UserPage, error)
	listFailed          func(context.Context, ListFailedNotificationsParams) (FailedNotificationPage, error)
}

func (stub *platformOperationsRepositoryStub) ListUsers(ctx context.Context, params ListUsersParams) (UserPage, error) {
	if stub.listUsers == nil {
		return UserPage{}, ErrUnavailable
	}
	return stub.listUsers(ctx, params)
}
func (stub *platformOperationsRepositoryStub) GetSettings(context.Context, ReadSettingsParams) (GlobalSettings, error) {
	return GlobalSettings{}, ErrUnavailable
}
func (stub *platformOperationsRepositoryStub) UpdateSettings(ctx context.Context, params UpdateSettingsParams) (GlobalSettings, error) {
	stub.updateSettingsCalls++
	if stub.updateSettings == nil {
		return GlobalSettings{}, ErrUnavailable
	}
	return stub.updateSettings(ctx, params)
}
func (stub *platformOperationsRepositoryStub) GetHealth(ctx context.Context, params ReadHealthParams) (Health, error) {
	stub.healthCalls++
	if stub.getHealth == nil {
		return Health{}, ErrUnavailable
	}
	return stub.getHealth(ctx, params)
}
func (stub *platformOperationsRepositoryStub) ListQueues(context.Context, ReadQueueParams) (QueueSnapshot, error) {
	return QueueSnapshot{}, ErrUnavailable
}
func (stub *platformOperationsRepositoryStub) ListFailedNotifications(ctx context.Context, params ListFailedNotificationsParams) (FailedNotificationPage, error) {
	if stub.listFailed == nil {
		return FailedNotificationPage{}, ErrUnavailable
	}
	return stub.listFailed(ctx, params)
}
func (stub *platformOperationsRepositoryStub) ListFeatureFlags(context.Context, ReadFeatureFlagsParams) (FeatureFlagList, error) {
	return FeatureFlagList{}, ErrUnavailable
}
func (stub *platformOperationsRepositoryStub) UpdateFeatureFlag(ctx context.Context, params UpdateFeatureFlagParams) (FeatureFlag, error) {
	if stub.updateFlag == nil {
		return FeatureFlag{}, ErrUnavailable
	}
	return stub.updateFlag(ctx, params)
}

func newPlatformOperationsTestService(t *testing.T, repository Repository) *Service {
	t.Helper()
	service, err := NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return platformOperationsTestNow }
	service.newID = func() (uuid.UUID, error) { return platformOperationsTestID(99), nil }
	return service
}

func platformOperationsTestSession(permissions ...authorization.Permission) authentication.Session {
	return authentication.Session{
		ID: platformOperationsTestID(1), User: authentication.User{ID: platformOperationsTestID(2)},
		AuthenticationMethod: "totp", Permissions: permissions,
		IdleExpiresAt:     platformOperationsTestNow.Add(time.Hour),
		AbsoluteExpiresAt: platformOperationsTestNow.Add(2 * time.Hour),
	}
}

func platformOperationsTestEvent() authentication.EventContext {
	return authentication.EventContext{
		RequestID: platformOperationsTestID(3), CorrelationID: platformOperationsTestID(4),
		RemoteAddress: netip.MustParseAddr("198.51.100.42"), UserAgent: "platform operations test",
	}
}

func platformOperationsHealth() Health {
	zero := int64(0)
	return Health{
		ProjectionVersion: 1, CheckedAt: platformOperationsTestNow, Status: "healthy",
		Checks: []HealthCheck{
			{Key: "database", Status: "healthy"},
			{Key: "platform_audit_chain", Status: "healthy"},
			{Key: "queue_backlog", Status: "healthy", PendingCount: &zero, OldestPendingSeconds: &zero},
			{Key: "queue_failures", Status: "healthy", FailedCount: &zero},
		},
	}
}

func platformOperationsTestID(offset int) uuid.UUID {
	return uuid.MustParse("019d4d16-2160-7000-8000-" +
		fmtTestSuffix(offset))
}

func fmtTestSuffix(offset int) string {
	const hexadecimal = "0123456789abcdef"
	value := make([]byte, 12)
	for index := len(value) - 1; index >= 0; index-- {
		value[index] = hexadecimal[offset&15]
		offset >>= 4
	}
	return string(value)
}
