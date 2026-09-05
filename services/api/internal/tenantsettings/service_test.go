package tenantsettings

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

var settingsTestNow = time.Date(2026, 9, 1, 18, 0, 0, 123_000_000, time.UTC)

func TestNewServiceRejectsNilDependencies(t *testing.T) {
	validRepository := &settingsRepositoryStub{}
	validAuthority := &settingsAuthorityStub{}
	var nilRepository *settingsRepositoryStub
	var nilAuthority *settingsAuthorityStub

	for name, dependencies := range map[string]struct {
		repository Repository
		authority  TenantAuthorityResolver
	}{
		"nil repository":       {repository: nil, authority: validAuthority},
		"typed nil repository": {repository: nilRepository, authority: validAuthority},
		"nil authority":        {repository: validRepository, authority: nil},
		"typed nil authority":  {repository: validRepository, authority: nilAuthority},
	} {
		t.Run(name, func(t *testing.T) {
			if service, err := NewService(dependencies.repository, dependencies.authority); err == nil || service != nil {
				t.Fatalf("service = %#v, error = %v", service, err)
			}
		})
	}
}

func TestGetRequiresLiveMatchingTenantAndExactReadAuthority(t *testing.T) {
	tenantID := settingsTestID(1)
	otherTenantID := settingsTestID(2)
	repository := &settingsRepositoryStub{}
	authority := &settingsAuthorityStub{authority: settingsTestAuthority(
		tenantID,
		authorization.TenantPermissionSettingsRead,
	)}
	service := newSettingsTestService(t, repository, authority)
	session := settingsTestSession(tenantID)
	want := settingsProjection(tenantID, 1)
	repository.get = func(_ context.Context, params ReadParams) (Settings, error) {
		if params.TenantID != tenantID || params.Actor.UserID != session.User.ID ||
			params.Actor.SessionID != session.ID || params.Actor.ActiveTenantID != tenantID ||
			params.Actor.AuthenticationMethod != "totp" {
			t.Fatalf("params = %#v", params)
		}
		return want, nil
	}

	got, err := service.Get(context.Background(), session, tenantID)
	if err != nil || got != want {
		t.Fatalf("settings = %#v, error = %v", got, err)
	}
	if authority.calls != 1 || repository.getCalls != 1 {
		t.Fatalf("authority calls = %d, repository calls = %d", authority.calls, repository.getCalls)
	}

	for name, invalidSession := range map[string]authentication.Session{
		"foreign active tenant": func() authentication.Session {
			value := session
			value.ActiveTenantID = &otherTenantID
			return value
		}(),
		"expired idle deadline": func() authentication.Session {
			value := session
			value.IdleExpiresAt = settingsTestNow
			return value
		}(),
		"revoked": func() authentication.Session {
			value := session
			revokedAt := settingsTestNow.Add(-time.Second)
			value.RevokedAt = &revokedAt
			return value
		}(),
		"non-v7 session": func() authentication.Session {
			value := session
			value.ID = uuid.New()
			return value
		}(),
		"unknown authentication method": func() authentication.Session {
			value := session
			value.AuthenticationMethod = "password"
			return value
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := service.Get(context.Background(), invalidSession, tenantID); !errors.Is(err, ErrForbidden) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if authority.calls != 1 || repository.getCalls != 1 {
		t.Fatalf("invalid sessions reached dependencies: %d, %d", authority.calls, repository.getCalls)
	}

	deniedAuthority := &settingsAuthorityStub{authority: settingsTestAuthority(tenantID)}
	deniedService := newSettingsTestService(t, repository, deniedAuthority)
	if _, err := deniedService.Get(context.Background(), session, tenantID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("missing permission error = %v", err)
	}
	if repository.getCalls != 1 {
		t.Fatalf("denied get reached repository: %d", repository.getCalls)
	}

	var nilContext context.Context
	if _, err := service.Get(nilContext, session, tenantID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("nil context error = %v", err)
	}
	if _, err := service.Get(context.Background(), session, uuid.Nil); !errors.Is(err, ErrForbidden) {
		t.Fatalf("nil tenant error = %v", err)
	}
}

func TestUpdateRequiresReadAndManageAndNormalizesInput(t *testing.T) {
	tenantID := settingsTestID(1)
	repository := &settingsRepositoryStub{}
	authority := &settingsAuthorityStub{authority: settingsTestAuthority(
		tenantID,
		authorization.TenantPermissionSettingsRead,
		authorization.TenantPermissionSettingsManage,
	)}
	service := newSettingsTestService(t, repository, authority)
	auditID := settingsTestID(50)
	service.newID = func() (uuid.UUID, error) { return auditID, nil }
	session := settingsTestSession(tenantID)
	event := settingsTestEvent()
	repository.update = func(_ context.Context, params UpdateParams) (Settings, error) {
		if params.Actor.UserID != session.User.ID || params.TenantID != tenantID ||
			params.ExpectedVersion != 1 || params.BrandName != "Orbit Response" ||
			params.BrandMark != "ORB" || params.PrimaryColor != "#2f5bea" ||
			params.AccentColor != "#10b981" || params.Timezone != "Europe/Rome" ||
			params.Locale != "it-IT" || params.Reason != "Apply approved identity" ||
			params.AuditID != auditID || params.Event != event {
			t.Fatalf("params = %#v", params)
		}
		return Settings{
			TenantID: tenantID, BrandName: params.BrandName, BrandMark: params.BrandMark,
			PrimaryColor: params.PrimaryColor, AccentColor: params.AccentColor,
			Timezone: params.Timezone, Locale: params.Locale, Version: 2,
			UpdatedAt: settingsTestNow,
		}, nil
	}

	got, err := service.Update(context.Background(), session, tenantID, UpdateInput{
		ExpectedVersion: 1,
		BrandName:       "  Orbit Response  ",
		BrandMark:       " orb ",
		PrimaryColor:    " #2F5BEA ",
		AccentColor:     " #10B981 ",
		Timezone:        " Europe/Rome ",
		Locale:          " it-IT ",
		Reason:          " Apply approved identity ",
		Event:           event,
	})
	if err != nil || got.Version != 2 || got.BrandMark != "ORB" {
		t.Fatalf("settings = %#v, error = %v", got, err)
	}

	for name, permissions := range map[string][]authorization.TenantPermission{
		"read only":   {authorization.TenantPermissionSettingsRead},
		"manage only": {authorization.TenantPermissionSettingsManage},
		"neither":     {},
	} {
		t.Run(name, func(t *testing.T) {
			denied := newSettingsTestService(t, repository, &settingsAuthorityStub{
				authority: settingsTestAuthority(tenantID, permissions...),
			})
			if _, err := denied.Update(context.Background(), session, tenantID, settingsTestInput()); !errors.Is(err, ErrForbidden) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if repository.updateCalls != 1 {
		t.Fatalf("denied updates reached repository: %d", repository.updateCalls)
	}
}

func TestUpdateRejectsMalformedInputsBeforePersistence(t *testing.T) {
	tenantID := settingsTestID(1)
	repository := &settingsRepositoryStub{}
	service := newSettingsTestService(t, repository, &settingsAuthorityStub{
		authority: settingsTestAuthority(
			tenantID,
			authorization.TenantPermissionSettingsRead,
			authorization.TenantPermissionSettingsManage,
		),
	})
	session := settingsTestSession(tenantID)

	tests := map[string]func(*UpdateInput){
		"zero version":      func(input *UpdateInput) { input.ExpectedVersion = 0 },
		"exhausted version": func(input *UpdateInput) { input.ExpectedVersion = 1<<31 - 1 },
		"empty brand":       func(input *UpdateInput) { input.BrandName = " \t " },
		"control in brand":  func(input *UpdateInput) { input.BrandName = "Unsafe\nBrand" },
		"format in brand":   func(input *UpdateInput) { input.BrandName = "Trusted\u202eexe" },
		"long brand":        func(input *UpdateInput) { input.BrandName = string(make([]rune, 81)) },
		"bad mark":          func(input *UpdateInput) { input.BrandMark = "TOO-LONG" },
		"bad primary":       func(input *UpdateInput) { input.PrimaryColor = "red" },
		"identical colors":  func(input *UpdateInput) { input.AccentColor = input.PrimaryColor },
		"local timezone":    func(input *UpdateInput) { input.Timezone = "Local" },
		"unknown timezone":  func(input *UpdateInput) { input.Timezone = "Mars/Olympus" },
		"undefined locale":  func(input *UpdateInput) { input.Locale = "und" },
		"bad locale":        func(input *UpdateInput) { input.Locale = "not_a_locale" },
		"empty reason":      func(input *UpdateInput) { input.Reason = "   " },
		"control in reason": func(input *UpdateInput) { input.Reason = "unsafe\nreason" },
		"non-v7 request":    func(input *UpdateInput) { input.Event.RequestID = uuid.New() },
		"invalid remote ip": func(input *UpdateInput) { input.Event.RemoteAddress = netip.Addr{} },
		"empty user agent":  func(input *UpdateInput) { input.Event.UserAgent = "" },
		"oversize user agent": func(input *UpdateInput) {
			input.Event.UserAgent = string(make([]byte, 1025))
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := settingsTestInput()
			mutate(&input)
			if _, err := service.Update(context.Background(), session, tenantID, input); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if repository.updateCalls != 0 {
		t.Fatalf("invalid updates reached repository: %d", repository.updateCalls)
	}
}

func TestDependencyErrorsAndMalformedProjectionsFailClosed(t *testing.T) {
	tenantID := settingsTestID(1)
	session := settingsTestSession(tenantID)
	permissions := settingsTestAuthority(
		tenantID,
		authorization.TenantPermissionSettingsRead,
		authorization.TenantPermissionSettingsManage,
	)

	for name, dependencyError := range map[string]error{
		"invalid":     authorization.ErrInvalidInput,
		"forbidden":   authorization.ErrForbidden,
		"not found":   authorization.ErrNotFound,
		"unavailable": errors.New("dependency unavailable"),
	} {
		t.Run("authority "+name, func(t *testing.T) {
			service := newSettingsTestService(t, &settingsRepositoryStub{}, &settingsAuthorityStub{err: dependencyError})
			_, err := service.Get(context.Background(), session, tenantID)
			want := mapDependencyError(dependencyError)
			if !errors.Is(err, want) {
				t.Fatalf("error = %v, want %v", err, want)
			}
		})
	}

	for name, dependencyError := range map[string]error{
		"invalid":     ErrInvalidInput,
		"forbidden":   ErrForbidden,
		"not found":   ErrNotFound,
		"conflict":    ErrConflict,
		"unavailable": errors.New("database unavailable"),
	} {
		t.Run("repository "+name, func(t *testing.T) {
			repository := &settingsRepositoryStub{
				get: func(context.Context, ReadParams) (Settings, error) {
					return Settings{}, dependencyError
				},
			}
			service := newSettingsTestService(t, repository, &settingsAuthorityStub{authority: permissions})
			_, err := service.Get(context.Background(), session, tenantID)
			want := mapDependencyError(dependencyError)
			if !errors.Is(err, want) {
				t.Fatalf("error = %v, want %v", err, want)
			}
		})
	}

	for name, malformed := range map[string]Settings{
		"wrong tenant": func() Settings {
			value := settingsProjection(tenantID, 1)
			value.TenantID = settingsTestID(99)
			return value
		}(),
		"future update": func() Settings {
			value := settingsProjection(tenantID, 1)
			value.UpdatedAt = settingsTestNow.Add(2 * time.Second)
			return value
		}(),
		"invalid colors": func() Settings {
			value := settingsProjection(tenantID, 1)
			value.AccentColor = value.PrimaryColor
			return value
		}(),
		"format in brand": func() Settings {
			value := settingsProjection(tenantID, 1)
			value.BrandName = "Trusted\u202eexe"
			return value
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			repository := &settingsRepositoryStub{
				get: func(context.Context, ReadParams) (Settings, error) { return malformed, nil },
			}
			service := newSettingsTestService(t, repository, &settingsAuthorityStub{authority: permissions})
			if _, err := service.Get(context.Background(), session, tenantID); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	repository := &settingsRepositoryStub{}
	service := newSettingsTestService(t, repository, &settingsAuthorityStub{authority: permissions})
	service.newID = func() (uuid.UUID, error) { return uuid.Nil, errors.New("entropy unavailable") }
	if _, err := service.Update(context.Background(), session, tenantID, settingsTestInput()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("ID generator error = %v", err)
	}
	service.newID = func() (uuid.UUID, error) { return uuid.New(), nil }
	if _, err := service.Update(context.Background(), session, tenantID, settingsTestInput()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("non-v7 audit ID error = %v", err)
	}
	if repository.updateCalls != 0 {
		t.Fatalf("invalid audit IDs reached repository: %d", repository.updateCalls)
	}
}

type settingsRepositoryStub struct {
	getCalls    int
	updateCalls int
	get         func(context.Context, ReadParams) (Settings, error)
	update      func(context.Context, UpdateParams) (Settings, error)
}

func (stub *settingsRepositoryStub) Get(ctx context.Context, params ReadParams) (Settings, error) {
	stub.getCalls++
	if stub.get == nil {
		return Settings{}, ErrUnavailable
	}
	return stub.get(ctx, params)
}

func (stub *settingsRepositoryStub) Update(ctx context.Context, params UpdateParams) (Settings, error) {
	stub.updateCalls++
	if stub.update == nil {
		return Settings{}, ErrUnavailable
	}
	return stub.update(ctx, params)
}

type settingsAuthorityStub struct {
	calls     int
	authority authorization.TenantAuthority
	err       error
}

func (stub *settingsAuthorityStub) GetTenantAuthority(
	_ context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
) (authorization.TenantAuthority, error) {
	stub.calls++
	if actor.ActiveTenantID != tenantID || actor.UserID == uuid.Nil || actor.SessionID == uuid.Nil {
		return authorization.TenantAuthority{}, ErrInvalidInput
	}
	return stub.authority, stub.err
}

func newSettingsTestService(
	t *testing.T,
	repository Repository,
	authority TenantAuthorityResolver,
) *Service {
	t.Helper()
	service, err := NewService(repository, authority)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return settingsTestNow }
	service.newID = func() (uuid.UUID, error) { return settingsTestID(90), nil }
	return service
}

func settingsTestSession(tenantID uuid.UUID) authentication.Session {
	return authentication.Session{
		ID:                   settingsTestID(10),
		User:                 authentication.User{ID: settingsTestID(11)},
		ActiveTenantID:       &tenantID,
		AuthenticationMethod: "totp",
		IdleExpiresAt:        settingsTestNow.Add(time.Hour),
		AbsoluteExpiresAt:    settingsTestNow.Add(2 * time.Hour),
	}
}

func settingsTestAuthority(
	tenantID uuid.UUID,
	permissions ...authorization.TenantPermission,
) authorization.TenantAuthority {
	grants := make([]authorization.ScopedPermission, len(permissions))
	for index, permission := range permissions {
		grants[index] = authorization.ScopedPermission{
			Permission: permission,
			Scope:      authorization.ScopeTenant,
		}
	}
	return authorization.TenantAuthority{
		TenantID: tenantID,
		Principal: authorization.TenantPrincipal{
			ID:   settingsTestID(11),
			Kind: authorization.PrincipalKindHuman,
		},
		MembershipID:     settingsTestID(12),
		MembershipStatus: authorization.MembershipStatusActive,
		LegacyRole:       authorization.LegacyMembershipRoleTenantAdmin,
		Permissions:      grants,
		EvaluatedAt:      settingsTestNow,
	}
}

func settingsProjection(tenantID uuid.UUID, version int32) Settings {
	return Settings{
		TenantID:     tenantID,
		BrandName:    "Orbit Response",
		BrandMark:    "ORB",
		PrimaryColor: "#2f5bea",
		AccentColor:  "#10b981",
		Timezone:     "Europe/Rome",
		Locale:       "it-IT",
		Version:      version,
		UpdatedAt:    settingsTestNow,
	}
}

func settingsTestInput() UpdateInput {
	return UpdateInput{
		ExpectedVersion: 1,
		BrandName:       "Orbit Response",
		BrandMark:       "ORB",
		PrimaryColor:    "#2f5bea",
		AccentColor:     "#10b981",
		Timezone:        "Europe/Rome",
		Locale:          "it-IT",
		Reason:          "Apply approved identity",
		Event:           settingsTestEvent(),
	}
}

func settingsTestEvent() authentication.EventContext {
	return authentication.EventContext{
		RequestID:     settingsTestID(30),
		CorrelationID: settingsTestID(31),
		RemoteAddress: netip.MustParseAddr("192.0.2.10"),
		UserAgent:     "tenant-settings-test",
	}
}

func settingsTestID(value uint32) uuid.UUID {
	const digits = "0123456789abcdef"
	suffix := []byte("000000000000")
	for index := len(suffix) - 1; value > 0; index-- {
		suffix[index] = digits[value&15]
		value >>= 4
	}
	return uuid.MustParse("00000000-0000-7000-8000-" + string(suffix))
}
