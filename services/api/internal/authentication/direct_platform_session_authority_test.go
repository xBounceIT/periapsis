package authentication

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
)

type directPlatformSessionAuthorityFunc func(
	context.Context,
	DirectPlatformSessionAuthorityLookup,
) (DirectPlatformSessionAuthorityResult, error)

func (function directPlatformSessionAuthorityFunc) RevalidateDirectPlatformSession(
	ctx context.Context,
	lookup DirectPlatformSessionAuthorityLookup,
) (DirectPlatformSessionAuthorityResult, error) {
	return function(ctx, lookup)
}

func TestAuthenticateRevalidatesDirectPlatformOIDCBeforeIdleTouch(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	sessionID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	order := make([]string, 0, 2)
	repository := &repositoryStub{
		resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
			return Session{
				ID: sessionID, User: User{ID: userID}, AuthenticationMethod: "oidc",
				IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
			}, nil
		},
		touchSession: func(context.Context, []byte, time.Time, time.Time) error {
			order = append(order, "touch")
			return nil
		},
	}
	service := newAuthenticationServiceAt(
		t, repository, &passwordEngineStub{}, totpEngineStub{},
		digest("bootstrap-authority-value-000000"), now,
	)
	var observed DirectPlatformSessionAuthorityLookup
	err := service.BindDirectPlatformSessionAuthority(directPlatformSessionAuthorityFunc(func(
		_ context.Context,
		lookup DirectPlatformSessionAuthorityLookup,
	) (DirectPlatformSessionAuthorityResult, error) {
		order = append(order, "revalidate")
		observed = lookup
		return DirectPlatformSessionAuthorityResult{
			SessionID: lookup.SessionID, UserID: lookup.UserID,
			AllowAuthority: true, AllowIdleTouch: true,
		}, nil
	}))
	if err != nil {
		t.Fatalf("BindDirectPlatformSessionAuthority() error = %v", err)
	}

	if _, err = service.Authenticate(context.Background(), validTestToken(0x91)); err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if !slices.Equal(order, []string{"revalidate", "touch"}) {
		t.Fatalf("operation order = %v", order)
	}
	want := DirectPlatformSessionAuthorityLookup{
		SessionID: sessionID, UserID: userID, AuthenticationMethod: "oidc", Audience: "api",
	}
	if observed != want {
		t.Fatalf("authority lookup = %#v, want %#v", observed, want)
	}
}

func TestAuthenticateDirectPlatformOIDCFailsClosedWithoutTouch(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	sessionID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	tests := map[string]DirectPlatformSessionAuthority{
		"unbound": nil,
		"dependency failure": directPlatformSessionAuthorityFunc(func(
			context.Context,
			DirectPlatformSessionAuthorityLookup,
		) (DirectPlatformSessionAuthorityResult, error) {
			return DirectPlatformSessionAuthorityResult{}, errors.New("hidden")
		}),
		"authority denied": directPlatformSessionAuthorityFunc(func(
			_ context.Context,
			lookup DirectPlatformSessionAuthorityLookup,
		) (DirectPlatformSessionAuthorityResult, error) {
			return DirectPlatformSessionAuthorityResult{
				SessionID: lookup.SessionID, UserID: lookup.UserID, AllowIdleTouch: true,
			}, nil
		}),
		"idle touch denied": directPlatformSessionAuthorityFunc(func(
			_ context.Context,
			lookup DirectPlatformSessionAuthorityLookup,
		) (DirectPlatformSessionAuthorityResult, error) {
			return DirectPlatformSessionAuthorityResult{
				SessionID: lookup.SessionID, UserID: lookup.UserID, AllowAuthority: true,
			}, nil
		}),
		"identity mismatch": directPlatformSessionAuthorityFunc(func(
			_ context.Context,
			lookup DirectPlatformSessionAuthorityLookup,
		) (DirectPlatformSessionAuthorityResult, error) {
			return DirectPlatformSessionAuthorityResult{
				SessionID: lookup.SessionID, UserID: uuid.Must(uuid.NewV7()),
				AllowAuthority: true, AllowIdleTouch: true,
			}, nil
		}),
	}
	for name, authority := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			touched := false
			repository := &repositoryStub{
				resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
					return Session{
						ID: sessionID, User: User{ID: userID}, AuthenticationMethod: "oidc",
						IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
					}, nil
				},
				touchSession: func(context.Context, []byte, time.Time, time.Time) error {
					touched = true
					return nil
				},
			}
			service := newAuthenticationServiceAt(
				t, repository, &passwordEngineStub{}, totpEngineStub{},
				digest("bootstrap-authority-value-000000"), now,
			)
			if authority != nil {
				if err := service.BindDirectPlatformSessionAuthority(authority); err != nil {
					t.Fatalf("BindDirectPlatformSessionAuthority() error = %v", err)
				}
			}
			if _, err := service.Authenticate(context.Background(), validTestToken(0x92)); !errors.Is(err, ErrInvalidAuthentication) {
				t.Fatalf("Authenticate() error = %v, want invalid authentication", err)
			}
			if touched {
				t.Fatal("rejected direct authority touched idle expiry")
			}
		})
	}
}

func TestAuthenticateRoutesTenantlessSAMLToDirectPlatformDispatcher(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	sessionID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	touched := false
	repository := &repositoryStub{
		resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
			return Session{
				ID: sessionID, User: User{ID: userID}, AuthenticationMethod: "saml",
				IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
			}, nil
		},
		touchSession: func(context.Context, []byte, time.Time, time.Time) error {
			touched = true
			return nil
		},
	}
	service := newAuthenticationServiceAt(
		t, repository, &passwordEngineStub{}, totpEngineStub{},
		digest("bootstrap-authority-value-000000"), now,
	)
	var observed DirectPlatformSessionAuthorityLookup
	if err := service.BindDirectPlatformSessionAuthority(directPlatformSessionAuthorityFunc(func(
		_ context.Context,
		lookup DirectPlatformSessionAuthorityLookup,
	) (DirectPlatformSessionAuthorityResult, error) {
		observed = lookup
		return DirectPlatformSessionAuthorityResult{
			SessionID: lookup.SessionID, UserID: lookup.UserID,
			AllowAuthority: true, AllowIdleTouch: true,
		}, nil
	})); err != nil {
		t.Fatalf("BindDirectPlatformSessionAuthority() error = %v", err)
	}
	if _, err := service.Authenticate(context.Background(), validTestToken(0x93)); err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if !touched || observed != (DirectPlatformSessionAuthorityLookup{
		SessionID: sessionID, UserID: userID, AuthenticationMethod: "saml", Audience: "api",
	}) {
		t.Fatalf("SAML direct revalidation = touched %t, lookup %#v", touched, observed)
	}
}

func TestTenantlessPasskeyNeverUsesDirectProviderDispatcher(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	called := false
	repository := &repositoryStub{resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
		return Session{
			ID: uuid.Must(uuid.NewV7()), User: User{ID: uuid.Must(uuid.NewV7())},
			AuthenticationMethod: "passkey", IdleExpiresAt: now.Add(time.Hour),
			AbsoluteExpiresAt: now.Add(8 * time.Hour),
		}, nil
	}}
	service := newAuthenticationServiceAt(
		t, repository, &passwordEngineStub{}, totpEngineStub{},
		digest("bootstrap-authority-value-000000"), now,
	)
	if err := service.BindDirectPlatformSessionAuthority(directPlatformSessionAuthorityFunc(func(
		context.Context,
		DirectPlatformSessionAuthorityLookup,
	) (DirectPlatformSessionAuthorityResult, error) {
		called = true
		return DirectPlatformSessionAuthorityResult{}, nil
	})); err != nil {
		t.Fatalf("BindDirectPlatformSessionAuthority() error = %v", err)
	}
	if _, err := service.Authenticate(context.Background(), validTestToken(0x94)); !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("Authenticate() error = %v, want invalid authentication", err)
	}
	if called {
		t.Fatal("tenantless passkey session reached direct provider dispatcher")
	}
}

func TestBindDirectPlatformSessionAuthorityIsIndependentAndOneTime(t *testing.T) {
	t.Parallel()
	service := newAuthenticationService(
		t, &repositoryStub{}, &passwordEngineStub{}, totpEngineStub{},
		digest("bootstrap-authority-value-000000"),
	)
	authority := directPlatformSessionAuthorityFunc(func(
		context.Context,
		DirectPlatformSessionAuthorityLookup,
	) (DirectPlatformSessionAuthorityResult, error) {
		return DirectPlatformSessionAuthorityResult{}, nil
	})
	if err := service.BindDirectPlatformSessionAuthority(nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("BindDirectPlatformSessionAuthority(nil) error = %v", err)
	}
	if err := service.BindDirectPlatformSessionAuthority(authority); err != nil {
		t.Fatalf("BindDirectPlatformSessionAuthority() error = %v", err)
	}
	if err := service.BindDirectPlatformSessionAuthority(authority); !errors.Is(err, ErrConflict) {
		t.Fatalf("second BindDirectPlatformSessionAuthority() error = %v", err)
	}
}

func TestAuthenticateReturnsExactDirectPlatformTransitionWithoutIdleTouch(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	sessionID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	delivery := &federatedSessionTransitionDeliveryStub{}
	touched := false
	repository := &repositoryStub{
		resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
			return Session{
				ID: sessionID, User: User{ID: userID}, AuthenticationMethod: "saml",
				IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
			}, nil
		},
		touchSession: func(context.Context, []byte, time.Time, time.Time) error {
			touched = true
			return nil
		},
	}
	service := newAuthenticationServiceAt(
		t, repository, &passwordEngineStub{}, totpEngineStub{},
		digest("bootstrap-authority-value-000000"), now,
	)
	continuationID := uuid.Must(uuid.NewV7())
	if err := service.BindDirectPlatformSessionAuthority(directPlatformSessionAuthorityFunc(func(
		_ context.Context,
		lookup DirectPlatformSessionAuthorityLookup,
	) (DirectPlatformSessionAuthorityResult, error) {
		transition, transitionErr := NewDirectPlatformSessionStepUpTransition(
			lookup, continuationID, now.Add(5*time.Minute), []byte(validTestToken(0xb1)), delivery,
		)
		if transitionErr != nil {
			return DirectPlatformSessionAuthorityResult{}, transitionErr
		}
		return DirectPlatformSessionAuthorityResult{
			SessionID: lookup.SessionID, UserID: lookup.UserID, Transition: transition,
		}, nil
	})); err != nil {
		t.Fatalf("BindDirectPlatformSessionAuthority() error = %v", err)
	}
	_, err := service.Authenticate(context.Background(), validTestToken(0xb2))
	var transitionError *FederatedSessionTransitionError
	if !errors.As(err, &transitionError) || !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("Authenticate() error = %T %v", err, err)
	}
	if touched {
		t.Fatal("direct transition touched the rejected predecessor session")
	}
	material, consumed := transitionError.Consume()
	if !consumed || material.ContinuationID != continuationID || material.Delivery != delivery {
		t.Fatalf("transition material = %s, consumed=%t", material, consumed)
	}
	material.Destroy()
}

func TestAuthenticateCompensatesMalformedDirectPlatformTransitionResult(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	sessionID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	delivery := &federatedSessionTransitionDeliveryStub{}
	repository := &repositoryStub{
		resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
			return Session{
				ID: sessionID, User: User{ID: userID}, AuthenticationMethod: "saml",
				IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
			}, nil
		},
	}
	service := newAuthenticationServiceAt(
		t, repository, &passwordEngineStub{}, totpEngineStub{},
		digest("bootstrap-authority-value-000000"), now,
	)
	if err := service.BindDirectPlatformSessionAuthority(directPlatformSessionAuthorityFunc(func(
		_ context.Context,
		lookup DirectPlatformSessionAuthorityLookup,
	) (DirectPlatformSessionAuthorityResult, error) {
		transition, transitionErr := NewDirectPlatformSessionRotationTransition(
			lookup, uuid.Must(uuid.NewV7()), now.Add(time.Hour),
			[]byte(validTestToken(0xb3)), []byte(validTestToken(0xb4)), delivery,
		)
		if transitionErr != nil {
			return DirectPlatformSessionAuthorityResult{}, transitionErr
		}
		return DirectPlatformSessionAuthorityResult{
			SessionID: lookup.SessionID, UserID: uuid.Must(uuid.NewV7()), Transition: transition,
		}, nil
	})); err != nil {
		t.Fatalf("BindDirectPlatformSessionAuthority() error = %v", err)
	}
	if _, err := service.Authenticate(context.Background(), validTestToken(0xb5)); !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("Authenticate() error = %v", err)
	}
	confirmed, compensated := delivery.counts()
	if confirmed != 0 || compensated != 1 {
		t.Fatalf("delivery finalization = confirmed %d, compensated %d", confirmed, compensated)
	}
}
