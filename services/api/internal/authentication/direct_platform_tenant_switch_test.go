package authentication

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type directPlatformTenantSwitcherFunc func(
	context.Context,
	DirectPlatformTenantSwitchRequest,
) (Session, error)

func (function directPlatformTenantSwitcherFunc) SwitchDirectPlatformTenant(
	ctx context.Context,
	request DirectPlatformTenantSwitchRequest,
) (Session, error) {
	return function(ctx, request)
}

type directSwitchTokenSource struct {
	opaque string
	err    error
}

func (source directSwitchTokenSource) Opaque() (string, error) { return source.opaque, source.err }
func (directSwitchTokenSource) RecoveryCode() (string, []byte, error) {
	return "", nil, errors.New("not used")
}

func TestSwitchTenantRotatesDirectPlatformFederationThroughDedicatedBoundary(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 13, 0, 0, 0, time.UTC)
	for _, method := range []string{"oidc", "saml"} {
		method := method
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			sourceID := uuid.Must(uuid.NewV7())
			familyID := uuid.Must(uuid.NewV7())
			userID := uuid.Must(uuid.NewV7())
			targetID := uuid.Must(uuid.NewV7())
			sessionToken := validTestToken(0x94)
			csrf := validTestToken(0x95)
			repository := &repositoryStub{
				resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
					return Session{
						ID: sourceID, RotationFamilyID: familyID, User: User{ID: userID},
						CSRFDigest: digest(csrf), AuthenticationMethod: method,
						CreatedAt: now.Add(-time.Hour), LastSeenAt: now.Add(-time.Minute),
						IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
					}, nil
				},
			}
			service := newAuthenticationServiceAt(
				t, repository, &passwordEngineStub{}, totpEngineStub{},
				digest("bootstrap-authority-value-000000"), now,
			)
			bindAllowingDirectAuthority(t, service)
			var observed DirectPlatformTenantSwitchRequest
			if err := service.BindDirectPlatformTenantSwitcher(directPlatformTenantSwitcherFunc(func(
				_ context.Context,
				request DirectPlatformTenantSwitchRequest,
			) (Session, error) {
				observed = request
				return validDirectSwitchSession(request), nil
			})); err != nil {
				t.Fatalf("BindDirectPlatformTenantSwitcher() error = %v", err)
			}

			credential, err := service.SwitchTenant(
				context.Background(), sessionToken, csrf, targetID, testEvent(),
			)
			if err != nil {
				t.Fatalf("SwitchTenant() error = %v", err)
			}
			if observed.SourceSessionID != sourceID || observed.RotationFamilyID != familyID ||
				observed.AuthenticationMethod != method || observed.UserID != userID ||
				observed.TargetTenantID != targetID || observed.NewSessionID != credential.Session.ID ||
				!observed.AbsoluteExpiresAt.Equal(now.Add(8*time.Hour)) {
				t.Fatalf("switch request = %#v", observed)
			}
			if len(observed.AdmissionRules) != 1 ||
				observed.AdmissionRules[0].Key.Scope != rateScopeTenantSwitch {
				t.Fatalf("switch admission = %#v", observed.AdmissionRules)
			}
			if credential.SessionToken == sessionToken || credential.CSRFToken == csrf ||
				credential.Session.AuthenticationMethod != method || credential.Session.ActiveTenantID == nil ||
				*credential.Session.ActiveTenantID != targetID {
				t.Fatalf("switch credential = %#v", credential)
			}
		})
	}
}

func TestSwitchTenantDirectPlatformOIDCFailsClosedWithoutDedicatedBoundary(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 13, 0, 0, 0, time.UTC)
	service, csrf := directSwitchTestService(t, now)
	bindAllowingDirectAuthority(t, service)
	if _, err := service.SwitchTenant(
		context.Background(), validTestToken(0x97), csrf, uuid.Must(uuid.NewV7()), testEvent(),
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("SwitchTenant() error = %v, want forbidden", err)
	}
}

func TestDirectPlatformTenantSwitchRejectsLocalAndUnknownMethodsBeforeAdapter(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 13, 0, 0, 0, time.UTC)
	for _, method := range []string{"local", "future_protocol"} {
		method := method
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			csrf := validTestToken(0x98)
			service := newAuthenticationServiceAt(
				t, &repositoryStub{}, &passwordEngineStub{}, totpEngineStub{},
				digest("bootstrap-authority-value-000000"), now,
			)
			calls := 0
			if err := service.BindDirectPlatformTenantSwitcher(directPlatformTenantSwitcherFunc(func(
				context.Context,
				DirectPlatformTenantSwitchRequest,
			) (Session, error) {
				calls++
				return Session{}, nil
			})); err != nil {
				t.Fatalf("BindDirectPlatformTenantSwitcher() error = %v", err)
			}
			source := Session{
				ID: uuid.Must(uuid.NewV7()), RotationFamilyID: uuid.Must(uuid.NewV7()),
				User: User{ID: uuid.Must(uuid.NewV7())}, CSRFDigest: digest(csrf),
				AuthenticationMethod: method, IdleExpiresAt: now.Add(time.Hour),
				AbsoluteExpiresAt: now.Add(8 * time.Hour),
			}
			if _, err := service.switchDirectPlatformTenant(
				context.Background(), validTestToken(0x99), source,
				uuid.Must(uuid.NewV7()), testEvent(),
			); !errors.Is(err, ErrForbidden) {
				t.Fatalf("switchDirectPlatformTenant() error = %v, want forbidden", err)
			}
			if calls != 0 {
				t.Fatalf("non-federated method reached direct switch adapter %d times", calls)
			}
		})
	}
}

func TestSwitchTenantRejectsMalformedDirectRotationProjection(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 13, 0, 0, 0, time.UTC)
	service, csrf := directSwitchTestService(t, now)
	bindAllowingDirectAuthority(t, service)
	if err := service.BindDirectPlatformTenantSwitcher(directPlatformTenantSwitcherFunc(func(
		_ context.Context,
		request DirectPlatformTenantSwitchRequest,
	) (Session, error) {
		result := validDirectSwitchSession(request)
		result.RotationFamilyID = uuid.Must(uuid.NewV7())
		return result, nil
	})); err != nil {
		t.Fatalf("BindDirectPlatformTenantSwitcher() error = %v", err)
	}
	if _, err := service.SwitchTenant(
		context.Background(), validTestToken(0x99), csrf, uuid.Must(uuid.NewV7()), testEvent(),
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("SwitchTenant() error = %v, want unavailable", err)
	}
}

func TestSwitchTenantRejectsCrossFamilyDirectRotationProjection(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 13, 0, 0, 0, time.UTC)
	service, csrf := directSwitchTestServiceForMethod(t, now, "saml")
	bindAllowingDirectAuthority(t, service)
	if err := service.BindDirectPlatformTenantSwitcher(directPlatformTenantSwitcherFunc(func(
		_ context.Context,
		request DirectPlatformTenantSwitchRequest,
	) (Session, error) {
		result := validDirectSwitchSession(request)
		result.AuthenticationMethod = "oidc"
		return result, nil
	})); err != nil {
		t.Fatalf("BindDirectPlatformTenantSwitcher() error = %v", err)
	}
	if _, err := service.SwitchTenant(
		context.Background(), validTestToken(0x9a), csrf, uuid.Must(uuid.NewV7()), testEvent(),
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("SwitchTenant() error = %v, want unavailable", err)
	}
}

func TestSwitchTenantCanonicalizesDirectPlatformRotationBeforeCommit(t *testing.T) {
	t.Parallel()
	rawNow := time.Date(2026, 8, 30, 13, 0, 0, 123_456_789, time.UTC)
	canonicalNow := rawNow.Truncate(time.Microsecond)
	sourceID := uuid.Must(uuid.NewV7())
	familyID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	sessionToken := validTestToken(0xa1)
	csrf := validTestToken(0xa2)
	absoluteExpiry := rawNow.Truncate(time.Millisecond).Add(8 * time.Hour)
	repository := &repositoryStub{resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
		return Session{
			ID: sourceID, RotationFamilyID: familyID, User: User{ID: userID},
			CSRFDigest: digest(csrf), AuthenticationMethod: "oidc",
			IdleExpiresAt:     rawNow.Truncate(time.Millisecond).Add(time.Hour),
			AbsoluteExpiresAt: absoluteExpiry,
		}, nil
	}}
	service := newAuthenticationServiceAt(
		t, repository, &passwordEngineStub{}, totpEngineStub{},
		digest("bootstrap-authority-value-000000"), rawNow,
	)
	bindAllowingDirectAuthority(t, service)
	if err := service.BindDirectPlatformTenantSwitcher(directPlatformTenantSwitcherFunc(func(
		_ context.Context,
		request DirectPlatformTenantSwitchRequest,
	) (Session, error) {
		if request.OccurredAt != canonicalNow ||
			request.OccurredAt.Nanosecond()%int(time.Microsecond) != 0 ||
			request.IdleExpiresAt.Nanosecond()%int(time.Millisecond) != 0 ||
			request.AbsoluteExpiresAt != absoluteExpiry {
			t.Fatalf("non-canonical switch request = %#v", request)
		}
		return validDirectSwitchSession(request), nil
	})); err != nil {
		t.Fatalf("BindDirectPlatformTenantSwitcher() error = %v", err)
	}
	if _, err := service.SwitchTenant(
		context.Background(), sessionToken, csrf, uuid.Must(uuid.NewV7()), testEvent(),
	); err != nil {
		t.Fatalf("SwitchTenant() error = %v", err)
	}
}

func TestSwitchTenantRejectsUnsafeSuccessorMaterialBeforeAdapter(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 13, 0, 0, 0, time.UTC)
	for _, testCase := range []struct {
		name      string
		configure func(*Service, *Session, string, string)
	}{
		{
			name: "bearer repeats source",
			configure: func(service *Service, _ *Session, token, _ string) {
				service.tokens = directSwitchTokenSource{opaque: token}
			},
		},
		{
			name: "bearer repeats source csrf",
			configure: func(service *Service, _ *Session, _, csrf string) {
				service.tokens = directSwitchTokenSource{opaque: csrf}
			},
		},
		{
			name: "bearer equals csrf",
			configure: func(service *Service, source *Session, _, _ string) {
				newID := uuid.Must(uuid.NewV7())
				service.newID = func() (uuid.UUID, error) { return newID, nil }
				service.tokens = directSwitchTokenSource{opaque: service.csrfForSession(newID)}
				if newID == source.ID || newID == source.RotationFamilyID {
					t.Fatal("test UUID collision")
				}
			},
		},
		{
			name: "session repeats source",
			configure: func(service *Service, source *Session, _, _ string) {
				service.newID = func() (uuid.UUID, error) { return source.ID, nil }
			},
		},
		{
			name: "session repeats family",
			configure: func(service *Service, source *Session, _, _ string) {
				service.newID = func() (uuid.UUID, error) { return source.RotationFamilyID, nil }
			},
		},
		{
			name: "malformed bearer",
			configure: func(service *Service, _ *Session, _, _ string) {
				service.tokens = directSwitchTokenSource{opaque: "not-an-opaque-token"}
			},
		},
		{
			name: "all-zero bearer",
			configure: func(service *Service, _ *Session, _, _ string) {
				service.tokens = directSwitchTokenSource{
					opaque: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
				}
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			sourceToken := validTestToken(0xa3)
			csrf := validTestToken(0xa4)
			source := Session{
				ID: uuid.Must(uuid.NewV7()), RotationFamilyID: uuid.Must(uuid.NewV7()),
				User: User{ID: uuid.Must(uuid.NewV7())}, CSRFDigest: digest(csrf),
				AuthenticationMethod: "oidc", IdleExpiresAt: now.Add(time.Hour),
				AbsoluteExpiresAt: now.Add(8 * time.Hour),
			}
			repository := &repositoryStub{resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
				return source, nil
			}}
			service := newAuthenticationServiceAt(
				t, repository, &passwordEngineStub{}, totpEngineStub{},
				digest("bootstrap-authority-value-000000"), now,
			)
			bindAllowingDirectAuthority(t, service)
			testCase.configure(service, &source, sourceToken, csrf)
			calls := 0
			if err := service.BindDirectPlatformTenantSwitcher(directPlatformTenantSwitcherFunc(func(
				context.Context,
				DirectPlatformTenantSwitchRequest,
			) (Session, error) {
				calls++
				return Session{}, nil
			})); err != nil {
				t.Fatalf("BindDirectPlatformTenantSwitcher() error = %v", err)
			}
			if _, err := service.SwitchTenant(
				context.Background(), sourceToken, csrf, uuid.Must(uuid.NewV7()), testEvent(),
			); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("SwitchTenant() error = %v, want unavailable", err)
			}
			if calls != 0 {
				t.Fatalf("unsafe successor reached adapter %d times", calls)
			}
		})
	}
}

func TestSwitchTenantRejectsAdapterDigestMutationAndDetachesReturnedSession(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 13, 0, 0, 0, time.UTC)
	t.Run("digest mutation", func(t *testing.T) {
		service, csrf := directSwitchTestService(t, now)
		bindAllowingDirectAuthority(t, service)
		if err := service.BindDirectPlatformTenantSwitcher(directPlatformTenantSwitcherFunc(func(
			_ context.Context,
			request DirectPlatformTenantSwitchRequest,
		) (Session, error) {
			request.NewCSRFDigest[0] ^= 0xff
			return validDirectSwitchSession(request), nil
		})); err != nil {
			t.Fatalf("BindDirectPlatformTenantSwitcher() error = %v", err)
		}
		if _, err := service.SwitchTenant(
			context.Background(), validTestToken(0xa5), csrf,
			uuid.Must(uuid.NewV7()), testEvent(),
		); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("SwitchTenant() error = %v, want unavailable", err)
		}
	})

	t.Run("result ownership", func(t *testing.T) {
		service, csrf := directSwitchTestService(t, now)
		bindAllowingDirectAuthority(t, service)
		var retained Session
		if err := service.BindDirectPlatformTenantSwitcher(directPlatformTenantSwitcherFunc(func(
			_ context.Context,
			request DirectPlatformTenantSwitchRequest,
		) (Session, error) {
			retained = validDirectSwitchSession(request)
			return retained, nil
		})); err != nil {
			t.Fatalf("BindDirectPlatformTenantSwitcher() error = %v", err)
		}
		targetID := uuid.Must(uuid.NewV7())
		credential, err := service.SwitchTenant(
			context.Background(), validTestToken(0xa6), csrf, targetID, testEvent(),
		)
		if err != nil {
			t.Fatalf("SwitchTenant() error = %v", err)
		}
		retained.CSRFDigest[0] ^= 0xff
		*retained.ActiveTenantID = uuid.Must(uuid.NewV7())
		if credential.Session.ActiveTenantID == nil ||
			*credential.Session.ActiveTenantID != targetID ||
			subtle.ConstantTimeCompare(credential.Session.CSRFDigest, digest(credential.CSRFToken)) != 1 {
			t.Fatalf("returned session retained adapter aliases: %#v", credential.Session)
		}
	})
}

func TestBindDirectPlatformTenantSwitcherIsOneTime(t *testing.T) {
	t.Parallel()
	service := newAuthenticationService(
		t, &repositoryStub{}, &passwordEngineStub{}, totpEngineStub{},
		digest("bootstrap-authority-value-000000"),
	)
	switcher := directPlatformTenantSwitcherFunc(func(
		context.Context,
		DirectPlatformTenantSwitchRequest,
	) (Session, error) {
		return Session{}, nil
	})
	if err := service.BindDirectPlatformTenantSwitcher(nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("BindDirectPlatformTenantSwitcher(nil) error = %v", err)
	}
	if err := service.BindDirectPlatformTenantSwitcher(switcher); err != nil {
		t.Fatalf("BindDirectPlatformTenantSwitcher() error = %v", err)
	}
	if err := service.BindDirectPlatformTenantSwitcher(switcher); !errors.Is(err, ErrConflict) {
		t.Fatalf("second BindDirectPlatformTenantSwitcher() error = %v", err)
	}
}

func directSwitchTestService(t *testing.T, now time.Time) (*Service, string) {
	return directSwitchTestServiceForMethod(t, now, "oidc")
}

func directSwitchTestServiceForMethod(t *testing.T, now time.Time, method string) (*Service, string) {
	t.Helper()
	csrf := validTestToken(0x96)
	repository := &repositoryStub{resolveSession: func(context.Context, []byte, time.Time) (Session, error) {
		return Session{
			ID: uuid.Must(uuid.NewV7()), RotationFamilyID: uuid.Must(uuid.NewV7()),
			User: User{ID: uuid.Must(uuid.NewV7())}, CSRFDigest: digest(csrf),
			AuthenticationMethod: method, IdleExpiresAt: now.Add(time.Hour),
			AbsoluteExpiresAt: now.Add(8 * time.Hour),
		}, nil
	}}
	return newAuthenticationServiceAt(
		t, repository, &passwordEngineStub{}, totpEngineStub{},
		digest("bootstrap-authority-value-000000"), now,
	), csrf
}

func bindAllowingDirectAuthority(t *testing.T, service *Service) {
	t.Helper()
	if err := service.BindDirectPlatformSessionAuthority(directPlatformSessionAuthorityFunc(func(
		_ context.Context,
		lookup DirectPlatformSessionAuthorityLookup,
	) (DirectPlatformSessionAuthorityResult, error) {
		return DirectPlatformSessionAuthorityResult{
			SessionID: lookup.SessionID, UserID: lookup.UserID,
			AllowAuthority: true, AllowIdleTouch: true,
		}, nil
	})); err != nil {
		t.Fatalf("BindDirectPlatformSessionAuthority() error = %v", err)
	}
}

func TestClearDirectPlatformTenantSwitchRequestMaterial(t *testing.T) {
	request := DirectPlatformTenantSwitchRequest{
		SourceTokenDigest: sha256.Sum256([]byte("source-token")),
		NewTokenDigest:    sha256.Sum256([]byte("new-token")),
		NewCSRFDigest:     sha256.Sum256([]byte("new-csrf")),
	}
	clearDirectPlatformTenantSwitchRequestMaterial(&request)
	if request.SourceTokenDigest != ([sha256.Size]byte{}) ||
		request.NewTokenDigest != ([sha256.Size]byte{}) ||
		request.NewCSRFDigest != ([sha256.Size]byte{}) {
		t.Fatal("tenant-switch request digest material was not cleared")
	}
	clearDirectPlatformTenantSwitchRequestMaterial(nil)
}

func validDirectSwitchSession(request DirectPlatformTenantSwitchRequest) Session {
	return Session{
		ID: request.NewSessionID, RotationFamilyID: request.RotationFamilyID,
		User: User{ID: request.UserID}, CSRFDigest: append([]byte(nil), request.NewCSRFDigest[:]...),
		ActiveTenantID: &request.TargetTenantID, AuthenticationMethod: request.AuthenticationMethod,
		CreatedAt: request.OccurredAt, LastSeenAt: request.OccurredAt,
		IdleExpiresAt: request.IdleExpiresAt, AbsoluteExpiresAt: request.AbsoluteExpiresAt,
	}
}
