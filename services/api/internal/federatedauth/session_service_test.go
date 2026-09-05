package federatedauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

func TestNewSessionServiceRequiresCompleteBoundedDependencies(t *testing.T) {
	t.Parallel()
	store := sessionStoreFunc{
		load: func(context.Context, SessionLookup) (SessionProjection, error) {
			return SessionProjection{}, errors.New("unused")
		},
		apply: func(context.Context, SessionMutation) (SessionMutationResult, error) {
			return SessionMutationResult{}, errors.New("unused")
		},
	}
	valid := SessionServiceOptions{
		Sessions: store, Credentials: testApplyCredentialIssuer(), OperationTimeout: time.Second,
	}
	for name, mutate := range map[string]func(*SessionServiceOptions){
		"missing sessions":    func(options *SessionServiceOptions) { options.Sessions = nil },
		"missing credentials": func(options *SessionServiceOptions) { options.Credentials = nil },
		"short timeout":       func(options *SessionServiceOptions) { options.OperationTimeout = time.Millisecond },
		"fractional timeout":  func(options *SessionServiceOptions) { options.OperationTimeout = time.Second + time.Nanosecond },
	} {
		t.Run(name, func(t *testing.T) {
			options := valid
			mutate(&options)
			if service, err := NewSessionService(options); !errors.Is(err, ErrInvalidOptions) || service != nil {
				t.Fatalf("NewSessionService() = %#v, %v", service, err)
			}
		})
	}
	if service, err := NewSessionService(valid); err != nil || service == nil {
		t.Fatalf("NewSessionService(valid) = %#v, %v", service, err)
	}
}

func TestSessionServiceRevalidatesPasskeyWithoutBrowserFederationGraph(t *testing.T) {
	t.Parallel()
	snapshot, live := currentSessionProjection()
	lookup := SessionLookup{
		SessionID: snapshot.SessionID, TenantID: snapshot.TenantID, Audience: live.Audience,
		AuthenticationMethod: AuthenticationMethodPasskey,
		ObservedAt:           serviceTestNow.Add(-time.Hour),
	}
	expectedLookup := lookup
	expectedLookup.ObservedAt = serviceTestNow
	var applied SessionMutation
	service, err := NewSessionService(SessionServiceOptions{
		Sessions: sessionStoreFunc{
			load: func(_ context.Context, actual SessionLookup) (SessionProjection, error) {
				if actual != expectedLookup {
					t.Fatalf("LoadSessionForRevalidation() lookup = %#v", actual)
				}
				return SessionProjection{
					Snapshot: snapshot, Live: live, AuthenticationMethod: AuthenticationMethodPasskey,
				}, nil
			},
			apply: func(_ context.Context, mutation SessionMutation) (SessionMutationResult, error) {
				applied = mutation
				return SessionMutationResult{Applied: true}, nil
			},
		},
		Credentials: testApplyCredentialIssuer(), OperationTimeout: time.Second,
		Now: func() time.Time { return serviceTestNow },
	})
	if err != nil {
		t.Fatalf("NewSessionService() error = %v", err)
	}
	result, err := service.RevalidateSession(context.Background(), lookup)
	if err != nil || result.Decision != mfa.SessionUsable || !result.AllowAuthority ||
		!result.AllowIdleTouch || result.SessionID != lookup.SessionID ||
		result.TenantID != lookup.TenantID || result.UserID != snapshot.UserID ||
		result.AuthenticationMethod != AuthenticationMethodPasskey {
		t.Fatalf("RevalidateSession() = %+v, %v", result, err)
	}
	if applied.Decision != mfa.SessionUsable || applied.Reason != mfa.SessionReasonCurrent ||
		applied.SessionID != lookup.SessionID || applied.TenantID != lookup.TenantID ||
		applied.UserID != snapshot.UserID || applied.ExpectedVersion != snapshot.Version ||
		applied.AuthenticationMethod != AuthenticationMethodPasskey ||
		!applied.ObservedAt.Equal(serviceTestNow) {
		t.Fatalf("ApplySessionRevalidation() mutation = %+v", applied)
	}
}

func TestNilSessionServiceFailsClosed(t *testing.T) {
	t.Parallel()
	var service *SessionService
	if result, err := service.RevalidateSession(context.Background(), SessionLookup{}); !errors.Is(err, ErrInvalidInput) || result != (SessionResult{}) {
		t.Fatalf("nil RevalidateSession() = %+v, %v", result, err)
	}
}
