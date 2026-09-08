package federatedauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

func TestSessionConflictReloadsAuthorityBeforeRetry(t *testing.T) {
	for _, test := range []struct {
		name                        string
		revoked, persistent, cancel bool
		wantLoads                   int
	}{
		{name: "fresh version", wantLoads: 2}, {name: "revoked during contention", revoked: true, wantLoads: 2}, {name: "bounded conflict", persistent: true, wantLoads: 6}, {name: "cancelled backoff", cancel: true, wantLoads: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot, live := currentSessionProjection()
			loads, applies := 0, 0
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var observed []time.Time
			service := newServiceFixture(t, func(options *Options) {
				options.Now = func() time.Time { return serviceTestNow.Add(time.Duration(loads) * time.Microsecond) }
				options.Sessions = sessionStoreFunc{
					load: func(_ context.Context, lookup SessionLookup) (SessionProjection, error) {
						loads++
						observed = append(observed, lookup.ObservedAt)
						current := snapshot
						current.Version += uint64(loads - 1)
						currentLive := live
						if test.revoked && loads > 1 {
							currentLive.IdentityEpoch++
						}
						return SessionProjection{Snapshot: current, Live: currentLive, AuthenticationMethod: AuthenticationMethodPasskey}, nil
					},
					apply: func(_ context.Context, mutation SessionMutation) (SessionMutationResult, error) {
						applies++
						if mutation.ExpectedVersion != snapshot.Version+uint64(loads-1) {
							t.Fatal("stale version reused")
						}
						if applies == 1 || test.persistent {
							if test.cancel {
								cancel()
							}
							return SessionMutationResult{}, ErrSessionRevalidationConflict
						}
						return SessionMutationResult{Applied: true}, nil
					},
				}
			})
			result, err := service.RevalidateSession(ctx, SessionLookup{SessionID: snapshot.SessionID, TenantID: snapshot.TenantID, Audience: live.Audience, AuthenticationMethod: AuthenticationMethodPasskey})
			if loads != test.wantLoads || applies != loads {
				t.Fatalf("loads=%d applies=%d error=%v", loads, applies, err)
			}
			if test.cancel || test.persistent {
				if !errors.Is(err, ErrSessionRejected) || result.AllowAuthority {
					t.Fatal("exhausted retry authorized")
				}
				return
			}
			if err != nil || !observed[1].After(observed[0]) {
				t.Fatalf("retry did not refresh authority time: %v", err)
			}
			if test.revoked {
				if result.AllowAuthority || result.Decision != mfa.SessionRevoke {
					t.Fatal("revocation was bypassed")
				}
			} else if !result.AllowAuthority {
				t.Fatal("fresh session was denied")
			}
		})
	}
}
