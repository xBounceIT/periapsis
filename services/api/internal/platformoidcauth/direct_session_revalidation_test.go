package platformoidcauth

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

var directSessionTestNow = time.Date(2026, 8, 30, 12, 30, 0, 123456000, time.UTC)

type directSessionStoreStub struct {
	load  func(context.Context, DirectSessionRevalidationLookup) (DirectSessionRevalidationSnapshot, error)
	apply func(context.Context, DirectSessionRevalidationMutation) (DirectSessionRevalidationMutationResult, error)
}

func (store directSessionStoreStub) LoadDirectPlatformSessionForRevalidation(
	ctx context.Context,
	lookup DirectSessionRevalidationLookup,
) (DirectSessionRevalidationSnapshot, error) {
	if store.load == nil {
		return DirectSessionRevalidationSnapshot{}, errors.New("unexpected load")
	}
	return store.load(ctx, lookup)
}

func (store directSessionStoreStub) ApplyDirectPlatformSessionRevalidation(
	ctx context.Context,
	mutation DirectSessionRevalidationMutation,
) (DirectSessionRevalidationMutationResult, error) {
	if store.apply == nil {
		return DirectSessionRevalidationMutationResult{}, errors.New("unexpected apply")
	}
	return store.apply(ctx, mutation)
}

func TestDirectPlatformSessionAuthorityCommitsExactCASBeforeGrant(t *testing.T) {
	t.Parallel()
	snapshot := directSessionSnapshotFixture(t)
	lookup := directSessionAuthorityLookup(snapshot)
	order := make([]string, 0, 2)
	var observedMutation DirectSessionRevalidationMutation
	nowSource := directSessionTestNow.In(time.FixedZone("test-offset", 2*60*60)).Add(789 * time.Nanosecond)
	service := newDirectSessionAuthorityFixture(t, directSessionStoreStub{
		load: func(ctx context.Context, got DirectSessionRevalidationLookup) (DirectSessionRevalidationSnapshot, error) {
			order = append(order, "load")
			deadline, hasDeadline := ctx.Deadline()
			if !hasDeadline || time.Until(deadline) <= 0 || got.SessionID != lookup.SessionID ||
				got.ObservedAt != directSessionTestNow {
				t.Fatalf("load lookup = %s, deadline=%v/%t", got, deadline, hasDeadline)
			}
			return snapshot, nil
		},
		apply: func(_ context.Context, mutation DirectSessionRevalidationMutation) (DirectSessionRevalidationMutationResult, error) {
			order = append(order, "apply")
			observedMutation = mutation
			return successfulDirectSessionMutation(mutation, snapshot.Session.UserID), nil
		},
	}, func(options *DirectPlatformSessionAuthorityOptions) {
		options.Now = func() time.Time { return nowSource }
	})

	result, err := service.RevalidateDirectPlatformSession(context.Background(), lookup)
	if err != nil {
		t.Fatalf("RevalidateDirectPlatformSession() error = %v", err)
	}
	if !reflect.DeepEqual(order, []string{"load", "apply"}) {
		t.Fatalf("operation order = %v", order)
	}
	if result.SessionID != lookup.SessionID || result.UserID != lookup.UserID ||
		!result.AllowAuthority || !result.AllowIdleTouch {
		t.Fatalf("authority result = %+v", result)
	}
	if observedMutation.SessionID != snapshot.Session.SessionID ||
		observedMutation.ExpectedVersion != snapshot.Session.CurrentVersion ||
		observedMutation.ObservedAt != directSessionTestNow ||
		observedMutation.Decision != DirectSessionRevalidationUsable ||
		observedMutation.Reason != DirectSessionReasonCurrent ||
		observedMutation.RequestDigest == (DirectSessionRevalidationRequestDigest{}) {
		t.Fatalf("usable mutation = %s", observedMutation)
	}
	if observedMutation.RequestDigest != directSessionMutationDigest(observedMutation) {
		t.Fatal("request digest is not deterministic over the exact mutation")
	}
}

func TestDirectPlatformSessionAuthorityAppliesOnlySemanticallyTerminalDrift(t *testing.T) {
	t.Parallel()
	disabledAt := directSessionTestNow.Add(-time.Minute)
	retiredAt := directSessionTestNow.Add(-time.Minute)
	tests := map[string]struct {
		mutate       func(*DirectSessionRevalidationSnapshot)
		wantApply    bool
		wantDecision DirectSessionRevalidationDecision
		wantReason   DirectSessionRevalidationReason
	}{
		"expired": {
			mutate: func(value *DirectSessionRevalidationSnapshot) {
				value.Session.IdleExpiresAt = directSessionTestNow
			},
			wantApply: true, wantDecision: DirectSessionRevalidationRevoke, wantReason: DirectSessionReasonExpired,
		},
		"provider disabled": {
			mutate:    func(value *DirectSessionRevalidationSnapshot) { value.Authority.ProviderEnabled = false },
			wantApply: true, wantDecision: DirectSessionRevalidationRevoke, wantReason: DirectSessionReasonLifecycle,
		},
		"session inactive": {
			mutate:    func(value *DirectSessionRevalidationSnapshot) { value.Session.Active = false },
			wantApply: true, wantDecision: DirectSessionRevalidationRevoke, wantReason: DirectSessionReasonLifecycle,
		},
		"rotation family inactive": {
			mutate:    func(value *DirectSessionRevalidationSnapshot) { value.Session.RotationFamilyLive = false },
			wantApply: true, wantDecision: DirectSessionRevalidationRevoke, wantReason: DirectSessionReasonLifecycle,
		},
		"user inactive": {
			mutate:    func(value *DirectSessionRevalidationSnapshot) { value.Authority.UserActive = false },
			wantApply: true, wantDecision: DirectSessionRevalidationRevoke, wantReason: DirectSessionReasonLifecycle,
		},
		"runtime policy disabled": {
			mutate:    func(value *DirectSessionRevalidationSnapshot) { value.Authority.RuntimePolicyEnabled = false },
			wantApply: true, wantDecision: DirectSessionRevalidationRevoke, wantReason: DirectSessionReasonLifecycle,
		},
		"legacy login sentinel enabled": {
			mutate:    func(value *DirectSessionRevalidationSnapshot) { value.Authority.LegacyPlatformLoginEnabled = true },
			wantApply: true, wantDecision: DirectSessionRevalidationRevoke, wantReason: DirectSessionReasonLifecycle,
		},
		"login policy disabled": {
			mutate:    func(value *DirectSessionRevalidationSnapshot) { value.Authority.LoginPolicyEnabled = false },
			wantApply: true, wantDecision: DirectSessionRevalidationRevoke, wantReason: DirectSessionReasonLifecycle,
		},
		"account mode disabled": {
			mutate:    func(value *DirectSessionRevalidationSnapshot) { value.Authority.AccountMode = "disabled" },
			wantApply: true, wantDecision: DirectSessionRevalidationRevoke, wantReason: DirectSessionReasonLifecycle,
		},
		"identity retired": {
			mutate:    func(value *DirectSessionRevalidationSnapshot) { value.Authority.IdentityRetiredAt = &retiredAt },
			wantApply: true, wantDecision: DirectSessionRevalidationRevoke, wantReason: DirectSessionReasonLifecycle,
		},
		"alias retired": {
			mutate:    func(value *DirectSessionRevalidationSnapshot) { value.Authority.AliasRetiredAt = &retiredAt },
			wantApply: true, wantDecision: DirectSessionRevalidationRevoke, wantReason: DirectSessionReasonLifecycle,
		},
		"provider revision drift": {
			mutate: func(value *DirectSessionRevalidationSnapshot) {
				value.Authority.Revisions.Provider.Current++
			},
			wantApply: true, wantDecision: DirectSessionRevalidationRevoke, wantReason: DirectSessionReasonPrimaryDrift,
		},
		"security revision drift": {
			mutate: func(value *DirectSessionRevalidationSnapshot) {
				value.Authority.Revisions.Security.Current++
			},
			wantApply: true, wantDecision: DirectSessionRevalidationRevoke, wantReason: DirectSessionReasonPrimaryDrift,
		},
		"login revision drift": {
			mutate: func(value *DirectSessionRevalidationSnapshot) {
				value.Authority.Revisions.LoginPolicy.Current++
			},
			wantApply: true, wantDecision: DirectSessionRevalidationRevoke, wantReason: DirectSessionReasonPrimaryDrift,
		},
		"user authentication revision drift": {
			mutate: func(value *DirectSessionRevalidationSnapshot) {
				value.Authority.Revisions.UserAuthentication.Current++
			},
			wantApply: true, wantDecision: DirectSessionRevalidationRevoke, wantReason: DirectSessionReasonPrimaryDrift,
		},
		"identity revision drift": {
			mutate: func(value *DirectSessionRevalidationSnapshot) {
				value.Authority.Revisions.ExternalIdentity.Current++
			},
			wantApply: true, wantDecision: DirectSessionRevalidationRevoke, wantReason: DirectSessionReasonPrimaryDrift,
		},
		"alias revision drift": {
			mutate: func(value *DirectSessionRevalidationSnapshot) {
				value.Authority.Revisions.SubjectAliasKey.Current++
			},
			wantApply: true, wantDecision: DirectSessionRevalidationRevoke, wantReason: DirectSessionReasonPrimaryDrift,
		},
		"factor disabled": {
			mutate: func(value *DirectSessionRevalidationSnapshot) {
				directSessionAddTOTP(t, value)
				value.FactorAuthorities[0].DisabledAt = &disabledAt
			},
			wantApply: true, wantDecision: DirectSessionRevalidationRevoke, wantReason: DirectSessionReasonFactorDrift,
		},
		"factor revision drift": {
			mutate: func(value *DirectSessionRevalidationSnapshot) {
				directSessionAddTOTP(t, value)
				value.FactorAuthorities[0].CurrentSecurityRevision++
			},
			wantApply: true, wantDecision: DirectSessionRevalidationRevoke, wantReason: DirectSessionReasonFactorDrift,
		},
		"trust retired": {
			mutate: func(value *DirectSessionRevalidationSnapshot) {
				directSessionAddTrust(t, value)
				value.TrustAuthorities[0].RetiredAt = &retiredAt
			},
			wantApply: true, wantDecision: DirectSessionRevalidationRevoke, wantReason: DirectSessionReasonTrustDrift,
		},
		"trust revision drift": {
			mutate: func(value *DirectSessionRevalidationSnapshot) {
				directSessionAddTrust(t, value)
				value.TrustAuthorities[0].CurrentRevision++
			},
			wantApply: true, wantDecision: DirectSessionRevalidationRevoke, wantReason: DirectSessionReasonTrustDrift,
		},
		"policy pins drift": {
			mutate: func(value *DirectSessionRevalidationSnapshot) { value.PolicyPins[0].Revision++ },
		},
		"assurance policy revision": {
			mutate: func(value *DirectSessionRevalidationSnapshot) {
				value.Authority.Revisions.AssurancePolicy.Current++
			},
		},
		"platform floor revision": {
			mutate: func(value *DirectSessionRevalidationSnapshot) {
				value.Authority.PlatformFloor.CurrentRevision++
			},
		},
		"recoverable assurance shortfall": {
			mutate: func(value *DirectSessionRevalidationSnapshot) {
				value.Authority.PlatformFloor.Level = identity.AssuranceMFA
			},
		},
		"future evidence": {
			mutate: func(value *DirectSessionRevalidationSnapshot) {
				value.Evidence[0].AuthenticatedAt = directSessionTestNow.Add(time.Minute)
				expires := directSessionTestNow.Add(time.Hour)
				value.Evidence[0].ExpiresAt = &expires
			},
		},
		"expired evidence": {
			mutate: func(value *DirectSessionRevalidationSnapshot) {
				expires := directSessionTestNow
				value.Evidence[0].ExpiresAt = &expires
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			snapshot := directSessionSnapshotFixture(t)
			test.mutate(&snapshot)
			lookup := directSessionAuthorityLookup(snapshot)
			applyCalls := 0
			service := newDirectSessionAuthorityFixture(t, directSessionStoreStub{
				load: func(context.Context, DirectSessionRevalidationLookup) (DirectSessionRevalidationSnapshot, error) {
					return snapshot, nil
				},
				apply: func(_ context.Context, mutation DirectSessionRevalidationMutation) (DirectSessionRevalidationMutationResult, error) {
					applyCalls++
					if mutation.Decision != test.wantDecision || mutation.Reason != test.wantReason {
						t.Fatalf("terminal mutation = %s", mutation)
					}
					return successfulDirectSessionMutation(mutation, snapshot.Session.UserID), nil
				},
			})
			result, err := service.RevalidateDirectPlatformSession(context.Background(), lookup)
			if !errors.Is(err, ErrDirectSessionRejected) || result != (DirectSessionAuthorityResult{}) {
				t.Fatalf("revalidation = %+v, %v", result, err)
			}
			wantCalls := 0
			if test.wantApply {
				wantCalls = 1
			}
			if applyCalls != wantCalls {
				t.Fatalf("apply calls = %d, want %d", applyCalls, wantCalls)
			}
		})
	}
}

func TestDirectPlatformSessionAuthorityRejectsMalformedOrMismatchedProjectionWithoutApply(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*DirectSessionRevalidationSnapshot){
		"session echo": func(value *DirectSessionRevalidationSnapshot) {
			value.Session.SessionID = uuid.Must(uuid.NewV7())
		},
		"user echo": func(value *DirectSessionRevalidationSnapshot) {
			value.Session.UserID = uuid.Must(uuid.NewV7())
		},
		"tenantful": func(value *DirectSessionRevalidationSnapshot) {
			tenantID := uuid.Must(uuid.NewV7())
			value.Session.ActiveTenantID = &tenantID
		},
		"wrong method":      func(value *DirectSessionRevalidationSnapshot) { value.Session.AuthenticationMethod = "saml" },
		"wrong audience":    func(value *DirectSessionRevalidationSnapshot) { value.Session.Audience = "console" },
		"ambiguous state":   func(value *DirectSessionRevalidationSnapshot) { value.Session.DirectStateCount = 2 },
		"tenant provenance": func(value *DirectSessionRevalidationSnapshot) { value.Session.TenantProvenanceCount = 1 },
		"evidence count":    func(value *DirectSessionRevalidationSnapshot) { value.Session.ProviderEvidenceCount = 2 },
		"version exhausted": func(value *DirectSessionRevalidationSnapshot) {
			value.Session.CurrentVersion = maximumDirectSessionVersion
		},
		"non canonical time": func(value *DirectSessionRevalidationSnapshot) {
			value.Session.IssuedAt = value.Session.IssuedAt.In(time.FixedZone("bad", 3600))
		},
		"unsorted policy pins": func(value *DirectSessionRevalidationSnapshot) {
			value.PolicyPins[0], value.PolicyPins[1] = value.PolicyPins[1], value.PolicyPins[0]
		},
		"duplicate evidence": func(value *DirectSessionRevalidationSnapshot) {
			value.Evidence = append(value.Evidence, value.Evidence[0])
			value.Session.ProviderEvidenceCount = 2
		},
		"factor authority missing": func(value *DirectSessionRevalidationSnapshot) {
			directSessionAddTOTP(t, value)
			value.FactorAuthorities = nil
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			snapshot := directSessionSnapshotFixture(t)
			lookup := directSessionAuthorityLookup(snapshot)
			mutate(&snapshot)
			applied := false
			service := newDirectSessionAuthorityFixture(t, directSessionStoreStub{
				load: func(context.Context, DirectSessionRevalidationLookup) (DirectSessionRevalidationSnapshot, error) {
					return snapshot, nil
				},
				apply: func(context.Context, DirectSessionRevalidationMutation) (DirectSessionRevalidationMutationResult, error) {
					applied = true
					return DirectSessionRevalidationMutationResult{}, nil
				},
			})
			result, err := service.RevalidateDirectPlatformSession(context.Background(), lookup)
			if !errors.Is(err, ErrDirectSessionRejected) || result != (DirectSessionAuthorityResult{}) || applied {
				t.Fatalf("malformed result = %+v, %v, applied=%t", result, err, applied)
			}
		})
	}
}

func TestDirectPlatformSessionAuthorityRequiresExactApplyEcho(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*DirectSessionRevalidationMutationResult){
		"not applied":      func(value *DirectSessionRevalidationMutationResult) { value.Applied = false },
		"session":          func(value *DirectSessionRevalidationMutationResult) { value.SessionID = uuid.Must(uuid.NewV7()) },
		"user":             func(value *DirectSessionRevalidationMutationResult) { value.UserID = uuid.Must(uuid.NewV7()) },
		"expected version": func(value *DirectSessionRevalidationMutationResult) { value.ExpectedVersion++ },
		"decision":         func(value *DirectSessionRevalidationMutationResult) { value.Decision = DirectSessionRevalidationRevoke },
		"new version":      func(value *DirectSessionRevalidationMutationResult) { value.NewVersion++ },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			snapshot := directSessionSnapshotFixture(t)
			service := newDirectSessionAuthorityFixture(t, directSessionStoreStub{
				load: func(context.Context, DirectSessionRevalidationLookup) (DirectSessionRevalidationSnapshot, error) {
					return snapshot, nil
				},
				apply: func(_ context.Context, mutation DirectSessionRevalidationMutation) (DirectSessionRevalidationMutationResult, error) {
					result := successfulDirectSessionMutation(mutation, snapshot.Session.UserID)
					mutate(&result)
					return result, nil
				},
			})
			result, err := service.RevalidateDirectPlatformSession(
				context.Background(), directSessionAuthorityLookup(snapshot),
			)
			if !errors.Is(err, ErrDirectSessionRejected) || result != (DirectSessionAuthorityResult{}) {
				t.Fatalf("ambiguous apply result = %+v, %v", result, err)
			}
		})
	}
}

func TestDirectPlatformSessionAuthorityRetriesBoundedlyAndHonorsCancellation(t *testing.T) {
	t.Parallel()
	snapshot := directSessionSnapshotFixture(t)
	loadCalls, applyCalls := 0, 0
	service := newDirectSessionAuthorityFixture(t, directSessionStoreStub{
		load: func(context.Context, DirectSessionRevalidationLookup) (DirectSessionRevalidationSnapshot, error) {
			loadCalls++
			if loadCalls == 1 {
				return DirectSessionRevalidationSnapshot{}, errors.New("transient load")
			}
			return snapshot, nil
		},
		apply: func(_ context.Context, mutation DirectSessionRevalidationMutation) (DirectSessionRevalidationMutationResult, error) {
			applyCalls++
			if applyCalls == 1 {
				return DirectSessionRevalidationMutationResult{}, errors.New("response lost")
			}
			return successfulDirectSessionMutation(mutation, snapshot.Session.UserID), nil
		},
	})
	if _, err := service.RevalidateDirectPlatformSession(
		context.Background(), directSessionAuthorityLookup(snapshot),
	); err != nil || loadCalls != 2 || applyCalls != 2 {
		t.Fatalf("bounded retry error=%v loads=%d applies=%d", err, loadCalls, applyCalls)
	}

	preCanceled, cancel := context.WithCancel(context.Background())
	cancel()
	loadCalls = 0
	if result, err := service.RevalidateDirectPlatformSession(
		preCanceled, directSessionAuthorityLookup(snapshot),
	); !errors.Is(err, ErrDirectSessionRejected) || result != (DirectSessionAuthorityResult{}) || loadCalls != 0 {
		t.Fatalf("pre-canceled result=%+v error=%v loads=%d", result, err, loadCalls)
	}

	parent, cancelParent := context.WithCancel(context.Background())
	blocking := newDirectSessionAuthorityFixture(t, directSessionStoreStub{
		load: func(ctx context.Context, _ DirectSessionRevalidationLookup) (DirectSessionRevalidationSnapshot, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("operation context has no deadline")
			}
			cancelParent()
			<-ctx.Done()
			return DirectSessionRevalidationSnapshot{}, ctx.Err()
		},
	})
	if result, err := blocking.RevalidateDirectPlatformSession(
		parent, directSessionAuthorityLookup(snapshot),
	); !errors.Is(err, ErrDirectSessionRejected) || result != (DirectSessionAuthorityResult{}) {
		t.Fatalf("canceled load result=%+v error=%v", result, err)
	}
}

func TestDirectPlatformSessionAuthorityRejectsInvalidBoundaryInputBeforePersistence(t *testing.T) {
	t.Parallel()
	snapshot := directSessionSnapshotFixture(t)
	lookup := directSessionAuthorityLookup(snapshot)
	loadCalls := 0
	service := newDirectSessionAuthorityFixture(t, directSessionStoreStub{
		load: func(context.Context, DirectSessionRevalidationLookup) (DirectSessionRevalidationSnapshot, error) {
			loadCalls++
			return snapshot, nil
		},
	})
	tests := map[string]struct {
		ctx    context.Context
		mutate func(*DirectSessionAuthorityLookup)
	}{
		"nil context": {ctx: nil},
		"session UUID": {ctx: context.Background(), mutate: func(value *DirectSessionAuthorityLookup) {
			value.SessionID = uuid.New()
		}},
		"user UUID": {ctx: context.Background(), mutate: func(value *DirectSessionAuthorityLookup) {
			value.UserID = uuid.New()
		}},
		"method": {ctx: context.Background(), mutate: func(value *DirectSessionAuthorityLookup) {
			value.AuthenticationMethod = "saml"
		}},
		"audience": {ctx: context.Background(), mutate: func(value *DirectSessionAuthorityLookup) {
			value.Audience = "console"
		}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := lookup
			if test.mutate != nil {
				test.mutate(&candidate)
			}
			if result, err := service.RevalidateDirectPlatformSession(test.ctx, candidate); !errors.Is(err, ErrDirectSessionRejected) ||
				result != (DirectSessionAuthorityResult{}) {
				t.Fatalf("invalid input result=%+v error=%v", result, err)
			}
		})
	}
	if loadCalls != 0 {
		t.Fatalf("invalid inputs reached persistence %d times", loadCalls)
	}
	var nilService *DirectPlatformSessionAuthorityService
	if result, err := nilService.RevalidateDirectPlatformSession(context.Background(), lookup); !errors.Is(err, ErrDirectSessionRejected) ||
		result != (DirectSessionAuthorityResult{}) {
		t.Fatalf("nil service result=%+v error=%v", result, err)
	}

	invalidClock := newDirectSessionAuthorityFixture(t, directSessionStoreStub{
		load: func(context.Context, DirectSessionRevalidationLookup) (DirectSessionRevalidationSnapshot, error) {
			t.Fatal("invalid clock reached persistence")
			return DirectSessionRevalidationSnapshot{}, nil
		},
	}, func(options *DirectPlatformSessionAuthorityOptions) {
		options.Now = func() time.Time { return time.Time{} }
	})
	if result, err := invalidClock.RevalidateDirectPlatformSession(context.Background(), lookup); !errors.Is(err, ErrDirectSessionRejected) ||
		result != (DirectSessionAuthorityResult{}) {
		t.Fatalf("invalid clock result=%+v error=%v", result, err)
	}
}

func TestDirectPlatformSessionAuthorityOptionsOwnershipAndFormatting(t *testing.T) {
	t.Parallel()
	snapshot := directSessionSnapshotFixture(t)
	base := DirectPlatformSessionAuthorityOptions{
		Store: directSessionStoreStub{}, OperationTimeout: time.Second,
		Now: func() time.Time { return directSessionTestNow },
	}
	for name, mutate := range map[string]func(*DirectPlatformSessionAuthorityOptions){
		"nil store":     func(value *DirectPlatformSessionAuthorityOptions) { value.Store = nil },
		"short timeout": func(value *DirectPlatformSessionAuthorityOptions) { value.OperationTimeout = 99 * time.Millisecond },
		"long timeout": func(value *DirectPlatformSessionAuthorityOptions) {
			value.OperationTimeout = 2*time.Minute + time.Microsecond
		},
		"fractional timeout": func(value *DirectPlatformSessionAuthorityOptions) {
			value.OperationTimeout = time.Second + time.Nanosecond
		},
	} {
		t.Run(name, func(t *testing.T) {
			options := base
			mutate(&options)
			if service, err := NewDirectPlatformSessionAuthority(options); !errors.Is(err, ErrDirectSessionRejected) || service != nil {
				t.Fatalf("constructor = %v, %v", service, err)
			}
		})
	}
	if service, err := NewDirectPlatformSessionAuthority(DirectPlatformSessionAuthorityOptions{
		Store: directSessionStoreStub{}, OperationTimeout: 100 * time.Millisecond,
	}); err != nil || service == nil {
		t.Fatalf("minimum/default constructor = %v, %v", service, err)
	}

	clone := cloneDirectSessionSnapshot(snapshot)
	snapshot.PolicyPins[0].Revision++
	*snapshot.Evidence[0].ExpiresAt = snapshot.Evidence[0].ExpiresAt.Add(time.Hour)
	if clone.PolicyPins[0].Revision == snapshot.PolicyPins[0].Revision ||
		clone.Evidence[0].ExpiresAt.Equal(*snapshot.Evidence[0].ExpiresAt) {
		t.Fatal("snapshot clone retained caller-owned slices or pointers")
	}
	clone.PolicyPins[1].Revision++
	if clone.PolicyPins[1].Revision == snapshot.PolicyPins[1].Revision {
		t.Fatal("snapshot caller retained clone-owned policy slice")
	}

	mutation, ok := newDirectSessionMutation(
		clone, directSessionTestNow, DirectSessionRevalidationUsable, DirectSessionReasonCurrent,
	)
	if !ok {
		t.Fatal("fixture mutation rejected")
	}
	lookup := directSessionAuthorityLookup(clone)
	result := DirectSessionAuthorityResult{
		SessionID: lookup.SessionID, UserID: lookup.UserID, AllowAuthority: true, AllowIdleTouch: true,
	}
	formatted := fmt.Sprintf("%v %#v %v %#v %v %#v %v %#v", clone, clone, mutation, mutation, lookup, lookup, result, result)
	for _, material := range []string{
		clone.Session.SessionID.String(), clone.Session.UserID.String(),
		clone.Authority.ProviderID.String(), clone.Authority.ExternalIdentityID.String(),
	} {
		if strings.Contains(formatted, material) {
			t.Fatalf("formatted authority leaked identifier %q: %s", material, formatted)
		}
	}
}

func directSessionSnapshotFixture(t *testing.T) DirectSessionRevalidationSnapshot {
	t.Helper()
	sessionID := uuid.Must(uuid.NewV7())
	familyID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	providerID := uuid.Must(uuid.NewV7())
	identityID := uuid.Must(uuid.NewV7())
	floorID := uuid.Must(uuid.NewV7())
	providerEvidenceID := uuid.Must(uuid.NewV7())
	providerIDPointer := providerID
	identityIDPointer := identityID
	expiresAt := directSessionTestNow.Add(6 * time.Hour)
	return DirectSessionRevalidationSnapshot{
		Session: DirectSessionState{
			SessionID: sessionID, RotationFamilyID: familyID, UserID: userID,
			AuthenticationMethod: "oidc", Audience: "api", PrimaryKind: "platform_provider",
			DirectStateCount: 1, DirectProvenanceCount: 1, ProviderEvidenceCount: 1,
			CurrentVersion: 7, UserAuthenticationRevision: 14,
			IssuedAt: directSessionTestNow.Add(-time.Hour), IdleExpiresAt: directSessionTestNow.Add(time.Hour),
			AbsoluteExpiresAt: expiresAt, Active: true, RotationFamilyLive: true,
		},
		Authority: DirectSessionAuthorityFacts{
			ProviderID: providerID, ExternalIdentityID: identityID, ProviderKind: "oidc",
			ProviderEnabled: true, RuntimePolicyEnabled: true, LoginPolicyEnabled: true,
			AccountMode: AccountModeExistingIdentity, UserActive: true,
			IdentityCurrentProviderID: providerID, IdentityCurrentUserID: userID, IdentityProviderKind: "oidc",
			AliasCurrentProviderID: providerID, AliasCurrentIdentityID: identityID,
			Revisions: DirectSessionAuthorityRevisions{
				Provider:           ExactRevision{Pinned: 10, Current: 10},
				Security:           ExactRevision{Pinned: 11, Current: 11},
				LoginPolicy:        ExactRevision{Pinned: 12, Current: 12},
				UserAuthentication: ExactRevision{Pinned: 14, Current: 14},
				ExternalIdentity:   ExactRevision{Pinned: 15, Current: 15},
				SubjectAliasKey:    ExactRevision{Pinned: 2, Current: 2},
				AssurancePolicy:    ExactRevision{Pinned: 16, Current: 16},
			},
			PlatformFloor: DirectSessionPlatformFloor{
				PinnedID: floorID, PinnedRevision: 17, CurrentID: floorID, CurrentRevision: 17,
				CurrentCount: 1, CurrentScope: "platform_floor", Level: identity.AssurancePrimary,
			},
		},
		Evidence: []DirectSessionEvidence{{
			ID: providerEvidenceID, UserID: userID, Kind: DirectSessionEvidencePlatformProvider,
			Level: identity.AssurancePrimary, PlatformProviderID: &providerIDPointer,
			ExternalIdentityID: &identityIDPointer, AuthenticatedAt: directSessionTestNow.Add(-time.Hour),
			ExpiresAt: &expiresAt,
		}},
		PolicyPins: []DirectSessionPolicyPin{
			{Kind: DirectSessionPolicyAssurance, ID: providerID, Revision: 16},
			{Kind: DirectSessionPolicyLogin, ID: providerID, Revision: 12},
			{Kind: DirectSessionPolicyPlatformFloor, ID: floorID, Revision: 17},
		},
	}
}

func directSessionAddTOTP(t *testing.T, snapshot *DirectSessionRevalidationSnapshot) {
	t.Helper()
	factorEvidenceID := uuid.Must(uuid.NewV7())
	factorID := uuid.Must(uuid.NewV7())
	factorIDPointer := factorID
	factorRevision := int64(21)
	authenticatedAt := directSessionTestNow.Add(-10 * time.Minute)
	expiresAt := directSessionTestNow.Add(time.Hour)
	snapshot.Evidence = append(snapshot.Evidence, DirectSessionEvidence{
		ID: factorEvidenceID, UserID: snapshot.Session.UserID, Kind: DirectSessionEvidenceTOTP,
		Level: identity.AssuranceMFA, TOTPCredentialID: &factorIDPointer, FactorRevision: &factorRevision,
		AuthenticatedAt: authenticatedAt, ExpiresAt: &expiresAt,
	})
	snapshot.FactorAuthorities = []DirectSessionFactorAuthority{{
		EvidenceID: factorEvidenceID, EvidenceUserID: snapshot.Session.UserID, TOTPCredentialID: factorID,
		PinnedSecurityRevision: factorRevision, CurrentUserID: snapshot.Session.UserID,
		CurrentSecurityRevision: factorRevision, ConfirmedAt: &authenticatedAt,
	}}
	snapshot.Session.TOTPEvidenceCount = 1
	snapshot.Session.IssuedAt = directSessionTestNow.Add(-5 * time.Minute)
	snapshot.Authority.PlatformFloor.Level = identity.AssuranceMFA
	snapshot.Authority.PlatformFloor.LocalRequired = true
}

func directSessionAddTrust(t *testing.T, snapshot *DirectSessionRevalidationSnapshot) {
	t.Helper()
	ruleID := uuid.Must(uuid.NewV7())
	revision := int64(23)
	provider := &snapshot.Evidence[0]
	provider.Level = identity.AssuranceMFA
	provider.TrustRuleID = &ruleID
	provider.TrustRuleRevision = &revision
	snapshot.Authority.TrustRuleID = &ruleID
	snapshot.Authority.TrustRuleRevision = &revision
	snapshot.TrustAuthorities = []DirectSessionTrustAuthority{{
		EvidenceID: provider.ID, TrustRuleID: ruleID, PinnedRevision: revision,
		CurrentProviderID: snapshot.Authority.ProviderID, CurrentProviderKind: "oidc",
		CurrentRevision: revision, CurrentLevel: identity.AssuranceMFA, Enabled: true,
	}}
	snapshot.Authority.PlatformFloor.Level = identity.AssuranceMFA
}

func directSessionAuthorityLookup(snapshot DirectSessionRevalidationSnapshot) DirectSessionAuthorityLookup {
	return DirectSessionAuthorityLookup{
		SessionID: snapshot.Session.SessionID, UserID: snapshot.Session.UserID,
		AuthenticationMethod: "oidc", Audience: "api",
	}
}

func successfulDirectSessionMutation(
	mutation DirectSessionRevalidationMutation,
	userID uuid.UUID,
) DirectSessionRevalidationMutationResult {
	result := DirectSessionRevalidationMutationResult{
		Applied: true, SessionID: mutation.SessionID, UserID: userID,
		ExpectedVersion: mutation.ExpectedVersion, Decision: mutation.Decision,
	}
	if mutation.Decision == DirectSessionRevalidationUsable {
		result.NewVersion = mutation.ExpectedVersion + 1
	}
	return result
}

func newDirectSessionAuthorityFixture(
	t *testing.T,
	store DirectSessionRevalidationStore,
	mutations ...func(*DirectPlatformSessionAuthorityOptions),
) *DirectPlatformSessionAuthorityService {
	t.Helper()
	options := DirectPlatformSessionAuthorityOptions{
		Store: store, OperationTimeout: time.Second, Now: func() time.Time { return directSessionTestNow },
	}
	for _, mutate := range mutations {
		mutate(&options)
	}
	service, err := NewDirectPlatformSessionAuthority(options)
	if err != nil {
		t.Fatalf("NewDirectPlatformSessionAuthority() error = %v", err)
	}
	return service
}
