package platformsamlauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

type directSAMLSessionStoreStub struct {
	guard   sync.Mutex
	load    func(context.Context, DirectSAMLSessionRevalidationLookup) (DirectSAMLSessionRevalidationSnapshot, error)
	apply   func(context.Context, DirectSAMLSessionRevalidationCommand) (DirectSAMLSessionRevalidationResult, error)
	recover func(context.Context, DirectSAMLSessionRevalidationRecoveryLookup) (DirectSAMLSessionRevalidationRecoveryResult, error)
	cleanup func(context.Context, DirectSAMLSessionRevalidationCleanup) error

	loadCalls    int
	applyCalls   int
	recoverCalls int
	cleanupCalls int
	lastCommand  DirectSAMLSessionRevalidationCommand
	lastRecovery DirectSAMLSessionRevalidationRecoveryLookup
	lastCleanup  DirectSAMLSessionRevalidationCleanup
}

func (store *directSAMLSessionStoreStub) LoadDirectSAMLSessionForRevalidation(
	ctx context.Context,
	lookup DirectSAMLSessionRevalidationLookup,
) (DirectSAMLSessionRevalidationSnapshot, error) {
	store.guard.Lock()
	store.loadCalls++
	function := store.load
	store.guard.Unlock()
	return function(ctx, lookup)
}

func (store *directSAMLSessionStoreStub) ApplyDirectSAMLSessionRevalidation(
	ctx context.Context,
	command DirectSAMLSessionRevalidationCommand,
) (DirectSAMLSessionRevalidationResult, error) {
	store.guard.Lock()
	store.applyCalls++
	store.lastCommand = command
	function := store.apply
	store.guard.Unlock()
	return function(ctx, command)
}

func (store *directSAMLSessionStoreStub) RecoverDirectSAMLSessionRevalidationApply(
	ctx context.Context,
	lookup DirectSAMLSessionRevalidationRecoveryLookup,
) (DirectSAMLSessionRevalidationRecoveryResult, error) {
	store.guard.Lock()
	store.recoverCalls++
	store.lastRecovery = lookup
	function := store.recover
	store.guard.Unlock()
	return function(ctx, lookup)
}

func (store *directSAMLSessionStoreStub) CleanupDirectSAMLSessionRevalidationDelivery(
	ctx context.Context,
	cleanup DirectSAMLSessionRevalidationCleanup,
) error {
	store.guard.Lock()
	store.cleanupCalls++
	store.lastCleanup = cleanup
	function := store.cleanup
	store.guard.Unlock()
	return function(ctx, cleanup)
}

func (store *directSAMLSessionStoreStub) counts() (int, int, int, int) {
	store.guard.Lock()
	defer store.guard.Unlock()
	return store.loadCalls, store.applyCalls, store.recoverCalls, store.cleanupCalls
}

type directSAMLSessionCredentialIssuerFunc func(CredentialRequest) (*CredentialReservation, error)

func (function directSAMLSessionCredentialIssuerFunc) ReserveDirectSAMLCredential(
	request CredentialRequest,
) (*CredentialReservation, error) {
	return function(request)
}

type directSAMLSessionFixture struct {
	now      time.Time
	snapshot DirectSAMLSessionRevalidationSnapshot
	lookup   DirectSAMLSessionAuthorityLookup
}

func TestDirectSAMLSessionAuthorityAllDecisionsAndExactCommands(t *testing.T) {
	base := newDirectSAMLSessionFixture()
	tests := map[string]struct {
		mutate       func(*DirectSAMLSessionRevalidationSnapshot)
		wantDecision mfa.SessionDecision
		wantReason   mfa.SessionReason
		wantError    error
		transition   bool
	}{
		"usable": {
			wantDecision: mfa.SessionUsable, wantReason: mfa.SessionReasonCurrent,
		},
		"expired": {
			mutate: func(value *DirectSAMLSessionRevalidationSnapshot) {
				value.Session.IdleExpiresAt = base.now
			},
			wantDecision: mfa.SessionRevoke, wantReason: mfa.SessionReasonExpired,
			wantError: ErrAuthenticationDenied,
		},
		"expired provider evidence": {
			mutate: func(value *DirectSAMLSessionRevalidationSnapshot) {
				*value.Evidence[0].ExpiresAt = base.now
				value.Authority.EvidenceFresh = false
			},
			wantDecision: mfa.SessionRevoke, wantReason: mfa.SessionReasonExpired,
			wantError: ErrAuthenticationDenied,
		},
		"lifecycle": {
			mutate: func(value *DirectSAMLSessionRevalidationSnapshot) {
				value.Authority.ProviderEnabled = false
			},
			wantDecision: mfa.SessionRevoke, wantReason: mfa.SessionReasonLifecycle,
			wantError: ErrAuthenticationDenied,
		},
		"identity epoch": {
			mutate: func(value *DirectSAMLSessionRevalidationSnapshot) {
				value.Authority.CurrentUserAuthenticationRevision++
			},
			wantDecision: mfa.SessionRevoke, wantReason: mfa.SessionReasonIdentityEpoch,
			wantError: ErrAuthenticationDenied,
		},
		"primary drift": {
			mutate: func(value *DirectSAMLSessionRevalidationSnapshot) {
				value.Authority.CurrentMetadataDigest[0]++
			},
			wantDecision: mfa.SessionRevoke, wantReason: mfa.SessionReasonPrimaryDrift,
			wantError: ErrAuthenticationDenied,
		},
		"factor drift": {
			mutate: func(value *DirectSAMLSessionRevalidationSnapshot) {
				directSAMLSessionAddTOTP(value, base.now)
				value.FactorAuthorities[0].CurrentSecurityRevision++
			},
			wantDecision: mfa.SessionRevoke, wantReason: mfa.SessionReasonFactorDrift,
			wantError: ErrAuthenticationDenied,
		},
		"trust drift": {
			mutate: func(value *DirectSAMLSessionRevalidationSnapshot) {
				directSAMLSessionAddTrust(value)
				value.TrustAuthorities[0].Enabled = false
			},
			wantDecision: mfa.SessionRevoke, wantReason: mfa.SessionReasonTrustDrift,
			wantError: ErrAuthenticationDenied,
		},
		"policy refresh rotation": {
			mutate: func(value *DirectSAMLSessionRevalidationSnapshot) {
				value.Authority.CurrentAssurancePolicyRevision++
				value.Authority.PolicyPinsExact = false
			},
			wantDecision: mfa.SessionRotate, wantReason: mfa.SessionReasonPolicyRefresh,
			transition: true,
		},
		"assurance step up": {
			mutate: func(value *DirectSAMLSessionRevalidationSnapshot) {
				directSAMLSessionSetFloor(value, identity.AssuranceMFA, true)
			},
			wantDecision: mfa.SessionStepUp, wantReason: mfa.SessionReasonAssuranceInsufficient,
			transition: true,
		},
		"expired local evidence step up": {
			mutate: func(value *DirectSAMLSessionRevalidationSnapshot) {
				directSAMLSessionAddTOTP(value, base.now)
				expiresAt := base.now
				value.Evidence[1].ExpiresAt = &expiresAt
				value.Authority.EvidenceFresh = false
				directSAMLSessionSetFloor(value, identity.AssuranceMFA, true)
			},
			wantDecision: mfa.SessionStepUp, wantReason: mfa.SessionReasonAssuranceInsufficient,
			transition: true,
		},
		"recovery restriction step up": {
			mutate: func(value *DirectSAMLSessionRevalidationSnapshot) {
				value.Session.RecoveryRestricted = true
			},
			wantDecision: mfa.SessionStepUp, wantReason: mfa.SessionReasonRecoveryRestricted,
			transition: true,
		},
		"no exact factor denies": {
			mutate: func(value *DirectSAMLSessionRevalidationSnapshot) {
				directSAMLSessionSetFloor(value, identity.AssuranceMFA, true)
				value.Authority.StepUpTOTP = nil
			},
			wantDecision: mfa.SessionDeny, wantReason: mfa.SessionReasonAssuranceInsufficient,
			wantError: ErrAuthenticationDenied,
		},
		"exhausted version denies": {
			mutate: func(value *DirectSAMLSessionRevalidationSnapshot) {
				value.Session.CurrentVersion = DirectSAMLSessionMaximumVersion
			},
			wantDecision: mfa.SessionDeny, wantReason: mfa.SessionReasonMalformed,
			wantError: ErrAuthenticationDenied,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := base
			fixture.snapshot = cloneDirectSAMLSessionSnapshot(base.snapshot)
			if test.mutate != nil {
				test.mutate(&fixture.snapshot)
			}
			var observed DirectSAMLSessionRevalidationCommand
			store := directSAMLSessionStore(&fixture, func(
				_ context.Context,
				command DirectSAMLSessionRevalidationCommand,
			) (DirectSAMLSessionRevalidationResult, error) {
				observed = command
				return directSAMLSessionResult(command, fixture.snapshot.Session.UserID), nil
			})
			service := directSAMLSessionService(t, &fixture, store, directSAMLSessionIssuer(&fixture, nil))
			outcome, err := service.RevalidateDirectPlatformSession(context.Background(), fixture.lookup)
			if !errors.Is(err, test.wantError) || outcome.Decision != test.wantDecision ||
				outcome.Reason != test.wantReason || observed.Decision != test.wantDecision ||
				observed.Reason != test.wantReason || observed.Audit != fixture.lookup.Audit ||
				observed.RequestDigest == (DirectSAMLSessionRevalidationRequestDigest{}) ||
				observed.RequestDigest != directSAMLSessionCommandDigest(observed) {
				t.Fatalf("outcome=%s err=%v command=%s", outcome.String(), err, observed.String())
			}
			if test.wantDecision == mfa.SessionUsable {
				if !outcome.AllowAuthority || !outcome.AllowIdleTouch || outcome.Credential != nil || outcome.Delivery != nil {
					t.Fatalf("usable outcome = %s", outcome.String())
				}
			} else if outcome.AllowAuthority || outcome.AllowIdleTouch {
				t.Fatalf("non-authorizing outcome = %s", outcome.String())
			}
			if test.transition {
				if outcome.Credential == nil || outcome.Delivery == nil || outcome.ExpiresAt.IsZero() {
					t.Fatalf("transition outcome = %s", outcome.String())
				}
				material, consumed := outcome.Credential.Consume()
				if !consumed {
					t.Fatal("transition credential was not consumable")
				}
				material.Destroy()
				if err := outcome.Delivery.ConfirmBrowserDelivery(); err != nil {
					t.Fatalf("ConfirmBrowserDelivery() error = %v", err)
				}
			}
			if outcome.Credential != nil {
				outcome.Credential.Destroy()
			}
		})
	}
}

func TestDirectSAMLSessionAuthorityRejectsMalformedAndMixedSnapshotsBeforeMutation(t *testing.T) {
	base := newDirectSAMLSessionFixture()
	tenantID := testID(90)
	tests := map[string]func(*DirectSAMLSessionRevalidationSnapshot){
		"session echo": func(value *DirectSAMLSessionRevalidationSnapshot) {
			value.Session.SessionID = testID(91)
		},
		"user echo": func(value *DirectSAMLSessionRevalidationSnapshot) {
			value.Session.UserID = testID(91)
		},
		"tenantful": func(value *DirectSAMLSessionRevalidationSnapshot) {
			value.Session.ActiveTenantID = &tenantID
		},
		"tenant provenance": func(value *DirectSAMLSessionRevalidationSnapshot) {
			value.Session.TenantProvenanceCount = 1
		},
		"OIDC state": func(value *DirectSAMLSessionRevalidationSnapshot) {
			value.Session.SAMLStateCount = 0
			value.Session.OIDCStateCount = 1
		},
		"wrong authority": func(value *DirectSAMLSessionRevalidationSnapshot) {
			value.Session.Authority = "direct_platform_oidc"
		},
		"wrong method": func(value *DirectSAMLSessionRevalidationSnapshot) {
			value.Session.AuthenticationMethod = "oidc"
		},
		"wrong provider kind": func(value *DirectSAMLSessionRevalidationSnapshot) {
			value.Authority.ProviderKind = "oidc"
		},
		"ambiguous provenance": func(value *DirectSAMLSessionRevalidationSnapshot) {
			value.Session.SAMLProvenanceCount = 2
		},
		"provider count": func(value *DirectSAMLSessionRevalidationSnapshot) {
			value.Session.ProviderEvidenceCount = 2
		},
		"duplicate evidence": func(value *DirectSAMLSessionRevalidationSnapshot) {
			value.Evidence = append(value.Evidence, value.Evidence[0])
		},
		"unsorted policy pins": func(value *DirectSAMLSessionRevalidationSnapshot) {
			value.PolicyPins[0], value.PolicyPins[1] = value.PolicyPins[1], value.PolicyPins[0]
		},
		"wrong pinned policy": func(value *DirectSAMLSessionRevalidationSnapshot) {
			value.PolicyPins[0].Revision++
		},
		"zero digest": func(value *DirectSAMLSessionRevalidationSnapshot) {
			value.Authority.CurrentMetadataDigest = [sha256.Size]byte{}
		},
		"future evidence": func(value *DirectSAMLSessionRevalidationSnapshot) {
			value.Evidence[0].AuthenticatedAt = base.now.Add(time.Minute)
		},
		"fresh aggregate contradicts expired evidence": func(value *DirectSAMLSessionRevalidationSnapshot) {
			*value.Evidence[0].ExpiresAt = base.now
		},
		"missing factor authority": func(value *DirectSAMLSessionRevalidationSnapshot) {
			directSAMLSessionAddTOTP(value, base.now)
			value.FactorAuthorities = nil
		},
		"foreign requirement": func(value *DirectSAMLSessionRevalidationSnapshot) {
			value.Authority.PlatformFloor.PolicyRevisions[0].PolicyID = testID(92)
		},
		"invalid step up selection": func(value *DirectSAMLSessionRevalidationSnapshot) {
			value.Authority.StepUpTOTP.Revision = 0
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := base
			fixture.snapshot = cloneDirectSAMLSessionSnapshot(base.snapshot)
			mutate(&fixture.snapshot)
			store := directSAMLSessionStore(&fixture, func(
				context.Context,
				DirectSAMLSessionRevalidationCommand,
			) (DirectSAMLSessionRevalidationResult, error) {
				t.Fatal("malformed snapshot reached Apply")
				return DirectSAMLSessionRevalidationResult{}, nil
			})
			issuerCalls := 0
			service := directSAMLSessionService(t, &fixture, store, directSAMLSessionIssuer(&fixture, &issuerCalls))
			outcome, err := service.RevalidateDirectPlatformSession(context.Background(), fixture.lookup)
			if !errors.Is(err, ErrAuthenticationDenied) || outcome != (DirectSAMLSessionAuthorityOutcome{}) ||
				issuerCalls != 0 {
				t.Fatalf("RevalidateDirectPlatformSession() = %s, %v; issuer calls=%d", outcome.String(), err, issuerCalls)
			}
			_, applyCalls, recoverCalls, cleanupCalls := store.counts()
			if applyCalls != 0 || recoverCalls != 0 || cleanupCalls != 0 {
				t.Fatalf("persistence calls apply/recover/cleanup = %d/%d/%d", applyCalls, recoverCalls, cleanupCalls)
			}
		})
	}
}

func TestDirectSAMLSessionAuthorityRequiresSAMLLookupAndExplicitAudit(t *testing.T) {
	fixture := newDirectSAMLSessionFixture()
	store := directSAMLSessionStore(&fixture, func(
		context.Context,
		DirectSAMLSessionRevalidationCommand,
	) (DirectSAMLSessionRevalidationResult, error) {
		t.Fatal("invalid lookup reached Apply")
		return DirectSAMLSessionRevalidationResult{}, nil
	})
	service := directSAMLSessionService(t, &fixture, store, directSAMLSessionIssuer(&fixture, nil))
	tests := map[string]func(*DirectSAMLSessionAuthorityLookup){
		"OIDC":       func(value *DirectSAMLSessionAuthorityLookup) { value.AuthenticationMethod = "oidc" },
		"tenant":     func(value *DirectSAMLSessionAuthorityLookup) { value.Audience = "tenant" },
		"session":    func(value *DirectSAMLSessionAuthorityLookup) { value.SessionID = identity.EntityID{} },
		"user":       func(value *DirectSAMLSessionAuthorityLookup) { value.UserID = identity.EntityID{} },
		"same IDs":   func(value *DirectSAMLSessionAuthorityLookup) { value.UserID = value.SessionID },
		"audit":      func(value *DirectSAMLSessionAuthorityLookup) { value.Audit = AuditContext{} },
		"user agent": func(value *DirectSAMLSessionAuthorityLookup) { value.Audit.UserAgent = " secret\n" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			lookup := fixture.lookup
			mutate(&lookup)
			outcome, err := service.RevalidateDirectPlatformSession(context.Background(), lookup)
			if !errors.Is(err, ErrAuthenticationDenied) || outcome != (DirectSAMLSessionAuthorityOutcome{}) {
				t.Fatalf("RevalidateDirectPlatformSession() = %s, %v", outcome.String(), err)
			}
		})
	}
	loadCalls, _, _, _ := store.counts()
	if loadCalls != 0 {
		t.Fatalf("invalid lookups reached Load %d times", loadCalls)
	}
}

func TestDirectSAMLSessionAuthorityRetriesAndRecoversExactApply(t *testing.T) {
	fixture := newDirectSAMLSessionFixture()
	fixture.snapshot.Authority.CurrentAssurancePolicyRevision++
	fixture.snapshot.Authority.PolicyPinsExact = false
	loadCalls := 0
	applyCalls := 0
	recoverCalls := 0
	var wanted DirectSAMLSessionRevalidationCommand
	store := &directSAMLSessionStoreStub{}
	store.load = func(_ context.Context, lookup DirectSAMLSessionRevalidationLookup) (DirectSAMLSessionRevalidationSnapshot, error) {
		loadCalls++
		if loadCalls == 1 {
			return DirectSAMLSessionRevalidationSnapshot{}, errors.New("transient load")
		}
		if lookup.SessionID != fixture.lookup.SessionID || !lookup.ObservedAt.Equal(fixture.now) {
			t.Fatalf("lookup = %s", lookup.String())
		}
		return cloneDirectSAMLSessionSnapshot(fixture.snapshot), nil
	}
	store.apply = func(_ context.Context, command DirectSAMLSessionRevalidationCommand) (DirectSAMLSessionRevalidationResult, error) {
		applyCalls++
		wanted = command
		return DirectSAMLSessionRevalidationResult{}, errors.New("response lost")
	}
	store.recover = func(ctx context.Context, lookup DirectSAMLSessionRevalidationRecoveryLookup) (DirectSAMLSessionRevalidationRecoveryResult, error) {
		recoverCalls++
		if ctx.Err() != nil {
			t.Fatalf("recovery inherited cancellation: %v", ctx.Err())
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("recovery context has no deadline")
		}
		if lookup.Command != wanted {
			t.Fatalf("recovery command = %s; want %s", lookup.Command.String(), wanted.String())
		}
		if recoverCalls == 1 {
			return DirectSAMLSessionRevalidationRecoveryResult{}, errors.New("transient recovery")
		}
		return DirectSAMLSessionRevalidationRecoveryResult{
			Matched: true, Result: directSAMLSessionResult(wanted, fixture.snapshot.Session.UserID),
		}, nil
	}
	store.cleanup = func(context.Context, DirectSAMLSessionRevalidationCleanup) error { return nil }
	service := directSAMLSessionService(t, &fixture, store, directSAMLSessionIssuer(&fixture, nil))
	outcome, err := service.RevalidateDirectPlatformSession(context.Background(), fixture.lookup)
	if err != nil || outcome.Decision != mfa.SessionRotate || outcome.Credential == nil || outcome.Delivery == nil ||
		loadCalls != 2 || applyCalls != 2 || recoverCalls != 2 {
		t.Fatalf("outcome=%s err=%v calls=%d/%d/%d", outcome.String(), err, loadCalls, applyCalls, recoverCalls)
	}
	outcome.Credential.Destroy()
	if err := outcome.Delivery.ConfirmBrowserDelivery(); err != nil {
		t.Fatalf("ConfirmBrowserDelivery() error = %v", err)
	}
}

func TestDirectSAMLSessionAuthorityAmbiguousTransitionReturnsCleanupOnlyProof(t *testing.T) {
	fixture := newDirectSAMLSessionFixture()
	directSAMLSessionSetFloor(&fixture.snapshot, identity.AssuranceMFA, true)
	var command DirectSAMLSessionRevalidationCommand
	store := directSAMLSessionStore(&fixture, func(
		_ context.Context,
		value DirectSAMLSessionRevalidationCommand,
	) (DirectSAMLSessionRevalidationResult, error) {
		command = value
		return DirectSAMLSessionRevalidationResult{}, errors.New("ambiguous apply")
	})
	store.recover = func(ctx context.Context, lookup DirectSAMLSessionRevalidationRecoveryLookup) (DirectSAMLSessionRevalidationRecoveryResult, error) {
		if ctx.Err() != nil || lookup.Command != command {
			t.Fatalf("recovery = %v / %s", ctx.Err(), lookup.Command.String())
		}
		return DirectSAMLSessionRevalidationRecoveryResult{}, nil
	}
	cleanupCalls := 0
	store.cleanup = func(ctx context.Context, cleanup DirectSAMLSessionRevalidationCleanup) error {
		cleanupCalls++
		if ctx.Err() != nil {
			t.Fatalf("cleanup inherited cancellation: %v", ctx.Err())
		}
		if cleanup.Command != command || cleanup.Result.ContinuationID != command.Continuation.ContinuationID() ||
			cleanup.Reason != CleanupDeliveryFailed || cleanup.Audit != command.Audit ||
			!validDirectSAMLSessionCleanup(cleanup) {
			t.Fatalf("cleanup = %s", cleanup.String())
		}
		return nil
	}
	service := directSAMLSessionService(t, &fixture, store, directSAMLSessionIssuer(&fixture, nil))
	cancelled, cancel := context.WithCancel(context.Background())
	outcome, err := service.RevalidateDirectPlatformSession(cancelled, fixture.lookup)
	cancel()
	if !errors.Is(err, ErrAuthenticationUnavailable) || outcome.Credential != nil ||
		outcome.Delivery == nil || outcome.ContinuationID == (identity.EntityID{}) {
		t.Fatalf("ambiguous outcome = %s, %v", outcome.String(), err)
	}
	if err := outcome.Delivery.CompensateBrowserDelivery(cancelled); err != nil || cleanupCalls != 1 {
		t.Fatalf("CompensateBrowserDelivery() = %v; calls=%d", err, cleanupCalls)
	}
	if err := outcome.Delivery.CompensateBrowserDelivery(context.Background()); err != nil || cleanupCalls != 1 {
		t.Fatalf("second compensation = %v; calls=%d", err, cleanupCalls)
	}
}

func TestDirectSAMLSessionAuthorityRecoversAfterCallerCancellation(t *testing.T) {
	fixture := newDirectSAMLSessionFixture()
	fixture.snapshot.Authority.CurrentAssurancePolicyRevision++
	fixture.snapshot.Authority.PolicyPinsExact = false
	ctx, cancel := context.WithCancel(context.Background())
	var command DirectSAMLSessionRevalidationCommand
	store := directSAMLSessionStore(&fixture, func(
		_ context.Context,
		value DirectSAMLSessionRevalidationCommand,
	) (DirectSAMLSessionRevalidationResult, error) {
		command = value
		cancel()
		return DirectSAMLSessionRevalidationResult{}, context.Canceled
	})
	store.recover = func(recovery context.Context, lookup DirectSAMLSessionRevalidationRecoveryLookup) (DirectSAMLSessionRevalidationRecoveryResult, error) {
		if recovery.Err() != nil {
			t.Fatalf("recovery inherited caller cancellation: %v", recovery.Err())
		}
		if _, ok := recovery.Deadline(); !ok {
			t.Fatal("recovery context has no deadline")
		}
		if lookup.Command != command {
			t.Fatalf("recovery lookup = %s", lookup.String())
		}
		return DirectSAMLSessionRevalidationRecoveryResult{
			Matched: true, Result: directSAMLSessionResult(command, fixture.snapshot.Session.UserID),
		}, nil
	}
	service := directSAMLSessionService(t, &fixture, store, directSAMLSessionIssuer(&fixture, nil))
	outcome, err := service.RevalidateDirectPlatformSession(ctx, fixture.lookup)
	if err != nil || outcome.Credential == nil || outcome.Delivery == nil {
		t.Fatalf("RevalidateDirectPlatformSession() = %s, %v", outcome.String(), err)
	}
	outcome.Credential.Destroy()
	if err := outcome.Delivery.ConfirmBrowserDelivery(); err != nil {
		t.Fatalf("ConfirmBrowserDelivery() error = %v", err)
	}
}

func TestDirectSAMLSessionAuthorityCredentialReleaseFailureKeepsExactCompensation(t *testing.T) {
	fixture := newDirectSAMLSessionFixture()
	fixture.snapshot.Authority.CurrentAssurancePolicyRevision++
	fixture.snapshot.Authority.PolicyPinsExact = false
	var issued *CredentialReservation
	issuer := directSAMLSessionIssuer(&fixture, nil)
	wrapped := directSAMLSessionCredentialIssuerFunc(func(request CredentialRequest) (*CredentialReservation, error) {
		var err error
		issued, err = issuer.ReserveDirectSAMLCredential(request)
		return issued, err
	})
	cleanupCalls := 0
	store := directSAMLSessionStore(&fixture, func(
		_ context.Context,
		command DirectSAMLSessionRevalidationCommand,
	) (DirectSAMLSessionRevalidationResult, error) {
		result := directSAMLSessionResult(command, fixture.snapshot.Session.UserID)
		issued.Destroy()
		return result, nil
	})
	store.cleanup = func(_ context.Context, cleanup DirectSAMLSessionRevalidationCleanup) error {
		cleanupCalls++
		if cleanup.Result.NewSessionID != cleanup.Command.Session.SessionID() ||
			!validDirectSAMLSessionCleanup(cleanup) {
			t.Fatalf("cleanup = %s", cleanup.String())
		}
		return nil
	}
	service := directSAMLSessionService(t, &fixture, store, wrapped)
	outcome, err := service.RevalidateDirectPlatformSession(context.Background(), fixture.lookup)
	if !errors.Is(err, ErrAuthenticationUnavailable) || outcome.Credential != nil || outcome.Delivery == nil ||
		outcome.NewSessionID == (identity.EntityID{}) {
		t.Fatalf("release-failure outcome = %s, %v", outcome.String(), err)
	}
	if err := outcome.Delivery.CompensateBrowserDelivery(context.Background()); err != nil || cleanupCalls != 1 {
		t.Fatalf("CompensateBrowserDelivery() = %v; calls=%d", err, cleanupCalls)
	}
}

func TestDirectSAMLSessionAuthorityStaleAndReplayDestroyReservedCredential(t *testing.T) {
	for _, category := range []DirectSAMLSessionRevalidationCategory{
		DirectSAMLSessionRevalidationStale, DirectSAMLSessionRevalidationReplay,
	} {
		t.Run(string(category), func(t *testing.T) {
			fixture := newDirectSAMLSessionFixture()
			fixture.snapshot.Authority.CurrentAssurancePolicyRevision++
			fixture.snapshot.Authority.PolicyPinsExact = false
			var issued *CredentialReservation
			issuer := directSAMLSessionIssuer(&fixture, nil)
			wrapped := directSAMLSessionCredentialIssuerFunc(func(request CredentialRequest) (*CredentialReservation, error) {
				var err error
				issued, err = issuer.ReserveDirectSAMLCredential(request)
				return issued, err
			})
			store := directSAMLSessionStore(&fixture, func(
				_ context.Context,
				command DirectSAMLSessionRevalidationCommand,
			) (DirectSAMLSessionRevalidationResult, error) {
				return DirectSAMLSessionRevalidationResult{
					Applied: false, Category: category, Decision: command.Decision,
					SessionID: command.SessionID, UserID: fixture.snapshot.Session.UserID,
					ExpectedVersion: command.ExpectedVersion,
				}, nil
			})
			service := directSAMLSessionService(t, &fixture, store, wrapped)
			outcome, err := service.RevalidateDirectPlatformSession(context.Background(), fixture.lookup)
			if !errors.Is(err, ErrAuthenticationDenied) || outcome != (DirectSAMLSessionAuthorityOutcome{}) || issued == nil {
				t.Fatalf("outcome=%s err=%v issued=%t", outcome.String(), err, issued != nil)
			}
			if !issued.Session().IsZero() || !issued.Continuation().IsZero() {
				t.Fatal("reserved credential survived stale/replay")
			}
		})
	}
}

func TestDirectSAMLSessionCredentialAndDeliveryAreCopySafe(t *testing.T) {
	fixture := newDirectSAMLSessionFixture()
	fixture.snapshot.Authority.CurrentAssurancePolicyRevision++
	fixture.snapshot.Authority.PolicyPinsExact = false
	cleanupCalls := 0
	store := directSAMLSessionStore(&fixture, func(
		_ context.Context,
		command DirectSAMLSessionRevalidationCommand,
	) (DirectSAMLSessionRevalidationResult, error) {
		return directSAMLSessionResult(command, fixture.snapshot.Session.UserID), nil
	})
	store.cleanup = func(context.Context, DirectSAMLSessionRevalidationCleanup) error {
		cleanupCalls++
		return nil
	}
	service := directSAMLSessionService(t, &fixture, store, directSAMLSessionIssuer(&fixture, nil))
	outcome, err := service.RevalidateDirectPlatformSession(context.Background(), fixture.lookup)
	if err != nil {
		t.Fatalf("RevalidateDirectPlatformSession() error = %v", err)
	}
	credential := outcome.Credential
	credentialCopy := credential
	var successes int
	var guard sync.Mutex
	var wait sync.WaitGroup
	for _, candidate := range []*BrowserCredential{credential, credentialCopy} {
		wait.Add(1)
		go func(value *BrowserCredential) {
			defer wait.Done()
			material, ok := value.Consume()
			if ok {
				material.Destroy()
				guard.Lock()
				successes++
				guard.Unlock()
			}
		}(candidate)
	}
	wait.Wait()
	if successes != 1 {
		t.Fatalf("credential consumption successes = %d", successes)
	}
	first := *outcome.Delivery
	second := *outcome.Delivery
	results := make(chan error, 2)
	go func() { results <- first.CompensateBrowserDelivery(context.Background()) }()
	go func() { results <- second.CompensateBrowserDelivery(context.Background()) }()
	if err := <-results; err != nil {
		t.Fatalf("first compensation error = %v", err)
	}
	if err := <-results; err != nil {
		t.Fatalf("second compensation error = %v", err)
	}
	if cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d", cleanupCalls)
	}
}

func TestDirectSAMLSessionDeliveryConfirmationIsExactlyOnce(t *testing.T) {
	fixture := newDirectSAMLSessionFixture()
	fixture.snapshot.Authority.CurrentAssurancePolicyRevision++
	fixture.snapshot.Authority.PolicyPinsExact = false
	store := directSAMLSessionStore(&fixture, func(
		_ context.Context,
		command DirectSAMLSessionRevalidationCommand,
	) (DirectSAMLSessionRevalidationResult, error) {
		return directSAMLSessionResult(command, fixture.snapshot.Session.UserID), nil
	})
	service := directSAMLSessionService(t, &fixture, store, directSAMLSessionIssuer(&fixture, nil))
	outcome, err := service.RevalidateDirectPlatformSession(context.Background(), fixture.lookup)
	if err != nil {
		t.Fatalf("RevalidateDirectPlatformSession() error = %v", err)
	}
	outcome.Credential.Destroy()
	copyFinalizer := *outcome.Delivery
	if err := outcome.Delivery.ConfirmBrowserDelivery(); err != nil {
		t.Fatalf("ConfirmBrowserDelivery() error = %v", err)
	}
	if err := copyFinalizer.ConfirmBrowserDelivery(); !errors.Is(err, ErrBrowserDeliveryRejected) {
		t.Fatalf("second ConfirmBrowserDelivery() error = %v", err)
	}
	if err := copyFinalizer.CompensateBrowserDelivery(context.Background()); !errors.Is(err, ErrBrowserDeliveryRejected) {
		t.Fatalf("post-confirm compensation error = %v", err)
	}
	_, _, _, cleanupCalls := store.counts()
	if cleanupCalls != 0 {
		t.Fatalf("confirmed transition cleanup calls = %d", cleanupCalls)
	}
}

func TestDirectSAMLSessionDeliveryFreezesAmbiguousCleanupProof(t *testing.T) {
	fixture := newDirectSAMLSessionFixture()
	fixture.snapshot.Authority.CurrentAssurancePolicyRevision++
	fixture.snapshot.Authority.PolicyPinsExact = false
	var cleanupCalls int
	var cleanedUpAt []time.Time
	store := directSAMLSessionStore(&fixture, func(
		_ context.Context,
		command DirectSAMLSessionRevalidationCommand,
	) (DirectSAMLSessionRevalidationResult, error) {
		return directSAMLSessionResult(command, fixture.snapshot.Session.UserID), nil
	})
	store.cleanup = func(_ context.Context, cleanup DirectSAMLSessionRevalidationCleanup) error {
		cleanupCalls++
		cleanedUpAt = append(cleanedUpAt, cleanup.CleanedUpAt)
		if cleanupCalls <= 2 {
			return errors.New("ambiguous cleanup")
		}
		return nil
	}
	clockCalls := 0
	service := directSAMLSessionService(t, &fixture, store, directSAMLSessionIssuer(&fixture, nil))
	service.now = func() time.Time {
		clockCalls++
		return fixture.now.Add(time.Duration(clockCalls-1) * time.Second)
	}
	outcome, err := service.RevalidateDirectPlatformSession(context.Background(), fixture.lookup)
	if err != nil || outcome.Credential == nil || outcome.Delivery == nil {
		t.Fatalf("RevalidateDirectPlatformSession() = %s, %v", outcome.String(), err)
	}
	outcome.Credential.Destroy()
	copyFinalizer := *outcome.Delivery
	if err := outcome.Delivery.CompensateBrowserDelivery(context.Background()); !errors.Is(err, ErrBrowserDeliveryUnavailable) {
		t.Fatalf("first compensation = %v", err)
	}
	if err := copyFinalizer.ConfirmBrowserDelivery(); !errors.Is(err, ErrBrowserDeliveryRejected) {
		t.Fatalf("confirm after ambiguous compensation = %v", err)
	}
	if err := copyFinalizer.CompensateBrowserDelivery(context.Background()); err != nil {
		t.Fatalf("recovered compensation = %v", err)
	}
	if err := outcome.Delivery.CompensateBrowserDelivery(context.Background()); err != nil ||
		cleanupCalls != 3 || clockCalls != 2 || len(cleanedUpAt) != 3 ||
		cleanedUpAt[0] != cleanedUpAt[1] || cleanedUpAt[1] != cleanedUpAt[2] {
		t.Fatalf("idempotent compensation = %v, calls=%d clock=%d cleaned=%v",
			err, cleanupCalls, clockCalls, cleanedUpAt)
	}
}

func TestDirectSAMLSessionCommandDigestBindsReservationAndAudit(t *testing.T) {
	fixture := newDirectSAMLSessionFixture()
	fixture.snapshot.Authority.CurrentAssurancePolicyRevision++
	fixture.snapshot.Authority.PolicyPinsExact = false
	service := directSAMLSessionService(t, &fixture, directSAMLSessionStore(&fixture, func(
		context.Context,
		DirectSAMLSessionRevalidationCommand,
	) (DirectSAMLSessionRevalidationResult, error) {
		return DirectSAMLSessionRevalidationResult{}, errors.New("unused")
	}), directSAMLSessionIssuer(&fixture, nil))
	reservation, command, err := service.command(
		fixture.snapshot, fixture.lookup.Audit, fixture.now,
		mfa.SessionRotate, mfa.SessionReasonPolicyRefresh,
	)
	if err != nil {
		t.Fatalf("command() error = %v", err)
	}
	defer reservation.Destroy()
	want := command.RequestDigest
	if want != directSAMLSessionCommandDigest(command) {
		t.Fatal("command digest is not deterministic")
	}
	mutations := []func(*DirectSAMLSessionRevalidationCommand){
		func(value *DirectSAMLSessionRevalidationCommand) { value.Audit.UserAgent = "different-browser/1" },
		func(value *DirectSAMLSessionRevalidationCommand) { value.Audit.RequestID = testID(93) },
		func(value *DirectSAMLSessionRevalidationCommand) { value.ExpectedVersion++ },
		func(value *DirectSAMLSessionRevalidationCommand) { value.Reason = mfa.SessionReasonMalformed },
	}
	for index, mutate := range mutations {
		candidate := command
		mutate(&candidate)
		if directSAMLSessionCommandDigest(candidate) == want {
			t.Fatalf("mutation %d did not change digest", index)
		}
	}
	alternateToken := opaqueCredential(75)
	alternateCSRF := opaqueCredential(76)
	alternateSession, sessionErr := mfa.NewSessionReservation(mfa.SessionMaterial{
		SessionID: command.Session.SessionID(), FamilyID: command.Session.FamilyID(),
		TokenDigest: sha256.Sum256(alternateToken), CSRFDigest: sha256.Sum256(alternateCSRF),
		AuthenticationMethod: command.Session.AuthenticationMethod(),
		IdleExpiresAt:        command.Session.IdleExpiresAt(), AbsoluteExpiresAt: command.Session.AbsoluteExpiresAt(),
	}, command.ObservedAt.Truncate(time.Millisecond))
	if sessionErr != nil {
		t.Fatalf("alternate session reservation error = %v", sessionErr)
	}
	alternate := command
	alternate.Session = alternateSession
	if directSAMLSessionCommandDigest(alternate) == want {
		t.Fatal("changed reserved bearer digests did not change command digest")
	}
	if strings.Contains(command.String(), fixture.lookup.Audit.UserAgent) ||
		strings.Contains(command.String(), string(opaqueCredential(72))) ||
		strings.Contains(fmt.Sprintf("%#v", command), fixture.lookup.Audit.UserAgent) {
		t.Fatalf("command formatting exposed protected material: %s / %#v", command.String(), command)
	}
}

func TestDirectSAMLSessionAuthorityCancellationIsBounded(t *testing.T) {
	fixture := newDirectSAMLSessionFixture()
	store := directSAMLSessionStore(&fixture, func(
		ctx context.Context,
		_ DirectSAMLSessionRevalidationCommand,
	) (DirectSAMLSessionRevalidationResult, error) {
		<-ctx.Done()
		return DirectSAMLSessionRevalidationResult{}, ctx.Err()
	})
	service := directSAMLSessionService(t, &fixture, store, directSAMLSessionIssuer(&fixture, nil))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if outcome, err := service.RevalidateDirectPlatformSession(ctx, fixture.lookup); !errors.Is(err, ErrAuthenticationUnavailable) ||
		outcome != (DirectSAMLSessionAuthorityOutcome{}) {
		t.Fatalf("canceled RevalidateDirectPlatformSession() = %s, %v", outcome.String(), err)
	}
	loadCalls, applyCalls, _, _ := store.counts()
	if loadCalls != 0 || applyCalls != 0 {
		t.Fatalf("canceled calls load/apply = %d/%d", loadCalls, applyCalls)
	}
}

func TestDirectSAMLSessionAuthorityConstructorRejectsInvalidDependencies(t *testing.T) {
	fixture := newDirectSAMLSessionFixture()
	store := directSAMLSessionStore(&fixture, func(
		context.Context,
		DirectSAMLSessionRevalidationCommand,
	) (DirectSAMLSessionRevalidationResult, error) {
		return DirectSAMLSessionRevalidationResult{}, nil
	})
	issuer := directSAMLSessionIssuer(&fixture, nil)
	options := DirectSAMLSessionAuthorityOptions{
		Store: store, Credentials: issuer, Now: func() time.Time { return fixture.now },
		OperationTimeout: time.Second, RecoveryTimeout: 25 * time.Millisecond,
	}
	for name, mutate := range map[string]func(*DirectSAMLSessionAuthorityOptions){
		"store":             func(value *DirectSAMLSessionAuthorityOptions) { value.Store = nil },
		"credentials":       func(value *DirectSAMLSessionAuthorityOptions) { value.Credentials = nil },
		"operation timeout": func(value *DirectSAMLSessionAuthorityOptions) { value.OperationTimeout = time.Nanosecond },
		"recovery timeout":  func(value *DirectSAMLSessionAuthorityOptions) { value.RecoveryTimeout = time.Nanosecond },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := options
			mutate(&candidate)
			if service, err := NewDirectSAMLSessionAuthority(candidate); !errors.Is(err, ErrInvalidOptions) || service != nil {
				t.Fatalf("NewDirectSAMLSessionAuthority() = %v, %v", service, err)
			}
		})
	}
}

func newDirectSAMLSessionFixture() directSAMLSessionFixture {
	now := time.Date(2026, time.August, 30, 12, 0, 0, 123_000_000, time.UTC)
	providerID := testID(4)
	externalIdentityID := testID(5)
	floorID := testID(21)
	providerEvidenceID := testID(30)
	providerExpiry := now.Add(20 * time.Minute)
	stepUp := &TOTPSelection{FactorID: testID(40), Revision: 15}
	metadataDigest := [sha256.Size]byte{1, 2, 3}
	configurationDigest := [sha256.Size]byte{4, 5, 6}
	snapshot := DirectSAMLSessionRevalidationSnapshot{
		Session: DirectSAMLSessionState{
			SessionID: testID(1), RotationFamilyID: testID(2), UserID: testID(3),
			Authority: DirectSAMLSessionAuthority, AuthenticationMethod: DirectSAMLSessionMethod,
			Audience: DirectSAMLSessionAudience, PrimaryKind: DirectSAMLSessionPrimaryKind,
			SAMLStateCount: 1, SAMLProvenanceCount: 1, OIDCStateCount: 0,
			TenantProvenanceCount: 0, ProviderEvidenceCount: 1, TOTPEvidenceCount: 0,
			CurrentVersion: 4, UserAuthenticationRevision: 10,
			IssuedAt: now.Add(-5 * time.Minute), IdleExpiresAt: now.Add(15 * time.Minute),
			AbsoluteExpiresAt: now.Add(time.Hour), Active: true, RotationFamilyLive: true,
		},
		Authority: DirectSAMLSessionAuthorityFacts{
			ProviderID: providerID, ExternalIdentityID: externalIdentityID,
			ProviderKind: DirectSAMLSessionProviderKind, AccountMode: DirectSAMLSessionAccountExisting,
			PinnedProviderRevision: 2, CurrentProviderRevision: 2,
			PinnedLoginPolicyRevision: 3, CurrentLoginPolicyRevision: 3,
			PinnedConfigurationRevision: 4, CurrentConfigurationRevision: 4,
			PinnedSecurityRevision: 5, CurrentSecurityRevision: 5,
			PinnedPlanRevision: 6, CurrentPlanRevision: 6,
			PinnedAssurancePolicyRevision: 7, CurrentAssurancePolicyRevision: 7,
			PinnedMetadataRevision: 8, CurrentMetadataRevision: 8,
			PinnedSPKeyRevision: 9, CurrentSPKeyRevision: 9,
			PinnedUserAuthenticationRevision: 10, CurrentUserAuthenticationRevision: 10,
			PinnedIdentityRevision: 11, CurrentIdentityRevision: 11,
			PinnedAliasKeyVersion: 12, CurrentAliasKeyVersion: 12,
			PinnedMetadataDigest: metadataDigest, CurrentMetadataDigest: metadataDigest,
			PinnedConfigurationDigest: configurationDigest, CurrentConfigurationDigest: configurationDigest,
			IdentityCurrentProviderID: providerID, IdentityCurrentUserID: testID(3),
			AliasCurrentProviderID: providerID, AliasCurrentIdentityID: externalIdentityID,
			PinnedPlatformAuthorityID: testID(20), CurrentPlatformAuthorityID: testID(20),
			PinnedPlatformAuthorityRevision: 14, CurrentPlatformAuthorityRevision: 14,
			PinnedPlatformFloorID: floorID, CurrentPlatformFloorID: floorID,
			PinnedPlatformFloorRevision: 13, CurrentPlatformFloorRevision: 13,
			ProviderEnabled: true, PlatformLoginLive: true, UserActive: true,
			IdentityLive: true, SubjectAliasLive: true, FactorEvidenceLive: true,
			EvidenceFresh: true, PolicyPinsExact: true, TrustEvidenceLive: true,
			ConfigurationLive: true, MetadataLive: true, SPKeyLive: true,
			PlatformAuthorityLive: true, PlatformFloorLive: true,
			PlatformFloor: identity.EffectiveAssuranceRequirement{
				Level:           identity.AssurancePrimary,
				PolicyRevisions: []identity.AssurancePolicyRevision{{PolicyID: floorID, Revision: 13}},
			},
			StepUpTOTP: stepUp,
		},
		Evidence: []DirectSAMLSessionEvidence{{
			ID: providerEvidenceID, UserID: testID(3), Kind: DirectSAMLSessionEvidenceProvider,
			Level: identity.AssurancePrimary, PlatformProviderID: &providerID,
			ExternalIdentityID: &externalIdentityID, AuthenticatedAt: now.Add(-10 * time.Minute),
			ExpiresAt: &providerExpiry,
		}},
		PolicyPins: []DirectSAMLSessionPolicyPin{
			{Kind: DirectSAMLSessionPolicyAssurance, ID: providerID, Revision: 7},
			{Kind: DirectSAMLSessionPolicyLogin, ID: providerID, Revision: 3},
			{Kind: DirectSAMLSessionPolicyPlatformFloor, ID: floorID, Revision: 13},
		},
	}
	return directSAMLSessionFixture{
		now: now, snapshot: snapshot,
		lookup: DirectSAMLSessionAuthorityLookup{
			SessionID: testID(1), UserID: testID(3), AuthenticationMethod: DirectSAMLSessionMethod,
			Audience: DirectSAMLSessionAudience,
			Audit: AuditContext{
				RequestID: testID(50), CorrelationID: testID(51),
				RemoteAddress: netip.MustParseAddr("192.0.2.40"), UserAgent: "session-browser/1",
			},
		},
	}
}

func directSAMLSessionService(
	t *testing.T,
	fixture *directSAMLSessionFixture,
	store DirectSAMLSessionRevalidationStore,
	issuer CredentialIssuer,
) *DirectSAMLSessionAuthorityService {
	t.Helper()
	service, err := NewDirectSAMLSessionAuthority(DirectSAMLSessionAuthorityOptions{
		Store: store, Credentials: issuer, Now: func() time.Time { return fixture.now },
		OperationTimeout: time.Second, RecoveryTimeout: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewDirectSAMLSessionAuthority() error = %v", err)
	}
	return service
}

func directSAMLSessionStore(
	fixture *directSAMLSessionFixture,
	apply func(context.Context, DirectSAMLSessionRevalidationCommand) (DirectSAMLSessionRevalidationResult, error),
) *directSAMLSessionStoreStub {
	return &directSAMLSessionStoreStub{
		load: func(_ context.Context, lookup DirectSAMLSessionRevalidationLookup) (DirectSAMLSessionRevalidationSnapshot, error) {
			if lookup.SessionID != fixture.lookup.SessionID || !lookup.ObservedAt.Equal(fixture.now) {
				return DirectSAMLSessionRevalidationSnapshot{}, errors.New("wrong lookup")
			}
			return cloneDirectSAMLSessionSnapshot(fixture.snapshot), nil
		},
		apply: apply,
		recover: func(context.Context, DirectSAMLSessionRevalidationRecoveryLookup) (DirectSAMLSessionRevalidationRecoveryResult, error) {
			return DirectSAMLSessionRevalidationRecoveryResult{}, nil
		},
		cleanup: func(context.Context, DirectSAMLSessionRevalidationCleanup) error { return nil },
	}
}

func directSAMLSessionIssuer(
	fixture *directSAMLSessionFixture,
	calls *int,
) CredentialIssuer {
	return directSAMLSessionCredentialIssuerFunc(func(request CredentialRequest) (*CredentialReservation, error) {
		if calls != nil {
			(*calls)++
		}
		switch request.Disposition {
		case ImmediateSession:
			token := opaqueCredential(72)
			csrf := opaqueCredential(73)
			session, err := mfa.NewSessionReservation(mfa.SessionMaterial{
				SessionID: testID(70), FamilyID: fixture.snapshot.Session.RotationFamilyID,
				TokenDigest: sha256.Sum256(token), CSRFDigest: sha256.Sum256(csrf),
				AuthenticationMethod: mfa.SessionAuthenticationSAML,
				IdleExpiresAt:        request.IssuedAt.Add(10 * time.Minute).Truncate(time.Millisecond),
				AbsoluteExpiresAt:    fixture.snapshot.Session.AbsoluteExpiresAt,
			}, request.IssuedAt.Truncate(time.Millisecond))
			if err != nil {
				return nil, err
			}
			return NewSessionCredentialReservation(session, token, csrf)
		case TOTPContinuation:
			receipt := opaqueCredential(74)
			continuationID := testID(71)
			digest, err := ContinuationReceiptDigest(continuationID, receipt)
			if err != nil {
				return nil, err
			}
			reservation, err := NewContinuationReservation(ContinuationMaterial{
				ContinuationID: continuationID, FactorID: request.TOTP.FactorID,
				FactorRevision: request.TOTP.Revision, ReceiptDigest: digest,
				ExpiresAt: request.IssuedAt.Add(5 * time.Minute),
			}, request.IssuedAt)
			if err != nil {
				return nil, err
			}
			return NewContinuationCredentialReservation(reservation, receipt)
		default:
			return nil, ErrAuthenticationDenied
		}
	})
}

func directSAMLSessionResult(
	command DirectSAMLSessionRevalidationCommand,
	userID identity.EntityID,
) DirectSAMLSessionRevalidationResult {
	result := DirectSAMLSessionRevalidationResult{
		Applied: true, Category: DirectSAMLSessionRevalidationSuccess,
		Decision: command.Decision, SessionID: command.SessionID, UserID: userID,
		ExpectedVersion: command.ExpectedVersion, AppliedAt: command.ObservedAt,
	}
	switch command.Decision {
	case mfa.SessionUsable:
		result.NewVersion = command.ExpectedVersion + 1
	case mfa.SessionRotate:
		result.NewSessionID = command.Session.SessionID()
	case mfa.SessionStepUp:
		result.NewVersion = command.ExpectedVersion + 1
		result.ContinuationID = command.Continuation.ContinuationID()
	}
	return result
}

func directSAMLSessionSetFloor(
	value *DirectSAMLSessionRevalidationSnapshot,
	level identity.AssuranceLevel,
	localRequired bool,
) {
	value.Authority.PlatformFloor.Level = level
	value.Authority.PlatformFloor.LocalRequired = localRequired
}

func directSAMLSessionAddTOTP(value *DirectSAMLSessionRevalidationSnapshot, now time.Time) {
	evidenceID := testID(31)
	factorID := testID(40)
	revision := uint64(15)
	authenticatedAt := now.Add(-6 * time.Minute)
	confirmedAt := now.Add(-30 * time.Minute)
	value.Evidence = append(value.Evidence, DirectSAMLSessionEvidence{
		ID: evidenceID, UserID: value.Session.UserID, Kind: DirectSAMLSessionEvidenceTOTP,
		Level: identity.AssuranceMFA, TOTPCredentialID: &factorID, FactorRevision: &revision,
		AuthenticatedAt: authenticatedAt,
	})
	value.FactorAuthorities = []DirectSAMLSessionFactorAuthority{{
		EvidenceID: evidenceID, EvidenceUserID: value.Session.UserID, TOTPCredentialID: factorID,
		PinnedSecurityRevision: revision, CurrentUserID: value.Session.UserID,
		CurrentSecurityRevision: revision, ConfirmedAt: &confirmedAt,
	}}
	value.Session.TOTPEvidenceCount = 1
}

func directSAMLSessionAddTrust(value *DirectSAMLSessionRevalidationSnapshot) {
	trustID := testID(32)
	revision := uint64(16)
	provider := &value.Evidence[0]
	provider.Level = identity.AssuranceMFA
	provider.TrustRuleID = &trustID
	provider.TrustRuleRevision = &revision
	value.TrustAuthorities = []DirectSAMLSessionTrustAuthority{{
		EvidenceID: provider.ID, TrustRuleID: trustID, PinnedRevision: revision,
		CurrentProviderID: value.Authority.ProviderID, CurrentProviderKind: DirectSAMLSessionProviderKind,
		CurrentRevision: revision, CurrentLevel: identity.AssuranceMFA, Enabled: true,
	}}
}

func TestDirectSAMLSessionOutcomeFormattingRedactsCredentials(t *testing.T) {
	fixture := newDirectSAMLSessionFixture()
	fixture.snapshot.Authority.CurrentAssurancePolicyRevision++
	fixture.snapshot.Authority.PolicyPinsExact = false
	store := directSAMLSessionStore(&fixture, func(
		_ context.Context,
		command DirectSAMLSessionRevalidationCommand,
	) (DirectSAMLSessionRevalidationResult, error) {
		return directSAMLSessionResult(command, fixture.snapshot.Session.UserID), nil
	})
	service := directSAMLSessionService(t, &fixture, store, directSAMLSessionIssuer(&fixture, nil))
	outcome, err := service.RevalidateDirectPlatformSession(context.Background(), fixture.lookup)
	if err != nil {
		t.Fatalf("RevalidateDirectPlatformSession() error = %v", err)
	}
	formatted := fmt.Sprintf("%s %#v %s", outcome.String(), outcome, outcome.Delivery.String())
	for _, secret := range [][]byte{opaqueCredential(72), opaqueCredential(73), []byte(fixture.lookup.Audit.UserAgent)} {
		if bytes.Contains([]byte(formatted), secret) {
			t.Fatalf("formatting exposed protected material: %s", formatted)
		}
	}
	outcome.Credential.Destroy()
	if err := outcome.Delivery.ConfirmBrowserDelivery(); err != nil {
		t.Fatalf("ConfirmBrowserDelivery() error = %v", err)
	}
}
