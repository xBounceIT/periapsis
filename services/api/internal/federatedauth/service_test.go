package federatedauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/modules/identity/webauthn"
)

var serviceTestNow = time.Date(2026, time.August, 25, 14, 0, 0, 0, time.UTC)

type plannerFunc func(context.Context, PlanningRequest) (AuthenticationPlan, error)

func (function plannerFunc) PlanFederatedAuthentication(ctx context.Context, request PlanningRequest) (AuthenticationPlan, error) {
	return function(ctx, request)
}

type oidcTrustFunc func(context.Context, OIDCTrustRequest) ([]identity.AssuranceEvidence, error)

func (function oidcTrustFunc) ResolveOIDCAssurance(ctx context.Context, request OIDCTrustRequest) ([]identity.AssuranceEvidence, error) {
	return function(ctx, request)
}

type applierFunc func(context.Context, ApplyRequest) (ApplyResult, error)

func (function applierFunc) ApplyFederatedAuthentication(ctx context.Context, request ApplyRequest) (ApplyResult, error) {
	return function(ctx, request)
}

type sessionStoreFunc struct {
	load  func(context.Context, SessionLookup) (SessionProjection, error)
	apply func(context.Context, SessionMutation) (SessionMutationResult, error)
}

func (store sessionStoreFunc) LoadSessionForRevalidation(ctx context.Context, lookup SessionLookup) (SessionProjection, error) {
	return store.load(ctx, lookup)
}
func (store sessionStoreFunc) ApplySessionRevalidation(ctx context.Context, mutation SessionMutation) (SessionMutationResult, error) {
	return store.apply(ctx, mutation)
}

type refreshStoreFake struct {
	snapshot    RefreshSnapshot
	claimErr    error
	claims      int
	completeErr error
	completion  RefreshCompletion
	revocations []RevocationReason
}

func (store *refreshStoreFake) ClaimRefreshRotation(context.Context, RefreshCommand, time.Time) (RefreshSnapshot, error) {
	store.claims++
	return store.snapshot, store.claimErr
}
func (store *refreshStoreFake) CompleteRefreshRotation(_ context.Context, completion RefreshCompletion) error {
	store.completion = completion
	store.completion.SuccessorToken.Ciphertext = append([]byte(nil), completion.SuccessorToken.Ciphertext...)
	return store.completeErr
}
func (store *refreshStoreFake) RevokeSessionFamily(_ context.Context, _ identity.EntityID, reason RevocationReason, _ time.Time) error {
	store.revocations = append(store.revocations, reason)
	return nil
}

type tokenProtectorFake struct {
	opened        []byte
	sealed        ProtectedToken
	err           error
	openedContext RefreshTokenContext
	sealedContext RefreshTokenContext
}

func (protector *tokenProtectorFake) OpenRefreshToken(_ context.Context, protection RefreshTokenContext, _ ProtectedToken) ([]byte, error) {
	protector.openedContext = protection
	return append([]byte(nil), protector.opened...), protector.err
}
func (protector *tokenProtectorFake) SealRefreshToken(_ context.Context, protection RefreshTokenContext, _ []byte) (ProtectedToken, error) {
	protector.sealedContext = protection
	result := protector.sealed
	result.Ciphertext = append([]byte(nil), result.Ciphertext...)
	return result, protector.err
}

func TestRotateOIDCRefreshSupportsDirectPlatformScope(t *testing.T) {
	presented := []byte("direct-platform-refresh-token")
	successor := []byte("direct-platform-successor-token")
	familyID := serviceID(72)
	providerID := serviceID(73)
	materialID := serviceID(74)
	snapshot := validRefreshSnapshotFixture(familyID, presented)
	snapshot.TenantID = identity.EntityID{}
	snapshot.EffectiveTenantID = serviceID(75)
	snapshot.MaterialID = materialID
	snapshot.Provider = identity.ProviderContext{
		Scope: identity.PlatformProviderScope, ProviderID: providerID,
	}
	snapshot.Admission = identity.TenantAdmissionContext{}
	snapshot.BindingID = identity.EntityID{}
	store := &refreshStoreFake{snapshot: snapshot}
	protector := &tokenProtectorFake{
		opened: presented, sealed: ProtectedToken{KeyVersion: 3, Ciphertext: randomServiceBytes(t, 32)},
	}
	var secretContext ClientSecretContext
	service := newServiceFixture(t, func(options *Options) {
		options.Refreshes = store
		options.TokenProtector = protector
		options.ClientSecrets = clientSecretSourceFunc(func(_ context.Context, context ClientSecretContext) ([]byte, error) {
			secretContext = context
			return []byte("direct-platform-client-secret"), nil
		})
		options.OIDCRefresh = refreshExchangerFunc(func(
			context.Context, federatedoidc.StoredRefreshExchangeRequest, time.Time,
		) (*OIDCRotation, error) {
			return &OIDCRotation{
				successor: append([]byte(nil), successor...), accessExpiresAt: serviceTestNow.Add(10 * time.Minute),
			}, nil
		})
	})
	command := RefreshCommand{
		SessionFamilyID: familyID, ExpectedGeneration: snapshot.Generation,
		ExpectedDigest: snapshot.TokenDigest,
	}
	if err := service.RotateOIDCRefresh(context.Background(), command); err != nil {
		t.Fatalf("RotateOIDCRefresh() error = %v", err)
	}
	expectedCurrent := RefreshTokenContext{
		MaterialID: materialID, SessionFamilyID: familyID, Provider: snapshot.Provider,
		Generation: snapshot.Generation,
	}
	expectedSuccessor := expectedCurrent
	expectedSuccessor.Generation++
	if protector.openedContext != expectedCurrent || protector.sealedContext != expectedSuccessor ||
		secretContext.Provider != snapshot.Provider || secretContext.Admission != (identity.TenantAdmissionContext{}) ||
		secretContext.BindingID != (identity.EntityID{}) || store.completion.TenantID != (identity.EntityID{}) ||
		store.completion.EffectiveTenantID != snapshot.EffectiveTenantID ||
		store.completion.SuccessorGeneration != expectedSuccessor.Generation {
		t.Fatalf("direct-platform context drifted: open=%+v seal=%+v secret=%+v completion=%+v",
			protector.openedContext, protector.sealedContext, secretContext, store.completion)
	}
}

func TestExecuteClaimedOIDCRefreshDoesNotReclaimDispatcherLease(t *testing.T) {
	presented := []byte("dispatcher-owned-refresh-token")
	successor := []byte("dispatcher-successor-token")
	familyID := serviceID(84)
	snapshot := validRefreshSnapshotFixture(familyID, presented)
	retainedCiphertext := snapshot.Token.Ciphertext
	store := &refreshStoreFake{snapshot: RefreshSnapshot{Category: RefreshBusy}}
	protector := &tokenProtectorFake{
		opened: presented, sealed: ProtectedToken{KeyVersion: 3, Ciphertext: randomServiceBytes(t, 32)},
	}
	service := newServiceFixture(t, func(options *Options) {
		options.Refreshes = store
		options.TokenProtector = protector
		options.ClientSecrets = clientSecretSourceFunc(func(context.Context, ClientSecretContext) ([]byte, error) {
			return []byte("dispatcher-client-secret"), nil
		})
		options.OIDCRefresh = refreshExchangerFunc(func(
			context.Context,
			federatedoidc.StoredRefreshExchangeRequest,
			time.Time,
		) (*OIDCRotation, error) {
			return &OIDCRotation{
				successor: append([]byte(nil), successor...), accessExpiresAt: serviceTestNow.Add(10 * time.Minute),
			}, nil
		})
	})
	command := RefreshCommand{
		SessionFamilyID: familyID, ExpectedGeneration: snapshot.Generation, ExpectedDigest: snapshot.TokenDigest,
	}
	if err := service.ExecuteClaimedOIDCRefresh(context.Background(), command, snapshot); err != nil {
		t.Fatalf("ExecuteClaimedOIDCRefresh() error = %v", err)
	}
	if store.claims != 0 || store.completion.Outcome != RefreshRotated ||
		store.completion.SuccessorGeneration != snapshot.Generation+1 || len(store.revocations) != 0 {
		t.Fatalf("preclaimed execution reclaimed or drifted: claims=%d completion=%+v revocations=%v",
			store.claims, store.completion, store.revocations)
	}
	if !allZero(retainedCiphertext) {
		t.Fatal("preclaimed snapshot retained transferred ciphertext")
	}
}

func TestRotateOIDCRefreshTreatsLiveDuplicateClaimAsBusyNotReuse(t *testing.T) {
	presented := []byte("busy-refresh-token")
	familyID := serviceID(85)
	command := RefreshCommand{
		SessionFamilyID: familyID, ExpectedGeneration: 7, ExpectedDigest: sha256.Sum256(presented),
	}
	store := &refreshStoreFake{snapshot: RefreshSnapshot{
		Category: RefreshBusy, SessionFamilyID: familyID,
	}}
	service := newServiceFixture(t, func(options *Options) { options.Refreshes = store })
	if err := service.RotateOIDCRefresh(context.Background(), command); !errors.Is(err, ErrRefreshRejected) {
		t.Fatalf("RotateOIDCRefresh() busy error = %v", err)
	}
	if store.claims != 1 || len(store.revocations) != 0 || store.completion.Outcome != "" {
		t.Fatalf("busy claim mutated family: claims=%d completion=%+v revocations=%v",
			store.claims, store.completion, store.revocations)
	}
}

func TestRotateOIDCRefreshUsesAuthoritySpecificMaintenanceSecretLookup(t *testing.T) {
	presented := []byte("authority-refresh-token")
	for name, configure := range map[string]func(*RefreshSnapshot){
		"tenant": func(*RefreshSnapshot) {},
		"admitted platform": func(snapshot *RefreshSnapshot) {
			snapshot.Provider = identity.ProviderContext{
				Scope: identity.PlatformProviderScope, ProviderID: serviceID(79),
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			familyID := serviceID(80)
			snapshot := validRefreshSnapshotFixture(familyID, presented)
			configure(&snapshot)
			store := &refreshStoreFake{snapshot: snapshot}
			protector := &tokenProtectorFake{
				opened: presented, sealed: ProtectedToken{KeyVersion: 3, Ciphertext: randomServiceBytes(t, 32)},
			}
			var got ClientSecretContext
			service := newServiceFixture(t, func(options *Options) {
				options.Refreshes = store
				options.TokenProtector = protector
				options.ClientSecrets = clientSecretSourceFunc(func(
					_ context.Context,
					lookup ClientSecretContext,
				) ([]byte, error) {
					got = lookup
					return []byte("authority-client-secret"), nil
				})
				options.OIDCRefresh = refreshExchangerFunc(func(
					context.Context,
					federatedoidc.StoredRefreshExchangeRequest,
					time.Time,
				) (*OIDCRotation, error) {
					return &OIDCRotation{
						successor:       []byte("authority-successor-token"),
						accessExpiresAt: serviceTestNow.Add(10 * time.Minute),
					}, nil
				})
			})
			command := RefreshCommand{
				SessionFamilyID: familyID, ExpectedGeneration: snapshot.Generation,
				ExpectedDigest: snapshot.TokenDigest,
			}
			if err := service.RotateOIDCRefresh(context.Background(), command); err != nil {
				t.Fatalf("RotateOIDCRefresh() error = %v", err)
			}
			want := ClientSecretContext{
				Provider: snapshot.Provider, BindingID: snapshot.BindingID,
				Revision: snapshot.ClientSecretRevision,
				Maintenance: OIDCMaintenanceSecretProof{
					Kind: OIDCMaintenanceSecretRefresh, MaterialID: snapshot.MaterialID,
					SessionFamilyID: snapshot.SessionFamilyID, ClaimVersion: snapshot.Version,
					RefreshGeneration: snapshot.Generation,
				},
			}
			if snapshot.Provider.Scope == identity.PlatformProviderScope {
				want.Admission = snapshot.Admission
				want.BindingID = identity.EntityID{}
			}
			if got != want {
				t.Fatalf("maintenance client secret lookup = %+v, want %+v", got, want)
			}
		})
	}
}

func TestRefreshSnapshotScopesAndSafeCounters(t *testing.T) {
	t.Parallel()
	presented := []byte("scope-refresh-token")
	command := RefreshCommand{
		SessionFamilyID: serviceID(75), ExpectedGeneration: 7, ExpectedDigest: sha256.Sum256(presented),
	}
	tenant := validRefreshSnapshotFixture(command.SessionFamilyID, presented)
	platformAdmission := tenant
	platformAdmission.Provider = identity.ProviderContext{
		Scope: identity.PlatformProviderScope, ProviderID: serviceID(76),
	}
	direct := platformAdmission
	direct.TenantID = identity.EntityID{}
	direct.EffectiveTenantID = identity.EntityID{}
	direct.Admission = identity.TenantAdmissionContext{}
	direct.BindingID = identity.EntityID{}
	switchedDirect := direct
	switchedDirect.EffectiveTenantID = serviceID(79)
	for name, snapshot := range map[string]RefreshSnapshot{
		"tenant provider": tenant, "platform tenant admission": platformAdmission,
		"direct platform": direct, "switched direct platform": switchedDirect,
	} {
		if !validRefreshSnapshot(snapshot, command, serviceTestNow) {
			t.Fatalf("%s refresh scope rejected", name)
		}
	}
	invalid := []RefreshSnapshot{direct, platformAdmission, tenant}
	invalid[0].BindingID = serviceID(77)
	invalid[1].Admission = identity.TenantAdmissionContext{}
	invalid[2].Provider.TenantID = serviceID(78)
	for index, snapshot := range invalid {
		if validRefreshSnapshot(snapshot, command, serviceTestNow) {
			t.Fatalf("invalid scope %d accepted", index)
		}
	}
	overflow := tenant
	overflow.Generation = maximumPersistentOIDCCounter
	overflowCommand := command
	overflowCommand.ExpectedGeneration = overflow.Generation
	if validRefreshSnapshot(overflow, overflowCommand, serviceTestNow) {
		t.Fatal("non-incrementable refresh generation accepted")
	}
	overflow = tenant
	overflow.Version = maximumPersistentOIDCCounter
	if validRefreshSnapshot(overflow, command, serviceTestNow) {
		t.Fatal("non-incrementable material version accepted")
	}
	logout := validLogoutRetryJobFixture(t, serviceID(86))
	logout.RefreshGeneration = maximumPersistentOIDCCounter
	if validLogoutJobShape(logout, logout.JobID) {
		t.Fatal("out-of-range persisted logout refresh generation accepted")
	}
}

type clientSecretSourceFunc func(context.Context, ClientSecretContext) ([]byte, error)

func (function clientSecretSourceFunc) OpenOIDCClientSecret(ctx context.Context, key ClientSecretContext) ([]byte, error) {
	return function(ctx, key)
}

type refreshExchangerFunc func(context.Context, federatedoidc.StoredRefreshExchangeRequest, time.Time) (*OIDCRotation, error)

func (function refreshExchangerFunc) ExchangeOIDCRefresh(
	ctx context.Context,
	request federatedoidc.StoredRefreshExchangeRequest,
	now time.Time,
) (*OIDCRotation, error) {
	return function(ctx, request, now)
}

type logoutStoreFake struct {
	job       LogoutRetryJob
	claimErr  error
	update    LogoutRetryUpdate
	updateErr error
}

func (store *logoutStoreFake) ClaimLogoutRetry(context.Context, identity.EntityID, time.Time) (LogoutRetryJob, error) {
	return store.job, store.claimErr
}
func (store *logoutStoreFake) CompleteLogoutRetry(_ context.Context, update LogoutRetryUpdate) error {
	store.update = update
	return store.updateErr
}

type logoutExecutorFunc func(context.Context, LogoutRetryJob) error

func (function logoutExecutorFunc) ExecuteUpstreamLogoutRetry(ctx context.Context, job LogoutRetryJob) error {
	return function(ctx, job)
}

func TestOIDCLogoutMaterialOpenerUsesAuthoritySpecificMaintenanceSecretLookup(t *testing.T) {
	for name, configure := range map[string]func(*LogoutRetryJob){
		"tenant": func(*LogoutRetryJob) {},
		"admitted platform": func(job *LogoutRetryJob) {
			job.Provider = identity.ProviderContext{
				Scope: identity.PlatformProviderScope, ProviderID: serviceID(81),
			}
		},
		"direct platform": func(job *LogoutRetryJob) {
			job.TenantID = identity.EntityID{}
			job.Provider = identity.ProviderContext{
				Scope: identity.PlatformProviderScope, ProviderID: serviceID(82),
			}
			job.Admission = identity.TenantAdmissionContext{}
			job.BindingID = identity.EntityID{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			job := validLogoutRetryJobFixture(t, serviceID(83))
			configure(&job)
			token := []byte("logout-retry-refresh-token")
			job.TokenDigest = sha256.Sum256(token)
			protector := &tokenProtectorFake{opened: token}
			var gotSecret ClientSecretContext
			opener, err := NewOIDCLogoutMaterialOpener(
				protector,
				clientSecretSourceFunc(func(
					_ context.Context,
					lookup ClientSecretContext,
				) ([]byte, error) {
					gotSecret = lookup
					return []byte("logout-maintenance-client-secret"), nil
				}),
			)
			if err != nil {
				t.Fatalf("NewOIDCLogoutMaterialOpener() error = %v", err)
			}
			material, err := opener.OpenOIDCLogoutRetry(context.Background(), job)
			if err != nil || string(material.Token) != string(token) ||
				string(material.ClientSecret) != "logout-maintenance-client-secret" {
				t.Fatalf("OpenOIDCLogoutRetry() = %s, %v", material, err)
			}
			wantToken := RefreshTokenContext{
				TenantID: job.TenantID, MaterialID: job.MaterialID, SessionFamilyID: job.SessionFamilyID,
				Provider: job.Provider, BindingID: job.BindingID, Generation: job.RefreshGeneration,
			}
			wantSecret := ClientSecretContext{
				Provider: job.Provider, BindingID: job.BindingID, Revision: job.ClientSecretRevision,
				Maintenance: OIDCMaintenanceSecretProof{
					Kind: OIDCMaintenanceSecretLogoutRetry, MaterialID: job.MaterialID,
					SessionFamilyID: job.SessionFamilyID, ClaimVersion: job.ClaimVersion,
					RefreshGeneration: job.RefreshGeneration, JobID: job.JobID, Attempt: job.Attempt,
				},
			}
			if job.Provider.Scope == identity.PlatformProviderScope {
				wantSecret.Admission = job.Admission
				wantSecret.BindingID = identity.EntityID{}
			}
			if protector.openedContext != wantToken || gotSecret != wantSecret {
				t.Fatalf("logout maintenance context drifted: token=%+v want=%+v secret=%+v want=%+v",
					protector.openedContext, wantToken, gotSecret, wantSecret)
			}
			clear(material.Token)
			clear(material.ClientSecret)
		})
	}
}

func TestApplyPasskeyCreatesSessionOrRestrictedContinuation(t *testing.T) {
	tenantID, userID := serviceID(1), serviceID(2)
	artifact := passkeyArtifact(t, tenantID, userID, identity.AssurancePrimary)
	for name, testCase := range map[string]struct {
		requirement identity.AssuranceLevel
		disposition ApplyDisposition
	}{
		"satisfied": {requirement: identity.AssurancePrimary, disposition: ApplySession},
		"step up":   {requirement: identity.AssuranceMFA, disposition: ApplyContinuation},
	} {
		t.Run(name, func(t *testing.T) {
			var applied ApplyRequest
			service := newServiceFixture(t, func(options *Options) {
				options.Planner = plannerFunc(func(context.Context, PlanningRequest) (AuthenticationPlan, error) {
					return passkeyPlan(tenantID, userID, testCase.requirement), nil
				})
				options.Applier = applierFunc(func(_ context.Context, request ApplyRequest) (ApplyResult, error) {
					applied = request
					result := ApplyResult{Category: ApplySuccess, UserID: userID}
					if request.Disposition == ApplySession {
						result.SessionID = request.Session.SessionID()
					} else {
						result.ContinuationID = request.Continuation.ContinuationID()
					}
					return result, nil
				})
			})
			result, err := service.ApplyPasskey(context.Background(), tenantID, artifact)
			if err != nil || result.Category != ApplySuccess || applied.Disposition != testCase.disposition ||
				applied.Authentication.Method != AuthenticationMethodPasskey ||
				applied.Authentication.Passkey == nil || applied.Authentication.Passkey.UserID != userID {
				t.Fatalf("ApplyPasskey() = %+v, %v, applied=%+v", result, err, applied)
			}
		})
	}
}

func TestOIDCEvidenceAlwaysRetainsPrimaryProvenance(t *testing.T) {
	tenantID := serviceID(60)
	provider := identity.ProviderContext{
		Scope: identity.TenantProviderScope, TenantID: tenantID, ProviderID: serviceID(61),
	}
	bindingID := serviceID(62)
	authenticatedAt := serviceTestNow.Add(-10 * time.Minute)
	validUntil := serviceTestNow.Add(time.Hour)
	staleExpiry := serviceTestNow.Add(-time.Minute)
	expectedStaleExpiry := staleExpiry
	trustRevision := int64(9)
	trusted := []identity.AssuranceEvidence{{
		Level: identity.AssuranceMFA, Kind: identity.AssuranceEvidenceFactor,
		Source:          identity.AssuranceSource{ProviderID: provider.ProviderID, BindingID: bindingID},
		AuthenticatedAt: authenticatedAt, ExpiresAt: &staleExpiry, TrustRuleRevision: &trustRevision,
	}}
	evidence, ok := oidcEvidenceWithPrimary(
		provider, bindingID, authenticatedAt, validUntil, 7, trusted,
	)
	if !ok || len(evidence) != 2 || evidence[0].Level != identity.AssurancePrimary ||
		evidence[0].TrustRuleRevision == nil || *evidence[0].TrustRuleRevision != 7 ||
		evidence[0].ExpiresAt == nil || !evidence[0].ExpiresAt.Equal(validUntil) ||
		evidence[1].ExpiresAt == nil || !evidence[1].ExpiresAt.Equal(staleExpiry) {
		t.Fatalf("OIDC evidence = %+v, ok=%t", evidence, ok)
	}
	*trusted[0].ExpiresAt = serviceTestNow.Add(30 * time.Minute)
	*trusted[0].TrustRuleRevision = 10
	if !evidence[1].ExpiresAt.Equal(expectedStaleExpiry) || *evidence[1].TrustRuleRevision != 9 {
		t.Fatal("OIDC evidence retained caller-owned pointers")
	}
}

func TestPlanAndApplyAcceptsOnlyCollisionSafeFirstJITShape(t *testing.T) {
	tenantID := serviceID(70)
	provider := identity.ProviderContext{Scope: identity.TenantProviderScope, TenantID: tenantID, ProviderID: serviceID(71)}
	bindingID := serviceID(72)
	evidence, ok := providerPrimaryEvidence(provider, bindingID, serviceTestNow.Add(-time.Minute), serviceTestNow.Add(time.Hour), 3)
	if !ok {
		t.Fatal("primary evidence fixture rejected")
	}
	projection := AuthenticationProjection{
		Protocol: ProtocolOIDC, TenantID: tenantID,
		Subject:         ExternalSubject{Provider: provider, BindingID: bindingID, Issuer: "https://issuer.example", Value: "opaque-subject"},
		AuthenticatedAt: serviceTestNow.Add(-time.Minute), ValidUntil: serviceTestNow.Add(time.Hour),
		Evidence:       []identity.AssuranceEvidence{evidence},
		OIDCCompletion: oidcCompletionFixture(provider, bindingID, "/first-jit"),
	}
	basePlan := AuthenticationPlan{
		PlanRevision: 1, TenantID: tenantID, PolicyRevision: 1,
		ProviderRevision: 2, BindingRevision: 7, ConfigurationRevision: 3,
		SecurityRevision: 3, MappingRevision: 4, AuthorizationRevision: 5,
		Subject: protectedFederatedSubjectFixture(serviceID(86)),
		Mapping: oidcMappingPlanFixture(t, tenantID, provider, bindingID),
		Requirement: identity.EffectiveAssuranceRequirement{
			Level:           identity.AssurancePrimary,
			PolicyRevisions: []identity.AssurancePolicyRevision{{PolicyID: serviceID(73), Revision: 1}},
		},
	}
	for name, mutate := range map[string]func(*AuthenticationPlan){
		"first JIT":               func(*AuthenticationPlan) {},
		"missing user with epoch": func(plan *AuthenticationPlan) { plan.IdentityEpoch = 1 },
		"user without epoch":      func(plan *AuthenticationPlan) { plan.UserID = serviceID(74) },
		"existing user still creates identity": func(plan *AuthenticationPlan) {
			plan.UserID = serviceID(74)
			plan.IdentityEpoch = 1
		},
		"missing user omits identity creation": func(plan *AuthenticationPlan) {
			plan.Mapping = oidcExistingMappingPlanFixture(t, tenantID, provider, bindingID)
		},
	} {
		t.Run(name, func(t *testing.T) {
			plan := basePlan
			mutate(&plan)
			var applied *ApplyRequest
			service := newServiceFixture(t, func(options *Options) {
				options.Planner = plannerFunc(func(context.Context, PlanningRequest) (AuthenticationPlan, error) { return plan, nil })
				options.Applier = applierFunc(func(_ context.Context, request ApplyRequest) (ApplyResult, error) {
					copyOfRequest := request
					applied = &copyOfRequest
					return ApplyResult{
						Category: ApplySuccess, UserID: serviceID(75), SessionID: request.Session.SessionID(), ReturnPath: "/first-jit",
					}, nil
				})
			})
			_, err := service.planAndApply(context.Background(), projection)
			if name == "first JIT" {
				if err != nil || applied == nil || applied.Authentication.Method != AuthenticationMethodOIDC {
					t.Fatalf("first JIT = %v, applied=%v", err, applied)
				}
			} else if !errors.Is(err, ErrAuthentication) || applied != nil {
				t.Fatalf("malformed JIT = %v, applied=%v", err, applied)
			}
		})
	}
}

func TestPlanAndApplyConvergesAfterConcurrentFirstJITCollision(t *testing.T) {
	tenantID := serviceID(95)
	provider := identity.ProviderContext{
		Scope: identity.TenantProviderScope, TenantID: tenantID, ProviderID: serviceID(96),
	}
	bindingID := serviceID(97)
	evidence, ok := providerPrimaryEvidence(
		provider, bindingID, serviceTestNow.Add(-time.Minute), serviceTestNow.Add(time.Hour), 3,
	)
	if !ok {
		t.Fatal("primary evidence fixture rejected")
	}
	projection := AuthenticationProjection{
		Protocol: ProtocolOIDC, TenantID: tenantID,
		Subject: ExternalSubject{
			Provider: provider, BindingID: bindingID, Issuer: "https://issuer.example", Value: "opaque-subject",
		},
		AuthenticatedAt: serviceTestNow.Add(-time.Minute), ValidUntil: serviceTestNow.Add(time.Hour),
		Evidence:       []identity.AssuranceEvidence{evidence},
		OIDCCompletion: oidcCompletionFixture(provider, bindingID, "/converged-first-jit"),
	}
	first := AuthenticationPlan{
		PlanRevision: 1, TenantID: tenantID, PolicyRevision: 1,
		ProviderRevision: 2, BindingRevision: 7, ConfigurationRevision: 3,
		SecurityRevision: 3, MappingRevision: 4, AuthorizationRevision: 5,
		Subject: protectedFederatedSubjectFixture(serviceID(98)),
		Mapping: oidcMappingPlanFixture(t, tenantID, provider, bindingID),
		Requirement: identity.EffectiveAssuranceRequirement{
			Level:           identity.AssurancePrimary,
			PolicyRevisions: []identity.AssurancePolicyRevision{{PolicyID: serviceID(99), Revision: 1}},
		},
	}
	winnerUserID := serviceID(100)
	converged := clonePlan(first)
	converged.PlanRevision = 2
	converged.UserID = winnerUserID
	converged.IdentityEpoch = 1
	winnerSubject := protectedFederatedSubjectFixture(serviceID(101))
	winnerSubject.Aliases = append([]identity.SubjectAlias(nil), first.Subject.Aliases...)
	converged.Subject = winnerSubject
	converged.Mapping = oidcExistingMappingPlanFixture(t, tenantID, provider, bindingID)

	plannerCalls, applyCalls := 0, 0
	service := newServiceFixture(t, func(options *Options) {
		options.Planner = plannerFunc(func(context.Context, PlanningRequest) (AuthenticationPlan, error) {
			plannerCalls++
			if plannerCalls == 1 {
				return first, nil
			}
			return converged, nil
		})
		options.Applier = applierFunc(func(_ context.Context, request ApplyRequest) (ApplyResult, error) {
			applyCalls++
			if applyCalls == 1 {
				return ApplyResult{Category: ApplyCollision}, nil
			}
			if request.Plan.UserID != winnerUserID || request.Plan.IdentityEpoch != 1 ||
				request.Plan.Mapping.IdentityAction() != identity.LDAPIdentityNoChange {
				t.Fatalf("second apply did not use converged winner: %s", request)
			}
			return ApplyResult{
				Category: ApplySuccess, UserID: winnerUserID, SessionID: request.Session.SessionID(),
				ReturnPath: "/converged-first-jit",
			}, nil
		})
	})
	result, err := service.planAndApply(context.Background(), projection)
	if err != nil || result.Category != ApplySuccess || result.UserID != winnerUserID ||
		plannerCalls != 2 || applyCalls != 2 {
		t.Fatalf("planAndApply() = %s, %v plannerCalls=%d applyCalls=%d", result, err, plannerCalls, applyCalls)
	}
}

func TestPlanAndApplyConcurrentFirstJITHasOneIdentityWinner(t *testing.T) {
	tenantID := serviceID(110)
	provider := identity.ProviderContext{
		Scope: identity.TenantProviderScope, TenantID: tenantID, ProviderID: serviceID(111),
	}
	bindingID := serviceID(112)
	evidence, ok := providerPrimaryEvidence(
		provider, bindingID, serviceTestNow.Add(-time.Minute), serviceTestNow.Add(time.Hour), 3,
	)
	if !ok {
		t.Fatal("primary evidence fixture rejected")
	}
	baseProjection := AuthenticationProjection{
		Protocol: ProtocolOIDC, TenantID: tenantID,
		Subject: ExternalSubject{
			Provider: provider, BindingID: bindingID, Issuer: "https://issuer.example", Value: "opaque-subject",
		},
		AuthenticatedAt: serviceTestNow.Add(-time.Minute), ValidUntil: serviceTestNow.Add(time.Hour),
		Evidence:       []identity.AssuranceEvidence{evidence},
		OIDCCompletion: oidcCompletionFixture(provider, bindingID, "/concurrent-first-jit"),
	}
	first := AuthenticationPlan{
		PlanRevision: 1, TenantID: tenantID, PolicyRevision: 1,
		ProviderRevision: 2, BindingRevision: 7, ConfigurationRevision: 3,
		SecurityRevision: 3, MappingRevision: 4, AuthorizationRevision: 5,
		Subject: protectedFederatedSubjectFixture(serviceID(113)),
		Mapping: oidcMappingPlanFixture(t, tenantID, provider, bindingID),
		Requirement: identity.EffectiveAssuranceRequirement{
			Level:           identity.AssurancePrimary,
			PolicyRevisions: []identity.AssurancePolicyRevision{{PolicyID: serviceID(114), Revision: 1}},
		},
	}
	winnerUserID := serviceID(115)
	converged := clonePlan(first)
	converged.PlanRevision = 2
	converged.UserID = winnerUserID
	converged.IdentityEpoch = 1
	winnerSubject := protectedFederatedSubjectFixture(serviceID(116))
	winnerSubject.Aliases = append([]identity.SubjectAlias(nil), first.Subject.Aliases...)
	converged.Subject = winnerSubject
	converged.Mapping = oidcExistingMappingPlanFixture(t, tenantID, provider, bindingID)

	firstPlansReady := make(chan struct{}, 2)
	releaseFirstPlans := make(chan struct{})
	var plannerCalls atomic.Int32
	var applyCalls atomic.Int32
	var applyMu sync.Mutex
	identityCreated := false
	service := newServiceFixture(t, func(options *Options) {
		options.Planner = plannerFunc(func(context.Context, PlanningRequest) (AuthenticationPlan, error) {
			call := plannerCalls.Add(1)
			if call <= 2 {
				firstPlansReady <- struct{}{}
				<-releaseFirstPlans
				return clonePlan(first), nil
			}
			return clonePlan(converged), nil
		})
		options.Applier = applierFunc(func(_ context.Context, request ApplyRequest) (ApplyResult, error) {
			applyCalls.Add(1)
			applyMu.Lock()
			defer applyMu.Unlock()
			if request.Plan.UserID == (identity.EntityID{}) {
				if identityCreated {
					return ApplyResult{Category: ApplyCollision}, nil
				}
				identityCreated = true
			} else if request.Plan.UserID != winnerUserID {
				return ApplyResult{}, errors.New("converged apply selected wrong user")
			}
			return ApplyResult{
				Category: ApplySuccess, UserID: winnerUserID,
				SessionID:  request.Session.SessionID(),
				ReturnPath: "/concurrent-first-jit",
			}, nil
		})
	})

	type outcome struct {
		result ApplyResult
		err    error
	}
	outcomes := make(chan outcome, 2)
	for index := byte(1); index <= 2; index++ {
		projection := cloneProjection(baseProjection)
		projection.OIDCCompletion.ID[0] = index
		go func() {
			result, err := service.planAndApply(context.Background(), projection)
			outcomes <- outcome{result: result, err: err}
		}()
	}
	<-firstPlansReady
	<-firstPlansReady
	close(releaseFirstPlans)
	for range 2 {
		outcome := <-outcomes
		if outcome.err != nil || outcome.result.Category != ApplySuccess || outcome.result.UserID != winnerUserID {
			t.Fatalf("concurrent planAndApply() = %s, %v", outcome.result, outcome.err)
		}
	}
	applyMu.Lock()
	created := identityCreated
	applyMu.Unlock()
	if !created || plannerCalls.Load() != 3 || applyCalls.Load() != 3 {
		t.Fatalf("race calls: identityCreated=%t planner=%d apply=%d", created, plannerCalls.Load(), applyCalls.Load())
	}
}

func TestPlanAndApplyRejectsUnsafeFirstJITCollisionConvergence(t *testing.T) {
	tenantID := serviceID(103)
	provider := identity.ProviderContext{
		Scope: identity.TenantProviderScope, TenantID: tenantID, ProviderID: serviceID(104),
	}
	bindingID := serviceID(105)
	evidence, ok := providerPrimaryEvidence(
		provider, bindingID, serviceTestNow.Add(-time.Minute), serviceTestNow.Add(time.Hour), 3,
	)
	if !ok {
		t.Fatal("primary evidence fixture rejected")
	}
	projection := AuthenticationProjection{
		Protocol: ProtocolOIDC, TenantID: tenantID,
		Subject: ExternalSubject{
			Provider: provider, BindingID: bindingID, Issuer: "https://issuer.example", Value: "opaque-subject",
		},
		AuthenticatedAt: serviceTestNow.Add(-time.Minute), ValidUntil: serviceTestNow.Add(time.Hour),
		Evidence:       []identity.AssuranceEvidence{evidence},
		OIDCCompletion: oidcCompletionFixture(provider, bindingID, "/unsafe-convergence"),
	}
	first := AuthenticationPlan{
		PlanRevision: 1, TenantID: tenantID, PolicyRevision: 1,
		ProviderRevision: 2, BindingRevision: 7, ConfigurationRevision: 3,
		SecurityRevision: 3, MappingRevision: 4, AuthorizationRevision: 5,
		Subject: protectedFederatedSubjectFixture(serviceID(106)),
		Mapping: oidcMappingPlanFixture(t, tenantID, provider, bindingID),
		Requirement: identity.EffectiveAssuranceRequirement{
			Level:           identity.AssurancePrimary,
			PolicyRevisions: []identity.AssurancePolicyRevision{{PolicyID: serviceID(107), Revision: 1}},
		},
	}

	for name, mutate := range map[string]func(*AuthenticationPlan){
		"still creates identity": func(plan *AuthenticationPlan) {
			plan.UserID = serviceID(108)
			plan.IdentityEpoch = 1
		},
		"different subject alias": func(plan *AuthenticationPlan) {
			plan.UserID = serviceID(108)
			plan.IdentityEpoch = 1
			plan.Subject.ExternalIdentityID = serviceID(109)
			plan.Subject.Aliases[0].Digest[0] ^= 0xff
			plan.Mapping = oidcExistingMappingPlanFixture(t, tenantID, provider, bindingID)
		},
	} {
		t.Run(name, func(t *testing.T) {
			second := clonePlan(first)
			second.PlanRevision = 2
			mutate(&second)
			plannerCalls, applyCalls := 0, 0
			service := newServiceFixture(t, func(options *Options) {
				options.Planner = plannerFunc(func(context.Context, PlanningRequest) (AuthenticationPlan, error) {
					plannerCalls++
					if plannerCalls == 1 {
						return first, nil
					}
					return second, nil
				})
				options.Applier = applierFunc(func(context.Context, ApplyRequest) (ApplyResult, error) {
					applyCalls++
					return ApplyResult{Category: ApplyCollision}, nil
				})
			})
			if _, err := service.planAndApply(context.Background(), projection); !errors.Is(err, ErrAuthentication) ||
				plannerCalls != 2 || applyCalls != 1 {
				t.Fatalf("unsafe convergence = %v plannerCalls=%d applyCalls=%d", err, plannerCalls, applyCalls)
			}
		})
	}
}

func TestPlanAndApplyReplaysExactMutationAfterLostResponse(t *testing.T) {
	tenantID := serviceID(87)
	provider := identity.ProviderContext{
		Scope: identity.TenantProviderScope, TenantID: tenantID, ProviderID: serviceID(88),
	}
	bindingID := serviceID(89)
	evidence, ok := providerPrimaryEvidence(
		provider, bindingID, serviceTestNow.Add(-time.Minute), serviceTestNow.Add(time.Hour), 3,
	)
	if !ok {
		t.Fatal("primary evidence fixture rejected")
	}
	projection := AuthenticationProjection{
		Protocol: ProtocolOIDC, TenantID: tenantID,
		Subject: ExternalSubject{
			Provider: provider, BindingID: bindingID, Issuer: "https://issuer.example", Value: "opaque-subject",
		},
		AuthenticatedAt: serviceTestNow.Add(-time.Minute), ValidUntil: serviceTestNow.Add(time.Hour),
		Evidence:       []identity.AssuranceEvidence{evidence},
		OIDCCompletion: oidcCompletionFixture(provider, bindingID, "/response-loss"),
	}
	plan := AuthenticationPlan{
		PlanRevision: 1, TenantID: tenantID, PolicyRevision: 1,
		ProviderRevision: 2, BindingRevision: 7, ConfigurationRevision: 3,
		SecurityRevision: 3, MappingRevision: 4, AuthorizationRevision: 5,
		Subject: protectedFederatedSubjectFixture(serviceID(91)),
		Mapping: oidcMappingPlanFixture(t, tenantID, provider, bindingID),
		Requirement: identity.EffectiveAssuranceRequirement{
			Level:           identity.AssurancePrimary,
			PolicyRevisions: []identity.AssurancePolicyRevision{{PolicyID: serviceID(92), Revision: 1}},
		},
	}
	var first ApplyRequest
	calls := 0
	service := newServiceFixture(t, func(options *Options) {
		options.Planner = plannerFunc(func(context.Context, PlanningRequest) (AuthenticationPlan, error) {
			return plan, nil
		})
		options.Applier = applierFunc(func(_ context.Context, request ApplyRequest) (ApplyResult, error) {
			calls++
			if calls == 1 {
				first = cloneApplyRequest(request)
				request.Plan.Subject.Envelope.Ciphertext[0] ^= 0xff
				return ApplyResult{}, errors.New("commit response lost")
			}
			if !reflect.DeepEqual(first, request) {
				t.Fatalf("apply replay diverged: first=%s second=%s", first, request)
			}
			return ApplyResult{
				Category: ApplySuccess, UserID: serviceID(93), SessionID: request.Session.SessionID(), ReturnPath: "/response-loss",
			}, nil
		})
	})
	result, err := service.planAndApply(context.Background(), projection)
	if err != nil || result.Category != ApplySuccess || calls != 2 {
		t.Fatalf("planAndApply() = %s, %v calls=%d", result, err, calls)
	}
}

func TestPlanAndApplyRejectsMismatchedEvidenceAndApplyAuthority(t *testing.T) {
	tenantID, userID := serviceID(77), serviceID(78)
	provider := identity.ProviderContext{
		Scope: identity.TenantProviderScope, TenantID: tenantID, ProviderID: serviceID(79),
	}
	bindingID := serviceID(80)
	evidence, ok := providerPrimaryEvidence(
		provider, bindingID, serviceTestNow.Add(-time.Minute), serviceTestNow.Add(time.Hour), 3,
	)
	if !ok {
		t.Fatal("primary evidence fixture rejected")
	}
	projection := AuthenticationProjection{
		Protocol: ProtocolOIDC, TenantID: tenantID,
		Subject: ExternalSubject{
			Provider: provider, BindingID: bindingID, Issuer: "https://issuer.example", Value: "opaque-subject",
		},
		AuthenticatedAt: serviceTestNow.Add(-time.Minute), ValidUntil: serviceTestNow.Add(time.Hour),
		Evidence:       []identity.AssuranceEvidence{evidence},
		OIDCCompletion: oidcCompletionFixture(provider, bindingID, "/incidents?view=mine"),
	}
	plan := AuthenticationPlan{
		PlanRevision: 1, TenantID: tenantID, UserID: userID, IdentityEpoch: 1, PolicyRevision: 1,
		ProviderRevision: 2, BindingRevision: 7, ConfigurationRevision: 3,
		SecurityRevision: 3, MappingRevision: 4, AuthorizationRevision: 5,
		Subject: protectedFederatedSubjectFixture(serviceID(87)),
		Mapping: oidcMappingPlanFixture(t, tenantID, provider, bindingID),
		Requirement: identity.EffectiveAssuranceRequirement{
			Level:           identity.AssurancePrimary,
			PolicyRevisions: []identity.AssurancePolicyRevision{{PolicyID: serviceID(81), Revision: 1}},
		},
	}

	for name, mutate := range map[string]func(*AuthenticationProjection){
		"evidence binding": func(value *AuthenticationProjection) {
			value.Evidence[0].Source.BindingID = serviceID(82)
		},
		"transaction binding": func(value *AuthenticationProjection) {
			value.OIDCCompletion.Pins.BindingID = serviceID(82)
		},
		"unsafe return path": func(value *AuthenticationProjection) {
			value.OIDCCompletion.ReturnPath = "//attacker.example"
		},
		"platform provider before platform federation": func(value *AuthenticationProjection) {
			platform := value.Subject.Provider
			platform.Scope = identity.PlatformProviderScope
			platform.TenantID = identity.EntityID{}
			value.Subject.Provider = platform
			value.OIDCCompletion.Pins.Provider = platform
		},
	} {
		t.Run(name, func(t *testing.T) {
			malformed := cloneProjection(projection)
			mutate(&malformed)
			plannerCalled := false
			service := newServiceFixture(t, func(options *Options) {
				options.Planner = plannerFunc(func(context.Context, PlanningRequest) (AuthenticationPlan, error) {
					plannerCalled = true
					return plan, nil
				})
			})
			if _, err := service.planAndApply(context.Background(), malformed); !errors.Is(err, ErrInvalidInput) || plannerCalled {
				t.Fatalf("malformed projection = %v, plannerCalled=%t", err, plannerCalled)
			}
		})
	}

	for name, result := range map[string]ApplyResult{
		"return path": {
			Category: ApplySuccess, UserID: userID, SessionID: serviceID(83), ReturnPath: "/other",
		},
		"both authorities": {
			Category: ApplySuccess, UserID: userID, SessionID: serviceID(83),
			ContinuationID: serviceID(84), ReturnPath: "/incidents?view=mine",
		},
		"wrong user": {
			Category: ApplySuccess, UserID: serviceID(85), SessionID: serviceID(83),
			ReturnPath: "/incidents?view=mine",
		},
	} {
		t.Run(name, func(t *testing.T) {
			service := newServiceFixture(t, func(options *Options) {
				options.Planner = plannerFunc(func(context.Context, PlanningRequest) (AuthenticationPlan, error) {
					return plan, nil
				})
				options.Applier = applierFunc(func(context.Context, ApplyRequest) (ApplyResult, error) {
					return result, nil
				})
			})
			if _, err := service.planAndApply(context.Background(), projection); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("malformed apply result = %v", err)
			}
		})
	}
}

func protectedFederatedSubjectFixture(externalIdentityID identity.EntityID) *ProtectedFederatedSubject {
	digest := [sha256.Size]byte{1}
	return &ProtectedFederatedSubject{
		ExternalIdentityID: externalIdentityID,
		Aliases:            []identity.SubjectAlias{{KeyVersion: 1, Digest: digest}},
		Envelope: identity.ExternalSubjectEnvelope{
			KeyVersion: 1,
			Format:     identity.UTF8ExactSubject,
			Ciphertext: make([]byte, 17),
		},
	}
}

func TestPlanAndApplyMapsCollisionStaleAndInvalidClockFailClosed(t *testing.T) {
	tenantID, userID := serviceID(10), serviceID(11)
	artifact := passkeyArtifact(t, tenantID, userID, identity.AssurancePrimary)
	for category, expected := range map[ApplyCategory]error{
		ApplyCollision: ErrIdentityCollision,
		ApplyStale:     ErrStaleConfiguration,
		ApplyReplay:    ErrAuthentication,
		ApplyDenied:    ErrAuthentication,
	} {
		t.Run(string(category), func(t *testing.T) {
			service := newServiceFixture(t, func(options *Options) {
				options.Planner = plannerFunc(func(context.Context, PlanningRequest) (AuthenticationPlan, error) {
					return passkeyPlan(tenantID, userID, identity.AssurancePrimary), nil
				})
				options.Applier = applierFunc(func(context.Context, ApplyRequest) (ApplyResult, error) {
					return ApplyResult{Category: category}, nil
				})
			})
			if _, err := service.ApplyPasskey(context.Background(), tenantID, artifact); !errors.Is(err, expected) {
				t.Fatalf("ApplyPasskey() error = %v, want %v", err, expected)
			}
		})
	}

	service := newServiceFixture(t, func(options *Options) { options.Now = func() time.Time { return time.Time{} } })
	if _, err := service.ApplyPasskey(context.Background(), tenantID, artifact); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("invalid clock error = %v", err)
	}

	applierCalled := false
	service = newServiceFixture(t, func(options *Options) {
		options.Planner = plannerFunc(func(context.Context, PlanningRequest) (AuthenticationPlan, error) {
			plan := passkeyPlan(tenantID, serviceID(99), identity.AssurancePrimary)
			return plan, nil
		})
		options.Applier = applierFunc(func(context.Context, ApplyRequest) (ApplyResult, error) {
			applierCalled = true
			return ApplyResult{}, nil
		})
	})
	if _, err := service.ApplyPasskey(context.Background(), tenantID, artifact); !errors.Is(err, ErrAuthentication) || applierCalled {
		t.Fatalf("mismatched planner identity error = %v, applierCalled=%t", err, applierCalled)
	}
}

func TestRevalidateSessionCommitsDecisionBeforeAuthority(t *testing.T) {
	snapshot, live := currentSessionProjection()
	for name, mutate := range map[string]func(*mfa.LiveSessionProjection, *SessionMutationResult){
		"usable":         func(_ *mfa.LiveSessionProjection, _ *SessionMutationResult) {},
		"identity drift": func(live *mfa.LiveSessionProjection, _ *SessionMutationResult) { live.IdentityEpoch++ },
		"policy rotate": func(live *mfa.LiveSessionProjection, _ *SessionMutationResult) {
			live.Requirement.PolicyRevisions[0].Revision++
		},
		"step up": func(live *mfa.LiveSessionProjection, _ *SessionMutationResult) {
			live.Requirement.Level = identity.AssuranceMFA
		},
	} {
		t.Run(name, func(t *testing.T) {
			caseLive := live
			caseLive.Requirement.PolicyRevisions = append([]identity.AssurancePolicyRevision(nil), live.Requirement.PolicyRevisions...)
			mutationResult := SessionMutationResult{Applied: true}
			mutate(&caseLive, &mutationResult)
			var observed SessionMutation
			service := newServiceFixture(t, func(options *Options) {
				options.Sessions = sessionStoreFunc{
					load: func(context.Context, SessionLookup) (SessionProjection, error) {
						return SessionProjection{
							Snapshot: snapshot, Live: caseLive, AuthenticationMethod: AuthenticationMethodPasskey,
						}, nil
					},
					apply: func(_ context.Context, mutation SessionMutation) (SessionMutationResult, error) {
						observed = mutation
						if mutation.Decision == mfa.SessionRotate {
							mutationResult.NewSessionID = mutation.Session.SessionID()
						}
						if mutation.Decision == mfa.SessionStepUp {
							mutationResult.ContinuationID = mutation.Continuation.ContinuationID()
						}
						return mutationResult, nil
					},
				}
			})
			result, err := service.RevalidateSession(context.Background(), SessionLookup{
				SessionID: snapshot.SessionID, TenantID: snapshot.TenantID, Audience: caseLive.Audience,
				AuthenticationMethod: AuthenticationMethodPasskey,
			})
			if err != nil || observed.SessionID != snapshot.SessionID || !mutationResult.Applied {
				t.Fatalf("RevalidateSession() = %+v, %v, mutation=%+v", result, err, observed)
			}
			if result.SessionID != snapshot.SessionID || result.TenantID != snapshot.TenantID ||
				result.UserID != snapshot.UserID || result.AuthenticationMethod != AuthenticationMethodPasskey {
				t.Fatalf("revalidation identity echo = %s", result)
			}
			switch name {
			case "usable":
				if !result.AllowAuthority || result.Decision != mfa.SessionUsable {
					t.Fatal("current session did not receive authority")
				}
			case "identity drift":
				if result.AllowAuthority || result.Decision != mfa.SessionRevoke {
					t.Fatal("identity drift retained authority")
				}
			case "policy rotate":
				if result.AllowAuthority || result.Decision != mfa.SessionRotate || result.NewSessionID == (identity.EntityID{}) {
					t.Fatal("policy rotation returned old authority")
				}
			case "step up":
				if result.AllowAuthority || result.Decision != mfa.SessionStepUp || result.ContinuationID == (identity.EntityID{}) {
					t.Fatal("step-up decision returned authority")
				}
			}
		})
	}

	service := newServiceFixture(t, func(options *Options) {
		options.Sessions = sessionStoreFunc{
			load: func(context.Context, SessionLookup) (SessionProjection, error) {
				return SessionProjection{
					Snapshot: snapshot, Live: live, AuthenticationMethod: AuthenticationMethodPasskey,
				}, nil
			},
			apply: func(context.Context, SessionMutation) (SessionMutationResult, error) {
				return SessionMutationResult{}, errors.New("commit rejected")
			},
		}
	})
	if result, err := service.RevalidateSession(context.Background(), SessionLookup{
		SessionID: snapshot.SessionID, TenantID: snapshot.TenantID, Audience: live.Audience,
		AuthenticationMethod: AuthenticationMethodPasskey,
	}); !errors.Is(err, ErrSessionRejected) || result.AllowAuthority {
		t.Fatalf("failed revalidation commit = %+v, %v", result, err)
	}

	rotatedLive := live
	rotatedLive.Requirement.PolicyRevisions = append([]identity.AssurancePolicyRevision(nil), live.Requirement.PolicyRevisions...)
	rotatedLive.Requirement.PolicyRevisions[0].Revision++
	service = newServiceFixture(t, func(options *Options) {
		options.Sessions = sessionStoreFunc{
			load: func(context.Context, SessionLookup) (SessionProjection, error) {
				return SessionProjection{
					Snapshot: snapshot, Live: rotatedLive, AuthenticationMethod: AuthenticationMethodPasskey,
				}, nil
			},
			apply: func(context.Context, SessionMutation) (SessionMutationResult, error) {
				return SessionMutationResult{
					Applied: true, NewSessionID: serviceID(33), ContinuationID: serviceID(34),
				}, nil
			},
		}
	})
	if result, err := service.RevalidateSession(context.Background(), SessionLookup{
		SessionID: snapshot.SessionID, TenantID: snapshot.TenantID, Audience: rotatedLive.Audience,
		AuthenticationMethod: AuthenticationMethodPasskey,
	}); !errors.Is(err, ErrSessionRejected) || result.AllowAuthority || result.NewSessionID != (identity.EntityID{}) {
		t.Fatalf("ambiguous revalidation authority = %+v, %v", result, err)
	}
}

func TestRotateOIDCRefreshCompletesExactSuccessorAndRevokesAmbiguity(t *testing.T) {
	familyID := serviceID(40)
	presented := []byte("presented-refresh-token")
	successor := []byte("successor-refresh-token")
	secret := randomServiceBytes(t, 32)
	command := RefreshCommand{SessionFamilyID: familyID, ExpectedGeneration: 7, ExpectedDigest: sha256.Sum256(presented)}
	store := &refreshStoreFake{snapshot: validRefreshSnapshotFixture(familyID, presented)}
	protector := &tokenProtectorFake{
		opened: presented, sealed: ProtectedToken{KeyVersion: 3, Ciphertext: randomServiceBytes(t, 32)},
	}
	service := newServiceFixture(t, func(options *Options) {
		options.Refreshes = store
		options.TokenProtector = protector
		options.ClientSecrets = clientSecretSourceFunc(func(context.Context, ClientSecretContext) ([]byte, error) {
			return append([]byte(nil), secret...), nil
		})
		options.OIDCRefresh = refreshExchangerFunc(func(_ context.Context, request federatedoidc.StoredRefreshExchangeRequest, now time.Time) (*OIDCRotation, error) {
			if request.ClientID != "oidc-client" || len(request.ClientSecret) == 0 || len(request.RefreshToken) == 0 || now != serviceTestNow {
				return nil, errors.New("invalid exchange request")
			}
			clear(request.ClientSecret)
			clear(request.RefreshToken)
			return &OIDCRotation{successor: append([]byte(nil), successor...), accessExpiresAt: now.Add(15 * time.Minute)}, nil
		})
	})
	if err := service.RotateOIDCRefresh(context.Background(), command); err != nil {
		t.Fatalf("RotateOIDCRefresh() error = %v", err)
	}
	if store.completion.SuccessorGeneration != 8 || store.completion.SuccessorDigest != sha256.Sum256(successor) ||
		store.completion.AccessExpiresAt != serviceTestNow.Add(15*time.Minute) || len(store.revocations) != 0 {
		t.Fatalf("unexpected refresh completion: %+v revocations=%v", store.completion, store.revocations)
	}

	for name, rotation := range map[string]OIDCRotation{
		"same successor": {successor: append([]byte(nil), presented...), accessExpiresAt: serviceTestNow.Add(time.Minute)},
		"expired access": {successor: []byte("another-refresh-token"), accessExpiresAt: serviceTestNow},
		"binary token":   {successor: []byte{0xff, 0xfe}, accessExpiresAt: serviceTestNow.Add(time.Minute)},
	} {
		t.Run(name, func(t *testing.T) {
			caseStore := &refreshStoreFake{snapshot: validRefreshSnapshotFixture(familyID, presented)}
			caseProtector := &tokenProtectorFake{
				opened: presented, sealed: ProtectedToken{KeyVersion: 3, Ciphertext: randomServiceBytes(t, 32)},
			}
			service := newServiceFixture(t, func(options *Options) {
				options.Refreshes = caseStore
				options.TokenProtector = caseProtector
				options.ClientSecrets = clientSecretSourceFunc(func(context.Context, ClientSecretContext) ([]byte, error) {
					return []byte("client-secret"), nil
				})
				options.OIDCRefresh = refreshExchangerFunc(func(
					context.Context, federatedoidc.StoredRefreshExchangeRequest, time.Time,
				) (*OIDCRotation, error) {
					copyRotation := rotation
					copyRotation.successor = append([]byte(nil), rotation.successor...)
					return &copyRotation, nil
				})
			})
			if err := service.RotateOIDCRefresh(context.Background(), command); !errors.Is(err, ErrRefreshRejected) ||
				len(caseStore.revocations) != 1 || caseStore.completion.SuccessorGeneration != 0 {
				t.Fatalf("malformed rotation = %v, completion=%+v revocations=%v", err, caseStore.completion, caseStore.revocations)
			}
		})
	}

	for name, configure := range map[string]func(*refreshStoreFake){
		"claim error": func(store *refreshStoreFake) { store.claimErr = errors.New("claim failed") },
		"malformed claim": func(store *refreshStoreFake) {
			store.snapshot = validRefreshSnapshotFixture(familyID, presented)
			store.snapshot.Version = 0
		},
		"provider boundary": func(store *refreshStoreFake) {
			store.snapshot = validRefreshSnapshotFixture(familyID, presented)
			store.snapshot.Provider.Scope = 0
		},
		"reuse": func(store *refreshStoreFake) { store.snapshot = RefreshSnapshot{Category: RefreshReuse} },
	} {
		t.Run(name, func(t *testing.T) {
			caseStore := &refreshStoreFake{snapshot: validRefreshSnapshotFixture(familyID, presented)}
			configure(caseStore)
			service := newServiceFixture(t, func(options *Options) { options.Refreshes = caseStore })
			if err := service.RotateOIDCRefresh(context.Background(), command); !errors.Is(err, ErrRefreshRejected) ||
				len(caseStore.revocations) != 1 {
				t.Fatalf("ambiguous refresh = %v, revocations=%v", err, caseStore.revocations)
			}
		})
	}
}

func TestOIDCRefreshClientIDUsesCanonicalUTF8Boundary(t *testing.T) {
	t.Parallel()
	if !validOIDCClientID("client-ümlaut-東京") || !validOIDCClientID(strings.Repeat("é", 256)) {
		t.Fatal("valid multibyte OIDC client ID was rejected")
	}
	for name, value := range map[string]string{
		"empty": "", "too long": strings.Repeat("é", 256) + "a",
		"space": "client id", "unicode whitespace": "client\u00a0id",
		"control": "client\u0000id", "invalid utf8": string([]byte{0xff}),
	} {
		if validOIDCClientID(value) {
			t.Fatalf("%s client ID accepted", name)
		}
	}
}

func TestRunLogoutRetryCompletesReschedulesAndDeadLetters(t *testing.T) {
	jobID := serviceID(50)
	for name, testCase := range map[string]struct {
		attempt     int
		execution   error
		disposition LogoutRetryDisposition
	}{
		"complete":   {attempt: 1, disposition: LogoutRetryComplete},
		"reschedule": {attempt: 2, execution: errors.Join(federatedoidc.ErrRevocationFailed, federatedoidc.ErrRevocationSafeToRetry), disposition: LogoutRetryReschedule},
		"ambiguous":  {attempt: 2, execution: errors.Join(federatedoidc.ErrRevocationFailed, federatedoidc.ErrRevocationAmbiguous), disposition: LogoutRetryAmbiguous},
		"rejected":   {attempt: 4, execution: errors.New("upstream rejected"), disposition: LogoutRetryRejected},
	} {
		t.Run(name, func(t *testing.T) {
			job := validLogoutRetryJobFixture(t, jobID)
			job.Attempt = testCase.attempt
			store := &logoutStoreFake{job: job}
			service := newServiceFixture(t, func(options *Options) {
				options.LogoutRetries = store
				options.LogoutExecutor = logoutExecutorFunc(func(context.Context, LogoutRetryJob) error { return testCase.execution })
			})
			err := service.RunLogoutRetry(context.Background(), jobID)
			if (testCase.execution == nil) != (err == nil) || store.update.Disposition != testCase.disposition ||
				store.update.JobID != jobID || store.update.ExpectedVersion != job.ClaimVersion {
				t.Fatalf("RunLogoutRetry() = %v, update=%+v", err, store.update)
			}
			if testCase.disposition == LogoutRetryReschedule && !store.update.NextTryAt.After(serviceTestNow) {
				t.Fatal("retry was not rescheduled in the future")
			}
		})
	}
}

func validLogoutRetryJobFixture(t *testing.T, jobID identity.EntityID) LogoutRetryJob {
	t.Helper()
	tenantID := serviceID(52)
	bindingID := serviceID(53)
	token := []byte("logout-retry-refresh-token")
	return LogoutRetryJob{
		JobID: jobID, TenantID: tenantID, MaterialID: serviceID(54), SessionFamilyID: serviceID(51),
		Attempt: 1, MaximumAttempts: 4, ClaimVersion: 3,
		LeaseExpiresAt: serviceTestNow.Add(2 * time.Minute), NotBefore: serviceTestNow,
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: tenantID, ProviderID: serviceID(55),
		},
		Admission: identity.TenantAdmissionContext{TenantID: tenantID, BindingID: bindingID},
		BindingID: bindingID, ClientSecretRevision: 2,
		ClientAuthentication: federatedoidc.ClientSecretBasic, ClientID: "logout-client",
		Endpoint: "https://idp.example.test/revoke", RefreshGeneration: 7,
		TokenDigest: sha256.Sum256(token), MaterialExpiresAt: serviceTestNow.Add(time.Hour),
		OpaqueReference: ProtectedToken{KeyVersion: 1, Ciphertext: randomServiceBytes(t, 32)},
	}
}

func TestSensitiveApplicationArtifactsAlwaysRedact(t *testing.T) {
	const canary = "application-secret-canary"
	protectedSubject := &ProtectedFederatedSubject{
		ExternalIdentityID: serviceID(63),
		Envelope: identity.ExternalSubjectEnvelope{
			KeyVersion: 1, Format: identity.UTF8ExactSubject, Ciphertext: []byte(canary),
		},
	}
	values := []any{
		NamedValue{Name: "claim", Value: canary},
		ProfileValue{Field: "email", Value: canary},
		ExternalSubject{Issuer: canary, Value: canary},
		AuthenticationProjection{Groups: []string{canary}},
		PlanningRequest{Authentication: AuthenticationProjection{Groups: []string{canary}}, Action: canary},
		*protectedSubject,
		AuthenticationPlan{Subject: protectedSubject},
		ApplyAuthenticationProjection{Protocol: ProtocolOIDC},
		ApplyRequest{Plan: AuthenticationPlan{Subject: protectedSubject}},
		OIDCTrustRequest{AMR: []string{canary}},
		ApplyResult{Category: ApplySuccess, ReturnPath: "/incidents?filter=" + canary},
		ProtectedToken{KeyVersion: 1, Ciphertext: []byte(canary)},
		RefreshSnapshot{ClientID: canary, Token: ProtectedToken{KeyVersion: 1, Ciphertext: []byte(canary)}},
		RefreshCompletion{SuccessorToken: ProtectedToken{KeyVersion: 1, Ciphertext: []byte(canary)}},
		LogoutRetryJob{Attempt: 1, OpaqueReference: ProtectedToken{KeyVersion: 1, Ciphertext: []byte(canary)}},
		OIDCRotation{successor: []byte(canary)},
	}
	encodedCanary := fmt.Sprintf("%x", []byte(canary))
	for _, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			formatted := fmt.Sprintf(format, value)
			if strings.Contains(formatted, canary) || strings.Contains(formatted, encodedCanary) {
				t.Fatalf("%T with %q leaked material: %s", value, format, formatted)
			}
		}
	}
}

func TestNewServiceAllowsCoreOIDCWithoutOptionalRefreshOrLogout(t *testing.T) {
	options := serviceOptionsFixture()
	options.Refreshes = nil
	options.TokenProtector = nil
	options.ClientSecrets = nil
	options.OIDCRefresh = nil
	options.LogoutRetries = nil
	options.LogoutExecutor = nil
	service, err := New(options)
	if err != nil {
		t.Fatalf("New() core OIDC error = %v", err)
	}
	command := RefreshCommand{SessionFamilyID: serviceID(120), ExpectedGeneration: 1}
	command.ExpectedDigest[0] = 1
	if err = service.RotateOIDCRefresh(context.Background(), command); !errors.Is(err, ErrRefreshRejected) {
		t.Fatalf("RotateOIDCRefresh() without capability error = %v", err)
	}
	if err = service.RunLogoutRetry(context.Background(), serviceID(121)); !errors.Is(err, ErrUpstreamLogoutRetry) {
		t.Fatalf("RunLogoutRetry() without capability error = %v", err)
	}

	partial := serviceOptionsFixture()
	partial.OIDCRefresh = nil
	if _, err = New(partial); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("New() partial refresh error = %v", err)
	}
	partial = serviceOptionsFixture()
	partial.LogoutExecutor = nil
	if _, err = New(partial); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("New() partial logout error = %v", err)
	}
}

func newServiceFixture(t *testing.T, mutate func(*Options)) *Service {
	t.Helper()
	options := serviceOptionsFixture()
	if mutate != nil {
		mutate(&options)
	}
	service, err := New(options)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return service
}

func serviceOptionsFixture() Options {
	tenantID, userID := serviceID(1), serviceID(2)
	return Options{
		Planner: plannerFunc(func(context.Context, PlanningRequest) (AuthenticationPlan, error) {
			return passkeyPlan(tenantID, userID, identity.AssurancePrimary), nil
		}),
		OIDCTrust: oidcTrustFunc(func(context.Context, OIDCTrustRequest) ([]identity.AssuranceEvidence, error) { return nil, nil }),
		Applier: applierFunc(func(_ context.Context, request ApplyRequest) (ApplyResult, error) {
			return ApplyResult{Category: ApplySuccess, UserID: userID, SessionID: request.Session.SessionID()}, nil
		}),
		Credentials: testApplyCredentialIssuer(),
		Sessions: sessionStoreFunc{
			load: func(context.Context, SessionLookup) (SessionProjection, error) {
				return SessionProjection{}, errors.New("unused")
			},
			apply: func(context.Context, SessionMutation) (SessionMutationResult, error) {
				return SessionMutationResult{}, errors.New("unused")
			},
		},
		Refreshes:      &refreshStoreFake{},
		TokenProtector: &tokenProtectorFake{err: errors.New("unused")},
		ClientSecrets: clientSecretSourceFunc(func(context.Context, ClientSecretContext) ([]byte, error) {
			return nil, errors.New("unused")
		}),
		OIDCRefresh: refreshExchangerFunc(func(context.Context, federatedoidc.StoredRefreshExchangeRequest, time.Time) (*OIDCRotation, error) {
			return nil, errors.New("unused")
		}),
		LogoutRetries: &logoutStoreFake{},
		LogoutExecutor: logoutExecutorFunc(func(context.Context, LogoutRetryJob) error {
			return errors.New("unused")
		}),
		OperationTimeout: time.Second,
		Now:              func() time.Time { return serviceTestNow },
	}
}

func passkeyArtifact(t *testing.T, tenantID, userID identity.EntityID, level identity.AssuranceLevel) webauthn.AuthenticationArtifact {
	t.Helper()
	revision := int64(1)
	return webauthn.AuthenticationArtifact{
		TenantID: tenantID, UserID: userID, CredentialVersion: 1,
		CredentialDigest: sha256.Sum256(randomServiceBytes(t, 32)),
		Evidence: identity.AssuranceEvidence{
			Level: level, Kind: identity.AssuranceEvidenceFactor, Source: identity.AssuranceSource{Local: true},
			AuthenticatedAt: serviceTestNow, FactorRevision: &revision,
		},
	}
}

func passkeyPlan(tenantID, userID identity.EntityID, level identity.AssuranceLevel) AuthenticationPlan {
	return AuthenticationPlan{
		PlanRevision: 1, TenantID: tenantID, UserID: userID, IdentityEpoch: 1, PolicyRevision: 1,
		Requirement: identity.EffectiveAssuranceRequirement{
			Level:           level,
			PolicyRevisions: []identity.AssurancePolicyRevision{{PolicyID: serviceID(90), Revision: 1}},
		},
		HasEnrollableFactor: true,
	}
}

func oidcCompletionFixture(
	provider identity.ProviderContext,
	bindingID identity.EntityID,
	returnPath string,
) *federatedoidc.TransactionCompletion {
	var transactionID federatedoidc.TransactionID
	transactionID[0] = 1
	return &federatedoidc.TransactionCompletion{
		ID: transactionID, ExpectedVersion: 2, CompletedAt: serviceTestNow, ReturnPath: returnPath,
		Pins: federatedoidc.TransactionPins{
			Provider: provider, BindingID: bindingID, ProviderRevision: 2, BindingRevision: 7,
			ConfigurationRevision: 3, SecurityRevision: 3, MappingRevision: 4,
			AuthorizationRevision: 5, AssurancePolicyRevision: 1, ClientSecretRevision: 4, DiscoveryRevision: 5,
			DiscoveryDigest: sha256.Sum256([]byte("discovery")), JWKSRevision: 6,
			JWKSDigest: sha256.Sum256([]byte("jwks")),
		},
	}
}

func oidcMappingPlanFixture(
	t *testing.T,
	tenantID identity.EntityID,
	provider identity.ProviderContext,
	bindingID identity.EntityID,
) *identity.FederatedMappingPlan {
	t.Helper()
	subject, err := identity.CanonicalUTF8Exact([]byte("opaque-subject"))
	if err != nil {
		t.Fatal(err)
	}
	defer subject.Clear()
	observation, err := identity.NewFederatedMappingObservation(identity.FederatedMappingObservationInput{
		Subject: subject, Complete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := identity.PlanFederatedMapping(observation, identity.FederatedPlanningSnapshot{
		TenantID: tenantID, Provider: provider, BindingID: bindingID,
		ConfigurationRevision: 3, RuleSetRevision: 4, AuthorizationRevision: 5,
		JITMode: identity.LDAPJITCreate, NoMatchPolicy: identity.LDAPNoMatchProviderAccessOnly,
		ProviderAccess: identity.LDAPProviderAccessState{
			SourceID: serviceID(91), AccessEpochID: serviceID(92),
		},
	})
	if err != nil || plan.Disposition() != identity.LDAPPlanAdmitted {
		t.Fatalf("PlanFederatedMapping() = %s, %v", plan, err)
	}
	return &plan
}

func oidcExistingMappingPlanFixture(
	t *testing.T,
	tenantID identity.EntityID,
	provider identity.ProviderContext,
	bindingID identity.EntityID,
) *identity.FederatedMappingPlan {
	t.Helper()
	subject, err := identity.CanonicalUTF8Exact([]byte("opaque-subject"))
	if err != nil {
		t.Fatal(err)
	}
	defer subject.Clear()
	observation, err := identity.NewFederatedMappingObservation(identity.FederatedMappingObservationInput{
		Subject: subject, Complete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := identity.PlanFederatedMapping(observation, identity.FederatedPlanningSnapshot{
		TenantID: tenantID, Provider: provider, BindingID: bindingID,
		ConfigurationRevision: 3, RuleSetRevision: 4, AuthorizationRevision: 5,
		JITMode: identity.LDAPJITCreate, NoMatchPolicy: identity.LDAPNoMatchProviderAccessOnly,
		ProviderAccess: identity.LDAPProviderAccessState{
			SourceID: serviceID(91), AccessEpochID: serviceID(92),
			ExternalIdentityExists: true, UserActive: true,
			TenantMembershipExists: true, TenantMembershipActive: true, AccessGrantLive: true,
		},
	})
	if err != nil || plan.Disposition() != identity.LDAPPlanAdmitted ||
		plan.IdentityAction() != identity.LDAPIdentityNoChange {
		t.Fatalf("PlanFederatedMapping() = %s, %v", plan, err)
	}
	return &plan
}

func currentSessionProjection() (mfa.SessionSnapshot, mfa.LiveSessionProjection) {
	tenantID, userID, primaryID := serviceID(20), serviceID(21), serviceID(26)
	revision := int64(1)
	policy := identity.AssurancePolicyRevision{PolicyID: serviceID(23), Revision: 1}
	evidence := identity.AssuranceEvidence{
		Level: identity.AssurancePrimary, Kind: identity.AssuranceEvidenceFactor,
		Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: serviceTestNow.Add(-time.Minute),
		FactorRevision: &revision,
	}
	snapshot := mfa.SessionSnapshot{
		SessionID: serviceID(24), RotationFamilyID: serviceID(25), Version: 1,
		TenantID: tenantID, UserID: userID, IdentityEpoch: 1,
		Primary: mfa.PrimaryProvenance{
			Kind: mfa.PrimaryPasskey, PrimaryID: primaryID, PrimaryRevision: 1,
			SessionInvalidationEpoch: 1, AuthenticatedAt: serviceTestNow.Add(-time.Minute),
		},
		Evidence: []mfa.SessionEvidence{{
			Reference: mfa.LocalEvidenceReference{WebAuthnCredentialID: primaryID}, Evidence: evidence,
		}},
		PolicyRevisions: []identity.AssurancePolicyRevision{policy}, IssuedAt: serviceTestNow.Add(-time.Minute),
		IdleExpiresAt: serviceTestNow.Add(time.Hour), AbsoluteExpiresAt: serviceTestNow.Add(8 * time.Hour),
	}
	live := mfa.LiveSessionProjection{
		TenantID: tenantID, UserID: userID, Audience: "api", SessionActive: true,
		RotationFamilyActive: true, UserActive: true, TenantActive: true, MembershipActive: true,
		IdentityEpoch: 1, PrimaryActive: true, PrimaryRevision: 1, SessionInvalidationEpoch: 1,
		Factors: []mfa.FactorState{{
			Reference: mfa.LocalEvidenceReference{WebAuthnCredentialID: primaryID}, Revision: 1, Active: true,
		}},
		Requirement: identity.EffectiveAssuranceRequirement{
			Level: identity.AssurancePrimary, PolicyRevisions: []identity.AssurancePolicyRevision{policy},
		},
	}
	return snapshot, live
}

func validRefreshSnapshotFixture(familyID identity.EntityID, token []byte) RefreshSnapshot {
	tenantID := serviceID(60)
	bindingID := serviceID(62)
	provider := identity.ProviderContext{Scope: identity.TenantProviderScope, TenantID: tenantID, ProviderID: serviceID(61)}
	return RefreshSnapshot{
		Category: RefreshClaimed, TenantID: tenantID, EffectiveTenantID: tenantID,
		MaterialID:      serviceID(63),
		SessionFamilyID: familyID, Generation: 7, Version: 2,
		Provider: provider, Admission: identity.TenantAdmissionContext{TenantID: tenantID, BindingID: bindingID},
		BindingID: bindingID, ClientSecretRevision: 3,
		Endpoint:             "https://idp.example.test/token",
		ClientAuthentication: federatedoidc.ClientSecretBasic, ClientID: "oidc-client",
		Token: ProtectedToken{KeyVersion: 1, Ciphertext: make([]byte, 32)}, TokenDigest: sha256.Sum256(token),
		ObservedAt: serviceTestNow, LeaseExpiresAt: serviceTestNow.Add(2 * time.Minute),
		MaterialExpiresAt:     serviceTestNow.Add(time.Hour),
		AbsoluteSessionExpiry: serviceTestNow.Add(time.Hour),
	}
}

func serviceID(value byte) identity.EntityID {
	var result identity.EntityID
	result[6] = 0x70
	result[8] = 0x80
	result[15] = value
	return result
}

func randomServiceBytes(t *testing.T, size int) []byte {
	t.Helper()
	result := make([]byte, size)
	if _, err := rand.Read(result); err != nil {
		t.Fatal(err)
	}
	return result
}
