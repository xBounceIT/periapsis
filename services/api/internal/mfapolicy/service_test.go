package mfapolicy

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

var policyTestNow = time.Date(2026, 8, 30, 12, 0, 0, 123_000_000, time.UTC)

func TestPlatformPolicyAuthorityIsDenyByDefault(t *testing.T) {
	repository := &policyRepositoryStub{}
	service := newPolicyTestService(t, repository, &policyAuthorityStub{})
	session := policyTestSession(nil)

	if _, err := service.ListPlatform(context.Background(), session, ListInput{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("list error = %v", err)
	}
	session.Permissions = []authorization.Permission{authorization.PermissionPlatformIdentityPolicyRead}
	repository.listPlatform = func(_ context.Context, params ListParams) ([]mfa.PolicyDocument, error) {
		if params.Limit != DefaultPageSize+1 || params.TenantID != uuid.Nil {
			t.Fatalf("params = %#v", params)
		}
		return nil, nil
	}
	if _, err := service.ListPlatform(context.Background(), session, ListInput{}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.PublishPlatform(context.Background(), session, policyPublishInput(platformTarget(), nil, 0)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("publish error = %v", err)
	}
}

func TestTenantPolicyRequiresExactLiveHumanAuthorityAndInjectsPathTenant(t *testing.T) {
	tenantID := policyTestID(1)
	otherTenantID := policyTestID(2)
	authority := &policyAuthorityStub{authority: policyTestAuthority(
		tenantID,
		authorization.TenantPermissionIdentityPolicyRead,
	)}
	repository := &policyRepositoryStub{}
	service := newPolicyTestService(t, repository, authority)
	session := policyTestSession(&tenantID)

	if _, err := service.ListTenant(context.Background(), session, otherTenantID, ListInput{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross-tenant error = %v", err)
	}
	if authority.calls != 0 {
		t.Fatalf("cross-tenant authority calls = %d", authority.calls)
	}

	repository.simulateTenant = func(_ context.Context, params SimulationParams) (mfa.PolicySimulation, error) {
		if params.TenantID != tenantID || params.Target.TenantID != identity.EntityID(tenantID) ||
			params.Context == nil || len(params.Context.RoleIDs) != 2 ||
			params.Context.RoleIDs[0] != identity.EntityID(policyTestID(3)) {
			t.Fatalf("params = %#v", params)
		}
		return tenantCreateSimulation(params.Target, *params.Requirement), nil
	}
	requirement := policyRequirement()
	result, err := service.SimulateTenant(context.Background(), session, tenantID, SimulationInput{
		Operation:   mfa.PolicyPublish,
		Target:      mfa.AdministrationTarget{Scope: mfa.PolicyTenantBaseline},
		Requirement: &requirement,
		Context: &mfa.PolicySimulationContext{
			RoleIDs: []identity.EntityID{identity.EntityID(policyTestID(4)), identity.EntityID(policyTestID(3))},
			Action:  "case.export",
		},
	})
	if err != nil || result.Target.TenantID != identity.EntityID(tenantID) {
		t.Fatalf("result = %#v, %v", result, err)
	}
	if authority.calls != 1 {
		t.Fatalf("authority calls = %d", authority.calls)
	}
}

func TestTenantBodyCannotSmuggleTenantOrPlatformTarget(t *testing.T) {
	tenantID := policyTestID(1)
	authority := &policyAuthorityStub{authority: policyTestAuthority(
		tenantID,
		authorization.TenantPermissionIdentityPolicyRead,
	)}
	repository := &policyRepositoryStub{}
	service := newPolicyTestService(t, repository, authority)
	session := policyTestSession(&tenantID)
	requirement := policyRequirement()
	contextValue := mfa.PolicySimulationContext{Action: "case.export"}

	for name, target := range map[string]mfa.AdministrationTarget{
		"foreign tenant": {Scope: mfa.PolicyTenantBaseline, TenantID: identity.EntityID(policyTestID(9))},
		"platform":       platformTarget(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := service.SimulateTenant(context.Background(), session, tenantID, SimulationInput{
				Operation: mfa.PolicyPublish, Target: target,
				Requirement: &requirement, Context: &contextValue,
			}); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	for name, target := range map[string]mfa.AdministrationTarget{
		"role absent from context": {
			Scope: mfa.PolicyRole, RoleID: identity.EntityID(policyTestID(40)),
		},
		"group absent from context": {
			Scope: mfa.PolicySecurityGroup, SecurityGroupID: identity.EntityID(policyTestID(41)),
		},
		"action differs from context": {
			Scope: mfa.PolicyAction, Action: "alert.export",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := service.SimulateTenant(context.Background(), session, tenantID, SimulationInput{
				Operation: mfa.PolicyPublish, Target: target,
				Requirement: &requirement, Context: &contextValue,
			}); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if repository.calls != 0 {
		t.Fatalf("repository calls = %d", repository.calls)
	}
}

func TestPublishValidatesInsideRepositoryTransactionAndOnReturn(t *testing.T) {
	repository := &policyRepositoryStub{}
	service := newPolicyTestService(t, repository, &policyAuthorityStub{})
	session := policyTestSession(nil)
	session.Permissions = []authorization.Permission{
		authorization.PermissionPlatformIdentityPolicyRead,
		authorization.PermissionPlatformIdentityPolicyManage,
	}
	input := policyPublishInput(platformTarget(), nil, 0)
	policyID := policyTestID(20)
	repository.publishPlatform = func(_ context.Context, params PublishParams) (MutationResult, error) {
		if params.CommandID != input.CommandID || !validUUIDv7(params.Audit.EventID) ||
			params.ExpectedRevision != 0 || params.ExpectedPolicyID != nil || params.ValidateResult == nil {
			t.Fatalf("params = %#v", params)
		}
		result := MutationResult{Policy: policyDocument(policyID, 1, params.Target, params.Requirement, mfa.PolicyLive)}
		validated, err := params.ValidateResult(result)
		if err != nil {
			t.Fatal(err)
		}
		return validated, nil
	}
	result, err := service.PublishPlatform(context.Background(), session, input)
	if err != nil || uuid.UUID(result.Policy.ID) != policyID || result.Policy.Revision != 1 {
		t.Fatalf("result = %#v, %v", result, err)
	}

	repository.publishPlatform = func(_ context.Context, params PublishParams) (MutationResult, error) {
		return MutationResult{Policy: policyDocument(policyID, 2, params.Target, params.Requirement, mfa.PolicyLive)}, nil
	}
	if _, err = service.PublishPlatform(context.Background(), session, input); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unbound projection error = %v", err)
	}
}

func TestReplaceReplayBindsExactPolicyRevisionAndPayload(t *testing.T) {
	policyID := policyTestID(20)
	repository := &policyRepositoryStub{}
	service := newPolicyTestService(t, repository, &policyAuthorityStub{})
	session := policyTestSession(nil)
	session.Permissions = []authorization.Permission{
		authorization.PermissionPlatformIdentityPolicyRead,
		authorization.PermissionPlatformIdentityPolicyManage,
	}
	input := policyPublishInput(platformTarget(), &policyID, 4)
	repository.publishPlatform = func(_ context.Context, params PublishParams) (MutationResult, error) {
		result := MutationResult{
			Policy:   policyDocument(policyID, 5, params.Target, params.Requirement, mfa.PolicyLive),
			Replayed: true,
		}
		return params.ValidateResult(result)
	}
	result, err := service.PublishPlatform(context.Background(), session, input)
	if err != nil || !result.Replayed || result.Policy.Revision != 5 {
		t.Fatalf("result = %#v, %v", result, err)
	}

	wrongPolicyID := policyTestID(21)
	repository.publishPlatform = func(_ context.Context, params PublishParams) (MutationResult, error) {
		return MutationResult{
			Policy:   policyDocument(wrongPolicyID, 5, params.Target, params.Requirement, mfa.PolicyLive),
			Replayed: true,
		}, nil
	}
	if _, err = service.PublishPlatform(context.Background(), session, input); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("wrong replay error = %v", err)
	}
}

func TestMutationPreservesRecoveryUnsafeCASAndReauthenticationErrors(t *testing.T) {
	repository := &policyRepositoryStub{}
	service := newPolicyTestService(t, repository, &policyAuthorityStub{})
	session := policyTestSession(nil)
	session.Permissions = []authorization.Permission{
		authorization.PermissionPlatformIdentityPolicyRead,
		authorization.PermissionPlatformIdentityPolicyManage,
	}
	input := policyPublishInput(platformTarget(), nil, 0)

	for name, repositoryError := range map[string]error{
		"recovery": ErrRecoveryUnsafe,
		"stale":    ErrPreconditionFailed,
		"reauth":   authentication.ErrForbidden,
	} {
		t.Run(name, func(t *testing.T) {
			repository.publishPlatform = func(context.Context, PublishParams) (MutationResult, error) {
				return MutationResult{}, repositoryError
			}
			_, err := service.PublishPlatform(context.Background(), session, input)
			want := repositoryError
			if errors.Is(repositoryError, authentication.ErrForbidden) {
				want = ErrForbidden
			}
			if !errors.Is(err, want) {
				t.Fatalf("error = %v, want %v", err, want)
			}
		})
	}
}

func TestPublishCandidateDeadlineMustBeFutureBeforeRepositoryCall(t *testing.T) {
	repository := &policyRepositoryStub{}
	service := newPolicyTestService(t, repository, &policyAuthorityStub{})
	session := policyTestSession(nil)
	session.Permissions = []authorization.Permission{
		authorization.PermissionPlatformIdentityPolicyRead,
		authorization.PermissionPlatformIdentityPolicyManage,
	}

	for _, deadline := range []time.Time{policyTestNow.Add(-time.Millisecond), policyTestNow} {
		input := policyPublishInput(platformTarget(), nil, 0)
		input.Requirement.EnrollmentDeadline = &deadline
		if _, err := service.PublishPlatform(context.Background(), session, input); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("deadline %s error = %v", deadline, err)
		}
		requirement := input.Requirement
		if _, err := service.SimulatePlatform(context.Background(), session, SimulationInput{
			Operation: mfa.PolicyPublish, Target: platformTarget(), Requirement: &requirement,
		}); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("simulation deadline %s error = %v", deadline, err)
		}
	}
	if repository.calls != 0 {
		t.Fatalf("repository calls = %d", repository.calls)
	}
}

func TestListRejectsMalformedOrOutOfOrderRepositoryProjection(t *testing.T) {
	repository := &policyRepositoryStub{}
	service := newPolicyTestService(t, repository, &policyAuthorityStub{})
	session := policyTestSession(nil)
	session.Permissions = []authorization.Permission{authorization.PermissionPlatformIdentityPolicyRead}
	firstID, secondID := policyTestID(20), policyTestID(21)
	requirement := policyRequirement()
	repository.listPlatform = func(context.Context, ListParams) ([]mfa.PolicyDocument, error) {
		return []mfa.PolicyDocument{
			policyDocument(secondID, 1, platformTarget(), requirement, mfa.PolicyLive),
			policyDocument(firstID, 1, platformTarget(), requirement, mfa.PolicyLive),
		}, nil
	}
	if _, err := service.ListPlatform(context.Background(), session, ListInput{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("out-of-order error = %v", err)
	}

	repository.listPlatform = func(context.Context, ListParams) ([]mfa.PolicyDocument, error) {
		return []mfa.PolicyDocument{policyDocument(firstID, 1, platformTarget(), requirement, mfa.PolicyRetired)}, nil
	}
	if _, err := service.ListPlatform(context.Background(), session, ListInput{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("retired leakage error = %v", err)
	}
}

type policyRepositoryStub struct {
	calls            int
	listPlatform     func(context.Context, ListParams) ([]mfa.PolicyDocument, error)
	getPlatform      func(context.Context, GetParams) (mfa.PolicyDocument, error)
	simulatePlatform func(context.Context, SimulationParams) (mfa.PolicySimulation, error)
	publishPlatform  func(context.Context, PublishParams) (MutationResult, error)
	retirePlatform   func(context.Context, RetireParams) (MutationResult, error)
	listTenant       func(context.Context, ListParams) ([]mfa.PolicyDocument, error)
	getTenant        func(context.Context, GetParams) (mfa.PolicyDocument, error)
	simulateTenant   func(context.Context, SimulationParams) (mfa.PolicySimulation, error)
	publishTenant    func(context.Context, PublishParams) (MutationResult, error)
	retireTenant     func(context.Context, RetireParams) (MutationResult, error)
}

func (stub *policyRepositoryStub) ListPlatform(ctx context.Context, params ListParams) ([]mfa.PolicyDocument, error) {
	stub.calls++
	if stub.listPlatform == nil {
		return nil, ErrUnavailable
	}
	return stub.listPlatform(ctx, params)
}
func (stub *policyRepositoryStub) GetPlatform(ctx context.Context, params GetParams) (mfa.PolicyDocument, error) {
	stub.calls++
	if stub.getPlatform == nil {
		return mfa.PolicyDocument{}, ErrUnavailable
	}
	return stub.getPlatform(ctx, params)
}
func (stub *policyRepositoryStub) SimulatePlatform(ctx context.Context, params SimulationParams) (mfa.PolicySimulation, error) {
	stub.calls++
	if stub.simulatePlatform == nil {
		return mfa.PolicySimulation{}, ErrUnavailable
	}
	return stub.simulatePlatform(ctx, params)
}
func (stub *policyRepositoryStub) PublishPlatform(ctx context.Context, params PublishParams) (MutationResult, error) {
	stub.calls++
	if stub.publishPlatform == nil {
		return MutationResult{}, ErrUnavailable
	}
	return stub.publishPlatform(ctx, params)
}
func (stub *policyRepositoryStub) RetirePlatform(ctx context.Context, params RetireParams) (MutationResult, error) {
	stub.calls++
	if stub.retirePlatform == nil {
		return MutationResult{}, ErrUnavailable
	}
	return stub.retirePlatform(ctx, params)
}
func (stub *policyRepositoryStub) ListTenant(ctx context.Context, params ListParams) ([]mfa.PolicyDocument, error) {
	stub.calls++
	if stub.listTenant == nil {
		return nil, ErrUnavailable
	}
	return stub.listTenant(ctx, params)
}
func (stub *policyRepositoryStub) GetTenant(ctx context.Context, params GetParams) (mfa.PolicyDocument, error) {
	stub.calls++
	if stub.getTenant == nil {
		return mfa.PolicyDocument{}, ErrUnavailable
	}
	return stub.getTenant(ctx, params)
}
func (stub *policyRepositoryStub) SimulateTenant(ctx context.Context, params SimulationParams) (mfa.PolicySimulation, error) {
	stub.calls++
	if stub.simulateTenant == nil {
		return mfa.PolicySimulation{}, ErrUnavailable
	}
	return stub.simulateTenant(ctx, params)
}
func (stub *policyRepositoryStub) PublishTenant(ctx context.Context, params PublishParams) (MutationResult, error) {
	stub.calls++
	if stub.publishTenant == nil {
		return MutationResult{}, ErrUnavailable
	}
	return stub.publishTenant(ctx, params)
}
func (stub *policyRepositoryStub) RetireTenant(ctx context.Context, params RetireParams) (MutationResult, error) {
	stub.calls++
	if stub.retireTenant == nil {
		return MutationResult{}, ErrUnavailable
	}
	return stub.retireTenant(ctx, params)
}

type policyAuthorityStub struct {
	calls     int
	authority authorization.TenantAuthority
	err       error
}

func (stub *policyAuthorityStub) GetTenantAuthority(
	_ context.Context,
	_ authorization.Actor,
	_ uuid.UUID,
) (authorization.TenantAuthority, error) {
	stub.calls++
	return stub.authority, stub.err
}

func newPolicyTestService(
	t *testing.T,
	repository Repository,
	authority TenantAuthorityResolver,
) *Service {
	t.Helper()
	service, err := NewService(repository, authority)
	if err != nil {
		t.Fatal(err)
	}
	next := uint32(100)
	service.newID = func() (uuid.UUID, error) {
		next++
		return policyTestID(next), nil
	}
	service.now = func() time.Time { return policyTestNow }
	return service
}

func policyTestSession(tenantID *uuid.UUID) authentication.Session {
	return authentication.Session{
		ID: policyTestID(10), User: authentication.User{ID: policyTestID(11)},
		ActiveTenantID: tenantID, AuthenticationMethod: "totp",
	}
}

func policyTestAuthority(
	tenantID uuid.UUID,
	permissions ...authorization.TenantPermission,
) authorization.TenantAuthority {
	grants := make([]authorization.ScopedPermission, len(permissions))
	for index, permission := range permissions {
		grants[index] = authorization.ScopedPermission{Permission: permission, Scope: authorization.ScopeTenant}
	}
	return authorization.TenantAuthority{
		TenantID:     tenantID,
		Principal:    authorization.TenantPrincipal{ID: policyTestID(11), Kind: authorization.PrincipalKindHuman},
		MembershipID: policyTestID(12), MembershipStatus: authorization.MembershipStatusActive,
		LegacyRole:  authorization.LegacyMembershipRoleTenantAdmin,
		Permissions: grants, EvaluatedAt: policyTestNow,
	}
}

func policyPublishInput(
	target mfa.AdministrationTarget,
	policyID *uuid.UUID,
	revision int64,
) PublishInput {
	return PublishInput{
		CommandID: policyTestID(30), Target: target, ExpectedPolicyID: policyID,
		ExpectedRevision: revision, Requirement: policyRequirement(), Reason: "Publish the explicit MFA floor.",
		Event: authentication.EventContext{
			RequestID: policyTestID(31), CorrelationID: policyTestID(32),
			RemoteAddress: netip.MustParseAddr("192.0.2.10"), UserAgent: "mfapolicy-test",
		},
	}
}

func policyRequirement() mfa.PolicyRequirement {
	return mfa.PolicyRequirement{
		Level: identity.AssuranceMFA, LocalRequired: true, Freshness: 5 * time.Minute,
	}
}

func platformTarget() mfa.AdministrationTarget {
	return mfa.AdministrationTarget{Scope: mfa.PolicyPlatformFloor}
}

func policyDocument(
	id uuid.UUID,
	revision int64,
	target mfa.AdministrationTarget,
	requirement mfa.PolicyRequirement,
	status mfa.PolicyStatus,
) mfa.PolicyDocument {
	document := mfa.PolicyDocument{
		ID: identity.EntityID(id), Revision: revision, Target: target,
		Requirement: requirement, Status: status, CreatedAt: policyTestNow,
	}
	if status == mfa.PolicyRetired {
		retiredAt := policyTestNow.Add(time.Minute)
		document.RetiredAt = &retiredAt
	}
	return document
}

func tenantCreateSimulation(
	target mfa.AdministrationTarget,
	requirement mfa.PolicyRequirement,
) mfa.PolicySimulation {
	contextValue := mfa.PolicySimulationContext{
		RoleIDs: []identity.EntityID{identity.EntityID(policyTestID(3)), identity.EntityID(policyTestID(4))},
		Action:  "case.export",
	}
	return mfa.PolicySimulation{
		Operation: mfa.PolicyPublish, Target: target,
		Context:   &contextValue,
		Candidate: &mfa.PolicySimulationCandidate{Target: target, Requirement: requirement},
		Effective: mfa.PolicyEffectiveSimulation{
			Requirement: &requirement,
			Sources: []mfa.PolicySimulationSource{{
				Source: mfa.PolicySimulationCandidateSource, Target: target, Requirement: requirement,
			}},
		},
		Recovery: mfa.PolicyRecoverySafety{
			Safe: true, EligibleDirectAdministrators: 1, ReadyDirectAdministrators: 1,
		},
	}
}

func policyTestID(value uint32) uuid.UUID {
	return uuid.MustParse("00000000-0000-7000-8000-" + formatPolicyTestID(value))
}

func formatPolicyTestID(value uint32) string {
	const digits = "0123456789abcdef"
	result := []byte("000000000000")
	for index := len(result) - 1; value > 0; index-- {
		result[index] = digits[value&15]
		value >>= 4
	}
	return string(result)
}
