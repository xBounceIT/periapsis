package webhookurlpolicy

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

var serviceTestNow = time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)

func TestNewServiceRejectsNilDependencies(t *testing.T) {
	validRepository := &policyRepositoryStub{}
	validAuthority := &policyAuthorityStub{}
	var nilRepository *policyRepositoryStub
	var nilAuthority *policyAuthorityStub
	for name, dependencies := range map[string]struct {
		repository Repository
		authority  TenantAuthorityResolver
	}{
		"nil repository":       {nil, validAuthority},
		"typed nil repository": {nilRepository, validAuthority},
		"nil authority":        {validRepository, nil},
		"typed nil authority":  {validRepository, nilAuthority},
	} {
		t.Run(name, func(t *testing.T) {
			service, err := NewService(dependencies.repository, dependencies.authority)
			if !errors.Is(err, ErrUnavailable) || service != nil {
				t.Fatalf("service = %#v, error = %v", service, err)
			}
		})
	}
}

func TestGetAndDecideRequireLiveNotificationManageAndValidateTenantProjection(t *testing.T) {
	tenantID := testUUID(1000)
	current := servicePolicyFixture(t, tenantID, testUUID(1001), 1, serviceTestNow.Add(-time.Hour), defaultRules())
	repository := &policyRepositoryStub{currentValue: current}
	authority := &policyAuthorityStub{value: serviceAuthority(
		tenantID, authorization.TenantPermissionNotificationManage,
	)}
	service := newPolicyService(t, repository, authority)
	session := serviceSession(tenantID)

	got, err := service.Get(context.Background(), session, tenantID)
	if err != nil || !SamePolicy(got, current) {
		t.Fatalf("policy = %#v, error = %v", got, err)
	}
	decision, err := service.Decide(context.Background(), session, tenantID, "https://HOOKS.example/path?opaque=value")
	if err != nil || !decision.Allowed || decision.Reason != DecisionAllowedByRule {
		t.Fatalf("decision = %#v, error = %v", decision, err)
	}
	if repository.currentCalls.Load() != 2 || authority.calls.Load() != 2 {
		t.Fatalf("calls = repository %d, authority %d", repository.currentCalls.Load(), authority.calls.Load())
	}

	denied := newPolicyService(t, repository, &policyAuthorityStub{value: serviceAuthority(tenantID)})
	if _, err := denied.Get(context.Background(), session, tenantID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("permission error = %v", err)
	}
	foreignTenant := testUUID(1002)
	foreignSession := session
	foreignSession.ActiveTenantID = &foreignTenant
	if _, err := service.Get(context.Background(), foreignSession, tenantID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("active tenant error = %v", err)
	}
	revokedSession := session
	revoked := serviceTestNow.Add(-time.Second)
	revokedSession.RevokedAt = &revoked
	if _, err := service.Get(context.Background(), revokedSession, tenantID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked session error = %v", err)
	}

	repository.currentValue = servicePolicyFixture(
		t, foreignTenant, testUUID(1003), 1, serviceTestNow, defaultRules(),
	)
	if _, err := service.Get(context.Background(), session, tenantID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("foreign projection error = %v", err)
	}
}

func TestGetAllowsOnlyTheDatabaseClockSkewWindow(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(1050)
	repository := &policyRepositoryStub{}
	service := newPolicyService(t, repository, &policyAuthorityStub{value: serviceAuthority(
		tenantID, authorization.TenantPermissionNotificationManage,
	)})
	session := serviceSession(tenantID)

	repository.currentValue = servicePolicyFixture(
		t, tenantID, testUUID(1051), 1,
		serviceTestNow.Add(maximumProjectionClockSkew), defaultRules(),
	)
	if _, err := service.Get(context.Background(), session, tenantID); err != nil {
		t.Fatalf("policy at positive clock-skew boundary: %v", err)
	}
	repository.currentValue = servicePolicyFixture(
		t, tenantID, testUUID(1052), 1,
		serviceTestNow.Add(maximumProjectionClockSkew+time.Millisecond), defaultRules(),
	)
	if _, err := service.Get(context.Background(), session, tenantID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("policy beyond positive clock-skew boundary error = %v", err)
	}
}

func TestPublishRequiresNotificationManageAndBuildsAppendOnlyPlan(t *testing.T) {
	tenantID := testUUID(1100)
	session := serviceSession(tenantID)
	repository := &policyRepositoryStub{}
	service := newPolicyService(t, repository, &policyAuthorityStub{value: serviceAuthority(
		tenantID,
		authorization.TenantPermissionNotificationManage,
	)})
	ids := []uuid.UUID{testUUID(1101), testUUID(1102)}
	var next atomic.Uint32
	service.newID = func() (uuid.UUID, error) {
		index := next.Add(1) - 1
		if int(index) >= len(ids) {
			return uuid.Nil, errors.New("unexpected ID request")
		}
		return ids[index], nil
	}
	repository.publish = func(_ context.Context, params PublishParams) (PublishResult, error) {
		if params.TenantID != tenantID || params.Actor.UserID != session.User.ID ||
			params.PublisherMembershipID != testUUID(1202) || params.ExpectedVersion != 0 ||
			params.Command.Operation != publishPolicyOperation || params.Reason != "Enable vendor hooks" {
			t.Fatalf("params = %#v", params)
		}
		plan, err := params.BuildPlan(nil)
		if err != nil {
			return PublishResult{}, err
		}
		result := PublishResult{Policy: plan.Next(), Command: params.Command}
		if err := params.ValidateResult(result); err != nil {
			return PublishResult{}, err
		}
		return result, nil
	}

	result, err := service.Publish(context.Background(), session, tenantID, publishInput(0, "policy-create-key-0001"))
	if err != nil || result.Replayed || result.Policy.Version() != 1 || result.Policy.VersionID() != ids[0] ||
		result.Policy.ID() != ids[1] || result.Policy.TenantID() != tenantID ||
		result.Policy.PublishedByMembershipID() != testUUID(1202) {
		t.Fatalf("result = %#v, error = %v", result, err)
	}

	for name, permissions := range map[string][]authorization.TenantPermission{
		"settings read":   {authorization.TenantPermissionSettingsRead},
		"settings manage": {authorization.TenantPermissionSettingsManage},
		"none":            {},
	} {
		t.Run(name, func(t *testing.T) {
			denied := newPolicyService(t, repository, &policyAuthorityStub{value: serviceAuthority(tenantID, permissions...)})
			if _, err := denied.Publish(context.Background(), session, tenantID, publishInput(0, "policy-denied-key-001")); !errors.Is(err, ErrForbidden) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if repository.publishCalls.Load() != 1 {
		t.Fatalf("denied calls reached repository: %d", repository.publishCalls.Load())
	}
}

func TestPublishRejectsNonCanonicalHTTPAuditReasonsBeforeRepository(t *testing.T) {
	t.Parallel()
	tenantID := testUUID(1250)
	repository := &policyRepositoryStub{}
	service := newPolicyService(t, repository, &policyAuthorityStub{value: serviceAuthority(
		tenantID,
		authorization.TenantPermissionNotificationManage,
	)})
	for name, reason := range map[string]string{
		"leading space":  " Approved",
		"trailing space": "Approved ",
		"comma folded":   "Approved,reviewed",
		"unicode":        "Apprové",
		"control":        "Approved\trequest",
		"too long":       strings.Repeat("A", 2_049),
	} {
		t.Run(name, func(t *testing.T) {
			input := publishInput(0, "policy-invalid-reason-01")
			input.Reason = reason
			if _, err := service.Publish(
				context.Background(), serviceSession(tenantID), tenantID, input,
			); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if repository.publishCalls.Load() != 0 {
		t.Fatalf("invalid reasons reached repository: %d", repository.publishCalls.Load())
	}
}

func TestPublishExactReplayDoesNotReserveIDsOrRequireCurrentTimestamp(t *testing.T) {
	tenantID := testUUID(1300)
	original := servicePolicyFixture(
		t, tenantID, testUUID(1301), 1, serviceTestNow.Add(-time.Hour), defaultRules(),
	)
	repository := &policyRepositoryStub{publish: func(_ context.Context, params PublishParams) (PublishResult, error) {
		result := PublishResult{Policy: original, Command: params.Command, Replayed: true}
		if err := params.ValidateResult(result); err != nil {
			return PublishResult{}, err
		}
		return result, nil
	}}
	service := newPolicyService(t, repository, &policyAuthorityStub{value: serviceAuthority(
		tenantID,
		authorization.TenantPermissionNotificationManage,
	)})
	service.newID = func() (uuid.UUID, error) {
		t.Fatal("exact replay reserved an ID")
		return uuid.Nil, ErrUnavailable
	}

	result, err := service.Publish(context.Background(), serviceSession(tenantID), tenantID, publishInput(0, "policy-replay-key-001"))
	if err != nil || !result.Replayed || !SamePolicy(result.Policy, original) {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
}

func TestPublishAcceptsExactWinnerAfterLosingOptimisticCommit(t *testing.T) {
	tenantID := testUUID(1400)
	winner := servicePolicyFixture(t, tenantID, testUUID(1401), 1, serviceTestNow, defaultRules())
	repository := &policyRepositoryStub{publish: func(_ context.Context, params PublishParams) (PublishResult, error) {
		losingPlan, err := params.BuildPlan(nil)
		if err != nil {
			return PublishResult{}, err
		}
		if SamePolicy(losingPlan.Next(), winner) {
			t.Fatal("fixture did not reserve a distinct losing plan")
		}
		result := PublishResult{Policy: winner, Command: params.Command, Replayed: true}
		if err := params.ValidateResult(result); err != nil {
			return PublishResult{}, err
		}
		return result, nil
	}}
	service := newPolicyService(t, repository, &policyAuthorityStub{value: serviceAuthority(
		tenantID,
		authorization.TenantPermissionNotificationManage,
	)})

	result, err := service.Publish(
		context.Background(), serviceSession(tenantID), tenantID, publishInput(0, "policy-malicious-key-1"),
	)
	if err != nil || !result.Replayed || !SamePolicy(result.Policy, winner) {
		t.Fatalf("result = %#v, error = %v", result, err)
	}
}

func TestPublishRejectsAResultBoundToAnotherCommand(t *testing.T) {
	tenantID := testUUID(1450)
	repository := &policyRepositoryStub{publish: func(_ context.Context, params PublishParams) (PublishResult, error) {
		plan, err := params.BuildPlan(nil)
		if err != nil {
			return PublishResult{}, err
		}
		result := PublishResult{Policy: plan.Next()}
		if err := params.ValidateResult(result); err != nil {
			return PublishResult{}, err
		}
		return result, nil
	}}
	service := newPolicyService(t, repository, &policyAuthorityStub{value: serviceAuthority(
		tenantID,
		authorization.TenantPermissionNotificationManage,
	)})

	if _, err := service.Publish(
		context.Background(), serviceSession(tenantID), tenantID, publishInput(0, "policy-command-key-01"),
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v", err)
	}
}

func TestConcurrentExactPublishConvergesOnOneVersionAndOneReplay(t *testing.T) {
	tenantID := testUUID(1500)
	repository := newOptimisticPolicyRepository()
	authority := &policyAuthorityStub{value: serviceAuthority(
		tenantID,
		authorization.TenantPermissionNotificationManage,
	)}
	service := newPolicyService(t, repository, authority)
	var idCounter atomic.Uint32
	service.newID = func() (uuid.UUID, error) {
		return testUUID(1600 + idCounter.Add(1)), nil
	}
	input := publishInput(0, "policy-concurrent-key-1")
	results := make(chan PublishResult, 2)
	errorsChannel := make(chan error, 2)
	start := make(chan struct{})
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			result, err := service.Publish(context.Background(), serviceSession(tenantID), tenantID, input)
			results <- result
			errorsChannel <- err
		}()
	}
	close(start)
	group.Wait()
	close(results)
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("concurrent publish error = %v", err)
		}
	}
	var fresh, replayed int
	var winner Policy
	for result := range results {
		if result.Replayed {
			replayed++
		} else {
			fresh++
		}
		if winner.ID() == uuid.Nil {
			winner = result.Policy
		} else if !SamePolicy(winner, result.Policy) {
			t.Fatalf("concurrent callers received different policies: %#v, %#v", winner, result.Policy)
		}
	}
	if fresh != 1 || replayed != 1 || repository.effects != 1 || idCounter.Load() != 4 {
		t.Fatalf("fresh=%d replayed=%d effects=%d ids=%d", fresh, replayed, repository.effects, idCounter.Load())
	}
}

func TestPublishCommandBindingIsCanonicalAndDivergenceSensitive(t *testing.T) {
	tenantID := testUUID(1700)
	first := publishInput(0, "policy-binding-key-01")
	second := first
	second.Policy.Rules = []RuleInput{{Effect: RuleAllow, Match: RuleExact, Hostname: "HOOKS.EXAMPLE", Port: 443}}
	left, err := bindPublishCommand(tenantID, testUUID(1701), testUUID(1702), first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := bindPublishCommand(tenantID, testUUID(1701), testUUID(1702), second)
	if err != nil {
		t.Fatal(err)
	}
	if left != right {
		t.Fatalf("canonical equivalents diverged: %#v, %#v", left, right)
	}
	second.Reason = "Different reason"
	divergent, err := bindPublishCommand(tenantID, testUUID(1701), testUUID(1702), second)
	if err != nil {
		t.Fatal(err)
	}
	if divergent.KeyDigest != left.KeyDigest || divergent.RequestDigest == left.RequestDigest {
		t.Fatalf("divergent binding = %#v", divergent)
	}
	foreignScope, err := bindPublishCommand(testUUID(1703), testUUID(1701), testUUID(1702), first)
	if err != nil {
		t.Fatal(err)
	}
	foreignActor, err := bindPublishCommand(tenantID, testUUID(1704), testUUID(1702), first)
	if err != nil {
		t.Fatal(err)
	}
	if foreignScope.KeyDigest == left.KeyDigest || foreignActor.KeyDigest == left.KeyDigest {
		t.Fatal("idempotency digest was not scoped to tenant and actor")
	}
	if string(left.KeyDigest[:]) == first.IdempotencyKey || string(left.RequestDigest[:]) == first.Reason {
		t.Fatal("command binding retained raw input")
	}
}

type policyRepositoryStub struct {
	currentValue Policy
	currentErr   error
	publish      func(context.Context, PublishParams) (PublishResult, error)
	currentCalls atomic.Uint32
	publishCalls atomic.Uint32
}

func (repository *policyRepositoryStub) Current(_ context.Context, _ ReadParams) (Policy, error) {
	repository.currentCalls.Add(1)
	return repository.currentValue, repository.currentErr
}

func (repository *policyRepositoryStub) Publish(ctx context.Context, params PublishParams) (PublishResult, error) {
	repository.publishCalls.Add(1)
	if repository.publish == nil {
		return PublishResult{}, ErrRepositoryNotFound
	}
	return repository.publish(ctx, params)
}

type policyAuthorityStub struct {
	value authorization.TenantAuthority
	err   error
	calls atomic.Uint32
}

func (authority *policyAuthorityStub) GetTenantAuthority(
	_ context.Context,
	_ authorization.Actor,
	_ uuid.UUID,
) (authorization.TenantAuthority, error) {
	authority.calls.Add(1)
	return authority.value, authority.err
}

type storedPolicyCommand struct {
	binding CommandBinding
	result  PublishResult
}

type memoryPolicyRepository struct {
	guard    sync.Mutex
	current  *Policy
	commands map[[32]byte]storedPolicyCommand
	effects  int
}

type optimisticPolicyRepository struct {
	guard   sync.Mutex
	arrived atomic.Uint32
	release chan struct{}
	winner  *storedPolicyCommand
	effects int
}

func newOptimisticPolicyRepository() *optimisticPolicyRepository {
	return &optimisticPolicyRepository{release: make(chan struct{})}
}

func (repository *optimisticPolicyRepository) Current(context.Context, ReadParams) (Policy, error) {
	return Policy{}, ErrRepositoryNotFound
}

func (repository *optimisticPolicyRepository) Publish(_ context.Context, params PublishParams) (PublishResult, error) {
	plan, err := params.BuildPlan(nil)
	if err != nil {
		return PublishResult{}, err
	}
	if repository.arrived.Add(1) == 2 {
		close(repository.release)
	}
	<-repository.release

	repository.guard.Lock()
	defer repository.guard.Unlock()
	if repository.winner == nil {
		result := PublishResult{Policy: plan.Next(), Command: params.Command}
		if err := params.ValidateResult(result); err != nil {
			return PublishResult{}, err
		}
		repository.winner = &storedPolicyCommand{binding: params.Command, result: result}
		repository.effects++
		return result, nil
	}
	if repository.winner.binding.RequestDigest != params.Command.RequestDigest ||
		repository.winner.binding.KeyDigest != params.Command.KeyDigest {
		return PublishResult{}, ErrRepositoryConflict
	}
	result := repository.winner.result
	result.Replayed = true
	if err := params.ValidateResult(result); err != nil {
		return PublishResult{}, err
	}
	return result, nil
}

func newMemoryPolicyRepository() *memoryPolicyRepository {
	return &memoryPolicyRepository{commands: make(map[[32]byte]storedPolicyCommand)}
}

func (repository *memoryPolicyRepository) Current(_ context.Context, params ReadParams) (Policy, error) {
	repository.guard.Lock()
	defer repository.guard.Unlock()
	if repository.current == nil || repository.current.TenantID() != params.TenantID {
		return Policy{}, ErrRepositoryNotFound
	}
	return *repository.current, nil
}

func (repository *memoryPolicyRepository) Publish(_ context.Context, params PublishParams) (PublishResult, error) {
	repository.guard.Lock()
	defer repository.guard.Unlock()
	if stored, ok := repository.commands[params.Command.KeyDigest]; ok {
		if stored.binding.RequestDigest != params.Command.RequestDigest {
			return PublishResult{}, ErrRepositoryConflict
		}
		result := stored.result
		result.Replayed = true
		if err := params.ValidateResult(result); err != nil {
			return PublishResult{}, err
		}
		return result, nil
	}
	currentVersion := int64(0)
	var current *Policy
	if repository.current != nil {
		copy := *repository.current
		current = &copy
		currentVersion = copy.Version()
	}
	if currentVersion != params.ExpectedVersion {
		return PublishResult{}, ErrRepositoryConflict
	}
	plan, err := params.BuildPlan(current)
	if err != nil {
		return PublishResult{}, err
	}
	result := PublishResult{Policy: plan.Next(), Command: params.Command}
	if err := params.ValidateResult(result); err != nil {
		return PublishResult{}, err
	}
	copy := result.Policy
	repository.current = &copy
	repository.commands[params.Command.KeyDigest] = storedPolicyCommand{binding: params.Command, result: result}
	repository.effects++
	return result, nil
}

func newPolicyService(t *testing.T, repository Repository, authority TenantAuthorityResolver) *Service {
	t.Helper()
	service, err := NewService(repository, authority)
	if err != nil {
		t.Fatal(err)
	}
	service.clock = func() time.Time { return serviceTestNow }
	var idCounter atomic.Uint32
	service.newID = func() (uuid.UUID, error) { return testUUID(1900 + idCounter.Add(1)), nil }
	return service
}

func serviceSession(tenantID uuid.UUID) authentication.Session {
	return authentication.Session{
		ID: testUUID(1200), User: authentication.User{ID: testUUID(1201)}, ActiveTenantID: &tenantID,
		IdleExpiresAt: serviceTestNow.Add(time.Hour), AbsoluteExpiresAt: serviceTestNow.Add(2 * time.Hour),
		AuthenticationMethod: "totp",
	}
}

func serviceAuthority(tenantID uuid.UUID, permissions ...authorization.TenantPermission) authorization.TenantAuthority {
	grants := make([]authorization.ScopedPermission, len(permissions))
	for index, permission := range permissions {
		grants[index] = authorization.ScopedPermission{Permission: permission, Scope: authorization.ScopeTenant}
	}
	return authorization.TenantAuthority{
		TenantID:     tenantID,
		Principal:    authorization.TenantPrincipal{ID: testUUID(1201), Kind: authorization.PrincipalKindHuman},
		MembershipID: testUUID(1202), MembershipStatus: authorization.MembershipStatusActive,
		LegacyRole:  authorization.LegacyMembershipRoleTenantAdmin,
		Permissions: grants, EvaluatedAt: serviceTestNow,
	}
}

func publishInput(expectedVersion int64, key string) PublishInput {
	return PublishInput{
		ExpectedVersion: expectedVersion,
		Policy:          PolicyDraft{Rules: defaultRules()},
		IdempotencyKey:  key,
		Reason:          "Enable vendor hooks",
		Event: authentication.EventContext{
			RequestID: testUUID(1800), CorrelationID: testUUID(1801),
			RemoteAddress: netip.MustParseAddr("203.0.113.10"), UserAgent: "policy-test/1",
		},
	}
}

func defaultRules() []RuleInput {
	return []RuleInput{{Effect: RuleAllow, Match: RuleExact, Hostname: "hooks.example"}}
}

func servicePolicyFixture(
	t *testing.T,
	tenantID, versionID uuid.UUID,
	version int64,
	publishedAt time.Time,
	rules []RuleInput,
) Policy {
	t.Helper()
	policy, err := NewPolicy(PolicyInput{
		ID: testUUID(1990), VersionID: versionID, TenantID: tenantID, Version: version,
		Rules: rules, PublishedByMembershipID: testUUID(1202), PublishedAt: publishedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
