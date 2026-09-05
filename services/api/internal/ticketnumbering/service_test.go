package ticketnumbering

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

var numberingServiceTestNow = time.Date(2026, 9, 3, 12, 0, 0, 123_456_000, time.UTC)

func TestNewServiceRejectsNilDependencies(t *testing.T) {
	validRepository := &numberingRepositoryStub{}
	validAuthority := &numberingAuthorityStub{}
	var nilRepository *numberingRepositoryStub
	var nilAuthority *numberingAuthorityStub
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

func TestGetRequiresLiveMatchingTenantAndSettingsRead(t *testing.T) {
	tenantID := numberingTestUUID(1)
	otherTenantID := numberingTestUUID(2)
	session := numberingTestSession(tenantID)
	policy := numberingPolicyFixture(t, tenantID, kernel.AggregateCase, 1, numberingServiceTestNow.Add(-time.Hour))
	repository := &numberingRepositoryStub{
		current: func(_ context.Context, params ReadParams) (kernel.NumberingPolicy, error) {
			if params.TenantID != tenantID || params.Kind != kernel.AggregateCase ||
				params.Actor.UserID != session.User.ID || params.Actor.SessionID != session.ID ||
				params.Actor.ActiveTenantID != tenantID || params.Actor.AuthenticationMethod != "totp" {
				t.Fatalf("params = %#v", params)
			}
			return policy, nil
		},
	}
	authority := &numberingAuthorityStub{authority: numberingTestAuthority(
		tenantID, authorization.TenantPermissionSettingsRead,
	)}
	service := newNumberingTestService(t, repository, authority)
	got, err := service.Get(context.Background(), session, tenantID, kernel.AggregateCase)
	if err != nil || !kernel.SameNumberingPolicy(got, policy) {
		t.Fatalf("policy = %v, error = %v", got, err)
	}
	if repository.currentCalls != 1 || authority.calls != 1 {
		t.Fatalf("repository calls = %d, authority calls = %d", repository.currentCalls, authority.calls)
	}

	for name, invalid := range map[string]authentication.Session{
		"foreign tenant": func() authentication.Session {
			value := session
			value.ActiveTenantID = &otherTenantID
			return value
		}(),
		"revoked": func() authentication.Session {
			value := session
			revoked := numberingServiceTestNow.Add(-time.Second)
			value.RevokedAt = &revoked
			return value
		}(),
		"idle expired": func() authentication.Session {
			value := session
			value.IdleExpiresAt = numberingServiceTestNow
			return value
		}(),
		"non-v7 session": func() authentication.Session {
			value := session
			value.ID = uuid.New()
			return value
		}(),
		"unknown method": func() authentication.Session {
			value := session
			value.AuthenticationMethod = "password"
			return value
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := service.Get(context.Background(), invalid, tenantID, kernel.AggregateCase); !errors.Is(err, ErrForbidden) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if repository.currentCalls != 1 || authority.calls != 1 {
		t.Fatalf("invalid sessions reached dependencies: %d, %d", repository.currentCalls, authority.calls)
	}

	for name, permissions := range map[string][]authorization.TenantPermission{
		"manage only": {authorization.TenantPermissionSettingsManage},
		"none":        {},
	} {
		t.Run(name, func(t *testing.T) {
			denied := newNumberingTestService(t, repository, &numberingAuthorityStub{
				authority: numberingTestAuthority(tenantID, permissions...),
			})
			if _, err := denied.Get(context.Background(), session, tenantID, kernel.AggregateCase); !errors.Is(err, ErrForbidden) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if repository.currentCalls != 1 {
		t.Fatalf("denied reads reached repository: %d", repository.currentCalls)
	}
	foreignPrincipal := numberingTestAuthority(tenantID, authorization.TenantPermissionSettingsRead)
	foreignPrincipal.Principal.ID = numberingTestUUID(999)
	foreignService := newNumberingTestService(
		t, repository, &numberingAuthorityStub{authority: foreignPrincipal},
	)
	if _, err := foreignService.Get(context.Background(), session, tenantID, kernel.AggregateCase); !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign principal authority error = %v", err)
	}
	if repository.currentCalls != 1 {
		t.Fatal("foreign principal authority reached persistence")
	}

	wrongTenantPolicy := numberingPolicyFixture(t, otherTenantID, kernel.AggregateCase, 1, numberingServiceTestNow)
	repository.current = func(context.Context, ReadParams) (kernel.NumberingPolicy, error) {
		return wrongTenantPolicy, nil
	}
	if _, err := service.Get(context.Background(), session, tenantID, kernel.AggregateCase); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("wrong-tenant projection error = %v", err)
	}
	boundaryPolicy := numberingPolicyFixture(
		t, tenantID, kernel.AggregateCase, 1,
		numberingServiceTestNow.Add(maximumProjectionClockSkew),
	)
	repository.current = func(context.Context, ReadParams) (kernel.NumberingPolicy, error) {
		return boundaryPolicy, nil
	}
	if _, err := service.Get(context.Background(), session, tenantID, kernel.AggregateCase); err != nil {
		t.Fatalf("clock-skew boundary error = %v", err)
	}
	futurePolicy := numberingPolicyFixture(
		t, tenantID, kernel.AggregateCase, 1,
		numberingServiceTestNow.Add(maximumProjectionClockSkew+time.Microsecond),
	)
	repository.current = func(context.Context, ReadParams) (kernel.NumberingPolicy, error) {
		return futurePolicy, nil
	}
	if _, err := service.Get(context.Background(), session, tenantID, kernel.AggregateCase); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("future projection error = %v", err)
	}
}

func TestPreviewNormalizesSafeGrammarWithoutAllocating(t *testing.T) {
	tenantID := numberingTestUUID(10)
	repository := &numberingRepositoryStub{}
	service := newNumberingTestService(t, repository, &numberingAuthorityStub{
		authority: numberingTestAuthority(tenantID, authorization.TenantPermissionSettingsRead),
	})
	preview, err := service.Preview(
		context.Background(), numberingTestSession(tenantID), tenantID, kernel.AggregateCase,
		PolicyDraft{
			Prefix: " case ", Separator: " - ", Period: kernel.NumberingPeriodAnnual,
			Width: 6, Start: 1,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if preview.TenantID != tenantID || preview.Kind != kernel.AggregateCase ||
		preview.Prefix != "CASE" || preview.Separator != "-" || preview.PeriodKey != 2026 ||
		preview.Example != "CASE-2026-000001" || preview.MaximumSequence != 999_999 ||
		!preview.At.Equal(numberingServiceTestNow) {
		t.Fatalf("preview = %#v", preview)
	}
	if repository.currentCalls != 0 || repository.replaceCalls != 0 {
		t.Fatalf("preview touched persistence: %#v", repository)
	}

	for name, draft := range map[string]PolicyDraft{
		"separator in prefix": {Prefix: "CASE-OPS", Separator: "-", Period: kernel.NumberingPeriodAnnual, Width: 6, Start: 1},
		"unicode prefix":      {Prefix: "CАSE", Separator: "-", Period: kernel.NumberingPeriodAnnual, Width: 6, Start: 1},
		"unknown separator":   {Prefix: "CASE", Separator: ":", Period: kernel.NumberingPeriodAnnual, Width: 6, Start: 1},
		"unknown period":      {Prefix: "CASE", Separator: "-", Period: kernel.NumberingPeriod(99), Width: 6, Start: 1},
		"small width":         {Prefix: "CASE", Separator: "-", Period: kernel.NumberingPeriodAnnual, Width: 3, Start: 1},
		"exhausted start":     {Prefix: "CASE", Separator: "-", Period: kernel.NumberingPeriodAnnual, Width: 4, Start: 10_000},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := service.Preview(
				context.Background(), numberingTestSession(tenantID), tenantID,
				kernel.AggregateCase, draft,
			); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestReplaceRequiresExactDualPermissionAndBuildsImmutablePlan(t *testing.T) {
	tenantID := numberingTestUUID(20)
	session := numberingTestSession(tenantID)
	current := numberingPolicyFixture(t, tenantID, kernel.AggregateCase, 7, numberingServiceTestNow.Add(-time.Hour))
	original := current
	repository := &numberingRepositoryStub{}
	authority := &numberingAuthorityStub{authority: numberingTestAuthority(
		tenantID,
		authorization.TenantPermissionSettingsRead,
		authorization.TenantPermissionSettingsManage,
	)}
	service := newNumberingTestService(t, repository, authority)
	nextVersionID := numberingTestUUID(21)
	service.newID = func() (uuid.UUID, error) { return nextVersionID, nil }
	input := numberingReplaceInput()
	input.ExpectedVersion = 7
	wantEvent := input.Event
	wantEvent.RemoteAddress = wantEvent.RemoteAddress.Unmap()
	repository.replace = func(_ context.Context, params ReplaceParams) (ReplaceResult, error) {
		if params.TenantID != tenantID || params.Kind != kernel.AggregateCase ||
			params.ExpectedVersion != 7 || params.Actor.UserID != session.User.ID ||
			params.Reason != "Approve incident numbering" || params.Audit != wantEvent ||
			params.Command.Operation != replacePolicyOperation ||
			params.Command.KeyDigest == ([32]byte{}) || params.Command.RequestDigest == ([32]byte{}) ||
			params.BuildPlan == nil || params.ValidateResult == nil {
			t.Fatalf("params = %#v", params)
		}
		plan, err := params.BuildPlan(current)
		if err != nil {
			return ReplaceResult{}, err
		}
		next := plan.Next()
		if plan.ExpectedVersion() != 7 || next.Version() != 8 ||
			uuidFromEntity(next.VersionID()) != nextVersionID || next.PublishedBy() != mustEntityID(t, numberingTestUUID(102)) ||
			next.Spec().Prefix() != "CASE" || next.Spec().Separator() != "/" ||
			next.Spec().Period() != kernel.NumberingPeriodAnnual || next.Spec().Width() != 8 ||
			next.Spec().Start() != 100 {
			t.Fatalf("plan = %v", plan.Next())
		}
		result := ReplaceResult{Policy: next}
		if err := params.ValidateResult(result); err != nil {
			return ReplaceResult{}, err
		}
		return result, nil
	}

	result, err := service.Replace(
		context.Background(), session, tenantID, kernel.AggregateCase, input,
	)
	if err != nil || result.Replayed || result.Policy.Version() != 8 ||
		result.Policy.Spec().Prefix() != "CASE" {
		t.Fatalf("result = %v, error = %v", result, err)
	}
	if !kernel.SameNumberingPolicy(current, original) {
		t.Fatal("application plan mutated the immutable current policy")
	}

	for name, permissions := range map[string][]authorization.TenantPermission{
		"read only":   {authorization.TenantPermissionSettingsRead},
		"manage only": {authorization.TenantPermissionSettingsManage},
		"neither":     {},
	} {
		t.Run(name, func(t *testing.T) {
			denied := newNumberingTestService(t, repository, &numberingAuthorityStub{
				authority: numberingTestAuthority(tenantID, permissions...),
			})
			if _, err := denied.Replace(
				context.Background(), session, tenantID, kernel.AggregateCase, input,
			); !errors.Is(err, ErrForbidden) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if repository.replaceCalls != 1 {
		t.Fatalf("denied writes reached repository: %d", repository.replaceCalls)
	}
}

func TestReplaceExactReplayPrecedesStaleCASAndDivergentReuseCannotValidate(t *testing.T) {
	tenantID := numberingTestUUID(30)
	session := numberingTestSession(tenantID)
	desired := numberingReplaceInput()
	firstPolicy := numberingPolicyWithSpec(
		t, numberingTestUUID(31), tenantID, kernel.AggregateCase, 2,
		PolicyDraft{Prefix: "CASE", Separator: "/", Period: kernel.NumberingPeriodAnnual, Width: 8, Start: 100},
		numberingTestUUID(102), numberingServiceTestNow.Add(-time.Minute),
	)
	repository := &numberingRepositoryStub{
		replace: func(_ context.Context, params ReplaceParams) (ReplaceResult, error) {
			result := ReplaceResult{Policy: firstPolicy, Replayed: true}
			if err := params.ValidateResult(result); err != nil {
				return ReplaceResult{}, err
			}
			return result, nil
		},
	}
	service := newNumberingTestService(t, repository, &numberingAuthorityStub{
		authority: numberingTestAuthority(
			tenantID,
			authorization.TenantPermissionSettingsRead,
			authorization.TenantPermissionSettingsManage,
		),
	})
	service.newID = func() (uuid.UUID, error) { return uuid.Nil, errors.New("entropy unavailable") }
	result, err := service.Replace(
		context.Background(), session, tenantID, kernel.AggregateCase, desired,
	)
	if err != nil || !result.Replayed || !kernel.SameNumberingPolicy(result.Policy, firstPolicy) {
		t.Fatalf("replay = %v, error = %v", result, err)
	}
	service.newID = func() (uuid.UUID, error) { return numberingTestUUID(39), nil }

	// A repository that performs CAS planning before claiming an exact replay
	// violates the callback contract and is rejected even if it labels the result
	// as replayed.
	current := numberingPolicyFixture(t, tenantID, kernel.AggregateCase, 1, numberingServiceTestNow.Add(-time.Hour))
	repository.replace = func(_ context.Context, params ReplaceParams) (ReplaceResult, error) {
		plan, err := params.BuildPlan(current)
		if err != nil {
			return ReplaceResult{}, err
		}
		result := ReplaceResult{Policy: plan.Next(), Replayed: true}
		if err := params.ValidateResult(result); err != nil {
			return ReplaceResult{}, err
		}
		return result, nil
	}
	if _, err := service.Replace(
		context.Background(), session, tenantID, kernel.AggregateCase, desired,
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("late replay error = %v", err)
	}

	// A successful return without the mandatory pre-commit validator also fails
	// closed at the application boundary.
	repository.replace = func(_ context.Context, _ ReplaceParams) (ReplaceResult, error) {
		return ReplaceResult{Policy: firstPolicy, Replayed: true}, nil
	}
	if _, err := service.Replace(
		context.Background(), session, tenantID, kernel.AggregateCase, desired,
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing validator error = %v", err)
	}

	// A replay with the wrong configuration cannot be substituted for the bound
	// command even when its coordinate and version are otherwise well formed.
	wrongPolicy := numberingPolicyWithSpec(
		t, numberingTestUUID(32), tenantID, kernel.AggregateCase, 2,
		PolicyDraft{Prefix: "INC", Separator: "-", Period: kernel.NumberingPeriodAnnual, Width: 6, Start: 1},
		numberingTestUUID(102), numberingServiceTestNow.Add(-time.Minute),
	)
	repository.replace = func(_ context.Context, params ReplaceParams) (ReplaceResult, error) {
		result := ReplaceResult{Policy: wrongPolicy, Replayed: true}
		if err := params.ValidateResult(result); err != nil {
			return ReplaceResult{}, err
		}
		return result, nil
	}
	if _, err := service.Replace(
		context.Background(), session, tenantID, kernel.AggregateCase, desired,
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("divergent replay error = %v", err)
	}
}

func TestReplaceRejectsMalformedInputsBeforeMutation(t *testing.T) {
	tenantID := numberingTestUUID(40)
	repository := &numberingRepositoryStub{}
	service := newNumberingTestService(t, repository, &numberingAuthorityStub{
		authority: numberingTestAuthority(
			tenantID,
			authorization.TenantPermissionSettingsRead,
			authorization.TenantPermissionSettingsManage,
		),
	})
	session := numberingTestSession(tenantID)
	for name, mutate := range map[string]func(*ReplaceInput){
		"zero revision":      func(value *ReplaceInput) { value.ExpectedVersion = 0 },
		"exhausted revision": func(value *ReplaceInput) { value.ExpectedVersion = MaximumRevision },
		"bad prefix":         func(value *ReplaceInput) { value.Policy.Prefix = "CASE-OPS" },
		"control prefix":     func(value *ReplaceInput) { value.Policy.Prefix = "CASE\n" },
		"bad separator":      func(value *ReplaceInput) { value.Policy.Separator = ":" },
		"bad period":         func(value *ReplaceInput) { value.Policy.Period = kernel.NumberingPeriod(99) },
		"small width":        func(value *ReplaceInput) { value.Policy.Width = 3 },
		"zero start":         func(value *ReplaceInput) { value.Policy.Start = 0 },
		"short key":          func(value *ReplaceInput) { value.IdempotencyKey = "short" },
		"key whitespace":     func(value *ReplaceInput) { value.IdempotencyKey = "numbering key invalid" },
		"empty reason":       func(value *ReplaceInput) { value.Reason = "  " },
		"control reason":     func(value *ReplaceInput) { value.Reason = "unsafe\nreason" },
		"format reason":      func(value *ReplaceInput) { value.Reason = "unsafe\u202ereason" },
		"non-v7 request":     func(value *ReplaceInput) { value.Event.RequestID = uuid.New() },
		"non-v7 correlation": func(value *ReplaceInput) { value.Event.CorrelationID = uuid.New() },
		"zoned remote":       func(value *ReplaceInput) { value.Event.RemoteAddress = netip.MustParseAddr("fe80::1%eth0") },
		"empty user agent":   func(value *ReplaceInput) { value.Event.UserAgent = "" },
		"control user agent": func(value *ReplaceInput) { value.Event.UserAgent = "browser\nforged" },
		"long user agent": func(value *ReplaceInput) {
			value.Event.UserAgent = string(make([]byte, 513))
		},
	} {
		t.Run(name, func(t *testing.T) {
			input := numberingReplaceInput()
			mutate(&input)
			if _, err := service.Replace(
				context.Background(), session, tenantID, kernel.AggregateCase, input,
			); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if repository.replaceCalls != 0 {
		t.Fatalf("invalid commands reached repository: %d", repository.replaceCalls)
	}

	current := numberingPolicyFixture(
		t, tenantID, kernel.AggregateCase, 1, numberingServiceTestNow.Add(-time.Hour),
	)
	repository.replace = func(_ context.Context, params ReplaceParams) (ReplaceResult, error) {
		_, err := params.BuildPlan(current)
		return ReplaceResult{}, err
	}
	service.newID = func() (uuid.UUID, error) { return uuid.Nil, errors.New("entropy unavailable") }
	if _, err := service.Replace(
		context.Background(), session, tenantID, kernel.AggregateCase, numberingReplaceInput(),
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("entropy error = %v", err)
	}
	service.newID = func() (uuid.UUID, error) { return uuid.New(), nil }
	if _, err := service.Replace(
		context.Background(), session, tenantID, kernel.AggregateCase, numberingReplaceInput(),
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("non-v7 generated ID error = %v", err)
	}
}

func TestPolicyReplacementCommandBindingIsCanonicalAndDivergenceSensitive(t *testing.T) {
	tenantID := numberingTestUUID(50)
	input := numberingReplaceInput()
	normalized, _, err := normalizeReplaceInput(input)
	if err != nil {
		t.Fatal(err)
	}
	base, err := bindReplaceCommand(tenantID, kernel.AggregateCase, normalized)
	if err != nil || base.KeyDigest == ([32]byte{}) || base.RequestDigest == ([32]byte{}) {
		t.Fatalf("binding = %#v, error = %v", base, err)
	}
	same, err := bindReplaceCommand(tenantID, kernel.AggregateCase, normalized)
	if err != nil || same != base {
		t.Fatalf("non-deterministic binding = %#v, error = %v", same, err)
	}

	mutations := []func(*ReplaceInput){
		func(value *ReplaceInput) { value.ExpectedVersion++ },
		func(value *ReplaceInput) { value.Policy.Prefix = "INC" },
		func(value *ReplaceInput) { value.Policy.Separator = "_" },
		func(value *ReplaceInput) { value.Policy.Period = kernel.NumberingPeriodNone },
		func(value *ReplaceInput) { value.Policy.Width = 7 },
		func(value *ReplaceInput) { value.Policy.Start++ },
		func(value *ReplaceInput) { value.Reason = "Another approved change" },
	}
	for index, mutate := range mutations {
		candidate := normalized
		mutate(&candidate)
		binding, bindErr := bindReplaceCommand(tenantID, kernel.AggregateCase, candidate)
		if bindErr != nil {
			t.Fatalf("mutation %d: %v", index, bindErr)
		}
		if binding.KeyDigest != base.KeyDigest || binding.RequestDigest == base.RequestDigest {
			t.Fatalf("mutation %d did not preserve key and change request digest", index)
		}
	}
	otherKind, err := bindReplaceCommand(tenantID, kernel.AggregateAlert, normalized)
	if err != nil || otherKind.RequestDigest == base.RequestDigest {
		t.Fatalf("kind was not bound: %#v, %v", otherKind, err)
	}
	otherTenant, err := bindReplaceCommand(numberingTestUUID(51), kernel.AggregateCase, normalized)
	if err != nil || otherTenant.RequestDigest == base.RequestDigest {
		t.Fatalf("tenant was not bound: %#v, %v", otherTenant, err)
	}
	otherKeyInput := normalized
	otherKeyInput.IdempotencyKey = "numbering-policy-key-0002"
	otherKey, err := bindReplaceCommand(tenantID, kernel.AggregateCase, otherKeyInput)
	if err != nil || otherKey.KeyDigest == base.KeyDigest || otherKey.RequestDigest != base.RequestDigest {
		t.Fatalf("key isolation = %#v, %v", otherKey, err)
	}
}

func TestDependencyAndContextFailuresStayBounded(t *testing.T) {
	tenantID := numberingTestUUID(60)
	session := numberingTestSession(tenantID)
	for name, dependencyErr := range map[string]error{
		"invalid":     authorization.ErrInvalidInput,
		"forbidden":   authorization.ErrForbidden,
		"not found":   authorization.ErrNotFound,
		"unavailable": errors.New("authority unavailable"),
	} {
		t.Run(name, func(t *testing.T) {
			service := newNumberingTestService(
				t, &numberingRepositoryStub{}, &numberingAuthorityStub{err: dependencyErr},
			)
			_, err := service.Get(context.Background(), session, tenantID, kernel.AggregateCase)
			if !errors.Is(err, repositoryError(dependencyErr)) {
				t.Fatalf("error = %v", err)
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	repository := &numberingRepositoryStub{}
	authority := &numberingAuthorityStub{authority: numberingTestAuthority(
		tenantID, authorization.TenantPermissionSettingsRead,
	)}
	service := newNumberingTestService(t, repository, authority)
	if _, err := service.Get(ctx, session, tenantID, kernel.AggregateCase); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context error = %v", err)
	}
	if authority.calls != 0 || repository.currentCalls != 0 {
		t.Fatal("canceled context reached dependencies")
	}

	service.clock = func() time.Time { return time.Time{} }
	if _, err := service.Get(context.Background(), session, tenantID, kernel.AggregateCase); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("invalid clock error = %v", err)
	}
}

type numberingRepositoryStub struct {
	currentCalls int
	replaceCalls int
	current      func(context.Context, ReadParams) (kernel.NumberingPolicy, error)
	replace      func(context.Context, ReplaceParams) (ReplaceResult, error)
}

func (stub *numberingRepositoryStub) Current(
	ctx context.Context,
	params ReadParams,
) (kernel.NumberingPolicy, error) {
	stub.currentCalls++
	if stub.current == nil {
		return kernel.NumberingPolicy{}, ErrRepositoryNotFound
	}
	return stub.current(ctx, params)
}

func (stub *numberingRepositoryStub) Replace(
	ctx context.Context,
	params ReplaceParams,
) (ReplaceResult, error) {
	stub.replaceCalls++
	if stub.replace == nil {
		return ReplaceResult{}, ErrUnavailable
	}
	return stub.replace(ctx, params)
}

type numberingAuthorityStub struct {
	calls     int
	authority authorization.TenantAuthority
	err       error
}

func (stub *numberingAuthorityStub) GetTenantAuthority(
	_ context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
) (authorization.TenantAuthority, error) {
	stub.calls++
	if actor.ActiveTenantID != tenantID || actor.UserID == uuid.Nil || actor.SessionID == uuid.Nil {
		return authorization.TenantAuthority{}, authorization.ErrInvalidInput
	}
	return stub.authority, stub.err
}

func newNumberingTestService(
	t testing.TB,
	repository Repository,
	authority TenantAuthorityResolver,
) *Service {
	t.Helper()
	service, err := NewService(repository, authority)
	if err != nil {
		t.Fatal(err)
	}
	service.clock = func() time.Time { return numberingServiceTestNow }
	service.newID = func() (uuid.UUID, error) { return numberingTestUUID(99), nil }
	return service
}

func numberingTestSession(tenantID uuid.UUID) authentication.Session {
	return authentication.Session{
		ID: numberingTestUUID(100), User: authentication.User{ID: numberingTestUUID(101)},
		ActiveTenantID: &tenantID, AuthenticationMethod: "totp",
		IdleExpiresAt:     numberingServiceTestNow.Add(time.Hour),
		AbsoluteExpiresAt: numberingServiceTestNow.Add(2 * time.Hour),
	}
}

func numberingTestAuthority(
	tenantID uuid.UUID,
	permissions ...authorization.TenantPermission,
) authorization.TenantAuthority {
	grants := make([]authorization.ScopedPermission, len(permissions))
	for index, permission := range permissions {
		grants[index] = authorization.ScopedPermission{Permission: permission, Scope: authorization.ScopeTenant}
	}
	return authorization.TenantAuthority{
		TenantID: tenantID,
		Principal: authorization.TenantPrincipal{
			ID: numberingTestUUID(101), Kind: authorization.PrincipalKindHuman,
		},
		MembershipID: numberingTestUUID(102), MembershipStatus: authorization.MembershipStatusActive,
		LegacyRole:  authorization.LegacyMembershipRoleTenantAdmin,
		Permissions: grants, EvaluatedAt: numberingServiceTestNow,
	}
}

func numberingReplaceInput() ReplaceInput {
	return ReplaceInput{
		ExpectedVersion: 1,
		Policy: PolicyDraft{
			Prefix: " case ", Separator: " / ", Period: kernel.NumberingPeriodAnnual,
			Width: 8, Start: 100,
		},
		IdempotencyKey: "numbering-policy-key-0001",
		Reason:         " Approve incident numbering ",
		Event: authentication.EventContext{
			RequestID: numberingTestUUID(110), CorrelationID: numberingTestUUID(111),
			RemoteAddress: netip.MustParseAddr("::ffff:192.0.2.10"), UserAgent: "numbering-test-client",
		},
	}
}

func numberingPolicyFixture(
	t testing.TB,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	version uint64,
	publishedAt time.Time,
) kernel.NumberingPolicy {
	t.Helper()
	prefix := "CASE"
	if kind == kernel.AggregateAlert {
		prefix = "ALT"
	}
	return numberingPolicyWithSpec(
		t, numberingTestUUID(uint32(200+version)), tenantID, kind, version,
		PolicyDraft{
			Prefix: prefix, Separator: "-", Period: kernel.NumberingPeriodAnnual,
			Width: 6, Start: 1,
		},
		numberingTestUUID(102), publishedAt,
	)
}

func numberingPolicyWithSpec(
	t testing.TB,
	versionID uuid.UUID,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	version uint64,
	draft PolicyDraft,
	publisher uuid.UUID,
	publishedAt time.Time,
) kernel.NumberingPolicy {
	t.Helper()
	_, spec, err := normalizeDraft(draft)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := kernel.NewNumberingPolicy(
		mustEntityID(t, versionID), mustEntityID(t, tenantID), kind, version, spec,
		mustEntityID(t, publisher), publishedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func mustEntityID(t testing.TB, value uuid.UUID) kernel.EntityID {
	t.Helper()
	id, ok := entityID(value)
	if !ok {
		t.Fatalf("invalid test entity ID %s", value)
	}
	return id
}

func numberingTestUUID(value uint32) uuid.UUID {
	const digits = "0123456789abcdef"
	suffix := []byte("000000000000")
	for index := len(suffix) - 1; value > 0; index-- {
		suffix[index] = digits[value&15]
		value >>= 4
	}
	return uuid.MustParse("00000000-0000-7000-8000-" + string(suffix))
}
