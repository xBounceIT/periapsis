package securityaudit

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

var (
	testTenantID    = uuid.MustParse("00000000-0000-7000-8000-000000000001")
	testOtherTenant = uuid.MustParse("00000000-0000-7000-8000-000000000002")
	testUserID      = uuid.MustParse("00000000-0000-7000-8000-000000000003")
	testSessionID   = uuid.MustParse("00000000-0000-7000-8000-000000000004")
	testMembership  = uuid.MustParse("00000000-0000-7000-8000-000000000005")
	testRequestID   = uuid.MustParse("00000000-0000-7000-8000-000000000006")
	testCorrelation = uuid.MustParse("00000000-0000-7000-8000-000000000007")
	testAuditID     = uuid.MustParse("00000000-0000-7000-8000-000000000008")
	testEventID1    = uuid.MustParse("00000000-0000-7000-8000-000000000009")
	testEventID2    = uuid.MustParse("00000000-0000-7000-8000-00000000000a")
	testNow         = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
)

type repositoryStub struct {
	tenantRows              []Event
	platformRows            []Event
	tenantErr               error
	platformErr             error
	tenantVerification      Verification
	platformVerification    Verification
	tenantVerificationErr   error
	platformVerificationErr error
	tenantCalls             []TenantReadParams
	platformCalls           []PlatformReadParams
	tenantVerifyCalls       []TenantVerifyParams
	platformVerifyCalls     []PlatformVerifyParams
}

func (repository *repositoryStub) ListTenantEvents(_ context.Context, params TenantReadParams) ([]Event, error) {
	repository.tenantCalls = append(repository.tenantCalls, params)
	return repository.tenantRows, repository.tenantErr
}

func (repository *repositoryStub) ListPlatformEvents(_ context.Context, params PlatformReadParams) ([]Event, error) {
	repository.platformCalls = append(repository.platformCalls, params)
	return repository.platformRows, repository.platformErr
}

func (repository *repositoryStub) VerifyTenantChain(_ context.Context, params TenantVerifyParams) (Verification, error) {
	repository.tenantVerifyCalls = append(repository.tenantVerifyCalls, params)
	return repository.tenantVerification, repository.tenantVerificationErr
}

func (repository *repositoryStub) VerifyPlatformChain(_ context.Context, params PlatformVerifyParams) (Verification, error) {
	repository.platformVerifyCalls = append(repository.platformVerifyCalls, params)
	return repository.platformVerification, repository.platformVerificationErr
}

type resolverStub struct {
	authority authorization.TenantAuthority
	err       error
	calls     []authorization.ResolveAuthorityParams
}

func (resolver *resolverStub) ResolveAuthority(_ context.Context, params authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
	resolver.calls = append(resolver.calls, params)
	return resolver.authority, resolver.err
}

func TestNewServiceRequiresBothSecurityBoundaries(t *testing.T) {
	t.Parallel()

	repository := &repositoryStub{}
	resolver := &resolverStub{}
	for _, test := range []struct {
		name       string
		repository Repository
		resolver   AuthorityResolver
	}{
		{name: "missing repository", resolver: resolver},
		{name: "missing resolver", repository: repository},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewService(test.repository, test.resolver); err == nil {
				t.Fatal("NewService() error = nil")
			}
		})
	}
}

func TestTenantReadResolvesLiveAuthorityAndAuditsAccess(t *testing.T) {
	t.Parallel()

	event := validTenantEvent(9)
	repository := &repositoryStub{tenantRows: []Event{event}}
	resolver := &resolverStub{authority: validAuthority()}
	service := mustService(t, repository, resolver)
	service.newID = func() (uuid.UUID, error) { return testAuditID, nil }

	page, err := service.ListTenant(context.Background(), validActor(), testTenantID, Query{
		Limit: 7, ActionPrefix: "case", Search: "claimed",
	}, tenantAuditFixture())
	if err != nil {
		t.Fatalf("ListTenant() error = %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != event.ID || page.NextSequence != nil {
		t.Fatalf("ListTenant() page = %#v", page)
	}
	if len(resolver.calls) != 1 || resolver.calls[0].Actor != validActor() || resolver.calls[0].TenantID != testTenantID {
		t.Fatalf("ResolveAuthority calls = %#v", resolver.calls)
	}
	if len(repository.tenantCalls) != 1 {
		t.Fatalf("tenant repository calls = %d", len(repository.tenantCalls))
	}
	call := repository.tenantCalls[0]
	if call.Permission != authorization.TenantPermissionAuditRead || call.Query.Limit != 8 ||
		call.AccessAuditID != testAuditID || call.Actor != validActor() || call.TenantID != testTenantID ||
		call.Audit != tenantAuditFixture() {
		t.Fatalf("tenant repository call = %#v", call)
	}
}

func TestTenantReadFailsClosedBeforeRepository(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name        string
		actor       authorization.Actor
		authority   authorization.TenantAuthority
		resolverErr error
		want        error
	}{
		{name: "wrong active tenant", actor: func() authorization.Actor {
			value := validActor()
			value.ActiveTenantID = testOtherTenant
			return value
		}(), authority: validAuthority(), want: ErrForbidden},
		{name: "permission missing", actor: validActor(), authority: func() authorization.TenantAuthority { value := validAuthority(); value.Permissions = nil; return value }(), want: ErrForbidden},
		{name: "resolver principal substitution", actor: validActor(), authority: func() authorization.TenantAuthority {
			value := validAuthority()
			value.Principal.ID = testEventID1
			return value
		}(), want: ErrForbidden},
		{name: "resolver denied", actor: validActor(), authority: validAuthority(), resolverErr: authorization.ErrForbidden, want: ErrForbidden},
		{name: "resolver canceled", actor: validActor(), authority: validAuthority(), resolverErr: context.Canceled, want: context.Canceled},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repository := &repositoryStub{}
			resolver := &resolverStub{authority: test.authority, err: test.resolverErr}
			service := mustService(t, repository, resolver)
			_, err := service.ListTenant(context.Background(), test.actor, testTenantID, Query{}, tenantAuditFixture())
			if !errors.Is(err, test.want) {
				t.Fatalf("ListTenant() error = %v, want %v", err, test.want)
			}
			if len(repository.tenantCalls) != 0 {
				t.Fatalf("repository called %d times", len(repository.tenantCalls))
			}
		})
	}
}

func TestReadErrorMappingPreservesCancellationAndSanitizesUnknownFailures(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		input error
		want  error
	}{
		{input: context.Canceled, want: context.Canceled},
		{input: context.DeadlineExceeded, want: context.DeadlineExceeded},
		{input: errors.New("database details"), want: ErrUnavailable},
	} {
		if actual := mapReadError(test.input); !errors.Is(actual, test.want) {
			t.Fatalf("mapReadError(%v) = %v, want %v", test.input, actual, test.want)
		}
	}
}

func TestPlatformReadRequiresLiveSessionAndDedicatedPermission(t *testing.T) {
	t.Parallel()

	repository := &repositoryStub{platformRows: []Event{validPlatformEventProjection(4)}}
	service := mustService(t, repository, &resolverStub{})
	service.newID = func() (uuid.UUID, error) { return testAuditID, nil }
	service.now = func() time.Time { return testNow }

	session := validSession()
	page, err := service.ListPlatform(context.Background(), session, Query{Limit: 3}, validPlatformAccessEvent())
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("ListPlatform() = %#v, %v", page, err)
	}
	if len(repository.platformCalls) != 1 || repository.platformCalls[0].Permission != authorization.PermissionPlatformAuditRead ||
		repository.platformCalls[0].Query.Limit != 4 || repository.platformCalls[0].AccessAuditID != testAuditID {
		t.Fatalf("platform repository calls = %#v", repository.platformCalls)
	}

	for _, mutate := range []func(*authentication.Session){
		func(value *authentication.Session) { value.Permissions = nil },
		func(value *authentication.Session) { revoked := testNow.Add(-time.Minute); value.RevokedAt = &revoked },
		func(value *authentication.Session) { value.IdleExpiresAt = testNow },
		func(value *authentication.Session) { value.AbsoluteExpiresAt = testNow },
	} {
		candidate := validSession()
		mutate(&candidate)
		if _, err := service.ListPlatform(context.Background(), candidate, Query{}, validPlatformAccessEvent()); !errors.Is(err, ErrForbidden) && !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("ListPlatform() invalid session error = %v", err)
		}
	}
	if len(repository.platformCalls) != 1 {
		t.Fatalf("repository called for denied platform session: %d", len(repository.platformCalls))
	}
	if _, err := service.ListPlatform(
		context.Background(), validSession(),
		Query{ActorServiceAccountID: pointer(testEventID1)}, validPlatformAccessEvent(),
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("ListPlatform() service-account identifier filter error = %v", err)
	}
	if len(repository.platformCalls) != 1 {
		t.Fatalf("repository called for unsupported platform filter: %d", len(repository.platformCalls))
	}
}

func TestChainVerificationUsesSameAuthorityAndAccessAuditBoundary(t *testing.T) {
	t.Parallel()

	valid := Verification{
		EventCount: 12, LastSequence: 12, HeadValid: true, Valid: true,
		VerifiedAt: testNow,
	}
	repository := &repositoryStub{tenantVerification: valid, platformVerification: valid}
	resolver := &resolverStub{authority: validAuthority()}
	service := mustService(t, repository, resolver)
	service.newID = func() (uuid.UUID, error) { return testAuditID, nil }
	service.now = func() time.Time { return testNow }

	tenantResult, err := service.VerifyTenant(
		context.Background(), validActor(), testTenantID, tenantAuditFixture(),
	)
	if err != nil || !tenantResult.Valid || tenantResult.EventCount != 12 {
		t.Fatalf("VerifyTenant() = %#v, %v", tenantResult, err)
	}
	if len(repository.tenantVerifyCalls) != 1 {
		t.Fatalf("tenant verification calls = %#v", repository.tenantVerifyCalls)
	}
	tenantCall := repository.tenantVerifyCalls[0]
	if tenantCall.Permission != authorization.TenantPermissionAuditRead ||
		tenantCall.AccessAuditID != testAuditID || tenantCall.TenantID != testTenantID ||
		tenantCall.Actor != validActor() || tenantCall.Audit != tenantAuditFixture() {
		t.Fatalf("tenant verification call = %#v", tenantCall)
	}

	platformResult, err := service.VerifyPlatform(
		context.Background(), validSession(), validPlatformAccessEvent(),
	)
	if err != nil || !platformResult.Valid || platformResult.LastSequence != 12 {
		t.Fatalf("VerifyPlatform() = %#v, %v", platformResult, err)
	}
	if len(repository.platformVerifyCalls) != 1 ||
		repository.platformVerifyCalls[0].Permission != authorization.PermissionPlatformAuditRead ||
		repository.platformVerifyCalls[0].AccessAuditID != testAuditID {
		t.Fatalf("platform verification calls = %#v", repository.platformVerifyCalls)
	}
}

func TestVerificationProjectionRejectsContradictions(t *testing.T) {
	t.Parallel()

	invalidSequence := uint64(4)
	tests := []Verification{
		{EventCount: 5, LastSequence: 4, HeadValid: true, Valid: true, VerifiedAt: testNow},
		{EventCount: 4, LastSequence: 4, HeadValid: false, Valid: true, VerifiedAt: testNow},
		{EventCount: 4, LastSequence: 4, FirstInvalidSequence: &invalidSequence, HeadValid: true, Valid: true, VerifiedAt: testNow},
		{EventCount: 4, LastSequence: 4, HeadValid: true, Valid: false, VerifiedAt: testNow},
		{EventCount: 4, LastSequence: 4, HeadValid: true, Valid: true, VerifiedAt: testNow.Add(-6 * time.Minute)},
		{EventCount: 4, LastSequence: 4, HeadValid: true, Valid: true, VerifiedAt: testNow.Add(3 * time.Minute)},
	}
	for index, verification := range tests {
		repository := &repositoryStub{tenantVerification: verification}
		service := mustService(t, repository, &resolverStub{authority: validAuthority()})
		service.newID = func() (uuid.UUID, error) { return testAuditID, nil }
		service.now = func() time.Time { return testNow }
		if _, err := service.VerifyTenant(context.Background(), validActor(), testTenantID, tenantAuditFixture()); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("case %d VerifyTenant() error = %v", index, err)
		}
	}

	actualInvalid := Verification{
		EventCount: 3, LastSequence: 4, FirstInvalidSequence: &invalidSequence,
		HeadValid: false, Valid: false, VerifiedAt: testNow,
	}
	repository := &repositoryStub{tenantVerification: actualInvalid}
	service := mustService(t, repository, &resolverStub{authority: validAuthority()})
	service.newID = func() (uuid.UUID, error) { return testAuditID, nil }
	service.now = func() time.Time { return testNow }
	result, err := service.VerifyTenant(context.Background(), validActor(), testTenantID, tenantAuditFixture())
	if err != nil || result.Valid || result.FirstInvalidSequence == nil || *result.FirstInvalidSequence != 4 {
		t.Fatalf("VerifyTenant() invalid-chain result = %#v, %v", result, err)
	}
	*actualInvalid.FirstInvalidSequence = 2
	if *result.FirstInvalidSequence != 4 {
		t.Fatal("verification result aliases repository pointer")
	}
}

func TestPageUsesStableSentinelAndDefensiveCopies(t *testing.T) {
	t.Parallel()

	first := validTenantEvent(9)
	second := validTenantEvent(10)
	second.ID = testEventID2
	second.PreviousHash = first.EventHash
	repository := &repositoryStub{tenantRows: []Event{first, second}}
	service := mustService(t, repository, &resolverStub{authority: validAuthority()})
	service.newID = func() (uuid.UUID, error) { return testAuditID, nil }

	page, err := service.ListTenant(context.Background(), validActor(), testTenantID, Query{Limit: 1}, tenantAuditFixture())
	if err != nil {
		t.Fatalf("ListTenant() error = %v", err)
	}
	if len(page.Items) != 1 || page.NextSequence == nil || *page.NextSequence != 9 {
		t.Fatalf("page = %#v", page)
	}
	repository.tenantRows[0].Metadata[0] = '['
	*repository.tenantRows[0].TenantID = testOtherTenant
	if string(page.Items[0].Metadata) != `{}` || *page.Items[0].TenantID != testTenantID {
		t.Fatalf("returned page aliases repository storage: %#v", page.Items[0])
	}
}

func TestRepositoryProjectionIsValidatedFailClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Event)
	}{
		{name: "cross tenant", mutate: func(event *Event) { event.TenantID = pointer(testOtherTenant) }},
		{name: "duplicate sequence", mutate: func(event *Event) { event.Sequence = 9 }},
		{name: "broken adjacent chain", mutate: func(event *Event) { event.PreviousHash = strings.Repeat("c", 64) }},
		{name: "nested secret", mutate: func(event *Event) { event.Metadata = json.RawMessage(`{"safe":{"client_secret":"leak"}}`) }},
		{name: "non object metadata", mutate: func(event *Event) { event.Metadata = json.RawMessage(`[]`) }},
		{name: "missing before object", mutate: func(event *Event) { event.Before = nil }},
		{name: "null after object", mutate: func(event *Event) { event.After = json.RawMessage(`null`) }},
		{name: "malformed action", mutate: func(event *Event) { event.Action = "case..claimed" }},
		{name: "unexpected filtered row", mutate: func(event *Event) { event.Action = "alert.created" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			first := validTenantEvent(9)
			second := validTenantEvent(10)
			second.ID = testEventID2
			second.PreviousHash = first.EventHash
			test.mutate(&second)
			repository := &repositoryStub{tenantRows: []Event{first, second}}
			service := mustService(t, repository, &resolverStub{authority: validAuthority()})
			service.newID = func() (uuid.UUID, error) { return testAuditID, nil }
			_, err := service.ListTenant(context.Background(), validActor(), testTenantID, Query{ActionPrefix: "case"}, tenantAuditFixture())
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("ListTenant() error = %v", err)
			}
		})
	}
}

func TestQueryValidationRejectsAmbiguousOrUnboundedFilters(t *testing.T) {
	t.Parallel()

	actorType := ActorSystem
	userID := testUserID
	serviceID := testEventID1
	from := testNow
	before := testNow
	for _, query := range []Query{
		{Limit: -1},
		{Limit: 101},
		{AfterSequence: uint64(math.MaxInt64) + 1},
		{OccurredFrom: &from, OccurredBefore: &before},
		{ActorUserID: &userID, ActorServiceAccountID: &serviceID},
		{ActorType: &actorType, ActorUserID: &userID},
		{ActionPrefix: "case%"},
		{ActionPrefix: strings.Repeat("a", 129)},
		{ResourceType: "case;drop"},
		{Search: strings.Repeat("x", maximumSearchRunes+1)},
		{Search: "line\nbreak"},
	} {
		if _, err := normalizeQuery(query); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("normalizeQuery(%#v) error = %v", query, err)
		}
	}
}

func TestAuditReasonUsesPersistedUTF8ByteContract(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		reason *string
		valid  bool
	}{
		{name: "absent", reason: nil, valid: true},
		{name: "1025 ASCII bytes", reason: pointer(strings.Repeat("a", 1_025)), valid: true},
		{name: "exactly 2048 ASCII bytes", reason: pointer(strings.Repeat("a", 2_048)), valid: true},
		{name: "exactly 2048 multibyte bytes", reason: pointer(strings.Repeat("é", 1_024)), valid: true},
		{name: "2049 bytes", reason: pointer(strings.Repeat("a", 2_049)), valid: false},
		{name: "2050 multibyte bytes", reason: pointer(strings.Repeat("é", 1_025)), valid: false},
		{name: "empty", reason: pointer(""), valid: false},
		{name: "leading whitespace", reason: pointer(" approved"), valid: false},
		{name: "trailing whitespace", reason: pointer("approved "), valid: false},
		{name: "control", reason: pointer("approved\nchange"), valid: false},
		{name: "format character", reason: pointer("approved\u200bchange"), valid: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			event := validPlatformEventProjection(4)
			event.Reason = test.reason
			err := validateEvent(event, nil)
			if test.valid && err != nil {
				t.Fatalf("validateEvent() error = %v", err)
			}
			if !test.valid && !errors.Is(err, ErrUnavailable) {
				t.Fatalf("validateEvent() error = %v, want unavailable", err)
			}
		})
	}
}

func TestJSONRedactionNormalizesCredentialKeySpellingsWithoutBlockingSafeFlags(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		`{"token_digest":"x"}`,
		`{"outer":{"Client-Secret":"x"}}`,
		`{"items":[{"TOTP secret":"x"}]}`,
		`{"recoveryCodes":["x"]}`,
		`{"access_token_digest":"x"}`,
		`{"SAMLAssertion":"x"}`,
		`{"user_password":"x"}`,
		`{"password_value":"x"}`,
		`{"outer":{"myClientSecret":"x"}}`,
		`{"opaque_token":"x"}`,
		`{"sessionCookie":"x"}`,
		`{"passwordConfigured":"plaintext"}`,
		`{"secret_id":"not-an-id"}`,
		`{"credential_kind":{"password":"x"}}`,
		`{"fenceToken":"11"}`,
	} {
		if err := validateJSONDocument(json.RawMessage(raw), maximumMetadataBytes); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("validateJSONDocument(%s) error = %v", raw, err)
		}
	}
	for _, raw := range []string{
		`{"api_key_id":"00000000-0000-7000-8000-000000000001"}`,
		`{"secret_material_included":false}`,
		`{"secret_id":"00000000-0000-7000-8000-000000000001","secret_version":4}`,
		`{"credential_kind":"local_break_glass","credential_key_version":2}`,
		`{"predecessor_credential_id":"00000000-0000-7000-8000-000000000001","replacement_credential_id":"00000000-0000-7000-8000-000000000002"}`,
		`{"bind_secret_configured":true,"bind_secret_id":"00000000-0000-7000-8000-000000000001","bind_secret_key_version":3}`,
		`{"passwordConfigured":true}`,
		`{"privateKeyConfigured":true,"fenceToken":"00000000-0000-7000-8000-000000000003"}`,
		`{"authorization_revision":7}`,
		`{"bind_secret_version":4}`,
		`{"token_kind":"opaque"}`,
	} {
		if err := validateJSONDocument(json.RawMessage(raw), maximumMetadataBytes); err != nil {
			t.Fatalf("validateJSONDocument(%s) error = %v", raw, err)
		}
	}
}

func TestSensitiveMetadataAllowlistAlwaysHasAnExactValueContract(t *testing.T) {
	t.Parallel()

	for catalogIndex, catalog := range safeSensitiveKeyCatalogs {
		for key := range catalog {
			for otherIndex, other := range safeSensitiveKeyCatalogs {
				if catalogIndex == otherIndex {
					continue
				}
				if _, duplicate := other[key]; duplicate {
					t.Fatalf("safe sensitive key %q has multiple value contracts", key)
				}
			}
		}
	}
}

func validActor() authorization.Actor {
	return authorization.Actor{
		UserID: testUserID, SessionID: testSessionID, ActiveTenantID: testTenantID,
		AuthenticationMethod: "password+mfa",
	}
}

func validAuthority() authorization.TenantAuthority {
	return authorization.TenantAuthority{
		TenantID:     testTenantID,
		Principal:    authorization.TenantPrincipal{ID: testUserID, Kind: authorization.PrincipalKindHuman},
		MembershipID: testMembership, MembershipStatus: authorization.MembershipStatusActive,
		LegacyRole: authorization.LegacyMembershipRoleTenantAdmin,
		Permissions: []authorization.ScopedPermission{{
			Permission: authorization.TenantPermissionAuditRead, Scope: authorization.ScopeTenant,
		}},
		EvaluatedAt: testNow,
	}
}

func tenantAuditFixture() authorization.AuditContext {
	return authorization.AuditContext{
		RequestID: testRequestID, CorrelationID: testCorrelation,
		RemoteAddress: netip.MustParseAddr("198.51.100.8"), UserAgent: "audit-test/1",
	}
}

func validPlatformAccessEvent() authentication.EventContext {
	return authentication.EventContext{
		RequestID: testRequestID, CorrelationID: testCorrelation,
		RemoteAddress: netip.MustParseAddr("198.51.100.8"), UserAgent: "audit-test/1",
	}
}

func validSession() authentication.Session {
	return authentication.Session{
		ID: testSessionID, User: authentication.User{ID: testUserID},
		Permissions: []authorization.Permission{authorization.PermissionPlatformAuditRead},
		CreatedAt:   testNow.Add(-time.Hour), LastSeenAt: testNow.Add(-time.Minute),
		IdleExpiresAt: testNow.Add(time.Hour), AbsoluteExpiresAt: testNow.Add(8 * time.Hour),
		AuthenticationMethod: "password+mfa",
	}
}

func validTenantEvent(sequence uint64) Event {
	event := validEvent(sequence)
	event.TenantID = pointer(testTenantID)
	event.ActorServiceAccountID = nil
	return event
}

func validPlatformEventProjection(sequence uint64) Event {
	event := validEvent(sequence)
	event.TenantID = nil
	return event
}

func validEvent(sequence uint64) Event {
	return Event{
		ID: testEventID1, Sequence: sequence, OccurredAt: testNow.Add(-time.Minute),
		ActorType: ActorUser, ActorUserID: pointer(testUserID), Action: "case.claimed",
		ResourceType: "case", ResourceID: pointer(testEventID2), RequestID: pointer(testRequestID),
		CorrelationID: pointer(testCorrelation), Outcome: OutcomeSuccess,
		Before: json.RawMessage(`{"state":"open"}`), After: json.RawMessage(`{"state":"in_progress"}`),
		Metadata: json.RawMessage(`{}`), PreviousHash: strings.Repeat("a", 64), EventHash: strings.Repeat("b", 64),
	}
}

func mustService(t *testing.T, repository Repository, resolver AuthorityResolver) *Service {
	t.Helper()
	service, err := NewService(repository, resolver)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

func pointer[T any](value T) *T { return &value }
