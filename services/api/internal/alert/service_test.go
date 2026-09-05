package alert

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/serviceaccount"
)

type repositoryStub struct {
	resolveResult authorization.TenantAuthority
	resolveErr    error
	humanResult   IdempotentCreateResult
	humanErr      error
	bearerResult  IdempotentCreateResult
	bearerErr     error
	humanParams   *CreateAsHumanParams
	bearerParams  *CreateAsServiceAccountParams
}

func (s *repositoryStub) ResolveHumanAuthority(_ context.Context, _ authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
	return s.resolveResult, s.resolveErr
}

func (s *repositoryStub) CreateAsHuman(_ context.Context, params CreateAsHumanParams) (IdempotentCreateResult, error) {
	s.humanParams = &params
	result := s.humanResult
	if result.Alert.ID == uuid.Nil {
		result.Alert = storedHumanAlert(params, alertTestID(91))
	}
	return result, s.humanErr
}

func (s *repositoryStub) CreateAsServiceAccount(_ context.Context, params CreateAsServiceAccountParams) (IdempotentCreateResult, error) {
	s.bearerParams = &params
	result := s.bearerResult
	if result.Alert.ID == uuid.Nil {
		result.Alert = storedMachineAlert(params, alertTestID(92), alertTestID(90))
	}
	return result, s.bearerErr
}

func TestCreateAsHumanNormalizesAndBindsCommand(t *testing.T) {
	t.Parallel()

	tenantID := alertTestID(1)
	userID := alertTestID(2)
	membershipID := alertTestID(3)
	repository := &repositoryStub{resolveResult: humanAuthority(tenantID, userID, membershipID, true)}
	service := testService(t, repository)
	externalID := " collector-42 "
	description := "  Suspicious process execution  "
	input := CreateInput{
		ExternalID: &externalID, Title: "  Endpoint detection  ", Description: &description,
		Severity: SeverityHigh, IdempotencyKey: "alert-create-retry-0001", Audit: testAudit(tenantID),
	}
	actor := authorization.Actor{
		UserID: userID, SessionID: alertTestID(4), ActiveTenantID: tenantID, AuthenticationMethod: "local_password_totp",
	}

	created, err := service.CreateAsHuman(context.Background(), actor, tenantID, input)
	if err != nil {
		t.Fatalf("CreateAsHuman() error = %v", err)
	}
	if created.ID != alertTestID(91) || repository.humanParams == nil {
		t.Fatalf("created ID = %v, params = %#v", created.ID, repository.humanParams)
	}
	params := *repository.humanParams
	if params.MembershipID != membershipID || params.Actor != actor || params.Payload.Title != "Endpoint detection" ||
		params.Payload.ExternalID == nil || *params.Payload.ExternalID != "collector-42" ||
		params.Payload.Description == nil || *params.Payload.Description != "Suspicious process execution" {
		t.Fatalf("CreateAsHuman params = %#v", params)
	}
	if params.Payload.KeyDigest == ([32]byte{}) || params.Payload.RequestDigest == ([32]byte{}) {
		t.Fatalf("command binding payload = %#v", params.Payload)
	}
}

func TestCreateAsHumanAcceptsPresentEmptyDescription(t *testing.T) {
	t.Parallel()

	tenantID, userID, membershipID := alertTestID(10), alertTestID(11), alertTestID(12)
	repository := &repositoryStub{resolveResult: humanAuthority(tenantID, userID, membershipID, true)}
	service := testService(t, repository)
	empty := ""
	input := validCreateInput(tenantID)
	input.Description = &empty
	actor := authorization.Actor{
		UserID: userID, SessionID: alertTestID(13), ActiveTenantID: tenantID, AuthenticationMethod: "local_password_totp",
	}

	created, err := service.CreateAsHuman(context.Background(), actor, tenantID, input)
	if err != nil {
		t.Fatalf("CreateAsHuman() error = %v", err)
	}
	if repository.humanParams == nil || repository.humanParams.Payload.Description == nil ||
		*repository.humanParams.Payload.Description != "" || created.Description == nil || *created.Description != "" {
		t.Fatalf("present-empty description was not preserved: params = %#v, result = %#v", repository.humanParams, created)
	}
}

func TestCreateAsHumanDeniesMissingLivePermissionBeforeMutation(t *testing.T) {
	t.Parallel()

	tenantID := alertTestID(20)
	userID := alertTestID(21)
	repository := &repositoryStub{resolveResult: humanAuthority(tenantID, userID, alertTestID(22), false)}
	service := testService(t, repository)
	input := validCreateInput(tenantID)
	actor := authorization.Actor{UserID: userID, SessionID: alertTestID(23), ActiveTenantID: tenantID, AuthenticationMethod: "totp"}

	if _, err := service.CreateAsHuman(context.Background(), actor, tenantID, input); !errors.Is(err, ErrForbidden) {
		t.Fatalf("CreateAsHuman() error = %v, want ErrForbidden", err)
	}
	if repository.humanParams != nil {
		t.Fatal("repository mutation ran without alert.create")
	}
}

func TestCreateAsBearerPassesOnlyDerivedCredentialMaterial(t *testing.T) {
	t.Parallel()

	tenantID := alertTestID(30)
	keyring, err := serviceaccount.NewCredentialKeyring(7, map[int16][]byte{7: bytes.Repeat([]byte{0xA7}, 32)})
	if err != nil {
		t.Fatalf("NewCredentialKeyring() error = %v", err)
	}
	issued, err := keyring.Issue()
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	repository := &repositoryStub{}
	service, err := NewService(repository, keyring)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	input := BearerCreateInput{CreateInput: validCreateInput(tenantID), Token: issued.Token}

	created, err := service.CreateAsBearer(context.Background(), tenantID, input)
	if err != nil {
		t.Fatalf("CreateAsBearer() error = %v", err)
	}
	if created.ID != alertTestID(92) || repository.bearerParams == nil {
		t.Fatalf("created ID = %v, params = %#v", created.ID, repository.bearerParams)
	}
	if repository.bearerParams.Credential != issued.PresentedCredential || repository.bearerParams.TenantID != tenantID {
		t.Fatalf("derived credential params = %#v", repository.bearerParams)
	}
}

func TestCreateAsBearerRejectsMalformedTokenBeforeRepository(t *testing.T) {
	t.Parallel()

	tenantID := alertTestID(40)
	repository := &repositoryStub{}
	service := testService(t, repository)
	input := BearerCreateInput{CreateInput: validCreateInput(tenantID), Token: "not-a-token"}

	if _, err := service.CreateAsBearer(context.Background(), tenantID, input); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("CreateAsBearer() error = %v, want ErrUnauthenticated", err)
	}
	if repository.bearerParams != nil {
		t.Fatal("repository received a malformed bearer token")
	}
}

func TestCreateRejectsRepositoryAttributionDivergence(t *testing.T) {
	t.Parallel()

	tenantID := alertTestID(50)
	userID := alertTestID(51)
	membershipID := alertTestID(52)
	repository := &repositoryStub{resolveResult: humanAuthority(tenantID, userID, membershipID, true)}
	service := testService(t, repository)
	input := validCreateInput(tenantID)
	normalized, err := normalizeCreateInput(input)
	if err != nil {
		t.Fatalf("normalizeCreateInput() error = %v", err)
	}
	bad := storedHumanAlert(CreateAsHumanParams{
		TenantID: tenantID, MembershipID: membershipID,
		Actor: authorization.Actor{UserID: userID},
		Payload: CreatePayload{
			ExternalID: normalized.ExternalID, Title: normalized.Title,
			Description: normalized.Description, Severity: normalized.Severity,
		},
	}, alertTestID(59))
	bad.CreatedByUserID = nil
	repository.humanResult = IdempotentCreateResult{Alert: bad, Replayed: true}
	actor := authorization.Actor{UserID: userID, SessionID: alertTestID(60), ActiveTenantID: tenantID, AuthenticationMethod: "totp"}

	if _, err := service.CreateAsHuman(context.Background(), actor, tenantID, input); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("CreateAsHuman() error = %v, want ErrUnavailable", err)
	}
}

func TestCreateRejectsRepositoryPayloadDivergence(t *testing.T) {
	t.Parallel()

	tenantID, userID, membershipID := alertTestID(61), alertTestID(62), alertTestID(63)
	input := validCreateInput(tenantID)
	normalized, err := normalizeCreateInput(input)
	if err != nil {
		t.Fatalf("normalizeCreateInput() error = %v", err)
	}
	params := CreateAsHumanParams{
		TenantID: tenantID, MembershipID: membershipID,
		Actor:   authorization.Actor{UserID: userID},
		Payload: createPayload(normalized),
	}
	bad := storedHumanAlert(params, alertTestID(64))
	bad.Title = "Unrelated alert"
	repository := &repositoryStub{
		resolveResult: humanAuthority(tenantID, userID, membershipID, true),
		humanResult:   IdempotentCreateResult{Alert: bad},
	}
	service := testService(t, repository)
	actor := authorization.Actor{
		UserID: userID, SessionID: alertTestID(65), ActiveTenantID: tenantID, AuthenticationMethod: "totp",
	}

	if _, err := service.CreateAsHuman(context.Background(), actor, tenantID, input); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("CreateAsHuman() error = %v, want ErrUnavailable", err)
	}
}

func TestCreateRejectsNonFreshProjection(t *testing.T) {
	t.Parallel()

	tenantID, userID, membershipID := alertTestID(66), alertTestID(67), alertTestID(68)
	input := validCreateInput(tenantID)
	normalized, err := normalizeCreateInput(input)
	if err != nil {
		t.Fatalf("normalizeCreateInput() error = %v", err)
	}
	stored := storedHumanAlert(CreateAsHumanParams{
		TenantID: tenantID, MembershipID: membershipID,
		Actor: authorization.Actor{UserID: userID}, Payload: createPayload(normalized),
	}, alertTestID(69))
	actor := authorization.Actor{
		UserID: userID, SessionID: alertTestID(79), ActiveTenantID: tenantID, AuthenticationMethod: "totp",
	}
	for _, test := range []struct {
		name   string
		mutate func(*Alert)
	}{
		{name: "non-new status", mutate: func(value *Alert) { value.Status = StatusInProgress }},
		{name: "advanced version", mutate: func(value *Alert) { value.Version = 2 }},
		{name: "advanced update timestamp", mutate: func(value *Alert) { value.UpdatedAt = value.CreatedAt.Add(time.Microsecond) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			bad := stored
			test.mutate(&bad)
			repository := &repositoryStub{
				resolveResult: humanAuthority(tenantID, userID, membershipID, true),
				humanResult:   IdempotentCreateResult{Alert: bad},
			}
			service := testService(t, repository)
			if _, err := service.CreateAsHuman(context.Background(), actor, tenantID, input); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("CreateAsHuman() error = %v, want ErrUnavailable", err)
			}
		})
	}
}

func TestCreateAsHumanReplayReturnsCurrentRepresentation(t *testing.T) {
	t.Parallel()

	tenantID, userID, membershipID := alertTestID(80), alertTestID(81), alertTestID(82)
	input := validCreateInput(tenantID)
	normalized, err := normalizeCreateInput(input)
	if err != nil {
		t.Fatalf("normalizeCreateInput() error = %v", err)
	}
	current := storedHumanAlert(CreateAsHumanParams{
		TenantID: tenantID, MembershipID: membershipID,
		Actor: authorization.Actor{UserID: userID}, Payload: createPayload(normalized),
	}, alertTestID(83))
	current.Title = "Triaged suspicious activity"
	current.Status = StatusInProgress
	current.Version = 2
	current.UpdatedAt = current.CreatedAt.Add(time.Minute)
	repository := &repositoryStub{
		resolveResult: humanAuthority(tenantID, userID, membershipID, true),
		humanResult:   IdempotentCreateResult{Alert: current, Replayed: true},
	}
	service := testService(t, repository)
	actor := authorization.Actor{
		UserID: userID, SessionID: alertTestID(84), ActiveTenantID: tenantID, AuthenticationMethod: "totp",
	}

	created, err := service.CreateAsHuman(context.Background(), actor, tenantID, input)
	if err != nil {
		t.Fatalf("CreateAsHuman() error = %v", err)
	}
	if created.Title != current.Title || created.Status != StatusInProgress || created.Version != 2 {
		t.Fatalf("replayed Alert = %#v, want current representation %#v", created, current)
	}
}

func TestCreateAsBearerReplayReturnsCurrentRepresentation(t *testing.T) {
	t.Parallel()

	tenantID := alertTestID(85)
	keyring, err := serviceaccount.NewCredentialKeyring(3, map[int16][]byte{3: bytes.Repeat([]byte{0xB3}, 32)})
	if err != nil {
		t.Fatalf("NewCredentialKeyring() error = %v", err)
	}
	issued, err := keyring.Issue()
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	input := validCreateInput(tenantID)
	normalized, err := normalizeCreateInput(input)
	if err != nil {
		t.Fatalf("normalizeCreateInput() error = %v", err)
	}
	current := storedMachineAlert(CreateAsServiceAccountParams{
		TenantID: tenantID, Payload: createPayload(normalized),
	}, alertTestID(86), alertTestID(87))
	current.Title = "Closed suspicious activity"
	current.Status = StatusClosed
	current.Version = 3
	current.UpdatedAt = current.CreatedAt.Add(2 * time.Minute)
	current.ClosedAt = &current.UpdatedAt
	repository := &repositoryStub{bearerResult: IdempotentCreateResult{Alert: current, Replayed: true}}
	service, err := NewService(repository, keyring)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	created, err := service.CreateAsBearer(context.Background(), tenantID, BearerCreateInput{
		CreateInput: input, Token: issued.Token,
	})
	if err != nil {
		t.Fatalf("CreateAsBearer() error = %v", err)
	}
	if created.Title != current.Title || created.Status != StatusClosed || created.Version != 3 {
		t.Fatalf("replayed Alert = %#v, want current representation %#v", created, current)
	}
}

func TestCreateRequestFingerprintIsCanonicalAndPayloadBound(t *testing.T) {
	t.Parallel()

	tenantID := alertTestID(70)
	first, err := normalizeCreateInput(validCreateInput(tenantID))
	if err != nil {
		t.Fatalf("normalizeCreateInput() error = %v", err)
	}
	second := first
	second.Title = "Different"
	if digestCreateRequest(first) == digestCreateRequest(second) {
		t.Fatal("title drift did not change the request digest")
	}
	withNilDescription := first
	withNilDescription.Description = nil
	empty := ""
	withEmptyDescription := first
	withEmptyDescription.Description = &empty
	if digestCreateRequest(withNilDescription) == digestCreateRequest(withEmptyDescription) {
		t.Fatal("nullable and present-empty representations collided")
	}
	if digestIdempotencyKey(first.IdempotencyKey) == digestIdempotencyKey(first.IdempotencyKey+"x") {
		t.Fatal("different idempotency keys collided")
	}
}

func testService(t *testing.T, repository Repository) *Service {
	t.Helper()
	keyring, err := serviceaccount.NewCredentialKeyring(1, map[int16][]byte{1: bytes.Repeat([]byte{0x91}, 32)})
	if err != nil {
		t.Fatalf("NewCredentialKeyring() error = %v", err)
	}
	service, err := NewService(repository, keyring)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

func validCreateInput(seed uuid.UUID) CreateInput {
	description := "A bounded description"
	return CreateInput{
		Title: "Suspicious activity", Description: &description, Severity: SeverityMedium,
		IdempotencyKey: "alert-create-retry-" + seed.String(), Audit: testAudit(seed),
	}
}

func testAudit(seed uuid.UUID) authorization.AuditContext {
	return authorization.AuditContext{
		RequestID: seed, CorrelationID: alertTestID(seed[15] + 1),
		RemoteAddress: netip.MustParseAddr("198.51.100.10"), UserAgent: "alert-service-test",
	}
}

func humanAuthority(tenantID, userID, membershipID uuid.UUID, allowed bool) authorization.TenantAuthority {
	authority := authorization.TenantAuthority{
		TenantID: tenantID, Principal: authorization.TenantPrincipal{ID: userID, Kind: authorization.PrincipalKindHuman},
		MembershipID: membershipID, MembershipStatus: authorization.MembershipStatusActive,
		LegacyRole: authorization.LegacyMembershipRoleAnalyst, EvaluatedAt: time.Date(2026, 8, 25, 1, 0, 0, 0, time.UTC),
	}
	if allowed {
		authority.Permissions = []authorization.ScopedPermission{{Permission: authorization.TenantPermissionAlertCreate, Scope: authorization.ScopeTenant}}
	}
	return authority
}

func storedHumanAlert(params CreateAsHumanParams, alertID uuid.UUID) Alert {
	createdAt := time.Date(2026, 8, 25, 1, 2, 3, 456000000, time.UTC)
	userID := params.Actor.UserID
	membershipID := params.MembershipID
	workflowID := alertTestID(88)
	if params.Payload.WorkflowID != nil {
		workflowID = *params.Payload.WorkflowID
	}
	version := int64(1)
	if params.Payload.AssignedTeamID != nil {
		version = 2
	}
	detectedAt := params.Payload.DetectedAt
	if detectedAt.IsZero() {
		detectedAt = createdAt
	}
	return Alert{
		ID: alertID, TenantID: params.TenantID, Number: "ALT-2026-000091", WorkflowID: workflowID,
		WorkflowVersion: 1, StateKey: "new", CustomerVisible: params.Payload.CustomerVisible,
		ExternalID: params.Payload.ExternalID, DeduplicationKey: params.Payload.DeduplicationKey,
		Title: params.Payload.Title, Description: params.Payload.Description, Status: StatusNew, Severity: params.Payload.Severity,
		Priority: params.Payload.Priority, Category: params.Payload.Category, Classification: params.Payload.Classification,
		Source: params.Payload.Source, SourceType: params.Payload.SourceType, Tags: params.Payload.Tags,
		CustomFields: params.Payload.CustomFields, CustomerCustomFields: map[string]any{}, RawPayload: params.Payload.RawPayload,
		AssignedTeamID: params.Payload.AssignedTeamID, AssigneeUserID: params.Payload.AssigneeUserID,
		CreatedByUserID: &userID, CreatedByMembershipID: &membershipID,
		DetectedAt: detectedAt, ReceivedAt: createdAt, CreatedAt: createdAt, UpdatedAt: createdAt, Version: version,
	}
}

func storedMachineAlert(params CreateAsServiceAccountParams, alertID, serviceAccountID uuid.UUID) Alert {
	createdAt := time.Date(2026, 8, 25, 1, 2, 3, 456000000, time.UTC)
	workflowID := alertTestID(89)
	if params.Payload.WorkflowID != nil {
		workflowID = *params.Payload.WorkflowID
	}
	detectedAt := params.Payload.DetectedAt
	if detectedAt.IsZero() {
		detectedAt = createdAt
	}
	return Alert{
		ID: alertID, TenantID: params.TenantID, Number: "ALT-2026-000092", WorkflowID: workflowID,
		WorkflowVersion: 1, StateKey: "new", CustomerVisible: params.Payload.CustomerVisible,
		ExternalID: params.Payload.ExternalID, DeduplicationKey: params.Payload.DeduplicationKey,
		Title: params.Payload.Title, Description: params.Payload.Description, Status: StatusNew, Severity: params.Payload.Severity,
		Priority: params.Payload.Priority, Category: params.Payload.Category, Classification: params.Payload.Classification,
		Source: params.Payload.Source, SourceType: params.Payload.SourceType, Tags: params.Payload.Tags,
		CustomFields: params.Payload.CustomFields, CustomerCustomFields: map[string]any{}, RawPayload: params.Payload.RawPayload,
		CreatedByServiceAccountID: &serviceAccountID,
		DetectedAt:                detectedAt, ReceivedAt: createdAt, CreatedAt: createdAt, UpdatedAt: createdAt, Version: 1,
	}
}

func alertTestID(last byte) uuid.UUID {
	value := uuid.MustParse("00000000-0000-7000-8000-000000000000")
	value[15] = last
	return value
}
