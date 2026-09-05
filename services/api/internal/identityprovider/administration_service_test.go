package identityprovider

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

var (
	testBindingID         = uuid.MustParse("00000000-0000-7000-8000-000000000120")
	testMappingID         = uuid.MustParse("00000000-0000-7000-8000-000000000121")
	testSecurityGroupID   = uuid.MustParse("00000000-0000-7000-8000-000000000122")
	testRoleID            = uuid.MustParse("00000000-0000-7000-8000-000000000123")
	testMappingAuditID    = uuid.MustParse("00000000-0000-7000-8000-000000000124")
	testMappingSourceID   = uuid.MustParse("00000000-0000-7000-8000-000000000125")
	testOperatorTeamID    = uuid.MustParse("00000000-0000-7000-8000-000000000126")
	testAssignmentEpochID = uuid.MustParse("00000000-0000-7000-8000-000000000127")
	testBindingPageID     = uuid.MustParse("00000000-0000-7000-8000-000000000128")
	testBindingTailID     = uuid.MustParse("00000000-0000-7000-8000-000000000129")
	testMappingPageID     = uuid.MustParse("00000000-0000-7000-8000-000000000130")
	testMappingTailID     = uuid.MustParse("00000000-0000-7000-8000-000000000131")
)

func TestAdministrationCreateBindingAuthorizesDigestsAndRejectsDivergentProjection(t *testing.T) {
	t.Parallel()

	base := &identityProviderRepositoryStub{}
	base.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderManage), nil
	}
	repository := &administrationRepositoryStub{identityProviderRepositoryStub: base}
	var received CreateBindingParams
	repository.createBinding = func(_ context.Context, params CreateBindingParams) (BindingMutationResult, error) {
		received = params
		return BindingMutationResult{Binding: testBinding(params.ProviderID)}, nil
	}
	service := testIdentityProviderService(t, repository, &diagnosticClientStub{})
	service.newID = func() (uuid.UUID, error) { return testMappingAuditID, nil }
	input := CreateBindingInput{
		ProviderID: testProviderID, LoginKey: "corp_ldap", ProfilePriority: 20,
		IdempotencyKey: "create-binding-0001", Audit: testAudit(),
	}

	result, err := service.CreateBinding(context.Background(), testActor(), testTenantID, input)
	if err != nil || result.ID != testBindingID {
		t.Fatalf("CreateBinding() = (%#v, %v)", result, err)
	}
	if received.IdempotencyKeyDigest != sha256.Sum256([]byte(input.IdempotencyKey)) ||
		received.AuditEventID != testMappingAuditID || received.MembershipID != testMembershipID ||
		received.OccurredAt != testNow {
		t.Fatalf("CreateBinding() params = %#v", received)
	}

	repository.createBinding = func(_ context.Context, params CreateBindingParams) (BindingMutationResult, error) {
		binding := testBinding(params.ProviderID)
		binding.LoginKey = "divergent"
		return BindingMutationResult{Binding: binding}, nil
	}
	if _, err := service.CreateBinding(context.Background(), testActor(), testTenantID, input); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("divergent CreateBinding() error = %v", err)
	}
}

func TestAdministrationMappingMutationRequiresEveryApplicationPermission(t *testing.T) {
	t.Parallel()

	base := &identityProviderRepositoryStub{}
	repository := &administrationRepositoryStub{identityProviderRepositoryStub: base}
	writeCalled := false
	repository.createMapping = func(_ context.Context, params CreateMappingParams) (MappingMutationResult, error) {
		writeCalled = true
		return MappingMutationResult{Mapping: testMapping(params)}, nil
	}
	service := testIdentityProviderService(t, repository, &diagnosticClientStub{})
	service.newID = func() (uuid.UUID, error) { return testMappingAuditID, nil }
	input := testCreateMappingInput()

	base.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testAdministrationAuthority(authorization.TenantPermissionIdentityMappingManage), nil
	}
	if _, err := service.CreateMapping(context.Background(), testActor(), testTenantID, input); !errors.Is(err, ErrForbidden) {
		t.Fatalf("CreateMapping() without role.grant error = %v", err)
	}
	if writeCalled {
		t.Fatal("mapping write reached repository without role.grant")
	}

	base.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testAdministrationAuthority(
			authorization.TenantPermissionIdentityMappingManage,
			authorization.TenantPermissionRoleGrant,
		), nil
	}
	result, err := service.CreateMapping(context.Background(), testActor(), testTenantID, input)
	if err != nil || result.ID != testMappingID || !writeCalled {
		t.Fatalf("CreateMapping() = (%#v, %v), write = %t", result, err, writeCalled)
	}

	writeCalled = false
	assignment := &OperatorTeamAssignmentTarget{
		OperatorTeamID: testOperatorTeamID, AssignmentEpochID: testAssignmentEpochID,
	}
	input.Target.OperatorTeamAssignment = assignment
	if _, err := service.CreateMapping(context.Background(), testActor(), testTenantID, input); !errors.Is(err, ErrForbidden) {
		t.Fatalf("CreateMapping() without roster authority error = %v", err)
	}
	if writeCalled {
		t.Fatal("operator-team mapping reached repository without exact roster authority")
	}

	base.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		authority := testAdministrationAuthority(
			authorization.TenantPermissionIdentityMappingManage,
			authorization.TenantPermissionRoleGrant,
			authorization.TenantPermissionOperatorTeamRosterManage,
		)
		authority.Permissions[2].Scope = authorization.ScopeOperatorTeam
		authority.OperatorTeamRelationships = []authorization.OperatorTeamRelationship{{
			OperatorTeamID: testOperatorTeamID, AssignmentEpochID: testAssignmentEpochID,
		}}
		return authority, nil
	}
	if _, err := service.CreateMapping(context.Background(), testActor(), testTenantID, input); err != nil {
		t.Fatalf("CreateMapping() with exact roster authority error = %v", err)
	}
}

func TestAdministrationListsFailClosedOnMalformedOrderingAndProjection(t *testing.T) {
	t.Parallel()

	base := &identityProviderRepositoryStub{}
	base.resolve = func(_ context.Context, _ authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testAdministrationAuthority(authorization.TenantPermissionIdentityProviderRead), nil
	}
	repository := &administrationRepositoryStub{identityProviderRepositoryStub: base}
	repository.listBindings = func(context.Context, ListBindingParams) ([]Binding, error) {
		first := testBinding(testProviderID)
		second := first
		second.ID = uuid.MustParse("00000000-0000-7000-8000-000000000119")
		return []Binding{first, second}, nil
	}
	service := testIdentityProviderService(t, repository, &diagnosticClientStub{})
	if _, err := service.ListBindings(context.Background(), testActor(), testTenantID, ListBindingsInput{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("non-monotonic ListBindings() error = %v", err)
	}

	base.resolve = func(_ context.Context, _ authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testAdministrationAuthority(authorization.TenantPermissionIdentityMappingRead), nil
	}
	repository.listMappings = func(context.Context, ListMappingParams) ([]Mapping, error) {
		mapping := testMapping(CreateMappingParams{
			BindingID: testBindingID, Matcher: testCreateMappingInput().Matcher,
			Priority: 10, Target: testCreateMappingInput().Target,
			ReconciliationMode: ReconciliationAdditive, Notes: "SOC access",
		})
		mapping.Enabled = true
		mapping.CurrentSourceEpoch = nil
		return []Mapping{mapping}, nil
	}
	if _, err := service.ListMappings(context.Background(), testActor(), testTenantID, ListMappingsInput{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("incoherent ListMappings() error = %v", err)
	}

	repository.listMappings = func(context.Context, ListMappingParams) ([]Mapping, error) {
		return []Mapping{testMapping(CreateMappingParams{
			BindingID: testBindingID, Matcher: testCreateMappingInput().Matcher,
			Priority: 10, Target: testCreateMappingInput().Target,
			ReconciliationMode: ReconciliationAdditive, Notes: "SOC access",
		})}, nil
	}
	after := MappingCursor{Priority: 10, ID: testMappingID}
	if _, err := service.ListMappings(context.Background(), testActor(), testTenantID, ListMappingsInput{
		After: &after,
	}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("non-advancing composite ListMappings() error = %v", err)
	}

	base.resolve = func(_ context.Context, _ authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testAdministrationAuthority(authorization.TenantPermissionIdentityProviderRead), nil
	}
	repository.listBindings = func(context.Context, ListBindingParams) ([]Binding, error) {
		binding := testBinding(testProviderID)
		archivedAt := binding.UpdatedAt.Add(time.Second)
		binding.ArchivedAt = &archivedAt
		return []Binding{binding}, nil
	}
	if _, err := service.ListBindings(context.Background(), testActor(), testTenantID, ListBindingsInput{
		IncludeArchived: true,
	}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("future binding archive error = %v", err)
	}

	base.resolve = func(_ context.Context, _ authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testAdministrationAuthority(authorization.TenantPermissionIdentityMappingRead), nil
	}
	repository.listMappings = func(context.Context, ListMappingParams) ([]Mapping, error) {
		mapping := testMapping(CreateMappingParams{
			BindingID: testBindingID, Matcher: testCreateMappingInput().Matcher,
			Priority: 10, Target: testCreateMappingInput().Target,
			ReconciliationMode: ReconciliationAdditive, Notes: "SOC access",
		})
		mapping.Enabled = true
		mapping.CurrentSourceEpoch = &MappingSourceEpoch{
			ID: testMappingSourceID, Sequence: 1, ReconciliationMode: ReconciliationAdditive,
			ActivatedAt: mapping.UpdatedAt.Add(time.Second),
		}
		return []Mapping{mapping}, nil
	}
	if _, err := service.ListMappings(context.Background(), testActor(), testTenantID, ListMappingsInput{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("future mapping epoch activation error = %v", err)
	}
}

func TestAdministrationBindingCRUDPaginationAndEntityTags(t *testing.T) {
	t.Parallel()

	base := &identityProviderRepositoryStub{}
	permission := authorization.TenantPermissionIdentityProviderRead
	base.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testAdministrationAuthority(permission), nil
	}
	repository := &administrationRepositoryStub{identityProviderRepositoryStub: base}
	service := testIdentityProviderService(t, repository, &diagnosticClientStub{})

	var listParams ListBindingParams
	repository.listBindings = func(_ context.Context, params ListBindingParams) ([]Binding, error) {
		listParams = params
		first := testBinding(testProviderID)
		second := first
		second.ID = testBindingPageID
		third := first
		third.ID = testBindingTailID
		return []Binding{first, second, third}, nil
	}
	page, err := service.ListBindings(context.Background(), testActor(), testTenantID, ListBindingsInput{
		PageInput: PageInput{Limit: 2},
	})
	if err != nil || len(page.Items) != 2 || page.NextCursor == nil || *page.NextCursor != testBindingPageID {
		t.Fatalf("ListBindings() = (%#v, %v)", page, err)
	}
	if listParams.Limit != 3 || listParams.MembershipID != testMembershipID || listParams.TenantID != testTenantID {
		t.Fatalf("ListBindings() params = %#v", listParams)
	}

	repository.getBinding = func(_ context.Context, params GetBindingParams) (Binding, error) {
		if params.BindingID != testBindingID {
			t.Fatalf("GetBinding() params = %#v", params)
		}
		return testBinding(testProviderID), nil
	}
	if result, getErr := service.GetBinding(context.Background(), testActor(), testTenantID, testBindingID); getErr != nil || result.ID != testBindingID {
		t.Fatalf("GetBinding() = (%#v, %v)", result, getErr)
	}

	permission = authorization.TenantPermissionIdentityProviderManage
	var updateParams UpdateBindingParams
	repository.updateBinding = func(_ context.Context, params UpdateBindingParams) (Binding, error) {
		updateParams = params
		result := testBinding(testProviderID)
		result.LoginKey = params.LoginKey
		result.ProfilePriority = params.ProfilePriority
		result.Enabled = params.Enabled
		result.Version = params.ExpectedVersion + 1
		result.UpdatedAt = params.OccurredAt
		if params.Enabled {
			epoch := testMappingSourceID
			result.CurrentAccessEpochID = &epoch
			result.AuthRevision = 2
		}
		return result, nil
	}
	etag := `"v1"`
	updated, err := service.UpdateBinding(context.Background(), testActor(), testTenantID, testBindingID, UpdateBindingInput{
		LoginKey: "corp_login", Enabled: true, ProfilePriority: 30,
		ExpectedEntityTag: &etag, Audit: testAudit(),
	})
	if err != nil || updated.Version != 2 || !updated.Enabled {
		t.Fatalf("UpdateBinding() = (%#v, %v)", updated, err)
	}
	if updateParams.ExpectedVersion != 1 || updateParams.OccurredAt != testNow || updateParams.MembershipID != testMembershipID {
		t.Fatalf("UpdateBinding() params = %#v", updateParams)
	}

	var archiveParams ArchiveBindingParams
	repository.archiveBinding = func(_ context.Context, params ArchiveBindingParams) (int64, error) {
		archiveParams = params
		return params.ExpectedVersion + 1, nil
	}
	etag = `"v2"`
	version, err := service.ArchiveBinding(context.Background(), testActor(), testTenantID, testBindingID, ArchiveBindingInput{
		Reason: "  Retire duplicate binding  ", ExpectedEntityTag: &etag, Audit: testAudit(),
	})
	if err != nil || version != 3 {
		t.Fatalf("ArchiveBinding() = (%d, %v)", version, err)
	}
	if archiveParams.Reason != "Retire duplicate binding" || archiveParams.ExpectedVersion != 2 {
		t.Fatalf("ArchiveBinding() params = %#v", archiveParams)
	}
}

func TestAdministrationMappingCRUDOrderingAndEntityTags(t *testing.T) {
	t.Parallel()

	base := &identityProviderRepositoryStub{}
	permissions := []authorization.TenantPermission{authorization.TenantPermissionIdentityMappingRead}
	base.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testAdministrationAuthority(permissions...), nil
	}
	repository := &administrationRepositoryStub{identityProviderRepositoryStub: base}
	service := testIdentityProviderService(t, repository, &diagnosticClientStub{})
	service.newID = func() (uuid.UUID, error) { return testMappingAuditID, nil }

	var listParams ListMappingParams
	repository.listMappings = func(_ context.Context, params ListMappingParams) ([]Mapping, error) {
		listParams = params
		first := testMapping(CreateMappingParams{
			BindingID: testBindingID, Matcher: testCreateMappingInput().Matcher, Priority: 10,
			Target: testCreateMappingInput().Target, ReconciliationMode: ReconciliationAdditive, Notes: "SOC access",
		})
		second := first
		second.ID = testMappingPageID
		third := first
		third.ID = testMappingTailID
		third.Priority = 20
		return []Mapping{first, second, third}, nil
	}
	after := MappingCursor{Priority: 9, ID: testMappingAuditID}
	page, err := service.ListMappings(context.Background(), testActor(), testTenantID, ListMappingsInput{
		After: &after, Limit: 2, BindingID: uuidPointer(testBindingID),
	})
	wantCursor := MappingCursor{Priority: 10, ID: testMappingPageID}
	if err != nil || len(page.Items) != 2 || page.NextCursor == nil || *page.NextCursor != wantCursor {
		t.Fatalf("ListMappings() = (%#v, %v)", page, err)
	}
	if listParams.After == nil || *listParams.After != after || listParams.Limit != 3 ||
		listParams.BindingID == nil || *listParams.BindingID != testBindingID {
		t.Fatalf("ListMappings() params = %#v", listParams)
	}

	repository.getMapping = func(_ context.Context, params GetMappingParams) (Mapping, error) {
		if params.MappingID != testMappingID {
			t.Fatalf("GetMapping() params = %#v", params)
		}
		return testMapping(CreateMappingParams{
			BindingID: testBindingID, Matcher: testCreateMappingInput().Matcher, Priority: 10,
			Target: testCreateMappingInput().Target, ReconciliationMode: ReconciliationAdditive, Notes: "SOC access",
		}), nil
	}
	if result, getErr := service.GetMapping(context.Background(), testActor(), testTenantID, testMappingID); getErr != nil || result.ID != testMappingID {
		t.Fatalf("GetMapping() = (%#v, %v)", result, getErr)
	}

	permissions = []authorization.TenantPermission{
		authorization.TenantPermissionIdentityMappingManage,
		authorization.TenantPermissionRoleGrant,
	}
	var updateParams UpdateMappingParams
	repository.updateMapping = func(_ context.Context, params UpdateMappingParams) (Mapping, error) {
		updateParams = params
		result := Mapping{
			ID: params.MappingID, TenantID: params.TenantID, BindingID: testBindingID,
			Matcher: params.Matcher, Priority: params.Priority, Target: params.Target,
			ReconciliationMode: params.ReconciliationMode, Enabled: params.Enabled, Notes: params.Notes,
			Version: params.ExpectedVersion + 1, CreatedAt: testNow, UpdatedAt: params.OccurredAt,
		}
		if params.Enabled {
			result.CurrentSourceEpoch = &MappingSourceEpoch{
				ID: testMappingSourceID, Sequence: 1,
				ReconciliationMode: params.ReconciliationMode, ActivatedAt: params.OccurredAt,
			}
		}
		return result, nil
	}
	etag := `"v1"`
	createInput := testCreateMappingInput()
	updated, err := service.UpdateMapping(context.Background(), testActor(), testTenantID, testMappingID, UpdateMappingInput{
		Matcher: createInput.Matcher, Priority: 25, Target: createInput.Target,
		ReconciliationMode: ReconciliationAuthoritative, Enabled: true,
		Notes: "Updated SOC access", Reason: "Activate reviewed mapping",
		ExpectedEntityTag: &etag, Audit: testAudit(),
	})
	if err != nil || updated.Version != 2 || updated.CurrentSourceEpoch == nil {
		t.Fatalf("UpdateMapping() = (%#v, %v)", updated, err)
	}
	if updateParams.AuditEventID != testMappingAuditID || updateParams.ExpectedVersion != 1 || updateParams.OccurredAt != testNow {
		t.Fatalf("UpdateMapping() params = %#v", updateParams)
	}

	var archiveParams ArchiveMappingParams
	repository.archiveMapping = func(_ context.Context, params ArchiveMappingParams) (int64, error) {
		archiveParams = params
		return params.ExpectedVersion + 1, nil
	}
	etag = `"v2"`
	version, err := service.ArchiveMapping(context.Background(), testActor(), testTenantID, testMappingID, ArchiveMappingInput{
		Reason: "  Retire superseded mapping  ", ExpectedEntityTag: &etag, Audit: testAudit(),
	})
	if err != nil || version != 3 {
		t.Fatalf("ArchiveMapping() = (%d, %v)", version, err)
	}
	if archiveParams.AuditEventID != testMappingAuditID || archiveParams.Reason != "Retire superseded mapping" {
		t.Fatalf("ArchiveMapping() params = %#v", archiveParams)
	}
}

func TestAdministrationCreateReplayReturnsCurrentRepresentation(t *testing.T) {
	t.Parallel()

	base := &identityProviderRepositoryStub{}
	base.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testAdministrationAuthority(
			authorization.TenantPermissionIdentityMappingManage,
			authorization.TenantPermissionRoleGrant,
		), nil
	}
	repository := &administrationRepositoryStub{identityProviderRepositoryStub: base}
	service := testIdentityProviderService(t, repository, &diagnosticClientStub{})
	service.newID = func() (uuid.UUID, error) { return testMappingAuditID, nil }

	repository.createBinding = func(_ context.Context, params CreateBindingParams) (BindingMutationResult, error) {
		result := testBinding(params.ProviderID)
		result.LoginKey = "current_login"
		result.ProfilePriority = 99
		result.Version = 5
		return BindingMutationResult{Binding: result, Replayed: true}, nil
	}
	base.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testAdministrationAuthority(authorization.TenantPermissionIdentityProviderManage), nil
	}
	binding, err := service.CreateBinding(context.Background(), testActor(), testTenantID, CreateBindingInput{
		ProviderID: testProviderID, LoginKey: "corp_ldap", ProfilePriority: 20,
		IdempotencyKey: "create-binding-0001", Audit: testAudit(),
	})
	if err != nil || binding.Version != 5 || binding.LoginKey != "current_login" {
		t.Fatalf("replayed CreateBinding() = (%#v, %v)", binding, err)
	}

	base.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testAdministrationAuthority(
			authorization.TenantPermissionIdentityMappingManage,
			authorization.TenantPermissionRoleGrant,
		), nil
	}
	repository.createMapping = func(_ context.Context, params CreateMappingParams) (MappingMutationResult, error) {
		result := testMapping(params)
		result.Matcher.Value = "CURRENT-SOC"
		result.Priority = 50
		result.Version = 4
		return MappingMutationResult{Mapping: result, Replayed: true}, nil
	}
	mapping, err := service.CreateMapping(context.Background(), testActor(), testTenantID, testCreateMappingInput())
	if err != nil || mapping.Version != 4 || mapping.Matcher.Value != "CURRENT-SOC" {
		t.Fatalf("replayed CreateMapping() = (%#v, %v)", mapping, err)
	}

	repository.createMapping = func(_ context.Context, params CreateMappingParams) (MappingMutationResult, error) {
		result := testMapping(params)
		result.Notes = ""
		return MappingMutationResult{Mapping: result}, nil
	}
	if _, err := service.CreateMapping(context.Background(), testActor(), testTenantID, testCreateMappingInput()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("divergent CreateMapping() error = %v", err)
	}
}

func TestAdministrationRepositoryErrorsAndMissingPermissionsFailClosed(t *testing.T) {
	t.Parallel()

	base := &identityProviderRepositoryStub{}
	repository := &administrationRepositoryStub{identityProviderRepositoryStub: base}
	service := testIdentityProviderService(t, repository, &diagnosticClientStub{})

	base.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testAdministrationAuthority(authorization.TenantPermissionIdentityProviderRead), nil
	}
	repository.listBindings = func(context.Context, ListBindingParams) ([]Binding, error) {
		return nil, context.Canceled
	}
	if _, err := service.ListBindings(context.Background(), testActor(), testTenantID, ListBindingsInput{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("ListBindings() cancellation = %v", err)
	}

	base.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testAdministrationAuthority(authorization.TenantPermissionIdentityMappingManage), nil
	}
	called := false
	repository.updateMapping = func(context.Context, UpdateMappingParams) (Mapping, error) {
		called = true
		return Mapping{}, nil
	}
	etag := `"v1"`
	input := testCreateMappingInput()
	if _, err := service.UpdateMapping(context.Background(), testActor(), testTenantID, testMappingID, UpdateMappingInput{
		Matcher: input.Matcher, Priority: input.Priority, Target: input.Target,
		ReconciliationMode: input.ReconciliationMode, Notes: input.Notes, Reason: "Update mapping",
		ExpectedEntityTag: &etag, Audit: testAudit(),
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("UpdateMapping() without role.grant = %v", err)
	}
	if called {
		t.Fatal("UpdateMapping() reached repository without role.grant")
	}

	repository.archiveMapping = func(context.Context, ArchiveMappingParams) (int64, error) {
		called = true
		return 2, nil
	}
	if _, err := service.ArchiveMapping(context.Background(), testActor(), testTenantID, testMappingID, ArchiveMappingInput{
		Reason: "Archive mapping", ExpectedEntityTag: &etag, Audit: testAudit(),
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ArchiveMapping() without role.grant = %v", err)
	}
	if called {
		t.Fatal("ArchiveMapping() reached repository without role.grant")
	}

	base.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testAdministrationAuthority(authorization.TenantPermissionIdentityProviderManage), nil
	}
	repository.updateBinding = func(context.Context, UpdateBindingParams) (Binding, error) {
		return Binding{}, ErrPreconditionFailed
	}
	if _, err := service.UpdateBinding(context.Background(), testActor(), testTenantID, testBindingID, UpdateBindingInput{
		LoginKey: "corp_ldap", ProfilePriority: 20, ExpectedEntityTag: &etag, Audit: testAudit(),
	}); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("UpdateBinding() stale ETag error = %v", err)
	}
}

func testBinding(providerID uuid.UUID) Binding {
	return Binding{
		ID: testBindingID, TenantID: testTenantID, ProviderID: providerID,
		LoginKey: "corp_ldap", ProfilePriority: 20, AuthRevision: 1,
		Version: 1, CreatedAt: testNow, UpdatedAt: testNow,
	}
}

func testCreateMappingInput() CreateMappingInput {
	return CreateMappingInput{
		BindingID:          testBindingID,
		Matcher:            MappingMatcher{Type: MappingMatcherExactCN, Value: "SOC-L2", CaseMode: MappingCaseInsensitive},
		Priority:           10,
		Target:             MappingTarget{TenantSecurityGroupID: testSecurityGroupID, RoleIDs: []uuid.UUID{testRoleID}},
		ReconciliationMode: ReconciliationAdditive,
		Notes:              "SOC access", Reason: "Create mapping",
		IdempotencyKey: "create-mapping-0001", Audit: testAudit(),
	}
}

func testMapping(params CreateMappingParams) Mapping {
	return Mapping{
		ID: testMappingID, TenantID: testTenantID, BindingID: params.BindingID,
		Matcher: params.Matcher, Priority: params.Priority, Target: params.Target,
		ReconciliationMode: params.ReconciliationMode, Notes: params.Notes,
		Version: 1, CreatedAt: testNow, UpdatedAt: testNow,
	}
}

func uuidPointer(value uuid.UUID) *uuid.UUID {
	return &value
}

func testAdministrationAuthority(permissions ...authorization.TenantPermission) authorization.TenantAuthority {
	authority := testIdentityProviderAuthority(permissions[0])
	authority.Permissions = make([]authorization.ScopedPermission, 0, len(permissions))
	for _, permission := range permissions {
		authority.Permissions = append(authority.Permissions, authorization.ScopedPermission{
			Permission: permission, Scope: authorization.ScopeTenant,
		})
	}
	return authority
}

type administrationRepositoryStub struct {
	*identityProviderRepositoryStub
	listBindings   func(context.Context, ListBindingParams) ([]Binding, error)
	getBinding     func(context.Context, GetBindingParams) (Binding, error)
	createBinding  func(context.Context, CreateBindingParams) (BindingMutationResult, error)
	updateBinding  func(context.Context, UpdateBindingParams) (Binding, error)
	archiveBinding func(context.Context, ArchiveBindingParams) (int64, error)
	listMappings   func(context.Context, ListMappingParams) ([]Mapping, error)
	getMapping     func(context.Context, GetMappingParams) (Mapping, error)
	createMapping  func(context.Context, CreateMappingParams) (MappingMutationResult, error)
	updateMapping  func(context.Context, UpdateMappingParams) (Mapping, error)
	archiveMapping func(context.Context, ArchiveMappingParams) (int64, error)
}

func (s *administrationRepositoryStub) ListBindings(ctx context.Context, params ListBindingParams) ([]Binding, error) {
	return s.listBindings(ctx, params)
}
func (s *administrationRepositoryStub) GetBinding(ctx context.Context, params GetBindingParams) (Binding, error) {
	return s.getBinding(ctx, params)
}
func (s *administrationRepositoryStub) CreateBinding(ctx context.Context, params CreateBindingParams) (BindingMutationResult, error) {
	return s.createBinding(ctx, params)
}
func (s *administrationRepositoryStub) UpdateBinding(ctx context.Context, params UpdateBindingParams) (Binding, error) {
	return s.updateBinding(ctx, params)
}
func (s *administrationRepositoryStub) ArchiveBinding(ctx context.Context, params ArchiveBindingParams) (int64, error) {
	return s.archiveBinding(ctx, params)
}
func (s *administrationRepositoryStub) ListMappings(ctx context.Context, params ListMappingParams) ([]Mapping, error) {
	return s.listMappings(ctx, params)
}
func (s *administrationRepositoryStub) GetMapping(ctx context.Context, params GetMappingParams) (Mapping, error) {
	return s.getMapping(ctx, params)
}
func (s *administrationRepositoryStub) CreateMapping(ctx context.Context, params CreateMappingParams) (MappingMutationResult, error) {
	return s.createMapping(ctx, params)
}
func (s *administrationRepositoryStub) UpdateMapping(ctx context.Context, params UpdateMappingParams) (Mapping, error) {
	return s.updateMapping(ctx, params)
}
func (s *administrationRepositoryStub) ArchiveMapping(ctx context.Context, params ArchiveMappingParams) (int64, error) {
	return s.archiveMapping(ctx, params)
}
