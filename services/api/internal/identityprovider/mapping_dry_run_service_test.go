package identityprovider

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

var (
	testMappingDryRunEpochID  = uuid.MustParse("00000000-0000-7000-8000-000000000140")
	testMappingDryRunAccessID = uuid.MustParse("00000000-0000-7000-8000-000000000141")
)

func TestServiceMappingDryRunUsesCommittedPinsDigestLookupAndSharedPlanner(t *testing.T) {
	t.Parallel()

	service, repository, observer := testMappingDryRunService(t)
	order := make([]string, 0, 4)
	var capturedAliases []identity.SubjectAlias
	repository.beginDryRun = func(_ context.Context, params BeginMappingDryRunParams) (DirectoryOperationSnapshot, error) {
		order = append(order, "begin")
		if params.BindingID != testBindingID || params.Reason != mappingDryRunReason ||
			params.OperationRunID != testRunID || params.AuditEventID != testDirectoryBeginAuditID ||
			len(params.IncludeDisabledMappingIDs) != 0 {
			t.Fatalf("begin dry-run params = %#v", params)
		}
		return repository.snapshot(params), nil
	}
	observer.observe = func(_ context.Context, request ldapclient.DirectoryRequest, secret []byte) (ldapclient.DirectoryResult, error) {
		order = append(order, "network")
		if !reflect.DeepEqual(order, []string{"begin", "network"}) || string(secret) != "directory-secret" ||
			len(request.Configuration.Endpoints) != 1 || request.Username.String() == "alice" {
			t.Fatalf("directory request = order %v, secret %q, request %#v", order, secret, request)
		}
		clear(secret)
		return successfulMappingDryRunDirectoryResult(), nil
	}
	repository.planning = func(_ context.Context, params GetMappingDryRunPlanningSnapshotParams) (MappingDryRunPlanningSnapshot, error) {
		order = append(order, "planning")
		capturedAliases = params.SubjectAliases
		if len(params.SubjectAliases) != 1 || params.SubjectAliases[0].KeyVersion != 1 ||
			params.SubjectAliases[0].Digest == ([32]byte{}) {
			t.Fatalf("digest-only planning lookup = %#v", params.SubjectAliases)
		}
		return repository.planningSnapshot(), nil
	}
	repository.complete = func(ctx context.Context, params CompleteDirectoryInspectionParams) (DirectoryInspectionCompletion, error) {
		order = append(order, "complete")
		if ctx.Err() != nil || params.ReportedOutcome != TestOutcomeSuccess ||
			params.ReportedCategory != TestCategorySuccess || params.EndpointPriority == nil ||
			*params.EndpointPriority != 1 || params.MatchedEntryCount != 1 || params.Truncated {
			t.Fatalf("dry-run completion = context %v, params %#v", ctx.Err(), params)
		}
		return echoDirectoryCompletion(params), nil
	}

	result, err := service.DryRunMappings(
		context.Background(),
		testActor(),
		testTenantID,
		DryRunInput{BindingID: testBindingID, Username: "alice", Audit: testAudit()},
	)
	if err != nil {
		t.Fatalf("DryRunMappings() error = %v", err)
	}
	if !reflect.DeepEqual(order, []string{"begin", "network", "planning", "complete"}) ||
		result.ID != testRunID || result.Outcome != "success" || result.Decision != "allow" ||
		result.IdentityDisposition != "create" || !result.ObservationComplete ||
		len(result.DenialReasons) != 0 || !reflect.DeepEqual(result.MatchedMappingIDs, []uuid.UUID{testMappingID}) ||
		result.Snapshot.ProviderID != testProviderID || result.Snapshot.BindingID != testBindingID ||
		result.Snapshot.AccessEpochID != testMappingDryRunAccessID ||
		result.Plan.ProfileAction != "create" || result.Plan.ProviderAccessAction != DryRunActionAdd ||
		len(result.Plan.GroupActions) != 1 || result.Plan.GroupActions[0].TenantSecurityGroupID != testSecurityGroupID ||
		result.Plan.GroupActions[0].Action != DryRunActionAdd ||
		!reflect.DeepEqual(result.Plan.GroupActions[0].SourceMappingIDs, []uuid.UUID{testMappingID}) ||
		len(result.Plan.RoleActions) != 1 || result.Plan.RoleActions[0].RoleID != testRoleID ||
		result.Plan.RoleActions[0].Action != DryRunActionAdd || len(result.Plan.OperatorTeamActions) != 0 {
		t.Fatalf("mapping dry-run result = %#v, order = %v", result, order)
	}
	if len(capturedAliases) != 1 || capturedAliases[0].Digest != ([32]byte{}) {
		t.Fatalf("post-network lookup digest was not cleared: %#v", capturedAliases)
	}
}

func TestServiceMappingDryRunReturnsBoundedExpectedDenialWithoutDigestLookup(t *testing.T) {
	t.Parallel()

	service, repository, observer := testMappingDryRunService(t)
	order := make([]string, 0, 3)
	repository.beginDryRun = func(_ context.Context, params BeginMappingDryRunParams) (DirectoryOperationSnapshot, error) {
		order = append(order, "begin")
		return repository.snapshot(params), nil
	}
	observer.observe = func(_ context.Context, _ ldapclient.DirectoryRequest, secret []byte) (ldapclient.DirectoryResult, error) {
		order = append(order, "network")
		clear(secret)
		return ldapclient.DirectoryResult{
			Category: ldapclient.DirectoryCategoryUserNotFound, EndpointPriority: 1,
		}, nil
	}
	repository.planning = func(context.Context, GetMappingDryRunPlanningSnapshotParams) (MappingDryRunPlanningSnapshot, error) {
		t.Fatal("identity-not-found result must not perform a subject lookup")
		return MappingDryRunPlanningSnapshot{}, nil
	}
	repository.complete = func(_ context.Context, params CompleteDirectoryInspectionParams) (DirectoryInspectionCompletion, error) {
		order = append(order, "complete")
		if params.ReportedOutcome != TestOutcomeFailure || params.ReportedCategory != TestCategoryProtocolFailed ||
			params.EndpointPriority == nil || *params.EndpointPriority != 1 || params.MatchedEntryCount != 0 {
			t.Fatalf("not-found completion = %#v", params)
		}
		return echoDirectoryCompletion(params), nil
	}

	result, err := service.DryRunMappings(
		context.Background(), testActor(), testTenantID,
		DryRunInput{BindingID: testBindingID, Username: "missing", Audit: testAudit()},
	)
	if err != nil || !reflect.DeepEqual(order, []string{"begin", "network", "complete"}) ||
		result.Outcome != "failure" || result.Decision != "deny" ||
		result.IdentityDisposition != "unresolved" || result.ObservationComplete ||
		!reflect.DeepEqual(result.DenialReasons, []string{"identity_not_found"}) ||
		result.Plan.ProfileAction != "none" || result.Plan.ProviderAccessAction != DryRunActionNone ||
		len(result.Plan.GroupActions) != 0 || len(result.MatchedMappingIDs) != 0 {
		t.Fatalf("not-found dry-run = %#v, %v, order %v", result, err, order)
	}
}

func TestServiceMappingDryRunDiscardsPlanWhenCompletionMarksSnapshotStale(t *testing.T) {
	t.Parallel()

	service, repository, observer := testMappingDryRunService(t)
	repository.beginDryRun = func(_ context.Context, params BeginMappingDryRunParams) (DirectoryOperationSnapshot, error) {
		return repository.snapshot(params), nil
	}
	observer.observe = func(_ context.Context, _ ldapclient.DirectoryRequest, secret []byte) (ldapclient.DirectoryResult, error) {
		clear(secret)
		return successfulMappingDryRunDirectoryResult(), nil
	}
	repository.planning = func(context.Context, GetMappingDryRunPlanningSnapshotParams) (MappingDryRunPlanningSnapshot, error) {
		return repository.planningSnapshot(), nil
	}
	repository.complete = func(_ context.Context, params CompleteDirectoryInspectionParams) (DirectoryInspectionCompletion, error) {
		return DirectoryInspectionCompletion{Diagnostic: TestResult{
			TestRunID: params.OperationRunID, Outcome: TestOutcomeInconclusive,
			Category: TestCategoryStaleConfiguration, Duration: params.Duration,
			Stale: true, CompletedAt: params.OccurredAt,
		}}, nil
	}

	result, err := service.DryRunMappings(
		context.Background(), testActor(), testTenantID,
		DryRunInput{BindingID: testBindingID, Username: "alice", Audit: testAudit()},
	)
	if err != nil || result.Outcome != "inconclusive" || result.Decision != "deny" ||
		result.IdentityDisposition != "unresolved" || result.ObservationComplete ||
		!reflect.DeepEqual(result.DenialReasons, []string{"stale_snapshot"}) ||
		len(result.MatchedMappingIDs) != 0 || result.Plan.ProfileAction != "none" ||
		len(result.Plan.GroupActions) != 0 || len(result.Plan.RoleActions) != 0 {
		t.Fatalf("stale dry-run = %#v, %v", result, err)
	}
}

func TestServiceMappingDryRunCompletesAfterCancellationAndRequiresBothPermissions(t *testing.T) {
	t.Parallel()

	t.Run("cancellation", func(t *testing.T) {
		service, repository, observer := testMappingDryRunService(t)
		ctx, cancel := context.WithCancel(context.Background())
		repository.beginDryRun = func(_ context.Context, params BeginMappingDryRunParams) (DirectoryOperationSnapshot, error) {
			return repository.snapshot(params), nil
		}
		observer.observe = func(_ context.Context, _ ldapclient.DirectoryRequest, secret []byte) (ldapclient.DirectoryResult, error) {
			clear(secret)
			cancel()
			return ldapclient.DirectoryResult{Category: ldapclient.DirectoryCategoryCancelled}, nil
		}
		completed := false
		repository.complete = func(completionContext context.Context, params CompleteDirectoryInspectionParams) (DirectoryInspectionCompletion, error) {
			if completionContext.Err() != nil || params.ReportedCategory != TestCategoryCancelled ||
				params.EndpointPriority != nil || params.MatchedEntryCount != 0 {
				t.Fatalf("cancelled dry-run completion = context %v, params %#v", completionContext.Err(), params)
			}
			completed = true
			return echoDirectoryCompletion(params), nil
		}
		_, err := service.DryRunMappings(
			ctx, testActor(), testTenantID,
			DryRunInput{BindingID: testBindingID, Username: "alice", Audit: testAudit()},
		)
		if !errors.Is(err, context.Canceled) || !completed {
			t.Fatalf("cancelled DryRunMappings() = %v, completed %t", err, completed)
		}
	})

	t.Run("missing provider test", func(t *testing.T) {
		service, repository, _ := testMappingDryRunService(t)
		repository.identityProviderRepositoryStub.resolve = func(
			context.Context,
			authorization.ResolveAuthorityParams,
		) (authorization.TenantAuthority, error) {
			return testAdministrationAuthority(authorization.TenantPermissionIdentityMappingManage), nil
		}
		beginCalled := false
		repository.beginDryRun = func(context.Context, BeginMappingDryRunParams) (DirectoryOperationSnapshot, error) {
			beginCalled = true
			return DirectoryOperationSnapshot{}, nil
		}
		_, err := service.DryRunMappings(
			context.Background(), testActor(), testTenantID,
			DryRunInput{BindingID: testBindingID, Username: "alice", Audit: testAudit()},
		)
		if !errors.Is(err, ErrForbidden) || beginCalled {
			t.Fatalf("missing provider-test permission = %v, begin called %t", err, beginCalled)
		}
	})

	t.Run("sanitized network diagnostic", func(t *testing.T) {
		service, repository, observer := testMappingDryRunService(t)
		repository.beginDryRun = func(_ context.Context, params BeginMappingDryRunParams) (DirectoryOperationSnapshot, error) {
			return repository.snapshot(params), nil
		}
		observer.observe = func(_ context.Context, _ ldapclient.DirectoryRequest, secret []byte) (ldapclient.DirectoryResult, error) {
			clear(secret)
			return ldapclient.DirectoryResult{
				Category: ldapclient.DirectoryCategoryTLSFailed, EndpointPriority: 1,
			}, nil
		}
		repository.complete = func(_ context.Context, params CompleteDirectoryInspectionParams) (DirectoryInspectionCompletion, error) {
			if params.ReportedCategory != TestCategoryTLSFailed || params.EndpointPriority == nil ||
				*params.EndpointPriority != 1 || params.MatchedEntryCount != 0 {
				t.Fatalf("TLS failure completion = %#v", params)
			}
			return echoDirectoryCompletion(params), nil
		}
		_, err := service.DryRunMappings(
			context.Background(), testActor(), testTenantID,
			DryRunInput{BindingID: testBindingID, Username: "alice", Audit: testAudit()},
		)
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("TLS failure error = %v", err)
		}
	})
}

type mappingDryRunRepositoryStub struct {
	*directoryInspectionRepositoryStub
	beginDryRun func(context.Context, BeginMappingDryRunParams) (DirectoryOperationSnapshot, error)
	planning    func(context.Context, GetMappingDryRunPlanningSnapshotParams) (MappingDryRunPlanningSnapshot, error)
}

func (s *mappingDryRunRepositoryStub) BeginMappingDryRun(
	ctx context.Context,
	params BeginMappingDryRunParams,
) (DirectoryOperationSnapshot, error) {
	return s.beginDryRun(ctx, params)
}

func (s *mappingDryRunRepositoryStub) GetMappingDryRunPlanningSnapshot(
	ctx context.Context,
	params GetMappingDryRunPlanningSnapshotParams,
) (MappingDryRunPlanningSnapshot, error) {
	return s.planning(ctx, params)
}

func (s *mappingDryRunRepositoryStub) snapshot(params BeginMappingDryRunParams) DirectoryOperationSnapshot {
	bindingID := params.BindingID
	bindingVersion := int64(5)
	bindingAuthRevision := 7
	accessEpochID := testMappingDryRunAccessID
	ruleSetRevision := int64(11)
	authorizationRevision := int64(13)
	sourceEpochID := testMappingDryRunEpochID
	sourceSequence := 2
	return DirectoryOperationSnapshot{
		OperationRunID: params.OperationRunID, TenantID: params.TenantID,
		ProviderID: testProviderID, OperationKind: DirectoryOperationSearchUser,
		ProviderVersion: 2, ConfigurationVersion: 3,
		EndpointSnapshotDigest: [32]byte{1}, Configuration: s.configuration,
		Endpoints: testEndpoints(), SecretVersion: 4, Secret: s.secret,
		BindingID: &bindingID, BindingVersion: &bindingVersion,
		BindingAuthRevision: &bindingAuthRevision, BindingAccessEpochID: &accessEpochID,
		RuleSetRevision: &ruleSetRevision, AuthorizationRevision: &authorizationRevision,
		MappingRevisions: []PinnedMappingRevision{{
			MappingID: testMappingID, MappingVersion: 2,
			SourceEpochID: &sourceEpochID, SourceEpochSequence: &sourceSequence,
		}},
		StartedAt: testNow, ExpiresAt: testNow.Add(time.Minute),
	}
}

func (s *mappingDryRunRepositoryStub) planningSnapshot() MappingDryRunPlanningSnapshot {
	tenantEntity := identity.EntityID(testTenantID)
	providerEntity := identity.EntityID(testProviderID)
	bindingEntity := identity.EntityID(testBindingID)
	accessEntity := identity.EntityID(testMappingDryRunAccessID)
	ruleEpochEntity := identity.EntityID(testMappingDryRunEpochID)
	mappingEntity := identity.EntityID(testMappingID)
	sourceEntity := identity.EntityID(testMappingSourceID)
	groupEntity := identity.EntityID(testSecurityGroupID)
	roleEntity := identity.EntityID(testRoleID)
	matcher, err := identity.CompileLDAPGroupMatcher(identity.LDAPGroupMatcherSpec{
		Kind: identity.LDAPGroupMatcherExactDN, CaseMode: identity.LDAPGroupCaseInsensitive,
		Pattern: "cn=SOC,ou=groups,dc=example,dc=com",
	})
	if err != nil {
		panic(err)
	}
	return MappingDryRunPlanningSnapshot{
		OperationRunID: testRunID, ProviderID: testProviderID, ProviderVersion: 2,
		BindingID: testBindingID, BindingVersion: 5, BindingAuthRevision: 7,
		BindingAccessEpochID:  testMappingDryRunAccessID,
		ConfigurationRevision: 3, RuleSetRevision: 11, AuthorizationRevision: 13,
		Planning: identity.LDAPPlanningSnapshot{
			TenantID: tenantEntity,
			Provider: identity.ProviderContext{
				Scope: identity.TenantProviderScope, TenantID: tenantEntity, ProviderID: providerEntity,
			},
			BindingID: bindingEntity, ConfigurationRevision: 3,
			RuleSetRevision: 11, AuthorizationRevision: 13,
			JITMode: identity.LDAPJITCreate, NoMatchPolicy: identity.LDAPNoMatchDeny,
			ProviderAccess: identity.LDAPProviderAccessState{
				SourceID: identity.EntityID(testMappingDryRunAccessID), AccessEpochID: accessEntity,
			},
			Rules: []identity.LDAPMappingRule{{
				RuleID: mappingEntity, RuleEpochID: ruleEpochEntity, SourceID: sourceEntity,
				Revision: 2, Priority: 10, Enabled: true, Matcher: matcher,
				Mode:            identity.LDAPReconciliationAuthoritative,
				SecurityGroupID: groupEntity, RoleIDs: []identity.EntityID{roleEntity},
			}},
			SecurityGroups:           []identity.LDAPSecurityGroupPolicy{{SecurityGroupID: groupEntity}},
			LiveAssignments:          []identity.LDAPOperatorTeamAssignment{},
			RolePolicies:             []identity.LDAPRolePolicy{{RoleID: roleEntity}},
			ExistingEffectiveRoleIDs: []identity.EntityID{},
			Delegation:               []identity.LDAPDelegationGrant{},
			LiveOwnedEdges:           []identity.LDAPOwnedMappingEdge{},
		},
	}
}

type mappingDryRunClientStub struct {
	*diagnosticClientStub
	observe func(context.Context, ldapclient.DirectoryRequest, []byte) (ldapclient.DirectoryResult, error)
}

func (s *mappingDryRunClientStub) ObserveDirectory(
	ctx context.Context,
	request ldapclient.DirectoryRequest,
	secret []byte,
) (ldapclient.DirectoryResult, error) {
	return s.observe(ctx, request, secret)
}

func testMappingDryRunService(
	t *testing.T,
) (*Service, *mappingDryRunRepositoryStub, *mappingDryRunClientStub) {
	t.Helper()
	keyring := testIdentityKeyring(t)
	plaintext := []byte("directory-secret")
	envelope, err := keyring.EncryptBindSecret(
		bindSecretContext(testTenantID, testProviderID, testSecretID),
		plaintext,
	)
	clear(plaintext)
	if err != nil {
		t.Fatalf("EncryptBindSecret() error = %v", err)
	}
	configuration := testConfiguration()
	configuration.JITMode = JITModeCreate
	configuration.GroupMembershipAttribute = stringPointer("memberOf")
	base := &identityProviderRepositoryStub{}
	base.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testAdministrationAuthority(
			authorization.TenantPermissionIdentityMappingManage,
			authorization.TenantPermissionIdentityProviderTest,
		), nil
	}
	directoryRepository := &directoryInspectionRepositoryStub{
		identityProviderRepositoryStub: base,
		configuration:                  configuration,
		secret:                         EncryptedBindSecret{SecretID: testSecretID, Envelope: envelope},
	}
	repository := &mappingDryRunRepositoryStub{directoryInspectionRepositoryStub: directoryRepository}
	client := &mappingDryRunClientStub{diagnosticClientStub: &diagnosticClientStub{}}
	service, err := NewService(repository, keyring, client)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	service.now = func() time.Time { return testNow }
	identifiers := []uuid.UUID{testRunID, testDirectoryBeginAuditID, testDirectoryEndAuditID}
	service.newID = func() (uuid.UUID, error) {
		if len(identifiers) == 0 {
			return uuid.Nil, errors.New("unexpected identifier request")
		}
		value := identifiers[0]
		identifiers = identifiers[1:]
		return value, nil
	}
	return service, repository, client
}

func successfulMappingDryRunDirectoryResult() ldapclient.DirectoryResult {
	return ldapclient.DirectoryResult{
		Category: ldapclient.DirectoryCategorySuccess, EndpointPriority: 1,
		Observation: ldapclient.DirectoryObservation{
			User: ldapclient.DirectoryEntry{
				DistinguishedName: "uid=alice,ou=users,dc=example,dc=com",
				Attributes: []ldapclient.DirectoryAttribute{
					{Name: "givenName", Values: [][]byte{[]byte("Alice")}},
					{Name: "sn", Values: [][]byte{[]byte("Example")}},
					{Name: "displayName", Values: [][]byte{[]byte("Alice Example")}},
					{Name: "uid", Values: [][]byte{[]byte("alice")}},
					{Name: "entryUUID", Values: [][]byte{[]byte("550e8400-e29b-41d4-a716-446655440000")}},
					{Name: "memberOf", Values: [][]byte{[]byte("cn=SOC,ou=groups,dc=example,dc=com")}},
				},
			},
			Groups: []ldapclient.DirectoryEntry{{
				DistinguishedName: "cn=SOC,ou=groups,dc=example,dc=com",
			}},
		},
	}
}
