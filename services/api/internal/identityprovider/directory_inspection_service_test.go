package identityprovider

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

var (
	testDirectoryBeginAuditID = uuid.MustParse("00000000-0000-7000-8000-00000000010a")
	testDirectoryEndAuditID   = uuid.MustParse("00000000-0000-7000-8000-00000000010b")
)

func TestServiceSearchUserCommitsBeforeNetworkAndReturnsOnlyRedactedShape(t *testing.T) {
	t.Parallel()

	configuration := testConfiguration()
	configuration.GroupMembershipAttribute = stringPointer("memberOf")
	service, repository, inspector := testDirectoryInspectionService(t, configuration)
	order := make([]string, 0, 3)
	repository.begin = func(_ context.Context, params BeginAdministrativeDirectoryInspectionParams) (DirectoryOperationSnapshot, error) {
		order = append(order, "begin")
		if params.OperationKind != DirectoryOperationSearchUser || params.Reason != directoryUserSearchReason ||
			params.ProviderID != testProviderID || params.AuditEventID != testDirectoryBeginAuditID {
			t.Fatalf("begin params = %#v", params)
		}
		return repository.snapshot(params), nil
	}
	inspector.search = func(_ context.Context, request ldapclient.DirectorySearchUserRequest, secret []byte) (ldapclient.DirectoryInspectionResult, error) {
		order = append(order, "network")
		if !reflect.DeepEqual(order, []string{"begin", "network"}) {
			t.Fatalf("operation order before network = %v", order)
		}
		if string(secret) != "directory-secret" {
			t.Fatalf("service-bind secret = %q", secret)
		}
		if len(request.Configuration.Network.Endpoints) != 1 ||
			!request.Configuration.Network.Endpoints[0].Enabled ||
			request.Configuration.Network.Endpoints[0].ReferralAllowed {
			t.Fatalf("network endpoint flags = %#v", request.Configuration.Network.Endpoints)
		}
		if request.UserBaseDN != configuration.UserBaseDN ||
			!slicesContainAll(request.Attributes, "displayname", "entryuuid", "givenname", "memberof", "sn", "uid") {
			t.Fatalf("user inspection shape = base %q, attributes %v", request.UserBaseDN, request.Attributes)
		}
		clear(secret)
		return ldapclient.DirectoryInspectionResult{
			Category: ldapclient.DirectoryCategorySuccess, EndpointPriority: 1, Truncated: true,
			Entries: []ldapclient.DirectoryEntry{{
				DistinguishedName: "uid=alice,ou=users,dc=example,dc=com",
				Attributes: []ldapclient.DirectoryAttribute{
					{Name: "displayname", Values: [][]byte{[]byte("Alice Example")}},
					{Name: "entryuuid", Values: [][]byte{[]byte("secret-immutable-subject")}},
					{Name: "memberof", Values: [][]byte{[]byte("cn=one,dc=example,dc=com"), []byte("cn=two,dc=example,dc=com")}},
					{Name: "uid", Values: [][]byte{[]byte("alice")}},
				},
			}},
		}, nil
	}
	repository.complete = echoDirectoryInspectionCompletion(t, &order)

	result, err := service.SearchUser(
		context.Background(), testActor(), testTenantID, testProviderID,
		UserSearchTestInput{Username: "alice", Audit: testAudit()},
	)
	if err != nil {
		t.Fatalf("SearchUser() error = %v", err)
	}
	if !reflect.DeepEqual(order, []string{"begin", "network", "complete"}) {
		t.Fatalf("operation order = %v", order)
	}
	if result.MatchedEntryCount != 1 || !result.Truncated || len(result.Entries) != 1 ||
		result.Entries[0].Ordinal != 1 || !result.Entries[0].DNPresent ||
		result.Entries[0].GroupValueCount != 2 {
		t.Fatalf("SearchUser() result = %#v", result)
	}
	if !reflect.DeepEqual(result.Entries[0].Attributes, []RedactedEntryAttribute{
		{Name: "displayname", ValueCount: 1},
		{Name: "entryuuid", ValueCount: 1},
		{Name: "uid", ValueCount: 1},
	}) {
		t.Fatalf("redacted attributes = %#v", result.Entries[0].Attributes)
	}
}

func TestServiceTestFilterUsesConfiguredPOSIXBoundary(t *testing.T) {
	t.Parallel()

	configuration := testConfiguration()
	configuration.Template = ProviderTemplatePOSIX
	configuration.GroupBaseDN = stringPointer("ou=groups,dc=example,dc=com")
	configuration.GroupSearchFilter = stringPointer("(&(objectClass=posixGroup)(memberUid={username})(gidNumber={gidNumber}))")
	configuration.NestedGroupMode = NestedGroupModePOSIXMemberUID
	configuration.MaxNestedGroupDepth = 2
	configuration.POSIXMemberUIDAttribute = stringPointer("memberUid")
	configuration.POSIXGIDNumberAttribute = stringPointer("gidNumber")
	service, repository, inspector := testDirectoryInspectionService(t, configuration)
	repository.begin = func(_ context.Context, params BeginAdministrativeDirectoryInspectionParams) (DirectoryOperationSnapshot, error) {
		if params.OperationKind != DirectoryOperationFilterGroup {
			t.Fatalf("operation kind = %q", params.OperationKind)
		}
		return repository.snapshot(params), nil
	}
	inspector.filter = func(_ context.Context, request ldapclient.DirectoryFilterTestRequest, secret []byte) (ldapclient.DirectoryInspectionResult, error) {
		defer clear(secret)
		if request.GroupBaseDN != *configuration.GroupBaseDN || request.UserBaseDN != "" ||
			request.MaxResults != 3 || !reflect.DeepEqual(request.GroupAttributes, []string{"cn", "memberuid"}) {
			t.Fatalf("group filter request = %#v", request)
		}
		return ldapclient.DirectoryInspectionResult{
			Category: ldapclient.DirectoryCategorySuccess, EndpointPriority: 1,
			Entries: []ldapclient.DirectoryEntry{{
				DistinguishedName: "cn=responders,ou=groups,dc=example,dc=com",
				Attributes: []ldapclient.DirectoryAttribute{
					{Name: "cn", Values: [][]byte{[]byte("responders")}},
					{Name: "memberuid", Values: [][]byte{[]byte("alice"), []byte("bob")}},
				},
			}},
		}, nil
	}
	repository.complete = echoDirectoryInspectionCompletion(t, nil)
	gid := 42
	result, err := service.TestFilter(
		context.Background(), testActor(), testTenantID, testProviderID,
		FilterTestInput{
			Kind:           DirectoryFilterKindGroup,
			FilterTemplate: "(&(objectClass=posixGroup)(memberUid={username})(gidNumber={gidNumber}))",
			Username:       "alice", GIDNumber: &gid, MaxResults: 3, Audit: testAudit(),
		},
	)
	if err != nil {
		t.Fatalf("TestFilter() error = %v", err)
	}
	if result.MatchedEntryCount != 1 || len(result.Entries) != 1 ||
		result.Entries[0].GroupValueCount != 2 ||
		!reflect.DeepEqual(result.Entries[0].Attributes, []RedactedEntryAttribute{{Name: "cn", ValueCount: 1}}) {
		t.Fatalf("TestFilter() result = %#v", result)
	}
}

func TestServiceDirectoryInspectionCompletesAfterCancellationAndReturnsContextError(t *testing.T) {
	t.Parallel()

	service, repository, inspector := testDirectoryInspectionService(t, testConfiguration())
	ctx, cancel := context.WithCancel(context.Background())
	repository.begin = func(_ context.Context, params BeginAdministrativeDirectoryInspectionParams) (DirectoryOperationSnapshot, error) {
		return repository.snapshot(params), nil
	}
	inspector.search = func(_ context.Context, _ ldapclient.DirectorySearchUserRequest, secret []byte) (ldapclient.DirectoryInspectionResult, error) {
		clear(secret)
		cancel()
		return ldapclient.DirectoryInspectionResult{Category: ldapclient.DirectoryCategoryCancelled}, nil
	}
	completed := false
	repository.complete = func(completionContext context.Context, params CompleteDirectoryInspectionParams) (DirectoryInspectionCompletion, error) {
		if completionContext.Err() != nil || params.ReportedCategory != TestCategoryCancelled ||
			params.EndpointPriority != nil || params.MatchedEntryCount != 0 || params.Truncated {
			t.Fatalf("cancel completion = context %v, params %#v", completionContext.Err(), params)
		}
		completed = true
		return echoDirectoryCompletion(params), nil
	}
	_, err := service.SearchUser(
		ctx, testActor(), testTenantID, testProviderID,
		UserSearchTestInput{Username: "alice", Audit: testAudit()},
	)
	if !errors.Is(err, context.Canceled) || !completed {
		t.Fatalf("SearchUser() error = %v, completed = %t", err, completed)
	}
}

func TestServiceDirectoryInspectionAcceptsDatabaseStaleOverride(t *testing.T) {
	t.Parallel()

	service, repository, inspector := testDirectoryInspectionService(t, testConfiguration())
	repository.begin = func(_ context.Context, params BeginAdministrativeDirectoryInspectionParams) (DirectoryOperationSnapshot, error) {
		return repository.snapshot(params), nil
	}
	inspector.search = func(_ context.Context, _ ldapclient.DirectorySearchUserRequest, secret []byte) (ldapclient.DirectoryInspectionResult, error) {
		clear(secret)
		return ldapclient.DirectoryInspectionResult{
			Category: ldapclient.DirectoryCategorySuccess, EndpointPriority: 1,
			Entries: []ldapclient.DirectoryEntry{{DistinguishedName: "uid=alice,dc=example,dc=com"}},
		}, nil
	}
	repository.complete = func(_ context.Context, params CompleteDirectoryInspectionParams) (DirectoryInspectionCompletion, error) {
		return DirectoryInspectionCompletion{
			Diagnostic: TestResult{
				TestRunID: params.OperationRunID, Outcome: TestOutcomeInconclusive,
				Category: TestCategoryStaleConfiguration, Stale: true,
				Duration: params.Duration, CompletedAt: params.OccurredAt,
			},
		}, nil
	}
	result, err := service.SearchUser(
		context.Background(), testActor(), testTenantID, testProviderID,
		UserSearchTestInput{Username: "alice", Audit: testAudit()},
	)
	if err != nil || result.Diagnostic.Category != TestCategoryStaleConfiguration ||
		!result.Diagnostic.Stale || result.MatchedEntryCount != 0 || result.Truncated || len(result.Entries) != 0 {
		t.Fatalf("SearchUser() stale result = %#v, %v", result, err)
	}
}

func TestDeploymentLDAPConfigurationPreservesEndpointPolicyFlags(t *testing.T) {
	t.Parallel()

	configuration := testConfiguration()
	configuration.ReferralMode = ReferralModeConfiguredEndpoints
	configuration.MaxReferralHops = 2
	endpoints := testEndpoints()
	endpoints[0].ReferralAllowed = true
	endpoints = append(endpoints, Endpoint{
		Priority: 2, Host: "disabled.example.com", Port: 636,
		Transport: ldapclient.TransportLDAPS, TLSServerName: "disabled.example.com",
	})
	all, err := deploymentLDAPConfiguration(configuration, endpoints, false)
	if err != nil || len(all.Endpoints) != 2 || !all.Endpoints[0].Enabled ||
		!all.Endpoints[0].ReferralAllowed || all.Endpoints[1].Enabled || all.Endpoints[1].ReferralAllowed {
		t.Fatalf("all endpoint mapping = %#v, %v", all.Endpoints, err)
	}
	enabled, err := deploymentLDAPConfiguration(configuration, endpoints, true)
	if err != nil || len(enabled.Endpoints) != 1 || !enabled.Endpoints[0].Enabled ||
		!enabled.Endpoints[0].ReferralAllowed {
		t.Fatalf("enabled endpoint mapping = %#v, %v", enabled.Endpoints, err)
	}
}

func TestCompletedDirectoryTestResultRejectsUnknownDatabaseCategory(t *testing.T) {
	t.Parallel()

	priority := 1
	_, err := completedDirectoryTestResult(
		DirectoryInspectionCompletion{Diagnostic: TestResult{
			TestRunID: testRunID, Outcome: TestOutcomeFailure,
			Category:         TestCategory("future_unreviewed_category"),
			EndpointPriority: &priority, CompletedAt: testNow,
		}},
		testRunID,
		nil,
		1,
	)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unknown completion category error = %v", err)
	}
}

type directoryInspectionRepositoryStub struct {
	*identityProviderRepositoryStub
	configuration Configuration
	secret        EncryptedBindSecret
	begin         func(context.Context, BeginAdministrativeDirectoryInspectionParams) (DirectoryOperationSnapshot, error)
	complete      func(context.Context, CompleteDirectoryInspectionParams) (DirectoryInspectionCompletion, error)
}

func (s *directoryInspectionRepositoryStub) BeginAdministrativeDirectoryInspection(ctx context.Context, params BeginAdministrativeDirectoryInspectionParams) (DirectoryOperationSnapshot, error) {
	return s.begin(ctx, params)
}

func (s *directoryInspectionRepositoryStub) CompleteDirectoryInspection(ctx context.Context, params CompleteDirectoryInspectionParams) (DirectoryInspectionCompletion, error) {
	return s.complete(ctx, params)
}

func (s *directoryInspectionRepositoryStub) snapshot(params BeginAdministrativeDirectoryInspectionParams) DirectoryOperationSnapshot {
	return DirectoryOperationSnapshot{
		OperationRunID: params.OperationRunID, TenantID: params.TenantID,
		ProviderID: params.ProviderID, OperationKind: params.OperationKind,
		ProviderVersion: 2, ConfigurationVersion: 3,
		EndpointSnapshotDigest: [32]byte{1}, Configuration: s.configuration,
		Endpoints: testEndpoints(), SecretVersion: 4, Secret: s.secret,
		StartedAt: testNow, ExpiresAt: testNow.Add(time.Minute),
	}
}

type directoryInspectionClientStub struct {
	*diagnosticClientStub
	search func(context.Context, ldapclient.DirectorySearchUserRequest, []byte) (ldapclient.DirectoryInspectionResult, error)
	filter func(context.Context, ldapclient.DirectoryFilterTestRequest, []byte) (ldapclient.DirectoryInspectionResult, error)
}

func (s *directoryInspectionClientStub) SearchDirectoryUser(ctx context.Context, request ldapclient.DirectorySearchUserRequest, secret []byte) (ldapclient.DirectoryInspectionResult, error) {
	return s.search(ctx, request, secret)
}

func (s *directoryInspectionClientStub) TestDirectoryFilter(ctx context.Context, request ldapclient.DirectoryFilterTestRequest, secret []byte) (ldapclient.DirectoryInspectionResult, error) {
	return s.filter(ctx, request, secret)
}

func testDirectoryInspectionService(
	t *testing.T,
	configuration Configuration,
) (*Service, *directoryInspectionRepositoryStub, *directoryInspectionClientStub) {
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
	base := &identityProviderRepositoryStub{}
	base.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderTest), nil
	}
	repository := &directoryInspectionRepositoryStub{
		identityProviderRepositoryStub: base,
		configuration:                  configuration,
		secret:                         EncryptedBindSecret{SecretID: testSecretID, Envelope: envelope},
	}
	inspector := &directoryInspectionClientStub{diagnosticClientStub: &diagnosticClientStub{}}
	service, err := NewService(repository, keyring, inspector)
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
	return service, repository, inspector
}

func echoDirectoryInspectionCompletion(
	t *testing.T,
	order *[]string,
) func(context.Context, CompleteDirectoryInspectionParams) (DirectoryInspectionCompletion, error) {
	t.Helper()
	return func(ctx context.Context, params CompleteDirectoryInspectionParams) (DirectoryInspectionCompletion, error) {
		if ctx.Err() != nil {
			t.Fatalf("completion context error = %v", ctx.Err())
		}
		if order != nil {
			*order = append(*order, "complete")
		}
		if params.AuditEventID != testDirectoryEndAuditID {
			t.Fatalf("completion audit event = %s", params.AuditEventID)
		}
		return echoDirectoryCompletion(params), nil
	}
}

func echoDirectoryCompletion(params CompleteDirectoryInspectionParams) DirectoryInspectionCompletion {
	return DirectoryInspectionCompletion{
		Diagnostic: TestResult{
			TestRunID: params.OperationRunID, Outcome: params.ReportedOutcome,
			Category: params.ReportedCategory, EndpointPriority: params.EndpointPriority,
			Duration: params.Duration, CompletedAt: params.OccurredAt,
		},
		MatchedEntryCount: params.MatchedEntryCount,
		Truncated:         params.Truncated,
	}
}

func slicesContainAll(values []string, expected ...string) bool {
	if len(values) != len(expected) {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	for _, value := range expected {
		if _, ok := seen[value]; !ok {
			return false
		}
	}
	return true
}
