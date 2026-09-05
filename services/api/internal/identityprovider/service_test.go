package identityprovider

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

var (
	testTenantID     = uuid.MustParse("00000000-0000-7000-8000-000000000101")
	testUserID       = uuid.MustParse("00000000-0000-7000-8000-000000000102")
	testSessionID    = uuid.MustParse("00000000-0000-7000-8000-000000000103")
	testMembershipID = uuid.MustParse("00000000-0000-7000-8000-000000000104")
	testProviderID   = uuid.MustParse("00000000-0000-7000-8000-000000000105")
	testSecretID     = uuid.MustParse("00000000-0000-7000-8000-000000000106")
	testRunID        = uuid.MustParse("00000000-0000-7000-8000-000000000107")
	testNow          = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
)

func TestServiceCreateRequiresLivePermissionAndDigestsRawIdempotencyKey(t *testing.T) {
	t.Parallel()

	repository := &identityProviderRepositoryStub{}
	repository.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderManage), nil
	}
	var received CreateParams
	repository.create = func(_ context.Context, params CreateParams) (CreateResult, error) {
		received = params
		return CreateResult{ProviderID: params.ProviderID, Version: 1}, nil
	}
	service := testIdentityProviderService(t, repository, &diagnosticClientStub{})
	service.newID = func() (uuid.UUID, error) { return testProviderID, nil }

	input := CreateInput{
		Key: "corp_ldap", DisplayName: "Corporate LDAP", Description: "Primary directory",
		Configuration: testConfiguration(), Endpoints: testEndpoints(),
		IdempotencyKey: "create-provider-0001", Audit: testAudit(),
	}
	result, err := service.Create(context.Background(), testActor(), testTenantID, input)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if result.ProviderID != testProviderID || result.Version != 1 || result.Replayed {
		t.Fatalf("Create() result = %#v", result)
	}
	expectedDigest := digestRawIdempotencyKey(input.IdempotencyKey)
	if received.IdempotencyKeyDigest != expectedDigest || received.MembershipID != testMembershipID ||
		received.TenantID != testTenantID || received.Actor.UserID != testUserID {
		t.Fatalf("Create() params = %#v", received)
	}

	repository.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderRead), nil
	}
	if _, err := service.Create(context.Background(), testActor(), testTenantID, input); !errors.Is(err, ErrForbidden) {
		t.Fatalf("Create() without manage error = %v", err)
	}
}

func TestServiceWritesValidateEveryEndpointAgainstDeploymentPolicy(t *testing.T) {
	t.Parallel()

	for _, operation := range []string{"create", "update"} {
		t.Run(operation, func(t *testing.T) {
			repository := &identityProviderRepositoryStub{}
			repository.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
				return testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderManage), nil
			}
			writeCalled := false
			repository.create = func(context.Context, CreateParams) (CreateResult, error) {
				writeCalled = true
				return CreateResult{}, nil
			}
			repository.update = func(context.Context, UpdateParams) (int64, error) {
				writeCalled = true
				return 0, nil
			}
			validationCalls := 0
			diagnostics := &diagnosticClientStub{validate: func(configuration ldapclient.Configuration) error {
				validationCalls++
				if len(configuration.Endpoints) != 2 || configuration.Endpoints[1].Port != 1636 {
					t.Fatalf("validated endpoints = %#v, want disabled endpoint included", configuration.Endpoints)
				}
				return ldapclient.ErrInvalidConfiguration
			}}
			service := testIdentityProviderService(t, repository, diagnostics)
			service.newID = func() (uuid.UUID, error) { return testProviderID, nil }
			endpoints := append(testEndpoints(), Endpoint{
				Priority: 2, Host: "standby.example.com", Port: 1636,
				Transport: ldapclient.TransportLDAPS, TLSServerName: "standby.example.com",
			})

			var err error
			if operation == "create" {
				_, err = service.Create(context.Background(), testActor(), testTenantID, CreateInput{
					Key: "corp_ldap", DisplayName: "Corporate LDAP", Configuration: testConfiguration(),
					Endpoints: endpoints, IdempotencyKey: "identity-provider-create-0001", Audit: testAudit(),
				})
			} else {
				tag := `"v1"`
				_, err = service.Update(context.Background(), testActor(), testTenantID, testProviderID, UpdateInput{
					Key: "corp_ldap", DisplayName: "Corporate LDAP", Configuration: testConfiguration(),
					Endpoints: endpoints, ExpectedEntityTag: &tag, Audit: testAudit(),
				})
			}
			if !errors.Is(err, ErrInvalidInput) || validationCalls != 1 || writeCalled {
				t.Fatalf("error = %v, validation calls = %d, write called = %t", err, validationCalls, writeCalled)
			}
		})
	}
}

func TestServiceUpdateRequiresExactStrongEntityTag(t *testing.T) {
	t.Parallel()

	repository := &identityProviderRepositoryStub{}
	repository.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderManage), nil
	}
	var calls int
	repository.update = func(_ context.Context, params UpdateParams) (int64, error) {
		calls++
		if params.ExpectedVersion != 7 {
			t.Fatalf("ExpectedVersion = %d", params.ExpectedVersion)
		}
		return 8, nil
	}
	service := testIdentityProviderService(t, repository, &diagnosticClientStub{})
	validTag := "\"v7\""
	base := UpdateInput{
		Key: "corp_ldap", DisplayName: "Corporate LDAP", Configuration: testConfiguration(),
		Endpoints: testEndpoints(), ExpectedEntityTag: &validTag, Audit: testAudit(),
	}
	version, err := service.Update(context.Background(), testActor(), testTenantID, testProviderID, base)
	if err != nil || version != 8 {
		t.Fatalf("Update() = (%d, %v)", version, err)
	}
	for _, value := range []*string{nil, stringPointer("*"), stringPointer("W/\"v7\""), stringPointer("\"v07\""), stringPointer("\"v7\", \"v8\"")} {
		input := base
		input.ExpectedEntityTag = value
		_, updateErr := service.Update(context.Background(), testActor(), testTenantID, testProviderID, input)
		if value == nil {
			if !errors.Is(updateErr, ErrPreconditionRequired) {
				t.Fatalf("missing If-Match error = %v", updateErr)
			}
		} else if !errors.Is(updateErr, ErrInvalidInput) {
			t.Fatalf("If-Match %q error = %v", *value, updateErr)
		}
	}
	if calls != 1 {
		t.Fatalf("repository update calls = %d", calls)
	}
}

func TestServiceRotateBindSecretPreservesSecretIDAndClearsPlaintext(t *testing.T) {
	t.Parallel()

	repository := &identityProviderRepositoryStub{}
	repository.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderManage), nil
	}
	order := make([]string, 0, 2)
	repository.getSecretID = func(_ context.Context, params GetBindSecretIDParams) (*uuid.UUID, error) {
		order = append(order, "lookup")
		value := testSecretID
		return &value, nil
	}
	keyring := testIdentityKeyring(t)
	repository.rotate = func(_ context.Context, params RotateBindSecretParams) (int64, error) {
		order = append(order, "write")
		if params.Secret.SecretID != testSecretID {
			t.Fatalf("secret ID = %s", params.Secret.SecretID)
		}
		plaintext, err := keyring.DecryptBindSecret(
			bindSecretContext(testTenantID, testProviderID, testSecretID),
			params.Secret.Envelope,
		)
		if err != nil {
			t.Fatalf("DecryptBindSecret() error = %v", err)
		}
		defer clear(plaintext)
		if string(plaintext) != "directory-password" {
			t.Fatalf("decrypted secret = %q", plaintext)
		}
		return 4, nil
	}
	service, err := NewService(repository, keyring, &diagnosticClientStub{})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	service.now = func() time.Time { return testNow }
	secret := []byte("directory-password")
	tag := "\"v3\""
	version, err := service.RotateBindSecret(context.Background(), testActor(), testTenantID, testProviderID, RotateBindSecretInput{
		Secret: secret, ExpectedEntityTag: &tag, Audit: testAudit(),
	})
	if err != nil || version != 4 {
		t.Fatalf("RotateBindSecret() = (%d, %v)", version, err)
	}
	if !allBytesCleared(secret) {
		t.Fatal("RotateBindSecret() did not clear caller plaintext")
	}
	if !reflect.DeepEqual(order, []string{"lookup", "write"}) {
		t.Fatalf("operation order = %v", order)
	}
}

func TestServiceTestBindCommitsSnapshotBeforeNetworkAndCompletesAfterward(t *testing.T) {
	t.Parallel()

	keyring := testIdentityKeyring(t)
	plaintext := []byte("bind-password")
	envelope, err := keyring.EncryptBindSecret(
		bindSecretContext(testTenantID, testProviderID, testSecretID), plaintext,
	)
	clear(plaintext)
	if err != nil {
		t.Fatalf("EncryptBindSecret() error = %v", err)
	}
	order := make([]string, 0, 4)
	repository := &identityProviderRepositoryStub{}
	repository.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		order = append(order, "authorize")
		return testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderTest), nil
	}
	repository.beginTest = func(_ context.Context, params BeginTestParams) (TestSnapshot, error) {
		order = append(order, "begin-committed")
		secretVersion := int64(2)
		return TestSnapshot{
			TestRunID: params.TestRunID, ProviderID: params.ProviderID, ProviderVersion: 4,
			ConfigurationVersion: 3, SecretVersion: &secretVersion,
			Configuration: testConfiguration(), Endpoints: testEndpoints(),
			Secret: &EncryptedBindSecret{SecretID: testSecretID, Envelope: envelope}, StartedAt: testNow,
		}, nil
	}
	repository.completeTest = func(_ context.Context, params CompleteTestParams) (TestResult, error) {
		order = append(order, "complete")
		if params.ReportedOutcome != TestOutcomeSuccess || params.ReportedCategory != TestCategorySuccess ||
			params.EndpointPriority == nil || *params.EndpointPriority != 1 {
			t.Fatalf("completion params = %#v", params)
		}
		return TestResult{
			TestRunID: params.TestRunID, Outcome: TestOutcomeSuccess, Category: TestCategorySuccess,
			EndpointPriority: intPointer(1), Duration: 125 * time.Millisecond, CompletedAt: testNow.Add(time.Second),
		}, nil
	}
	diagnostics := &diagnosticClientStub{}
	diagnostics.bind = func(_ context.Context, configuration ldapclient.Configuration, bindDN string, secret []byte) (ldapclient.Diagnostic, error) {
		order = append(order, "network")
		defer clear(secret)
		if bindDN != "cn=svc,dc=example,dc=com" || string(secret) != "bind-password" ||
			len(configuration.Endpoints) != 1 || configuration.Endpoints[0].Host != "ldap.example.com" {
			t.Fatalf("diagnostic input = DN %q secret %q config %#v", bindDN, secret, configuration)
		}
		return ldapclient.Diagnostic{
			Outcome: ldapclient.OutcomeSuccess, Category: ldapclient.CategorySuccess,
			EndpointPriority: 1, Duration: 125 * time.Millisecond,
		}, nil
	}
	service, err := NewService(repository, keyring, diagnostics)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	service.now = func() time.Time { return testNow }
	service.newID = func() (uuid.UUID, error) { return testRunID, nil }
	result, err := service.TestBind(context.Background(), testActor(), testTenantID, testProviderID, TestInput{Audit: testAudit()})
	if err != nil {
		t.Fatalf("TestBind() error = %v", err)
	}
	if result.Outcome != TestOutcomeSuccess || result.Category != TestCategorySuccess {
		t.Fatalf("TestBind() result = %#v", result)
	}
	if !reflect.DeepEqual(order, []string{"authorize", "begin-committed", "network", "complete"}) {
		t.Fatalf("operation order = %v", order)
	}
	if !allBytesCleared(envelope.Ciphertext) {
		t.Fatal("TestBind() retained encrypted snapshot bytes")
	}
}

func TestServiceTestConnectionReturnsDatabaseStaleOverride(t *testing.T) {
	t.Parallel()

	repository := &identityProviderRepositoryStub{}
	repository.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderTest), nil
	}
	repository.beginTest = func(_ context.Context, params BeginTestParams) (TestSnapshot, error) {
		return TestSnapshot{
			TestRunID: params.TestRunID, ProviderID: params.ProviderID, ProviderVersion: 1,
			ConfigurationVersion: 1, Configuration: testConfiguration(), Endpoints: testEndpoints(), StartedAt: testNow,
		}, nil
	}
	repository.completeTest = func(_ context.Context, params CompleteTestParams) (TestResult, error) {
		return TestResult{
			TestRunID: params.TestRunID, Outcome: TestOutcomeInconclusive,
			Category: TestCategoryStaleConfiguration, EndpointPriority: intPointer(1),
			Duration: 10 * time.Millisecond, Stale: true, CompletedAt: testNow.Add(time.Second),
		}, nil
	}
	diagnostics := &diagnosticClientStub{connection: func(context.Context, ldapclient.Configuration) (ldapclient.Diagnostic, error) {
		return ldapclient.Diagnostic{
			Outcome: ldapclient.OutcomeSuccess, Category: ldapclient.CategorySuccess,
			EndpointPriority: 1, Duration: 10 * time.Millisecond,
		}, nil
	}}
	service := testIdentityProviderService(t, repository, diagnostics)
	service.newID = func() (uuid.UUID, error) { return testRunID, nil }
	result, err := service.TestConnection(context.Background(), testActor(), testTenantID, testProviderID, TestInput{Audit: testAudit()})
	if err != nil {
		t.Fatalf("TestConnection() error = %v", err)
	}
	if result.Outcome != TestOutcomeInconclusive || result.Category != TestCategoryStaleConfiguration || !result.Stale {
		t.Fatalf("TestConnection() result = %#v", result)
	}
}

func TestServiceDiagnosticRevalidatesCurrentDeploymentPolicyBeforeNetwork(t *testing.T) {
	t.Parallel()

	repository := &identityProviderRepositoryStub{}
	repository.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderTest), nil
	}
	repository.beginTest = func(_ context.Context, params BeginTestParams) (TestSnapshot, error) {
		endpoints := testEndpoints()
		endpoints[0].Port = 1636
		return TestSnapshot{
			TestRunID: params.TestRunID, ProviderID: params.ProviderID, ProviderVersion: 1,
			ConfigurationVersion: 1, Configuration: testConfiguration(), Endpoints: endpoints, StartedAt: testNow,
		}, nil
	}
	completed := false
	repository.completeTest = func(_ context.Context, params CompleteTestParams) (TestResult, error) {
		completed = true
		if params.ReportedOutcome != TestOutcomeFailure || params.ReportedCategory != TestCategoryCancelled ||
			params.EndpointPriority != nil {
			t.Fatalf("completion report = %#v", params)
		}
		return TestResult{
			TestRunID: params.TestRunID, Outcome: TestOutcomeFailure, Category: TestCategoryCancelled,
			Duration: params.Duration, CompletedAt: testNow.Add(time.Second),
		}, nil
	}
	networkCalled := false
	diagnostics := &diagnosticClientStub{
		validate: func(configuration ldapclient.Configuration) error {
			if len(configuration.Endpoints) != 1 || configuration.Endpoints[0].Port != 1636 {
				t.Fatalf("validated configuration = %#v", configuration)
			}
			return ldapclient.ErrInvalidConfiguration
		},
		connection: func(context.Context, ldapclient.Configuration) (ldapclient.Diagnostic, error) {
			networkCalled = true
			return ldapclient.Diagnostic{}, nil
		},
	}
	service := testIdentityProviderService(t, repository, diagnostics)
	service.newID = func() (uuid.UUID, error) { return testRunID, nil }
	_, err := service.TestConnection(
		context.Background(), testActor(), testTenantID, testProviderID, TestInput{Audit: testAudit()},
	)
	if !errors.Is(err, ErrUnavailable) || !completed || networkCalled {
		t.Fatalf("error = %v, completed = %t, network called = %t", err, completed, networkCalled)
	}
}

func TestNormalizeConfigurationRejectsUnsafeValues(t *testing.T) {
	t.Parallel()

	base := testConfiguration()
	for _, test := range []struct {
		name   string
		mutate func(*Configuration, *[]Endpoint)
	}{
		{name: "certificate verification disabled", mutate: func(value *Configuration, _ *[]Endpoint) { value.VerifyCertificate = false }},
		{name: "invalid bind DN", mutate: func(value *Configuration, _ *[]Endpoint) { value.BindDN = "cn=svc,dc" }},
		{name: "placeholder outside filter", mutate: func(value *Configuration, _ *[]Endpoint) { value.UserSearchFilter = "not-a-filter{username}" }},
		{name: "unbalanced filter parentheses", mutate: func(value *Configuration, _ *[]Endpoint) { value.UserSearchFilter = "(&(uid={username})" }},
		{name: "trailing filter", mutate: func(value *Configuration, _ *[]Endpoint) { value.UserSearchFilter = "(uid={username})(objectClass=*)" }},
		{name: "malformed placeholder token", mutate: func(value *Configuration, _ *[]Endpoint) { value.UserSearchFilter = "(uid={user-name})" }},
		{name: "unknown placeholder", mutate: func(value *Configuration, _ *[]Endpoint) { value.UserSearchFilter = "(uid={user})" }},
		{name: "duplicate username placeholder", mutate: func(value *Configuration, _ *[]Endpoint) {
			value.UserSearchFilter = "(|(uid={username})(mail={username}))"
		}},
		{name: "missing username placeholder", mutate: func(value *Configuration, _ *[]Endpoint) { value.UserSearchFilter = "(objectClass=person)" }},
		{name: "trailing DN component", mutate: func(value *Configuration, _ *[]Endpoint) {
			value.UserDNTemplate = stringPointer("uid={username},ou=users,dc=example,dc=com,")
		}},
		{name: "disabled mode group filter", mutate: func(value *Configuration, _ *[]Endpoint) {
			value.GroupSearchFilter = stringPointer("(member={userDn})")
		}},
		{name: "active directory missing group filter", mutate: func(value *Configuration, _ *[]Endpoint) {
			value.NestedGroupMode = NestedGroupModeActiveDirectory
			value.MaxNestedGroupDepth = 1
		}},
		{name: "active directory missing user DN placeholder", mutate: func(value *Configuration, _ *[]Endpoint) {
			value.NestedGroupMode = NestedGroupModeActiveDirectory
			value.MaxNestedGroupDepth = 1
			value.GroupSearchFilter = stringPointer("(memberUid={username})")
		}},
		{name: "posix mode inapplicable user DN placeholder", mutate: func(value *Configuration, _ *[]Endpoint) {
			value.NestedGroupMode = NestedGroupModePOSIXMemberUID
			value.MaxNestedGroupDepth = 1
			value.GroupSearchFilter = stringPointer("(member={userDn})")
		}},
		{name: "unknown JIT", mutate: func(value *Configuration, _ *[]Endpoint) { value.JITMode = "future" }},
		{name: "duplicate priority", mutate: func(_ *Configuration, endpoints *[]Endpoint) { *endpoints = append(*endpoints, (*endpoints)[0]) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			configuration := base
			endpoints := testEndpoints()
			test.mutate(&configuration, &endpoints)
			if _, _, err := normalizeConfiguration(configuration, endpoints); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("normalizeConfiguration() error = %v", err)
			}
		})
	}
}

func TestNormalizeConfigurationAcceptsModeScopedPlaceholderGrammar(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mode   NestedGroupMode
		filter string
	}{
		{
			name:   "active directory",
			mode:   NestedGroupModeActiveDirectory,
			filter: "(&(member={userDn})(sAMAccountName={username}))",
		},
		{
			name:   "reverse search",
			mode:   NestedGroupModeReverseSearch,
			filter: "(member={userDn})",
		},
		{
			name:   "posix member UID",
			mode:   NestedGroupModePOSIXMemberUID,
			filter: "(&(memberUid={username})(gidNumber={gidNumber}))",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			configuration := testConfiguration()
			configuration.NestedGroupMode = test.mode
			configuration.MaxNestedGroupDepth = 1
			configuration.GroupSearchFilter = stringPointer(test.filter)
			if _, _, err := normalizeConfiguration(configuration, testEndpoints()); err != nil {
				t.Fatalf("normalizeConfiguration() error = %v", err)
			}
		})
	}
}

type identityProviderRepositoryStub struct {
	resolve      func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error)
	list         func(context.Context, ListParams) ([]ProviderSummary, error)
	get          func(context.Context, GetParams) (Provider, error)
	create       func(context.Context, CreateParams) (CreateResult, error)
	update       func(context.Context, UpdateParams) (int64, error)
	archive      func(context.Context, ArchiveParams) (int64, error)
	getSecretID  func(context.Context, GetBindSecretIDParams) (*uuid.UUID, error)
	rotate       func(context.Context, RotateBindSecretParams) (int64, error)
	clear        func(context.Context, ClearBindSecretParams) (int64, error)
	beginTest    func(context.Context, BeginTestParams) (TestSnapshot, error)
	completeTest func(context.Context, CompleteTestParams) (TestResult, error)
}

func (s *identityProviderRepositoryStub) ResolveHumanAuthority(ctx context.Context, params authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
	return s.resolve(ctx, params)
}
func (s *identityProviderRepositoryStub) List(ctx context.Context, params ListParams) ([]ProviderSummary, error) {
	return s.list(ctx, params)
}
func (s *identityProviderRepositoryStub) Get(ctx context.Context, params GetParams) (Provider, error) {
	return s.get(ctx, params)
}
func (s *identityProviderRepositoryStub) Create(ctx context.Context, params CreateParams) (CreateResult, error) {
	return s.create(ctx, params)
}
func (s *identityProviderRepositoryStub) Update(ctx context.Context, params UpdateParams) (int64, error) {
	return s.update(ctx, params)
}
func (s *identityProviderRepositoryStub) Archive(ctx context.Context, params ArchiveParams) (int64, error) {
	return s.archive(ctx, params)
}
func (s *identityProviderRepositoryStub) GetBindSecretID(ctx context.Context, params GetBindSecretIDParams) (*uuid.UUID, error) {
	return s.getSecretID(ctx, params)
}
func (s *identityProviderRepositoryStub) RotateBindSecret(ctx context.Context, params RotateBindSecretParams) (int64, error) {
	return s.rotate(ctx, params)
}
func (s *identityProviderRepositoryStub) ClearBindSecret(ctx context.Context, params ClearBindSecretParams) (int64, error) {
	return s.clear(ctx, params)
}
func (s *identityProviderRepositoryStub) BeginTest(ctx context.Context, params BeginTestParams) (TestSnapshot, error) {
	return s.beginTest(ctx, params)
}
func (s *identityProviderRepositoryStub) CompleteTest(ctx context.Context, params CompleteTestParams) (TestResult, error) {
	return s.completeTest(ctx, params)
}

type diagnosticClientStub struct {
	validate   func(ldapclient.Configuration) error
	connection func(context.Context, ldapclient.Configuration) (ldapclient.Diagnostic, error)
	bind       func(context.Context, ldapclient.Configuration, string, []byte) (ldapclient.Diagnostic, error)
}

func (s *diagnosticClientStub) ValidateConfiguration(configuration ldapclient.Configuration) error {
	if s.validate == nil {
		return nil
	}
	return s.validate(configuration)
}

func (s *diagnosticClientStub) TestConnection(ctx context.Context, configuration ldapclient.Configuration) (ldapclient.Diagnostic, error) {
	return s.connection(ctx, configuration)
}
func (s *diagnosticClientStub) TestBind(ctx context.Context, configuration ldapclient.Configuration, bindDN string, secret []byte) (ldapclient.Diagnostic, error) {
	return s.bind(ctx, configuration, bindDN, secret)
}

func testIdentityProviderService(t *testing.T, repository Repository, diagnostics DiagnosticClient) *Service {
	t.Helper()
	service, err := NewService(repository, testIdentityKeyring(t), diagnostics)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	service.now = func() time.Time { return testNow }
	return service
}

func testIdentityKeyring(t *testing.T) identity.Keyring {
	t.Helper()
	root := make([]byte, 32)
	for index := range root {
		root[index] = byte(index + 1)
	}
	keyring, err := identity.NewKeyring(1, map[int16][]byte{1: root})
	clear(root)
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	return keyring
}

func testIdentityProviderAuthority(permission authorization.TenantPermission) authorization.TenantAuthority {
	return authorization.TenantAuthority{
		TenantID: testTenantID, MembershipID: testMembershipID,
		MembershipStatus: authorization.MembershipStatusActive,
		LegacyRole:       authorization.LegacyMembershipRoleTenantAdmin, EvaluatedAt: testNow,
		Principal:   authorization.TenantPrincipal{ID: testUserID, Kind: authorization.PrincipalKindHuman},
		Permissions: []authorization.ScopedPermission{{Permission: permission, Scope: authorization.ScopeTenant}},
	}
}

func testActor() authorization.Actor {
	return authorization.Actor{
		UserID: testUserID, SessionID: testSessionID, ActiveTenantID: testTenantID,
		AuthenticationMethod: "session",
	}
}

func testAudit() authorization.AuditContext {
	return authorization.AuditContext{
		RequestID:     uuid.MustParse("00000000-0000-7000-8000-000000000108"),
		CorrelationID: uuid.MustParse("00000000-0000-7000-8000-000000000109"),
		RemoteAddress: netip.MustParseAddr("192.0.2.10"), UserAgent: "identity-provider-test",
	}
}

func testConfiguration() Configuration {
	return Configuration{
		Template: ProviderTemplateOpenLDAP, VerifyCertificate: true,
		ConnectTimeoutMS: 1_000, OperationTimeoutMS: 5_000,
		BindDN: "cn=svc,dc=example,dc=com", UserBaseDN: "ou=users,dc=example,dc=com",
		UserSearchFilter: "(uid={username})", PageSize: 100, MaxPages: 10,
		MaxEntries: 1_000, MaxResponseBytes: 1_048_576,
		ReferralMode: ReferralModeDisabled, NestedGroupMode: NestedGroupModeDisabled, MaxGroups: 100,
		FirstNameAttribute: "givenName", LastNameAttribute: "sn", DisplayNameAttribute: "displayName",
		UsernameAttribute: "uid", ImmutableSubjectAttribute: "entryUUID",
		ImmutableSubjectFormat: SubjectFormatEntryUUID, AccountStatusMode: AccountStatusModeNone,
		JITMode: JITModeDisabled, NoMatchPolicy: NoMatchPolicyDeny, DeprovisionMode: DeprovisionModeRetain,
	}
}

func testEndpoints() []Endpoint {
	return []Endpoint{{
		Priority: 1, Host: "ldap.example.com", Port: 636, Transport: ldapclient.TransportLDAPS,
		TLSServerName: "ldap.example.com", Enabled: true,
	}}
}

func digestRawIdempotencyKey(value string) [32]byte {
	return sha256Sum([]byte(value))
}

func sha256Sum(value []byte) [32]byte {
	// Kept as a helper to make the test's exact raw-key requirement explicit.
	return sha256.Sum256(value)
}

func stringPointer(value string) *string { return &value }
func intPointer(value int) *int          { return &value }

func allBytesCleared(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
