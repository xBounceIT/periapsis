package platformidentityprovider

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

func TestPlatformLDAPConnectionDiagnosticPersistsOneRedactedResult(t *testing.T) {
	providerID, testID := mustUUIDv7(t), mustUUIDv7(t)
	order := make([]string, 0, 3)
	repository := &ldapTestRepositoryStub{repositoryStub: &repositoryStub{}}
	repository.begin = func(_ context.Context, params BeginLDAPTestParams) (LDAPTestSnapshot, error) {
		order = append(order, "begin")
		if params.ProviderID != providerID || params.TestID != testID || params.Kind != LDAPTestConnection {
			t.Fatalf("BeginLDAPTest() params = %#v", params)
		}
		return platformLDAPTestSnapshot(t, providerID, testID, LDAPTestConnection, false), nil
	}
	repository.complete = func(_ context.Context, params CompleteLDAPTestParams) (LDAPDiagnostic, error) {
		order = append(order, "complete")
		if params.TestID != testID || params.Outcome != "success" || params.Category != "success" ||
			params.EndpointPriority == nil || *params.EndpointPriority != 1 || params.MatchedEntryCount != nil ||
			len(params.Attributes) != 0 || params.CompletedAt.IsZero() {
			t.Fatalf("CompleteLDAPTest() params = %#v", params)
		}
		return ldapDiagnosticFromCompletion(LDAPTestConnection, params), nil
	}
	client := &ldapDiagnosticClientStub{
		validate: func(configuration ldapclient.Configuration) error {
			if len(configuration.Endpoints) != 1 || configuration.Endpoints[0].Host != "ldap.example.test" {
				t.Fatalf("ValidateConfiguration() = %#v", configuration)
			}
			return nil
		},
		connection: func(_ context.Context, _ ldapclient.Configuration) (ldapclient.Diagnostic, error) {
			order = append(order, "network")
			return ldapclient.Diagnostic{
				Outcome: ldapclient.OutcomeSuccess, Category: ldapclient.CategorySuccess,
				EndpointPriority: 1, Duration: 17 * time.Millisecond,
			}, nil
		},
	}
	service := mustService(t, repository)
	service.newID = func() (uuid.UUID, error) { return testID, nil }
	if err := service.ConfigureLDAPDiagnostics(client); err != nil {
		t.Fatalf("ConfigureLDAPDiagnostics() error = %v", err)
	}

	result, err := service.TestLDAP(
		context.Background(), platformLDAPTestSession(t, "ldap"), providerID,
		LDAPTestInput{Kind: LDAPTestConnection, Reason: "Verify directory egress", Event: platformLDAPTestEvent(t)},
	)
	if err != nil || result.TestID != testID || result.Kind != LDAPTestConnection ||
		result.Outcome != "success" || result.Category != "ok" || result.Duration != 17*time.Millisecond ||
		!slices.Equal(order, []string{"begin", "network", "complete"}) {
		t.Fatalf("TestLDAP() result=%#v error=%v order=%v", result, err, order)
	}
}

func TestPlatformLDAPMappingDiagnosticUsesEncryptedServiceSecretAndCanonicalMatchers(t *testing.T) {
	providerID, testID := mustUUIDv7(t), mustUUIDv7(t)
	roleID := mustUUIDv7(t)
	secret := []byte("platform-bind-secret")
	repository := &ldapTestRepositoryStub{repositoryStub: &repositoryStub{}}
	repository.begin = func(_ context.Context, _ BeginLDAPTestParams) (LDAPTestSnapshot, error) {
		snapshot := platformLDAPTestSnapshot(t, providerID, testID, LDAPTestMappingDryRun, true)
		snapshot.Mappings = []LDAPMapping{{
			ID: mustUUIDv7(t), MatcherType: identityprovider.MappingMatcherExactDN,
			MatcherValue: "cn=SOC,ou=groups,dc=example,dc=test", Priority: 10,
			PlatformRoleID: roleID, ReconciliationMode: identityprovider.ReconciliationAuthoritative,
			Enabled: true, Version: 1,
		}}
		return snapshot, nil
	}
	repository.complete = func(_ context.Context, params CompleteLDAPTestParams) (LDAPDiagnostic, error) {
		if params.Outcome != "success" || params.Category != "success" ||
			params.MatchedEntryCount == nil || *params.MatchedEntryCount != 1 ||
			!slices.Equal(params.Attributes, []string{"cn", "entryuuid", "mail", "uid"}) {
			t.Fatalf("CompleteLDAPTest() params = %#v", params)
		}
		return ldapDiagnosticFromCompletion(LDAPTestMappingDryRun, params), nil
	}
	var observedSecret []byte
	client := &ldapDiagnosticClientStub{
		observe: func(_ context.Context, request ldapclient.DirectoryRequest, bindSecret []byte) (ldapclient.DirectoryResult, error) {
			observedSecret = bindSecret
			if request.Username.String() != "identity.LDAPUsername{valid:true,value:[REDACTED]}" || !slices.Equal(bindSecret, secret) {
				t.Fatalf("ObserveDirectory() username=%q secret=%q", request.Username.String(), bindSecret)
			}
			return ldapclient.DirectoryResult{
				Category: ldapclient.DirectoryCategorySuccess, EndpointPriority: 1,
				Observation: ldapclient.DirectoryObservation{
					User: ldapclient.DirectoryEntry{DistinguishedName: "uid=analyst,ou=users,dc=example,dc=test", Attributes: []ldapclient.DirectoryAttribute{
						{Name: "uid"}, {Name: "MAIL"}, {Name: "entryUUID"}, {Name: "ignored attribute"},
					}},
					Groups: []ldapclient.DirectoryEntry{{
						DistinguishedName: "cn=SOC,ou=groups,dc=example,dc=test",
						Attributes:        []ldapclient.DirectoryAttribute{{Name: "cn"}},
					}},
				},
			}, nil
		},
	}
	service := mustService(t, repository)
	service.newID = func() (uuid.UUID, error) { return testID, nil }
	if err := service.ConfigureLDAPDiagnostics(client); err != nil {
		t.Fatalf("ConfigureLDAPDiagnostics() error = %v", err)
	}
	username := "analyst@example.test"
	result, err := service.TestLDAP(
		context.Background(), platformLDAPTestSession(t, "passkey"), providerID,
		LDAPTestInput{Kind: LDAPTestMappingDryRun, Username: &username, Reason: "Verify platform role mapping", Event: platformLDAPTestEvent(t)},
	)
	if err != nil || result.Outcome != "success" || result.Category != "ok" ||
		result.MatchedEntryCount == nil || *result.MatchedEntryCount != 1 ||
		!slices.Equal(result.Attributes, []string{"cn", "entryuuid", "mail", "uid"}) {
		t.Fatalf("TestLDAP() result=%#v error=%v", result, err)
	}
	if !platformLDAPTestBytesCleared(observedSecret) {
		t.Fatalf("TestLDAP() retained decrypted service secret: %q", observedSecret)
	}
}

func TestPlatformLDAPDiagnosticCompletesAfterCancellationAndMapsCapacity(t *testing.T) {
	for _, test := range []struct {
		name    string
		network func(context.Context, ldapclient.Configuration) (ldapclient.Diagnostic, error)
		wantErr error
	}{
		{
			name:    "cancelled request still completes",
			wantErr: context.Canceled,
		},
		{
			name: "capacity is rate limited",
			network: func(context.Context, ldapclient.Configuration) (ldapclient.Diagnostic, error) {
				return ldapclient.Diagnostic{}, ldapclient.ErrBusy
			},
			wantErr: identityprovider.ErrRateLimited,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			providerID, testID := mustUUIDv7(t), mustUUIDv7(t)
			completed := false
			repository := &ldapTestRepositoryStub{repositoryStub: &repositoryStub{}}
			repository.begin = func(_ context.Context, _ BeginLDAPTestParams) (LDAPTestSnapshot, error) {
				return platformLDAPTestSnapshot(t, providerID, testID, LDAPTestConnection, false), nil
			}
			repository.complete = func(ctx context.Context, params CompleteLDAPTestParams) (LDAPDiagnostic, error) {
				completed = true
				if ctx.Err() != nil || params.Outcome != "failure" || params.Category != "cancelled" {
					t.Fatalf("CompleteLDAPTest() context=%v params=%#v", ctx.Err(), params)
				}
				return ldapDiagnosticFromCompletion(LDAPTestConnection, params), nil
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			network := test.network
			if network == nil {
				network = func(context.Context, ldapclient.Configuration) (ldapclient.Diagnostic, error) {
					cancel()
					return ldapclient.Diagnostic{}, context.Canceled
				}
			}
			client := &ldapDiagnosticClientStub{validate: func(ldapclient.Configuration) error { return nil }, connection: network}
			service := mustService(t, repository)
			service.newID = func() (uuid.UUID, error) { return testID, nil }
			if err := service.ConfigureLDAPDiagnostics(client); err != nil {
				t.Fatal(err)
			}
			_, err := service.TestLDAP(
				ctx, platformLDAPTestSession(t, "passkey"), providerID,
				LDAPTestInput{Kind: LDAPTestConnection, Reason: "Cancellation proof", Event: platformLDAPTestEvent(t)},
			)
			if !errors.Is(err, test.wantErr) || !completed {
				t.Fatalf("TestLDAP() error=%v completed=%v", err, completed)
			}
		})
	}
}

func TestPlatformLDAPDiagnosticFailsClosedBeforeNetwork(t *testing.T) {
	providerID, testID := mustUUIDv7(t), mustUUIDv7(t)
	repository := &ldapTestRepositoryStub{repositoryStub: &repositoryStub{}}
	beginCalls, completeCalls, networkCalls := 0, 0, 0
	repository.begin = func(_ context.Context, _ BeginLDAPTestParams) (LDAPTestSnapshot, error) {
		beginCalls++
		return platformLDAPTestSnapshot(t, providerID, testID, LDAPTestConnection, false), nil
	}
	repository.complete = func(_ context.Context, params CompleteLDAPTestParams) (LDAPDiagnostic, error) {
		completeCalls++
		if params.Category != "configuration_invalid" {
			t.Fatalf("CompleteLDAPTest() category = %q", params.Category)
		}
		return ldapDiagnosticFromCompletion(LDAPTestConnection, params), nil
	}
	client := &ldapDiagnosticClientStub{
		validate: func(ldapclient.Configuration) error { return ldapclient.ErrInvalidConfiguration },
		connection: func(context.Context, ldapclient.Configuration) (ldapclient.Diagnostic, error) {
			networkCalls++
			return ldapclient.Diagnostic{}, nil
		},
	}
	service := mustService(t, repository)
	service.newID = func() (uuid.UUID, error) { return testID, nil }
	if err := service.ConfigureLDAPDiagnostics(client); err != nil {
		t.Fatal(err)
	}
	if err := service.ConfigureLDAPDiagnostics(client); err == nil {
		t.Fatal("ConfigureLDAPDiagnostics() accepted a second dependency")
	}
	_, err := service.TestLDAP(
		context.Background(), platformLDAPTestSession(t, "passkey"), providerID,
		LDAPTestInput{Kind: LDAPTestConnection, Reason: "Invalid configuration proof", Event: platformLDAPTestEvent(t)},
	)
	if !errors.Is(err, authentication.ErrUnavailable) || beginCalls != 1 || completeCalls != 1 || networkCalls != 0 {
		t.Fatalf("TestLDAP() error=%v begin=%d complete=%d network=%d", err, beginCalls, completeCalls, networkCalls)
	}

	denied := platformLDAPTestSession(t, "passkey")
	denied.Permissions = nil
	if _, err := service.TestLDAP(
		context.Background(), denied, providerID,
		LDAPTestInput{Kind: LDAPTestConnection, Reason: "Denied", Event: platformLDAPTestEvent(t)},
	); !errors.Is(err, authentication.ErrForbidden) || beginCalls != 1 {
		t.Fatalf("permission denial error=%v begin=%d", err, beginCalls)
	}
}

type ldapTestRepositoryStub struct {
	*repositoryStub
	begin    func(context.Context, BeginLDAPTestParams) (LDAPTestSnapshot, error)
	complete func(context.Context, CompleteLDAPTestParams) (LDAPDiagnostic, error)
}

func (repository *ldapTestRepositoryStub) BeginLDAPTest(ctx context.Context, params BeginLDAPTestParams) (LDAPTestSnapshot, error) {
	return repository.begin(ctx, params)
}

func (repository *ldapTestRepositoryStub) CompleteLDAPTest(ctx context.Context, params CompleteLDAPTestParams) (LDAPDiagnostic, error) {
	return repository.complete(ctx, params)
}

type ldapDiagnosticClientStub struct {
	validate   func(ldapclient.Configuration) error
	connection func(context.Context, ldapclient.Configuration) (ldapclient.Diagnostic, error)
	bind       func(context.Context, ldapclient.Configuration, string, []byte) (ldapclient.Diagnostic, error)
	search     func(context.Context, ldapclient.DirectorySearchUserRequest, []byte) (ldapclient.DirectoryInspectionResult, error)
	filter     func(context.Context, ldapclient.DirectoryFilterTestRequest, []byte) (ldapclient.DirectoryInspectionResult, error)
	observe    func(context.Context, ldapclient.DirectoryRequest, []byte) (ldapclient.DirectoryResult, error)
}

func (client *ldapDiagnosticClientStub) ValidateConfiguration(configuration ldapclient.Configuration) error {
	if client.validate == nil {
		return nil
	}
	return client.validate(configuration)
}

func (client *ldapDiagnosticClientStub) TestConnection(ctx context.Context, configuration ldapclient.Configuration) (ldapclient.Diagnostic, error) {
	return client.connection(ctx, configuration)
}

func (client *ldapDiagnosticClientStub) TestBind(ctx context.Context, configuration ldapclient.Configuration, bindDN string, secret []byte) (ldapclient.Diagnostic, error) {
	return client.bind(ctx, configuration, bindDN, secret)
}

func (client *ldapDiagnosticClientStub) SearchDirectoryUser(ctx context.Context, request ldapclient.DirectorySearchUserRequest, secret []byte) (ldapclient.DirectoryInspectionResult, error) {
	return client.search(ctx, request, secret)
}

func (client *ldapDiagnosticClientStub) TestDirectoryFilter(ctx context.Context, request ldapclient.DirectoryFilterTestRequest, secret []byte) (ldapclient.DirectoryInspectionResult, error) {
	return client.filter(ctx, request, secret)
}

func (client *ldapDiagnosticClientStub) ObserveDirectory(ctx context.Context, request ldapclient.DirectoryRequest, secret []byte) (ldapclient.DirectoryResult, error) {
	return client.observe(ctx, request, secret)
}

func platformLDAPTestSnapshot(
	t testing.TB,
	providerID, testID uuid.UUID,
	kind LDAPTestKind,
	withSecret bool,
) LDAPTestSnapshot {
	t.Helper()
	configuration := identityprovider.Configuration{
		Template: identityprovider.ProviderTemplateOpenLDAP, VerifyCertificate: true,
		ConnectTimeoutMS: 1_000, OperationTimeoutMS: 5_000,
		BindDN: "cn=service,dc=example,dc=test", UserBaseDN: "ou=users,dc=example,dc=test",
		UserSearchFilter: "(uid={username})", PageSize: 100, MaxPages: 10,
		MaxEntries: 1_000, MaxResponseBytes: 1_048_576,
		ReferralMode:    identityprovider.ReferralModeDisabled,
		NestedGroupMode: identityprovider.NestedGroupModeDisabled, MaxGroups: 100,
		FirstNameAttribute: "givenName", LastNameAttribute: "sn", DisplayNameAttribute: "cn",
		UsernameAttribute: "uid", EmailAttribute: platformLDAPTestStringPointer("mail"),
		ImmutableSubjectAttribute: "entryUUID", ImmutableSubjectFormat: identityprovider.SubjectFormatEntryUUID,
		AccountStatusMode: identityprovider.AccountStatusModeNone,
		JITMode:           identityprovider.JITModeExistingIdentity, NoMatchPolicy: identityprovider.NoMatchPolicyDeny,
		DeprovisionMode: identityprovider.DeprovisionModeRetain,
	}
	snapshot := LDAPTestSnapshot{
		TestID: testID, ProviderID: providerID, Kind: kind,
		ProviderVersion: 3, ConfigurationRevision: 2, MappingRevision: 4,
		Configuration: configuration,
		Endpoints: []LDAPEndpoint{{
			ID: mustUUIDv7(t), Priority: 1, Host: "ldap.example.test", Port: 636,
			Transport: string(ldapclient.TransportLDAPS), TLSServerName: "ldap.example.test", Enabled: true,
		}},
		Mappings: []LDAPMapping{},
	}
	if !withSecret {
		return snapshot
	}
	secretID := mustUUIDv7(t)
	envelope, err := testKeyring(t).EncryptBindSecret(identity.BindSecretContext{
		Provider: identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: identity.EntityID(providerID),
		},
		SecretID: identity.EntityID(secretID),
	}, []byte("platform-bind-secret"))
	if err != nil {
		t.Fatalf("EncryptBindSecret() error = %v", err)
	}
	revision := int64(2)
	snapshot.BindSecret = &EncryptedLDAPBindSecret{SecretID: secretID, Envelope: envelope}
	snapshot.SecretRevision = &revision
	return snapshot
}

func platformLDAPTestSession(t testing.TB, method string) authentication.Session {
	t.Helper()
	return authentication.Session{
		ID: mustUUIDv7(t), User: authentication.User{ID: mustUUIDv7(t)},
		Permissions:          []authorization.Permission{authorization.PermissionPlatformIdentityProviderTest},
		AuthenticationMethod: method,
	}
}

func platformLDAPTestEvent(t testing.TB) authentication.EventContext {
	t.Helper()
	return authentication.EventContext{
		RequestID: mustUUIDv7(t), CorrelationID: mustUUIDv7(t),
		RemoteAddress: netip.MustParseAddr("198.51.100.21"), UserAgent: "platform-ldap-diagnostic-test/1",
	}
}

func ldapDiagnosticFromCompletion(kind LDAPTestKind, params CompleteLDAPTestParams) LDAPDiagnostic {
	return LDAPDiagnostic{
		TestID: params.TestID, Kind: kind, Outcome: params.Outcome, Category: params.Category,
		EndpointPriority: params.EndpointPriority, Duration: params.Duration,
		MatchedEntryCount: params.MatchedEntryCount, Attributes: append([]string{}, params.Attributes...),
	}
}

func platformLDAPTestStringPointer(value string) *string { return &value }

func platformLDAPTestBytesCleared(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
