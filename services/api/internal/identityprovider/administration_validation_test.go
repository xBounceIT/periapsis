package identityprovider

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestNormalizeLDAPBindingInputsAreClosedAndVersioned(t *testing.T) {
	t.Parallel()

	providerID := mustAdministrationUUIDv7(t)
	created, err := normalizeCreateBinding(CreateBindingInput{
		ProviderID: providerID, LoginKey: "acme_ldap", Enabled: true,
		ProfilePriority: 25, IdempotencyKey: "binding-command-0001", Audit: testAudit(),
	})
	if err != nil || created.ProviderID != providerID || created.LoginKey != "acme_ldap" {
		t.Fatalf("normalizeCreateBinding() = %#v, %v", created, err)
	}

	bindingID := mustAdministrationUUIDv7(t)
	if _, _, err := normalizeUpdateBinding(bindingID, UpdateBindingInput{
		LoginKey: "acme_ldap", ProfilePriority: 25, Audit: testAudit(),
	}); !errors.Is(err, ErrPreconditionRequired) {
		t.Fatalf("missing If-Match error = %v", err)
	}
	invalidKey := created
	invalidKey.LoginKey = "Acme LDAP"
	if _, err := normalizeCreateBinding(invalidKey); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid login key error = %v", err)
	}
	invalidPriority := created
	invalidPriority.ProfilePriority = maximumLDAPAdministrationPriority + 1
	if _, err := normalizeCreateBinding(invalidPriority); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid priority error = %v", err)
	}
}

func TestNormalizeLDAPMappingCompilesMatcherAndCanonicalizesTargets(t *testing.T) {
	t.Parallel()

	firstRoleID := uuid.MustParse("0198c97d-cf4f-7000-8000-000000000041")
	secondRoleID := uuid.MustParse("0198c97d-cf4f-7000-8000-000000000042")
	inputRoles := []uuid.UUID{secondRoleID, firstRoleID}
	input := CreateMappingInput{
		BindingID: mustAdministrationUUIDv7(t),
		Matcher: MappingMatcher{
			Type: MappingMatcherExactDN, CaseMode: MappingCaseInsensitive,
			Value: "cn=SOC\\2dL2,ou=Groups,dc=example,dc=com",
		},
		Priority: 20,
		Target: MappingTarget{
			TenantSecurityGroupID: mustAdministrationUUIDv7(t), RoleIDs: inputRoles,
			OperatorTeamAssignment: &OperatorTeamAssignmentTarget{
				OperatorTeamID: mustAdministrationUUIDv7(t), AssignmentEpochID: mustAdministrationUUIDv7(t),
			},
		},
		ReconciliationMode: ReconciliationAuthoritative,
		Notes:              "Reviewed mapping",
		Reason:             "  Publish SOC mapping  ",
		IdempotencyKey:     "mapping-command-0001",
		Audit:              testAudit(),
	}
	normalized, err := normalizeCreateMapping(input)
	if err != nil {
		t.Fatalf("normalizeCreateMapping() error = %v", err)
	}
	if normalized.Reason != "Publish SOC mapping" ||
		normalized.Matcher.Value != "cn=SOC-L2,ou=Groups,dc=example,dc=com" ||
		normalized.Target.RoleIDs[0] != firstRoleID ||
		normalized.Target.RoleIDs[1] != secondRoleID {
		t.Fatalf("normalized mapping = %#v", normalized)
	}
	inputRoles[0] = mustAdministrationUUIDv7(t)
	if normalized.Target.RoleIDs[1] != secondRoleID {
		t.Fatal("normalized role target aliases request memory")
	}

	duplicate := input
	duplicate.Target.RoleIDs = []uuid.UUID{firstRoleID, firstRoleID}
	if _, err := normalizeCreateMapping(duplicate); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("duplicate role error = %v", err)
	}
	inlineFlags := input
	inlineFlags.Matcher = MappingMatcher{
		Type: MappingMatcherRegex, CaseMode: MappingCaseSensitive, Value: "(?i)soc.*",
	}
	if _, err := normalizeCreateMapping(inlineFlags); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("inline regex flag error = %v", err)
	}
	canonicalExpansion := input
	canonicalExpansion.Matcher.Value = "cn=" + strings.Repeat("é", 700) + ",dc=example,dc=com"
	if _, err := normalizeCreateMapping(canonicalExpansion); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("overlong canonical DN error = %v", err)
	}
}

func TestNormalizeLDAPAdministrativeFilterUsesClosedTypedGrammar(t *testing.T) {
	t.Parallel()

	providerID := mustAdministrationUUIDv7(t)
	userDN := "uid=alice,ou=people,dc=example,dc=com"
	reverse, err := normalizeFilterTest(providerID, FilterTestInput{
		Kind: DirectoryFilterKindGroup, FilterTemplate: "(member={userDn})",
		Username: "alice", UserDN: &userDN, MaxResults: 10, Audit: testAudit(),
	})
	if err != nil || reverse.UserDN == nil || *reverse.UserDN != userDN {
		t.Fatalf("reverse filter = %#v, %v", reverse, err)
	}
	userDN = "changed"
	if *reverse.UserDN != "uid=alice,ou=people,dc=example,dc=com" {
		t.Fatal("normalized filter aliases request memory")
	}

	gid := 42
	if _, err := normalizeFilterTest(providerID, FilterTestInput{
		Kind:           DirectoryFilterKindGroup,
		FilterTemplate: "(|(memberUid={username})(gidNumber={gidNumber}))",
		Username:       "alice", GIDNumber: &gid, MaxResults: 5, Audit: testAudit(),
	}); err != nil {
		t.Fatalf("POSIX filter error = %v", err)
	}
	if _, err := normalizeFilterTest(providerID, FilterTestInput{
		Kind: DirectoryFilterKindUser, FilterTemplate: "(uid={username})",
		Username: "alice", UserDN: &userDN, MaxResults: 5, Audit: testAudit(),
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("user filter with group-only input error = %v", err)
	}
	if _, err := normalizeFilterTest(providerID, FilterTestInput{
		Kind: DirectoryFilterKindGroup, FilterTemplate: "(member={userDn})",
		Username: "alice", MaxResults: 5, Audit: testAudit(),
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing typed placeholder input error = %v", err)
	}
}

func TestNormalizeLDAPDryRunRejectsDuplicateMappingsAndOwnsSortedIDs(t *testing.T) {
	t.Parallel()

	first := uuid.MustParse("0198c97d-cf4f-7000-8000-000000000051")
	second := uuid.MustParse("0198c97d-cf4f-7000-8000-000000000052")
	requestIDs := []uuid.UUID{second, first}
	normalized, err := normalizeDryRun(DryRunInput{
		BindingID: mustAdministrationUUIDv7(t), Username: "alice",
		IncludeDisabledMappingIDs: requestIDs, Audit: testAudit(),
	})
	if err != nil || normalized.IncludeDisabledMappingIDs[0] != first ||
		normalized.IncludeDisabledMappingIDs[1] != second {
		t.Fatalf("normalizeDryRun() = %#v, %v", normalized, err)
	}
	requestIDs[0] = mustAdministrationUUIDv7(t)
	if normalized.IncludeDisabledMappingIDs[1] != second {
		t.Fatal("normalized dry-run IDs alias request memory")
	}
	if _, err := normalizeDryRun(DryRunInput{
		BindingID: mustAdministrationUUIDv7(t), Username: "alice",
		IncludeDisabledMappingIDs: []uuid.UUID{first, first}, Audit: testAudit(),
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("duplicate dry-run mapping error = %v", err)
	}
}

func TestNormalizeLDAPManualSyncRequiresReasonIdempotencyAndETag(t *testing.T) {
	t.Parallel()

	bindingID := mustAdministrationUUIDv7(t)
	tag, err := EntityTag(7)
	if err != nil {
		t.Fatalf("EntityTag() error = %v", err)
	}
	normalized, version, err := normalizeStartManualSync(bindingID, StartManualSyncInput{
		Reason: "  Operator-requested reconciliation  ", IdempotencyKey: "sync-command-0000001",
		ExpectedEntityTag: &tag, Audit: testAudit(),
	})
	if err != nil || version != 7 || normalized.Reason != "Operator-requested reconciliation" {
		t.Fatalf("normalizeStartManualSync() = %#v, %d, %v", normalized, version, err)
	}
	missingTag := normalized
	missingTag.ExpectedEntityTag = nil
	if _, _, err := normalizeStartManualSync(bindingID, missingTag); !errors.Is(err, ErrPreconditionRequired) {
		t.Fatalf("missing manual-sync ETag error = %v", err)
	}
}

func TestNormalizeLDAPConfigurationAdmitsOnlyCanonicalJITSyncAndDeprovisionPolicies(t *testing.T) {
	t.Parallel()

	configuration := testConfiguration()
	configuration.JITMode = JITModeCreate
	configuration.NoMatchPolicy = NoMatchPolicyProviderAccessOnly
	configuration.DeprovisionMode = DeprovisionModeGrace
	configuration.DeprovisionGraceSeconds = 600
	syncInterval := 900
	configuration.SyncIntervalSeconds = &syncInterval
	if _, _, err := normalizeConfiguration(configuration, testEndpoints()); err != nil {
		t.Fatalf("canonical enabled configuration error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Configuration)
	}{
		{"unknown JIT", func(value *Configuration) { value.JITMode = "future" }},
		{"unknown no-match", func(value *Configuration) { value.NoMatchPolicy = "future" }},
		{"grace too short", func(value *Configuration) { value.DeprovisionGraceSeconds = 59 }},
		{"immediate with grace", func(value *Configuration) {
			value.DeprovisionMode = DeprovisionModeImmediate
			value.DeprovisionGraceSeconds = 60
		}},
		{"sync too fast", func(value *Configuration) {
			seconds := 299
			value.SyncIntervalSeconds = &seconds
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := configuration
			test.mutate(&candidate)
			if _, _, err := normalizeConfiguration(candidate, testEndpoints()); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("normalizeConfiguration() error = %v", err)
			}
		})
	}
}

func TestNormalizeLDAPConfigurationRequiresExplicitLiveReferralTargets(t *testing.T) {
	t.Parallel()

	configuration := testConfiguration()
	configuration.ReferralMode = ReferralModeConfiguredEndpoints
	configuration.MaxReferralHops = 2
	endpoints := testEndpoints()
	if _, _, err := normalizeConfiguration(configuration, endpoints); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("configured referrals without target error = %v", err)
	}
	endpoints[0].ReferralAllowed = true
	if _, _, err := normalizeConfiguration(configuration, endpoints); err != nil {
		t.Fatalf("configured referral target error = %v", err)
	}
	endpoints[0].Enabled = false
	if _, _, err := normalizeConfiguration(configuration, endpoints); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("disabled referral target error = %v", err)
	}
	configuration.ReferralMode = ReferralModeDisabled
	configuration.MaxReferralHops = 0
	endpoints[0].Enabled = true
	if _, _, err := normalizeConfiguration(configuration, endpoints); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("latent referral target error = %v", err)
	}
}

func mustAdministrationUUIDv7(t *testing.T) uuid.UUID {
	t.Helper()
	value, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7() error = %v", err)
	}
	return value
}
