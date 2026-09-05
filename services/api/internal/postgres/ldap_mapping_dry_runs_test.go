package postgres

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

var (
	ldapDryRunAccessSourceID    = uuid.MustParse("00000000-0000-7000-8000-000000000222")
	ldapDryRunMappingSourceID   = uuid.MustParse("00000000-0000-7000-8000-000000000223")
	ldapDryRunDisabledMappingID = uuid.MustParse("00000000-0000-7000-8000-000000000224")
	ldapDryRunDisabledEpochID   = uuid.MustParse("00000000-0000-7000-8000-000000000225")
	ldapDryRunDisabledSourceID  = uuid.MustParse("00000000-0000-7000-8000-000000000226")
)

func TestLDAPMappingDryRunRepositoryCommitsBeginAndPinsEveryRevision(t *testing.T) {
	t.Parallel()

	h := newLDAPMappingDryRunHarness(t)
	params := ldapMappingDryRunBeginParams()
	snapshot, err := h.repository.BeginMappingDryRun(h.context(), params)
	if err != nil {
		t.Fatalf("BeginMappingDryRun() error = %v", err)
	}
	if snapshot.OperationRunID != ldapDirectoryRunID || snapshot.ProviderID != ldapAdminProviderID ||
		snapshot.OperationKind != identityprovider.DirectoryOperationSearchUser ||
		snapshot.BindingID == nil || *snapshot.BindingID != ldapAdminBindingID ||
		snapshot.BindingVersion == nil || *snapshot.BindingVersion != 5 ||
		snapshot.BindingAuthRevision == nil || *snapshot.BindingAuthRevision != 7 ||
		snapshot.BindingAccessEpochID == nil || *snapshot.BindingAccessEpochID != ldapAdminBindingEpochID ||
		snapshot.RuleSetRevision == nil || *snapshot.RuleSetRevision != 11 ||
		snapshot.AuthorizationRevision == nil || *snapshot.AuthorizationRevision != 13 ||
		len(snapshot.MappingRevisions) != 2 ||
		snapshot.MappingRevisions[0].MappingID != ldapAdminMappingID ||
		snapshot.MappingRevisions[0].SourceEpochID == nil ||
		*snapshot.MappingRevisions[0].SourceEpochID != ldapAdminMappingEpochID ||
		snapshot.MappingRevisions[1].MappingID != ldapDryRunDisabledMappingID ||
		snapshot.MappingRevisions[1].SourceEpochID != nil {
		t.Fatalf("mapping dry-run network snapshot = %#v", snapshot)
	}
	if got := h.queries.dryRunBeginParams.IncludeDisabledMappingIds; len(got) != 1 ||
		domainUUIDMust(got[0]) != ldapDryRunDisabledMappingID ||
		domainUUIDMust(h.queries.dryRunBeginParams.AuditEventID) != ldapAdminAuditEventID ||
		h.queries.dryRunBeginParams.Reason != "administrative mapping dry run" {
		t.Fatalf("mapping dry-run begin params = %#v", h.queries.dryRunBeginParams)
	}
	if !allZero(h.queries.dryRunBeginRow.BindSecretCiphertext) ||
		!allZero(h.queries.dryRunBeginRow.BindSecretNonce) ||
		!allZero(h.queries.dryRunBeginRow.EndpointSnapshotDigest) {
		t.Fatal("database dry-run secret projection was not cleared")
	}
	if allZero(snapshot.Secret.Envelope.Ciphertext) || allZero(snapshot.EndpointSnapshotDigest[:]) {
		t.Fatal("returned mapping dry-run snapshot did not own protected bytes")
	}
	h.assertSuccess(t, "begin-mapping-dry-run")
}

func TestLDAPMappingDryRunRepositoryMapsDigestOnlyPlanningSnapshot(t *testing.T) {
	t.Parallel()

	h := newLDAPMappingDryRunHarness(t)
	aliases := []identity.SubjectAlias{
		{KeyVersion: 1, Digest: [32]byte{1, 2, 3}},
		{KeyVersion: 2, Digest: [32]byte{4, 5, 6}},
	}
	snapshot, err := h.repository.GetMappingDryRunPlanningSnapshot(
		h.context(),
		identityprovider.GetMappingDryRunPlanningSnapshotParams{
			HumanParams: ldapAdministrationHuman(), OperationRunID: ldapDirectoryRunID,
			SubjectAliases: aliases,
		},
	)
	if err != nil {
		t.Fatalf("GetMappingDryRunPlanningSnapshot() error = %v", err)
	}
	if snapshot.OperationRunID != ldapDirectoryRunID || snapshot.ProviderID != ldapAdminProviderID ||
		snapshot.BindingID != ldapAdminBindingID || snapshot.ProviderVersion != 2 ||
		snapshot.BindingVersion != 5 || snapshot.BindingAuthRevision != 7 ||
		snapshot.BindingAccessEpochID != ldapAdminBindingEpochID ||
		snapshot.ConfigurationRevision != 3 || snapshot.RuleSetRevision != 11 ||
		snapshot.AuthorizationRevision != 13 || len(snapshot.Planning.Rules) != 1 ||
		len(snapshot.Planning.SecurityGroups) != 1 ||
		snapshot.Planning.ProviderAccess.ExternalIdentityExists ||
		snapshot.Planning.ProviderAccess.AccessEpochID != identity.EntityID(ldapAdminBindingEpochID) {
		t.Fatalf("mapping dry-run planning snapshot = %#v", snapshot)
	}
	if len(h.queries.dryRunPlanningParams.DigestKeyVersions) != 2 ||
		h.queries.dryRunPlanningParams.DigestKeyVersions[0] != 1 ||
		h.queries.dryRunPlanningParams.DigestKeyVersions[1] != 2 ||
		len(h.queries.dryRunPlanningParams.SubjectDigests) != 2 ||
		!allZero(h.queries.dryRunPlanningParams.SubjectDigests[0]) ||
		!allZero(h.queries.dryRunPlanningParams.SubjectDigests[1]) {
		t.Fatalf("digest-only query params were not bounded and cleared: %#v", h.queries.dryRunPlanningParams)
	}
	if _, err := identity.PlanLDAPDeprovision(
		snapshot.Planning,
		identity.LDAPDeprovisionInput{
			Policy: identity.LDAPDeprovisionRetain, SourceComplete: true,
		},
	); err != nil {
		t.Fatalf("mapped planner snapshot is not valid: %v", err)
	}
	h.assertSuccess(t, "get-mapping-dry-run-planning-snapshot")
}

func TestLDAPMappingDryRunRepositoryRejectsMalformedPinsAndLifecycle(t *testing.T) {
	t.Parallel()

	t.Run("disabled revision cannot carry a live source epoch", func(t *testing.T) {
		h := newLDAPMappingDryRunHarness(t)
		documents := []ldapPinnedMappingRevisionDocument{{
			MappingID: ldapDryRunDisabledMappingID, MappingVersion: 1,
			SourceEpochID: &ldapDryRunDisabledEpochID, SourceEpochSequence: intPointer(1),
			IncludedDisabled: true,
		}}
		h.queries.dryRunBeginRow.MappingRevisions = mustLDAPDryRunJSON(t, documents)
		_, err := h.repository.BeginMappingDryRun(h.context(), ldapMappingDryRunBeginParams())
		if !errors.Is(err, identityprovider.ErrUnavailable) {
			t.Fatalf("invalid disabled pin error = %v", err)
		}
		h.assertRollback(t, "begin-mapping-dry-run")
	})

	t.Run("access grant cannot outlive an inactive membership", func(t *testing.T) {
		h := newLDAPMappingDryRunHarness(t)
		row := h.queries.dryRunPlanningRow
		row.ExternalIdentityExists = true
		row.ExternalIdentityID = toDatabaseUUID(ldapDryRunDisabledEpochID)
		row.UserID = toDatabaseUUID(ldapDryRunDisabledSourceID)
		row.UserActive = true
		row.TenantMembershipExists = true
		row.MembershipID = toDatabaseUUID(ldapDryRunDisabledMappingID)
		row.TenantMembershipActive = false
		row.AccessGrantLive = true
		_, err := h.repository.GetMappingDryRunPlanningSnapshot(
			h.context(),
			identityprovider.GetMappingDryRunPlanningSnapshotParams{
				HumanParams: ldapAdministrationHuman(), OperationRunID: ldapDirectoryRunID,
				SubjectAliases: []identity.SubjectAlias{{KeyVersion: 1, Digest: [32]byte{1}}},
			},
		)
		if !errors.Is(err, identityprovider.ErrUnavailable) {
			t.Fatalf("invalid lifecycle error = %v", err)
		}
		h.assertRollback(t, "get-mapping-dry-run-planning-snapshot")
	})

	t.Run("unknown JSON field is rejected", func(t *testing.T) {
		h := newLDAPMappingDryRunHarness(t)
		h.queries.dryRunPlanningRow.Rules = []byte(`[{"future":true}]`)
		_, err := h.repository.GetMappingDryRunPlanningSnapshot(
			h.context(),
			identityprovider.GetMappingDryRunPlanningSnapshotParams{
				HumanParams: ldapAdministrationHuman(), OperationRunID: ldapDirectoryRunID,
				SubjectAliases: []identity.SubjectAlias{{KeyVersion: 1, Digest: [32]byte{1}}},
			},
		)
		if !errors.Is(err, identityprovider.ErrUnavailable) {
			t.Fatalf("unknown planning JSON error = %v", err)
		}
		h.assertRollback(t, "get-mapping-dry-run-planning-snapshot")
	})

	t.Run("aliases must be sorted and nonzero before transaction", func(t *testing.T) {
		h := newLDAPMappingDryRunHarness(t)
		_, err := h.repository.GetMappingDryRunPlanningSnapshot(
			h.context(),
			identityprovider.GetMappingDryRunPlanningSnapshotParams{
				HumanParams: ldapAdministrationHuman(), OperationRunID: ldapDirectoryRunID,
				SubjectAliases: []identity.SubjectAlias{
					{KeyVersion: 2, Digest: [32]byte{1}},
					{KeyVersion: 1, Digest: [32]byte{2}},
				},
			},
		)
		if !errors.Is(err, identityprovider.ErrInvalidInput) || len(h.events) != 0 {
			t.Fatalf("unsorted aliases error = %v, events = %v", err, h.events)
		}
	})
}

func newLDAPMappingDryRunHarness(t *testing.T) *ldapDirectoryInspectionHarness {
	t.Helper()
	h := newLDAPDirectoryInspectionHarness(t)
	configuration := append([]byte(nil), h.queries.beginRow.Configuration...)
	endpoints := append([]byte(nil), h.queries.beginRow.Endpoints...)
	ciphertext := make([]byte, 32)
	nonce := make([]byte, 12)
	endpointDigest := make([]byte, 32)
	for index := range ciphertext {
		ciphertext[index] = byte(index + 1)
		endpointDigest[index] = byte(0xf0 - index)
	}
	for index := range nonce {
		nonce[index] = byte(index + 1)
	}
	sequence := 4
	h.queries.dryRunBeginRow = &dbsql.BeginTenantLDAPMappingDryRunRow{
		OperationRunID: toDatabaseUUID(ldapDirectoryRunID), TenantID: toDatabaseUUID(ldapAdminTenantID),
		ProviderID: toDatabaseUUID(ldapAdminProviderID), ProviderVersion: 2, ConfigurationVersion: 3,
		EndpointSnapshotDigest: endpointDigest, Configuration: configuration, Endpoints: endpoints,
		BindSecretID: toDatabaseUUID(ldapDirectorySecretID), BindSecretCiphertext: ciphertext,
		BindSecretNonce: nonce, BindSecretVersion: 4, BindSecretKeyVersion: 1,
		BindSecretAlgorithm: "aes-256-gcm", BindingID: toDatabaseUUID(ldapAdminBindingID),
		BindingVersion: 5, BindingAuthRevision: 7,
		BindingAccessEpochID: toDatabaseUUID(ldapAdminBindingEpochID), RuleSetRevision: 11,
		AuthorizationRevision: 13,
		MappingRevisions: mustLDAPDryRunJSON(t, []ldapPinnedMappingRevisionDocument{
			{
				MappingID: ldapAdminMappingID, MappingVersion: 2,
				SourceEpochID: &ldapAdminMappingEpochID, SourceEpochSequence: &sequence,
			},
			{
				MappingID: ldapDryRunDisabledMappingID, MappingVersion: 1,
				IncludedDisabled: true,
			},
		}),
		StartedAt: pgtype.Timestamptz{Time: ldapAdminNow, Valid: true},
		ExpiresAt: pgtype.Timestamptz{Time: ldapAdminNow.Add(time.Minute), Valid: true},
	}
	h.queries.dryRunPlanningRow = &dbsql.GetTenantLDAPMappingDryRunPlanningSnapshotRow{
		OperationRunID: toDatabaseUUID(ldapDirectoryRunID), TenantID: toDatabaseUUID(ldapAdminTenantID),
		ProviderID: toDatabaseUUID(ldapAdminProviderID), ProviderVersion: 2,
		BindingID: toDatabaseUUID(ldapAdminBindingID), BindingVersion: 5, BindingAuthRevision: 7,
		BindingAccessEpochID: toDatabaseUUID(ldapAdminBindingEpochID), ConfigurationRevision: 3,
		RuleSetRevision: 11, AuthorizationRevision: 13,
		JitMode:                string(identityprovider.JITModeCreate),
		NoMatchPolicy:          string(identityprovider.NoMatchPolicyDeny),
		ProviderAccessSourceID: toDatabaseUUID(ldapDryRunAccessSourceID),
		ProviderAccessEpochID:  toDatabaseUUID(ldapAdminBindingEpochID),
		Rules: mustLDAPDryRunJSON(t, []ldapPlanningRuleDocument{{
			RuleID: ldapAdminMappingID, RuleEpochID: ldapAdminMappingEpochID,
			SourceID: ldapDryRunMappingSourceID, Revision: 2, Priority: 10, Enabled: true,
			MatcherType:        string(identityprovider.MappingMatcherExactDN),
			MatcherValue:       "cn=SOC,ou=groups,dc=example,dc=com",
			CaseMode:           string(identityprovider.MappingCaseInsensitive),
			ReconciliationMode: string(identityprovider.ReconciliationAuthoritative),
			SecurityGroupID:    ldapAdminSecurityGroupID, RoleIDs: []uuid.UUID{ldapAdminRoleID},
			AdministrativeNote: "",
		}}),
		SecurityGroups: mustLDAPDryRunJSON(t, []ldapPlanningSecurityGroupDocument{{
			SecurityGroupID: ldapAdminSecurityGroupID, ActiveRoleIDs: []uuid.UUID{},
		}}),
		LiveAssignments: mustLDAPDryRunJSON(t, []ldapPlanningAssignmentDocument{}),
		RolePolicies: mustLDAPDryRunJSON(t, []ldapPlanningRolePolicyDocument{{
			RoleID: ldapAdminRoleID, Policy: []ldapPlanningPermissionDocument{},
		}}),
		ExistingEffectiveRoleIds: []pgtype.UUID{},
		Delegation:               mustLDAPDryRunJSON(t, []ldapPlanningDelegationDocument{}),
		LiveOwnedEdges:           mustLDAPDryRunJSON(t, []ldapPlanningOwnedEdgeDocument{}),
	}
	return h
}

func ldapMappingDryRunBeginParams() identityprovider.BeginMappingDryRunParams {
	return identityprovider.BeginMappingDryRunParams{
		HumanParams: ldapAdministrationHuman(), Audit: ldapAdministrationAudit(),
		OccurredAt: ldapAdminNow, OperationRunID: ldapDirectoryRunID,
		AuditEventID: ldapAdminAuditEventID, BindingID: ldapAdminBindingID,
		IncludeDisabledMappingIDs: []uuid.UUID{ldapDryRunDisabledMappingID},
		Reason:                    "administrative mapping dry run",
	}
}

func mustLDAPDryRunJSON(t *testing.T, value any) []byte {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return document
}

func intPointer(value int) *int { return &value }
