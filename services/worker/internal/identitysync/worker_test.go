package identitysync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
)

var errFakeResponseLost = errors.New("database response lost")

func TestObservationDigestsAreCanonicalAndPurposeSeparated(t *testing.T) {
	_, claim, _ := testClaim(t)
	defer claim.ClearSensitive()
	left := ldapclient.DirectoryObservation{
		User: ldapclient.DirectoryEntry{
			DistinguishedName: "uid=private,dc=example,dc=com",
			Attributes: []ldapclient.DirectoryAttribute{
				{Name: "uid", Values: [][]byte{[]byte("private"), []byte("alternate")}},
				{Name: "entryUUID", Values: [][]byte{[]byte("subject")}},
			},
		},
		Groups: []ldapclient.DirectoryEntry{
			{DistinguishedName: "cn=Zulu,dc=example,dc=com"},
			{DistinguishedName: "cn=Alpha,dc=example,dc=com"},
		},
	}
	right := ldapclient.DirectoryObservation{
		User: ldapclient.DirectoryEntry{
			DistinguishedName: left.User.DistinguishedName,
			Attributes: []ldapclient.DirectoryAttribute{
				{Name: "ENTRYUUID", Values: [][]byte{[]byte("subject")}},
				{Name: "UID", Values: [][]byte{[]byte("alternate"), []byte("private")}},
			},
		},
		Groups: []ldapclient.DirectoryEntry{left.Groups[1], left.Groups[0]},
	}
	leftDigest := observationDigest(claim, 1, left)
	if rightDigest := observationDigest(claim, 1, right); rightDigest != leftDigest {
		t.Fatal("canonical LDAP observation order changed its digest")
	}
	if observationDigest(claim, 2, left) == leftDigest {
		t.Fatal("observation ordinal was not domain-bound into its digest")
	}
	changedClaim := claim
	changedClaim.BindingAccessEpochID = mustV7(t)
	if observationDigest(changedClaim, 1, left) == leftDigest {
		t.Fatal("pinned provider-access epoch was not domain-bound into its digest")
	}
	cursor := enumerationDigest([]preparedObservation{{
		Staged: StagedObservation{Ordinal: 1, ObservationDigest: leftDigest},
	}})
	if cursor == leftDigest || allZero(cursor[:]) {
		t.Fatal("enumeration cursor was not purpose-separated")
	}
	proof, err := newClaimProof()
	if err != nil || proof.ID.Version() != 7 || allZero(proof.ReceiptDigest[:]) {
		t.Fatalf("newClaimProof() = %+v, %v", proof, err)
	}
}

func TestWorkerDrivesSharedPlannerAndReplaysExactMutationsAfterResponseLoss(t *testing.T) {
	keyring, claim, secret := testClaim(t)
	repository := newFakeRepository(claim)
	matchedEpochID := repository.enableMappingProjection(t)
	repository.responseLoss = map[string]bool{
		"claim": true, "stage": true, "planning": true, "apply": true,
		"absence": true, "complete": true,
	}
	directory := &fakeDirectory{
		enumeration: ldapclient.DirectoryEnumerationResult{
			Category: ldapclient.DirectoryCategorySuccess, EndpointPriority: 1,
			Complete: true, Users: []ldapclient.DirectoryEntry{enumeratedUser("private-login-marker")},
		},
		observation: ldapclient.DirectoryResult{
			Category: ldapclient.DirectoryCategorySuccess, EndpointPriority: 1,
			Observation: rawObservation(
				"private-login-marker", "private-profile-marker",
				"cn=SOC-L2,ou=groups,dc=example,dc=com",
			),
		},
	}
	var logs bytes.Buffer
	worker := testWorker(t, repository, directory, keyring, &logs)

	worked, err := worker.PollOnce(context.Background())
	if err != nil || !worked {
		t.Fatalf("PollOnce() = %t, %v", worked, err)
	}
	repository.mu.Lock()
	if repository.claimCalls != 2 || repository.stageCalls != 2 ||
		repository.planningCalls != 2 || repository.applyCalls != 2 ||
		repository.absenceCalls != 4 || repository.completeCalls != 2 {
		t.Fatalf(
			"retry calls claim/stage/planning/apply/absence/complete = %d/%d/%d/%d/%d/%d; fail=%d/%s",
			repository.claimCalls, repository.stageCalls, repository.planningCalls,
			repository.applyCalls, repository.absenceCalls, repository.completeCalls,
			repository.failCalls, repository.failCategory,
		)
	}
	if repository.applyRequest == nil || repository.applyRequest.Decision != "admitted" ||
		repository.applyRequest.ExternalIdentityID == nil || repository.applyRequest.UserID == nil ||
		repository.applyRequest.MembershipID == nil || repository.applyRequest.AccessGrantID == nil ||
		len(repository.applyRequest.MatchedEpochIDs) != 1 ||
		repository.applyRequest.MatchedEpochIDs[0] != matchedEpochID {
		t.Fatalf("shared planner apply request = %+v", repository.applyRequest)
	}
	returnedSecrets := append([][]byte(nil), repository.returnedCiphertexts...)
	repository.applyRequest.ClearSensitive()
	repository.mu.Unlock()

	assertZeroBackings(t, directory.secretBackings(), "decrypted bind secret")
	assertZeroBackings(t, returnedSecrets, "claimed bind ciphertext")
	assertZeroBackings(t, directory.rawBackings(), "raw LDAP value")
	if bytes.Contains(logs.Bytes(), secret) || strings.Contains(logs.String(), "private-login-marker") ||
		strings.Contains(logs.String(), "private-profile-marker") ||
		strings.Contains(logs.String(), "directory-private-marker") || strings.Contains(logs.String(), "SOC-L2") {
		t.Fatalf("worker logs exposed directory or secret material: %s", logs.String())
	}
}

func TestWorkerCarriesOnlyPinnedAuthoritativeRevocationsOnDeniedMapping(t *testing.T) {
	keyring, claim, _ := testClaim(t)
	claim.Configuration.NoMatchPolicy = "deny"
	repository := newFakeRepository(claim)
	epochID := repository.enableMappingProjection(t)
	sourceID := repository.mappingRule.SourceID
	groupID := repository.mappingRule.SecurityGroupID
	roleID := repository.mappingRule.RoleIDs[0]
	externalIdentityID, userID := mustV7(t), mustV7(t)
	membershipID, accessGrantID := mustV7(t), mustV7(t)
	repository.projectionMutation = func(projection *PlanningProjection) {
		projection.ExternalIdentityID = &externalIdentityID
		projection.UserID = &userID
		projection.MembershipID = &membershipID
		projection.AccessGrantID = &accessGrantID
		projection.ExternalIdentityExists = true
		projection.UserActive = true
		projection.TenantMembershipExists = true
		projection.TenantMembershipActive = true
		projection.AccessGrantLive = true
		projection.LiveOwnedEdges = mustJSON([]planningOwnedEdgeDocument{
			{SourceID: sourceID, RuleEpochID: epochID, Kind: "security_group_membership", PrimaryID: groupID},
			{SourceID: sourceID, RuleEpochID: epochID, Kind: "security_group_role_grant", PrimaryID: groupID, SecondaryID: &roleID},
		})
	}
	directory := &fakeDirectory{
		enumeration: ldapclient.DirectoryEnumerationResult{
			Category: ldapclient.DirectoryCategorySuccess, EndpointPriority: 1,
			Complete: true, Users: []ldapclient.DirectoryEntry{enumeratedUser("removed-from-soc")},
		},
		observation: ldapclient.DirectoryResult{
			Category: ldapclient.DirectoryCategorySuccess, EndpointPriority: 1,
			Observation: rawObservation("removed-from-soc", "Removed From SOC"),
		},
	}
	worker := testWorker(t, repository, directory, keyring, nil)

	worked, err := worker.PollOnce(context.Background())
	if err != nil || !worked {
		t.Fatalf("PollOnce() = %t, %v", worked, err)
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	request := repository.applyRequest
	if request == nil || request.Decision != "denied" || request.DenialCategory == nil ||
		*request.DenialCategory != "no_mapping" ||
		!sameOptionalUUID(request.ExistingExternalIdentityID, &externalIdentityID) ||
		!sameOptionalUUID(request.ExistingUserID, &userID) ||
		!sameOptionalUUID(request.ExistingMembershipID, &membershipID) ||
		!sameOptionalUUID(request.ExistingAccessGrantID, &accessGrantID) ||
		len(request.RevocationEpochIDs) != 1 || request.RevocationEpochIDs[0] != epochID ||
		request.ExternalIdentityID != nil || request.UserID != nil ||
		request.MembershipID != nil || request.AccessGrantID != nil ||
		request.ProfileContributionID != nil || len(request.SubjectCiphertext) != 0 ||
		len(request.AliasIDs) != 0 || len(request.MatchedEpochIDs) != 0 {
		t.Fatalf("denied reconciliation request = %+v", request)
	}
}

func TestWorkerExcludesMappingGlobalRoleGrantFromDeniedUserRevocations(t *testing.T) {
	keyring, claim, _ := testClaim(t)
	claim.Configuration.NoMatchPolicy = "deny"
	repository := newFakeRepository(claim)
	epochID := repository.enableMappingProjection(t)
	sourceID := repository.mappingRule.SourceID
	groupID := repository.mappingRule.SecurityGroupID
	roleID := repository.mappingRule.RoleIDs[0]
	externalIdentityID, userID := mustV7(t), mustV7(t)
	membershipID, accessGrantID := mustV7(t), mustV7(t)
	repository.projectionMutation = func(projection *PlanningProjection) {
		projection.ExternalIdentityID = &externalIdentityID
		projection.UserID = &userID
		projection.MembershipID = &membershipID
		projection.AccessGrantID = &accessGrantID
		projection.ExternalIdentityExists = true
		projection.UserActive = true
		projection.TenantMembershipExists = true
		projection.TenantMembershipActive = true
		projection.AccessGrantLive = true
		projection.LiveOwnedEdges = mustJSON([]planningOwnedEdgeDocument{{
			SourceID: sourceID, RuleEpochID: epochID,
			Kind: "security_group_role_grant", PrimaryID: groupID,
			SecondaryID: &roleID,
		}})
	}
	directory := &fakeDirectory{
		enumeration: ldapclient.DirectoryEnumerationResult{
			Category: ldapclient.DirectoryCategorySuccess, EndpointPriority: 1,
			Complete: true, Users: []ldapclient.DirectoryEntry{enumeratedUser("role-only-grace")},
		},
		observation: ldapclient.DirectoryResult{
			Category: ldapclient.DirectoryCategorySuccess, EndpointPriority: 1,
			Observation: rawObservation("role-only-grace", "Role Only Grace"),
		},
	}
	worker := testWorker(t, repository, directory, keyring, nil)

	worked, err := worker.PollOnce(context.Background())
	if err != nil || !worked {
		t.Fatalf("PollOnce() = %t, %v", worked, err)
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	request := repository.applyRequest
	if request == nil || request.Decision != "denied" ||
		!sameOptionalUUID(request.ExistingExternalIdentityID, &externalIdentityID) ||
		!sameOptionalUUID(request.ExistingUserID, &userID) ||
		!sameOptionalUUID(request.ExistingMembershipID, &membershipID) ||
		!sameOptionalUUID(request.ExistingAccessGrantID, &accessGrantID) ||
		len(request.RevocationEpochIDs) != 0 {
		t.Fatalf("role-only denied reconciliation request = %+v", request)
	}
}

func TestWorkerFailsClosedOnIncompleteOrTruncatedEnumeration(t *testing.T) {
	tests := []struct {
		name     string
		result   ldapclient.DirectoryEnumerationResult
		category string
	}{
		{
			name: "truncated",
			result: ldapclient.DirectoryEnumerationResult{
				Category: ldapclient.DirectoryCategorySuccess, EndpointPriority: 1,
				Complete: false, Truncated: true,
				Users: []ldapclient.DirectoryEntry{enumeratedUser("partial-truncated-marker")},
			},
			category: "limit_exceeded",
		},
		{
			name: "partial source failure",
			result: ldapclient.DirectoryEnumerationResult{
				Category: ldapclient.DirectoryCategoryConnectFailed, EndpointPriority: 1,
				Complete: false,
				Users:    []ldapclient.DirectoryEntry{enumeratedUser("partial-network-marker")},
			},
			category: "connect_failed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keyring, claim, _ := testClaim(t)
			repository := newFakeRepository(claim)
			directory := &fakeDirectory{enumeration: test.result}
			worker := testWorker(t, repository, directory, keyring, nil)

			worked, err := worker.PollOnce(context.Background())
			if err != nil || !worked {
				t.Fatalf("PollOnce() = %t, %v", worked, err)
			}
			repository.mu.Lock()
			defer repository.mu.Unlock()
			if repository.enumerationCalls != 1 || repository.enumerationFailure != test.category ||
				repository.stageCalls != 0 || repository.planningCalls != 0 ||
				repository.applyCalls != 0 || repository.absenceCalls != 0 ||
				repository.completeCalls != 0 || repository.failCalls != 0 {
				t.Fatalf("fail-closed calls/category = %+v / %q", repository, repository.enumerationFailure)
			}
			assertZeroBackings(t, directory.rawBackings(), "partial raw LDAP value")
		})
	}
}

func TestTwoWorkersHaveOneClaimWinner(t *testing.T) {
	keyring, claim, _ := testClaim(t)
	repository := newFakeRepository(claim)
	directory := &fakeDirectory{enumeration: ldapclient.DirectoryEnumerationResult{
		Category: ldapclient.DirectoryCategorySuccess, EndpointPriority: 1, Complete: true,
	}}
	left := testWorker(t, repository, directory, keyring, nil)
	right := testWorker(t, repository, directory, keyring, nil)
	start := make(chan struct{})
	type result struct {
		worked bool
		err    error
	}
	results := make(chan result, 2)
	for _, worker := range []*Worker{left, right} {
		go func(candidate *Worker) {
			<-start
			worked, err := candidate.PollOnce(context.Background())
			results <- result{worked: worked, err: err}
		}(worker)
	}
	close(start)
	first, second := <-results, <-results
	if first.err != nil || second.err != nil || first.worked == second.worked {
		t.Fatalf("two-worker results = %+v / %+v", first, second)
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.completeCalls != 1 {
		t.Fatalf("terminal winners = %d, want 1", repository.completeCalls)
	}
}

func TestExpiredLeaseFenceStopsOldWorkerWithoutTerminalMutation(t *testing.T) {
	keyring, claim, _ := testClaim(t)
	repository := newFakeRepository(claim)
	repository.loseOnRenewal = true
	directory := &fakeDirectory{
		blockEnumeration: true,
		entered:          make(chan struct{}),
	}
	worker := testWorker(t, repository, directory, keyring, nil)
	done := make(chan error, 1)
	go func() {
		_, err := worker.PollOnce(context.Background())
		done <- err
	}()
	select {
	case <-directory.entered:
	case <-time.After(time.Second):
		t.Fatal("directory enumeration did not start")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("fenced PollOnce() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("old worker was not stopped by its lease fence")
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.claimCalls < 2 || repository.failCalls != 0 || repository.completeCalls != 0 {
		t.Fatalf("fenced worker mutated terminal state: claims/fails/completes = %d/%d/%d",
			repository.claimCalls, repository.failCalls, repository.completeCalls)
	}
}

func TestPlanningFenceLossStopsBeforeApply(t *testing.T) {
	keyring, claim, _ := testClaim(t)
	repository := newFakeRepository(claim)
	repository.staleAt = "planning"
	directory := &fakeDirectory{
		enumeration: ldapclient.DirectoryEnumerationResult{
			Category: ldapclient.DirectoryCategorySuccess, EndpointPriority: 1,
			Complete: true, Users: []ldapclient.DirectoryEntry{enumeratedUser("stale-pin-marker")},
		},
		observation: ldapclient.DirectoryResult{
			Category: ldapclient.DirectoryCategorySuccess, EndpointPriority: 1,
			Observation: rawObservation("stale-pin-marker", "stale-profile-marker"),
		},
	}
	worker := testWorker(t, repository, directory, keyring, nil)
	worked, err := worker.PollOnce(context.Background())
	if err != nil || !worked {
		t.Fatalf("PollOnce() = %t, %v", worked, err)
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.planningCalls != 1 || repository.applyCalls != 0 || repository.failCalls != 0 {
		t.Fatalf("stale planning calls planning/apply/fail = %d/%d/%d",
			repository.planningCalls, repository.applyCalls, repository.failCalls)
	}
}

func TestApplyingCrashIsReclaimedAndSkipsCommittedObservation(t *testing.T) {
	keyring, claim, _ := testClaim(t)
	repository := newFakeRepository(claim)
	repository.loseAfterApply = true
	directory := &fakeDirectory{
		enumeration: ldapclient.DirectoryEnumerationResult{
			Category: ldapclient.DirectoryCategorySuccess, EndpointPriority: 1,
			Complete: true, Users: []ldapclient.DirectoryEntry{enumeratedUser("crash-reclaim-marker")},
		},
		observation: ldapclient.DirectoryResult{
			Category: ldapclient.DirectoryCategorySuccess, EndpointPriority: 1,
			Observation: rawObservation("crash-reclaim-marker", "crash-profile-marker"),
		},
	}
	firstWorker := testWorker(t, repository, directory, keyring, nil)
	worked, err := firstWorker.PollOnce(context.Background())
	if err != nil || !worked {
		t.Fatalf("crashing PollOnce() = %t, %v", worked, err)
	}
	repository.expireClaimForReclaim()
	secondWorker := testWorker(t, repository, directory, keyring, nil)
	worked, err = secondWorker.PollOnce(context.Background())
	if err != nil || !worked {
		t.Fatalf("reclaimed PollOnce() = %t, %v", worked, err)
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.base.Fence != 2 || repository.applyCalls != 1 ||
		repository.completeCalls != 1 || repository.absenceCalls < 1 ||
		repository.staged == nil || !repository.staged.Applied {
		t.Fatalf("crash reclaim state = fence/apply/complete/absence/staged %d/%d/%d/%d/%+v",
			repository.base.Fence, repository.applyCalls, repository.completeCalls,
			repository.absenceCalls, repository.staged)
	}
}

func TestCancellationTerminallyMetersWithoutIdentityMaterial(t *testing.T) {
	keyring, claim, _ := testClaim(t)
	repository := newFakeRepository(claim)
	directory := &fakeDirectory{blockEnumeration: true, entered: make(chan struct{})}
	worker := testWorker(t, repository, directory, keyring, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := worker.PollOnce(ctx)
		done <- err
	}()
	select {
	case <-directory.entered:
	case <-time.After(time.Second):
		t.Fatal("directory enumeration did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("cancelled PollOnce() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled operation did not stop")
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.failCalls != 1 || repository.failCategory != "cancelled" ||
		repository.stageCalls != 0 || repository.applyCalls != 0 {
		t.Fatalf("cancel terminal calls/category = %+v / %q", repository, repository.failCategory)
	}
}

func TestPlanningSnapshotRejectsPolicyPinAndUnknownProjectionDivergence(t *testing.T) {
	_, claim, _ := testClaim(t)
	baseline := baselineProjection(claim, mustV7(t))
	if _, _, err := planningSnapshot(claim, baseline); err != nil {
		t.Fatalf("baseline planningSnapshot() error = %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*Claim, *PlanningProjection)
	}{
		{
			name: "JIT policy",
			mutate: func(_ *Claim, projection *PlanningProjection) {
				projection.JITMode = "disabled"
			},
		},
		{
			name: "unknown planner field",
			mutate: func(_ *Claim, projection *PlanningProjection) {
				projection.Rules = []byte(`[{"unknown":true}]`)
			},
		},
		{
			name: "mapping pin",
			mutate: func(claim *Claim, _ *PlanningProjection) {
				claim.MappingRevisions = []PinnedMappingRevision{{
					MappingID: mustV7(t), MappingVersion: 1, ConfigurationVersion: 1,
					SourceEpochID: mustV7(t), SourceID: mustV7(t), Priority: 1,
				}}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidateClaim := cloneClaim(claim)
			candidateProjection := baseline
			test.mutate(&candidateClaim, &candidateProjection)
			if _, _, err := planningSnapshot(candidateClaim, candidateProjection); !errors.Is(err, ErrInvalidSnapshot) {
				t.Fatalf("planningSnapshot() error = %v, want ErrInvalidSnapshot", err)
			}
		})
	}
}

func testWorker(
	t *testing.T,
	repository Repository,
	directory DirectoryClient,
	keyring identity.Keyring,
	logs *bytes.Buffer,
) *Worker {
	t.Helper()
	if logs == nil {
		logs = new(bytes.Buffer)
	}
	worker, err := New(Options{
		Repository: repository, Directory: directory, Keyring: keyring,
		Lease: time.Second, OperationTimeout: time.Minute, TerminalTimeout: time.Second,
		AbsenceBatch: 2, Parallelism: 1, MinBackoff: 100 * time.Millisecond,
		MaxBackoff: time.Second, Logger: slog.New(slog.NewJSONHandler(logs, nil)),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return worker
}

func baselineProjection(claim Claim, observationID uuid.UUID) PlanningProjection {
	empty := []byte("[]")
	return PlanningProjection{
		RunID: claim.RunID, ObservationID: observationID, TenantID: claim.TenantID,
		Fence: claim.Fence, ProviderID: claim.ProviderID, ProviderVersion: claim.ProviderVersion,
		BindingID: claim.BindingID, BindingVersion: claim.BindingVersion,
		BindingAuthRevision:   claim.BindingAuthRevision,
		BindingAccessEpochID:  claim.BindingAccessEpochID,
		ConfigurationRevision: int64(claim.ConfigurationVersion),
		RuleSetRevision:       claim.RuleSetRevision, AuthorizationRevision: claim.AuthorizationRevision,
		JITMode: claim.Configuration.JITMode, NoMatchPolicy: claim.Configuration.NoMatchPolicy,
		ProviderAccessSourceID: mustRepositoryV7(),
		Rules:                  empty, SecurityGroups: empty, LiveAssignments: empty,
		RolePolicies: empty, Delegation: empty, LiveOwnedEdges: empty,
	}
}

func testClaim(t *testing.T) (identity.Keyring, Claim, []byte) {
	t.Helper()
	document := []byte(`{"activeVersion":1,"keys":[{"version":1,"key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}`)
	keyring, err := identity.ParseKeyringDocument(document)
	if err != nil {
		t.Fatalf("ParseKeyringDocument() error = %v", err)
	}
	tenantID, providerID, bindingID, secretID := mustV7(t), mustV7(t), mustV7(t), mustV7(t)
	secret := []byte("private-bind-secret-marker")
	plaintext := append([]byte(nil), secret...)
	envelope, err := keyring.EncryptBindSecret(identity.BindSecretContext{
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: identity.EntityID(tenantID),
			ProviderID: identity.EntityID(providerID),
		},
		SecretID: identity.EntityID(secretID),
	}, plaintext)
	clear(plaintext)
	if err != nil {
		t.Fatalf("EncryptBindSecret() error = %v", err)
	}
	claim := Claim{
		RunID: mustV7(t), TenantID: tenantID, Fence: 1,
		ExpiresAt: time.Now().Add(time.Minute), Status: "enumerating", Version: 2,
		ProviderID: providerID, ProviderVersion: 1, ConfigurationVersion: 1,
		EndpointSnapshotDigest: [32]byte{1},
		Configuration: SnapshotConfiguration{
			Template: "openldap", VerifyCertificate: true,
			ConnectTimeoutMS: 1_000, OperationTimeoutMS: 2_000,
			BindDN:     "cn=directory-private-marker,dc=example,dc=com",
			UserBaseDN: "ou=people,dc=example,dc=com", UserSearchFilter: "(uid={username})",
			PageSize: 100, MaxPages: 10, MaxEntries: 100, MaxResponseBytes: 1 << 20,
			ReferralMode: "disabled", MaxReferralHops: 0,
			NestedGroupMode: "disabled", MaxNestedGroupDepth: 0, MaxGroups: 100,
			FirstNameAttribute: "givenName", LastNameAttribute: "sn",
			DisplayNameAttribute: "displayName", UsernameAttribute: "uid",
			ImmutableSubjectAttribute: "entryUUID", ImmutableSubjectFormat: "utf8_exact",
			AccountStatusMode: "none", JITMode: "create", NoMatchPolicy: "provider_access_only",
			DeprovisionMode: "disable", DeprovisionGraceSeconds: 60,
		},
		Endpoints: []SnapshotEndpoint{{
			Priority: 1, Host: "directory-private-marker.internal", Port: 636,
			Transport: ldapclient.TransportLDAPS, TLSServerName: "directory-private-marker.internal",
			Enabled: true,
		}},
		SecretID: secretID, SecretCiphertext: append([]byte(nil), envelope.Ciphertext...),
		SecretNonce: envelope.Nonce, SecretVersion: 1, SecretKeyVersion: envelope.KeyVersion,
		SecretAlgorithm: "aes-256-gcm", BindingID: bindingID, BindingVersion: 1,
		BindingAuthRevision: 1, BindingAccessEpochID: mustV7(t),
		RuleSetRevision: 1, AuthorizationRevision: 1, QueuedAt: time.Now().Add(-time.Minute),
	}
	startedAt := time.Now().Add(-time.Second)
	claim.EnumerationStartedAt = &startedAt
	clear(envelope.Ciphertext)
	return keyring, claim, secret
}

func mustV7(t *testing.T) uuid.UUID {
	t.Helper()
	value, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7() error = %v", err)
	}
	return value
}

func enumeratedUser(username string) ldapclient.DirectoryEntry {
	return ldapclient.DirectoryEntry{
		DistinguishedName: "uid=" + username + ",ou=people,dc=example,dc=com",
		Attributes:        []ldapclient.DirectoryAttribute{{Name: "uid", Values: [][]byte{[]byte(username)}}},
	}
}

func rawObservation(username, displayName string, groupDNs ...string) ldapclient.DirectoryObservation {
	observation := ldapclient.DirectoryObservation{User: ldapclient.DirectoryEntry{
		DistinguishedName: "uid=" + username + ",ou=people,dc=example,dc=com",
		Attributes: []ldapclient.DirectoryAttribute{
			{Name: "givenName", Values: [][]byte{[]byte("Private")}},
			{Name: "sn", Values: [][]byte{[]byte("Profile")}},
			{Name: "displayName", Values: [][]byte{[]byte(displayName)}},
			{Name: "uid", Values: [][]byte{[]byte(username)}},
			{Name: "entryUUID", Values: [][]byte{[]byte("private-subject-marker")}},
		},
	}}
	for _, distinguishedName := range groupDNs {
		observation.Groups = append(observation.Groups, ldapclient.DirectoryEntry{
			DistinguishedName: distinguishedName,
		})
	}
	return observation
}

type fakeDirectory struct {
	mu               sync.Mutex
	enumeration      ldapclient.DirectoryEnumerationResult
	enumerationError error
	observation      ldapclient.DirectoryResult
	observationError error
	blockEnumeration bool
	entered          chan struct{}
	enteredOnce      sync.Once
	secrets          [][]byte
	raw              [][]byte
}

func (directory *fakeDirectory) EnumerateDirectoryUsers(
	ctx context.Context,
	_ ldapclient.DirectoryEnumerationRequest,
	secret []byte,
) (ldapclient.DirectoryEnumerationResult, error) {
	directory.mu.Lock()
	directory.secrets = append(directory.secrets, secret)
	directory.mu.Unlock()
	defer clear(secret)
	if directory.blockEnumeration {
		directory.enteredOnce.Do(func() { close(directory.entered) })
		<-ctx.Done()
		return ldapclient.DirectoryEnumerationResult{}, ctx.Err()
	}
	result := cloneEnumeration(directory.enumeration)
	directory.captureEntries(result.Users)
	return result, directory.enumerationError
}

func (directory *fakeDirectory) ObserveDirectory(
	_ context.Context,
	_ ldapclient.DirectoryRequest,
	secret []byte,
) (ldapclient.DirectoryResult, error) {
	directory.mu.Lock()
	directory.secrets = append(directory.secrets, secret)
	directory.mu.Unlock()
	defer clear(secret)
	result := cloneDirectoryResult(directory.observation)
	directory.captureEntries(append([]ldapclient.DirectoryEntry{result.Observation.User}, result.Observation.Groups...))
	return result, directory.observationError
}

func (directory *fakeDirectory) captureEntries(entries []ldapclient.DirectoryEntry) {
	directory.mu.Lock()
	defer directory.mu.Unlock()
	for _, entry := range entries {
		for _, attribute := range entry.Attributes {
			directory.raw = append(directory.raw, attribute.Values...)
		}
	}
}

func (directory *fakeDirectory) secretBackings() [][]byte {
	directory.mu.Lock()
	defer directory.mu.Unlock()
	return append([][]byte(nil), directory.secrets...)
}

func (directory *fakeDirectory) rawBackings() [][]byte {
	directory.mu.Lock()
	defer directory.mu.Unlock()
	return append([][]byte(nil), directory.raw...)
}

func cloneEnumeration(source ldapclient.DirectoryEnumerationResult) ldapclient.DirectoryEnumerationResult {
	result := source
	result.Users = cloneEntries(source.Users)
	return result
}

func cloneDirectoryResult(source ldapclient.DirectoryResult) ldapclient.DirectoryResult {
	result := source
	entries := cloneEntries(append([]ldapclient.DirectoryEntry{source.Observation.User}, source.Observation.Groups...))
	result.Observation.User = entries[0]
	result.Observation.Groups = entries[1:]
	return result
}

func cloneEntries(source []ldapclient.DirectoryEntry) []ldapclient.DirectoryEntry {
	result := make([]ldapclient.DirectoryEntry, len(source))
	for index, entry := range source {
		result[index].DistinguishedName = entry.DistinguishedName
		result[index].Attributes = make([]ldapclient.DirectoryAttribute, len(entry.Attributes))
		for attributeIndex, attribute := range entry.Attributes {
			result[index].Attributes[attributeIndex].Name = attribute.Name
			result[index].Attributes[attributeIndex].Values = make([][]byte, len(attribute.Values))
			for valueIndex, value := range attribute.Values {
				result[index].Attributes[attributeIndex].Values[valueIndex] = append([]byte(nil), value...)
			}
		}
	}
	return result
}

func assertZeroBackings(t *testing.T, values [][]byte, label string) {
	t.Helper()
	if len(values) == 0 {
		t.Fatalf("no %s backing was observed", label)
	}
	for _, value := range values {
		if !allZero(value) {
			t.Fatalf("%s backing was not cleared", label)
		}
	}
}

type enumerationFingerprint struct {
	expectedVersion int
	complete        bool
	truncated       bool
	hasCursor       bool
	cursor          [32]byte
	failure         string
	audit           AuditIDs
}

type fakeRepository struct {
	mu sync.Mutex

	base                Claim
	proof               ClaimProof
	claimed             bool
	terminal            bool
	status              string
	version             int
	staged              *StagedObservation
	responseLoss        map[string]bool
	lossReturned        map[string]bool
	loseOnRenewal       bool
	loseAfterApply      bool
	staleAt             string
	returnedCiphertexts [][]byte

	claimCalls       int
	stageCalls       int
	planningCalls    int
	applyCalls       int
	enumerationCalls int
	absenceCalls     int
	completeCalls    int
	failCalls        int

	stageRequest       *StagedObservation
	enumerationRequest *enumerationFingerprint
	enumerationResult  EnumerationCompletion
	enumerationFailure string
	applyRequest       *ApplyRequest
	absenceResults     map[AuditIDs]AbsenceResult
	completeAudit      *AuditIDs
	completeVersion    int
	failAudit          *AuditIDs
	failCategory       string
	mappingRule        *planningRuleDocument
	mappingGroup       *planningSecurityGroupDocument
	mappingRolePolicy  *planningRolePolicyDocument
	mappingDelegation  *planningDelegationDocument
	projectionMutation func(*PlanningProjection)
}

func newFakeRepository(claim Claim) *fakeRepository {
	return &fakeRepository{
		base: claim, status: claim.Status, version: claim.Version,
		responseLoss: make(map[string]bool), lossReturned: make(map[string]bool),
		absenceResults: make(map[AuditIDs]AbsenceResult),
	}
}

func (repository *fakeRepository) enableMappingProjection(t *testing.T) uuid.UUID {
	t.Helper()
	ruleID, epochID, sourceID, groupID, roleID := mustV7(t), mustV7(t), mustV7(t), mustV7(t), mustV7(t)
	repository.base.MappingRevisions = []PinnedMappingRevision{{
		MappingID: ruleID, MappingVersion: 1, ConfigurationVersion: 1,
		SourceEpochID: epochID, SourceID: sourceID, Priority: 1,
	}}
	repository.mappingRule = &planningRuleDocument{
		RuleID: ruleID, RuleEpochID: epochID, SourceID: sourceID,
		Revision: 1, Priority: 1, Enabled: true,
		MatcherType: "exact_cn", MatcherValue: "SOC-L2", CaseMode: "sensitive",
		ReconciliationMode: "authoritative", SecurityGroupID: groupID,
		RoleIDs: []uuid.UUID{roleID}, AdministrativeNote: "",
	}
	repository.mappingGroup = &planningSecurityGroupDocument{
		SecurityGroupID: groupID, ActiveRoleIDs: []uuid.UUID{roleID},
	}
	repository.mappingRolePolicy = &planningRolePolicyDocument{
		RoleID: roleID,
		Policy: []planningPermissionDocument{{Permission: "case.read", Scope: "tenant"}},
	}
	repository.mappingDelegation = &planningDelegationDocument{
		Permission: "case.read", Scope: "tenant",
	}
	return epochID
}

func (repository *fakeRepository) expireClaimForReclaim() {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.claimed = false
	repository.proof = ClaimProof{}
	repository.loseAfterApply = false
	repository.base.Fence++
	repository.base.Status = "applying"
	repository.base.Version = repository.version
	repository.status = "applying"
	repository.terminal = false
}

func (repository *fakeRepository) Claim(
	ctx context.Context,
	proof ClaimProof,
	_ int,
) (*Claim, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.claimCalls++
	if !repository.claimed {
		repository.claimed = true
		repository.proof = proof
		if repository.shouldLose("claim") {
			return nil, errFakeResponseLost
		}
	} else if proof != repository.proof || repository.terminal ||
		repository.loseOnRenewal && repository.claimCalls > 1 {
		return nil, nil
	}
	claim := cloneClaim(repository.base)
	claim.Proof = repository.proof
	claim.Status = repository.status
	claim.Version = repository.version
	claim.ExpiresAt = time.Now().Add(time.Minute)
	if repository.staged != nil {
		staged := *repository.staged
		claim.Staged = []StagedObservation{staged}
	}
	repository.returnedCiphertexts = append(repository.returnedCiphertexts, claim.SecretCiphertext)
	return &claim, nil
}

func (repository *fakeRepository) Stage(
	_ context.Context,
	claim Claim,
	observation StagedObservation,
) (*uuid.UUID, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.stageCalls++
	if !repository.owns(claim) || repository.staleAt == "stage" {
		return nil, ErrClaimLost
	}
	if repository.stageRequest == nil {
		copy := observation
		repository.stageRequest = &copy
		repository.staged = &copy
	} else if *repository.stageRequest != observation {
		return nil, ErrInvalidSnapshot
	}
	if repository.shouldLose("stage") {
		return nil, errFakeResponseLost
	}
	return nil, nil
}

func (repository *fakeRepository) CompleteEnumeration(
	_ context.Context,
	claim Claim,
	expectedVersion int,
	complete bool,
	truncated bool,
	cursor *[32]byte,
	failure *string,
	audit AuditIDs,
) (EnumerationCompletion, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.enumerationCalls++
	if !repository.owns(claim) {
		return EnumerationCompletion{}, ErrClaimLost
	}
	fingerprint := enumerationFingerprint{
		expectedVersion: expectedVersion, complete: complete, truncated: truncated, audit: audit,
	}
	if cursor != nil {
		fingerprint.hasCursor = true
		fingerprint.cursor = *cursor
	}
	if failure != nil {
		fingerprint.failure = *failure
	}
	if repository.enumerationRequest == nil {
		repository.enumerationRequest = &fingerprint
		repository.enumerationFailure = fingerprint.failure
		if complete && !truncated && cursor != nil && failure == nil {
			repository.status = "applying"
			repository.version++
			repository.enumerationResult = EnumerationCompletion{
				Status: "applying", Version: repository.version,
				ObservedCount: boolCount(repository.staged != nil), AbsenceAllowed: true,
			}
		} else {
			repository.status = "failed"
			repository.version++
			repository.terminal = true
			repository.enumerationResult = EnumerationCompletion{Status: "failed", Version: repository.version}
		}
	} else if *repository.enumerationRequest != fingerprint {
		return EnumerationCompletion{}, ErrInvalidSnapshot
	}
	if repository.shouldLose("enumeration") {
		return EnumerationCompletion{}, errFakeResponseLost
	}
	return repository.enumerationResult, nil
}

func (repository *fakeRepository) Planning(
	_ context.Context,
	claim Claim,
	observationID uuid.UUID,
	aliases []identity.SubjectAlias,
) (PlanningProjection, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.planningCalls++
	if !repository.owns(claim) || repository.staleAt == "planning" {
		return PlanningProjection{}, ErrClaimLost
	}
	if repository.staged == nil || repository.staged.ObservationID != observationID || len(aliases) < 1 {
		return PlanningProjection{}, ErrInvalidSnapshot
	}
	if repository.shouldLose("planning") {
		return PlanningProjection{}, errFakeResponseLost
	}
	fence := claim.Fence
	repository.staged.PlanningFence = &fence
	projection := baselineProjection(claim, observationID)
	if repository.mappingRule != nil {
		projection.Rules = mustJSON([]planningRuleDocument{*repository.mappingRule})
		projection.SecurityGroups = mustJSON([]planningSecurityGroupDocument{*repository.mappingGroup})
		projection.RolePolicies = mustJSON([]planningRolePolicyDocument{*repository.mappingRolePolicy})
		projection.Delegation = mustJSON([]planningDelegationDocument{*repository.mappingDelegation})
	}
	if repository.projectionMutation != nil {
		repository.projectionMutation(&projection)
	}
	return projection, nil
}

func (repository *fakeRepository) Apply(
	_ context.Context,
	claim Claim,
	request ApplyRequest,
) (ApplyResult, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.applyCalls++
	if !repository.owns(claim) || repository.staleAt == "apply" {
		return ApplyResult{}, ErrClaimLost
	}
	if repository.applyRequest == nil {
		copy := cloneApplyRequest(request)
		repository.applyRequest = &copy
		if repository.staged != nil {
			repository.staged.Applied = true
		}
	} else if !reflect.DeepEqual(*repository.applyRequest, request) {
		return ApplyResult{}, ErrInvalidSnapshot
	}
	if repository.shouldLose("apply") {
		return ApplyResult{}, errFakeResponseLost
	}
	if repository.loseAfterApply {
		return ApplyResult{}, ErrClaimLost
	}
	return ApplyResult{
		ApplicationID: request.ApplicationID, Decision: request.Decision,
		ExternalIdentityID: request.ExternalIdentityID, UserID: request.UserID,
		MembershipID: request.MembershipID, AccessGrantID: request.AccessGrantID,
	}, nil
}

func (repository *fakeRepository) ApplyAbsence(
	_ context.Context,
	claim Claim,
	_ int,
	audit AuditIDs,
) (AbsenceResult, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.absenceCalls++
	if !repository.owns(claim) {
		return AbsenceResult{}, ErrClaimLost
	}
	result, found := repository.absenceResults[audit]
	if !found {
		logicalCall := len(repository.absenceResults)
		if logicalCall == 0 {
			result = AbsenceResult{Inspected: 1, Remaining: 1}
		} else {
			result = AbsenceResult{Inspected: 1, Remaining: 0}
		}
		repository.absenceResults[audit] = result
	}
	if repository.responseLoss["absence"] && !repository.lossReturned["absence:"+audit.EventID.String()] {
		repository.lossReturned["absence:"+audit.EventID.String()] = true
		return AbsenceResult{}, errFakeResponseLost
	}
	return result, nil
}

func (repository *fakeRepository) Complete(
	_ context.Context,
	claim Claim,
	expectedVersion int,
	audit AuditIDs,
) (int, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.completeCalls++
	if !repository.owns(claim) {
		return 0, ErrClaimLost
	}
	if repository.completeAudit == nil {
		copy := audit
		repository.completeAudit = &copy
		repository.completeVersion = expectedVersion + 1
		repository.status = "succeeded"
		repository.version = repository.completeVersion
		repository.terminal = true
	} else if *repository.completeAudit != audit || repository.completeVersion != expectedVersion+1 {
		return 0, ErrInvalidSnapshot
	}
	if repository.shouldLose("complete") {
		return 0, errFakeResponseLost
	}
	return repository.completeVersion, nil
}

func (repository *fakeRepository) Fail(
	_ context.Context,
	claim Claim,
	expectedVersion int,
	category string,
	audit AuditIDs,
) (TerminalResult, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.failCalls++
	if !repository.owns(claim) {
		return TerminalResult{}, ErrClaimLost
	}
	if repository.failAudit == nil {
		copy := audit
		repository.failAudit = &copy
		repository.failCategory = category
		repository.version = expectedVersion + 1
		repository.terminal = true
		repository.status = map[bool]string{true: "cancelled", false: "failed"}[category == "cancelled"]
	} else if *repository.failAudit != audit || repository.failCategory != category {
		return TerminalResult{}, ErrInvalidSnapshot
	}
	if repository.shouldLose("fail") {
		return TerminalResult{}, errFakeResponseLost
	}
	return TerminalResult{Status: repository.status, Version: repository.version}, nil
}

func (repository *fakeRepository) owns(claim Claim) bool {
	return repository.claimed && claim.Proof == repository.proof &&
		claim.RunID == repository.base.RunID && claim.Fence == repository.base.Fence
}

func (repository *fakeRepository) shouldLose(operation string) bool {
	if !repository.responseLoss[operation] || repository.lossReturned[operation] {
		return false
	}
	repository.lossReturned[operation] = true
	return true
}

func cloneClaim(source Claim) Claim {
	result := source
	result.SecretCiphertext = append([]byte(nil), source.SecretCiphertext...)
	result.Endpoints = append([]SnapshotEndpoint(nil), source.Endpoints...)
	result.MappingRevisions = append([]PinnedMappingRevision(nil), source.MappingRevisions...)
	result.Staged = append([]StagedObservation(nil), source.Staged...)
	return result
}

func cloneApplyRequest(source ApplyRequest) ApplyRequest {
	result := source
	cloneUUID := func(value *uuid.UUID) *uuid.UUID {
		if value == nil {
			return nil
		}
		copy := *value
		return &copy
	}
	result.ExternalIdentityID = cloneUUID(source.ExternalIdentityID)
	result.ExistingExternalIdentityID = cloneUUID(source.ExistingExternalIdentityID)
	result.ExistingUserID = cloneUUID(source.ExistingUserID)
	result.ExistingMembershipID = cloneUUID(source.ExistingMembershipID)
	result.ExistingAccessGrantID = cloneUUID(source.ExistingAccessGrantID)
	result.RevocationEpochIDs = cloneSlice(source.RevocationEpochIDs)
	result.UserID = cloneUUID(source.UserID)
	result.MembershipID = cloneUUID(source.MembershipID)
	result.AccessGrantID = cloneUUID(source.AccessGrantID)
	result.ProfileContributionID = cloneUUID(source.ProfileContributionID)
	result.SubjectCiphertext = cloneBytes(source.SubjectCiphertext)
	result.SubjectNonce = cloneBytes(source.SubjectNonce)
	result.AliasIDs = cloneSlice(source.AliasIDs)
	result.AliasKeyVersions = cloneSlice(source.AliasKeyVersions)
	result.AliasDigests = make([][]byte, len(source.AliasDigests))
	for index, digest := range source.AliasDigests {
		result.AliasDigests[index] = cloneBytes(digest)
	}
	result.MatchedEpochIDs = cloneSlice(source.MatchedEpochIDs)
	return result
}

func cloneBytes(source []byte) []byte {
	if source == nil {
		return nil
	}
	result := make([]byte, len(source))
	copy(result, source)
	return result
}

func cloneSlice[T any](source []T) []T {
	if source == nil {
		return nil
	}
	result := make([]T, len(source))
	copy(result, source)
	return result
}

func boolCount(value bool) int {
	if value {
		return 1
	}
	return 0
}

func mustRepositoryV7() uuid.UUID {
	value, err := uuid.NewV7()
	if err != nil {
		panic(err)
	}
	return value
}

func mustJSON(value any) []byte {
	document, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return document
}
