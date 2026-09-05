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
	testSyncRunID       = uuid.MustParse("00000000-0000-7000-8000-000000000140")
	testSyncRunTailID   = uuid.MustParse("00000000-0000-7000-8000-000000000141")
	testSyncAuditID     = uuid.MustParse("00000000-0000-7000-8000-000000000142")
	testSyncAccessEpoch = uuid.MustParse("00000000-0000-7000-8000-000000000143")
)

func TestSyncAdministrationStartManualAuthorizesAndSealsIdempotency(t *testing.T) {
	t.Parallel()

	base := &identityProviderRepositoryStub{}
	base.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testIdentityProviderAuthority(authorization.TenantPermissionIdentitySyncRun), nil
	}
	repository := &syncAdministrationRepositoryStub{identityProviderRepositoryStub: base}
	var received StartManualSyncParams
	repository.start = func(_ context.Context, params StartManualSyncParams) (SyncRunMutationResult, error) {
		received = params
		return SyncRunMutationResult{Run: testQueuedSyncRun(params.RunID, params.Reason, params.ExpectedVersion)}, nil
	}
	service := testIdentityProviderService(t, repository, &diagnosticClientStub{})
	ids := []uuid.UUID{testSyncRunID, testSyncAuditID}
	service.newID = func() (uuid.UUID, error) {
		result := ids[0]
		ids = ids[1:]
		return result, nil
	}
	etag, err := EntityTag(7)
	if err != nil {
		t.Fatal(err)
	}
	input := StartManualSyncInput{
		Reason: "Operator requested reconciliation", IdempotencyKey: "sync-request-0001",
		ExpectedEntityTag: &etag, Audit: testAudit(),
	}

	result, err := service.StartManualSync(context.Background(), testActor(), testTenantID, testBindingID, input)
	if err != nil || result.ID != testSyncRunID {
		t.Fatalf("StartManualSync() = (%#v, %v)", result, err)
	}
	expectedDigest, err := syncRunRequestDigest(testTenantID, testBindingID, 7, input.Reason)
	if err != nil {
		t.Fatal(err)
	}
	if received.RunID != testSyncRunID || received.AuditEventID != testSyncAuditID ||
		received.MembershipID != testMembershipID || received.ExpectedVersion != 7 ||
		received.IdempotencyKeyDigest != sha256.Sum256([]byte(input.IdempotencyKey)) ||
		received.RequestDigest != expectedDigest || received.OccurredAt != testNow {
		t.Fatalf("StartManualSync() params = %#v", received)
	}
}

func TestSyncAdministrationManualReplayRecoversCommittedResponse(t *testing.T) {
	t.Parallel()

	base := &identityProviderRepositoryStub{}
	base.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testIdentityProviderAuthority(authorization.TenantPermissionIdentitySyncRun), nil
	}
	repository := &syncAdministrationRepositoryStub{identityProviderRepositoryStub: base}
	repository.start = func(_ context.Context, params StartManualSyncParams) (SyncRunMutationResult, error) {
		return SyncRunMutationResult{
			Run: testQueuedSyncRun(testSyncRunTailID, params.Reason, params.ExpectedVersion), Replayed: true,
		}, nil
	}
	service := testIdentityProviderService(t, repository, &diagnosticClientStub{})
	ids := []uuid.UUID{testSyncRunID, testSyncAuditID}
	service.newID = func() (uuid.UUID, error) {
		result := ids[0]
		ids = ids[1:]
		return result, nil
	}
	etag, _ := EntityTag(3)

	result, err := service.StartManualSync(context.Background(), testActor(), testTenantID, testBindingID, StartManualSyncInput{
		Reason: "Retry committed command", IdempotencyKey: "sync-response-lost-0001",
		ExpectedEntityTag: &etag, Audit: testAudit(),
	})
	if err != nil || result.ID != testSyncRunTailID {
		t.Fatalf("replayed StartManualSync() = (%#v, %v)", result, err)
	}

	repository.start = func(_ context.Context, params StartManualSyncParams) (SyncRunMutationResult, error) {
		run := testQueuedSyncRun(params.RunID, params.Reason, params.ExpectedVersion)
		run.Snapshot.BindingVersion++
		return SyncRunMutationResult{Run: run}, nil
	}
	ids = []uuid.UUID{testSyncRunID, testSyncAuditID}
	if _, err := service.StartManualSync(context.Background(), testActor(), testTenantID, testBindingID, StartManualSyncInput{
		Reason: "Retry committed command", IdempotencyKey: "sync-response-lost-0001",
		ExpectedEntityTag: &etag, Audit: testAudit(),
	}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("divergent StartManualSync() error = %v", err)
	}
}

func TestSyncAdministrationReadSurfacePaginatesAndFailsClosed(t *testing.T) {
	t.Parallel()

	base := &identityProviderRepositoryStub{}
	base.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderRead), nil
	}
	repository := &syncAdministrationRepositoryStub{identityProviderRepositoryStub: base}
	interval := 900
	repository.status = func(context.Context, GetSyncStatusParams) (SyncStatus, error) {
		return SyncStatus{
			BindingID: testBindingID, ScheduleState: "idle", SyncIntervalSeconds: &interval,
			Version: 1, UpdatedAt: testNow,
		}, nil
	}
	repository.list = func(context.Context, ListSyncRunParams) ([]SyncRun, error) {
		first := testSucceededSyncRun(testSyncRunID)
		second := testQueuedSyncRun(testSyncRunTailID, "Queued", 2)
		return []SyncRun{first, second}, nil
	}
	repository.get = func(context.Context, GetSyncRunParams) (SyncRun, error) {
		return testSucceededSyncRun(testSyncRunID), nil
	}
	service := testIdentityProviderService(t, repository, &diagnosticClientStub{})

	status, err := service.GetSyncStatus(context.Background(), testActor(), testTenantID, testBindingID)
	if err != nil || status.ScheduleState != "idle" {
		t.Fatalf("GetSyncStatus() = (%#v, %v)", status, err)
	}
	page, err := service.ListSyncRuns(context.Background(), testActor(), testTenantID, testBindingID, PageInput{Limit: 1})
	if err != nil || len(page.Items) != 1 || page.NextCursor == nil || *page.NextCursor != testSyncRunID {
		t.Fatalf("ListSyncRuns() = (%#v, %v)", page, err)
	}
	run, err := service.GetSyncRun(context.Background(), testActor(), testTenantID, testBindingID, testSyncRunID)
	if err != nil || run.ID != testSyncRunID {
		t.Fatalf("GetSyncRun() = (%#v, %v)", run, err)
	}

	repository.get = func(context.Context, GetSyncRunParams) (SyncRun, error) {
		value := testSucceededSyncRun(testSyncRunID)
		value.TenantID = uuid.MustParse("00000000-0000-7000-8000-000000000199")
		return value, nil
	}
	if _, err := service.GetSyncRun(context.Background(), testActor(), testTenantID, testBindingID, testSyncRunID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cross-tenant GetSyncRun() error = %v", err)
	}
}

func TestSyncAdministrationRequiresInstalledRepositoryAndExactPermission(t *testing.T) {
	t.Parallel()

	base := &identityProviderRepositoryStub{}
	base.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderManage), nil
	}
	service := testIdentityProviderService(t, base, &diagnosticClientStub{})
	if _, err := service.GetSyncStatus(context.Background(), testActor(), testTenantID, testBindingID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("GetSyncStatus() without read permission error = %v", err)
	}

	base.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderRead), nil
	}
	if _, err := service.GetSyncStatus(context.Background(), testActor(), testTenantID, testBindingID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("GetSyncStatus() without repository surface error = %v", err)
	}
}

func testQueuedSyncRun(runID uuid.UUID, reason string, bindingVersion int64) SyncRun {
	return SyncRun{
		ID: runID, TenantID: testTenantID, BindingID: testBindingID, ProviderID: testProviderID,
		Trigger: "manual", ManualReason: &reason, State: SyncRunQueued,
		Snapshot: PinnedPlannerSnapshot{
			ProviderID: testProviderID, ProviderVersion: 4, BindingID: testBindingID,
			BindingVersion: bindingVersion, ConfigurationRevision: 5, AccessEpochID: testSyncAccessEpoch,
			MappingRevisions: []PinnedMappingRevision{},
		},
		Enumeration: SyncEnumeration{State: "not_started", CursorState: "none"},
		Version:     1, CreatedAt: testNow, UpdatedAt: testNow,
	}
}

func testSucceededSyncRun(runID uuid.UUID) SyncRun {
	startedAt := testNow.Add(time.Second)
	completedAt := testNow.Add(2 * time.Second)
	run := testQueuedSyncRun(runID, "Completed", 2)
	run.State = SyncRunSucceeded
	run.Enumeration = SyncEnumeration{
		State: "complete", Complete: true, AbsenceBasedRevocationAllowed: true,
		EntryCount: 1, PageCount: 1, ResponseBytes: 256, CursorState: "terminal",
	}
	run.Counters = SyncCounters{Observed: 1, Staged: 1, IdentitiesLinked: 1}
	run.StartedAt = &startedAt
	run.CompletedAt = &completedAt
	run.Version = 4
	run.UpdatedAt = completedAt
	return run
}

type syncAdministrationRepositoryStub struct {
	*identityProviderRepositoryStub
	status func(context.Context, GetSyncStatusParams) (SyncStatus, error)
	list   func(context.Context, ListSyncRunParams) ([]SyncRun, error)
	get    func(context.Context, GetSyncRunParams) (SyncRun, error)
	start  func(context.Context, StartManualSyncParams) (SyncRunMutationResult, error)
}

func (s *syncAdministrationRepositoryStub) GetSyncStatus(ctx context.Context, params GetSyncStatusParams) (SyncStatus, error) {
	return s.status(ctx, params)
}

func (s *syncAdministrationRepositoryStub) ListSyncRuns(ctx context.Context, params ListSyncRunParams) ([]SyncRun, error) {
	return s.list(ctx, params)
}

func (s *syncAdministrationRepositoryStub) GetSyncRun(ctx context.Context, params GetSyncRunParams) (SyncRun, error) {
	return s.get(ctx, params)
}

func (s *syncAdministrationRepositoryStub) StartManualSync(ctx context.Context, params StartManualSyncParams) (SyncRunMutationResult, error) {
	return s.start(ctx, params)
}
