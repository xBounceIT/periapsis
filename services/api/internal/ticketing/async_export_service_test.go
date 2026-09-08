package ticketing

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	customkernel "github.com/periapsis-im/periapsis/modules/customfields"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

func TestAsyncExportServiceConstructorRejectsTypedNilRepository(t *testing.T) {
	var repository *fakeAsyncExportRepository
	if _, err := NewAsyncExportService(repository, nil, nil); err == nil {
		t.Fatal("NewAsyncExportService(typed nil) succeeded")
	}
	fixture := newAsyncExportFixture(t)
	var storage *fakeAsyncExportDownloadStorage
	if _, err := NewAsyncExportServiceWithDownloadStorage(
		newFakeAsyncExportRepository(fixture), nil, nil, storage,
	); err == nil {
		t.Fatal("NewAsyncExportServiceWithDownloadStorage(typed nil) succeeded")
	}
}

func TestAsyncExportPrepareDownloadReauthorizesAndBindsExactManifest(t *testing.T) {
	fixture := newAsyncExportFixture(t)
	repository := newFakeAsyncExportRepository(fixture)
	storage := &fakeAsyncExportDownloadStorage{}
	service, err := NewAsyncExportServiceWithDownloadStorage(
		repository,
		func() time.Time { return fixture.now },
		func() ([32]byte, error) { return [32]byte{1, 2, 3, 4}, nil },
		storage,
	)
	if err != nil {
		t.Fatal(err)
	}
	created := mustRequestAsyncExport(t, service, fixture, fixture.operatorRequest)
	jobID := uuidFromEntity(created.Record.Job.Definition().ID())
	if _, err := service.PrepareDownload(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, kernel.TicketExportAudienceOperator, jobID,
	); !errors.Is(err, ErrConflict) || storage.calls != 0 {
		t.Fatalf("pending download = %v, storage calls = %d", err, storage.calls)
	}

	repository.candidateID = jobID
	claimed, found, err := service.Claim(
		context.Background(), fixture.worker, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceOperator, AsyncExportClaimInput{LeaseDuration: 5 * time.Minute},
	)
	if err != nil || !found {
		t.Fatalf("Claim() = (%s, %t, %v)", claimed, found, err)
	}
	artifactID := mustUUIDv7(t)
	digest := sha256.Sum256([]byte("exact artifact"))
	lease := claimed.Record.Job.Lease()
	finished, err := service.Finish(
		context.Background(), fixture.worker, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceOperator, jobID, AsyncExportFinishInput{
			ExpectedRevision: claimed.Record.Job.Revision(), Fence: lease.Fence(),
			Action: AsyncExportFinishSuccess, Artifact: &AsyncExportArtifactInput{
				ID: artifactID, Digest: digest, Rows: 17, Bytes: 211,
				ExpiresAt: fixture.now.Add(fixture.operatorRequest.Retention),
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	storage.grant = AsyncExportDownloadGrant{
		TargetURL: "https://storage.invalid/export.csv?X-Amz-Signature=secret",
		ExpiresAt: fixture.now.Add(AsyncExportDownloadMaximumLifetime),
	}
	prepared, err := service.PrepareDownload(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, kernel.TicketExportAudienceOperator, jobID,
	)
	if err != nil || storage.calls != 1 {
		t.Fatalf("PrepareDownload() = (%s, %v), calls = %d", prepared, err, storage.calls)
	}
	definition := finished.Record.Job.Definition()
	artifact := finished.Record.Job.Artifact()
	if storage.location.TenantID != definition.Tenant() ||
		storage.location.JobID != definition.ID() ||
		storage.location.ArtifactID != artifact.ID() ||
		storage.location.Revision != claimed.Record.Job.Revision() ||
		finished.Record.Job.Revision() != claimed.Record.Job.Revision()+1 ||
		storage.location.Attempt != finished.Record.Job.Attempts() ||
		storage.location.Projection != definition.ProjectionVersion() ||
		storage.location.Digest != digest || storage.location.Rows != 17 ||
		storage.location.Bytes != 211 || storage.expiresAt != storage.grant.ExpiresAt {
		t.Fatalf("download binding = %+v, expiry = %s", storage.location, storage.expiresAt)
	}
	if prepared.Artifact.ID() != artifact.ID() ||
		strings.Contains(prepared.String(), "Signature") ||
		strings.Contains(prepared.GoString(), "storage.invalid") {
		t.Fatalf("prepared download leaked or drifted: %s", prepared)
	}

	repository.humanAllowed = false
	if _, err := service.PrepareDownload(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, kernel.TicketExportAudienceOperator, jobID,
	); !errors.Is(err, ErrForbidden) || storage.calls != 1 {
		t.Fatalf("revoked download = %v, storage calls = %d", err, storage.calls)
	}
}

func TestAsyncExportPrepareDownloadRejectsMalformedStorageGrant(t *testing.T) {
	fixture := newAsyncExportFixture(t)
	repository := newFakeAsyncExportRepository(fixture)
	storage := &fakeAsyncExportDownloadStorage{}
	service, err := NewAsyncExportServiceWithDownloadStorage(
		repository,
		func() time.Time { return fixture.now },
		nil,
		storage,
	)
	if err != nil {
		t.Fatal(err)
	}
	created := mustRequestAsyncExport(t, service, fixture, fixture.operatorRequest)
	jobID := uuidFromEntity(created.Record.Job.Definition().ID())
	repository.candidateID = jobID
	claimed, found, err := service.Claim(
		context.Background(), fixture.worker, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceOperator, AsyncExportClaimInput{LeaseDuration: 5 * time.Minute},
	)
	if err != nil || !found {
		t.Fatal(err)
	}
	artifactID := mustUUIDv7(t)
	digest := sha256.Sum256([]byte("artifact"))
	lease := claimed.Record.Job.Lease()
	if _, err := service.Finish(
		context.Background(), fixture.worker, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceOperator, jobID, AsyncExportFinishInput{
			ExpectedRevision: claimed.Record.Job.Revision(), Fence: lease.Fence(),
			Action: AsyncExportFinishSuccess, Artifact: &AsyncExportArtifactInput{
				ID: artifactID, Digest: digest, Bytes: 20,
				ExpiresAt: fixture.now.Add(fixture.operatorRequest.Retention),
			},
		},
	); err != nil {
		t.Fatal(err)
	}
	for _, grant := range []AsyncExportDownloadGrant{
		{TargetURL: "javascript:alert(1)", ExpiresAt: fixture.now.Add(time.Minute)},
		{TargetURL: "https://user:secret@storage.invalid/export", ExpiresAt: fixture.now.Add(time.Minute)},
		{TargetURL: "https://storage.invalid/export#secret", ExpiresAt: fixture.now.Add(time.Minute)},
		{TargetURL: "https://storage.invalid/export", ExpiresAt: fixture.now.Add(6 * time.Minute)},
	} {
		storage.grant = grant
		if _, err := service.PrepareDownload(
			context.Background(), fixture.base.actor, fixture.base.tenantUUID,
			kernel.AggregateAlert, kernel.TicketExportAudienceOperator, jobID,
		); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("malformed grant %#v error = %v", grant, err)
		}
	}
}

func TestAsyncExportRequestUsesExplicitAudienceAndLiveReplayAuthorization(t *testing.T) {
	fixture := newAsyncExportFixture(t)
	repository := newFakeAsyncExportRepository(fixture)
	service := mustAsyncExportService(t, repository, fixture.now)
	input := fixture.operatorRequest

	first, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, kernel.AggregateAlert, input,
	)
	if err != nil || first.Replayed {
		t.Fatalf("first Request() = (%s, %v)", first, err)
	}
	second, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, kernel.AggregateAlert, input,
	)
	if err != nil || !second.Replayed ||
		second.Record.Job.Definition().ID() != first.Record.Job.Definition().ID() {
		t.Fatalf("replayed Request() = (%s, %v)", second, err)
	}
	if repository.reserveCalls.Load() != 1 || repository.commitRequestCalls.Load() != 1 {
		t.Fatalf(
			"replay work: reserve=%d commit=%d",
			repository.reserveCalls.Load(), repository.commitRequestCalls.Load(),
		)
	}

	repository.humanAllowed = false
	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, kernel.AggregateAlert, input,
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked replay error = %v", err)
	}
	repository.humanAllowed = true

	drifted := input
	drifted.MaximumRows++
	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, kernel.AggregateAlert, drifted,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("divergent idempotency reuse error = %v", err)
	}
	if repository.reserveCalls.Load() != 1 {
		t.Fatal("divergent replay reserved another ID")
	}

	repository.forcePrincipal = kernel.PrincipalCustomer
	repository.resolveQueryCalls.Store(0)
	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, kernel.AggregateAlert,
		asyncExportRequestWithKey(input, "async-export-route-intent-0002"),
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("customer on operator intent error = %v", err)
	}
	if repository.resolveQueryCalls.Load() != 0 {
		t.Fatal("denied audience reached query resolution")
	}

	// A read-only or custom/JIT operator is represented by the resolved route
	// intent and live capability, not by a LegacyRole string. PrincipalOperator
	// with allowed=true remains valid regardless of role vocabulary.
	repository.forcePrincipal = kernel.PrincipalOperator
	if _, err := NewAsyncExportAccess(
		fixture.base.tenantUUID, fixture.base.actor.UserID, fixture.base.membershipUUID,
		kernel.AggregateAlert, kernel.TicketExportAudienceOperator,
		AsyncExportCapabilityExecute, kernel.PrincipalOperator, nil, true, true, true,
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("worker capability on human authority error = %v", err)
	}
	repository.publicComments = false
	repository.resolveQueryCalls.Store(0)
	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, kernel.AggregateAlert,
		asyncExportRequestWithKey(input, "async-export-public-comment-revoked"),
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("public-comment capability revoked error = %v", err)
	}
	if repository.resolveQueryCalls.Load() != 0 {
		t.Fatal("missing public-comment capability reached query resolution")
	}
	withoutComments := asyncExportRequestWithKey(input, "async-export-without-comments")
	withoutComments.Comments = kernel.TicketExportCommentsNone
	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, withoutComments,
	); err != nil {
		t.Fatalf("comment-free request incorrectly required comment permission: %v", err)
	}
	repository.publicComments = true
	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, kernel.AggregateAlert,
		asyncExportRequestWithKey(input, "async-export-read-only-operator"),
	); err != nil {
		t.Fatalf("capability-authorized operator request: %v", err)
	}

	repository.revokeHumanAtCommit = true
	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, kernel.AggregateAlert,
		asyncExportRequestWithKey(input, "async-export-commit-revoked"),
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("commit-time revocation error = %v", err)
	}
}

func TestAsyncExportConcurrentRequestCommitReturnsImmutableWinnerReplay(t *testing.T) {
	fixture := newAsyncExportFixture(t)
	repository := newFakeAsyncExportRepository(fixture)
	repository.uniqueReservedIDs = true
	repository.reserveBarrier = &sync.WaitGroup{}
	repository.reserveBarrier.Add(2)
	var ticks atomic.Int64
	service, err := NewAsyncExportService(repository, func() time.Time {
		return fixture.now.Add(time.Duration(ticks.Add(1)) * time.Microsecond)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		result AsyncExportResult
		err    error
	}
	outcomes := make(chan outcome, 2)
	for range 2 {
		go func() {
			result, requestErr := service.Request(
				context.Background(), fixture.base.actor, fixture.base.tenantUUID,
				kernel.AggregateAlert, fixture.operatorRequest,
			)
			outcomes <- outcome{result: result, err: requestErr}
		}()
	}
	replayed := 0
	var winner kernel.TicketExportJob
	for range 2 {
		outcome := <-outcomes
		if outcome.err != nil {
			t.Fatalf("concurrent Request() error = %v", outcome.err)
		}
		if outcome.result.Replayed {
			replayed++
		}
		if winner.Revision() == 0 {
			winner = outcome.result.Record.Job
		} else if !kernel.SameTicketExportJob(winner, outcome.result.Record.Job) {
			t.Fatalf("request replay drifted from winner: %s != %s", winner, outcome.result.Record.Job)
		}
	}
	if replayed != 1 || repository.reserveCalls.Load() != 2 || repository.commitRequestCalls.Load() != 2 {
		t.Fatalf(
			"request winners: replayed=%d reserves=%d commits=%d",
			replayed, repository.reserveCalls.Load(), repository.commitRequestCalls.Load(),
		)
	}
}

func TestAsyncExportReplayRejectsRepositoryAttemptPolicyDrift(t *testing.T) {
	fixture := newAsyncExportFixture(t)
	repository := newFakeAsyncExportRepository(fixture)
	service := mustAsyncExportService(t, repository, fixture.now)
	first := mustRequestAsyncExport(t, service, fixture, fixture.operatorRequest)

	repository.mu.Lock()
	for key, replay := range repository.replays {
		definition := replay.result.Record.Job.Definition()
		input := asyncExportDefinitionInput(definition)
		input.MaximumAttempts = 1
		drifted, err := kernel.NewTicketExportDefinition(input)
		if err != nil {
			repository.mu.Unlock()
			t.Fatal(err)
		}
		snapshot := replay.result.Record.Job.Snapshot()
		snapshot.Definition = drifted
		job, err := kernel.RestoreTicketExportJob(snapshot)
		if err != nil {
			repository.mu.Unlock()
			t.Fatal(err)
		}
		replay.result.Record.Job = job
		repository.replays[key] = replay
	}
	repository.mu.Unlock()

	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, fixture.operatorRequest,
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("attempt-policy replay drift error = %v; first=%s", err, first)
	}
}

func TestAsyncExportRejectsMalformedReservedIDAsRepositoryFailure(t *testing.T) {
	fixture := newAsyncExportFixture(t)
	repository := newFakeAsyncExportRepository(fixture)
	repository.invalidReservedID = true
	service := mustAsyncExportService(t, repository, fixture.now)

	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, fixture.operatorRequest,
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("malformed reserved ID error = %v", err)
	}
	if repository.commitRequestCalls.Load() != 0 {
		t.Fatal("malformed reserved ID reached commit")
	}
}

func TestAsyncExportReservesTerminalRevisionCapacity(t *testing.T) {
	fixture := newAsyncExportFixture(t)
	id, _ := entityID(fixture.reservedID)
	access := mustAsyncExportAccess(
		t, fixture, kernel.TicketExportAudienceOperator, AsyncExportCapabilityRequest,
	)
	definition, err := newAsyncExportDefinition(id, access, fixture.operatorInlineQuery, fixture.operatorRequest)
	if err != nil {
		t.Fatal(err)
	}
	available := fixture.now.Add(time.Minute)
	job, err := kernel.RestoreTicketExportJob(kernel.TicketExportJobSnapshot{
		Definition: definition, State: kernel.TicketExportPending,
		Revision: maxResourceVersion - 1, Attempts: 1,
		FailureCode: kernel.TicketExportFailureTransientDatabase,
		RequestedAt: fixture.now, UpdatedAt: fixture.now, AvailableAt: available,
		ExpiresAt: fixture.now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	workerID, _ := entityID(fixture.worker.WorkerID)
	plan, err := kernel.PlanTicketExportClaim(
		job, workerID, [32]byte{4}, available, available.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAsyncExportPlanCapacity(plan); !errors.Is(err, ErrConflict) {
		t.Fatalf("non-terminal final revision error = %v", err)
	}

	snapshot := job.Snapshot()
	snapshot.Revision = maxResourceVersion
	poisoned, err := kernel.RestoreTicketExportJob(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := normalizeAsyncExportRecord(AsyncExportRecord{
		Job: poisoned, Query: fixture.operatorInlineQuery,
	}, nil, nil, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("repository non-terminal final revision error = %v", err)
	}
}

func TestAsyncExportCustomerShapeFailsClosed(t *testing.T) {
	fixture := newAsyncExportFixture(t)
	repository := newFakeAsyncExportRepository(fixture)
	service := mustAsyncExportService(t, repository, fixture.now)

	result, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, fixture.customerRequest,
	)
	if err != nil || result.Record.Job.Definition().Audience() != kernel.TicketExportAudienceCustomer {
		t.Fatalf("customer Request() = (%s, %v)", result, err)
	}
	definition := result.Record.Job.Definition()
	if definition.CustomerContact() == nil ||
		uuidFromEntity(*definition.CustomerContact()) != fixture.customerContact {
		t.Fatalf("customer relationship pin = %#v", definition.CustomerContact())
	}

	private := fixture.customerRequest
	private.Comments = kernel.TicketExportCommentsPublicAndPrivate
	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, kernel.AggregateAlert, private,
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("customer private-comment request error = %v", err)
	}
	saved := fixture.customerRequest
	saved.Source = fixture.operatorSavedSource
	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, kernel.AggregateAlert, saved,
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("customer saved-view request error = %v", err)
	}

	repository.customerQuery = fixture.operatorInlineQuery
	drifted := asyncExportRequestWithKey(fixture.customerRequest, "async-export-customer-overfetch")
	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, kernel.AggregateAlert, drifted,
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("customer operator-shaped query error = %v", err)
	}
	for _, test := range []struct {
		name  string
		query AsyncExportQuerySnapshot
	}{
		{name: "private assignment sort", query: customerAsyncExportQueryVariant(t, fixture, "oldest_unclaimed", false)},
		{name: "hidden output column", query: customerAsyncExportQueryVariant(t, fixture, "updated_at", true)},
	} {
		repository.customerQuery = test.query
		request := asyncExportRequestWithKey(
			fixture.customerRequest, "async-export-customer-"+strings.ReplaceAll(test.name, " ", "-"),
		)
		if _, err := service.Request(
			context.Background(), fixture.base.actor, fixture.base.tenantUUID,
			kernel.AggregateAlert, request,
		); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("%s error = %v", test.name, err)
		}
	}

	repository.customerQuery = fixture.customerQuery
	repository.forcePrincipal = kernel.PrincipalOperator
	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, kernel.AggregateAlert,
		asyncExportRequestWithKey(fixture.customerRequest, "async-export-operator-on-customer-route"),
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("operator on customer route error = %v", err)
	}
	repository.forcePrincipal = 0
	repository.missingCustomerContact = true
	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, kernel.AggregateAlert,
		asyncExportRequestWithKey(fixture.customerRequest, "async-export-customer-no-link"),
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing linked-contact evidence error = %v", err)
	}
	repository.missingCustomerContact = false
	repository.revokeHumanAtCommit = true
	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, kernel.AggregateAlert,
		asyncExportRequestWithKey(fixture.customerRequest, "async-export-customer-link-revoked"),
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("customer link revoked at commit error = %v", err)
	}
}

func TestAsyncExportSavedViewPinsAreExactAndOwnerBound(t *testing.T) {
	fixture := newAsyncExportFixture(t)
	repository := newFakeAsyncExportRepository(fixture)
	repository.operatorQuery = fixture.operatorSavedQuery
	service := mustAsyncExportService(t, repository, fixture.now)
	input := fixture.operatorRequest
	input.Source = fixture.operatorSavedSource
	input.IdempotencyKey = "async-export-saved-view-0001"

	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, kernel.AggregateAlert, input,
	); err != nil {
		t.Fatalf("saved-view Request(): %v", err)
	}

	for _, test := range []struct {
		name  string
		query AsyncExportQuerySnapshot
	}{
		{name: "revision drift", query: mustAsyncExportSavedQuery(t, fixture, fixture.savedViewRevision+1, fixture.base.membershipUUID)},
		{name: "owner drift", query: mustAsyncExportSavedQuery(t, fixture, fixture.savedViewRevision, mustUUIDv7(t))},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository.operatorQuery = test.query
			request := input
			request.IdempotencyKey = "async-export-saved-view-" + strings.ReplaceAll(test.name, " ", "-")
			if _, err := service.Request(
				context.Background(), fixture.base.actor, fixture.base.tenantUUID,
				kernel.AggregateAlert, request,
			); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("pin drift error = %v", err)
			}
		})
	}

	repository.resolveQueryErr = ErrNotFound
	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, kernel.AggregateAlert,
		asyncExportRequestWithKey(input, "async-export-archived-saved-view"),
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("archived saved-view error = %v", err)
	}

	dynamicPin, err := kernel.NewSavedViewDefinitionPin(
		workflowTenantEntity(mustUUIDv7(t)), fixture.base.tenant, kernel.AggregateAlert,
		mustApplicationTicketKey(t, "dynamic_signal"), maxResourceVersion+1, [32]byte{7},
	)
	if err != nil {
		t.Fatal(err)
	}
	dynamicColumn, err := kernel.NewSavedViewDynamicColumn(
		kernel.SavedViewColumnCustomField, dynamicPin, 160, true, kernel.SavedViewColumnUnpinned,
	)
	if err != nil {
		t.Fatal(err)
	}
	columns := append(fixture.operatorInlineQuery.Spec().Columns(), dynamicColumn)
	driftedSpec, err := kernel.NewSavedViewSpec(
		fixture.base.tenant, kernel.AggregateAlert, fixture.operatorInlineQuery.Spec().Filters(),
		fixture.operatorInlineQuery.Spec().Sort(), columns,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAsyncExportQuerySnapshot(
		fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportQueryInline, driftedSpec, nil,
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("oversized dynamic definition version error = %v", err)
	}
}

func TestAsyncExportInlineRequestBindsExactCanonicalResolvedSpec(t *testing.T) {
	fixture := newAsyncExportFixture(t)

	t.Run("substituted search", func(t *testing.T) {
		repository := newFakeAsyncExportRepository(fixture)
		repository.operatorQuery = asyncExportInlineQueryWithSearch(t, fixture, "substituted query")
		service := mustAsyncExportService(t, repository, fixture.now)

		if _, err := service.Request(
			context.Background(), fixture.base.actor, fixture.base.tenantUUID,
			kernel.AggregateAlert, fixture.operatorRequest,
		); !errors.Is(err, ErrUnavailable) || repository.reserveCalls.Load() != 0 ||
			repository.commitRequestCalls.Load() != 0 {
			t.Fatalf(
				"substituted search error=%v reserve=%d commit=%d",
				err, repository.reserveCalls.Load(), repository.commitRequestCalls.Load(),
			)
		}
	})

	t.Run("resolver cannot rewrite request clone", func(t *testing.T) {
		repository := newFakeAsyncExportRepository(fixture)
		repository.operatorQuery = asyncExportInlineQueryWithSearch(t, fixture, "substituted query")
		repository.resolveQueryHook = func(source *AsyncExportSourceInput) {
			source.Inline.Filters.Search = "substituted query"
		}
		service := mustAsyncExportService(t, repository, fixture.now)

		if _, err := service.Request(
			context.Background(), fixture.base.actor, fixture.base.tenantUUID,
			kernel.AggregateAlert, fixture.operatorRequest,
		); !errors.Is(err, ErrUnavailable) || repository.reserveCalls.Load() != 0 ||
			fixture.operatorRequest.Source.Inline.Filters.Search != "malware campaign" {
			t.Fatalf(
				"mutating resolver error=%v reserve=%d original_search=%q",
				err, repository.reserveCalls.Load(), fixture.operatorRequest.Source.Inline.Filters.Search,
			)
		}
	})

	t.Run("set ordering is canonical", func(t *testing.T) {
		input, query := asyncExportSetOrderedQueryFixture(t, fixture)
		repository := newFakeAsyncExportRepository(fixture)
		repository.operatorQuery = query
		service := mustAsyncExportService(t, repository, fixture.now)

		result, err := service.Request(
			context.Background(), fixture.base.actor, fixture.base.tenantUUID,
			kernel.AggregateAlert, input,
		)
		if err != nil || result.Record.Query.QueryDigest() != query.QueryDigest() ||
			repository.reserveCalls.Load() != 1 {
			t.Fatalf("canonically reordered request=(%s, %v), reserve=%d", result, err, repository.reserveCalls.Load())
		}
	})

	t.Run("column ordering remains structural", func(t *testing.T) {
		repository := newFakeAsyncExportRepository(fixture)
		repository.operatorQuery = asyncExportQueryWithReversedColumns(t, fixture)
		service := mustAsyncExportService(t, repository, fixture.now)

		if _, err := service.Request(
			context.Background(), fixture.base.actor, fixture.base.tenantUUID,
			kernel.AggregateAlert, fixture.operatorRequest,
		); !errors.Is(err, ErrUnavailable) || repository.reserveCalls.Load() != 0 {
			t.Fatalf("reordered columns error=%v reserve=%d", err, repository.reserveCalls.Load())
		}
	})
}

func TestAsyncExportInlineRequestUsesCanonicalDynamicFilterValue(t *testing.T) {
	fixture := newAsyncExportFixture(t)
	input, query := asyncExportDecimalQueryFixture(t, fixture, "10.500")
	repository := newFakeAsyncExportRepository(fixture)
	repository.operatorQuery = query
	service := mustAsyncExportService(t, repository, fixture.now)

	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, input,
	); err != nil {
		t.Fatalf("semantically equivalent decimal rejected: %v", err)
	}

	hostile := asyncExportRequestWithKey(input, "async-export-decimal-filter-0002")
	hostile.Source.Inline.Filters.Custom[0].Value = []byte("11")
	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, hostile,
	); !errors.Is(err, ErrUnavailable) || repository.reserveCalls.Load() != 1 {
		t.Fatalf("substituted filter error=%v reserve=%d", err, repository.reserveCalls.Load())
	}
}

func TestAsyncExportOwnerIsolationAndCancellationReplay(t *testing.T) {
	fixture := newAsyncExportFixture(t)
	repository := newFakeAsyncExportRepository(fixture)
	service := mustAsyncExportService(t, repository, fixture.now)
	created := mustRequestAsyncExport(t, service, fixture, fixture.operatorRequest)
	jobID := uuidFromEntity(created.Record.Job.Definition().ID())

	other := fixture.base.actor
	other.UserID = mustUUIDv7(t)
	other.SessionID = mustUUIDv7(t)
	if _, err := service.Get(
		context.Background(), other, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceOperator, jobID,
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign-owner Get() error = %v", err)
	}
	foreignDefinitionInput := asyncExportDefinitionInput(created.Record.Job.Definition())
	foreignRequester, _ := entityID(other.UserID)
	foreignDefinitionInput.Requester = foreignRequester
	foreignDefinition, err := kernel.NewTicketExportDefinition(foreignDefinitionInput)
	if err != nil {
		t.Fatal(err)
	}
	foreignSnapshot := created.Record.Job.Snapshot()
	foreignSnapshot.Definition = foreignDefinition
	foreignJob, err := kernel.RestoreTicketExportJob(foreignSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	access := mustAsyncExportAccess(
		t, fixture, kernel.TicketExportAudienceOperator, AsyncExportCapabilityRead,
	)
	if _, err := normalizeAsyncExportRecord(AsyncExportRecord{
		Job: foreignJob, Query: AsyncExportQuerySnapshot{},
	}, &access, nil, &jobID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("corrupt foreign-owner oracle error = %v", err)
	}

	cancelInput := AsyncExportCancelInput{
		ExpectedRevision: 1, IdempotencyKey: "async-export-cancel-0001",
	}
	first, err := service.Cancel(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceOperator, jobID, cancelInput,
	)
	if err != nil || first.Replayed || first.Record.Job.State() != kernel.TicketExportCancelledState {
		t.Fatalf("first Cancel() = (%s, %v)", first, err)
	}
	gets := repository.getCalls.Load()
	second, err := service.Cancel(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceOperator, jobID, cancelInput,
	)
	if err != nil || !second.Replayed || repository.getCalls.Load() != gets {
		t.Fatalf("replayed Cancel() = (%s, %v), gets=%d->%d", second, err, gets, repository.getCalls.Load())
	}

	repository.forceGetErr = ErrForbidden
	if _, err := service.Get(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceOperator, mustUUIDv7(t),
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("forbidden/missing oracle mapping error = %v", err)
	}
}

func TestAsyncExportConcurrentCancelCommitReturnsImmutableWinnerReplay(t *testing.T) {
	fixture := newAsyncExportFixture(t)
	repository := newFakeAsyncExportRepository(fixture)
	created := mustRequestAsyncExport(
		t, mustAsyncExportService(t, repository, fixture.now), fixture, fixture.operatorRequest,
	)
	jobID := uuidFromEntity(created.Record.Job.Definition().ID())
	repository.getBarrier = &sync.WaitGroup{}
	repository.getBarrier.Add(2)
	var ticks atomic.Int64
	service, err := NewAsyncExportService(repository, func() time.Time {
		return fixture.now.Add(time.Duration(ticks.Add(1)) * time.Microsecond)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	input := AsyncExportCancelInput{
		ExpectedRevision: created.Record.Job.Revision(),
		IdempotencyKey:   "async-export-concurrent-cancel-0001",
	}
	type outcome struct {
		result AsyncExportResult
		err    error
	}
	outcomes := make(chan outcome, 2)
	for range 2 {
		go func() {
			result, cancelErr := service.Cancel(
				context.Background(), fixture.base.actor, fixture.base.tenantUUID, kernel.AggregateAlert,
				kernel.TicketExportAudienceOperator, jobID, input,
			)
			outcomes <- outcome{result: result, err: cancelErr}
		}()
	}
	replayed := 0
	var winner kernel.TicketExportJob
	for range 2 {
		outcome := <-outcomes
		if outcome.err != nil {
			t.Fatalf("concurrent Cancel() error = %v", outcome.err)
		}
		if outcome.result.Replayed {
			replayed++
		}
		if winner.Revision() == 0 {
			winner = outcome.result.Record.Job
		} else if !kernel.SameTicketExportJob(winner, outcome.result.Record.Job) {
			t.Fatalf("cancel replay drifted from winner: %s != %s", winner, outcome.result.Record.Job)
		}
	}
	if replayed != 1 || repository.commitOwnerCalls.Load() != 2 {
		t.Fatalf("cancel winners: replayed=%d commits=%d", replayed, repository.commitOwnerCalls.Load())
	}
}

func TestAsyncExportWorkerClaimPageAndFinishAreFencedAndBounded(t *testing.T) {
	fixture := newAsyncExportFixture(t)
	repository := newFakeAsyncExportRepository(fixture)
	service := mustAsyncExportService(t, repository, fixture.now)
	request := fixture.operatorRequest
	request.Comments = kernel.TicketExportCommentsPublicAndPrivate
	created := mustRequestAsyncExport(t, service, fixture, request)
	jobID := uuidFromEntity(created.Record.Job.Definition().ID())
	repository.candidateID = jobID

	claimed, found, err := service.Claim(
		context.Background(), fixture.worker, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceOperator, AsyncExportClaimInput{LeaseDuration: 5 * time.Minute},
	)
	if err != nil || !found || claimed.Record.Job.State() != kernel.TicketExportRunning {
		t.Fatalf("Claim() = (%s, %t, %v)", claimed, found, err)
	}
	lease := claimed.Record.Job.Lease()
	repository.page = AsyncExportPage{Rows: []AsyncExportRow{
		{Kind: AsyncExportTicketRow, Cells: []string{"=HYPERLINK(\"https://invalid\")", "normal"}},
		{Kind: AsyncExportPrivateCommentRow, Cells: []string{"@SUM(1,1)", "+cmd"}},
	}, NextCursor: "bmV4dA"}
	page, err := service.ReadPage(
		context.Background(), fixture.worker, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceOperator, jobID, AsyncExportPageInput{
			ExpectedRevision: claimed.Record.Job.Revision(), Fence: lease.Fence(), Limit: 10,
		},
	)
	if err != nil || len(page.Rows) != 2 || !strings.HasPrefix(page.Rows[0].Cells[0], "'") ||
		!strings.HasPrefix(page.Rows[1].Cells[0], "'") {
		t.Fatalf("ReadPage() = (%#v, %v)", page, err)
	}
	if strings.HasPrefix(repository.page.Rows[0].Cells[0], "'") {
		t.Fatal("page normalization mutated repository-owned cells")
	}
	for name, page := range map[string]AsyncExportPage{
		"oversized cell": {
			Rows: []AsyncExportRow{{
				Kind:  AsyncExportTicketRow,
				Cells: []string{strings.Repeat("x", AsyncExportMaximumCellBytes+1), "normal"},
			}},
		},
		"directional control": {
			Rows: []AsyncExportRow{{Kind: AsyncExportTicketRow, Cells: []string{"safe\u202eunsafe", "normal"}}},
		},
		"row limit": {
			Rows: func() []AsyncExportRow {
				rows := make([]AsyncExportRow, 11)
				for index := range rows {
					rows[index] = AsyncExportRow{Kind: AsyncExportTicketRow, Cells: []string{"safe", "normal"}}
				}
				return rows
			}(),
		},
	} {
		repository.page = page
		if _, err := service.ReadPage(
			context.Background(), fixture.worker, fixture.base.tenantUUID, kernel.AggregateAlert,
			kernel.TicketExportAudienceOperator, jobID, AsyncExportPageInput{
				ExpectedRevision: claimed.Record.Job.Revision(), Fence: lease.Fence(), Limit: 10,
			},
		); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("%s page error = %v", name, err)
		}
	}

	stale := lease.Fence()
	stale[0]++
	if _, err := service.ReadPage(
		context.Background(), fixture.worker, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceOperator, jobID, AsyncExportPageInput{
			ExpectedRevision: claimed.Record.Job.Revision(), Fence: stale, Limit: 10,
		},
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale-fence page error = %v", err)
	}

	commits := repository.commitWorkerCalls.Load()
	if _, err := service.Finish(
		context.Background(), fixture.worker, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceOperator, jobID, AsyncExportFinishInput{
			ExpectedRevision: claimed.Record.Job.Revision(), Fence: lease.Fence(),
			Action: AsyncExportFinishFailure, FailureCode: kernel.TicketExportFailureAuthorizationRevoked,
		},
	); !errors.Is(err, ErrInvalidInput) || repository.commitWorkerCalls.Load() != commits {
		t.Fatalf("unproven revocation failure = %v, commits=%d->%d", err, commits, repository.commitWorkerCalls.Load())
	}

	artifactID := mustUUIDv7(t)
	digest := sha256.Sum256([]byte("artifact"))
	finished, err := service.Finish(
		context.Background(), fixture.worker, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceOperator, jobID, AsyncExportFinishInput{
			ExpectedRevision: claimed.Record.Job.Revision(), Fence: lease.Fence(),
			Action: AsyncExportFinishSuccess, Artifact: &AsyncExportArtifactInput{
				ID: artifactID, Digest: digest, Rows: 2, Bytes: 200,
				ExpiresAt: fixture.now.Add(time.Hour),
			},
		},
	)
	if err != nil || finished.Record.Job.State() != kernel.TicketExportSucceeded {
		t.Fatalf("Finish() = (%s, %v)", finished, err)
	}
}

func TestAsyncExportWorkerRechecksRequesterAndVisibilityAtEveryBoundary(t *testing.T) {
	fixture := newAsyncExportFixture(t)
	repository := newFakeAsyncExportRepository(fixture)
	service := mustAsyncExportService(t, repository, fixture.now)
	created := mustRequestAsyncExport(t, service, fixture, fixture.customerRequest)
	jobID := uuidFromEntity(created.Record.Job.Definition().ID())
	repository.candidateID = jobID

	repository.requesterAuthorized = false
	if _, _, err := service.Claim(
		context.Background(), fixture.worker, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceCustomer, AsyncExportClaimInput{LeaseDuration: time.Minute},
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("claim after contact/read revocation error = %v", err)
	}
	repository.requesterAuthorized = true
	claimed, found, err := service.Claim(
		context.Background(), fixture.worker, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceCustomer, AsyncExportClaimInput{LeaseDuration: time.Minute},
	)
	if err != nil || !found {
		t.Fatalf("authorized claim = (%s, %t, %v)", claimed, found, err)
	}
	lease := claimed.Record.Job.Lease()

	repository.page = AsyncExportPage{Rows: []AsyncExportRow{{
		Kind: AsyncExportPrivateCommentRow, Cells: []string{"private", "private", "private"},
	}}}
	if _, err := service.ReadPage(
		context.Background(), fixture.worker, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceCustomer, jobID, AsyncExportPageInput{
			ExpectedRevision: claimed.Record.Job.Revision(), Fence: lease.Fence(), Limit: 10,
		},
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("customer private row error = %v", err)
	}

	repository.page = AsyncExportPage{Rows: []AsyncExportRow{{
		Kind: AsyncExportTicketRow, Cells: []string{"ticket", "state", "updated"},
	}}, NextCursor: "c2FtZQ"}
	if _, err := service.ReadPage(
		context.Background(), fixture.worker, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceCustomer, jobID, AsyncExportPageInput{
			ExpectedRevision: claimed.Record.Job.Revision(), Fence: lease.Fence(), After: "c2FtZQ", Limit: 10,
		},
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("non-advancing cursor error = %v", err)
	}

	repository.requesterAuthorized = false
	digest := sha256.Sum256([]byte("artifact"))
	if _, err := service.Finish(
		context.Background(), fixture.worker, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceCustomer, jobID, AsyncExportFinishInput{
			ExpectedRevision: claimed.Record.Job.Revision(), Fence: lease.Fence(),
			Action: AsyncExportFinishSuccess, Artifact: &AsyncExportArtifactInput{
				ID: mustUUIDv7(t), Digest: digest, Rows: 1, Bytes: 100,
				ExpiresAt: fixture.now.Add(time.Hour),
			},
		},
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("finish after requester revocation error = %v", err)
	}
	revoked, err := service.RejectRevoked(
		context.Background(), fixture.worker, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceCustomer, jobID, claimed.Record.Job.Revision(),
	)
	if err != nil || revoked.Job.State() != kernel.TicketExportFailed ||
		revoked.Job.FailureCode() != kernel.TicketExportFailureAuthorizationRevoked ||
		revoked.Job.Artifact() != nil {
		t.Fatalf("RejectRevoked() = (%s, %v)", revoked, err)
	}
}

func TestAsyncExportWorkerRenewalAndExpiryTransitions(t *testing.T) {
	fixture := newAsyncExportFixture(t)
	repository := newFakeAsyncExportRepository(fixture)
	now := fixture.now
	var fenceCounter byte
	service, err := NewAsyncExportService(repository, func() time.Time { return now }, func() ([32]byte, error) {
		fenceCounter++
		return [32]byte{fenceCounter}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	created := mustRequestAsyncExport(t, service, fixture, fixture.operatorRequest)
	jobID := uuidFromEntity(created.Record.Job.Definition().ID())
	repository.candidateID = jobID
	claimed, found, err := service.Claim(
		context.Background(), fixture.worker, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceOperator, AsyncExportClaimInput{LeaseDuration: time.Minute},
	)
	if err != nil || !found {
		t.Fatalf("Claim() = (%s, %t, %v)", claimed, found, err)
	}
	firstLease := claimed.Record.Job.Lease()

	now = now.Add(30 * time.Second)
	renewed, err := service.Renew(
		context.Background(), fixture.worker, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceOperator, jobID, AsyncExportRenewInput{
			ExpectedRevision: claimed.Record.Job.Revision(), Fence: firstLease.Fence(),
			LeaseDuration: 2 * time.Minute,
		},
	)
	if err != nil || renewed.Record.Job.Lease() == nil ||
		!renewed.Record.Job.Lease().ExpiresAt().After(firstLease.ExpiresAt()) {
		t.Fatalf("Renew() = (%s, %v)", renewed, err)
	}

	now = renewed.Record.Job.Lease().ExpiresAt()
	released, err := service.Expire(
		context.Background(), fixture.worker, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceOperator, jobID, renewed.Record.Job.Revision(),
	)
	if err != nil || released.Record.Job.State() != kernel.TicketExportPending ||
		released.Record.Job.FailureCode() != kernel.TicketExportFailureLeaseExpired {
		t.Fatalf("lease Expire() = (%s, %v)", released, err)
	}

	claimed, found, err = service.Claim(
		context.Background(), fixture.worker, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceOperator, AsyncExportClaimInput{LeaseDuration: time.Minute},
	)
	if err != nil || !found {
		t.Fatalf("reclaim = (%s, %t, %v)", claimed, found, err)
	}
	cancelled, err := service.Cancel(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceOperator, jobID, AsyncExportCancelInput{
			ExpectedRevision: claimed.Record.Job.Revision(),
			IdempotencyKey:   "async-export-expiry-cancel-0001",
		},
	)
	if err != nil || cancelled.Record.Job.State() != kernel.TicketExportCancellationRequested {
		t.Fatalf("Cancel() = (%s, %v)", cancelled, err)
	}
	now = cancelled.Record.Job.Lease().ExpiresAt()
	cancelled, err = service.Expire(
		context.Background(), fixture.worker, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceOperator, jobID, cancelled.Record.Job.Revision(),
	)
	if err != nil || cancelled.Record.Job.State() != kernel.TicketExportCancelledState {
		t.Fatalf("cancellation Expire() = (%s, %v)", cancelled, err)
	}
}

func TestAsyncExportRevokedCleanupPreservesRetentionExpiry(t *testing.T) {
	fixture := newAsyncExportFixture(t)
	repository := newFakeAsyncExportRepository(fixture)
	now := fixture.now
	service, err := NewAsyncExportService(repository, func() time.Time { return now }, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := fixture.customerRequest
	request.Retention = kernel.TicketExportMinimumRetention
	created := mustRequestAsyncExport(t, service, fixture, request)
	jobID := uuidFromEntity(created.Record.Job.Definition().ID())
	repository.requesterAuthorized = false
	now = created.Record.Job.ExpiresAt()

	expired, err := service.RejectRevoked(
		context.Background(), fixture.worker, fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportAudienceCustomer, jobID, created.Record.Job.Revision(),
	)
	if err != nil || expired.Job.State() != kernel.TicketExportFailed ||
		expired.Job.FailureCode() != kernel.TicketExportFailureExpired ||
		expired.Job.TerminalAt() == nil || !expired.Job.TerminalAt().Equal(expired.Job.ExpiresAt()) {
		t.Fatalf("expired RejectRevoked() = (%s, %v)", expired, err)
	}
}

func TestAsyncExportConcurrentClaimsHaveOneCASWinner(t *testing.T) {
	fixture := newAsyncExportFixture(t)
	repository := newFakeAsyncExportRepository(fixture)
	var fenceCounter atomic.Uint32
	service, err := NewAsyncExportService(repository, func() time.Time { return fixture.now }, func() ([32]byte, error) {
		return [32]byte{byte(fenceCounter.Add(1))}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	created := mustRequestAsyncExport(t, service, fixture, fixture.operatorRequest)
	repository.candidateID = uuidFromEntity(created.Record.Job.Definition().ID())
	repository.selectBarrier = &sync.WaitGroup{}
	repository.selectBarrier.Add(2)

	type outcome struct {
		result AsyncExportResult
		found  bool
		err    error
	}
	outcomes := make(chan outcome, 2)
	for range 2 {
		go func() {
			result, found, claimErr := service.Claim(
				context.Background(), fixture.worker, fixture.base.tenantUUID, kernel.AggregateAlert,
				kernel.TicketExportAudienceOperator, AsyncExportClaimInput{LeaseDuration: time.Minute},
			)
			outcomes <- outcome{result: result, found: found, err: claimErr}
		}()
	}
	successes, conflicts := 0, 0
	for range 2 {
		outcome := <-outcomes
		switch {
		case outcome.err == nil && outcome.found:
			successes++
		case errors.Is(outcome.err, ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected claim outcome = (%s, %t, %v)", outcome.result, outcome.found, outcome.err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent claims successes=%d conflicts=%d", successes, conflicts)
	}
}

func TestAsyncExportDiagnosticsRedactQueriesFencesCursorsAndCells(t *testing.T) {
	fixture := newAsyncExportFixture(t)
	request := fixture.operatorRequest
	request.Source.Inline.Filters.Search = "sensitive-query-value"
	request.IdempotencyKey = "sensitive-export-key"
	fence := sha256.Sum256([]byte("sensitive-fence"))
	pageInput := AsyncExportPageInput{
		ExpectedRevision: 2, Fence: fence, After: "c2Vuc2l0aXZlLWN1cnNvcg", Limit: 10,
	}
	page := AsyncExportPage{Rows: []AsyncExportRow{{
		Kind: AsyncExportTicketRow, Cells: []string{"sensitive-cell", "safe"},
	}}, NextCursor: "c2Vuc2l0aXZlLW5leHQ"}
	command, err := bindAsyncExportRequestCommand(
		request.IdempotencyKey,
		mustAsyncExportAccess(t, fixture, kernel.TicketExportAudienceOperator, AsyncExportCapabilityRequest),
		fixture.operatorInlineQuery, request.Comments, 100, 1_000_000, time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		"sensitive-query-value", "sensitive-export-key", "sensitive-fence",
		"c2Vuc2l0aXZlLWN1cnNvcg", "c2Vuc2l0aXZlLW5leHQ", "sensitive-cell",
		fmt.Sprintf("%x", command.Fingerprint[:]),
	} {
		for _, rendered := range []string{
			fmt.Sprintf("%#v", request), fmt.Sprintf("%#v", request.Source),
			fmt.Sprintf("%#v", pageInput), fmt.Sprintf("%#v", page),
			fmt.Sprintf("%#v", page.Rows[0]), fmt.Sprintf("%#v", command),
		} {
			if strings.Contains(rendered, secret) {
				t.Fatalf("diagnostic leaked %q: %s", secret, rendered)
			}
		}
	}
}

type asyncExportFixture struct {
	base                serviceFixture
	now                 time.Time
	worker              AsyncExportWorker
	customerContact     uuid.UUID
	operatorInlineQuery AsyncExportQuerySnapshot
	operatorSavedQuery  AsyncExportQuerySnapshot
	customerQuery       AsyncExportQuerySnapshot
	operatorRequest     AsyncExportRequestInput
	customerRequest     AsyncExportRequestInput
	operatorSavedSource AsyncExportSourceInput
	savedViewRevision   uint64
	reservedID          uuid.UUID
}

func newAsyncExportFixture(t testing.TB) asyncExportFixture {
	t.Helper()
	saved := newSavedViewServiceFixture(t)
	inline, err := NewAsyncExportQuerySnapshot(
		saved.base.tenantUUID, kernel.AggregateAlert, kernel.TicketExportQueryInline, saved.spec, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	owner, _ := entityID(saved.base.membershipUUID)
	viewID, _ := entityID(saved.viewID)
	pin, err := kernel.NewTicketExportSavedViewPin(viewID, owner, saved.record.View.Revision(), saved.record.SpecDigest)
	if err != nil {
		t.Fatal(err)
	}
	savedQuery, err := NewAsyncExportQuerySnapshot(
		saved.base.tenantUUID, kernel.AggregateAlert, kernel.TicketExportQuerySavedView, saved.spec, &pin,
	)
	if err != nil {
		t.Fatal(err)
	}
	visible := true
	filters, err := kernel.NewSavedViewFilters(kernel.SavedViewFiltersInput{
		Queue: kernel.SavedViewQueueAll, CustomerVisible: &visible,
	})
	if err != nil {
		t.Fatal(err)
	}
	sortValue, _ := kernel.NewSavedViewCoreSort(mustApplicationTicketKey(t, "updated_at"), kernel.SavedViewSortDescending)
	columns := make([]kernel.SavedViewColumn, 0, 3)
	for _, key := range []string{"ticket", "state", "updated"} {
		column, columnErr := kernel.NewSavedViewCoreColumn(
			mustApplicationTicketKey(t, key), 160, true, kernel.SavedViewColumnUnpinned,
		)
		if columnErr != nil {
			t.Fatal(columnErr)
		}
		columns = append(columns, column)
	}
	customerSpec, err := kernel.NewSavedViewSpec(
		saved.base.tenant, kernel.AggregateAlert, filters, sortValue, columns,
	)
	if err != nil {
		t.Fatal(err)
	}
	customerQuery, err := NewAsyncExportQuerySnapshot(
		saved.base.tenantUUID, kernel.AggregateAlert, kernel.TicketExportQueryInline, customerSpec, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	customerVisible := true
	customerInput := SavedViewSpecInput{
		Filters: SavedViewFiltersInput{Queue: "all", CustomerVisible: &customerVisible},
		Sort:    SavedViewSortInput{Source: SavedViewDefinitionCore, CoreKey: "updated_at", Direction: "desc", Nulls: "last"},
		Columns: []SavedViewColumnInput{
			{Source: SavedViewDefinitionCore, CoreKey: "ticket", Width: 160, Visible: true, Pin: "none"},
			{Source: SavedViewDefinitionCore, CoreKey: "state", Width: 160, Visible: true, Pin: "none"},
			{Source: SavedViewDefinitionCore, CoreKey: "updated", Width: 160, Visible: true, Pin: "none"},
		},
	}
	return asyncExportFixture{
		base: saved.base, now: time.Date(2026, 8, 26, 15, 0, 0, 0, time.UTC),
		worker: AsyncExportWorker{
			ServiceAccountID: mustUUIDv7(t), WorkerID: mustUUIDv7(t), Purpose: AsyncExportWorkerPurpose,
		},
		customerContact: mustUUIDv7(t), operatorInlineQuery: inline,
		operatorSavedQuery: savedQuery, customerQuery: customerQuery,
		operatorRequest: AsyncExportRequestInput{
			Audience: kernel.TicketExportAudienceOperator, Comments: kernel.TicketExportCommentsPublic,
			Source:      AsyncExportSourceInput{Inline: cloneAsyncExportSpecInput(&saved.input)},
			MaximumRows: 100, MaximumBytes: 1_000_000, Retention: time.Hour,
			IdempotencyKey: "async-export-request-0001",
		},
		customerRequest: AsyncExportRequestInput{
			Audience: kernel.TicketExportAudienceCustomer, Comments: kernel.TicketExportCommentsPublic,
			Source:      AsyncExportSourceInput{Inline: &customerInput},
			MaximumRows: 100, MaximumBytes: 1_000_000, Retention: time.Hour,
			IdempotencyKey: "async-export-customer-0001",
		},
		operatorSavedSource: AsyncExportSourceInput{SavedView: &AsyncExportSavedViewSourceInput{
			ID: saved.viewID, ExpectedRevision: saved.record.View.Revision(),
			ExpectedSpecDigest: saved.record.SpecDigest,
		}},
		savedViewRevision: saved.record.View.Revision(), reservedID: mustUUIDv7(t),
	}
}

func mustAsyncExportSavedQuery(
	t testing.TB,
	fixture asyncExportFixture,
	revision uint64,
	ownerID uuid.UUID,
) AsyncExportQuerySnapshot {
	t.Helper()
	viewID := fixture.operatorSavedQuery.SavedView().ID()
	owner, _ := entityID(ownerID)
	pin, err := kernel.NewTicketExportSavedViewPin(
		viewID, owner, revision, fixture.operatorSavedQuery.QueryDigest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	query, err := NewAsyncExportQuerySnapshot(
		fixture.base.tenantUUID, kernel.AggregateAlert,
		kernel.TicketExportQuerySavedView, fixture.operatorSavedQuery.Spec(), &pin,
	)
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func customerAsyncExportQueryVariant(
	t testing.TB,
	fixture asyncExportFixture,
	sortKey string,
	hiddenColumn bool,
) AsyncExportQuerySnapshot {
	t.Helper()
	visible := true
	filters, err := kernel.NewSavedViewFilters(kernel.SavedViewFiltersInput{
		Queue: kernel.SavedViewQueueAll, CustomerVisible: &visible,
	})
	if err != nil {
		t.Fatal(err)
	}
	direction := kernel.SavedViewSortDescending
	if sortKey == "oldest_unclaimed" {
		direction = kernel.SavedViewSortAscending
	}
	sortValue, err := kernel.NewSavedViewCoreSort(mustApplicationTicketKey(t, sortKey), direction)
	if err != nil {
		t.Fatal(err)
	}
	ticket, _ := kernel.NewSavedViewCoreColumn(
		mustApplicationTicketKey(t, "ticket"), 160, true, kernel.SavedViewColumnUnpinned,
	)
	updated, _ := kernel.NewSavedViewCoreColumn(
		mustApplicationTicketKey(t, "updated"), 160, !hiddenColumn, kernel.SavedViewColumnUnpinned,
	)
	spec, err := kernel.NewSavedViewSpec(
		fixture.base.tenant, kernel.AggregateAlert, filters, sortValue,
		[]kernel.SavedViewColumn{ticket, updated},
	)
	if err != nil {
		t.Fatal(err)
	}
	query, err := NewAsyncExportQuerySnapshot(
		fixture.base.tenantUUID, kernel.AggregateAlert, kernel.TicketExportQueryInline, spec, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func asyncExportInlineQueryWithSearch(
	t testing.TB,
	fixture asyncExportFixture,
	search string,
) AsyncExportQuerySnapshot {
	t.Helper()
	filters, err := kernel.NewSavedViewFilters(kernel.SavedViewFiltersInput{
		Queue: kernel.SavedViewQueueAll, Search: search,
	})
	if err != nil {
		t.Fatal(err)
	}
	spec, err := kernel.NewSavedViewSpec(
		fixture.base.tenant, kernel.AggregateAlert, filters,
		fixture.operatorInlineQuery.Spec().Sort(), fixture.operatorInlineQuery.Spec().Columns(),
	)
	if err != nil {
		t.Fatal(err)
	}
	query, err := NewAsyncExportQuerySnapshot(
		fixture.base.tenantUUID, kernel.AggregateAlert, kernel.TicketExportQueryInline, spec, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func asyncExportSetOrderedQueryFixture(
	t testing.TB,
	fixture asyncExportFixture,
) (AsyncExportRequestInput, AsyncExportQuerySnapshot) {
	t.Helper()
	stateResolved := mustApplicationTicketKey(t, "resolved")
	stateNew := mustApplicationTicketKey(t, "new")
	filters, err := kernel.NewSavedViewFilters(kernel.SavedViewFiltersInput{
		States:     []kernel.Key{stateResolved, stateNew},
		Severities: []string{"medium", "critical"},
		Priorities: []string{"urgent", "low"},
		Queue:      kernel.SavedViewQueueAll,
		Search:     "malware campaign",
	})
	if err != nil {
		t.Fatal(err)
	}
	spec, err := kernel.NewSavedViewSpec(
		fixture.base.tenant, kernel.AggregateAlert, filters,
		fixture.operatorInlineQuery.Spec().Sort(), fixture.operatorInlineQuery.Spec().Columns(),
	)
	if err != nil {
		t.Fatal(err)
	}
	query, err := NewAsyncExportQuerySnapshot(
		fixture.base.tenantUUID, kernel.AggregateAlert, kernel.TicketExportQueryInline, spec, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	input := asyncExportRequestWithKey(fixture.operatorRequest, "async-export-canonical-ordering-0001")
	input.Source.Inline.Filters.States = []string{"resolved", "new"}
	input.Source.Inline.Filters.Severities = []string{"medium", "critical"}
	input.Source.Inline.Filters.Priorities = []string{"urgent", "low"}
	return input, query
}

func asyncExportQueryWithReversedColumns(
	t testing.TB,
	fixture asyncExportFixture,
) AsyncExportQuerySnapshot {
	t.Helper()
	columns := fixture.operatorInlineQuery.Spec().Columns()
	columns[0], columns[1] = columns[1], columns[0]
	spec, err := kernel.NewSavedViewSpec(
		fixture.base.tenant, kernel.AggregateAlert, fixture.operatorInlineQuery.Spec().Filters(),
		fixture.operatorInlineQuery.Spec().Sort(), columns,
	)
	if err != nil {
		t.Fatal(err)
	}
	query, err := NewAsyncExportQuerySnapshot(
		fixture.base.tenantUUID, kernel.AggregateAlert, kernel.TicketExportQueryInline, spec, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func asyncExportDecimalQueryFixture(
	t testing.TB,
	fixture asyncExportFixture,
	requestValue string,
) (AsyncExportRequestInput, AsyncExportQuerySnapshot) {
	t.Helper()
	definitionID, _ := entityID(mustUUIDv7(t))
	definitionKey := mustApplicationTicketKey(t, "export_risk_score")
	pin, err := kernel.NewSavedViewDefinitionPin(
		definitionID, fixture.base.tenant, kernel.AggregateAlert, definitionKey, 7, [32]byte{7},
	)
	if err != nil {
		t.Fatal(err)
	}
	filter, err := kernel.RestoreSavedViewCustomFilter(
		pin, customkernel.TypeDecimal, []byte("10.5"),
	)
	if err != nil {
		t.Fatal(err)
	}
	filters, err := kernel.NewSavedViewFilters(kernel.SavedViewFiltersInput{
		Queue: kernel.SavedViewQueueAll, Custom: []kernel.SavedViewCustomFilter{filter},
	})
	if err != nil {
		t.Fatal(err)
	}
	ticketColumn, err := kernel.NewSavedViewCoreColumn(
		mustApplicationTicketKey(t, "ticket"), 320, true, kernel.SavedViewColumnPinnedStart,
	)
	if err != nil {
		t.Fatal(err)
	}
	dynamicColumn, err := kernel.NewSavedViewDynamicColumn(
		kernel.SavedViewColumnCustomField, pin, 180, true, kernel.SavedViewColumnUnpinned,
	)
	if err != nil {
		t.Fatal(err)
	}
	sortValue, err := kernel.NewSavedViewDynamicSort(
		kernel.SavedViewColumnCustomField, pin,
		kernel.SavedViewSortDescending, kernel.SavedViewNullsLast,
	)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := kernel.NewSavedViewSpec(
		fixture.base.tenant, kernel.AggregateAlert, filters, sortValue,
		[]kernel.SavedViewColumn{ticketColumn, dynamicColumn},
	)
	if err != nil {
		t.Fatal(err)
	}
	query, err := NewAsyncExportQuerySnapshot(
		fixture.base.tenantUUID, kernel.AggregateAlert, kernel.TicketExportQueryInline, spec, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	inputSpec, err := SavedViewSpecInputFromResolved(spec)
	if err != nil {
		t.Fatal(err)
	}
	inputSpec.Filters.Custom[0].Value = []byte(requestValue)
	input := asyncExportRequestWithKey(fixture.operatorRequest, "async-export-decimal-filter-0001")
	input.Source = AsyncExportSourceInput{Inline: &inputSpec}
	return input, query
}

func asyncExportRequestWithKey(input AsyncExportRequestInput, key string) AsyncExportRequestInput {
	result := input
	result.Source = cloneAsyncExportSourceInput(input.Source)
	result.IdempotencyKey = key
	return result
}

func asyncExportDefinitionInput(
	definition kernel.TicketExportDefinition,
) kernel.TicketExportDefinitionInput {
	return kernel.TicketExportDefinitionInput{
		ID: definition.ID(), Tenant: definition.Tenant(), Requester: definition.Requester(),
		OwnerMembership: definition.OwnerMembership(), CustomerContact: definition.CustomerContact(),
		Kind: definition.Kind(), Audience: definition.Audience(), Comments: definition.Comments(),
		QuerySource: definition.QuerySource(), SavedView: definition.SavedView(),
		QueryDigest: definition.QueryDigest(), CatalogDigest: definition.CatalogDigest(),
		ProjectionVersion: definition.ProjectionVersion(), Format: definition.Format(),
		MaximumRows: definition.MaximumRows(), MaximumBytes: definition.MaximumBytes(),
		MaximumAttempts: definition.MaximumAttempts(),
	}
}

func mustRequestAsyncExport(
	t testing.TB,
	service *AsyncExportService,
	fixture asyncExportFixture,
	input AsyncExportRequestInput,
) AsyncExportResult {
	t.Helper()
	result, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, kernel.AggregateAlert, input,
	)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func mustAsyncExportService(
	t testing.TB,
	repository AsyncExportRepository,
	now time.Time,
) *AsyncExportService {
	t.Helper()
	service, err := NewAsyncExportService(repository, func() time.Time { return now }, func() ([32]byte, error) {
		return [32]byte{1, 2, 3, 4}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func mustAsyncExportAccess(
	t testing.TB,
	fixture asyncExportFixture,
	audience kernel.TicketExportAudience,
	capability AsyncExportCapability,
) AsyncExportAccess {
	t.Helper()
	principal := kernel.PrincipalOperator
	var contact *uuid.UUID
	if audience == kernel.TicketExportAudienceCustomer {
		principal, contact = kernel.PrincipalCustomer, &fixture.customerContact
	}
	access, err := NewAsyncExportAccess(
		fixture.base.tenantUUID, fixture.base.actor.UserID, fixture.base.membershipUUID,
		kernel.AggregateAlert, audience, capability, principal, contact, true, contact == nil, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	return access
}

type asyncExportReplayKey struct {
	tenant     uuid.UUID
	actor      uuid.UUID
	membership uuid.UUID
	kind       kernel.AggregateKind
	audience   kernel.TicketExportAudience
	action     AsyncExportCommandAction
	keyHash    [sha256.Size]byte
}

type asyncExportReplay struct {
	fingerprint [sha256.Size]byte
	result      AsyncExportResult
}

type fakeAsyncExportRepository struct {
	mu sync.Mutex

	fixture                asyncExportFixture
	humanAllowed           bool
	workerAllowed          bool
	requesterAuthorized    bool
	publicComments         bool
	privateComments        bool
	forcePrincipal         kernel.PrincipalKind
	missingCustomerContact bool
	revokeHumanAtCommit    bool
	invalidReservedID      bool
	uniqueReservedIDs      bool
	resolveQueryErr        error
	resolveQueryHook       func(*AsyncExportSourceInput)
	forceGetErr            error
	operatorQuery          AsyncExportQuerySnapshot
	customerQuery          AsyncExportQuerySnapshot
	records                map[uuid.UUID]AsyncExportRecord
	replays                map[asyncExportReplayKey]asyncExportReplay
	candidateID            uuid.UUID
	page                   AsyncExportPage
	selectBarrier          *sync.WaitGroup
	getBarrier             *sync.WaitGroup
	reserveBarrier         *sync.WaitGroup

	resolveQueryCalls  atomic.Int32
	reserveCalls       atomic.Int32
	commitRequestCalls atomic.Int32
	getCalls           atomic.Int32
	commitOwnerCalls   atomic.Int32
	commitWorkerCalls  atomic.Int32
}

type fakeAsyncExportDownloadStorage struct {
	calls     int
	location  AsyncExportArtifactLocation
	expiresAt time.Time
	grant     AsyncExportDownloadGrant
	err       error
}

func (storage *fakeAsyncExportDownloadStorage) PrepareAsyncExportDownload(
	_ context.Context,
	location AsyncExportArtifactLocation,
	expiresAt time.Time,
) (AsyncExportDownloadGrant, error) {
	storage.calls++
	storage.location = location
	storage.expiresAt = expiresAt
	return storage.grant, storage.err
}

func newFakeAsyncExportRepository(fixture asyncExportFixture) *fakeAsyncExportRepository {
	return &fakeAsyncExportRepository{
		fixture: fixture, humanAllowed: true, workerAllowed: true, requesterAuthorized: true,
		publicComments: true, privateComments: true, operatorQuery: fixture.operatorInlineQuery,
		customerQuery: fixture.customerQuery, records: map[uuid.UUID]AsyncExportRecord{},
		replays: map[asyncExportReplayKey]asyncExportReplay{},
	}
}

func (repository *fakeAsyncExportRepository) ResolveAsyncExportAccess(
	_ context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	audience kernel.TicketExportAudience,
	capability AsyncExportCapability,
) (AsyncExportAccess, error) {
	principal := repository.forcePrincipal
	if principal == 0 {
		principal = kernel.PrincipalOperator
		if audience == kernel.TicketExportAudienceCustomer {
			principal = kernel.PrincipalCustomer
		}
	}
	var contact *uuid.UUID
	if audience == kernel.TicketExportAudienceCustomer && !repository.missingCustomerContact {
		contact = &repository.fixture.customerContact
	}
	access, err := NewAsyncExportAccess(
		tenantID, actor.UserID, repository.fixture.base.membershipUUID, kind, audience,
		capability, principal, contact, repository.publicComments,
		repository.privateComments && audience == kernel.TicketExportAudienceOperator,
		repository.humanAllowed,
	)
	if repository.missingCustomerContact && audience == kernel.TicketExportAudienceCustomer {
		access = AsyncExportAccess{
			tenant: tenantID, actor: actor.UserID, membership: repository.fixture.base.membershipUUID,
			kind: kind, audience: audience, capability: capability, principal: principal,
			allowed: repository.humanAllowed,
		}
		return access, nil
	}
	return access, err
}

func (repository *fakeAsyncExportRepository) ResolveAsyncExportWorkerAccess(
	_ context.Context,
	worker AsyncExportWorker,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	audience kernel.TicketExportAudience,
	capability AsyncExportCapability,
) (AsyncExportWorkerAccess, error) {
	return NewAsyncExportWorkerAccess(
		tenantID, worker.ServiceAccountID, kind, audience, capability, repository.workerAllowed,
	)
}

func (repository *fakeAsyncExportRepository) ResolveAsyncExportQuery(
	_ context.Context,
	_ Actor,
	_ uuid.UUID,
	_ kernel.AggregateKind,
	audience kernel.TicketExportAudience,
	source AsyncExportSourceInput,
	_ AsyncExportAccess,
) (AsyncExportQuerySnapshot, error) {
	repository.resolveQueryCalls.Add(1)
	if repository.resolveQueryErr != nil {
		return AsyncExportQuerySnapshot{}, repository.resolveQueryErr
	}
	if repository.resolveQueryHook != nil {
		repository.resolveQueryHook(&source)
	}
	if audience == kernel.TicketExportAudienceCustomer {
		return repository.customerQuery, nil
	}
	return repository.operatorQuery, nil
}

func (repository *fakeAsyncExportRepository) ReserveAsyncExportID(
	_ context.Context,
	_ uuid.UUID,
) (kernel.EntityID, error) {
	repository.reserveCalls.Add(1)
	if repository.invalidReservedID {
		return kernel.EntityID{}, nil
	}
	if repository.uniqueReservedIDs {
		id, err := uuid.NewV7()
		if err != nil {
			return kernel.EntityID{}, err
		}
		if repository.reserveBarrier != nil {
			repository.reserveBarrier.Done()
			repository.reserveBarrier.Wait()
		}
		return entityID(id)
	}
	return entityID(repository.fixture.reservedID)
}

func (repository *fakeAsyncExportRepository) LookupAsyncExportReplay(
	_ context.Context,
	query AsyncExportReplayQuery,
) (AsyncExportResult, bool, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := asyncExportReplayKey{
		tenant: query.TenantID, actor: query.ActorID, membership: query.OwnerMembershipID,
		kind: query.Kind, audience: query.Audience, action: query.Action, keyHash: query.KeyHash,
	}
	replay, found := repository.replays[key]
	if !found {
		return AsyncExportResult{}, false, nil
	}
	if replay.fingerprint != query.Fingerprint {
		return AsyncExportResult{}, false, ErrConflict
	}
	if !repository.requesterAuthorized {
		return AsyncExportResult{}, false, ErrForbidden
	}
	result := replay.result
	result.Replayed = true
	return result, true, nil
}

func (repository *fakeAsyncExportRepository) CommitAsyncExportRequest(
	_ context.Context,
	write AsyncExportRequestWrite,
) (AsyncExportResult, error) {
	repository.commitRequestCalls.Add(1)
	if repository.revokeHumanAtCommit {
		return AsyncExportResult{}, ErrForbidden
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if replay, found, err := repository.lookupWriteReplayLocked(write.Access, write.Command); err != nil || found {
		return replay, err
	}
	next := write.Plan.Next()
	id := uuidFromEntity(next.Definition().ID())
	result := AsyncExportResult{Record: AsyncExportRecord{Job: next, Query: write.Query}}
	repository.records[id] = result.Record
	repository.storeReplayLocked(write.Access, write.Command, result)
	return result, nil
}

func (repository *fakeAsyncExportRepository) GetAsyncExport(
	_ context.Context,
	_ Actor,
	_ uuid.UUID,
	jobID uuid.UUID,
	_ AsyncExportAccess,
) (AsyncExportRecord, error) {
	repository.getCalls.Add(1)
	if repository.forceGetErr != nil {
		return AsyncExportRecord{}, repository.forceGetErr
	}
	repository.mu.Lock()
	record, found := repository.records[jobID]
	repository.mu.Unlock()
	if repository.getBarrier != nil {
		repository.getBarrier.Done()
		repository.getBarrier.Wait()
	}
	if !found {
		return AsyncExportRecord{}, ErrNotFound
	}
	return record, nil
}

func (repository *fakeAsyncExportRepository) CommitAsyncExportOwnerTransition(
	_ context.Context,
	write AsyncExportOwnerWrite,
) (AsyncExportResult, error) {
	repository.commitOwnerCalls.Add(1)
	if repository.revokeHumanAtCommit {
		return AsyncExportResult{}, ErrForbidden
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if replay, found, err := repository.lookupWriteReplayLocked(write.Access, write.Command); err != nil || found {
		return replay, err
	}
	next := write.Plan.Next()
	id := uuidFromEntity(next.Definition().ID())
	current, found := repository.records[id]
	if !found || current.Job.Revision() != write.Plan.ExpectedRevision() {
		return AsyncExportResult{}, ErrPreconditionFailed
	}
	result := AsyncExportResult{Record: AsyncExportRecord{Job: next, Query: write.Query}}
	repository.records[id] = result.Record
	repository.storeReplayLocked(write.Access, write.Command, result)
	return result, nil
}

func (repository *fakeAsyncExportRepository) SelectAsyncExportClaimCandidate(
	_ context.Context,
	_ AsyncExportWorker,
	_ AsyncExportWorkerAccess,
	_ time.Time,
) (AsyncExportRecord, bool, error) {
	repository.mu.Lock()
	record, found := repository.records[repository.candidateID]
	repository.mu.Unlock()
	if repository.selectBarrier != nil {
		repository.selectBarrier.Done()
		repository.selectBarrier.Wait()
	}
	if !repository.requesterAuthorized {
		return AsyncExportRecord{}, false, ErrForbidden
	}
	return record, found, nil
}

func (repository *fakeAsyncExportRepository) GetAsyncExportForWorker(
	_ context.Context,
	_ AsyncExportWorker,
	_ uuid.UUID,
	jobID uuid.UUID,
	_ AsyncExportWorkerAccess,
) (AsyncExportRecord, error) {
	if !repository.requesterAuthorized {
		return AsyncExportRecord{}, ErrForbidden
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	record, found := repository.records[jobID]
	if !found {
		return AsyncExportRecord{}, ErrNotFound
	}
	return record, nil
}

func (repository *fakeAsyncExportRepository) GetRevokedAsyncExportForWorker(
	_ context.Context,
	_ AsyncExportWorker,
	_ uuid.UUID,
	jobID uuid.UUID,
	_ AsyncExportWorkerAccess,
) (kernel.TicketExportJob, error) {
	if repository.requesterAuthorized {
		return kernel.TicketExportJob{}, ErrConflict
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	record, found := repository.records[jobID]
	if !found {
		return kernel.TicketExportJob{}, ErrNotFound
	}
	return record.Job, nil
}

func (repository *fakeAsyncExportRepository) CommitAsyncExportWorkerTransition(
	_ context.Context,
	write AsyncExportWorkerWrite,
) (AsyncExportResult, error) {
	repository.commitWorkerCalls.Add(1)
	if !repository.requesterAuthorized || !repository.workerAllowed {
		return AsyncExportResult{}, ErrForbidden
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	next := write.Plan.Next()
	id := uuidFromEntity(next.Definition().ID())
	current, found := repository.records[id]
	if !found || current.Job.Revision() != write.Plan.ExpectedRevision() {
		return AsyncExportResult{}, ErrConflict
	}
	result := AsyncExportResult{Record: AsyncExportRecord{Job: next, Query: write.Query}}
	repository.records[id] = result.Record
	return result, nil
}

func (repository *fakeAsyncExportRepository) CommitAsyncExportRevocation(
	_ context.Context,
	write AsyncExportRevocationWrite,
) (kernel.TicketExportJob, error) {
	if !repository.workerAllowed || repository.requesterAuthorized ||
		write.Plan.Action() != kernel.TicketExportRevokeAuthorization &&
			write.Plan.Action() != kernel.TicketExportExpire {
		return kernel.TicketExportJob{}, ErrForbidden
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	next := write.Plan.Next()
	id := uuidFromEntity(next.Definition().ID())
	current, found := repository.records[id]
	if !found || current.Job.Revision() != write.Plan.ExpectedRevision() {
		return kernel.TicketExportJob{}, ErrConflict
	}
	current.Job = next
	repository.records[id] = current
	return next, nil
}

func (repository *fakeAsyncExportRepository) ReadAsyncExportPage(
	_ context.Context,
	_ AsyncExportPageQuery,
) (AsyncExportPage, error) {
	if !repository.requesterAuthorized {
		return AsyncExportPage{}, ErrForbidden
	}
	return repository.page, nil
}

func (repository *fakeAsyncExportRepository) storeReplayLocked(
	access AsyncExportAccess,
	command AsyncExportCommandBinding,
	result AsyncExportResult,
) {
	repository.replays[asyncExportReplayKey{
		tenant: access.tenant, actor: access.actor, membership: access.membership,
		kind: access.kind, audience: access.audience, action: command.Action, keyHash: command.KeyHash,
	}] = asyncExportReplay{fingerprint: command.Fingerprint, result: result}
}

func (repository *fakeAsyncExportRepository) lookupWriteReplayLocked(
	access AsyncExportAccess,
	command AsyncExportCommandBinding,
) (AsyncExportResult, bool, error) {
	replay, found := repository.replays[asyncExportReplayKey{
		tenant: access.tenant, actor: access.actor, membership: access.membership,
		kind: access.kind, audience: access.audience, action: command.Action, keyHash: command.KeyHash,
	}]
	if !found {
		return AsyncExportResult{}, false, nil
	}
	if replay.fingerprint != command.Fingerprint {
		return AsyncExportResult{}, false, ErrConflict
	}
	result := replay.result
	result.Replayed = true
	return result, true, nil
}
