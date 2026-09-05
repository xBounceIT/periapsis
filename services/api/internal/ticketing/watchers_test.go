package ticketing

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

func TestListAlertWatchersRequiresLiveTicketReadAndBindsRepositoryQuery(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	targetID := mustUUIDv7(t)
	want := watcherTestProjection(
		fixture, kernel.AggregateAlert, fixture.ticketUUID, fixture.record.UpdatedAt, 1,
		TicketWatcher{UserID: targetID, DisplayName: "Incident Responder", AddedAt: fixture.record.UpdatedAt.Add(-time.Minute)},
	)
	repository := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalOperator, record: fixture.record,
		listWatchers: func(ctx context.Context, query WatcherListQuery) (TicketWatcherProjection, error) {
			if ctx == nil || query.Actor != fixture.actor || query.TenantID != fixture.tenantUUID ||
				query.Kind != kernel.AggregateAlert || query.TicketID != fixture.ticketUUID {
				t.Fatalf("watcher list query was not exactly bound: %#v", query)
			}
			return want, nil
		},
	}
	got, err := mustService(t, repository).ListAlertWatchers(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID,
	)
	if err != nil || got.Version != 1 || len(got.Items) != 1 || got.Items[0].UserID != targetID {
		t.Fatalf("ListAlertWatchers() = (%#v, %v)", got, err)
	}
	if repository.watcherListCalls.Load() != 1 || len(repository.accessCalls) != 1 ||
		repository.accessCalls[0] != CapabilityAlertRead {
		t.Fatalf("list calls=%d access=%v", repository.watcherListCalls.Load(), repository.accessCalls)
	}
}

func TestListWatchersAcceptsNewerProjectionFromReauthorizedDatabaseSnapshot(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	newer := watcherTestProjection(
		fixture, kernel.AggregateAlert, fixture.ticketUUID, fixture.record.UpdatedAt.Add(time.Second), 2,
	)
	repository := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalOperator, record: fixture.record,
		listWatchers: func(context.Context, WatcherListQuery) (TicketWatcherProjection, error) {
			return newer, nil
		},
	}
	result, err := mustService(t, repository).ListAlertWatchers(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID,
	)
	if err != nil || result.Version != 2 {
		t.Fatalf("newer reauthorized projection = (%#v, %v)", result, err)
	}
}

func TestListWatchersFailsClosedForTenantPrincipalAndResourceScope(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	tests := []struct {
		name       string
		actor      Actor
		repository *fakeRepository
		want       error
	}{
		{
			name:  "tenant mismatch",
			actor: func() Actor { actor := fixture.actor; actor.ActiveTenantID = mustUUIDv7(t); return actor }(),
			repository: &fakeRepository{
				fixture: fixture, principal: kernel.PrincipalOperator, record: fixture.record,
			},
			want: ErrForbidden,
		},
		{
			name:  "customer principal",
			actor: fixture.actor,
			repository: &fakeRepository{
				fixture: fixture, principal: kernel.PrincipalCustomer, record: fixture.record,
			},
			want: ErrForbidden,
		},
		{
			name:  "insufficient resource scope",
			actor: fixture.actor,
			repository: &fakeRepository{
				fixture: fixture, principal: kernel.PrincipalOperator, scopes: []Scope{ScopeAssigned},
				record: fixture.record,
			},
			want: ErrUnavailable,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := mustService(t, test.repository).ListAlertWatchers(
				context.Background(), test.actor, fixture.tenantUUID, fixture.ticketUUID,
			)
			if !errors.Is(err, test.want) || test.repository.watcherListCalls.Load() != 0 {
				t.Fatalf("list error=%v calls=%d", err, test.repository.watcherListCalls.Load())
			}
		})
	}
}

func TestAddAlertWatcherBindsCASIdempotencyAndAudit(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	targetID := mustUUIDv7(t)
	input := WatcherMutationInput{ExpectedVersion: 1, IdempotencyKey: "watcher-add-command-0001"}
	wantFingerprint, err := watcherMutationFingerprint(
		fixture.tenantUUID, fixture.actor.UserID, fixture.ticketUUID, targetID,
		kernel.AggregateAlert, WatcherAdd, input.ExpectedVersion,
	)
	if err != nil {
		t.Fatal(err)
	}
	updatedAt := fixture.record.UpdatedAt.Add(time.Second)
	repository := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalOperator, record: fixture.record,
		mutateWatcher: func(ctx context.Context, write WatcherMutationWrite) (WatcherMutationResult, error) {
			if ctx == nil || write.Actor != fixture.actor || write.TenantID != fixture.tenantUUID ||
				write.Kind != kernel.AggregateAlert || write.TicketID != fixture.ticketUUID ||
				write.TargetUserID != targetID || write.Action != WatcherAdd || write.ExpectedVersion != 1 ||
				write.KeyHash != sha256.Sum256([]byte(input.IdempotencyKey)) ||
				write.Fingerprint != wantFingerprint || write.Audit != fixture.actor.Audit {
				t.Fatalf("watcher mutation was not exactly bound: %#v", write)
			}
			return WatcherMutationResult{Projection: watcherTestProjection(
				fixture, kernel.AggregateAlert, fixture.ticketUUID, updatedAt, 2,
				TicketWatcher{UserID: targetID, DisplayName: "Incident Responder", AddedAt: updatedAt},
			)}, nil
		},
	}
	result, err := mustService(t, repository).AddAlertWatcher(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID, targetID, input,
	)
	if err != nil || result.Replayed || result.Projection.Version != 2 || len(result.Projection.Items) != 1 {
		t.Fatalf("AddAlertWatcher() = (%#v, %v)", result, err)
	}
	if repository.watcherMutationCalls.Load() != 1 || len(repository.accessCalls) != 1 ||
		repository.accessCalls[0] != CapabilityAlertUpdate {
		t.Fatalf("mutation calls=%d access=%v", repository.watcherMutationCalls.Load(), repository.accessCalls)
	}
}

func TestWatcherMutationsAreSetIdempotentWithoutVersionBump(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	targetID := mustUUIDv7(t)
	watcher := TicketWatcher{
		UserID: targetID, DisplayName: "Already Watching", AddedAt: fixture.record.UpdatedAt.Add(-time.Minute),
	}
	tests := []struct {
		name       string
		action     WatcherMutationAction
		projection TicketWatcherProjection
		invoke     func(*Service, WatcherMutationInput) (WatcherMutationResult, error)
	}{
		{
			name: "add existing", action: WatcherAdd,
			projection: watcherTestProjection(
				fixture, kernel.AggregateAlert, fixture.ticketUUID, fixture.record.UpdatedAt, 1, watcher,
			),
			invoke: func(service *Service, input WatcherMutationInput) (WatcherMutationResult, error) {
				return service.AddAlertWatcher(
					context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID, targetID, input,
				)
			},
		},
		{
			name: "remove absent", action: WatcherRemove,
			projection: watcherTestProjection(
				fixture, kernel.AggregateAlert, fixture.ticketUUID, fixture.record.UpdatedAt, 1,
			),
			invoke: func(service *Service, input WatcherMutationInput) (WatcherMutationResult, error) {
				return service.RemoveAlertWatcher(
					context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID, targetID, input,
				)
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repository := &fakeRepository{
				fixture: fixture, principal: kernel.PrincipalOperator, record: fixture.record,
				mutateWatcher: func(_ context.Context, write WatcherMutationWrite) (WatcherMutationResult, error) {
					if write.Action != test.action {
						t.Fatalf("action=%q", write.Action)
					}
					return WatcherMutationResult{Projection: test.projection}, nil
				},
			}
			result, err := test.invoke(
				mustService(t, repository),
				WatcherMutationInput{ExpectedVersion: 1, IdempotencyKey: "watcher-noop-command-0001"},
			)
			if err != nil || result.Replayed || result.Projection.Version != 1 {
				t.Fatalf("set-idempotent mutation = (%#v, %v)", result, err)
			}
		})
	}
}

func TestRemoveWatcherAllowsAnIneligibleHistoricalTarget(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	targetID := mustUUIDv7(t)
	repository := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalOperator, record: fixture.record,
		mutateWatcher: func(_ context.Context, write WatcherMutationWrite) (WatcherMutationResult, error) {
			if write.Action != WatcherRemove || write.TargetUserID != targetID {
				t.Fatalf("remove write=%#v", write)
			}
			return WatcherMutationResult{Projection: watcherTestProjection(
				fixture, kernel.AggregateAlert, fixture.ticketUUID, fixture.record.UpdatedAt.Add(time.Second), 2,
			)}, nil
		},
	}
	result, err := mustService(t, repository).RemoveAlertWatcher(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID, targetID,
		WatcherMutationInput{ExpectedVersion: 1, IdempotencyKey: "watcher-remove-inactive-0001"},
	)
	if err != nil || result.Projection.Version != 2 {
		t.Fatalf("remove historical watcher = (%#v, %v)", result, err)
	}
}

func TestAddWatcherFailsClosedForIneligibleTargetAndActorAuthority(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	targetID := mustUUIDv7(t)
	input := WatcherMutationInput{ExpectedVersion: 1, IdempotencyKey: "watcher-denied-command-0001"}
	for _, name := range []string{"inactive target", "target lacks live ticket read"} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			repository := &fakeRepository{
				fixture: fixture, principal: kernel.PrincipalOperator, record: fixture.record,
				mutateWatcher: func(context.Context, WatcherMutationWrite) (WatcherMutationResult, error) {
					return WatcherMutationResult{}, ErrForbidden
				},
			}
			_, err := mustService(t, repository).AddAlertWatcher(
				context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID, targetID, input,
			)
			if !errors.Is(err, ErrForbidden) || repository.watcherMutationCalls.Load() != 1 {
				t.Fatalf("add denied error=%v calls=%d", err, repository.watcherMutationCalls.Load())
			}
		})
	}

	repository := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalOperator, record: fixture.record,
		accessErrors: map[Capability]error{CapabilityAlertUpdate: ErrForbidden},
	}
	_, err := mustService(t, repository).AddAlertWatcher(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID, targetID, input,
	)
	if !errors.Is(err, ErrForbidden) || repository.watcherMutationCalls.Load() != 0 {
		t.Fatalf("actor denial error=%v calls=%d", err, repository.watcherMutationCalls.Load())
	}

	insufficientScope := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalOperator, scopes: []Scope{ScopeAssigned},
		record: fixture.record,
	}
	_, err = mustService(t, insufficientScope).AddAlertWatcher(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID, targetID, input,
	)
	if !errors.Is(err, ErrUnavailable) || insufficientScope.watcherMutationCalls.Load() != 0 {
		t.Fatalf("resource-scope denial error=%v calls=%d", err, insufficientScope.watcherMutationCalls.Load())
	}

	mismatchedActor := fixture.actor
	mismatchedActor.ActiveTenantID = mustUUIDv7(t)
	_, err = mustService(t, repository).AddAlertWatcher(
		context.Background(), mismatchedActor, fixture.tenantUUID, fixture.ticketUUID, targetID, input,
	)
	if !errors.Is(err, ErrForbidden) || repository.watcherMutationCalls.Load() != 0 {
		t.Fatalf("tenant mismatch error=%v calls=%d", err, repository.watcherMutationCalls.Load())
	}

	_, err = mustService(t, repository).AddAlertWatcher(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID, uuid.New(), input,
	)
	if !errors.Is(err, ErrInvalidInput) || repository.watcherMutationCalls.Load() != 0 {
		t.Fatalf("non-UUIDv7 target error=%v calls=%d", err, repository.watcherMutationCalls.Load())
	}
}

func TestWatcherMutationMapsStaleReplayConflictAndTimeout(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	targetID := mustUUIDv7(t)
	input := WatcherMutationInput{ExpectedVersion: 1, IdempotencyKey: "watcher-outcome-command-0001"}
	tests := []struct {
		name   string
		result WatcherMutationResult
		err    error
		want   error
	}{
		{name: "stale version", err: ErrPreconditionFailed, want: ErrPreconditionFailed},
		{name: "idempotency conflict", err: ErrConflict, want: ErrConflict},
		{name: "deadline", err: context.DeadlineExceeded, want: ErrUnavailable},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			repository := &fakeRepository{
				fixture: fixture, principal: kernel.PrincipalOperator, record: fixture.record,
				mutateWatcher: func(context.Context, WatcherMutationWrite) (WatcherMutationResult, error) {
					return test.result, test.err
				},
			}
			_, err := mustService(t, repository).AddAlertWatcher(
				context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID, targetID, input,
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("error=%v want=%v", err, test.want)
			}
		})
	}

	current := fixture.record
	current.Snapshot = mustSnapshot(
		t, current.Workflow, fixture.tenant, fixture.ticket, true, kernel.Assignment{}, 4,
	)
	current.UpdatedAt = current.UpdatedAt.Add(3 * time.Second)
	replayProjection := watcherTestProjection(
		fixture, kernel.AggregateAlert, fixture.ticketUUID, fixture.record.UpdatedAt.Add(time.Second), 2,
		TicketWatcher{UserID: targetID, DisplayName: "Historical Watcher", AddedAt: fixture.record.UpdatedAt.Add(time.Second)},
	)
	repository := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalOperator, record: current,
		mutateWatcher: func(context.Context, WatcherMutationWrite) (WatcherMutationResult, error) {
			return WatcherMutationResult{Projection: replayProjection, Replayed: true}, nil
		},
	}
	result, err := mustService(t, repository).AddAlertWatcher(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID, targetID, input,
	)
	if err != nil || !result.Replayed || result.Projection.Version != 2 {
		t.Fatalf("historical replay = (%#v, %v)", result, err)
	}
}

func TestWatcherProjectionAndCancellationFailClosed(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	targetID := mustUUIDv7(t)
	bad := watcherTestProjection(
		fixture, kernel.AggregateAlert, fixture.ticketUUID, fixture.record.UpdatedAt.Add(time.Second), 2,
		TicketWatcher{UserID: targetID, DisplayName: "Duplicate", AddedAt: fixture.record.UpdatedAt},
		TicketWatcher{UserID: targetID, DisplayName: "Duplicate", AddedAt: fixture.record.UpdatedAt},
	)
	repository := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalOperator, record: fixture.record,
		mutateWatcher: func(context.Context, WatcherMutationWrite) (WatcherMutationResult, error) {
			return WatcherMutationResult{Projection: bad}, nil
		},
	}
	_, err := mustService(t, repository).AddAlertWatcher(
		context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID, targetID,
		WatcherMutationInput{ExpectedVersion: 1, IdempotencyKey: "watcher-malformed-result-0001"},
	)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("malformed projection error=%v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	repository = &fakeRepository{fixture: fixture, principal: kernel.PrincipalOperator, record: fixture.record}
	_, err = mustService(t, repository).AddAlertWatcher(
		cancelled, fixture.actor, fixture.tenantUUID, fixture.ticketUUID, targetID,
		WatcherMutationInput{ExpectedVersion: 1, IdempotencyKey: "watcher-cancelled-command-0001"},
	)
	if !errors.Is(err, ErrUnavailable) || len(repository.accessCalls) != 0 || repository.watcherMutationCalls.Load() != 0 {
		t.Fatalf("cancelled error=%v access=%v calls=%d", err, repository.accessCalls, repository.watcherMutationCalls.Load())
	}
}

func TestValidWatcherProjectionRequiresCanonicalStrictOrder(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	firstID, secondID := mustUUIDv7(t), mustUUIDv7(t)
	if firstID.String() > secondID.String() {
		firstID, secondID = secondID, firstID
	}
	addedAt := fixture.record.UpdatedAt.Add(-time.Minute)
	first := TicketWatcher{UserID: firstID, DisplayName: "Alpha", AddedAt: addedAt}
	second := TicketWatcher{UserID: secondID, DisplayName: "Alpha", AddedAt: addedAt}
	last := TicketWatcher{UserID: mustUUIDv7(t), DisplayName: "Zulu", AddedAt: addedAt}
	canonical := watcherTestProjection(
		fixture, kernel.AggregateAlert, fixture.ticketUUID, fixture.record.UpdatedAt, 1,
		first, second, last,
	)
	if !validWatcherProjection(canonical, fixture.tenantUUID, kernel.AggregateAlert, fixture.ticketUUID) {
		t.Fatal("canonical watcher order was rejected")
	}
	for _, items := range [][]TicketWatcher{
		{second, first, last},
		{last, first, second},
	} {
		projection := canonical
		projection.Items = items
		if validWatcherProjection(projection, fixture.tenantUUID, kernel.AggregateAlert, fixture.ticketUUID) {
			t.Fatalf("non-canonical watcher order accepted: %#v", items)
		}
	}
	tooMany := make([]TicketWatcher, maximumTicketWatchers+1)
	for index := range tooMany {
		tooMany[index] = TicketWatcher{
			UserID: mustUUIDv7(t), DisplayName: fmt.Sprintf("Watcher %04d", index), AddedAt: addedAt,
		}
	}
	projection := canonical
	projection.Items = tooMany
	if validWatcherProjection(projection, fixture.tenantUUID, kernel.AggregateAlert, fixture.ticketUUID) {
		t.Fatal("over-limit watcher projection was accepted")
	}
}

func watcherTestProjection(
	fixture serviceFixture,
	kind kernel.AggregateKind,
	ticketID uuid.UUID,
	updatedAt time.Time,
	version uint64,
	items ...TicketWatcher,
) TicketWatcherProjection {
	return TicketWatcherProjection{
		TenantID: fixture.tenantUUID, TicketID: ticketID, Kind: kind,
		Items: append([]TicketWatcher{}, items...), Version: version, UpdatedAt: updatedAt,
	}
}
