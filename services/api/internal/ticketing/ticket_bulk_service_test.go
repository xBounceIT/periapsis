package ticketing

import (
	"context"
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

func TestTicketBulkServiceConstructorRejectsNilDependencies(t *testing.T) {
	if _, err := NewTicketBulkService(nil, nil); err == nil {
		t.Fatal("NewTicketBulkService(nil) succeeded")
	}
	var typedNil *fakeTicketBulkRepository
	if _, err := NewTicketBulkService(typedNil, nil); err == nil {
		t.Fatal("NewTicketBulkService(typed nil) succeeded")
	}
}

func TestTicketBulkRequestExplicitCommitsExactImmutableJob(t *testing.T) {
	fixture := newTicketBulkFixture(t)
	repository := newFakeTicketBulkRepository(fixture)
	service := mustTicketBulkService(t, repository, fixture.now)

	result, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, fixture.explicitRequest,
	)
	if err != nil {
		t.Fatal(err)
	}
	definition := result.Record.Job.Definition()
	selection := definition.Selection()
	if result.Replayed || result.Record.Query != nil || result.Record.Job.State() != kernel.TicketBulkPending ||
		result.Record.Job.Revision() != 1 || definition.ID() != fixture.reservedID ||
		definition.Tenant() != fixture.base.tenant ||
		uuidFromEntity(definition.Requester()) != fixture.base.actor.UserID ||
		uuidFromEntity(definition.OwnerMembership()) != fixture.base.membershipUUID ||
		definition.Mutation().Action() != kernel.ActionRelease ||
		selection.Source() != kernel.TicketBulkSelectionExplicit || selection.TargetCount() != 1 ||
		!result.Record.Job.RequestedAt().Equal(fixture.now) ||
		!result.Record.Job.ExpiresAt().Equal(fixture.now.Add(time.Hour)) {
		t.Fatalf("result = %#v", result)
	}
	if repository.resolveAccessCalls.Load() != 1 || repository.resolveQueryCalls.Load() != 0 ||
		repository.reserveCalls.Load() != 1 || repository.commitRequestCalls.Load() != 1 {
		t.Fatalf(
			"calls access=%d query=%d reserve=%d commit=%d",
			repository.resolveAccessCalls.Load(), repository.resolveQueryCalls.Load(),
			repository.reserveCalls.Load(), repository.commitRequestCalls.Load(),
		)
	}
}

func TestTicketBulkRequestDenyAndInvalidInputStopBeforeSelectionResolution(t *testing.T) {
	fixture := newTicketBulkFixture(t)
	for _, test := range []struct {
		name   string
		mutate func(*TicketBulkRequestInput, *fakeTicketBulkRepository)
		want   error
	}{
		{name: "denied", mutate: func(_ *TicketBulkRequestInput, repository *fakeTicketBulkRepository) {
			repository.allowed = false
		}, want: ErrForbidden},
		{name: "ambiguous selection", mutate: func(input *TicketBulkRequestInput, _ *fakeTicketBulkRepository) {
			input.Selection.Query = &fixture.inlineSource
		}, want: ErrInvalidInput},
		{name: "empty explicit alongside query", mutate: func(input *TicketBulkRequestInput, _ *fakeTicketBulkRepository) {
			input.Selection.Explicit = []TicketBulkTargetInput{}
			input.Selection.Query = &fixture.inlineSource
		}, want: ErrInvalidInput},
		{name: "duplicate target", mutate: func(input *TicketBulkRequestInput, _ *fakeTicketBulkRepository) {
			input.Selection.Explicit = append(input.Selection.Explicit, input.Selection.Explicit[0])
		}, want: ErrInvalidInput},
		{name: "unknown action", mutate: func(input *TicketBulkRequestInput, _ *fakeTicketBulkRepository) {
			input.Mutation.Action = "delete"
		}, want: ErrInvalidInput},
		{name: "hidden payload on release", mutate: func(input *TicketBulkRequestInput, _ *fakeTicketBulkRepository) {
			input.Mutation.TeamID = fixture.base.teamUUID
		}, want: ErrInvalidInput},
		{name: "sub microsecond retention", mutate: func(input *TicketBulkRequestInput, _ *fakeTicketBulkRepository) {
			input.Retention += time.Nanosecond
		}, want: ErrInvalidInput},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := newFakeTicketBulkRepository(fixture)
			input := fixture.explicitRequest
			input.Selection = cloneTicketBulkSelectionInput(input.Selection)
			test.mutate(&input, repository)
			service := mustTicketBulkService(t, repository, fixture.now)
			_, err := service.Request(
				context.Background(), fixture.base.actor, fixture.base.tenantUUID,
				kernel.AggregateAlert, input,
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if repository.reserveCalls.Load() != 0 || repository.commitRequestCalls.Load() != 0 ||
				test.want == ErrInvalidInput && repository.resolveAccessCalls.Load() != 0 {
				t.Fatalf(
					"calls access=%d reserve=%d commit=%d",
					repository.resolveAccessCalls.Load(), repository.reserveCalls.Load(),
					repository.commitRequestCalls.Load(),
				)
			}
		})
	}
}

func TestTicketBulkMutationInputUsesClosedDirectPathVocabulary(t *testing.T) {
	fixture := newTicketBulkFixture(t)
	assignee := mustUUIDv7(t)
	tests := []struct {
		name   string
		input  TicketBulkMutationInput
		action kernel.Action
		valid  bool
	}{
		{name: "transition", input: TicketBulkMutationInput{
			Action: "transition", Transition: "close_alert", To: "closed",
		}, action: kernel.ActionTransition, valid: true},
		{name: "assign team", input: TicketBulkMutationInput{
			Action: "assign", TeamID: fixture.base.teamUUID,
		}, action: kernel.ActionAssign, valid: true},
		{name: "assign user", input: TicketBulkMutationInput{
			Action: "assign", TeamID: fixture.base.teamUUID, AssigneeID: &assignee,
		}, action: kernel.ActionAssign, valid: true},
		{name: "transfer", input: TicketBulkMutationInput{
			Action: "transfer", TeamID: fixture.base.teamUUID, AssigneeID: &assignee,
		}, action: kernel.ActionTransfer, valid: true},
		{name: "claim", input: TicketBulkMutationInput{
			Action: "claim", TeamID: fixture.base.teamUUID,
		}, action: kernel.ActionClaim, valid: true},
		{name: "release", input: TicketBulkMutationInput{Action: "release"}, action: kernel.ActionRelease, valid: true},
		{name: "uppercase rejected", input: TicketBulkMutationInput{Action: "Release"}},
		{name: "transition missing destination", input: TicketBulkMutationInput{Action: "transition", Transition: "close_alert"}},
		{name: "claim with assignee", input: TicketBulkMutationInput{
			Action: "claim", TeamID: fixture.base.teamUUID, AssigneeID: &assignee,
		}},
		{name: "assign without team", input: TicketBulkMutationInput{Action: "assign"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutation, err := ticketBulkMutationFromInput(test.input)
			if test.valid {
				if err != nil || mutation.Action() != test.action {
					t.Fatalf("mutation=%#v error=%v", mutation, err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestTicketBulkServiceRejectsHostileAccessProjection(t *testing.T) {
	fixture := newTicketBulkFixture(t)
	for _, mutate := range []func(*fakeTicketBulkRepository){
		func(repository *fakeTicketBulkRepository) { repository.forceAccessTenant = mustUUIDv7(t) },
		func(repository *fakeTicketBulkRepository) { repository.forceAccessActor = mustUUIDv7(t) },
		func(repository *fakeTicketBulkRepository) { repository.forceInvalidMembership = true },
		func(repository *fakeTicketBulkRepository) {
			repository.forceAccessCapability = TicketBulkCapabilityRead
		},
	} {
		repository := newFakeTicketBulkRepository(fixture)
		mutate(repository)
		service := mustTicketBulkService(t, repository, fixture.now)
		if _, err := service.Request(
			context.Background(), fixture.base.actor, fixture.base.tenantUUID,
			kernel.AggregateAlert, fixture.explicitRequest,
		); !errors.Is(err, ErrUnavailable) || repository.reserveCalls.Load() != 0 {
			t.Fatalf("error=%v reserve=%d", err, repository.reserveCalls.Load())
		}
	}
}

func TestTicketBulkQueryRequestPinsResolvedQueryAndMaterializedTargets(t *testing.T) {
	fixture := newTicketBulkFixture(t)
	repository := newFakeTicketBulkRepository(fixture)
	service := mustTicketBulkService(t, repository, fixture.now)
	input := fixture.explicitRequest
	input.Selection = TicketBulkSelectionInput{Query: &fixture.inlineSource}
	input.IdempotencyKey = "ticket-bulk-query-0001"

	result, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, input,
	)
	if err != nil {
		t.Fatal(err)
	}
	selection := result.Record.Job.Definition().Selection()
	if result.Record.Query == nil || selection.Source() != kernel.TicketBulkSelectionQuery ||
		selection.TargetCount() != 2 || selection.QueryDigest() != fixture.inlineQuery.QueryDigest() ||
		selection.TargetSetDigest() != ([32]byte{9, 8, 7}) || selection.SavedView() != nil ||
		!sameTicketBulkQuery(*result.Record.Query, fixture.inlineQuery) ||
		repository.resolveQueryCalls.Load() != 1 {
		t.Fatalf("result = %#v", result)
	}

	repository = newFakeTicketBulkRepository(fixture)
	repository.query = TicketBulkQuerySnapshot{}
	service = mustTicketBulkService(t, repository, fixture.now)
	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, input,
	); !errors.Is(err, ErrUnavailable) || repository.reserveCalls.Load() != 0 {
		t.Fatalf("hostile query error = %v, reserve=%d", err, repository.reserveCalls.Load())
	}

	repository = newFakeTicketBulkRepository(fixture)
	repository.query = ticketBulkInlineQueryWithSearch(t, fixture, "substituted query")
	service = mustTicketBulkService(t, repository, fixture.now)
	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, input,
	); !errors.Is(err, ErrUnavailable) || repository.reserveCalls.Load() != 0 {
		t.Fatalf("substituted inline query error = %v, reserve=%d", err, repository.reserveCalls.Load())
	}

	repository = newFakeTicketBulkRepository(fixture)
	repository.query = ticketBulkInlineQueryWithSearch(t, fixture, "substituted query")
	repository.resolveQueryHook = func(input *TicketBulkQuerySourceInput) {
		input.Inline.Filters.Search = "substituted query"
	}
	service = mustTicketBulkService(t, repository, fixture.now)
	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, input,
	); !errors.Is(err, ErrUnavailable) || repository.reserveCalls.Load() != 0 ||
		fixture.inlineSource.Inline.Filters.Search != "malware campaign" {
		t.Fatalf(
			"mutating resolver error = %v, reserve=%d, original=%q",
			err, repository.reserveCalls.Load(), fixture.inlineSource.Inline.Filters.Search,
		)
	}
}

func TestTicketBulkInlineQueryValidatesCanonicalDynamicFilterValue(t *testing.T) {
	fixture := newTicketBulkFixture(t)
	source, query := ticketBulkDecimalQueryFixture(t, fixture, "10.500")
	repository := newFakeTicketBulkRepository(fixture)
	repository.query = query
	service := mustTicketBulkService(t, repository, fixture.now)
	input := fixture.explicitRequest
	input.Selection = TicketBulkSelectionInput{Query: &source}
	input.IdempotencyKey = "ticket-bulk-decimal-filter-0001"
	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, input,
	); err != nil {
		t.Fatalf("semantically equivalent decimal rejected: %v", err)
	}

	hostile := cloneTicketBulkQuerySourceInput(&source)
	hostile.Inline.Filters.Custom[0].Value = []byte("11")
	input.Selection.Query = hostile
	input.IdempotencyKey = "ticket-bulk-decimal-filter-0002"
	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, input,
	); !errors.Is(err, ErrUnavailable) || repository.reserveCalls.Load() != 1 {
		t.Fatalf("substituted filter error=%v reserve=%d", err, repository.reserveCalls.Load())
	}
}

func TestTicketBulkSavedViewQueryRequiresExactOwnerRevisionAndDigest(t *testing.T) {
	fixture := newTicketBulkFixture(t)
	repository := newFakeTicketBulkRepository(fixture)
	repository.query = fixture.savedQuery
	service := mustTicketBulkService(t, repository, fixture.now)
	input := fixture.explicitRequest
	input.Selection = TicketBulkSelectionInput{Query: &fixture.savedSource}
	input.IdempotencyKey = "ticket-bulk-saved-view-0001"

	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, input,
	); err != nil {
		t.Fatal(err)
	}

	for _, mutate := range []func(*TicketBulkSavedViewSourceInput){
		func(value *TicketBulkSavedViewSourceInput) { value.ID = mustUUIDv7(t) },
		func(value *TicketBulkSavedViewSourceInput) { value.ExpectedRevision++ },
		func(value *TicketBulkSavedViewSourceInput) { value.ExpectedSpecDigest[0]++ },
	} {
		repository := newFakeTicketBulkRepository(fixture)
		repository.query = fixture.savedQuery
		service := mustTicketBulkService(t, repository, fixture.now)
		saved := *fixture.savedSource.SavedView
		candidate := TicketBulkQuerySourceInput{SavedView: &saved}
		mutate(candidate.SavedView)
		input.Selection = TicketBulkSelectionInput{Query: &candidate}
		if _, err := service.Request(
			context.Background(), fixture.base.actor, fixture.base.tenantUUID,
			kernel.AggregateAlert, input,
		); !errors.Is(err, ErrUnavailable) || repository.reserveCalls.Load() != 0 {
			t.Fatalf("error = %v, reserve=%d", err, repository.reserveCalls.Load())
		}
	}
}

func TestTicketBulkRequestReplayIsExactAndDivergentReuseConflicts(t *testing.T) {
	fixture := newTicketBulkFixture(t)
	repository := newFakeTicketBulkRepository(fixture)
	service := mustTicketBulkService(t, repository, fixture.now)
	first, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, fixture.explicitRequest,
	)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, fixture.explicitRequest,
	)
	if err != nil || !replay.Replayed || !kernel.SameTicketBulkJob(first.Record.Job, replay.Record.Job) ||
		repository.reserveCalls.Load() != 1 || repository.commitRequestCalls.Load() != 1 {
		t.Fatalf("replay = %#v, error=%v", replay, err)
	}

	divergent := fixture.explicitRequest
	divergent.Retention = 2 * time.Hour
	if _, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, divergent,
	); !errors.Is(err, ErrConflict) || repository.reserveCalls.Load() != 1 {
		t.Fatalf("divergent error = %v", err)
	}
}

func TestTicketBulkRequestConcurrentRetryHasOneDurableWinner(t *testing.T) {
	fixture := newTicketBulkFixture(t)
	repository := newFakeTicketBulkRepository(fixture)
	service := mustTicketBulkService(t, repository, fixture.now)
	results := make(chan TicketBulkResult, 2)
	errorsSeen := make(chan error, 2)
	var group sync.WaitGroup
	for range 2 {
		group.Add(1)
		go func() {
			defer group.Done()
			result, err := service.Request(
				context.Background(), fixture.base.actor, fixture.base.tenantUUID,
				kernel.AggregateAlert, fixture.explicitRequest,
			)
			results <- result
			errorsSeen <- err
		}()
	}
	group.Wait()
	close(results)
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent request error = %v", err)
		}
	}
	var first *TicketBulkResult
	replayed := 0
	for result := range results {
		if first == nil {
			copy := result
			first = &copy
		} else if !kernel.SameTicketBulkJob(first.Record.Job, result.Record.Job) {
			t.Fatalf("concurrent winners differ: first=%#v next=%#v", *first, result)
		}
		if result.Replayed {
			replayed++
		}
	}
	if replayed != 1 || len(repository.records) != 1 {
		t.Fatalf("replayed=%d durable_records=%d", replayed, len(repository.records))
	}
}

func TestTicketBulkQueryReplayDoesNotReresolveMutableSource(t *testing.T) {
	fixture := newTicketBulkFixture(t)
	for _, test := range []struct {
		name   string
		source TicketBulkQuerySourceInput
		query  TicketBulkQuerySnapshot
	}{
		{name: "inline", source: fixture.inlineSource, query: fixture.inlineQuery},
		{name: "saved view", source: fixture.savedSource, query: fixture.savedQuery},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := newFakeTicketBulkRepository(fixture)
			repository.query = test.query
			service := mustTicketBulkService(t, repository, fixture.now)
			input := fixture.explicitRequest
			input.Selection = TicketBulkSelectionInput{Query: &test.source}
			input.IdempotencyKey = "ticket-bulk-query-replay-0001"
			first, err := service.Request(
				context.Background(), fixture.base.actor, fixture.base.tenantUUID,
				kernel.AggregateAlert, input,
			)
			if err != nil {
				t.Fatal(err)
			}

			// An exact retry is bound to the original request intent. It must return
			// the durable winner even if the mutable resolver is now unavailable.
			repository.query = TicketBulkQuerySnapshot{}
			replay, err := service.Request(
				context.Background(), fixture.base.actor, fixture.base.tenantUUID,
				kernel.AggregateAlert, input,
			)
			if err != nil || !replay.Replayed ||
				!kernel.SameTicketBulkJob(first.Record.Job, replay.Record.Job) ||
				repository.resolveQueryCalls.Load() != 1 || repository.reserveCalls.Load() != 1 ||
				repository.commitRequestCalls.Load() != 1 {
				t.Fatalf(
					"replay=%#v error=%v resolve=%d reserve=%d commit=%d",
					replay, err, repository.resolveQueryCalls.Load(), repository.reserveCalls.Load(),
					repository.commitRequestCalls.Load(),
				)
			}
		})
	}
}

func TestTicketBulkCommitRaceReplaysWinnerBeforeComparingMutableCatalog(t *testing.T) {
	fixture := newTicketBulkFixture(t)
	definitionID, _ := entityID(mustUUIDv7(t))
	source, firstQuery := ticketBulkDecimalQueryWithPin(
		t, fixture, definitionID, [32]byte{7}, "10.500",
	)
	_, driftedQuery := ticketBulkDecimalQueryWithPin(
		t, fixture, definitionID, [32]byte{8}, "10.500",
	)
	repository := newFakeTicketBulkRepository(fixture)
	repository.query = firstQuery
	service := mustTicketBulkService(t, repository, fixture.now)
	input := fixture.explicitRequest
	input.Selection = TicketBulkSelectionInput{Query: &source}
	input.IdempotencyKey = "ticket-bulk-query-commit-race-0001"
	first, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, input,
	)
	if err != nil {
		t.Fatal(err)
	}

	// The initial lookup can race before the durable winner. A same-version
	// catalog projection with a different digest must not replace that winner
	// or make the exact retry depend on the later projection.
	repository.hideReplayOnce.Store(true)
	repository.query = driftedQuery
	replay, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, input,
	)
	if err != nil || !replay.Replayed ||
		!kernel.SameTicketBulkJob(first.Record.Job, replay.Record.Job) ||
		repository.resolveQueryCalls.Load() != 2 || repository.commitRequestCalls.Load() != 2 {
		t.Fatalf(
			"replay=%#v error=%v resolves=%d commits=%d",
			replay, err, repository.resolveQueryCalls.Load(), repository.commitRequestCalls.Load(),
		)
	}
}

func TestTicketBulkRequestRejectsHostileCommitProjection(t *testing.T) {
	fixture := newTicketBulkFixture(t)
	for _, test := range []struct {
		name   string
		mutate func(TicketBulkResult) TicketBulkResult
	}{
		{name: "foreign id", mutate: func(result TicketBulkResult) TicketBulkResult {
			result.Record = reidentifyTicketBulkRecord(t, result.Record, mustUUIDv7(t))
			return result
		}},
		{name: "wrong state", mutate: func(result TicketBulkResult) TicketBulkResult {
			snapshot := result.Record.Job.Snapshot()
			snapshot.State, snapshot.ActiveBatch, snapshot.Revision = kernel.TicketBulkRunning, true, 2
			result.Record.Job, _ = kernel.RestoreTicketBulkJob(snapshot)
			return result
		}},
		{name: "query attached to explicit", mutate: func(result TicketBulkResult) TicketBulkResult {
			query := fixture.inlineQuery
			result.Record.Query = &query
			return result
		}},
		{name: "lower maximum attempts", mutate: func(result TicketBulkResult) TicketBulkResult {
			result.Record = setTicketBulkMaximumAttempts(t, result.Record, kernel.TicketBulkMaximumAttempts-1)
			return result
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := newFakeTicketBulkRepository(fixture)
			repository.commitRequestHook = test.mutate
			service := mustTicketBulkService(t, repository, fixture.now)
			if _, err := service.Request(
				context.Background(), fixture.base.actor, fixture.base.tenantUUID,
				kernel.AggregateAlert, fixture.explicitRequest,
			); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestTicketBulkCancelQueuedJobIsCASBoundAndReplaySafe(t *testing.T) {
	fixture := newTicketBulkFixture(t)
	repository := newFakeTicketBulkRepository(fixture)
	service := mustTicketBulkService(t, repository, fixture.now)
	created := mustRequestTicketBulk(t, service, fixture)

	cancelInput := TicketBulkCancelInput{
		ExpectedRevision: created.Record.Job.Revision(),
		IdempotencyKey:   "ticket-bulk-cancel-0001",
	}
	result, err := service.Cancel(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, uuidFromEntity(created.Record.Job.Definition().ID()), cancelInput,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Replayed || result.Record.Job.State() != kernel.TicketBulkCancelledState ||
		result.Record.Job.Revision() != 2 || !result.Record.Job.Progress().Complete() ||
		result.Record.Job.Progress().Count(kernel.TicketBulkTargetCancelled) != 1 {
		t.Fatalf("result = %#v", result)
	}
	replay, err := service.Cancel(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, uuidFromEntity(created.Record.Job.Definition().ID()), cancelInput,
	)
	if err != nil || !replay.Replayed || repository.commitCancelCalls.Load() != 1 {
		t.Fatalf("replay=%#v err=%v commits=%d", replay, err, repository.commitCancelCalls.Load())
	}

	stale := cancelInput
	stale.IdempotencyKey = "ticket-bulk-cancel-stale-0001"
	if _, err := service.Cancel(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, uuidFromEntity(created.Record.Job.Definition().ID()), stale,
	); !errors.Is(err, ErrPreconditionFailed) {
		t.Fatalf("stale cancellation error = %v", err)
	}
}

func TestTicketBulkCancelReplayClosesLookupToCASRace(t *testing.T) {
	fixture := newTicketBulkFixture(t)
	repository := newFakeTicketBulkRepository(fixture)
	service := mustTicketBulkService(t, repository, fixture.now)
	created := mustRequestTicketBulk(t, service, fixture)
	input := TicketBulkCancelInput{
		ExpectedRevision: created.Record.Job.Revision(),
		IdempotencyKey:   "ticket-bulk-cancel-race-replay-0001",
	}
	first, err := service.Cancel(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, fixture.jobID, input,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Model a lookup that raced just before the winner transaction committed:
	// the subsequent job read sees the new revision, so a second lookup must
	// recover the exact durable idempotency result rather than emit a false 412.
	repository.hideReplayOnce.Store(true)
	replay, err := service.Cancel(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, fixture.jobID, input,
	)
	if err != nil || !replay.Replayed ||
		!kernel.SameTicketBulkJob(first.Record.Job, replay.Record.Job) ||
		repository.commitCancelCalls.Load() != 1 {
		t.Fatalf(
			"replay=%#v error=%v commits=%d",
			replay, err, repository.commitCancelCalls.Load(),
		)
	}
}

func TestTicketBulkCancelRunningJobPreservesProgressAndRequestsControl(t *testing.T) {
	fixture := newTicketBulkFixture(t)
	repository := newFakeTicketBulkRepository(fixture)
	service := mustTicketBulkService(t, repository, fixture.now)
	created := mustRequestTicketBulk(t, service, fixture)
	repository.mu.Lock()
	record := repository.records[fixture.jobID]
	snapshot := record.Job.Snapshot()
	snapshot.State, snapshot.Revision, snapshot.ActiveBatch = kernel.TicketBulkRunning, 2, true
	snapshot.UpdatedAt, snapshot.AvailableAt = fixture.now.Add(time.Minute), fixture.now
	record.Job, _ = kernel.RestoreTicketBulkJob(snapshot)
	repository.records[fixture.jobID] = record
	repository.mu.Unlock()
	service.clock = func() time.Time { return fixture.now.Add(2 * time.Minute) }

	result, err := service.Cancel(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, fixture.jobID,
		TicketBulkCancelInput{ExpectedRevision: 2, IdempotencyKey: "ticket-bulk-running-cancel-0001"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Record.Job.State() != kernel.TicketBulkCancellationRequested ||
		result.Record.Job.Revision() != 3 || !result.Record.Job.ActiveBatch() ||
		result.Record.Job.Progress().Processed() != created.Record.Job.Progress().Processed() {
		t.Fatalf("result = %#v", result)
	}
}

func TestTicketBulkCancellationRaceHasOneCASWinner(t *testing.T) {
	fixture := newTicketBulkFixture(t)
	repository := newFakeTicketBulkRepository(fixture)
	service := mustTicketBulkService(t, repository, fixture.now)
	created := mustRequestTicketBulk(t, service, fixture)
	var group sync.WaitGroup
	errorsSeen := make(chan error, 2)
	for index := range 2 {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			_, err := service.Cancel(
				context.Background(), fixture.base.actor, fixture.base.tenantUUID,
				kernel.AggregateAlert, fixture.jobID, TicketBulkCancelInput{
					ExpectedRevision: created.Record.Job.Revision(),
					IdempotencyKey:   fmt.Sprintf("ticket-bulk-cancel-race-%04d", index),
				},
			)
			errorsSeen <- err
		}(index)
	}
	group.Wait()
	close(errorsSeen)
	winners, stale := 0, 0
	for err := range errorsSeen {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, ErrPreconditionFailed):
			stale++
		default:
			t.Fatalf("unexpected cancellation race error = %v", err)
		}
	}
	commitCalls := repository.commitCancelCalls.Load()
	if winners != 1 || stale != 1 || commitCalls < 1 || commitCalls > 2 {
		t.Fatalf(
			"winners=%d stale=%d commit_calls=%d",
			winners, stale, commitCalls,
		)
	}
}

func TestTicketBulkCancellationRejectsRegressedClockAsUnavailable(t *testing.T) {
	fixture := newTicketBulkFixture(t)
	repository := newFakeTicketBulkRepository(fixture)
	service := mustTicketBulkService(t, repository, fixture.now)
	created := mustRequestTicketBulk(t, service, fixture)
	service.clock = func() time.Time { return fixture.now.Add(-time.Microsecond) }
	if _, err := service.Cancel(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, fixture.jobID, TicketBulkCancelInput{
			ExpectedRevision: created.Record.Job.Revision(),
			IdempotencyKey:   "ticket-bulk-regressed-clock-0001",
		},
	); !errors.Is(err, ErrUnavailable) || repository.commitCancelCalls.Load() != 0 {
		t.Fatalf("error=%v commit_calls=%d", err, repository.commitCancelCalls.Load())
	}
}

func TestTicketBulkGetAndResultsAreOwnerScopedAndProjectionChecked(t *testing.T) {
	fixture := newTicketBulkFixture(t)
	repository := newFakeTicketBulkRepository(fixture)
	service := mustTicketBulkService(t, repository, fixture.now)
	created := mustRequestTicketBulk(t, service, fixture)

	record, err := service.Get(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, fixture.jobID,
	)
	if err != nil || !kernel.SameTicketBulkJob(record.Job, created.Record.Job) {
		t.Fatalf("record=%#v err=%v", record, err)
	}
	repository.forceGetErr = ErrForbidden
	if _, err := service.Get(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, fixture.jobID,
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("forbidden lookup error = %v", err)
	}
	repository.forceGetErr = nil
	repository.recordTicketBulkResult(t, fixture.jobID, kernel.TicketBulkTargetSucceeded, fixture.now)
	repository.page = TicketBulkResultPage{Items: []TicketBulkTargetResultRecord{{
		Sequence: 1, TargetID: fixture.base.ticketUUID, TargetVersion: 1,
		Result: kernel.TicketBulkTargetSucceeded, RecordedAt: fixture.now,
	}}, Next: "bmV4dA"}
	page, err := service.ListResults(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, fixture.jobID, TicketBulkResultListInput{Limit: 10},
	)
	if err != nil || len(page.Items) != 1 || page.Next != "bmV4dA" {
		t.Fatalf("page=%#v err=%v", page, err)
	}
	page.Items[0].TargetID = uuid.Nil
	if repository.page.Items[0].TargetID == uuid.Nil {
		t.Fatal("result items escaped by reference")
	}
}

func TestTicketBulkResultPageRejectsMalformedOrCyclingRows(t *testing.T) {
	fixture := newTicketBulkFixture(t)
	for _, test := range []struct {
		name string
		page TicketBulkResultPage
	}{
		{name: "zero sequence", page: TicketBulkResultPage{Items: []TicketBulkTargetResultRecord{{
			TargetID: fixture.base.ticketUUID, TargetVersion: 1,
			Result: kernel.TicketBulkTargetSucceeded, RecordedAt: fixture.now,
		}}}},
		{name: "duplicate sequence", page: TicketBulkResultPage{Items: []TicketBulkTargetResultRecord{
			{Sequence: 1, TargetID: fixture.base.ticketUUID, TargetVersion: 1, Result: kernel.TicketBulkTargetSucceeded, RecordedAt: fixture.now},
			{Sequence: 1, TargetID: mustUUIDv7(t), TargetVersion: 1, Result: kernel.TicketBulkTargetRejected, RecordedAt: fixture.now},
		}}},
		{name: "unknown result", page: TicketBulkResultPage{Items: []TicketBulkTargetResultRecord{{
			Sequence: 1, TargetID: fixture.base.ticketUUID, TargetVersion: 1,
			Result: 99, RecordedAt: fixture.now,
		}}}},
		{name: "category exceeds progress", page: TicketBulkResultPage{Items: []TicketBulkTargetResultRecord{{
			Sequence: 1, TargetID: fixture.base.ticketUUID, TargetVersion: 1,
			Result: kernel.TicketBulkTargetRejected, RecordedAt: fixture.now,
		}}}},
		{name: "future receipt", page: TicketBulkResultPage{Items: []TicketBulkTargetResultRecord{{
			Sequence: 1, TargetID: fixture.base.ticketUUID, TargetVersion: 1,
			Result: kernel.TicketBulkTargetSucceeded, RecordedAt: fixture.now.Add(time.Minute),
		}}}},
		{name: "cursor without rows", page: TicketBulkResultPage{Next: "bmV4dA"}},
		{name: "noncanonical cursor", page: TicketBulkResultPage{Items: []TicketBulkTargetResultRecord{{
			Sequence: 1, TargetID: fixture.base.ticketUUID, TargetVersion: 1,
			Result: kernel.TicketBulkTargetSucceeded, RecordedAt: fixture.now,
		}}, Next: "AB"}},
		{name: "immediate cycle", page: TicketBulkResultPage{Items: []TicketBulkTargetResultRecord{{
			Sequence: 1, TargetID: fixture.base.ticketUUID, TargetVersion: 1,
			Result: kernel.TicketBulkTargetSucceeded, RecordedAt: fixture.now,
		}}, Next: "c2FtZQ"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := newFakeTicketBulkRepository(fixture)
			service := mustTicketBulkService(t, repository, fixture.now)
			mustRequestTicketBulk(t, service, fixture)
			if test.name != "cursor without rows" {
				repository.recordTicketBulkResult(
					t, fixture.jobID, kernel.TicketBulkTargetSucceeded, fixture.now,
				)
			}
			repository.page = test.page
			input := TicketBulkResultListInput{Limit: 10}
			if test.name == "immediate cycle" {
				input.After = "c2FtZQ"
			}
			if _, err := service.ListResults(
				context.Background(), fixture.base.actor, fixture.base.tenantUUID,
				kernel.AggregateAlert, fixture.jobID, input,
			); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestTicketBulkResultPageRejectsReceiptsOutsideExplicitPins(t *testing.T) {
	fixture := newTicketBulkFixture(t)
	for _, test := range []struct {
		name  string
		item  TicketBulkTargetResultRecord
		input TicketBulkResultListInput
		want  error
	}{
		{name: "foreign target", item: TicketBulkTargetResultRecord{
			Sequence: 1, TargetID: mustUUIDv7(t), TargetVersion: 1,
			Result: kernel.TicketBulkTargetSucceeded, RecordedAt: fixture.now,
		}, input: TicketBulkResultListInput{Limit: 10}, want: ErrUnavailable},
		{name: "wrong target version", item: TicketBulkTargetResultRecord{
			Sequence: 1, TargetID: fixture.base.ticketUUID, TargetVersion: 2,
			Result: kernel.TicketBulkTargetSucceeded, RecordedAt: fixture.now,
		}, input: TicketBulkResultListInput{Limit: 10}, want: ErrUnavailable},
		{name: "noncanonical input cursor", input: TicketBulkResultListInput{
			Limit: 10, After: "AB",
		}, want: ErrInvalidInput},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := newFakeTicketBulkRepository(fixture)
			service := mustTicketBulkService(t, repository, fixture.now)
			mustRequestTicketBulk(t, service, fixture)
			if test.item.Sequence != 0 {
				repository.recordTicketBulkResult(
					t, fixture.jobID, kernel.TicketBulkTargetSucceeded, fixture.now,
				)
				repository.page = TicketBulkResultPage{Items: []TicketBulkTargetResultRecord{test.item}}
			}
			if _, err := service.ListResults(
				context.Background(), fixture.base.actor, fixture.base.tenantUUID,
				kernel.AggregateAlert, fixture.jobID, test.input,
			); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}

	t.Run("duplicate target with distinct sequence", func(t *testing.T) {
		repository := newFakeTicketBulkRepository(fixture)
		service := mustTicketBulkService(t, repository, fixture.now)
		input := fixture.explicitRequest
		input.Selection = cloneTicketBulkSelectionInput(input.Selection)
		input.Selection.Explicit = append(input.Selection.Explicit, TicketBulkTargetInput{
			ID: mustUUIDv7(t), ExpectedVersion: 2,
		})
		if _, err := service.Request(
			context.Background(), fixture.base.actor, fixture.base.tenantUUID,
			kernel.AggregateAlert, input,
		); err != nil {
			t.Fatal(err)
		}
		repository.recordTicketBulkResult(t, fixture.jobID, kernel.TicketBulkTargetSucceeded, fixture.now)
		repository.recordTicketBulkResult(t, fixture.jobID, kernel.TicketBulkTargetSucceeded, fixture.now)
		version := fixture.explicitRequest.Selection.Explicit[0].ExpectedVersion
		repository.page = TicketBulkResultPage{Items: []TicketBulkTargetResultRecord{
			{Sequence: 1, TargetID: fixture.base.ticketUUID, TargetVersion: version, Result: kernel.TicketBulkTargetSucceeded, RecordedAt: fixture.now},
			{Sequence: 2, TargetID: fixture.base.ticketUUID, TargetVersion: version, Result: kernel.TicketBulkTargetSucceeded, RecordedAt: fixture.now},
		}}
		if _, err := service.ListResults(
			context.Background(), fixture.base.actor, fixture.base.tenantUUID,
			kernel.AggregateAlert, fixture.jobID, TicketBulkResultListInput{Limit: 10},
		); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestTicketBulkServiceRejectsNilContextAndRedactsDiagnostics(t *testing.T) {
	fixture := newTicketBulkFixture(t)
	repository := newFakeTicketBulkRepository(fixture)
	service := mustTicketBulkService(t, repository, fixture.now)
	if _, err := service.Request(
		nil, fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, fixture.explicitRequest,
	); !errors.Is(err, ErrUnavailable) || repository.resolveAccessCalls.Load() != 0 {
		t.Fatalf("nil context error=%v calls=%d", err, repository.resolveAccessCalls.Load())
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.Request(
		cancelled, fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, fixture.explicitRequest,
	); !errors.Is(err, ErrUnavailable) || repository.resolveAccessCalls.Load() != 0 {
		t.Fatalf("cancelled context error=%v calls=%d", err, repository.resolveAccessCalls.Load())
	}

	access := mustTicketBulkAccess(t, fixture, TicketBulkCapabilityRequest, kernel.ActionRelease)
	selection, _ := ticketBulkExplicitSelection(fixture.explicitRequest.Selection.Explicit)
	command, _ := bindTicketBulkRequestCommand(
		fixture.explicitRequest.IdempotencyKey, access, &selection, nil,
		kernel.NewTicketBulkRelease(), fixture.explicitRequest.Retention,
	)
	values := []string{
		fmt.Sprintf("%v", fixture.explicitRequest), fmt.Sprintf("%#v", fixture.explicitRequest),
		fmt.Sprintf("%v", access), fmt.Sprintf("%#v", access),
		fmt.Sprintf("%v", command), fmt.Sprintf("%#v", command),
	}
	hostile := TicketBulkMutationInput{Action: "private-token-value"}
	values = append(values, fmt.Sprintf("%v", hostile), fmt.Sprintf("%#v", hostile))
	for _, value := range values {
		for _, secret := range []string{
			fixture.base.tenantUUID.String(), fixture.base.actor.UserID.String(),
			fixture.base.membershipUUID.String(), fixture.base.ticketUUID.String(),
			fixture.explicitRequest.IdempotencyKey,
			"private-token-value",
		} {
			if strings.Contains(value, secret) {
				t.Fatalf("diagnostic %q exposed %q", value, secret)
			}
		}
	}
}

type ticketBulkFixture struct {
	base            serviceFixture
	now             time.Time
	jobID           uuid.UUID
	reservedID      kernel.EntityID
	explicitRequest TicketBulkRequestInput
	inlineSource    TicketBulkQuerySourceInput
	inlineQuery     TicketBulkQuerySnapshot
	savedSource     TicketBulkQuerySourceInput
	savedQuery      TicketBulkQuerySnapshot
}

func newTicketBulkFixture(t testing.TB) ticketBulkFixture {
	t.Helper()
	saved := newSavedViewServiceFixture(t)
	jobID := mustUUIDv7(t)
	reservedID, _ := entityID(jobID)
	inlineQuery, err := NewTicketBulkQuerySnapshot(
		saved.base.tenantUUID, kernel.AggregateAlert, TicketBulkQueryInline, saved.spec, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	viewID, _ := entityID(saved.viewID)
	owner, _ := entityID(saved.base.membershipUUID)
	pin, err := kernel.NewTicketBulkSavedViewPin(viewID, owner, saved.record.View.Revision(), saved.record.SpecDigest)
	if err != nil {
		t.Fatal(err)
	}
	savedQuery, err := NewTicketBulkQuerySnapshot(
		saved.base.tenantUUID, kernel.AggregateAlert, TicketBulkQuerySavedView, saved.spec, &pin,
	)
	if err != nil {
		t.Fatal(err)
	}
	inlineInput := saved.input
	savedInput := TicketBulkSavedViewSourceInput{
		ID: saved.viewID, ExpectedRevision: saved.record.View.Revision(),
		ExpectedSpecDigest: saved.record.SpecDigest,
	}
	return ticketBulkFixture{
		base: saved.base, now: time.Date(2026, 8, 26, 18, 30, 0, 0, time.UTC),
		jobID: jobID, reservedID: reservedID,
		explicitRequest: TicketBulkRequestInput{
			Selection: TicketBulkSelectionInput{Explicit: []TicketBulkTargetInput{{
				ID: saved.base.ticketUUID, ExpectedVersion: saved.base.record.Snapshot.Version(),
			}}},
			Mutation:  TicketBulkMutationInput{Action: kernel.ActionRelease.String()},
			Retention: time.Hour, IdempotencyKey: "ticket-bulk-request-0001",
		},
		inlineSource: TicketBulkQuerySourceInput{Inline: &inlineInput}, inlineQuery: inlineQuery,
		savedSource: TicketBulkQuerySourceInput{SavedView: &savedInput}, savedQuery: savedQuery,
	}
}

func mustTicketBulkService(
	t testing.TB,
	repository TicketBulkRepository,
	now time.Time,
) *TicketBulkService {
	t.Helper()
	service, err := NewTicketBulkService(repository, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func mustTicketBulkAccess(
	t testing.TB,
	fixture ticketBulkFixture,
	capability TicketBulkCapability,
	mutation kernel.Action,
) TicketBulkAccess {
	t.Helper()
	access, err := NewTicketBulkAccess(
		fixture.base.tenantUUID, fixture.base.actor.UserID, fixture.base.membershipUUID,
		kernel.AggregateAlert, capability, kernel.PrincipalOperator, mutation, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	return access
}

func mustRequestTicketBulk(
	t testing.TB,
	service *TicketBulkService,
	fixture ticketBulkFixture,
) TicketBulkResult {
	t.Helper()
	result, err := service.Request(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, fixture.explicitRequest,
	)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func reidentifyTicketBulkRecord(
	t testing.TB,
	record TicketBulkRecord,
	id uuid.UUID,
) TicketBulkRecord {
	t.Helper()
	definition := record.Job.Definition()
	newID, _ := entityID(id)
	rebuilt, err := kernel.NewTicketBulkDefinition(kernel.TicketBulkDefinitionInput{
		ID: newID, Tenant: definition.Tenant(), Requester: definition.Requester(),
		OwnerMembership: definition.OwnerMembership(), Kind: definition.Kind(),
		Selection: definition.Selection(), Mutation: definition.Mutation(),
		ProjectionVersion: definition.ProjectionVersion(), MaximumAttempts: definition.MaximumAttempts(),
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := record.Job.Snapshot()
	snapshot.Definition = rebuilt
	record.Job, err = kernel.RestoreTicketBulkJob(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func setTicketBulkMaximumAttempts(
	t testing.TB,
	record TicketBulkRecord,
	maximum uint8,
) TicketBulkRecord {
	t.Helper()
	definition := record.Job.Definition()
	rebuilt, err := kernel.NewTicketBulkDefinition(kernel.TicketBulkDefinitionInput{
		ID: definition.ID(), Tenant: definition.Tenant(), Requester: definition.Requester(),
		OwnerMembership: definition.OwnerMembership(), Kind: definition.Kind(),
		Selection: definition.Selection(), Mutation: definition.Mutation(),
		ProjectionVersion: definition.ProjectionVersion(), MaximumAttempts: maximum,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := record.Job.Snapshot()
	snapshot.Definition = rebuilt
	record.Job, err = kernel.RestoreTicketBulkJob(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func ticketBulkInlineQueryWithSearch(
	t testing.TB,
	fixture ticketBulkFixture,
	search string,
) TicketBulkQuerySnapshot {
	t.Helper()
	filters, err := kernel.NewSavedViewFilters(kernel.SavedViewFiltersInput{
		Queue: kernel.SavedViewQueueAll, Search: search,
	})
	if err != nil {
		t.Fatal(err)
	}
	spec, err := kernel.NewSavedViewSpec(
		fixture.base.tenant, kernel.AggregateAlert, filters,
		fixture.inlineQuery.Spec().Sort(), fixture.inlineQuery.Spec().Columns(),
	)
	if err != nil {
		t.Fatal(err)
	}
	query, err := NewTicketBulkQuerySnapshot(
		fixture.base.tenantUUID, kernel.AggregateAlert, TicketBulkQueryInline, spec, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	return query
}

func ticketBulkDecimalQueryFixture(
	t testing.TB,
	fixture ticketBulkFixture,
	requestValue string,
) (TicketBulkQuerySourceInput, TicketBulkQuerySnapshot) {
	t.Helper()
	definitionID, _ := entityID(mustUUIDv7(t))
	return ticketBulkDecimalQueryWithPin(t, fixture, definitionID, [32]byte{7}, requestValue)
}

func ticketBulkDecimalQueryWithPin(
	t testing.TB,
	fixture ticketBulkFixture,
	definitionID kernel.EntityID,
	definitionDigest [32]byte,
	requestValue string,
) (TicketBulkQuerySourceInput, TicketBulkQuerySnapshot) {
	t.Helper()
	definitionKey, _ := kernel.NewKey("bulk_risk_score")
	pin, err := kernel.NewSavedViewDefinitionPin(
		definitionID, fixture.base.tenant, kernel.AggregateAlert, definitionKey, 7, definitionDigest,
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
	sortPlan, err := kernel.NewSavedViewDynamicSort(
		kernel.SavedViewColumnCustomField, pin,
		kernel.SavedViewSortDescending, kernel.SavedViewNullsLast,
	)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := kernel.NewSavedViewSpec(
		fixture.base.tenant, kernel.AggregateAlert, filters, sortPlan,
		[]kernel.SavedViewColumn{ticketColumn, dynamicColumn},
	)
	if err != nil {
		t.Fatal(err)
	}
	query, err := NewTicketBulkQuerySnapshot(
		fixture.base.tenantUUID, kernel.AggregateAlert, TicketBulkQueryInline, spec, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	input, err := SavedViewSpecInputFromResolved(spec)
	if err != nil {
		t.Fatal(err)
	}
	input.Filters.Custom[0].Value = []byte(requestValue)
	return TicketBulkQuerySourceInput{Inline: &input}, query
}

type ticketBulkReplayKey struct {
	tenant     uuid.UUID
	actor      uuid.UUID
	membership uuid.UUID
	kind       kernel.AggregateKind
	action     TicketBulkCommandAction
	keyHash    [32]byte
}

type ticketBulkReplayValue struct {
	fingerprint [32]byte
	result      TicketBulkResult
}

type fakeTicketBulkRepository struct {
	mu sync.Mutex

	fixture ticketBulkFixture
	allowed bool
	query   TicketBulkQuerySnapshot
	records map[uuid.UUID]TicketBulkRecord
	replays map[ticketBulkReplayKey]ticketBulkReplayValue
	page    TicketBulkResultPage

	forceGetErr            error
	commitRequestHook      func(TicketBulkResult) TicketBulkResult
	resolveQueryHook       func(*TicketBulkQuerySourceInput)
	forceAccessTenant      uuid.UUID
	forceAccessActor       uuid.UUID
	forceAccessMembership  uuid.UUID
	forceInvalidMembership bool
	forceAccessCapability  TicketBulkCapability

	resolveAccessCalls atomic.Int32
	resolveQueryCalls  atomic.Int32
	reserveCalls       atomic.Int32
	commitRequestCalls atomic.Int32
	getCalls           atomic.Int32
	commitCancelCalls  atomic.Int32
	listCalls          atomic.Int32
	hideReplayOnce     atomic.Bool
}

func newFakeTicketBulkRepository(fixture ticketBulkFixture) *fakeTicketBulkRepository {
	return &fakeTicketBulkRepository{
		fixture: fixture, allowed: true, query: fixture.inlineQuery,
		records: map[uuid.UUID]TicketBulkRecord{},
		replays: map[ticketBulkReplayKey]ticketBulkReplayValue{},
	}
}

func (repository *fakeTicketBulkRepository) ResolveTicketBulkAccess(
	_ context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	capability TicketBulkCapability,
	mutation kernel.Action,
) (TicketBulkAccess, error) {
	repository.resolveAccessCalls.Add(1)
	access, err := NewTicketBulkAccess(
		tenantID, actor.UserID, repository.fixture.base.membershipUUID, kind,
		capability, kernel.PrincipalOperator, mutation, repository.allowed,
	)
	if err != nil {
		return TicketBulkAccess{}, err
	}
	if repository.forceAccessTenant != uuid.Nil {
		access.tenant = repository.forceAccessTenant
	}
	if repository.forceAccessActor != uuid.Nil {
		access.actor = repository.forceAccessActor
	}
	if repository.forceAccessMembership != uuid.Nil {
		access.membership = repository.forceAccessMembership
	}
	if repository.forceInvalidMembership {
		access.membership = uuid.Nil
	}
	if repository.forceAccessCapability != "" {
		access.capability = repository.forceAccessCapability
	}
	return access, nil
}

func (repository *fakeTicketBulkRepository) ResolveTicketBulkQuery(
	_ context.Context,
	_ Actor,
	_ uuid.UUID,
	_ kernel.AggregateKind,
	input TicketBulkQuerySourceInput,
	_ TicketBulkAccess,
) (TicketBulkQuerySnapshot, error) {
	repository.resolveQueryCalls.Add(1)
	if repository.resolveQueryHook != nil {
		repository.resolveQueryHook(&input)
	}
	return repository.query, nil
}

func (repository *fakeTicketBulkRepository) ReserveTicketBulkID(
	_ context.Context,
	_ uuid.UUID,
) (kernel.EntityID, error) {
	repository.reserveCalls.Add(1)
	return repository.fixture.reservedID, nil
}

func (repository *fakeTicketBulkRepository) LookupTicketBulkReplay(
	_ context.Context,
	query TicketBulkReplayQuery,
) (TicketBulkResult, bool, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	value, found := repository.replays[ticketBulkReplayKey{
		tenant: query.TenantID, actor: query.ActorID, membership: query.OwnerMembershipID,
		kind: query.Kind, action: query.Action, keyHash: query.KeyHash,
	}]
	if !found {
		return TicketBulkResult{}, false, nil
	}
	if repository.hideReplayOnce.Swap(false) {
		return TicketBulkResult{}, false, nil
	}
	if value.fingerprint != query.Fingerprint {
		return TicketBulkResult{}, false, ErrConflict
	}
	result := value.result
	result.Replayed = true
	return result, true, nil
}

func (repository *fakeTicketBulkRepository) CommitTicketBulkRequest(
	_ context.Context,
	write TicketBulkRequestWrite,
) (TicketBulkResult, error) {
	repository.commitRequestCalls.Add(1)
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := ticketBulkReplayKey{
		tenant: write.Access.tenant, actor: write.Access.actor, membership: write.Access.membership,
		kind: write.Access.kind, action: write.Command.Action, keyHash: write.Command.KeyHash,
	}
	if replay, found := repository.replays[key]; found {
		if replay.fingerprint != write.Command.Fingerprint {
			return TicketBulkResult{}, ErrConflict
		}
		result := replay.result
		result.Replayed = true
		return result, nil
	}
	var selection kernel.TicketBulkSelection
	var query *TicketBulkQuerySnapshot
	if write.ExplicitSelection != nil {
		selection = *write.ExplicitSelection
	} else {
		saved := write.Query.SavedView()
		created, err := kernel.NewQueryTicketBulkSelection(
			write.Query.QueryDigest(), [32]byte{9, 8, 7}, 2, saved,
		)
		if err != nil {
			return TicketBulkResult{}, err
		}
		selection, query = created, cloneTicketBulkQuerySnapshot(write.Query)
	}
	definition, err := kernel.NewTicketBulkDefinition(kernel.TicketBulkDefinitionInput{
		ID: write.JobID, Tenant: entityMust(repository.fixture.base.tenantUUID),
		Requester: entityMust(write.Actor.UserID), OwnerMembership: entityMust(write.Access.membership),
		Kind: write.Access.kind, Selection: selection, Mutation: write.Mutation,
		ProjectionVersion: kernel.TicketBulkProjectionVersion,
		MaximumAttempts:   kernel.TicketBulkMaximumAttempts,
	})
	if err != nil {
		return TicketBulkResult{}, err
	}
	plan, err := kernel.PlanTicketBulkCreation(definition, write.RequestedAt, write.ExpiresAt)
	if err != nil {
		return TicketBulkResult{}, err
	}
	result := TicketBulkResult{Record: TicketBulkRecord{Job: plan.Next(), Query: query}}
	jobID := uuidFromEntity(definition.ID())
	repository.records[jobID] = result.Record
	repository.replays[key] = ticketBulkReplayValue{
		fingerprint: write.Command.Fingerprint, result: result,
	}
	if repository.commitRequestHook != nil {
		result = repository.commitRequestHook(result)
	}
	return result, nil
}

func (repository *fakeTicketBulkRepository) GetTicketBulk(
	_ context.Context,
	_ Actor,
	_ uuid.UUID,
	jobID uuid.UUID,
	_ TicketBulkAccess,
) (TicketBulkRecord, error) {
	repository.getCalls.Add(1)
	if repository.forceGetErr != nil {
		return TicketBulkRecord{}, repository.forceGetErr
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	record, found := repository.records[jobID]
	if !found {
		return TicketBulkRecord{}, ErrNotFound
	}
	return record, nil
}

func (repository *fakeTicketBulkRepository) CommitTicketBulkCancellation(
	_ context.Context,
	write TicketBulkCancellationWrite,
) (TicketBulkResult, error) {
	repository.commitCancelCalls.Add(1)
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := ticketBulkReplayKey{
		tenant: write.Access.tenant, actor: write.Access.actor, membership: write.Access.membership,
		kind: write.Access.kind, action: write.Command.Action, keyHash: write.Command.KeyHash,
	}
	if replay, found := repository.replays[key]; found {
		if replay.fingerprint != write.Command.Fingerprint {
			return TicketBulkResult{}, ErrConflict
		}
		result := replay.result
		result.Replayed = true
		return result, nil
	}
	next := write.Plan.Next()
	id := uuidFromEntity(next.Definition().ID())
	current, found := repository.records[id]
	if !found || current.Job.Revision() != write.Plan.ExpectedRevision() {
		return TicketBulkResult{}, ErrPreconditionFailed
	}
	result := TicketBulkResult{Record: TicketBulkRecord{Job: next, Query: current.Query}}
	repository.records[id] = result.Record
	repository.replays[key] = ticketBulkReplayValue{
		fingerprint: write.Command.Fingerprint, result: result,
	}
	return result, nil
}

func (repository *fakeTicketBulkRepository) ListTicketBulkResults(
	_ context.Context,
	_ TicketBulkResultQuery,
) (TicketBulkResultPage, error) {
	repository.listCalls.Add(1)
	return repository.page, nil
}

func (repository *fakeTicketBulkRepository) recordTicketBulkResult(
	t testing.TB,
	jobID uuid.UUID,
	result kernel.TicketBulkTargetResult,
	recordedAt time.Time,
) {
	t.Helper()
	repository.mu.Lock()
	defer repository.mu.Unlock()
	record, found := repository.records[jobID]
	if !found {
		t.Fatalf("job %s not found", jobID)
	}
	progress, err := record.Job.Progress().WithResult(result)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := record.Job.Snapshot()
	snapshot.Progress = progress.Snapshot()
	snapshot.Revision++
	snapshot.UpdatedAt = recordedAt
	snapshot.AvailableAt = recordedAt
	if progress.Complete() {
		snapshot.State = kernel.TicketBulkCompleted
		snapshot.TerminalAt = &recordedAt
	}
	record.Job, err = kernel.RestoreTicketBulkJob(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	repository.records[jobID] = record
}

func entityMust(value uuid.UUID) kernel.EntityID {
	result, _ := entityID(value)
	return result
}
