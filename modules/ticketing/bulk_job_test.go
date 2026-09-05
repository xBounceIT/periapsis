package ticketing

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTicketBulkCreationBuildsExactPendingJob(t *testing.T) {
	definition := fixtureTicketBulkDefinition(t, 3)
	now := time.Date(2026, 8, 26, 18, 0, 0, 123_000, time.UTC)
	plan, err := PlanTicketBulkCreation(definition, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	job := plan.Next()
	if plan.Action() != TicketBulkCreate || plan.ExpectedRevision() != 0 ||
		job.State() != TicketBulkPending || job.Revision() != 1 || job.ActiveBatch() ||
		job.Progress().Total() != 3 || job.Progress().Processed() != 0 ||
		!job.RequestedAt().Equal(now) || !job.UpdatedAt().Equal(now) ||
		!job.AvailableAt().Equal(now) || !job.ExpiresAt().Equal(now.Add(time.Hour)) ||
		job.TerminalAt() != nil || ValidateTicketBulkJob(job) != nil {
		t.Fatalf("plan = %#v, job = %#v", plan, job)
	}

	mutated := plan.Next().Snapshot()
	mutated.Progress.Total++
	if _, err := RestoreTicketBulkJob(mutated); !errors.Is(err, ErrInvalidTicketBulkJob) {
		t.Fatalf("mismatched total error = %v", err)
	}
}

func TestTicketBulkCancellationTerminalizesPendingRemainder(t *testing.T) {
	definition := fixtureTicketBulkDefinition(t, 4)
	now := time.Date(2026, 8, 26, 18, 0, 0, 0, time.UTC)
	created, _ := PlanTicketBulkCreation(definition, now, now.Add(time.Hour))
	job := created.Next()
	progress, _ := job.Progress().WithResult(TicketBulkTargetSucceeded)
	snapshot := job.Snapshot()
	snapshot.Revision = 3
	snapshot.Progress = progress.Snapshot()
	snapshot.UpdatedAt = now.Add(time.Minute)
	snapshot.AvailableAt = snapshot.UpdatedAt
	job, err := RestoreTicketBulkJob(snapshot)
	if err != nil {
		t.Fatal(err)
	}

	cancelledAt := now.Add(2 * time.Minute)
	plan, err := PlanTicketBulkCancellation(job, 3, cancelledAt)
	if err != nil {
		t.Fatal(err)
	}
	next := plan.Next()
	terminal := next.TerminalAt()
	if plan.Action() != TicketBulkRequestCancellation || plan.ExpectedRevision() != 3 ||
		next.State() != TicketBulkCancelledState || next.Revision() != 4 || next.ActiveBatch() ||
		!next.Progress().Complete() || next.Progress().Count(TicketBulkTargetSucceeded) != 1 ||
		next.Progress().Count(TicketBulkTargetCancelled) != 3 ||
		terminal == nil || !terminal.Equal(cancelledAt) {
		t.Fatalf("plan = %#v, next = %#v", plan, next)
	}
	*terminal = time.Time{}
	if next.TerminalAt() == nil || next.TerminalAt().IsZero() {
		t.Fatal("terminal timestamp escaped by reference")
	}
}

func TestTicketBulkCancellationMarksRunningJobWithoutInventingResults(t *testing.T) {
	definition := fixtureTicketBulkDefinition(t, 2)
	now := time.Date(2026, 8, 26, 18, 0, 0, 0, time.UTC)
	created, _ := PlanTicketBulkCreation(definition, now, now.Add(time.Hour))
	snapshot := created.Next().Snapshot()
	snapshot.State = TicketBulkRunning
	snapshot.Revision = 2
	snapshot.ActiveBatch = true
	snapshot.UpdatedAt = now.Add(time.Minute)
	snapshot.AvailableAt = now
	running, err := RestoreTicketBulkJob(snapshot)
	if err != nil {
		t.Fatal(err)
	}

	plan, err := PlanTicketBulkCancellation(running, 2, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	next := plan.Next()
	if next.State() != TicketBulkCancellationRequested || next.Revision() != 3 ||
		!next.ActiveBatch() || next.Progress().Processed() != 0 || next.TerminalAt() != nil {
		t.Fatalf("next = %#v", next)
	}
	if _, err := PlanTicketBulkCancellation(next, 3, now.Add(3*time.Minute)); !errors.Is(err, ErrTicketBulkConflict) {
		t.Fatalf("repeat cancellation error = %v", err)
	}
}

func TestTicketBulkJobRejectsImpossibleStateAndCounterShapes(t *testing.T) {
	definition := fixtureTicketBulkDefinition(t, 2)
	now := time.Date(2026, 8, 26, 18, 0, 0, 0, time.UTC)
	created, _ := PlanTicketBulkCreation(definition, now, now.Add(time.Hour))
	base := created.Next().Snapshot()
	terminal := now.Add(time.Minute)

	tests := []struct {
		name   string
		mutate func(*TicketBulkJobSnapshot)
	}{
		{name: "pending complete", mutate: func(value *TicketBulkJobSnapshot) {
			value.Progress.Succeeded = 2
		}},
		{name: "pending with control result", mutate: func(value *TicketBulkJobSnapshot) {
			value.Revision, value.Progress.InternalFailure = 2, 1
		}},
		{name: "running without batch", mutate: func(value *TicketBulkJobSnapshot) {
			value.State, value.Revision, value.UpdatedAt = TicketBulkRunning, 2, terminal
		}},
		{name: "cancellation requested before running revision", mutate: func(value *TicketBulkJobSnapshot) {
			value.State, value.Revision, value.ActiveBatch = TicketBulkCancellationRequested, 2, true
			value.UpdatedAt = terminal
		}},
		{name: "completed with cancellation", mutate: func(value *TicketBulkJobSnapshot) {
			value.State, value.Revision, value.Progress.Cancelled = TicketBulkCompleted, 2, 2
			value.UpdatedAt, value.TerminalAt = terminal, &terminal
		}},
		{name: "failed without internal failure", mutate: func(value *TicketBulkJobSnapshot) {
			value.State, value.Revision, value.Progress.Rejected = TicketBulkFailed, 2, 2
			value.UpdatedAt, value.TerminalAt = terminal, &terminal
		}},
		{name: "cancelled without cancelled rows", mutate: func(value *TicketBulkJobSnapshot) {
			value.State, value.Revision, value.Progress.Succeeded = TicketBulkCancelledState, 2, 2
			value.UpdatedAt, value.TerminalAt = terminal, &terminal
		}},
		{name: "cancelled mixed with internal failure", mutate: func(value *TicketBulkJobSnapshot) {
			value.State, value.Revision = TicketBulkCancelledState, 2
			value.Progress.Cancelled, value.Progress.InternalFailure = 1, 1
			value.UpdatedAt, value.TerminalAt = terminal, &terminal
		}},
		{name: "revoked mixed with cancellation", mutate: func(value *TicketBulkJobSnapshot) {
			value.State, value.Revision = TicketBulkAuthorizationRevokedState, 2
			value.Progress.AuthorizationRevoked, value.Progress.Cancelled = 1, 1
			value.UpdatedAt, value.TerminalAt = terminal, &terminal
		}},
		{name: "revoked mixed with internal failure", mutate: func(value *TicketBulkJobSnapshot) {
			value.State, value.Revision = TicketBulkAuthorizationRevokedState, 2
			value.Progress.AuthorizationRevoked, value.Progress.InternalFailure = 1, 1
			value.UpdatedAt, value.TerminalAt = terminal, &terminal
		}},
		{name: "terminal timestamp mismatch", mutate: func(value *TicketBulkJobSnapshot) {
			value.State, value.Revision, value.Progress.Succeeded = TicketBulkCompleted, 2, 2
			value.UpdatedAt, value.TerminalAt = terminal.Add(time.Minute), &terminal
		}},
		{name: "retention too short", mutate: func(value *TicketBulkJobSnapshot) {
			value.ExpiresAt = now.Add(TicketBulkMinimumRetention - time.Microsecond)
		}},
		{name: "state advanced without revision", mutate: func(value *TicketBulkJobSnapshot) {
			value.State, value.ActiveBatch = TicketBulkRunning, true
		}},
		{name: "creation revision with progress", mutate: func(value *TicketBulkJobSnapshot) {
			value.Progress.Succeeded = 1
		}},
		{name: "creation revision with retry time", mutate: func(value *TicketBulkJobSnapshot) {
			value.AvailableAt = now.Add(time.Minute)
		}},
		{name: "nonterminal at maximum revision", mutate: func(value *TicketBulkJobSnapshot) {
			value.Revision = maxVersion
		}},
		{name: "updated after expiry", mutate: func(value *TicketBulkJobSnapshot) {
			value.State, value.Revision, value.ActiveBatch = TicketBulkRunning, 2, true
			value.UpdatedAt = value.ExpiresAt.Add(time.Microsecond)
		}},
		{name: "timestamp outside RFC3339 year", mutate: func(value *TicketBulkJobSnapshot) {
			outside := time.Date(10_000, time.January, 1, 0, 0, 0, 0, time.UTC)
			value.RequestedAt, value.UpdatedAt, value.AvailableAt = outside, outside, outside
			value.ExpiresAt = outside.Add(time.Hour)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			test.mutate(&candidate)
			if _, err := RestoreTicketBulkJob(candidate); !errors.Is(err, ErrInvalidTicketBulkJob) {
				t.Fatalf("error = %v, candidate = %#v", err, candidate)
			}
		})
	}
}

func TestTicketBulkJobAllowsTerminalSnapshotAtMaximumRevision(t *testing.T) {
	definition := fixtureTicketBulkDefinition(t, 1)
	now := time.Date(2026, 8, 26, 18, 0, 0, 0, time.UTC)
	created, _ := PlanTicketBulkCreation(definition, now, now.Add(time.Hour))
	snapshot := created.Next().Snapshot()
	terminal := now.Add(time.Minute)
	snapshot.State, snapshot.Revision = TicketBulkCompleted, maxVersion
	snapshot.Progress.Succeeded = 1
	snapshot.UpdatedAt, snapshot.TerminalAt = terminal, &terminal
	if _, err := RestoreTicketBulkJob(snapshot); err != nil {
		t.Fatalf("terminal maximum revision rejected: %v", err)
	}
}

func TestTicketBulkCancellationRejectsStaleOrExpiredCommands(t *testing.T) {
	definition := fixtureTicketBulkDefinition(t, 1)
	now := time.Date(2026, 8, 26, 18, 0, 0, 0, time.UTC)
	created, _ := PlanTicketBulkCreation(definition, now, now.Add(TicketBulkMinimumRetention))
	job := created.Next()
	for _, test := range []struct {
		name     string
		revision uint64
		at       time.Time
	}{
		{name: "stale", revision: 2, at: now.Add(time.Minute)},
		{name: "before update", revision: 1, at: now.Add(-time.Microsecond)},
		{name: "expired", revision: 1, at: job.ExpiresAt()},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := PlanTicketBulkCancellation(job, test.revision, test.at); !errors.Is(err, ErrInvalidTicketBulkJob) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestTicketBulkJobDiagnosticsAreRedacted(t *testing.T) {
	definition := fixtureTicketBulkDefinition(t, 1)
	now := time.Date(2026, 8, 26, 18, 0, 0, 0, time.UTC)
	plan, _ := PlanTicketBulkCreation(definition, now, now.Add(time.Hour))
	values := []string{
		fmt.Sprintf("%v", plan.Next()), fmt.Sprintf("%#v", plan.Next()),
		fmt.Sprintf("%v", plan.Next().Snapshot()), fmt.Sprintf("%#v", plan.Next().Snapshot()),
		fmt.Sprintf("%v", plan), fmt.Sprintf("%#v", plan),
	}
	for _, value := range values {
		for _, secret := range []string{
			definition.ID().String(), definition.Tenant().String(),
			definition.Requester().String(), definition.OwnerMembership().String(),
		} {
			if strings.Contains(value, secret) {
				t.Fatalf("diagnostic %q exposed %q", value, secret)
			}
		}
	}
}

func fixtureTicketBulkDefinition(t testing.TB, targets int) TicketBulkDefinition {
	t.Helper()
	pins := make([]TicketBulkTargetPin, targets)
	for index := range pins {
		pin, err := NewTicketBulkTargetPin(fixtureID(uint16(2_000+index)), uint64(index+1))
		if err != nil {
			t.Fatal(err)
		}
		pins[index] = pin
	}
	selection, err := NewExplicitTicketBulkSelection(pins)
	if err != nil {
		t.Fatal(err)
	}
	definition, err := NewTicketBulkDefinition(TicketBulkDefinitionInput{
		ID: fixtureID(2_500), Tenant: fixtureID(2_501), Requester: fixtureID(2_502),
		OwnerMembership: fixtureID(2_503), Kind: AggregateAlert,
		Selection: selection, Mutation: NewTicketBulkRelease(),
		ProjectionVersion: TicketBulkProjectionVersion,
		MaximumAttempts:   TicketBulkMaximumAttempts,
	})
	if err != nil {
		t.Fatal(err)
	}
	return definition
}
