package sla

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestOverrideExtensionIsVersionedAuditedAndDoesNotDoubleCount(t *testing.T) {
	definition := mustMetricDefinition(t, elapsedMetricInput())
	instance := startedMetricInstance(t, definition)
	start := *instance.StartedAt()
	command := validOverrideCommand(instance, 110, OverrideExtend, start.Add(time.Hour))
	command.Extension = 2 * time.Hour
	authority := overrideAuthorityFixture(command)

	updated, record, changed, err := instance.ApplyOverride(instance.Version(), command, authority, nil, nil)
	if err != nil || !changed || record == nil {
		t.Fatalf("ApplyOverride() changed=%t record=%#v error=%v", changed, record, err)
	}
	if updated.EffectiveDuration() != 6*time.Hour || updated.Extension() != 2*time.Hour || updated.Consumed() != time.Hour {
		t.Fatalf("extended metric duration=%s extension=%s consumed=%s", updated.EffectiveDuration(), updated.Extension(), updated.Consumed())
	}
	if got, want := *updated.DueAt(), start.Add(6*time.Hour); !got.Equal(want) {
		t.Fatalf("extended due=%s, want %s", got, want)
	}
	evaluation, err := updated.Evaluate(start.Add(2*time.Hour), nil)
	if err != nil || evaluation.Remaining != 4*time.Hour {
		t.Fatalf("post-extension evaluation=%#v error=%v", evaluation, err)
	}
	if record.Previous().EffectiveDuration() != 4*time.Hour || record.Next().EffectiveDuration() != 6*time.Hour ||
		record.Reason() != command.Reason || record.AuthorityEpoch() != authority.PermissionEpoch {
		t.Fatalf("override audit record=%#v", record)
	}

	replayed, replayRecord, changed, err := updated.ApplyOverride(updated.Version(), command, authority, nil, nil)
	if err != nil || changed || replayRecord != nil || replayed.Version() != updated.Version() {
		t.Fatalf("override replay changed=%t record=%#v error=%v", changed, replayRecord, err)
	}
	aliased := command
	aliased.Reason = "different authority reason"
	if _, _, _, err := updated.ApplyOverride(updated.Version(), aliased, authority, nil, nil); !errors.Is(err, ErrInvalidOverride) {
		t.Fatalf("override id alias error=%v", err)
	}
}

func TestOverrideSuspendResumeAndManualCompletion(t *testing.T) {
	instance := startedMetricInstance(t, mustMetricDefinition(t, elapsedMetricInput()))
	start := *instance.StartedAt()
	suspend := validOverrideCommand(instance, 111, OverrideSuspend, start.Add(time.Hour))
	var err error
	instance, _, _, err = instance.ApplyOverride(instance.Version(), suspend, overrideAuthorityFixture(suspend), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	evaluation, err := instance.Evaluate(start.Add(24*time.Hour), nil)
	if err != nil || evaluation.State != StatePaused || evaluation.Remaining != 3*time.Hour {
		t.Fatalf("suspended evaluation=%#v error=%v", evaluation, err)
	}

	resume := validOverrideCommand(instance, 112, OverrideResume, start.Add(24*time.Hour))
	instance, _, _, err = instance.ApplyOverride(instance.Version(), resume, overrideAuthorityFixture(resume), nil, nil)
	if err != nil || instance.DueAt() == nil || !instance.DueAt().Equal(start.Add(27*time.Hour)) {
		t.Fatalf("resume due=%v error=%v", instance.DueAt(), err)
	}

	complete := validOverrideCommand(instance, 113, OverrideComplete, start.Add(25*time.Hour))
	instance, _, _, err = instance.ApplyOverride(instance.Version(), complete, overrideAuthorityFixture(complete), nil, nil)
	if err != nil || instance.CompletedAt() == nil || !instance.CompletedAt().Equal(complete.OccurredAt) {
		t.Fatalf("manual completion=%v error=%v", instance.CompletedAt(), err)
	}
}

func TestMetricLevelPolicyOverrideIsRejectedInFavorOfAggregatePlanner(t *testing.T) {
	instance := startedMetricInstance(t, mustMetricDefinition(t, elapsedMetricInput()))
	start := *instance.StartedAt()
	replacementInput := elapsedMetricInput()
	replacementInput.ID = fixtureID(120)
	replacementInput.Duration = 8 * time.Hour
	replacement := mustMetricDefinition(t, replacementInput)
	command := validOverrideCommand(instance, 114, OverrideChangePolicy, start.Add(time.Hour))
	command.NewPolicyID = fixtureID(121)
	command.NewPolicyVersion = 9
	command.NewMetric = &replacement
	command.SimulationDigest[0] = 1
	authority := overrideAuthorityFixture(command)
	if _, _, _, err := instance.ApplyOverride(
		instance.Version(), command, authority, nil, nil,
	); !errors.Is(err, ErrInvalidOverride) {
		t.Fatalf("metric-level policy override error=%v", err)
	}
}

func TestCalendarOverrideChangesOnlyExactTenantPinnedBusinessClock(t *testing.T) {
	current := mustCalendar(t, weekdayCalendarInput())
	metricInput := elapsedMetricInput()
	metricInput.Clock = ClockBusiness
	currentID := current.ID()
	metricInput.CalendarID, metricInput.CalendarVersion = &currentID, current.Version()
	metricInput.Duration = 2 * time.Hour
	definition := mustMetricDefinition(t, metricInput)
	created := time.Date(2026, 8, 28, 14, 0, 0, 0, time.UTC)
	instance, err := NewMetricInstance(MetricInstanceInput{
		ID: fixtureID(130), SLAInstanceID: fixtureID(133), TenantID: fixtureID(1), ObjectType: ObjectCase,
		ObjectID: fixtureID(131), PolicyID: fixtureID(132), PolicyVersion: 1,
		Definition: definition, CreatedAt: created,
	})
	if err != nil {
		t.Fatal(err)
	}
	start := metricEventForInstance(instance, 133, definition.StartEvent().String(), created)
	instance, _, err = instance.ApplyEvent(1, start, &current)
	if err != nil {
		t.Fatal(err)
	}
	replacementInput := allDayCalendarInput("Europe/Rome")
	replacementInput.ID = fixtureID(134)
	replacementInput.Version = 2
	replacement := mustCalendar(t, replacementInput)
	command := validOverrideCommand(instance, 135, OverrideChangeCalendar, created.Add(30*time.Minute))
	command.SimulationDigest[0] = 2
	updated, _, _, err := instance.ApplyOverride(
		instance.Version(), command, overrideAuthorityFixture(command), &current, &replacement,
	)
	if err != nil || updated.Definition().CalendarID() == nil || *updated.Definition().CalendarID() != replacement.ID() {
		t.Fatalf("calendar override definition=%#v error=%v", updated.Definition(), err)
	}
	if got, want := *updated.DueAt(), created.Add(2*time.Hour); !got.Equal(want) {
		t.Fatalf("replacement 24x7 due=%s, want %s", got, want)
	}
	sameCommand := command
	sameCommand.ID = fixtureID(138)
	sameAuthority := overrideAuthorityFixture(sameCommand)
	if _, _, _, err := instance.ApplyOverride(
		instance.Version(), sameCommand, sameAuthority, &current, &current,
	); !errors.Is(err, ErrInvalidOverride) {
		t.Fatalf("same pinned calendar override error=%v", err)
	}

	foreignInput := replacementInput
	foreignInput.ID, foreignInput.TenantID = fixtureID(136), fixtureID(2)
	foreign := mustCalendar(t, foreignInput)
	foreignCommand := command
	foreignCommand.ID = fixtureID(137)
	foreignAuthority := overrideAuthorityFixture(foreignCommand)
	if _, _, _, err := instance.ApplyOverride(instance.Version(), foreignCommand, foreignAuthority, &current, &foreign); !errors.Is(err, ErrInvalidOverride) {
		t.Fatalf("cross-tenant calendar override error=%v", err)
	}
}

func TestOverrideAuthorizationConflictAndFormattingFailClosed(t *testing.T) {
	instance := startedMetricInstance(t, mustMetricDefinition(t, elapsedMetricInput()))
	command := validOverrideCommand(instance, 140, OverrideExtend, instance.UpdatedAt().Add(time.Hour))
	command.Extension = time.Hour
	denied := overrideAuthorityFixture(command)
	denied.CanOverride = false
	if _, _, _, err := instance.ApplyOverride(instance.Version(), command, denied, nil, nil); !errors.Is(err, ErrOverrideDenied) {
		t.Fatalf("denied override error=%v", err)
	}
	command.Reason = ""
	if _, _, _, err := instance.ApplyOverride(0, command, denied, nil, nil); !errors.Is(err, ErrMetricConflict) {
		t.Fatalf("stale malformed override error=%v", err)
	}

	command = validOverrideCommand(instance, 141, OverrideExtend, instance.UpdatedAt().Add(time.Hour))
	command.Extension = time.Hour
	updated, record, _, err := instance.ApplyOverride(instance.Version(), command, overrideAuthorityFixture(command), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{fmt.Sprint(record), fmt.Sprintf("%#v", record), fmt.Sprint(updated)} {
		if strings.Contains(rendered, command.Reason) || strings.Contains(rendered, command.ActorID.String()) {
			t.Fatalf("override formatting leaked sensitive audit context: %q", rendered)
		}
	}
}

func validOverrideCommand(instance MetricInstance, sequence uint16, kind OverrideKind, at time.Time) OverrideCommand {
	return OverrideCommand{
		ID: fixtureID(sequence), TenantID: instance.TenantID(), ObjectID: instance.ObjectID(),
		ActorID: fixtureID(9), Kind: kind, Reason: "Approved customer-impact exception", OccurredAt: at,
	}
}

func overrideAuthorityFixture(command OverrideCommand) OverrideAuthority {
	return OverrideAuthority{
		TenantID: command.TenantID, ActorID: command.ActorID, CanOverride: true,
		PermissionEpoch: 7, SubjectEpoch: 11,
		EvaluatedAt: command.OccurredAt.Add(-time.Minute), ValidUntil: command.OccurredAt.Add(time.Minute),
	}
}
