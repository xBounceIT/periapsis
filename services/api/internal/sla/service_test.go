package sla

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/sla"
)

func TestPublishConfigurationRequiresLiveTenantManageAndBindsPayload(t *testing.T) {
	now := testNow()
	actor := operatorFixture()
	repository := newFakeRepository(now, actor)
	service := mustService(t, repository, now)
	ctx := deadlineContext(t, now)

	calendarInput := calendarInputFixture(10, actor.TenantID, 1)
	calendarResult, err := service.PublishCalendar(ctx, actor, actor.TenantID, CalendarPublishCommand{
		Input: calendarInput, ExpectedActiveVersion: 0, Envelope: envelopeFixture(),
	})
	if err != nil || calendarResult.Value.Version() != 1 || repository.calendarWrite.Command.RequestDigest == ([32]byte{}) {
		t.Fatalf("calendar result=%#v error=%v", calendarResult, err)
	}
	calendarDigest := repository.calendarWrite.Command.RequestDigest

	metric := metricFixture(t, 20, nil, 0, true)
	policyInput := policyInputFixture(t, 21, actor.TenantID, 1, metric)
	policyResult, err := service.PublishPolicy(ctx, actor, actor.TenantID, PolicyPublishCommand{
		Input: policyInput, ExpectedActiveVersion: 0, Envelope: envelopeFixture(),
	})
	if err != nil || policyResult.Value.Version() != 1 || repository.policyWrite.Command.RequestDigest == ([32]byte{}) {
		t.Fatalf("policy result=%#v error=%v", policyResult, err)
	}

	repository.metricDefinition = metric
	columnInput := columnInputFixture(22, actor.TenantID, metric, 1, true)
	columnResult, err := service.PublishColumn(ctx, actor, actor.TenantID, ColumnPublishCommand{
		Input: columnInput, ExpectedActiveVersion: 0, Envelope: envelopeFixture(),
	})
	if err != nil || columnResult.Value.Version() != 1 || repository.columnWrite.Command.RequestDigest == ([32]byte{}) {
		t.Fatalf("column result=%#v error=%v", columnResult, err)
	}

	changedCalendar := calendarInput
	changedCalendar.Version = 2
	changedCalendar.Label = "Changed support hours"
	_, err = service.PublishCalendar(ctx, actor, actor.TenantID, CalendarPublishCommand{
		Input: changedCalendar, ExpectedActiveVersion: 1, Envelope: envelopeFixture(),
	})
	if err != nil || repository.calendarWrite.Command.RequestDigest == calendarDigest {
		t.Fatalf("changed calendar digest was not payload-bound: %x error=%v", repository.calendarWrite.Command.RequestDigest, err)
	}

	repository.authority.Allowed = false
	before := repository.publishCalendarCalls
	_, err = service.PublishCalendar(ctx, actor, actor.TenantID, CalendarPublishCommand{
		Input: changedCalendar, ExpectedActiveVersion: 1, Envelope: envelopeFixture(),
	})
	if !errors.Is(err, ErrForbidden) || repository.publishCalendarCalls != before {
		t.Fatalf("denied publish calls=%d error=%v", repository.publishCalendarCalls-before, err)
	}

	if _, err := service.PublishCalendar(context.Background(), actor, actor.TenantID, CalendarPublishCommand{
		Input: calendarInput, Envelope: envelopeFixture(),
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing deadline error=%v", err)
	}
}

func TestPublishUsesTimeAfterAuthorityResolution(t *testing.T) {
	for _, test := range []struct {
		name                        string
		elapsed, evaluated, expires time.Duration
		allowed                     bool
	}{
		{"newly evaluated", 2 * time.Millisecond, time.Millisecond, time.Second, true},
		{"expired during resolution", 2 * time.Millisecond, -time.Second, time.Millisecond, false},
		{"future evaluation", time.Millisecond, 2 * time.Millisecond, time.Second, false},
		{"clock moved backwards", -time.Millisecond, -time.Second, time.Second, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			started := testNow()
			now := started
			actor := operatorFixture()
			repository := newFakeRepository(started, actor)
			repository.authority.EvaluatedAt = started.Add(test.evaluated)
			repository.authority.ValidUntil = started.Add(test.expires)
			repository.onResolve = func() { now = started.Add(test.elapsed) }
			service, err := NewService(repository, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			_, err = service.PublishCalendar(deadlineContext(t, started), actor, actor.TenantID, CalendarPublishCommand{
				Input: calendarInputFixture(10, actor.TenantID, 1), Envelope: envelopeFixture(),
			})
			if test.allowed {
				if err != nil || repository.publishCalendarCalls != 1 {
					t.Fatalf("publish calls=%d error=%v", repository.publishCalendarCalls, err)
				}
			} else if !errors.Is(err, ErrForbidden) || repository.publishCalendarCalls != 0 {
				t.Fatalf("invalid authority reached publication: calls=%d error=%v", repository.publishCalendarCalls, err)
			}
		})
	}
}

func TestServiceRejectsNilContextWithoutCallingRepository(t *testing.T) {
	now := testNow()
	actor := operatorFixture()
	repository := newFakeRepository(now, actor)
	service := mustService(t, repository, now)
	_, err := service.PublishCalendar(nil, actor, actor.TenantID, CalendarPublishCommand{})
	if !errors.Is(err, ErrInvalidInput) || repository.publishCalendarCalls != 0 {
		t.Fatalf("nil context calls=%d error=%v", repository.publishCalendarCalls, err)
	}
}

func TestArchiveConfigurationIsPayloadBoundAuthorizedAndVersionExact(t *testing.T) {
	now := testNow()
	actor := operatorFixture()
	repository := newFakeRepository(now, actor)
	service := mustService(t, repository, now)

	for index, kind := range []ArchiveKind{ArchiveCalendar, ArchivePolicy, ArchiveColumn} {
		command := ArchiveCommand{
			Kind: kind, ID: appEntity(uint16(100 + index)), ExpectedVersion: 3,
			Reason: "Retired configuration after approved replacement", Envelope: envelopeFixture(),
		}
		command.Envelope.IdempotencyKey = fmt.Sprintf("archive-key-%08d", index)
		version, replayed, err := service.Archive(deadlineContext(t, now), actor, actor.TenantID, command)
		if err != nil || replayed || version != 4 || repository.archiveWrite.Kind != kind ||
			repository.archiveWrite.ID != command.ID || repository.archiveWrite.Command.RequestDigest == ([32]byte{}) {
			t.Fatalf("archive kind=%s version=%d replayed=%t write=%#v error=%v", kind, version, replayed, repository.archiveWrite, err)
		}
	}

	repository.archiveVersion = 99
	command := ArchiveCommand{
		Kind: ArchivePolicy, ID: appEntity(110), ExpectedVersion: 3,
		Reason: "Retired configuration after approved replacement", Envelope: envelopeFixture(),
	}
	if _, _, err := service.Archive(
		deadlineContext(t, now), actor, actor.TenantID, command,
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("malformed archive version error=%v", err)
	}
	repository.archiveVersion = 0
	resource := Resource{ObjectType: kernel.ObjectCase, ObjectID: appEntity(111)}
	repository.authorityResourceOverride = &resource
	before := repository.archiveCalls
	if _, _, err := service.Archive(
		deadlineContext(t, now), actor, actor.TenantID, command,
	); !errors.Is(err, ErrForbidden) || repository.archiveCalls != before {
		t.Fatalf("resource-scoped manage archive calls=%d error=%v", repository.archiveCalls-before, err)
	}
}

func TestConfigurationReadsRequireTenantReadAndRejectMalformedPages(t *testing.T) {
	now := testNow()
	actor := operatorFixture()
	repository := newFakeRepository(now, actor)
	service := mustService(t, repository, now)
	calendarInput := calendarInputFixture(12, actor.TenantID, 1)
	calendarInput.Key = appKey("alpha_hours")
	alpha := mustCalendar(t, calendarInput)
	calendarInput = calendarInputFixture(13, actor.TenantID, 1)
	calendarInput.Key = appKey("beta_hours")
	beta := mustCalendar(t, calendarInput)
	repository.calendarPage = CalendarPage{
		Items: []CalendarRecord{
			{Value: alpha, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now},
			{Value: beta, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now},
		},
		NextCursor: EncodeConfigurationCursor(beta.Key(), beta.ID()),
	}
	repository.calendarRecord = repository.calendarPage.Items[0]
	page, err := service.ListCalendars(deadlineContext(t, now), actor, actor.TenantID, ConfigurationListInput{})
	if err != nil || len(page.Items) != 2 || page.NextCursor != repository.calendarPage.NextCursor {
		t.Fatalf("calendar page=%#v error=%v", page, err)
	}
	record, err := service.GetCalendar(deadlineContext(t, now), actor, actor.TenantID, alpha.ID())
	if err != nil || record.Value.ID() != alpha.ID() || StrongConfigurationETag(
		ArchiveCalendar, record.Value.ID(), record.ResourceVersion,
	) == "" {
		t.Fatalf("calendar record=%#v error=%v", record, err)
	}
	metric := metricFixture(t, 14, nil, 0, true)
	policy := mustPolicy(t, policyInputFixture(t, 15, actor.TenantID, 1, metric))
	repository.policyPage = PolicyPage{Items: []PolicyRecord{{Value: policy, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}}}
	repository.policyRecord = repository.policyPage.Items[0]
	if page, err := service.ListPolicies(
		deadlineContext(t, now), actor, actor.TenantID, ConfigurationListInput{},
	); err != nil || len(page.Items) != 1 {
		t.Fatalf("policy page=%#v error=%v", page, err)
	}
	if record, err := service.GetPolicy(
		deadlineContext(t, now), actor, actor.TenantID, policy.ID(),
	); err != nil || record.Value.ID() != policy.ID() {
		t.Fatalf("policy record=%#v error=%v", record, err)
	}
	column, err := kernel.NewColumnDefinition(metric, columnInputFixture(16, actor.TenantID, metric, 1, true))
	if err != nil {
		t.Fatal(err)
	}
	repository.columnPage = ColumnPage{Items: []ColumnRecord{{Value: column, ResourceVersion: 1, CreatedAt: now, UpdatedAt: now}}}
	repository.columnRecord = repository.columnPage.Items[0]
	if page, err := service.ListColumns(
		deadlineContext(t, now), actor, actor.TenantID, ConfigurationListInput{},
	); err != nil || len(page.Items) != 1 {
		t.Fatalf("column page=%#v error=%v", page, err)
	}
	if record, err := service.GetColumn(
		deadlineContext(t, now), actor, actor.TenantID, column.ID(),
	); err != nil || record.Value.ID() != column.ID() {
		t.Fatalf("column record=%#v error=%v", record, err)
	}

	repository.calendarPage.Items[0], repository.calendarPage.Items[1] =
		repository.calendarPage.Items[1], repository.calendarPage.Items[0]
	if _, err := service.ListCalendars(
		deadlineContext(t, now), actor, actor.TenantID, ConfigurationListInput{},
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unordered page error=%v", err)
	}
	if _, err := service.ListCalendars(
		deadlineContext(t, now), actor, actor.TenantID, ConfigurationListInput{After: "***"},
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("malformed cursor error=%v", err)
	}

	customer := customerFixture(actor.TenantID)
	if _, err := service.GetCalendar(
		deadlineContext(t, now), customer, actor.TenantID, alpha.ID(),
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("customer configuration read error=%v", err)
	}
}

func TestConfigurationCursorIsCanonicalAndTupleBound(t *testing.T) {
	t.Parallel()

	key, err := kernel.NewKey("response-time")
	if err != nil {
		t.Fatal(err)
	}
	id := appEntity(141)
	encoded := EncodeConfigurationCursor(key, id)
	decodedKey, decodedID, err := DecodeConfigurationCursor(encoded)
	if err != nil || decodedKey != key || decodedID != id {
		t.Fatalf("DecodeConfigurationCursor() = %q, %s, %v", decodedKey.String(), decodedID.String(), err)
	}
	wrongVersionPayload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	wrongVersionPayload[0] = 2
	wrongVersion := base64.RawURLEncoding.EncodeToString(wrongVersionPayload)
	for _, malformed := range []string{"", encoded + "=", "AQNhYmM", wrongVersion} {
		if _, _, err := DecodeConfigurationCursor(malformed); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("DecodeConfigurationCursor(%q) error = %v", malformed, err)
		}
	}
}

func TestStrongSLAETagsAreResourceBoundCanonicalAndVersionRecoverable(t *testing.T) {
	id := appEntity(240)
	configuration := StrongConfigurationETag(ArchivePolicy, id, 17)
	if version, err := ParseStrongConfigurationETag(configuration, ArchivePolicy, id); err != nil || version != 17 {
		t.Fatalf("configuration version=%d error=%v etag=%q", version, err, configuration)
	}
	object := StrongObjectSLAETag(id, 19)
	if version, err := ParseStrongObjectSLAETag(object, id); err != nil || version != 19 {
		t.Fatalf("object version=%d error=%v etag=%q", version, err, object)
	}
	for _, invalid := range []string{
		configuration + "," + configuration,
		"W/" + configuration,
		"*",
		strings.Replace(configuration, "-v17", "-v017", 1),
		StrongConfigurationETag(ArchiveCalendar, id, 17),
		StrongConfigurationETag(ArchivePolicy, appEntity(241), 17),
	} {
		if _, err := ParseStrongConfigurationETag(invalid, ArchivePolicy, id); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("configuration validator %q error=%v", invalid, err)
		}
	}
	if _, err := ParseStrongObjectSLAETag(StrongObjectSLAETag(appEntity(241), 19), id); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("cross-instance object validator error=%v", err)
	}
}

func TestConfigurationKeyMatchesCanonicalDatabaseShape(t *testing.T) {
	for _, valid := range []string{"ab", "a1", "a_b", "a.b", "a-b", strings.Repeat("a", 64)} {
		if _, err := kernel.NewKey(valid); err != nil {
			t.Fatalf("valid key %q: %v", valid, err)
		}
	}
	for _, invalid := range []string{"a", "A_key", "1key", "a-", "a/b", strings.Repeat("a", 65)} {
		if _, err := kernel.NewKey(invalid); err == nil {
			t.Fatalf("invalid key %q accepted", invalid)
		}
	}
}

func TestPolicyPublicationRejectsMissingOrForeignCalendarPins(t *testing.T) {
	now := testNow()
	actor := operatorFixture()
	repository := newFakeRepository(now, actor)
	service := mustService(t, repository, now)
	calendar := mustCalendar(t, calendarInputFixture(30, actor.TenantID, 3))
	calendarID := calendar.ID()
	metric := metricFixture(t, 31, &calendarID, calendar.Version(), true)
	command := PolicyPublishCommand{
		Input:    policyInputFixture(t, 32, actor.TenantID, 1, metric),
		Envelope: envelopeFixture(),
	}

	if _, err := service.PublishPolicy(deadlineContext(t, now), actor, actor.TenantID, command); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing calendar error=%v", err)
	}
	foreignInput := calendar.Input()
	foreignInput.TenantID = appEntity(999)
	repository.policyCalendars = []kernel.BusinessCalendar{mustCalendar(t, foreignInput)}
	if _, err := service.PublishPolicy(deadlineContext(t, now), actor, actor.TenantID, command); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("foreign calendar error=%v", err)
	}
	repository.policyCalendars = []kernel.BusinessCalendar{calendar}
	if _, err := service.PublishPolicy(deadlineContext(t, now), actor, actor.TenantID, command); err != nil {
		t.Fatalf("valid calendar publication error=%v", err)
	}
}

func TestSimulationAndCustomerProjectionUsePublishedInputsAndHideInternalPause(t *testing.T) {
	now := testNow()
	actor := operatorFixture()
	repository := newFakeRepository(now, actor)
	service := mustService(t, repository, now)
	metric := metricFixture(t, 40, nil, 0, true)
	policy := mustPolicy(t, policyInputFixture(t, 41, actor.TenantID, 1, metric))
	repository.simulationPolicy = policy

	snapshot, err := kernel.NewFactSnapshot(kernel.FactSnapshotInput{
		TenantID: appEntityFromUUID(actor.TenantID), ObjectType: kernel.ObjectCase,
		EvaluatedAt: now, Timezone: "UTC",
	})
	if err != nil {
		t.Fatal(err)
	}
	simulation, err := service.Simulate(deadlineContext(t, now), actor, actor.TenantID, SimulationCommand{
		PolicyID: policy.ID(), PolicyVersion: policy.Version(), Snapshot: snapshot,
		SLAInstanceID: appEntity(41), ObjectID: appEntity(42), CreatedAt: now, EvaluateAt: now,
		Bindings: []kernel.SimulationMetricBinding{{MetricID: metric.ID(), InstanceID: appEntity(43)}},
	})
	if err != nil || simulation.Digest == ([32]byte{}) || simulation.Digest != simulation.Result.Digest() {
		t.Fatalf("simulation=%#v error=%v", simulation, err)
	}

	createdAt := now.Add(-2 * time.Hour)
	instance := mustInstance(t, actor.TenantID, 44, 45, policy, metric, createdAt)
	started, _, err := instance.ApplyEvent(instance.Version(), metricEvent(instance, 46, metric.StartEvent(), createdAt), nil)
	if err != nil {
		t.Fatal(err)
	}
	pausedAt := createdAt.Add(time.Hour)
	paused, _, err := started.ApplyEvent(started.Version(), metricEvent(started, 47, metric.PauseEvent(), pausedAt), nil)
	if err != nil {
		t.Fatal(err)
	}
	column, err := kernel.NewColumnDefinition(metric, columnInputFixture(48, actor.TenantID, metric, 1, true))
	if err != nil {
		t.Fatal(err)
	}
	repository.objectProjection = ObjectProjectionState{
		SLAInstanceID: paused.SLAInstanceID(), AggregateVersion: 1,
		PolicyID: policy.ID(), PolicyVersion: policy.Version(),
		Metrics: []kernel.MetricWork{{Instance: paused, Columns: []kernel.ColumnDefinition{column}}},
	}

	customer := customerFixture(actor.TenantID)
	repository.authority = authorityFixture(now, customer, CapabilityPortalCaseRead, ScopeOwn, AudienceCustomer)
	projection, err := service.ProjectObject(deadlineContext(t, now), customer, actor.TenantID, ObjectProjectionCommand{
		ObjectType: kernel.ObjectCase, ObjectID: paused.ObjectID(), At: now,
	})
	if err != nil || len(projection.Metrics) != 1 || len(projection.Columns) != 1 {
		t.Fatalf("customer projection=%#v error=%v", projection, err)
	}
	if StrongObjectSLAETag(projection.SLAInstanceID, projection.AggregateVersion) == "" {
		t.Fatal("customer projection did not produce a strong aggregate ETag")
	}
	if projection.Metrics[0].State == kernel.StatePaused || projection.Metrics[0].PausedAt != nil ||
		projection.Columns[0].State == kernel.StatePaused || projection.Columns[0].StyleKey.String() != "" {
		t.Fatalf("customer projection leaked pause internals: %#v", projection)
	}
	foreignResource := Resource{ObjectType: kernel.ObjectCase, ObjectID: appEntity(999)}
	repository.authorityResourceOverride = &foreignResource
	if _, err := service.ProjectObject(deadlineContext(t, now), customer, actor.TenantID, ObjectProjectionCommand{
		ObjectType: kernel.ObjectCase, ObjectID: paused.ObjectID(), At: now,
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("foreign authority resource error=%v", err)
	}
	repository.authorityResourceOverride = nil
	repository.authority.Scope = ScopeTenant
	if _, err := service.ProjectObject(deadlineContext(t, now), customer, actor.TenantID, ObjectProjectionCommand{
		ObjectType: kernel.ObjectCase, ObjectID: paused.ObjectID(), At: now,
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("customer tenant-scope authority error=%v", err)
	}

	repository.authority = authorityFixture(now, actor, CapabilityCaseRead, ScopeTenant, AudienceOperator)
	operatorProjection, err := service.ProjectObject(deadlineContext(t, now), actor, actor.TenantID, ObjectProjectionCommand{
		ObjectType: kernel.ObjectCase, ObjectID: paused.ObjectID(), At: now,
	})
	if err != nil || operatorProjection.Metrics[0].State != kernel.StatePaused ||
		operatorProjection.Metrics[0].PausedAt == nil {
		t.Fatalf("operator projection=%#v error=%v", operatorProjection, err)
	}
	duplicateInput := column.Input()
	duplicateInput.ID = appEntity(49)
	duplicate, err := kernel.NewColumnDefinition(metric, duplicateInput)
	if err != nil {
		t.Fatal(err)
	}
	repository.objectProjection.Metrics[0].Columns = append(
		repository.objectProjection.Metrics[0].Columns, duplicate,
	)
	if _, err := service.ProjectObject(deadlineContext(t, now), actor, actor.TenantID, ObjectProjectionCommand{
		ObjectType: kernel.ObjectCase, ObjectID: paused.ObjectID(), At: now,
	}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("duplicate column key projection error=%v", err)
	}
}

func TestProjectObjectNeverFallsBackAcrossRouteAudiencesAndRechecksRevocation(t *testing.T) {
	now := testNow()
	operator := operatorFixture()
	repository := newFakeRepository(now, operator)
	service := mustService(t, repository, now)
	command := ObjectProjectionCommand{ObjectType: kernel.ObjectCase, ObjectID: appEntity(901), At: now}

	repository.authority = authorityFixture(now, operator, CapabilityCaseRead, ScopeOwn, AudienceCustomer)
	if _, err := service.ProjectObject(deadlineContext(t, now), operator, operator.TenantID, command); !errors.Is(err, ErrForbidden) {
		t.Fatalf("operator route accepted customer authority: %v", err)
	}
	if repository.objectProjectionCalls != 0 {
		t.Fatalf("operator route loaded after audience mismatch: %d", repository.objectProjectionCalls)
	}

	customer := customerFixture(operator.TenantID)
	repository.authority = authorityFixture(now, customer, CapabilityPortalCaseRead, ScopeOwn, AudienceOperator)
	if _, err := service.ProjectObject(deadlineContext(t, now), customer, operator.TenantID, command); !errors.Is(err, ErrForbidden) {
		t.Fatalf("customer route accepted operator authority: %v", err)
	}
	if repository.objectProjectionCalls != 0 {
		t.Fatalf("customer route loaded after audience mismatch: %d", repository.objectProjectionCalls)
	}

	repository.authority = authorityFixture(now, customer, CapabilityPortalCaseRead, ScopeOwn, AudienceCustomer)
	repository.resolveErr = ErrRepositoryForbidden
	if _, err := service.ProjectObject(deadlineContext(t, now), customer, operator.TenantID, command); !errors.Is(err, ErrForbidden) {
		t.Fatalf("customer route did not fail closed after permission revocation: %v", err)
	}
	if repository.objectProjectionCalls != 0 {
		t.Fatalf("permission-revoked customer loaded a resource: %d", repository.objectProjectionCalls)
	}
	repository.resolveErr = nil
	repository.writeErr = ErrRepositoryForbidden
	if _, err := service.ProjectObject(deadlineContext(t, now), customer, operator.TenantID, command); !errors.Is(err, ErrForbidden) {
		t.Fatalf("customer route did not fail closed after live revocation: %v", err)
	}
	if repository.objectProjectionCalls != 1 {
		t.Fatalf("revocation recheck calls = %d, want 1", repository.objectProjectionCalls)
	}
}

func TestProjectObjectAllowsEmptyCustomerVisibleInventoryOnlyForCustomer(t *testing.T) {
	now := testNow()
	operator := operatorFixture()
	repository := newFakeRepository(now, operator)
	service := mustService(t, repository, now)
	objectID := appEntity(902)
	repository.objectProjection = ObjectProjectionState{
		SLAInstanceID: appEntity(903), AggregateVersion: 1,
		PolicyID: appEntity(904), PolicyVersion: 1,
	}

	customer := customerFixture(operator.TenantID)
	repository.authority = authorityFixture(now, customer, CapabilityPortalCaseRead, ScopeOwn, AudienceCustomer)
	projection, err := service.ProjectObject(deadlineContext(t, now), customer, operator.TenantID, ObjectProjectionCommand{
		ObjectType: kernel.ObjectCase, ObjectID: objectID, At: now,
	})
	if err != nil || len(projection.Metrics) != 0 || len(projection.Columns) != 0 ||
		projection.Audience != AudienceCustomer {
		t.Fatalf("empty customer projection=%#v error=%v", projection, err)
	}

	repository.authority = authorityFixture(now, operator, CapabilityCaseRead, ScopeOwn, AudienceOperator)
	if _, err := service.ProjectObject(deadlineContext(t, now), operator, operator.TenantID, ObjectProjectionCommand{
		ObjectType: kernel.ObjectCase, ObjectID: objectID, At: now,
	}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("empty operator projection error=%v, want unavailable", err)
	}
}

func TestProcessEventUsesAtomicPlannerAndPayloadBoundReplay(t *testing.T) {
	now := testNow()
	actor := operatorFixture()
	repository := newFakeRepository(now, actor)
	service := mustService(t, repository, now)
	metric := metricFixture(t, 50, nil, 0, true)
	policy := mustPolicy(t, policyInputFixture(t, 51, actor.TenantID, 1, metric))
	instance := mustInstance(t, actor.TenantID, 52, 53, policy, metric, now)
	event := metricEvent(instance, 54, metric.StartEvent(), now)
	repository.eventState = EventState{
		Mode: EventStateExisting, AggregateVersion: 1, Metrics: []kernel.MetricWork{{Instance: instance}},
	}
	command := EventCommand{
		Actor:      actor,
		ObjectType: kernel.ObjectCase, Event: event, Origin: "ticket.transition",
		OriginID: appEntity(55), Envelope: envelopeFixture(),
	}
	result, err := service.ProcessEvent(deadlineContext(t, now), actor.TenantID, command)
	if err != nil || result.Replayed || result.Receipt.Outcome != EventOutcomeUpdated ||
		result.Receipt.AggregateVersion != 2 || repository.eventPlan.Engine == nil ||
		!repository.eventPlan.Engine.Metrics()[0].Changed() ||
		repository.eventPlan.Engine.Metrics()[0].Instance().Version() != 2 {
		t.Fatalf("event result=%#v error=%v", result, err)
	}
	for _, rendered := range []string{fmt.Sprint(result.Receipt), fmt.Sprintf("%#v", result.Receipt)} {
		if strings.Contains(rendered, command.Event.ID.String()) || strings.Contains(rendered, command.Event.ObjectID.String()) {
			t.Fatalf("event receipt formatter leaked identity: %q", rendered)
		}
	}
	for _, value := range []any{repository.eventTransaction, repository.eventState} {
		for _, rendered := range []string{fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value)} {
			for _, secret := range []string{
				command.Event.ID.String(), command.Event.ObjectID.String(), command.OriginID.String(),
				fmt.Sprintf("%x", repository.eventTransaction.Binding.KeyDigest),
				fmt.Sprintf("%x", repository.eventTransaction.Binding.RequestDigest),
			} {
				if strings.Contains(rendered, secret) {
					t.Fatalf("event repository formatter leaked %q: %q", secret, rendered)
				}
			}
		}
	}
	firstDigest := repository.eventTransaction.Binding.RequestDigest
	firstPlanCalls := repository.eventPlanCalls
	replay, err := service.ProcessEvent(deadlineContext(t, now), actor.TenantID, command)
	if err != nil || !replay.Replayed || replay.Receipt != result.Receipt ||
		repository.eventPlanCalls != firstPlanCalls {
		t.Fatalf("event replay=%#v planner calls=%d error=%v", replay, repository.eventPlanCalls, err)
	}

	changed := command
	changed.Event.Key = metric.CompletionEvent()
	if _, err := service.ProcessEvent(deadlineContext(t, now), actor.TenantID, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("payload-mismatched replay error=%v", err)
	}
	if repository.eventTransaction.Binding.RequestDigest == firstDigest {
		t.Fatal("different event payload reused request digest")
	}

	foreign := result
	foreign.Receipt.TenantID = appUUID(999)
	foreign.Replayed = true
	repository.eventResult = &foreign
	if _, err := service.ProcessEvent(deadlineContext(t, now), actor.TenantID, command); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("foreign receipt error=%v", err)
	}
	repository.eventResult = nil
	repository.eventState.AggregateVersion = uint64(math.MaxInt64 - 1)
	exhausted := command
	exhausted.Envelope.IdempotencyKey = "request-key-00000003"
	if _, err := service.ProcessEvent(
		deadlineContext(t, now), actor.TenantID, exhausted,
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("aggregate version exhaustion error=%v", err)
	}
}

func TestProcessEventAtomicallyAssignsOrRecordsNoPolicy(t *testing.T) {
	now := testNow()
	actor := operatorFixture()
	repository := newFakeRepository(now, actor)
	service := mustService(t, repository, now)
	metric := metricFixture(t, 70, nil, 0, true)
	policy := mustPolicy(t, policyInputFixture(t, 71, actor.TenantID, 1, metric))
	objectID := appEntity(72)
	event := kernel.MetricEvent{
		ID: appEntity(73), TenantID: appEntityFromUUID(actor.TenantID), ObjectID: objectID,
		Key: metric.StartEvent(), OccurredAt: now,
	}
	snapshot, err := kernel.NewFactSnapshot(kernel.FactSnapshotInput{
		TenantID: appEntityFromUUID(actor.TenantID), ObjectType: kernel.ObjectCase,
		EvaluatedAt: now, Timezone: "UTC",
	})
	if err != nil {
		t.Fatal(err)
	}
	repository.eventState = EventState{
		Mode: EventStateUnassigned, Snapshot: &snapshot, Policies: []kernel.Policy{policy},
	}
	command := EventCommand{
		Actor:      actor,
		ObjectType: kernel.ObjectCase, Event: event, Origin: "ticket.created",
		OriginID: appEntity(74), Envelope: envelopeFixture(),
	}
	result, err := service.ProcessEvent(deadlineContext(t, now), actor.TenantID, command)
	plan := repository.eventPlan
	if err != nil || result.Receipt.Outcome != EventOutcomeAssigned || result.Receipt.AggregateVersion != 1 ||
		plan.Assignment == nil || !plan.Assignment.Matched() || plan.Engine == nil ||
		!plan.Engine.Metrics()[0].Changed() ||
		plan.Engine.Metrics()[0].Instance().SLAInstanceID() != plan.Assignment.SLAInstanceID() {
		t.Fatalf("assigned event=%#v error=%v", result, err)
	}
	firstAggregate := *result.Receipt.SLAInstanceID
	firstPlanCalls := repository.eventPlanCalls
	replay, err := service.ProcessEvent(deadlineContext(t, now), actor.TenantID, command)
	if err != nil || !replay.Replayed || *replay.Receipt.SLAInstanceID != firstAggregate ||
		repository.eventPlanCalls != firstPlanCalls {
		t.Fatalf("assignment replay=%#v error=%v", replay, err)
	}

	disabledInput := policyInputFixture(t, 75, actor.TenantID, 1, metric)
	disabledInput.Enabled = false
	disabled := mustPolicy(t, disabledInput)
	repository.eventState = EventState{
		Mode: EventStateUnassigned, Snapshot: &snapshot, Policies: []kernel.Policy{disabled},
	}
	noPolicyCommand := command
	noPolicyCommand.Envelope.IdempotencyKey = "request-key-00000002"
	noPolicy, err := service.ProcessEvent(deadlineContext(t, now), actor.TenantID, noPolicyCommand)
	if err != nil || noPolicy.Receipt.Outcome != EventOutcomeNoPolicy || noPolicy.Receipt.SLAInstanceID != nil ||
		repository.eventPlan.Assignment == nil || repository.eventPlan.Assignment.Matched() ||
		repository.eventPlan.Engine != nil {
		t.Fatalf("no-policy event=%#v error=%v", noPolicy, err)
	}
}

func TestFreshEventReceiptMustExactlyRepresentTheExecutedPlan(t *testing.T) {
	now := testNow()
	actor := operatorFixture()
	repository := newFakeRepository(now, actor)
	service := mustService(t, repository, now)
	metric := metricFixture(t, 76, nil, 0, true)
	policy := mustPolicy(t, policyInputFixture(t, 77, actor.TenantID, 1, metric))
	instance := mustInstance(t, actor.TenantID, 78, 79, policy, metric, now)
	repository.eventState = EventState{
		Mode: EventStateExisting, AggregateVersion: 7, Metrics: []kernel.MetricWork{{Instance: instance}},
	}
	command := EventCommand{
		Actor:      actor,
		ObjectType: kernel.ObjectCase, Event: metricEvent(instance, 80, metric.StartEvent(), now),
		Origin: "ticket.transition", OriginID: appEntity(81), Envelope: envelopeFixture(),
	}
	repository.eventReceiptMutator = func(receipt *EventReceipt) { receipt.AggregateVersion++ }
	if _, err := service.ProcessEvent(deadlineContext(t, now), actor.TenantID, command); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("tampered fresh event receipt error=%v", err)
	}
	if repository.eventPlanCalls != 1 {
		t.Fatalf("fresh event planner calls=%d, want 1", repository.eventPlanCalls)
	}

	repository.eventReceiptMutator = nil
	repository.eventReceipts = nil
	repository.eventResult = &EventResult{}
	if _, err := service.ProcessEvent(deadlineContext(t, now), actor.TenantID, command); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("fresh result without planner error=%v", err)
	}
}

func TestOverrideRechecksResourceAuthorityAndSimulationDigestInTransaction(t *testing.T) {
	now := testNow()
	actor := operatorFixture()
	repository := newFakeRepository(now, actor)
	service := mustService(t, repository, now)
	metric := metricFixture(t, 60, nil, 0, true)
	policy := mustPolicy(t, policyInputFixture(t, 61, actor.TenantID, 1, metric))
	instance := mustInstance(t, actor.TenantID, 62, 63, policy, metric, now.Add(-time.Hour))
	instance, _, _ = instance.ApplyEvent(instance.Version(), metricEvent(instance, 64, metric.StartEvent(), now.Add(-time.Hour)), nil)
	repository.authority = authorityFixture(now, actor, CapabilityCaseOverride, ScopeAssigned, AudienceOperator)
	repository.overrideState = OverrideState{
		Metric: metricWorkPointer(instance), Metrics: []kernel.MetricWork{{Instance: instance}},
		AggregateVersion: 10, OccurredAt: now,
	}
	request := OverrideRequest{
		ObjectType: kernel.ObjectCase, ObjectID: instance.ObjectID(), SLAInstanceID: instance.SLAInstanceID(),
		MetricInstanceID: instance.ID(), ExpectedMetricVersion: instance.Version(),
		ExpectedAggregateVersion: 10,
		Intent:                   OverrideIntent{ID: appEntity(65), Kind: kernel.OverrideExtend, Reason: "Approved incident exception", Extension: time.Hour},
		Envelope:                 envelopeFixture(),
	}
	result, err := service.Override(deadlineContext(t, now), actor, actor.TenantID, request)
	if err != nil || result.Replayed || result.Receipt.Outcome != OverrideOutcomeMetricUpdated ||
		result.Receipt.CurrentVersion != instance.Version()+1 || result.Receipt.AggregateVersion != 11 ||
		repository.overridePlan.Record == nil || repository.overridePlan.Instance.Version() != instance.Version()+1 ||
		repository.overridePlan.Materialization == nil || len(repository.overridePlan.Materialization.Metrics()) != 1 {
		t.Fatalf("override result=%#v error=%v", result, err)
	}
	if result.Receipt.PermissionEpoch != repository.authority.PermissionEpoch ||
		result.Receipt.SubjectEpoch != repository.authority.SubjectEpoch ||
		repository.overridePlan.Record.AuthorityEpoch() != repository.authority.PermissionEpoch ||
		repository.overridePlan.Record.SubjectEpoch() != repository.authority.SubjectEpoch {
		t.Fatalf("override authority epochs=%#v", result.Receipt)
	}
	for _, rendered := range []string{fmt.Sprint(result.Receipt), fmt.Sprintf("%#v", result.Receipt)} {
		if strings.Contains(rendered, request.Intent.ID.String()) || strings.Contains(rendered, request.ObjectID.String()) ||
			strings.Contains(rendered, result.Receipt.ActorID.String()) {
			t.Fatalf("override receipt formatter leaked identity: %q", rendered)
		}
	}
	for _, value := range []any{repository.overrideTransaction, repository.overrideState} {
		for _, rendered := range []string{fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value)} {
			for _, secret := range []string{
				request.Intent.ID.String(), request.ObjectID.String(), request.MetricInstanceID.String(),
				fmt.Sprintf("%x", repository.overrideTransaction.Binding.KeyDigest),
				fmt.Sprintf("%x", repository.overrideTransaction.Binding.RequestDigest),
			} {
				if strings.Contains(rendered, secret) {
					t.Fatalf("override repository formatter leaked %q: %q", secret, rendered)
				}
			}
		}
	}
	firstPlanCalls := repository.overridePlanCalls
	replay, err := service.Override(deadlineContext(t, now), actor, actor.TenantID, request)
	if err != nil || !replay.Replayed || replay.Receipt.Command != result.Receipt.Command ||
		replay.Receipt.OverrideID != result.Receipt.OverrideID || repository.overridePlanCalls != firstPlanCalls {
		t.Fatalf("override replay=%#v planner calls=%d error=%v", replay, repository.overridePlanCalls, err)
	}
	malformedReplay := result
	malformedReplay.Receipt.Command.RequestDigest[0] ^= 0xff
	malformedReplay.Replayed = true
	repository.overrideResult = &malformedReplay
	if _, err := service.Override(deadlineContext(t, now), actor, actor.TenantID, request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unbound override replay error=%v", err)
	}
	repository.overrideResult = nil
	if _, err := service.Override(
		deadlineContext(t, now), customerFixture(actor.TenantID), actor.TenantID, request,
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("customer override error=%v", err)
	}

	digest := [32]byte{1}
	recalculate := request
	recalculate.ExpectedMetricVersion = instance.Version()
	recalculate.ExpectedAggregateVersion = 11
	recalculate.Intent = OverrideIntent{
		ID: appEntity(66), Kind: kernel.OverrideRecalculate, Reason: "Recalculate after approved correction",
		SimulationDigest: digest,
	}
	recalculate.Envelope.IdempotencyKey = "request-key-00000002"
	repository.overrideState = OverrideState{
		Metric: metricWorkPointer(instance), Metrics: []kernel.MetricWork{{Instance: instance}},
		AggregateVersion: 11, OccurredAt: now, SimulationDigest: [32]byte{2},
	}
	if _, err := service.Override(deadlineContext(t, now), actor, actor.TenantID, recalculate); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("simulation mismatch error=%v", err)
	}

	repository.authority.Allowed = false
	before := repository.overrideCalls
	if _, err := service.Override(deadlineContext(t, now), actor, actor.TenantID, request); !errors.Is(err, ErrForbidden) ||
		repository.overrideCalls != before {
		t.Fatalf("denied override calls=%d error=%v", repository.overrideCalls-before, err)
	}
	for _, rendered := range []string{fmt.Sprint(request), fmt.Sprintf("%#v", request.Intent)} {
		if strings.Contains(rendered, request.Intent.Reason) || strings.Contains(rendered, request.ObjectID.String()) {
			t.Fatalf("override formatter leaked sensitive data: %q", rendered)
		}
	}
}

func TestFreshOverrideReceiptMustExactlyRepresentTheExecutedPlan(t *testing.T) {
	now := testNow()
	actor := operatorFixture()
	repository := newFakeRepository(now, actor)
	service := mustService(t, repository, now)
	metric := metricFixture(t, 67, nil, 0, true)
	policy := mustPolicy(t, policyInputFixture(t, 68, actor.TenantID, 1, metric))
	instance := mustInstance(t, actor.TenantID, 69, 70, policy, metric, now.Add(-time.Hour))
	instance, _, _ = instance.ApplyEvent(
		instance.Version(), metricEvent(instance, 71, metric.StartEvent(), now.Add(-time.Hour)), nil,
	)
	repository.authority = authorityFixture(now, actor, CapabilityCaseOverride, ScopeAssigned, AudienceOperator)
	repository.overrideState = OverrideState{
		Metric: metricWorkPointer(instance), Metrics: []kernel.MetricWork{{Instance: instance}},
		AggregateVersion: 10, OccurredAt: now,
	}
	repository.overrideReceiptMutator = func(receipt *OverrideReceipt) { receipt.AggregateVersion++ }
	request := OverrideRequest{
		ObjectType: kernel.ObjectCase, ObjectID: instance.ObjectID(), SLAInstanceID: instance.SLAInstanceID(),
		MetricInstanceID: instance.ID(), ExpectedMetricVersion: instance.Version(), ExpectedAggregateVersion: 10,
		Intent: OverrideIntent{
			ID: appEntity(72), Kind: kernel.OverrideExtend,
			Reason: "Approved incident exception", Extension: time.Hour,
		},
		Envelope: envelopeFixture(),
	}
	if _, err := service.Override(deadlineContext(t, now), actor, actor.TenantID, request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("tampered fresh override receipt error=%v", err)
	}
	if repository.overridePlanCalls != 1 {
		t.Fatalf("fresh override planner calls=%d, want 1", repository.overridePlanCalls)
	}
}

func TestPolicyOverrideReplacesWholeAggregateUnderOnePrecondition(t *testing.T) {
	now := testNow()
	actor := operatorFixture()
	repository := newFakeRepository(now, actor)
	service := mustService(t, repository, now)
	first := metricFixture(t, 80, nil, 0, true)
	secondInput := first.Input()
	secondInput.ID = appEntity(81)
	secondInput.Key = appKey("resolution")
	secondInput.Label = "Resolution"
	secondInput.CompletionEvent = appKey("ticket.resolved")
	second, err := kernel.NewMetricDefinition(secondInput)
	if err != nil {
		t.Fatal(err)
	}
	currentInput := policyInputFixture(t, 82, actor.TenantID, 1, first)
	currentInput.Metrics = []kernel.MetricDefinition{first, second}
	current := mustPolicy(t, currentInput)
	createdAt := now.Add(-time.Hour)
	firstInstance := mustInstance(t, actor.TenantID, 83, 84, current, first, createdAt)
	secondInstance, err := kernel.NewMetricInstance(kernel.MetricInstanceInput{
		ID: appEntity(85), SLAInstanceID: firstInstance.SLAInstanceID(),
		TenantID: firstInstance.TenantID(), ObjectType: firstInstance.ObjectType(), ObjectID: firstInstance.ObjectID(),
		PolicyID: current.ID(), PolicyVersion: current.Version(), Definition: second, CreatedAt: createdAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	startEvent := func(instance kernel.MetricInstance, sequence uint16) kernel.MetricInstance {
		started, changed, startErr := instance.ApplyEvent(instance.Version(), metricEvent(
			instance, sequence, instance.Definition().StartEvent(), createdAt,
		), nil)
		if startErr != nil || !changed {
			t.Fatalf("start changed=%t error=%v", changed, startErr)
		}
		return started
	}
	firstInstance = startEvent(firstInstance, 86)
	secondInstance = startEvent(secondInstance, 86)
	firstReplacementInput := first.Input()
	firstReplacementInput.ID = appEntity(87)
	firstReplacementInput.Duration = 8 * time.Hour
	firstReplacement, err := kernel.NewMetricDefinition(firstReplacementInput)
	if err != nil {
		t.Fatal(err)
	}
	secondReplacementInput := second.Input()
	secondReplacementInput.ID = appEntity(88)
	secondReplacementInput.Duration = 12 * time.Hour
	secondReplacement, err := kernel.NewMetricDefinition(secondReplacementInput)
	if err != nil {
		t.Fatal(err)
	}
	replacementInput := policyInputFixture(t, 89, actor.TenantID, 2, firstReplacement)
	replacementInput.Metrics = []kernel.MetricDefinition{firstReplacement, secondReplacement}
	replacement := mustPolicy(t, replacementInput)
	digest := [32]byte{9}
	repository.authority = authorityFixture(now, actor, CapabilityCaseOverride, ScopeAssigned, AudienceOperator)
	repository.overrideState = OverrideState{
		Metrics:          []kernel.MetricWork{{Instance: firstInstance}, {Instance: secondInstance}},
		AggregateVersion: 5, ReplacementPolicy: &replacement, SimulationDigest: digest, OccurredAt: now,
	}
	request := OverrideRequest{
		ObjectType: kernel.ObjectCase, ObjectID: firstInstance.ObjectID(), SLAInstanceID: firstInstance.SLAInstanceID(),
		ExpectedAggregateVersion: 5, Intent: OverrideIntent{
			ID: appEntity(90), Kind: kernel.OverrideChangePolicy,
			Reason: "Approved aggregate policy replacement", NewPolicyID: replacement.ID(),
			NewPolicyVersion: replacement.Version(), SimulationDigest: digest,
		},
		Envelope: envelopeFixture(),
	}
	result, err := service.Override(deadlineContext(t, now), actor, actor.TenantID, request)
	plan := repository.overridePlan
	if err != nil || result.Receipt.Outcome != OverrideOutcomePolicyChanged ||
		result.Receipt.CurrentVersion != 6 || result.Receipt.AggregateVersion != 6 ||
		plan.Policy == nil || len(plan.Policy.Metrics()) != 2 || len(plan.Policy.Records()) != 2 {
		t.Fatalf("policy override=%#v error=%v", result, err)
	}
	for _, work := range plan.Policy.Metrics() {
		if work.Instance.PolicyID() != replacement.ID() ||
			work.Instance.SLAInstanceID() != firstInstance.SLAInstanceID() {
			t.Fatalf("replacement metric=%#v", work.Instance)
		}
	}
	malformed := request
	malformed.MetricInstanceID = firstInstance.ID()
	if _, err := service.Override(
		deadlineContext(t, now), actor, actor.TenantID, malformed,
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("metric-targeted policy override error=%v", err)
	}
}

type fakeRepository struct {
	onResolve                 func()
	authority                 Authority
	authorityResourceOverride *Resource
	now                       time.Time

	calendarWrite         CalendarPublication
	policyWrite           PolicyPublication
	columnWrite           ColumnPublication
	archiveWrite          ArchiveWrite
	eventTransaction      EventTransaction
	overrideTransaction   OverrideTransaction
	publishCalendarCalls  int
	archiveCalls          int
	overrideCalls         int
	eventPlanCalls        int
	overridePlanCalls     int
	objectProjectionCalls int

	policyCalendars        []kernel.BusinessCalendar
	calendarPage           CalendarPage
	calendarRecord         CalendarRecord
	policyPage             PolicyPage
	policyRecord           PolicyRecord
	columnPage             ColumnPage
	columnRecord           ColumnRecord
	metricDefinition       kernel.MetricDefinition
	simulationPolicy       kernel.Policy
	simulationCalendar     []kernel.BusinessCalendar
	objectProjection       ObjectProjectionState
	eventState             EventState
	eventPlan              EventPlan
	eventResult            *EventResult
	eventReceipts          map[[32]byte]EventResult
	eventReceiptMutator    func(*EventReceipt)
	overrideResult         *OverrideResult
	overrideState          OverrideState
	overridePlan           OverridePlan
	overrideReceipts       map[[32]byte]OverrideResult
	overrideReceiptMutator func(*OverrideReceipt)

	resolveErr     error
	writeErr       error
	archiveVersion uint64
}

func (repository *fakeRepository) ListCalendars(
	_ context.Context,
	_ Actor,
	_ uuid.UUID,
	_ ConfigurationListInput,
	_ Authority,
) (CalendarPage, error) {
	return repository.calendarPage, repository.writeErr
}

func (repository *fakeRepository) GetCalendar(
	_ context.Context,
	_ Actor,
	_ uuid.UUID,
	_ kernel.EntityID,
	_ Authority,
) (CalendarRecord, error) {
	return repository.calendarRecord, repository.writeErr
}

func newFakeRepository(now time.Time, actor Actor) *fakeRepository {
	return &fakeRepository{now: now, authority: authorityFixture(now, actor, CapabilityManage, ScopeTenant, AudienceOperator)}
}

func (repository *fakeRepository) ResolveAuthority(
	_ context.Context,
	actor Actor,
	tenantID uuid.UUID,
	capability Capability,
	resource Resource,
) (Authority, error) {
	if repository.onResolve != nil {
		repository.onResolve()
	}
	if repository.resolveErr != nil {
		return Authority{}, repository.resolveErr
	}
	authority := repository.authority
	authority.TenantID = tenantID
	authority.PrincipalID = actor.PrincipalID
	authority.MembershipID = actor.MembershipID
	authority.Capability = capability
	authority.Resource = resource
	if repository.authorityResourceOverride != nil {
		authority.Resource = *repository.authorityResourceOverride
	}
	return authority, nil
}

func (repository *fakeRepository) PublishCalendar(_ context.Context, write CalendarPublication) (PublicationResult[kernel.BusinessCalendar], error) {
	repository.publishCalendarCalls++
	repository.calendarWrite = write
	return PublicationResult[kernel.BusinessCalendar]{
		Value: write.Calendar, ResourceVersion: write.Calendar.Version(), CreatedAt: repository.now, UpdatedAt: repository.now,
	}, repository.writeErr
}

func (repository *fakeRepository) ListPolicies(
	_ context.Context,
	_ Actor,
	_ uuid.UUID,
	_ ConfigurationListInput,
	_ Authority,
) (PolicyPage, error) {
	return repository.policyPage, repository.writeErr
}

func (repository *fakeRepository) GetPolicy(
	_ context.Context,
	_ Actor,
	_ uuid.UUID,
	_ kernel.EntityID,
	_ Authority,
) (PolicyRecord, error) {
	return repository.policyRecord, repository.writeErr
}

func (repository *fakeRepository) LoadPolicyCalendars(_ context.Context, _ Actor, _ uuid.UUID, _ kernel.Policy) ([]kernel.BusinessCalendar, error) {
	return append([]kernel.BusinessCalendar(nil), repository.policyCalendars...), repository.writeErr
}

func (repository *fakeRepository) PublishPolicy(_ context.Context, write PolicyPublication) (PublicationResult[kernel.Policy], error) {
	repository.policyWrite = write
	return PublicationResult[kernel.Policy]{
		Value: write.Policy, ResourceVersion: write.Policy.Version(), CreatedAt: repository.now, UpdatedAt: repository.now,
	}, repository.writeErr
}

func (repository *fakeRepository) ListColumns(
	_ context.Context,
	_ Actor,
	_ uuid.UUID,
	_ ConfigurationListInput,
	_ Authority,
) (ColumnPage, error) {
	return repository.columnPage, repository.writeErr
}

func (repository *fakeRepository) GetColumn(
	_ context.Context,
	_ Actor,
	_ uuid.UUID,
	_ kernel.EntityID,
	_ Authority,
) (ColumnRecord, error) {
	return repository.columnRecord, repository.writeErr
}

func (repository *fakeRepository) LoadMetricDefinition(_ context.Context, _ Actor, _ uuid.UUID, _ kernel.EntityID) (kernel.MetricDefinition, error) {
	return repository.metricDefinition, repository.writeErr
}

func (repository *fakeRepository) PublishColumn(_ context.Context, write ColumnPublication) (PublicationResult[kernel.ColumnDefinition], error) {
	repository.columnWrite = write
	return PublicationResult[kernel.ColumnDefinition]{
		Value: write.Column, ResourceVersion: write.Column.Version(), CreatedAt: repository.now, UpdatedAt: repository.now,
	}, repository.writeErr
}

func (repository *fakeRepository) Archive(_ context.Context, write ArchiveWrite) (uint64, bool, error) {
	repository.archiveCalls++
	repository.archiveWrite = write
	if repository.writeErr != nil {
		return 0, false, repository.writeErr
	}
	if repository.archiveVersion != 0 {
		return repository.archiveVersion, false, nil
	}
	return write.ExpectedVersion + 1, false, nil
}

func (repository *fakeRepository) LoadSimulation(
	_ context.Context,
	_ Actor,
	_ uuid.UUID,
	_ kernel.EntityID,
	_ uint64,
) (kernel.Policy, []kernel.BusinessCalendar, error) {
	return repository.simulationPolicy, append([]kernel.BusinessCalendar(nil), repository.simulationCalendar...), repository.writeErr
}

func (repository *fakeRepository) LoadObjectProjection(
	_ context.Context,
	_ Actor,
	_ uuid.UUID,
	_ Resource,
	_ Authority,
) (ObjectProjectionState, error) {
	repository.objectProjectionCalls++
	return repository.objectProjection, repository.writeErr
}

func (repository *fakeRepository) TransactEvent(_ context.Context, transaction EventTransaction) (EventResult, error) {
	repository.eventTransaction = transaction
	if repository.writeErr != nil {
		return EventResult{}, repository.writeErr
	}
	if repository.eventResult != nil {
		return *repository.eventResult, nil
	}
	if previous, exists := repository.eventReceipts[transaction.Binding.KeyDigest]; exists {
		if previous.Receipt.Command.RequestDigest != transaction.Binding.RequestDigest {
			return EventResult{}, ErrRepositoryConflict
		}
		previous.Replayed = true
		return previous, nil
	}
	repository.eventPlanCalls++
	plan, err := transaction.Plan(repository.eventState)
	if err != nil {
		return EventResult{}, err
	}
	repository.eventPlan = plan
	result := EventResult{Receipt: eventReceipt(transaction, plan)}
	if repository.eventReceiptMutator != nil {
		repository.eventReceiptMutator(&result.Receipt)
	}
	if repository.eventReceipts == nil {
		repository.eventReceipts = make(map[[32]byte]EventResult)
	}
	repository.eventReceipts[transaction.Binding.KeyDigest] = result
	return result, nil
}

func (repository *fakeRepository) TransactOverride(_ context.Context, transaction OverrideTransaction) (OverrideResult, error) {
	repository.overrideCalls++
	repository.overrideTransaction = transaction
	if repository.writeErr != nil {
		return OverrideResult{}, repository.writeErr
	}
	if repository.overrideResult != nil {
		return *repository.overrideResult, nil
	}
	if previous, exists := repository.overrideReceipts[transaction.Binding.KeyDigest]; exists {
		if previous.Receipt.Command.RequestDigest != transaction.Binding.RequestDigest {
			return OverrideResult{}, ErrRepositoryConflict
		}
		previous.Replayed = true
		return previous, nil
	}
	repository.overridePlanCalls++
	plan, err := transaction.Plan(repository.overrideState)
	if err != nil {
		return OverrideResult{}, err
	}
	repository.overridePlan = plan
	result := OverrideResult{Receipt: overrideReceipt(transaction, plan, repository.overrideState.OccurredAt)}
	if repository.overrideReceiptMutator != nil {
		repository.overrideReceiptMutator(&result.Receipt)
	}
	if repository.overrideReceipts == nil {
		repository.overrideReceipts = make(map[[32]byte]OverrideResult)
	}
	repository.overrideReceipts[transaction.Binding.KeyDigest] = result
	return result, nil
}

func eventReceipt(transaction EventTransaction, plan EventPlan) EventReceipt {
	receipt := EventReceipt{
		Command: transaction.Binding, EventID: transaction.Command.Event.ID, TenantID: transaction.TenantID,
		ObjectType: transaction.Command.ObjectType, ObjectID: transaction.Command.Event.ObjectID,
		AggregateVersion: plan.NextAggregateVersion,
	}
	if plan.Assignment != nil && !plan.Assignment.Matched() {
		receipt.Outcome = EventOutcomeNoPolicy
		return receipt
	}
	if plan.Assignment != nil {
		receipt.Outcome = EventOutcomeAssigned
		policy := plan.Assignment.Policy()
		slaInstanceID, policyID := plan.Assignment.SLAInstanceID(), policy.ID()
		receipt.SLAInstanceID, receipt.PolicyID, receipt.PolicyVersion = &slaInstanceID, &policyID, policy.Version()
		return receipt
	}
	receipt.Outcome = EventOutcomeUpdated
	instance := plan.Engine.Metrics()[0].Instance()
	slaInstanceID, policyID := instance.SLAInstanceID(), instance.PolicyID()
	receipt.SLAInstanceID, receipt.PolicyID, receipt.PolicyVersion = &slaInstanceID, &policyID, instance.PolicyVersion()
	return receipt
}

func overrideReceipt(transaction OverrideTransaction, plan OverridePlan, occurredAt time.Time) OverrideReceipt {
	actorID, _ := kernel.ParseEntityID(transaction.Actor.MembershipID.String())
	receipt := OverrideReceipt{
		Command: transaction.Binding, OverrideID: transaction.Request.Intent.ID, TenantID: transaction.TenantID,
		ObjectType: transaction.Request.ObjectType, ObjectID: transaction.Request.ObjectID,
		Kind: transaction.Request.Intent.Kind, SLAInstanceID: transaction.Request.SLAInstanceID,
		PreviousVersion: overrideExpectedVersion(transaction.Request), AggregateVersion: plan.NextAggregateVersion,
		ActorID: actorID, PermissionEpoch: transaction.Authority.PermissionEpoch,
		SubjectEpoch: transaction.Authority.SubjectEpoch, OccurredAt: occurredAt,
		SimulationDigest: transaction.Request.Intent.SimulationDigest,
	}
	if plan.Policy != nil {
		policy := plan.Policy.ReplacementPolicy()
		receipt.Outcome, receipt.CurrentVersion = OverrideOutcomePolicyChanged, plan.NextAggregateVersion
		receipt.PolicyID, receipt.PolicyVersion = policy.ID(), policy.Version()
		return receipt
	}
	instance := plan.Instance
	metricID := instance.ID()
	receipt.Outcome, receipt.MetricInstanceID = OverrideOutcomeMetricUpdated, &metricID
	receipt.CurrentVersion = instance.Version()
	receipt.PolicyID, receipt.PolicyVersion = instance.PolicyID(), instance.PolicyVersion()
	return receipt
}

func mustService(t *testing.T, repository Repository, now time.Time) *Service {
	t.Helper()
	service, err := NewService(repository, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func deadlineContext(t *testing.T, now time.Time) context.Context {
	t.Helper()
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(5*time.Second))
	t.Cleanup(cancel)
	return ctx
}

func testNow() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

func operatorFixture() Actor {
	return Actor{
		TenantID: appUUID(1), PrincipalID: appUUID(2), MembershipID: appUUID(3),
		SessionID: appUUID(6), AuthenticationMethod: "webauthn", Kind: PrincipalOperator,
	}
}

func customerFixture(tenantID uuid.UUID) Actor {
	return Actor{
		TenantID: tenantID, PrincipalID: appUUID(4), MembershipID: appUUID(5),
		SessionID: appUUID(7), AuthenticationMethod: "oidc", Kind: PrincipalCustomer,
	}
}

func authorityFixture(now time.Time, actor Actor, capability Capability, scope Scope, audience Audience) Authority {
	return Authority{
		TenantID: actor.TenantID, PrincipalID: actor.PrincipalID, MembershipID: actor.MembershipID,
		Capability: capability, Scope: scope, Audience: audience, Allowed: true,
		PermissionEpoch: 7, SubjectEpoch: 11,
		EvaluatedAt: now.Add(-time.Minute), ValidUntil: now.Add(time.Minute),
	}
}

func envelopeFixture() MutationEnvelope {
	return MutationEnvelope{
		IdempotencyKey: "request-key-00000001",
		Audit: AuditContext{
			RequestID: appUUID(6), CorrelationID: appUUID(7), IPAddress: "192.0.2.10",
			UserAgent: "periapsis-test", AuthMethod: "session",
		},
	}
}

func appUUID(sequence uint16) uuid.UUID {
	value := [16]byte{0x01, 0x9d, 0, 0, 0, byte(sequence >> 8), 0x70, byte(sequence)}
	value[8] = 0x80
	return uuid.UUID(value)
}

func appEntity(sequence uint16) kernel.EntityID {
	return appEntityFromUUID(appUUID(sequence))
}

func appEntityFromUUID(value uuid.UUID) kernel.EntityID {
	id, err := kernel.ParseEntityID(value.String())
	if err != nil {
		panic(err)
	}
	return id
}

func appKey(value string) kernel.Key {
	key, err := kernel.NewKey(value)
	if err != nil {
		panic(err)
	}
	return key
}

func calendarInputFixture(sequence uint16, tenantID uuid.UUID, version uint64) kernel.BusinessCalendarInput {
	weekly := make([]kernel.WeeklyScheduleInput, 0, 7)
	for weekday := time.Sunday; weekday <= time.Saturday; weekday++ {
		weekly = append(weekly, kernel.WeeklyScheduleInput{
			Weekday: weekday, Intervals: []kernel.MinuteIntervalInput{{StartMinute: 0, EndMinute: 1_440}},
		})
	}
	return kernel.BusinessCalendarInput{
		ID: appEntity(sequence), TenantID: appEntityFromUUID(tenantID), Key: appKey("support_hours"),
		Label: "Support hours", Timezone: "UTC", Version: version, WeeklySchedules: weekly,
	}
}

func mustCalendar(t *testing.T, input kernel.BusinessCalendarInput) kernel.BusinessCalendar {
	t.Helper()
	calendar, err := kernel.NewBusinessCalendar(input)
	if err != nil {
		t.Fatal(err)
	}
	return calendar
}

func metricFixture(t *testing.T, sequence uint16, calendarID *kernel.EntityID, calendarVersion uint64, customerVisible bool) kernel.MetricDefinition {
	t.Helper()
	clock := kernel.ClockElapsed
	if calendarID != nil {
		clock = kernel.ClockBusiness
	}
	metric, err := kernel.NewMetricDefinition(kernel.MetricDefinitionInput{
		ID: appEntity(sequence), Key: appKey("first_response"), Label: "First response",
		Description: "Time to first response", Duration: 4 * time.Hour, Clock: clock,
		CalendarID: calendarID, CalendarVersion: calendarVersion,
		StartEvent: appKey("ticket.created"), PauseEvent: appKey("ticket.waiting_customer"),
		ResumeEvent: appKey("ticket.customer_replied"), CompletionEvent: appKey("ticket.responded"),
		ResetPolicy: kernel.ResetIgnore,
		Warning:     kernel.WarningThreshold{Kind: kernel.WarningConsumedPercent, ConsumedPercent: 75},
		BreachGrace: 30 * time.Minute, DisplayFormat: "duration",
		CustomerVisible: customerVisible, APIVisible: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return metric
}

func policyInputFixture(t *testing.T, sequence uint16, tenantID uuid.UUID, version uint64, metric kernel.MetricDefinition) kernel.PolicyInput {
	t.Helper()
	rule, err := kernel.NewRule(&kernel.RuleInput{Kind: kernel.RuleAll})
	if err != nil {
		t.Fatal(err)
	}
	return kernel.PolicyInput{
		ID: appEntity(sequence), TenantID: appEntityFromUUID(tenantID), Key: appKey("default_policy"),
		Name: "Default policy", Description: "Default tenant SLA", Version: version, Priority: 10,
		ObjectTypes: []kernel.ObjectType{kernel.ObjectAlert, kernel.ObjectCase}, MatchRule: rule,
		Metrics: []kernel.MetricDefinition{metric}, EffectiveFrom: time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC),
		Enabled: true,
	}
}

func mustPolicy(t *testing.T, input kernel.PolicyInput) kernel.Policy {
	t.Helper()
	policy, err := kernel.NewPolicy(input)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func columnInputFixture(sequence uint16, tenantID uuid.UUID, metric kernel.MetricDefinition, version uint64, customerVisible bool) kernel.ColumnDefinitionInput {
	return kernel.ColumnDefinitionInput{
		ID: appEntity(sequence), TenantID: appEntityFromUUID(tenantID), Key: appKey("first_response_state"),
		Label: "First response state", MetricID: metric.ID(), Calculation: kernel.ColumnState,
		Format: kernel.FormatStateBadge, Sortable: true, Filterable: true,
		CustomerVisible: customerVisible, Version: version,
		StyleRules: []kernel.ColumnStyleRuleInput{{StyleKey: appKey("paused_internal"), State: kernel.StatePaused}},
	}
}

func mustInstance(
	t *testing.T,
	tenantID uuid.UUID,
	instanceSequence uint16,
	objectSequence uint16,
	policy kernel.Policy,
	metric kernel.MetricDefinition,
	createdAt time.Time,
) kernel.MetricInstance {
	t.Helper()
	instance, err := kernel.NewMetricInstance(kernel.MetricInstanceInput{
		ID: appEntity(instanceSequence), SLAInstanceID: appEntity(instanceSequence + 1_000),
		TenantID: appEntityFromUUID(tenantID), ObjectType: kernel.ObjectCase,
		ObjectID: appEntity(objectSequence), PolicyID: policy.ID(), PolicyVersion: policy.Version(),
		Definition: metric, CreatedAt: createdAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return instance
}

func metricEvent(instance kernel.MetricInstance, sequence uint16, key kernel.Key, at time.Time) kernel.MetricEvent {
	return kernel.MetricEvent{
		ID: appEntity(sequence), TenantID: instance.TenantID(), ObjectID: instance.ObjectID(), Key: key, OccurredAt: at,
	}
}

func metricWorkPointer(instance kernel.MetricInstance) *kernel.MetricWork {
	return &kernel.MetricWork{Instance: instance}
}
