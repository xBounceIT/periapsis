package ticketing

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

func TestWorkflowAdministrationAccessIsOperatorOnlyAndFailClosed(t *testing.T) {
	fixture := newWorkflowAdminFixture(t)
	tests := []struct {
		name      string
		configure func(*fakeWorkflowAdminRepository)
		want      error
		wantReads int32
	}{
		{
			name: "customer principal",
			configure: func(repository *fakeWorkflowAdminRepository) {
				repository.principal = kernel.PrincipalCustomer
			},
			want: ErrForbidden,
		},
		{
			name: "service account principal",
			configure: func(repository *fakeWorkflowAdminRepository) {
				repository.principal = kernel.PrincipalServiceAccount
			},
			want: ErrForbidden,
		},
		{
			name: "denied operator",
			configure: func(repository *fakeWorkflowAdminRepository) {
				repository.allowed = false
			},
			want: ErrForbidden,
		},
		{
			name: "malformed repository evidence",
			configure: func(repository *fakeWorkflowAdminRepository) {
				repository.accessOverride = &WorkflowAdminAccess{
					tenant: fixture.base.ticketUUID, actor: fixture.base.actor.UserID,
					capability: WorkflowCapabilityRead, principal: kernel.PrincipalOperator, allowed: true,
				}
			},
			want: ErrUnavailable,
		},
		{
			name:      "operator",
			configure: func(*fakeWorkflowAdminRepository) {},
			wantReads: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := newFakeWorkflowAdminRepository(fixture)
			test.configure(repository)
			service := mustWorkflowAdminService(t, repository)
			_, err := service.GetWorkflow(
				context.Background(), fixture.base.actor, fixture.base.tenantUUID, fixture.workflowID,
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("GetWorkflow() error = %v, want %v", err, test.want)
			}
			if got := repository.getCalls.Load(); got != test.wantReads {
				t.Fatalf("repository reads = %d, want %d", got, test.wantReads)
			}
		})
	}
}

func TestWorkflowAdministrationRequiresRepository(t *testing.T) {
	if service, err := NewWorkflowAdminService(nil); err == nil || service != nil {
		t.Fatalf("NewWorkflowAdminService(nil) = (%v, %v)", service, err)
	}
}

func TestWorkflowAdministrationSeparatesInvalidResourceFromInvalidActor(t *testing.T) {
	fixture := newWorkflowAdminFixture(t)
	repository := newFakeWorkflowAdminRepository(fixture)
	service := mustWorkflowAdminService(t, repository)

	_, err := service.GetWorkflow(context.Background(), fixture.base.actor, fixture.base.tenantUUID, uuid.Nil)
	if !errors.Is(err, ErrInvalidInput) || repository.accessCalls.Load() != 0 {
		t.Fatalf("invalid workflow ID error=%v access=%d", err, repository.accessCalls.Load())
	}

	actor := fixture.base.actor
	actor.ActiveTenantID = fixture.base.ticketUUID
	_, err = service.GetWorkflow(context.Background(), actor, fixture.base.tenantUUID, fixture.workflowID)
	if !errors.Is(err, ErrForbidden) || repository.accessCalls.Load() != 0 {
		t.Fatalf("invalid actor error=%v access=%d", err, repository.accessCalls.Load())
	}
}

func TestWorkflowAdministrationRejectsStoredVersionsOutsideDatabaseBounds(t *testing.T) {
	fixture := newWorkflowAdminFixture(t)
	oversized := workflowWithIDAndVersion(
		t, fixture.record.Workflow.Current(), fixture.workflowID, maxResourceVersion+1, false,
	)
	fixture.record = managedWorkflowRecord(
		t, fixture.base.tenant, oversized, maxResourceVersion+1, false, kernel.WorkflowActive,
	)
	repository := newFakeWorkflowAdminRepository(fixture)
	service := mustWorkflowAdminService(t, repository)

	_, err := service.GetWorkflow(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, fixture.workflowID,
	)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("oversized stored workflow error = %v, want unavailable", err)
	}
}

func TestWorkflowAdministrationListRejectsCrossTenantAndUnorderedProjection(t *testing.T) {
	fixture := newWorkflowAdminFixture(t)
	repository := newFakeWorkflowAdminRepository(fixture)
	service := mustWorkflowAdminService(t, repository)

	otherTenant := mustUUIDv7(t)
	otherTenantID, _ := entityID(otherTenant)
	leaked := managedWorkflowRecord(t, otherTenantID, alertWorkflow(t), 1, false, kernel.WorkflowActive)
	repository.listOverride = &WorkflowAdminPage{Items: []WorkflowAdminRecord{leaked}}
	_, err := service.ListWorkflows(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, WorkflowAdminListInput{Limit: 10},
	)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cross-tenant list error = %v, want unavailable", err)
	}

	first := fixture.record
	secondDefinition := workflowWithIDAndVersion(t, alertWorkflow(t), mustUUIDv7(t), 1, false)
	second := managedWorkflowRecord(t, fixture.base.tenant, secondDefinition, 1, false, kernel.WorkflowActive)
	items := []WorkflowAdminRecord{first, second}
	if strings.Compare(items[0].Workflow.ID().String(), items[1].Workflow.ID().String()) < 0 {
		items[0], items[1] = items[1], items[0]
	}
	repository.listOverride = &WorkflowAdminPage{Items: items}
	_, err = service.ListWorkflows(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, WorkflowAdminListInput{Limit: 10},
	)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unordered list error = %v, want unavailable", err)
	}

	repository.listOverride = &WorkflowAdminPage{NextCursor: "AQ"}
	_, err = service.ListWorkflows(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, WorkflowAdminListInput{Limit: 10},
	)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("empty page cursor error = %v, want unavailable", err)
	}

	foreignCursorID := mustUUIDv7(t)
	repository.listOverride = &WorkflowAdminPage{
		Items:      []WorkflowAdminRecord{fixture.record},
		NextCursor: base64.RawURLEncoding.EncodeToString(foreignCursorID[:]),
	}
	_, err = service.ListWorkflows(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, WorkflowAdminListInput{Limit: 10},
	)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cursor not pinned to last item error = %v, want unavailable", err)
	}
}

func TestWorkflowAdministrationListSearchMatchesContractBound(t *testing.T) {
	fixture := newWorkflowAdminFixture(t)
	repository := newFakeWorkflowAdminRepository(fixture)
	service := mustWorkflowAdminService(t, repository)

	_, err := service.ListWorkflows(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		WorkflowAdminListInput{Search: strings.Repeat("a", 200)},
	)
	if err != nil {
		t.Fatalf("200-character workflow search error = %v", err)
	}
	accessCalls := repository.accessCalls.Load()

	_, err = service.ListWorkflows(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		WorkflowAdminListInput{Search: strings.Repeat("a", 201)},
	)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("201-character workflow search error = %v, want invalid input", err)
	}
	if got := repository.accessCalls.Load(); got != accessCalls {
		t.Fatalf("invalid workflow search reached authorization: calls = %d, want %d", got, accessCalls)
	}
}

func TestWorkflowAdministrationListRejectsNonCanonicalCursorBeforeAuthorization(t *testing.T) {
	fixture := newWorkflowAdminFixture(t)
	repository := newFakeWorkflowAdminRepository(fixture)
	service := mustWorkflowAdminService(t, repository)

	for _, cursor := range []string{"AQ", "not+url-safe", base64.RawURLEncoding.EncodeToString(uuid.Nil[:])} {
		_, err := service.ListWorkflows(
			context.Background(), fixture.base.actor, fixture.base.tenantUUID,
			WorkflowAdminListInput{After: cursor},
		)
		if !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("workflow cursor %q error = %v, want invalid input", cursor, err)
		}
	}
	if got := repository.accessCalls.Load(); got != 0 {
		t.Fatalf("invalid workflow cursors reached authorization %d times", got)
	}
}

func TestWorkflowCreationIsIdempotentAndFingerprintBound(t *testing.T) {
	fixture := newWorkflowAdminFixture(t)
	repository := newFakeWorkflowAdminRepository(fixture)
	repository.records = map[uuid.UUID]WorkflowAdminRecord{}
	repository.versions = map[uuid.UUID]map[uint64]WorkflowVersionRecord{}
	service := mustWorkflowAdminService(t, repository)
	input := WorkflowCreateInput{
		Kind: kernel.AggregateAlert, Key: "alert_response", DisplayName: "Alert response",
		Description: "Tenant alert workflow", Design: workflowDesign(fixture.record.Workflow.Current()),
		IdempotencyKey: "workflow-create-attempt-0001",
	}

	first, err := service.CreateWorkflow(context.Background(), fixture.base.actor, fixture.base.tenantUUID, input)
	if err != nil || first.Replayed {
		t.Fatalf("first CreateWorkflow() = (%+v, %v)", first, err)
	}
	second, err := service.CreateWorkflow(context.Background(), fixture.base.actor, fixture.base.tenantUUID, input)
	if err != nil || !second.Replayed || second.Record.Workflow.ID() != first.Record.Workflow.ID() {
		t.Fatalf("replayed CreateWorkflow() = (%+v, %v)", second, err)
	}
	if got := repository.successfulCommits.Load(); got != 1 {
		t.Fatalf("successful commits = %d, want 1", got)
	}

	input.DisplayName = "Different semantic request"
	_, err = service.CreateWorkflow(context.Background(), fixture.base.actor, fixture.base.tenantUUID, input)
	if !errors.Is(err, ErrConflict) || repository.successfulCommits.Load() != 1 {
		t.Fatalf("conflicting replay error=%v commits=%d", err, repository.successfulCommits.Load())
	}
}

func TestConcurrentWorkflowPublicationHasExactlyOneCASWinner(t *testing.T) {
	fixture := newWorkflowAdminFixture(t)
	repository := newFakeWorkflowAdminRepository(fixture)
	repository.synchronizeGets = 2
	repository.getGate = make(chan struct{})
	service := mustWorkflowAdminService(t, repository)
	design := changedWorkflowDesign(t, fixture.record.Workflow.Current())

	start := make(chan struct{})
	results := make(chan error, 2)
	for index := 0; index < 2; index++ {
		index := index
		go func() {
			<-start
			_, err := service.PublishWorkflow(
				context.Background(), fixture.base.actor, fixture.base.tenantUUID, fixture.workflowID,
				WorkflowPublishInput{
					ExpectedRevision: 1, Design: design,
					IdempotencyKey: fmt.Sprintf("workflow-publish-race-%04d", index),
				},
			)
			results <- err
		}()
	}
	close(start)
	winners, losers := 0, 0
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			winners++
		case errors.Is(err, ErrPreconditionFailed):
			losers++
		default:
			t.Fatalf("unexpected publication error: %v", err)
		}
	}
	if winners != 1 || losers != 1 || repository.commitAttempts.Load() != 2 ||
		repository.successfulCommits.Load() != 1 {
		t.Fatalf(
			"winners=%d losers=%d attempts=%d commits=%d",
			winners, losers, repository.commitAttempts.Load(), repository.successfulCommits.Load(),
		)
	}
}

func TestWorkflowPublicationRetryReplaysWithoutAnotherVersion(t *testing.T) {
	fixture := newWorkflowAdminFixture(t)
	repository := newFakeWorkflowAdminRepository(fixture)
	service := mustWorkflowAdminService(t, repository)
	input := WorkflowPublishInput{
		ExpectedRevision: 1, Design: changedWorkflowDesign(t, fixture.record.Workflow.Current()),
		IdempotencyKey: "workflow-publish-attempt-0001",
	}

	first, err := service.PublishWorkflow(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, fixture.workflowID, input,
	)
	if err != nil || first.Record.Workflow.CurrentVersion() != 2 || first.Replayed {
		t.Fatalf("first PublishWorkflow() = (%+v, %v)", first, err)
	}
	second, err := service.PublishWorkflow(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, fixture.workflowID, input,
	)
	if err != nil || !second.Replayed || second.Record.Workflow.CurrentVersion() != 2 {
		t.Fatalf("retry PublishWorkflow() = (%+v, %v)", second, err)
	}
	if repository.successfulCommits.Load() != 1 || len(repository.versions[fixture.workflowID]) != 2 {
		t.Fatalf("commits=%d versions=%d", repository.successfulCommits.Load(), len(repository.versions[fixture.workflowID]))
	}
}

func TestWorkflowCommitReauthorizesInsideTransaction(t *testing.T) {
	fixture := newWorkflowAdminFixture(t)
	repository := newFakeWorkflowAdminRepository(fixture)
	repository.revokeAtCommit = true
	service := mustWorkflowAdminService(t, repository)

	_, err := service.UpdateWorkflowMetadata(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, fixture.workflowID,
		WorkflowMetadataInput{
			ExpectedRevision: 1, DisplayName: "Renamed workflow", Description: "Tenant alert workflow",
			IdempotencyKey: "workflow-metadata-attempt-0001",
		},
	)
	if !errors.Is(err, ErrForbidden) || repository.commitAttempts.Load() != 1 ||
		repository.successfulCommits.Load() != 0 {
		t.Fatalf("UpdateWorkflowMetadata() error=%v attempts=%d commits=%d", err,
			repository.commitAttempts.Load(), repository.successfulCommits.Load())
	}
}

func TestSetDefaultWorkflowAtomicallyDisplacesPreviousDefault(t *testing.T) {
	fixture := newWorkflowAdminFixture(t)
	previousDefinition := workflowWithIDAndVersion(t, alertWorkflow(t), mustUUIDv7(t), 1, false)
	previous := managedWorkflowRecord(t, fixture.base.tenant, previousDefinition, 4, true, kernel.WorkflowActive)
	previousID := uuidFromEntity(previous.Workflow.ID())
	repository := newFakeWorkflowAdminRepository(fixture)
	repository.records[previousID] = previous
	repository.versions[previousID] = map[uint64]WorkflowVersionRecord{
		1: workflowVersionRecord(fixture.base.tenantUUID, previousDefinition),
	}
	service := mustWorkflowAdminService(t, repository)

	result, err := service.SetDefaultWorkflow(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, fixture.workflowID,
		WorkflowLifecycleInput{ExpectedRevision: 1, IdempotencyKey: "workflow-default-attempt-0001"},
	)
	if err != nil || !result.Record.Workflow.IsDefault() || result.Record.Workflow.Revision() != 2 {
		t.Fatalf("SetDefaultWorkflow() = (%+v, %v)", result, err)
	}
	repository.mu.Lock()
	displaced := repository.records[previousID]
	repository.mu.Unlock()
	if displaced.Workflow.IsDefault() || displaced.Workflow.Revision() != 5 ||
		repository.successfulCommits.Load() != 1 {
		t.Fatalf("displaced=%+v commits=%d", displaced, repository.successfulCommits.Load())
	}
	replayed, err := service.SetDefaultWorkflow(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, fixture.workflowID,
		WorkflowLifecycleInput{ExpectedRevision: 1, IdempotencyKey: "workflow-default-attempt-0001"},
	)
	if err != nil || !replayed.Replayed || repository.successfulCommits.Load() != 1 {
		t.Fatalf("SetDefaultWorkflow(replay) = (%+v, %v), commits=%d", replayed, err, repository.successfulCommits.Load())
	}
}

func TestDefaultWorkflowCannotBeArchived(t *testing.T) {
	fixture := newWorkflowAdminFixture(t)
	fixture.record = managedWorkflowRecord(
		t, fixture.base.tenant, fixture.record.Workflow.Current(), 1, true, kernel.WorkflowActive,
	)
	repository := newFakeWorkflowAdminRepository(fixture)
	service := mustWorkflowAdminService(t, repository)

	_, err := service.ArchiveWorkflow(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, fixture.workflowID,
		WorkflowLifecycleInput{ExpectedRevision: 1, IdempotencyKey: "workflow-archive-attempt-0001"},
	)
	if !errors.Is(err, ErrConflict) || repository.commitAttempts.Load() != 0 {
		t.Fatalf("ArchiveWorkflow() error=%v attempts=%d", err, repository.commitAttempts.Load())
	}
}

func TestWorkflowArchiveAndRestoreAdvanceOnlyCatalogRevision(t *testing.T) {
	fixture := newWorkflowAdminFixture(t)
	repository := newFakeWorkflowAdminRepository(fixture)
	service := mustWorkflowAdminService(t, repository)

	archived, err := service.ArchiveWorkflow(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, fixture.workflowID,
		WorkflowLifecycleInput{ExpectedRevision: 1, IdempotencyKey: "workflow-archive-attempt-0002"},
	)
	if err != nil || archived.Record.Workflow.Status() != kernel.WorkflowArchived ||
		archived.Record.Workflow.Revision() != 2 || archived.Record.Workflow.CurrentVersion() != 1 ||
		archived.Record.ArchivedAt == nil {
		t.Fatalf("ArchiveWorkflow() = (%+v, %v)", archived, err)
	}
	restored, err := service.RestoreWorkflow(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, fixture.workflowID,
		WorkflowLifecycleInput{ExpectedRevision: 2, IdempotencyKey: "workflow-restore-attempt-0001"},
	)
	if err != nil || restored.Record.Workflow.Status() != kernel.WorkflowActive ||
		restored.Record.Workflow.Revision() != 3 || restored.Record.Workflow.CurrentVersion() != 1 ||
		restored.Record.ArchivedAt != nil || len(repository.versions[fixture.workflowID]) != 1 {
		t.Fatalf("RestoreWorkflow() = (%+v, %v), versions=%d", restored, err, len(repository.versions[fixture.workflowID]))
	}
}

func TestWorkflowSimulationUsesPinnedHistoryAndRejectsDerivedFactDrift(t *testing.T) {
	fixture := newWorkflowAdminFixture(t)
	versionOne := fixture.record.Workflow.Current()
	versionTwo := workflowWithIDAndVersion(t, versionOne, fixture.workflowID, 2, true)
	fixture.record = managedWorkflowRecord(t, fixture.base.tenant, versionTwo, 2, false, kernel.WorkflowActive)
	repository := newFakeWorkflowAdminRepository(fixture)
	repository.versions[fixture.workflowID][1] = workflowVersionRecord(fixture.base.tenantUUID, versionOne)
	repository.versions[fixture.workflowID][2] = workflowVersionRecord(fixture.base.tenantUUID, versionTwo)
	service := mustWorkflowAdminService(t, repository)
	state, _ := kernel.NewKey("new")

	result, err := service.SimulateWorkflow(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, fixture.workflowID,
		WorkflowSimulationInput{Version: 1, State: state},
	)
	if err != nil || result.Version != 1 || len(result.Results) != 1 || !result.Results[0].Eligible() {
		t.Fatalf("SimulateWorkflow(version 1) = (%+v, %v)", result, err)
	}

	field, _ := kernel.NewConditionField("aggregate_kind")
	value, _ := kernel.NewTextConditionValue("case")
	fact, _ := kernel.NewConditionFact(field, value)
	facts, _ := kernel.NewConditionFacts(fact)
	_, err = service.SimulateWorkflow(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, fixture.workflowID,
		WorkflowSimulationInput{Version: 1, State: state, Facts: facts},
	)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("derived fact drift error = %v, want invalid input", err)
	}
}

func TestGetWorkflowVersionValidatesHistoryProjection(t *testing.T) {
	fixture := newWorkflowAdminFixture(t)
	repository := newFakeWorkflowAdminRepository(fixture)
	service := mustWorkflowAdminService(t, repository)

	record, err := service.GetWorkflowVersion(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, fixture.workflowID, 1,
	)
	if err != nil || record.Definition.Version() != 1 {
		t.Fatalf("GetWorkflowVersion(1) = (%+v, %v)", record, err)
	}
	_, err = service.GetWorkflowVersion(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, fixture.workflowID, 2,
	)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetWorkflowVersion(future) error = %v, want not found", err)
	}

	leaked := repository.versions[fixture.workflowID][1]
	leaked.TenantID = fixture.base.ticketUUID
	repository.versions[fixture.workflowID][1] = leaked
	_, err = service.GetWorkflowVersion(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, fixture.workflowID, 1,
	)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("GetWorkflowVersion(leaked projection) error = %v, want unavailable", err)
	}
}

func TestWorkflowVersionPaginationValidatesExclusiveCursorContract(t *testing.T) {
	fixture := newWorkflowAdminFixture(t)
	versionOne := fixture.record.Workflow.Current()
	versionTwo := workflowWithIDAndVersion(t, versionOne, fixture.workflowID, 2, true)
	fixture.record = managedWorkflowRecord(t, fixture.base.tenant, versionTwo, 2, false, kernel.WorkflowActive)
	repository := newFakeWorkflowAdminRepository(fixture)
	versionOneRecord := workflowVersionRecord(fixture.base.tenantUUID, versionOne)
	versionTwoRecord := workflowVersionRecord(fixture.base.tenantUUID, versionTwo)
	service := mustWorkflowAdminService(t, repository)

	repository.versionPageOverride = &WorkflowVersionPage{
		Items: []WorkflowVersionRecord{versionOneRecord}, NextVersion: 1,
	}
	page, err := service.ListWorkflowVersions(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID, fixture.workflowID,
		WorkflowVersionListInput{AfterVersion: 2, Limit: 1},
	)
	if err != nil || page.NextVersion != 1 {
		t.Fatalf("valid continuation page = (%+v, %v)", page, err)
	}

	tests := []struct {
		name string
		page WorkflowVersionPage
	}{
		{name: "cursor does not match last item", page: WorkflowVersionPage{Items: []WorkflowVersionRecord{versionOneRecord}, NextVersion: 2}},
		{name: "empty page has cursor", page: WorkflowVersionPage{NextVersion: 1}},
		{name: "exclusive upper bound repeated", page: WorkflowVersionPage{Items: []WorkflowVersionRecord{versionTwoRecord}, NextVersion: 2}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository.versionPageOverride = &test.page
			_, err := service.ListWorkflowVersions(
				context.Background(), fixture.base.actor, fixture.base.tenantUUID, fixture.workflowID,
				WorkflowVersionListInput{AfterVersion: 2, Limit: 1},
			)
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("ListWorkflowVersions() error = %v, want unavailable", err)
			}
		})
	}
}

func TestWorkflowCommandBindingIsDeterministicBoundedAndRedacted(t *testing.T) {
	fixture := newWorkflowAdminFixture(t)
	definition := fixture.record.Workflow.Current()
	otherID := mustUUIDv7(t)
	sameDesign := workflowWithIDAndVersion(t, definition, otherID, 1, false)
	first, err := bindWorkflowAdminCommand(
		"workflow-secret-attempt-0001", kernel.WorkflowAdministrationCreate,
		fixture.base.tenantUUID, nil, 0, "alert_response", "Alert response", "Description", &definition,
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := bindWorkflowAdminCommand(
		"workflow-secret-attempt-0001", kernel.WorkflowAdministrationCreate,
		fixture.base.tenantUUID, nil, 0, "alert_response", "Alert response", "Description", &sameDesign,
	)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("same design bindings differ: %+v != %+v", first, second)
	}
	if first.KeyHash != sha256.Sum256([]byte(workflowAdminIdempotencyDomain+"workflow-secret-attempt-0001")) ||
		strings.Contains(fmt.Sprintf("%v", first), "workflow-secret") {
		t.Fatalf("binding does not structurally redact key: %v", first)
	}

	changed := workflowWithIDAndVersion(t, definition, otherID, 1, true)
	third, err := bindWorkflowAdminCommand(
		"workflow-secret-attempt-0001", kernel.WorkflowAdministrationCreate,
		fixture.base.tenantUUID, nil, 0, "alert_response", "Alert response", "Description", &changed,
	)
	if err != nil {
		t.Fatal(err)
	}
	if third.Fingerprint == first.Fingerprint {
		t.Fatal("semantic workflow change did not change fingerprint")
	}

	conditional := workflowWithIDAndVersion(t, conditionalAlertWorkflow(t), fixture.workflowID, 1, false)
	conditionalBinding, err := bindWorkflowAdminCommand(
		"workflow-secret-attempt-0002", kernel.WorkflowAdministrationPublish,
		fixture.base.tenantUUID, &fixture.workflowID, 1, "", "", "", &conditional,
	)
	if err != nil || conditionalBinding.Fingerprint == first.Fingerprint {
		t.Fatalf("conditional workflow binding = (%+v, %v)", conditionalBinding, err)
	}
	mismatchedID := mustUUIDv7(t)
	if _, err = bindWorkflowAdminCommand(
		"workflow-secret-attempt-0003", kernel.WorkflowAdministrationPublish,
		fixture.base.tenantUUID, &mismatchedID, 1, "", "", "", &conditional,
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("mismatched workflow identity error = %v", err)
	}
}

func TestWorkflowAdministrationETagBindsIdentityAndIndependentRevision(t *testing.T) {
	fixture := newWorkflowAdminFixture(t)
	first := WorkflowAdminStrongETag(fixture.record)
	if first != WorkflowAdminStrongETag(fixture.record) || !strings.HasPrefix(first, "\"v1-") ||
		strings.Contains(first, fixture.record.Workflow.DisplayName()) {
		t.Fatalf("unexpected workflow ETag %q", first)
	}
	if other := WorkflowAdminStrongETagFor(mustUUIDv7(t), fixture.record.Workflow.Revision()); other == first {
		t.Fatalf("workflow identity change did not change ETag: %q", other)
	}
	updated := managedWorkflowRecord(
		t, fixture.base.tenant, fixture.record.Workflow.Current(), 2, false, kernel.WorkflowActive,
	)
	if second := WorkflowAdminStrongETag(updated); second == first {
		t.Fatalf("revision change did not change ETag: %q", second)
	}
	version := workflowVersionRecord(fixture.base.tenantUUID, fixture.record.Workflow.Current())
	if rendered := version.String(); strings.Contains(rendered, version.PublisherDisplayName) ||
		!strings.Contains(rendered, "publisher:[REDACTED]") {
		t.Fatalf("workflow version formatting leaked publisher: %q", rendered)
	}
}

func TestWorkflowAdministrationReadErrorsDoNotExposePersistenceConflicts(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		input error
		want  error
	}{
		{input: ErrInvalidInput, want: ErrInvalidInput},
		{input: ErrForbidden, want: ErrForbidden},
		{input: ErrNotFound, want: ErrNotFound},
		{input: ErrUnavailable, want: ErrUnavailable},
		{input: ErrConflict, want: ErrUnavailable},
		{input: ErrPreconditionFailed, want: ErrUnavailable},
		{input: errors.New("driver projection failure"), want: ErrUnavailable},
	} {
		if err := workflowAdminReadRepositoryError(test.input); !errors.Is(err, test.want) {
			t.Fatalf("workflowAdminReadRepositoryError(%v) = %v, want %v", test.input, err, test.want)
		}
	}
}

func TestWorkflowAdministrationInputFormattingIsStructurallyRedacted(t *testing.T) {
	fixture := newWorkflowAdminFixture(t)
	state, _ := kernel.NewKey("new")
	field, _ := kernel.NewConditionField("classification")
	value, _ := kernel.NewTextConditionValue("sensitive-fact")
	fact, _ := kernel.NewConditionFact(field, value)
	facts, _ := kernel.NewConditionFacts(fact)
	tests := []struct {
		name      string
		rendered  string
		forbidden []string
	}{
		{
			name: "list",
			rendered: (WorkflowAdminListInput{
				After: "sensitive-cursor", Search: "sensitive-search", Limit: 10,
			}).String(),
			forbidden: []string{"sensitive-cursor", "sensitive-search"},
		},
		{
			name: "create",
			rendered: (WorkflowCreateInput{
				Kind: kernel.AggregateAlert, Key: "alert_response", DisplayName: "sensitive-name",
				Description: "sensitive-description", Design: workflowDesign(fixture.record.Workflow.Current()),
				IdempotencyKey: "sensitive-idempotency",
			}).String(),
			forbidden: []string{"alert_response", "sensitive-name", "sensitive-description", "sensitive-idempotency"},
		},
		{
			name: "metadata",
			rendered: (WorkflowMetadataInput{
				ExpectedRevision: 1, DisplayName: "sensitive-name", Description: "sensitive-description",
				IdempotencyKey: "sensitive-idempotency",
			}).String(),
			forbidden: []string{"sensitive-name", "sensitive-description", "sensitive-idempotency"},
		},
		{
			name:      "simulation",
			rendered:  (WorkflowSimulationInput{Version: 1, State: state, Facts: facts}).String(),
			forbidden: []string{"new", "sensitive-fact"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, forbidden := range test.forbidden {
				if strings.Contains(test.rendered, forbidden) {
					t.Fatalf("formatting leaked %q: %q", forbidden, test.rendered)
				}
			}
			if !strings.Contains(test.rendered, "[REDACTED]") {
				t.Fatalf("formatting lacks structural redaction: %q", test.rendered)
			}
		})
	}
}

type workflowAdminFixture struct {
	base       serviceFixture
	workflowID uuid.UUID
	record     WorkflowAdminRecord
}

func newWorkflowAdminFixture(t testing.TB) workflowAdminFixture {
	t.Helper()
	base := newServiceFixture(t)
	record := managedWorkflowRecord(t, base.tenant, base.workflow, 1, false, kernel.WorkflowActive)
	return workflowAdminFixture{
		base: base, workflowID: uuidFromEntity(record.Workflow.ID()), record: record,
	}
}

func managedWorkflowRecord(
	t testing.TB,
	tenant kernel.EntityID,
	definition kernel.WorkflowDefinition,
	revision uint64,
	isDefault bool,
	status kernel.WorkflowStatus,
) WorkflowAdminRecord {
	t.Helper()
	key, _ := kernel.NewKey("alert_response")
	managed, err := kernel.NewManagedWorkflow(
		tenant, key, "Alert response", "Tenant alert workflow", isDefault, status, revision, definition,
	)
	if err != nil {
		t.Fatal(err)
	}
	createdAt := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	record := WorkflowAdminRecord{Workflow: managed, CreatedAt: createdAt, UpdatedAt: createdAt}
	if status == kernel.WorkflowArchived {
		archivedAt := createdAt
		record.ArchivedAt = &archivedAt
	}
	return record
}

func workflowDesign(definition kernel.WorkflowDefinition) WorkflowDesignInput {
	return WorkflowDesignInput{States: definition.States(), Transitions: definition.Transitions()}
}

func changedWorkflowDesign(t testing.TB, definition kernel.WorkflowDefinition) WorkflowDesignInput {
	t.Helper()
	changed := workflowWithIDAndVersion(t, definition, uuidFromEntity(definition.ID()), definition.Version(), true)
	return workflowDesign(changed)
}

func workflowWithIDAndVersion(
	t testing.TB,
	source kernel.WorkflowDefinition,
	id uuid.UUID,
	version uint64,
	changeTerminalVisibility bool,
) kernel.WorkflowDefinition {
	t.Helper()
	entity, err := entityID(id)
	if err != nil {
		t.Fatal(err)
	}
	states := source.States()
	if changeTerminalVisibility {
		for index, state := range states {
			if !state.Terminal() {
				continue
			}
			visibility := kernel.VisibilityInternal
			if state.Visibility() == kernel.VisibilityInternal {
				visibility = kernel.VisibilityCustomer
			}
			states[index], err = kernel.NewStateDefinition(
				state.Key(), state.Initial(), state.Terminal(), visibility, state.Actions(),
			)
			if err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	result, err := kernel.NewWorkflowDefinition(entity, source.Kind(), version, states, source.Transitions())
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func workflowVersionRecord(tenantID uuid.UUID, definition kernel.WorkflowDefinition) WorkflowVersionRecord {
	return WorkflowVersionRecord{
		TenantID: tenantID, Definition: definition, PublisherDisplayName: "Operator",
		PublishedAt: time.Date(2026, 8, 25, 10, 0, int(definition.Version()), 0, time.UTC),
	}
}

func mustWorkflowAdminService(t testing.TB, repository WorkflowAdminRepository) *WorkflowAdminService {
	t.Helper()
	service, err := NewWorkflowAdminService(repository)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type fakeWorkflowAdminReplayKey struct {
	tenant uuid.UUID
	actor  uuid.UUID
	action kernel.WorkflowAdministrationAction
	hash   [sha256.Size]byte
}

type fakeWorkflowAdminReplay struct {
	fingerprint [sha256.Size]byte
	result      WorkflowAdminMutationResult
}

type fakeWorkflowAdminRepository struct {
	mu                  sync.Mutex
	fixture             workflowAdminFixture
	principal           kernel.PrincipalKind
	allowed             bool
	accessOverride      *WorkflowAdminAccess
	listOverride        *WorkflowAdminPage
	versionPageOverride *WorkflowVersionPage
	records             map[uuid.UUID]WorkflowAdminRecord
	versions            map[uuid.UUID]map[uint64]WorkflowVersionRecord
	replays             map[fakeWorkflowAdminReplayKey]fakeWorkflowAdminReplay
	revokeAtCommit      bool
	synchronizeGets     int
	getGate             chan struct{}
	getArrivals         int
	getGateClosed       bool
	accessCalls         atomic.Int32
	getCalls            atomic.Int32
	commitAttempts      atomic.Int32
	successfulCommits   atomic.Int32
}

func newFakeWorkflowAdminRepository(fixture workflowAdminFixture) *fakeWorkflowAdminRepository {
	return &fakeWorkflowAdminRepository{
		fixture: fixture, principal: kernel.PrincipalOperator, allowed: true,
		records: map[uuid.UUID]WorkflowAdminRecord{fixture.workflowID: fixture.record},
		versions: map[uuid.UUID]map[uint64]WorkflowVersionRecord{
			fixture.workflowID: {
				fixture.record.Workflow.CurrentVersion(): workflowVersionRecord(
					fixture.base.tenantUUID, fixture.record.Workflow.Current(),
				),
			},
		},
		replays: map[fakeWorkflowAdminReplayKey]fakeWorkflowAdminReplay{},
	}
}

func (repository *fakeWorkflowAdminRepository) ResolveWorkflowAdminAccess(
	_ context.Context,
	actor Actor,
	tenantID uuid.UUID,
	capability WorkflowAdminCapability,
) (WorkflowAdminAccess, error) {
	repository.accessCalls.Add(1)
	if repository.accessOverride != nil {
		return *repository.accessOverride, nil
	}
	return NewWorkflowAdminAccess(tenantID, actor.UserID, capability, repository.principal, repository.allowed)
}

func (repository *fakeWorkflowAdminRepository) ReserveWorkflowID(
	_ context.Context,
	_ uuid.UUID,
) (kernel.EntityID, error) {
	value, err := uuid.NewV7()
	if err != nil {
		return kernel.EntityID{}, err
	}
	return entityID(value)
}

func (repository *fakeWorkflowAdminRepository) ListWorkflows(
	_ context.Context,
	_ Actor,
	_ uuid.UUID,
	_ WorkflowAdminListInput,
	_ WorkflowAdminAccess,
) (WorkflowAdminPage, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.listOverride != nil {
		return *repository.listOverride, nil
	}
	page := WorkflowAdminPage{}
	for _, record := range repository.records {
		page.Items = append(page.Items, record)
	}
	sort.Slice(page.Items, func(left, right int) bool {
		return strings.Compare(page.Items[left].Workflow.ID().String(), page.Items[right].Workflow.ID().String()) < 0
	})
	return page, nil
}

func (repository *fakeWorkflowAdminRepository) GetWorkflow(
	_ context.Context,
	_ Actor,
	_ uuid.UUID,
	workflowID uuid.UUID,
	_ WorkflowAdminAccess,
) (WorkflowAdminRecord, error) {
	repository.getCalls.Add(1)
	repository.mu.Lock()
	record, found := repository.records[workflowID]
	if repository.synchronizeGets > 0 {
		repository.getArrivals++
		if repository.getArrivals == repository.synchronizeGets && !repository.getGateClosed {
			close(repository.getGate)
			repository.getGateClosed = true
		}
		gate := repository.getGate
		repository.mu.Unlock()
		<-gate
	} else {
		repository.mu.Unlock()
	}
	if !found {
		return WorkflowAdminRecord{}, ErrNotFound
	}
	return record, nil
}

func (repository *fakeWorkflowAdminRepository) GetDefaultWorkflow(
	_ context.Context,
	_ Actor,
	_ uuid.UUID,
	kind kernel.AggregateKind,
	_ WorkflowAdminAccess,
) (WorkflowAdminRecord, bool, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	for _, record := range repository.records {
		if record.Workflow.Kind() == kind && record.Workflow.IsDefault() {
			return record, true, nil
		}
	}
	return WorkflowAdminRecord{}, false, nil
}

func (repository *fakeWorkflowAdminRepository) ListWorkflowVersions(
	_ context.Context,
	_ Actor,
	_ uuid.UUID,
	workflowID uuid.UUID,
	input WorkflowVersionListInput,
	_ WorkflowAdminAccess,
) (WorkflowVersionPage, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.versionPageOverride != nil {
		return *repository.versionPageOverride, nil
	}
	versions := repository.versions[workflowID]
	page := WorkflowVersionPage{}
	for version, record := range versions {
		if input.AfterVersion == 0 || version < input.AfterVersion {
			page.Items = append(page.Items, record)
		}
	}
	sort.Slice(page.Items, func(left, right int) bool {
		return page.Items[left].Definition.Version() > page.Items[right].Definition.Version()
	})
	if len(page.Items) > input.Limit {
		page.Items = page.Items[:input.Limit]
		page.NextVersion = page.Items[len(page.Items)-1].Definition.Version()
	}
	return page, nil
}

func (repository *fakeWorkflowAdminRepository) GetWorkflowVersion(
	_ context.Context,
	_ Actor,
	_ uuid.UUID,
	workflowID uuid.UUID,
	version uint64,
	_ WorkflowAdminAccess,
) (WorkflowVersionRecord, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	record, found := repository.versions[workflowID][version]
	if !found {
		return WorkflowVersionRecord{}, ErrNotFound
	}
	return record, nil
}

func (repository *fakeWorkflowAdminRepository) LookupWorkflowAdminReplay(
	_ context.Context,
	query WorkflowAdminReplayQuery,
) (WorkflowAdminMutationResult, bool, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := fakeWorkflowAdminReplayKey{
		tenant: query.TenantID, actor: query.ActorID, action: query.Action, hash: query.KeyHash,
	}
	replay, found := repository.replays[key]
	if !found {
		return WorkflowAdminMutationResult{}, false, nil
	}
	if replay.fingerprint != query.Fingerprint {
		return WorkflowAdminMutationResult{}, false, ErrConflict
	}
	return replay.result, true, nil
}

func (repository *fakeWorkflowAdminRepository) CommitWorkflow(
	_ context.Context,
	write WorkflowAdminWrite,
) (WorkflowAdminMutationResult, error) {
	repository.commitAttempts.Add(1)
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if write.RequiredCapability != WorkflowCapabilityManage || repository.revokeAtCommit {
		return WorkflowAdminMutationResult{}, ErrForbidden
	}
	next := write.Plan.Next()
	tenantID := uuidFromEntity(next.Tenant())
	workflowID := uuidFromEntity(next.ID())
	replayKey := fakeWorkflowAdminReplayKey{
		tenant: tenantID, actor: write.Actor.UserID, action: write.Command.Action, hash: write.Command.KeyHash,
	}
	if replay, found := repository.replays[replayKey]; found {
		if replay.fingerprint != write.Command.Fingerprint {
			return WorkflowAdminMutationResult{}, ErrConflict
		}
		result := replay.result
		result.Replayed = true
		return result, nil
	}

	current, exists := repository.records[workflowID]
	if write.Plan.Action() == kernel.WorkflowAdministrationCreate {
		if exists || write.Plan.ExpectedRevision() != 0 {
			return WorkflowAdminMutationResult{}, ErrConflict
		}
	} else if !exists || current.Workflow.Revision() != write.Plan.ExpectedRevision() {
		return WorkflowAdminMutationResult{}, ErrPreconditionFailed
	}

	displaced, displacedRevision, hasDisplaced := write.Plan.DisplacedDefault()
	var displacedID uuid.UUID
	var displacedRecord WorkflowAdminRecord
	if hasDisplaced {
		displacedID = uuidFromEntity(displaced.ID())
		stored, found := repository.records[displacedID]
		if !found || stored.Workflow.Revision() != displacedRevision {
			return WorkflowAdminMutationResult{}, ErrPreconditionFailed
		}
		displacedRecord = repository.recordForCommit(stored, displaced)
	}
	if write.Plan.PublishesDefinition() {
		version := next.CurrentVersion()
		if _, duplicate := repository.versions[workflowID][version]; duplicate {
			return WorkflowAdminMutationResult{}, ErrConflict
		}
	}

	record := repository.recordForCommit(current, next)
	if hasDisplaced {
		repository.records[displacedID] = displacedRecord
	}
	repository.records[workflowID] = record
	if write.Plan.PublishesDefinition() {
		if repository.versions[workflowID] == nil {
			repository.versions[workflowID] = map[uint64]WorkflowVersionRecord{}
		}
		version := next.CurrentVersion()
		repository.versions[workflowID][version] = workflowVersionRecord(tenantID, next.Current())
	}
	result := WorkflowAdminMutationResult{Record: record}
	repository.replays[replayKey] = fakeWorkflowAdminReplay{
		fingerprint: write.Command.Fingerprint, result: result,
	}
	repository.successfulCommits.Add(1)
	return result, nil
}

func (repository *fakeWorkflowAdminRepository) recordForCommit(
	current WorkflowAdminRecord,
	next kernel.ManagedWorkflow,
) WorkflowAdminRecord {
	createdAt := current.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	}
	updatedAt := createdAt.Add(time.Duration(next.Revision()) * time.Second)
	result := WorkflowAdminRecord{Workflow: next, CreatedAt: createdAt, UpdatedAt: updatedAt}
	if next.Status() == kernel.WorkflowArchived {
		archivedAt := updatedAt
		result.ArchivedAt = &archivedAt
	}
	return result
}
