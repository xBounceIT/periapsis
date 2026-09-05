package ticketing

import (
	"errors"
	"strings"
	"testing"
)

func TestWorkflowAdministrationPlansPreserveImmutablePublicationHistory(t *testing.T) {
	versionOne := workflowWithVersion(t, alertWorkflowFixture(t), fixtureID(510), 1, true)
	creation, err := PlanWorkflowCreation(
		fixtureID(1), mustKey(t, "alert_response"), "Alert response", "Primary alert workflow", versionOne,
	)
	if err != nil {
		t.Fatalf("PlanWorkflowCreation: %v", err)
	}
	created := creation.Next()
	if creation.Action() != WorkflowAdministrationCreate || creation.ExpectedRevision() != 0 ||
		!creation.PublishesDefinition() || created.Revision() != 1 || created.CurrentVersion() != 1 ||
		created.IsDefault() || created.Status() != WorkflowActive {
		t.Fatalf("unexpected create plan: %s / %s", creation, created)
	}

	versionTwo := workflowWithVersion(t, versionOne, versionOne.ID(), 2, false)
	publish, err := PlanWorkflowPublication(created, 1, versionTwo)
	if err != nil {
		t.Fatalf("PlanWorkflowPublication: %v", err)
	}
	published := publish.Next()
	if publish.Action() != WorkflowAdministrationPublish || !publish.PublishesDefinition() ||
		publish.ExpectedRevision() != 1 || published.Revision() != 2 || published.CurrentVersion() != 2 {
		t.Fatalf("unexpected publish plan: %s / %s", publish, published)
	}
	if created.CurrentVersion() != 1 || sameWorkflowDesign(created.current, published.current) {
		t.Fatal("publication mutated the pinned prior version")
	}

	if _, err = PlanWorkflowPublication(created, 2, versionTwo); !errors.Is(err, ErrWorkflowRevisionConflict) {
		t.Fatalf("stale publication error = %v", err)
	}
	unchanged := workflowWithVersion(t, versionOne, versionOne.ID(), 2, true)
	if _, err = PlanWorkflowPublication(created, 1, unchanged); !errors.Is(err, ErrWorkflowNoChange) {
		t.Fatalf("no-op publication error = %v", err)
	}
	wrongVersion := workflowWithVersion(t, versionOne, versionOne.ID(), 3, false)
	if _, err = PlanWorkflowPublication(created, 1, wrongVersion); !errors.Is(err, ErrInvalidWorkflowAdministration) {
		t.Fatalf("skipped publication version error = %v", err)
	}
}

func TestWorkflowAdministrationMetadataLifecycleAndDefaultSwap(t *testing.T) {
	target := managedWorkflowFixture(t, fixtureID(520), false, WorkflowActive, 4)
	metadata, err := PlanWorkflowMetadataUpdate(target, 4, "Alert response v2", "Updated description")
	if err != nil {
		t.Fatalf("PlanWorkflowMetadataUpdate: %v", err)
	}
	if metadata.Next().Revision() != 5 || metadata.Next().CurrentVersion() != target.CurrentVersion() ||
		metadata.PublishesDefinition() {
		t.Fatalf("metadata update changed publication identity: %s", metadata)
	}
	if strings.Contains(metadata.Next().String(), "Alert response") ||
		strings.Contains(metadata.Next().String(), "Updated description") {
		t.Fatalf("ManagedWorkflow.String leaked metadata: %q", metadata.Next().String())
	}
	if _, err = PlanWorkflowMetadataUpdate(target, 4, target.DisplayName(), target.Description()); !errors.Is(err, ErrWorkflowNoChange) {
		t.Fatalf("no-op metadata error = %v", err)
	}

	previous := managedWorkflowFixture(t, fixtureID(521), true, WorkflowActive, 9)
	setDefault, err := PlanWorkflowSetDefault(target, 4, &previous)
	if err != nil {
		t.Fatalf("PlanWorkflowSetDefault: %v", err)
	}
	displaced, expected, found := setDefault.DisplacedDefault()
	if !found || expected != 9 || !setDefault.Next().IsDefault() || displaced.IsDefault() ||
		setDefault.Next().Revision() != 5 || displaced.Revision() != 10 {
		t.Fatalf("unexpected default swap plan: %s", setDefault)
	}
	if _, err = PlanWorkflowArchive(setDefault.Next(), 5); !errors.Is(err, ErrWorkflowDefaultArchive) {
		t.Fatalf("archive default error = %v", err)
	}

	archive, err := PlanWorkflowArchive(target, 4)
	if err != nil {
		t.Fatalf("PlanWorkflowArchive: %v", err)
	}
	if archive.Next().Status() != WorkflowArchived || archive.Next().Revision() != 5 {
		t.Fatalf("unexpected archive plan: %s", archive)
	}
	if _, err = PlanWorkflowPublication(archive.Next(), 5, workflowWithVersion(t, target.Current(), target.ID(), 2, false)); !errors.Is(err, ErrWorkflowInactive) {
		t.Fatalf("publish archived error = %v", err)
	}
	restore, err := PlanWorkflowRestore(archive.Next(), 5)
	if err != nil || restore.Next().Status() != WorkflowActive || restore.Next().Revision() != 6 ||
		restore.Next().IsDefault() {
		t.Fatalf("unexpected restore plan: %s / %v", restore, err)
	}
}

func TestWorkflowAdministrationRejectsCrossTenantAndInvalidDefaultDisplacement(t *testing.T) {
	target := managedWorkflowFixture(t, fixtureID(530), false, WorkflowActive, 2)
	tests := []struct {
		name     string
		previous ManagedWorkflow
	}{
		{"cross tenant", managedWorkflowForTenant(t, fixtureID(2), fixtureID(531), true, WorkflowActive, 3)},
		{"cross kind", managedCaseWorkflowFixture(t, fixtureID(532), true, 3)},
		{"not default", managedWorkflowFixture(t, fixtureID(533), false, WorkflowActive, 3)},
		{"archived", managedWorkflowFixture(t, fixtureID(534), false, WorkflowArchived, 3)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := PlanWorkflowSetDefault(target, 2, &test.previous); !errors.Is(err, ErrInvalidWorkflowAdministration) {
				t.Fatalf("PlanWorkflowSetDefault error = %v", err)
			}
		})
	}
}

func TestWorkflowAdministrationOwnsReturnedGraphs(t *testing.T) {
	managed := managedWorkflowFixture(t, fixtureID(540), false, WorkflowActive, 2)
	plan, err := PlanWorkflowMetadataUpdate(managed, 2, "Renamed", managed.Description())
	if err != nil {
		t.Fatal(err)
	}
	first := plan.Next()
	mutatedIndex := -1
	for index := range first.current.states {
		if len(first.current.states[index].actions) > 0 {
			mutatedIndex = index
			first.current.states[index].actions = nil
			break
		}
	}
	if mutatedIndex < 0 {
		t.Fatal("fixture has no state actions")
	}
	second := plan.Next()
	if len(second.current.states[mutatedIndex].actions) == 0 {
		t.Fatal("plan exposed mutable workflow state")
	}
}

func FuzzWorkflowAdministrationRejectsHostileCatalogMetadata(f *testing.F) {
	for _, seed := range []struct {
		key         string
		displayName string
		description string
	}{
		{key: "alert_response", displayName: "Alert response", description: "Primary"},
		{key: "a", displayName: "Short key", description: ""},
		{key: "alert-response", displayName: "Hyphenated key", description: ""},
		{key: "alert_response", displayName: "", description: "Missing name"},
		{key: "alert_response", displayName: " Directional\u202e", description: ""},
		{key: "\x00", displayName: "Control", description: "\x00"},
	} {
		f.Add(seed.key, seed.displayName, seed.description)
	}
	f.Fuzz(func(t *testing.T, rawKey, displayName, description string) {
		definition := workflowWithVersion(t, alertWorkflowFixture(t), fixtureID(550), 1, true)
		key, keyErr := NewKey(rawKey)
		plan, err := PlanWorkflowCreation(
			fixtureID(1), key, displayName, description, definition,
		)
		valid := keyErr == nil && validWorkflowCatalogKey(key) &&
			validText(displayName, maxWorkflowDisplayNameBytes, false) &&
			validOptionalWorkflowText(description, maxWorkflowDescriptionBytes)
		if valid != (err == nil) {
			t.Fatalf("PlanWorkflowCreation(%q,%q) error=%v, valid=%t", rawKey, displayName, err, valid)
		}
		if err == nil {
			next := plan.Next()
			if next.Key() != key || next.DisplayName() != displayName || next.Description() != description ||
				!strings.Contains(next.String(), "metadata:[REDACTED]") {
				t.Fatalf("successful plan did not preserve/redact validated metadata: %s", next)
			}
		}
	})
}

func managedWorkflowFixture(
	t testing.TB,
	id EntityID,
	isDefault bool,
	status WorkflowStatus,
	revision uint64,
) ManagedWorkflow {
	t.Helper()
	return managedWorkflowForTenant(t, fixtureID(1), id, isDefault, status, revision)
}

func managedWorkflowForTenant(
	t testing.TB,
	tenant EntityID,
	id EntityID,
	isDefault bool,
	status WorkflowStatus,
	revision uint64,
) ManagedWorkflow {
	t.Helper()
	definition := workflowWithVersion(t, alertWorkflowFixture(t), id, 1, true)
	workflow, err := NewManagedWorkflow(
		tenant, mustKey(t, "alert_response"), "Alert response", "Primary alert workflow",
		isDefault, status, revision, definition,
	)
	if err != nil {
		t.Fatalf("NewManagedWorkflow: %v", err)
	}
	return workflow
}

func managedCaseWorkflowFixture(t testing.TB, id EntityID, isDefault bool, revision uint64) ManagedWorkflow {
	t.Helper()
	definition := workflowWithVersion(t, caseWorkflowFixture(t), id, 1, true)
	workflow, err := NewManagedWorkflow(
		fixtureID(1), mustKey(t, "case_response"), "Case response", "Primary Case workflow",
		isDefault, WorkflowActive, revision, definition,
	)
	if err != nil {
		t.Fatalf("NewManagedWorkflow(case): %v", err)
	}
	return workflow
}

func workflowWithVersion(
	t testing.TB,
	source WorkflowDefinition,
	id EntityID,
	version uint64,
	preserveDesign bool,
) WorkflowDefinition {
	t.Helper()
	states := source.States()
	if !preserveDesign {
		for index, state := range states {
			if state.Initial() || state.Terminal() {
				continue
			}
			visibility := VisibilityCustomer
			if state.Visibility() == VisibilityCustomer {
				visibility = VisibilityInternal
			}
			changed, err := NewStateDefinition(
				state.Key(), state.Initial(), state.Terminal(), visibility, state.Actions(),
			)
			if err != nil {
				t.Fatalf("NewStateDefinition: %v", err)
			}
			states[index] = changed
			break
		}
	}
	definition, err := NewWorkflowDefinition(id, source.Kind(), version, states, source.Transitions())
	if err != nil {
		t.Fatalf("NewWorkflowDefinition: %v", err)
	}
	return definition
}
