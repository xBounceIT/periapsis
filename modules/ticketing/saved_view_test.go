package ticketing

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	customfields "github.com/periapsis-im/periapsis/modules/customfields"
)

func TestSavedViewCanonicalSpecPinsDynamicSemanticsAndOwnsInputs(t *testing.T) {
	tenant := fixtureID(1)
	custom := savedViewCustomFilterFixture(
		t, tenant, AggregateAlert, fixtureID(610), customfields.TypeDecimal, json.RawMessage(`10.500`),
	)
	states := []Key{mustKey(t, "triage"), mustKey(t, "new")}
	severities := []string{"high", "low"}
	visible := true
	filters, err := NewSavedViewFilters(SavedViewFiltersInput{
		States: states, Severities: severities, Priorities: []string{"urgent"},
		Queue: SavedViewQueueMyOperatorTeams, CustomerVisible: &visible,
		Search: "bounded incident search", Custom: []SavedViewCustomFilter{custom},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := filters.States(); got[0].String() != "new" || got[1].String() != "triage" {
		t.Fatalf("states are not canonical: %#v", got)
	}
	if got := filters.Severities(); got[0] != "high" || got[1] != "low" {
		t.Fatalf("severities are not canonical: %#v", got)
	}
	states[0] = mustKey(t, "closed")
	severities[0] = "critical"
	visible = false
	if filters.States()[1].String() != "triage" || filters.Severities()[0] != "high" ||
		filters.CustomerVisible() == nil || !*filters.CustomerVisible() {
		t.Fatal("saved-view filters retained caller-owned storage")
	}

	ticketColumn := mustSavedViewCoreColumn(t, "ticket", 360, true, SavedViewColumnPinnedStart)
	updatedColumn := mustSavedViewCoreColumn(t, "updated", 200, true, SavedViewColumnUnpinned)
	customColumn, err := NewSavedViewDynamicColumn(
		SavedViewColumnCustomField, custom.Definition(), 180, true, SavedViewColumnUnpinned,
	)
	if err != nil {
		t.Fatal(err)
	}
	sort, err := NewSavedViewCoreSort(mustKey(t, "updated_at"), SavedViewSortDescending)
	if err != nil {
		t.Fatal(err)
	}
	columns := []SavedViewColumn{ticketColumn, customColumn, updatedColumn}
	spec, err := NewSavedViewSpec(tenant, AggregateAlert, filters, sort, columns)
	if err != nil {
		t.Fatal(err)
	}
	columns[0] = updatedColumn
	projected := spec.Columns()
	projected[0] = updatedColumn
	if spec.Columns()[0].Identifier() != "core:ticket" {
		t.Fatal("saved-view spec leaked mutable column storage")
	}
	customProjection := spec.Filters().Custom()
	customProjection[0].canonical[0] = '0'
	if string(spec.Filters().Custom()[0].CanonicalJSON()) != "10.5" {
		t.Fatal("saved-view spec leaked mutable canonical filter JSON")
	}

	creation, err := PlanSavedViewCreation(
		fixtureID(620), tenant, fixtureID(621), AggregateAlert,
		"SOC high-risk queue", spec,
	)
	if err != nil {
		t.Fatal(err)
	}
	created := creation.Next()
	if creation.Action() != SavedViewCreate || creation.ExpectedRevision() != 0 ||
		created.Revision() != 1 || created.Status() != SavedViewActive {
		t.Fatalf("unexpected saved-view creation: %s / %s", creation, created)
	}
	for _, secret := range []string{"SOC high-risk queue", "bounded incident search", "10.5"} {
		for _, rendered := range []string{
			fmt.Sprintf("%#v", custom), fmt.Sprintf("%#v", filters),
			fmt.Sprintf("%#v", spec), fmt.Sprintf("%#v", creation),
			fmt.Sprintf("%#v", created), fmt.Sprintf("%#v", SavedViewFiltersInput{
				Queue: SavedViewQueueAll, Search: "bounded incident search",
				Custom: []SavedViewCustomFilter{custom},
			}),
		} {
			if strings.Contains(rendered, secret) {
				t.Fatalf("saved-view diagnostic leaked %q: %s", secret, rendered)
			}
		}
	}
}

func TestRestoreSavedViewCustomFilterRevalidatesCanonicalPin(t *testing.T) {
	tenant := fixtureID(1)
	original := savedViewCustomFilterFixture(
		t, tenant, AggregateAlert, fixtureID(625), customfields.TypeDecimal,
		json.RawMessage(`10.500`),
	)
	restored, err := RestoreSavedViewCustomFilter(
		original.Definition(), original.DataType(), original.CanonicalJSON(),
	)
	if err != nil || restored.Definition() != original.Definition() ||
		restored.DataType() != original.DataType() ||
		string(restored.CanonicalJSON()) != "10.5" {
		t.Fatalf("RestoreSavedViewCustomFilter() = %s, %v", restored, err)
	}

	for _, malformed := range []struct {
		name      string
		dataType  customfields.DataType
		canonical json.RawMessage
	}{
		{name: "noncanonical decimal", dataType: customfields.TypeDecimal, canonical: json.RawMessage(`10.500`)},
		{name: "collection", dataType: customfields.TypeMultiSelect, canonical: json.RawMessage(`["one"]`)},
		{name: "null", dataType: customfields.TypeDecimal, canonical: json.RawMessage(`null`)},
	} {
		t.Run(malformed.name, func(t *testing.T) {
			if _, restoreErr := RestoreSavedViewCustomFilter(
				original.Definition(), malformed.dataType, malformed.canonical,
			); !errors.Is(restoreErr, ErrInvalidSavedView) {
				t.Fatalf("restore error = %v", restoreErr)
			}
		})
	}
}

func TestSavedViewSpecRejectsCrossTenantDriftAndUnsafeLayouts(t *testing.T) {
	tenant := fixtureID(1)
	filters, err := NewSavedViewFilters(SavedViewFiltersInput{Queue: SavedViewQueueAll})
	if err != nil {
		t.Fatal(err)
	}
	sort, err := NewSavedViewCoreSort(mustKey(t, "updated_at"), SavedViewSortDescending)
	if err != nil {
		t.Fatal(err)
	}
	ticket := mustSavedViewCoreColumn(t, "ticket", 0, true, SavedViewColumnPinnedStart)
	updated := mustSavedViewCoreColumn(t, "updated", 0, true, SavedViewColumnUnpinned)

	if _, err = NewSavedViewSpec(
		tenant, AggregateAlert, SavedViewFilters{}, sort, []SavedViewColumn{ticket},
	); !errors.Is(err, ErrInvalidSavedView) {
		t.Fatalf("zero filter value error = %v", err)
	}
	if _, err = NewSavedViewSpec(
		tenant, AggregateAlert, filters, sort, []SavedViewColumn{updated},
	); !errors.Is(err, ErrInvalidSavedView) {
		t.Fatalf("identity-less layout error = %v", err)
	}
	if _, err = NewSavedViewSpec(
		tenant, AggregateAlert, filters, sort, []SavedViewColumn{ticket, ticket},
	); !errors.Is(err, ErrInvalidSavedView) {
		t.Fatalf("duplicate column error = %v", err)
	}

	foreignPin, err := NewSavedViewDefinitionPin(
		fixtureID(630), fixtureID(2), AggregateAlert, mustKey(t, "risk_score"), 2,
		sha256.Sum256([]byte("foreign-definition")),
	)
	if err != nil {
		t.Fatal(err)
	}
	foreignColumn, err := NewSavedViewDynamicColumn(
		SavedViewColumnCustomField, foreignPin, 0, true, SavedViewColumnUnpinned,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewSavedViewSpec(
		tenant, AggregateAlert, filters, sort, []SavedViewColumn{ticket, foreignColumn},
	); !errors.Is(err, ErrInvalidSavedView) {
		t.Fatalf("cross-tenant dynamic column error = %v", err)
	}

	localPin, err := NewSavedViewDefinitionPin(
		fixtureID(631), tenant, AggregateAlert, mustKey(t, "risk_score"), 2,
		sha256.Sum256([]byte("local-definition")),
	)
	if err != nil {
		t.Fatal(err)
	}
	dynamicSort, err := NewSavedViewDynamicSort(
		SavedViewColumnCustomField, localPin, SavedViewSortDescending, SavedViewNullsLast,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewSavedViewSpec(
		tenant, AggregateAlert, filters, dynamicSort, []SavedViewColumn{ticket},
	); !errors.Is(err, ErrInvalidSavedView) {
		t.Fatalf("unprojected dynamic sort error = %v", err)
	}
	localColumn, err := NewSavedViewDynamicColumn(
		SavedViewColumnCustomField, localPin, 0, true, SavedViewColumnUnpinned,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewSavedViewSpec(
		tenant, AggregateAlert, filters, dynamicSort, []SavedViewColumn{ticket, localColumn},
	); err != nil {
		t.Fatalf("exact projected dynamic sort error = %v", err)
	}
	newerPin, err := NewSavedViewDefinitionPin(
		localPin.ID(), tenant, AggregateAlert, localPin.Key(), localPin.Version()+1,
		sha256.Sum256([]byte("newer-local-definition")),
	)
	if err != nil {
		t.Fatal(err)
	}
	newerColumn, err := NewSavedViewDynamicColumn(
		SavedViewColumnCustomField, newerPin, 0, true, SavedViewColumnUnpinned,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewSavedViewSpec(
		tenant, AggregateAlert, filters, sort,
		[]SavedViewColumn{ticket, localColumn, newerColumn},
	); !errors.Is(err, ErrInvalidSavedView) {
		t.Fatalf("duplicate definition across versions error = %v", err)
	}
	driftedPin, err := NewSavedViewDefinitionPin(
		localPin.ID(), tenant, AggregateAlert, localPin.Key(), localPin.Version(),
		sha256.Sum256([]byte("drifted-local-definition")),
	)
	if err != nil {
		t.Fatal(err)
	}
	driftedSort, err := NewSavedViewDynamicSort(
		SavedViewColumnCustomField, driftedPin, SavedViewSortDescending, SavedViewNullsLast,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewSavedViewSpec(
		tenant, AggregateAlert, filters, driftedSort, []SavedViewColumn{ticket, localColumn},
	); !errors.Is(err, ErrInvalidSavedView) {
		t.Fatalf("sort/column digest drift error = %v", err)
	}

	caseFilter := savedViewCustomFilterFixture(
		t, tenant, AggregateCase, fixtureID(632), customfields.TypeShortText, json.RawMessage(`"case"`),
	)
	caseFilters, err := NewSavedViewFilters(SavedViewFiltersInput{
		Queue: SavedViewQueueAll, Custom: []SavedViewCustomFilter{caseFilter},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewSavedViewSpec(
		tenant, AggregateAlert, caseFilters, sort, []SavedViewColumn{ticket},
	); !errors.Is(err, ErrInvalidSavedView) {
		t.Fatalf("cross-kind custom filter error = %v", err)
	}
}

func TestSavedViewSpecRequiresOneExactPinPerDynamicDefinition(t *testing.T) {
	tenant := fixtureID(1)
	filter := savedViewCustomFilterFixture(
		t, tenant, AggregateAlert, fixtureID(635), customfields.TypeDecimal,
		json.RawMessage(`10.5`),
	)
	filters, err := NewSavedViewFilters(SavedViewFiltersInput{
		Queue: SavedViewQueueAll, Custom: []SavedViewCustomFilter{filter},
	})
	if err != nil {
		t.Fatal(err)
	}
	driftedPin, err := NewSavedViewDefinitionPin(
		filter.Definition().ID(), tenant, AggregateAlert, filter.Definition().Key(),
		filter.Definition().Version()+1, sha256.Sum256([]byte("drifted-definition")),
	)
	if err != nil {
		t.Fatal(err)
	}
	driftedColumn, err := NewSavedViewDynamicColumn(
		SavedViewColumnCustomField, driftedPin, 180, true, SavedViewColumnUnpinned,
	)
	if err != nil {
		t.Fatal(err)
	}
	sortPlan, err := NewSavedViewCoreSort(mustKey(t, "updated_at"), SavedViewSortDescending)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewSavedViewSpec(
		tenant, AggregateAlert, filters, sortPlan,
		[]SavedViewColumn{
			mustSavedViewCoreColumn(t, "ticket", 320, true, SavedViewColumnPinnedStart),
			driftedColumn,
		},
	); !errors.Is(err, ErrInvalidSavedView) {
		t.Fatalf("filter/column pin drift error = %v", err)
	}
	replacementPin, err := NewSavedViewDefinitionPin(
		fixtureID(636), tenant, AggregateAlert, filter.Definition().Key(),
		filter.Definition().Version(), sha256.Sum256([]byte("replacement-definition")),
	)
	if err != nil {
		t.Fatal(err)
	}
	replacementColumn, err := NewSavedViewDynamicColumn(
		SavedViewColumnCustomField, replacementPin, 180, true, SavedViewColumnUnpinned,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewSavedViewSpec(
		tenant, AggregateAlert, filters, sortPlan,
		[]SavedViewColumn{
			mustSavedViewCoreColumn(t, "ticket", 320, true, SavedViewColumnPinnedStart),
			replacementColumn,
		},
	); !errors.Is(err, ErrInvalidSavedView) {
		t.Fatalf("filter/column stable-key drift error = %v", err)
	}
	duplicateKeyFilter := savedViewCustomFilterFixture(
		t, tenant, AggregateAlert, fixtureID(637), customfields.TypeDecimal,
		json.RawMessage(`11.5`),
	)
	if _, err = NewSavedViewFilters(SavedViewFiltersInput{
		Queue:  SavedViewQueueAll,
		Custom: []SavedViewCustomFilter{filter, duplicateKeyFilter},
	}); !errors.Is(err, ErrInvalidSavedView) {
		t.Fatalf("duplicate custom-filter stable-key error = %v", err)
	}

	tampered := filter
	tampered.canonical = json.RawMessage(`10.500`)
	if _, err = NewSavedViewFilters(SavedViewFiltersInput{
		Queue: SavedViewQueueAll, Custom: []SavedViewCustomFilter{tampered},
	}); !errors.Is(err, ErrInvalidSavedView) {
		t.Fatalf("noncanonical in-memory filter error = %v", err)
	}
}

func TestSavedViewLifecycleUsesExactOwnerBoundCAS(t *testing.T) {
	view := savedViewFixture(t)
	if _, err := PlanSavedViewReplacement(
		view, view.Revision()+1, view.Name(), view.Spec(),
	); !errors.Is(err, ErrSavedViewConflict) {
		t.Fatalf("stale replacement error = %v", err)
	}
	if _, err := PlanSavedViewReplacement(
		view, view.Revision(), view.Name(), view.Spec(),
	); !errors.Is(err, ErrSavedViewNoChange) {
		t.Fatalf("no-op replacement error = %v", err)
	}

	filters := view.Spec().Filters()
	changedFilters, err := NewSavedViewFilters(SavedViewFiltersInput{
		States: filters.States(), Severities: filters.Severities(), Priorities: filters.Priorities(),
		AssignedTeam: filters.AssignedTeam(), Assignee: filters.Assignee(), ClaimedBy: filters.ClaimedBy(),
		Queue: SavedViewQueueAssignedToMe, CustomerVisible: filters.CustomerVisible(),
		Search: filters.Search(), Custom: filters.Custom(),
	})
	if err != nil {
		t.Fatal(err)
	}
	changedSpec, err := NewSavedViewSpec(
		view.Tenant(), view.Kind(), changedFilters, view.Spec().Sort(), view.Spec().Columns(),
	)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := PlanSavedViewReplacement(
		view, view.Revision(), "My assigned incidents", changedSpec,
	)
	if err != nil || replacement.Next().Revision() != view.Revision()+1 ||
		replacement.Next().Owner() != view.Owner() || replacement.Next().Tenant() != view.Tenant() {
		t.Fatalf("replacement = (%s, %v)", replacement, err)
	}

	archive, err := PlanSavedViewArchive(replacement.Next(), replacement.Next().Revision())
	if err != nil || archive.Next().Status() != SavedViewArchived {
		t.Fatalf("archive = (%s, %v)", archive, err)
	}
	if _, err := PlanSavedViewArchive(archive.Next(), archive.Next().Revision()); !errors.Is(err, ErrSavedViewInactive) {
		t.Fatalf("double archive error = %v", err)
	}
	restore, err := PlanSavedViewRestore(archive.Next(), archive.Next().Revision())
	if err != nil || restore.Next().Status() != SavedViewActive ||
		restore.Next().Revision() != archive.Next().Revision()+1 {
		t.Fatalf("restore = (%s, %v)", restore, err)
	}
	if _, err := PlanSavedViewRestore(restore.Next(), restore.Next().Revision()); !errors.Is(err, ErrSavedViewAlreadyActive) {
		t.Fatalf("double restore error = %v", err)
	}

	terminal, err := NewSavedView(
		view.ID(), view.Tenant(), view.Owner(), view.Kind(), view.Name(), view.Spec(),
		view.Status(), maxVersion,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = PlanSavedViewArchive(terminal, maxVersion); !errors.Is(err, ErrInvalidSavedView) {
		t.Fatalf("terminal revision archive error = %v", err)
	}
}

func TestSavedViewCustomFilterRejectsCollectionContract(t *testing.T) {
	tenant := fixtureID(1)
	plan := savedViewCustomFilterPlan(
		t, tenant, AggregateAlert, fixtureID(640), customfields.TypeMultiSelect,
		json.RawMessage(`["open"]`),
	)
	if _, err := NewSavedViewCustomFilter(
		plan, 1, sha256.Sum256([]byte("multi-select-definition")),
	); !errors.Is(err, ErrInvalidSavedView) {
		t.Fatalf("collection filter error = %v", err)
	}
}

func TestSavedViewFiltersBoundAggregateCanonicalPayload(t *testing.T) {
	tenant := fixtureID(1)
	raw := json.RawMessage(`"` + strings.Repeat("&", 9_998) + `"`)
	filters := make([]SavedViewCustomFilter, 4)
	for index := range filters {
		filters[index] = savedViewCustomFilterFixture(
			t, tenant, AggregateAlert, fixtureID(uint16(670+index)),
			customfields.TypeLongText, raw,
		)
		key := mustKey(t, fmt.Sprintf("large_filter_%d", index))
		pin, err := NewSavedViewDefinitionPin(
			filters[index].Definition().ID(), tenant, AggregateAlert, key,
			filters[index].Definition().Version(),
			sha256.Sum256([]byte("large-filter:"+key.String())),
		)
		if err != nil {
			t.Fatal(err)
		}
		filters[index].definition = pin
	}
	if _, err := NewSavedViewFilters(SavedViewFiltersInput{
		Queue: SavedViewQueueAll, Custom: filters[:3],
	}); err != nil {
		t.Fatalf("bounded aggregate custom filters error = %v", err)
	}
	if _, err := NewSavedViewFilters(SavedViewFiltersInput{
		Queue: SavedViewQueueAll, Custom: filters,
	}); !errors.Is(err, ErrInvalidSavedView) {
		t.Fatalf("oversized aggregate custom filters error = %v", err)
	}
}

func savedViewFixture(t testing.TB) SavedView {
	t.Helper()
	tenant := fixtureID(1)
	filters, err := NewSavedViewFilters(SavedViewFiltersInput{
		Queue: SavedViewQueueAll, Search: "incident",
	})
	if err != nil {
		t.Fatal(err)
	}
	sort, err := NewSavedViewCoreSort(mustKey(t, "updated_at"), SavedViewSortDescending)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := NewSavedViewSpec(
		tenant, AggregateAlert, filters, sort,
		[]SavedViewColumn{
			mustSavedViewCoreColumn(t, "ticket", 360, true, SavedViewColumnPinnedStart),
			mustSavedViewCoreColumn(t, "updated", 200, true, SavedViewColumnUnpinned),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanSavedViewCreation(
		fixtureID(650), tenant, fixtureID(651), AggregateAlert, "My incidents", spec,
	)
	if err != nil {
		t.Fatal(err)
	}
	return plan.Next()
}

func mustSavedViewCoreColumn(
	t testing.TB,
	key string,
	width uint16,
	visible bool,
	pin SavedViewColumnPin,
) SavedViewColumn {
	t.Helper()
	column, err := NewSavedViewCoreColumn(mustKey(t, key), width, visible, pin)
	if err != nil {
		t.Fatal(err)
	}
	return column
}

func savedViewCustomFilterFixture(
	t testing.TB,
	tenant EntityID,
	kind AggregateKind,
	definitionID EntityID,
	dataType customfields.DataType,
	value json.RawMessage,
) SavedViewCustomFilter {
	t.Helper()
	plan := savedViewCustomFilterPlan(t, tenant, kind, definitionID, dataType, value)
	filter, err := NewSavedViewCustomFilter(
		plan, 7, sha256.Sum256([]byte("custom-definition-v7:"+definitionID.String())),
	)
	if err != nil {
		t.Fatal(err)
	}
	return filter
}

func savedViewCustomFilterPlan(
	t testing.TB,
	tenant EntityID,
	kind AggregateKind,
	definitionID EntityID,
	dataType customfields.DataType,
	value json.RawMessage,
) customfields.FilterPlan {
	t.Helper()
	customTenant, err := customfields.NewEntityID(tenant.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	customDefinitionID, err := customfields.NewEntityID(definitionID.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	key, err := customfields.NewKey("risk_score")
	if err != nil {
		t.Fatal(err)
	}
	objectType := customfields.ObjectAlert
	if kind == AggregateCase {
		objectType = customfields.ObjectCase
	}
	input := customfields.DefinitionInput{
		ID: customDefinitionID, TenantID: customTenant, ObjectType: objectType,
		Key: key, Label: "Risk score", DataType: dataType,
		Visibility: customfields.Visibility{Operator: true},
		EditPolicy: customfields.EditPolicy{OperatorCreate: true, OperatorUpdate: true},
		Placement:  customfields.Placement{ShowInList: true},
		Filterable: true, SchemaVersion: 7,
	}
	if dataType == customfields.TypeMultiSelect || dataType == customfields.TypeSingleSelect {
		optionID, optionErr := customfields.NewEntityID(fixtureID(641).Bytes())
		optionKey, keyErr := customfields.NewKey("open")
		if optionErr != nil || keyErr != nil {
			t.Fatalf("custom option fixture: %v / %v", optionErr, keyErr)
		}
		input.Options = []customfields.OptionInput{{ID: optionID, Key: optionKey, Label: "Open", Position: 1}}
	}
	definition, err := customfields.NewDefinition(input)
	if err != nil {
		t.Fatal(err)
	}
	plan, fieldError := customfields.PlanFilter(
		definition,
		customfields.FilterInput{
			Key: key, Operator: customfields.FilterEqual, Value: customfields.JSONInputValue(value),
		},
		customTenant, objectType, customfields.AudienceOperator, customfields.SurfaceList,
	)
	if fieldError != nil {
		t.Fatal(fieldError)
	}
	return plan
}
