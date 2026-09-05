package ticketing

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	customkernel "github.com/periapsis-im/periapsis/modules/customfields"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

func TestRestoreSavedViewRecordValidatesWholePersistenceProjection(t *testing.T) {
	fixture := newSavedViewServiceFixture(t)
	canonical, err := CanonicalSavedViewSpec(
		fixture.base.tenant, kernel.AggregateAlert, fixture.spec,
	)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(canonical)
	stored := SavedViewPersistenceRecord{
		ID:                fixture.viewID,
		TenantID:          fixture.base.tenantUUID,
		OwnerMembershipID: fixture.base.membershipUUID,
		Kind:              "alert",
		Name:              "My incident queue",
		SpecCanonical:     canonical,
		SpecDigest:        digest[:],
		Status:            "active",
		Revision:          1,
		CreatedAt:         time.Date(2026, 8, 26, 10, 0, 0, 0, time.UTC),
		UpdatedAt:         time.Date(2026, 8, 26, 10, 1, 0, 0, time.UTC),
	}
	restored, err := RestoreSavedViewRecord(
		stored.TenantID, stored.OwnerMembershipID, kernel.AggregateAlert, stored,
	)
	if err != nil || restored.View.ID().String() != stored.ID.String() ||
		restored.View.Owner().String() != stored.OwnerMembershipID.String() ||
		restored.SpecDigest != digest || restored.ArchivedAt != nil {
		t.Fatalf("RestoreSavedViewRecord() = %s, %v", restored, err)
	}
	if rendered := fmt.Sprintf("%#v", stored); strings.Contains(rendered, "My incident queue") ||
		strings.Contains(rendered, "malware campaign") {
		t.Fatalf("persistence record diagnostic leaked metadata: %s", rendered)
	}
	hostileDiagnostic := stored
	hostileDiagnostic.Kind = "alert\nforged-log-entry"
	hostileDiagnostic.Status = "active\nforged-log-entry"
	if rendered := fmt.Sprintf("%#v", hostileDiagnostic); strings.Contains(rendered, "forged-log-entry") {
		t.Fatalf("persistence diagnostic admitted log-control metadata: %s", rendered)
	}

	archivedAt := stored.UpdatedAt
	archived := stored
	archived.Status = "archived"
	archived.Revision = 2
	archived.ArchivedAt = &archivedAt
	if result, archiveErr := RestoreSavedViewRecord(
		stored.TenantID, stored.OwnerMembershipID, kernel.AggregateAlert, archived,
	); archiveErr != nil ||
		result.View.Status() != kernel.SavedViewArchived || result.ArchivedAt == nil {
		t.Fatalf("archived RestoreSavedViewRecord() = %s, %v", result, archiveErr)
	}

	tests := []struct {
		name string
		edit func(*SavedViewPersistenceRecord)
	}{
		{name: "digest mismatch", edit: func(value *SavedViewPersistenceRecord) {
			value.SpecDigest = append([]byte(nil), value.SpecDigest...)
			value.SpecDigest[0] ^= 0xff
		}},
		{name: "foreign tenant", edit: func(value *SavedViewPersistenceRecord) {
			value.TenantID = mustUUIDv7(t)
		}},
		{name: "foreign owner", edit: func(value *SavedViewPersistenceRecord) {
			value.OwnerMembershipID = mustUUIDv7(t)
		}},
		{name: "wrong kind", edit: func(value *SavedViewPersistenceRecord) { value.Kind = "incident" }},
		{name: "active with archived timestamp", edit: func(value *SavedViewPersistenceRecord) {
			value.ArchivedAt = &archivedAt
		}},
		{name: "archive before creation", edit: func(value *SavedViewPersistenceRecord) {
			value.Status = "archived"
			before := value.CreatedAt.Add(-time.Second)
			value.ArchivedAt = &before
		}},
		{name: "archive timestamp drift", edit: func(value *SavedViewPersistenceRecord) {
			value.Status = "archived"
			drifted := value.UpdatedAt.Add(-time.Second)
			value.ArchivedAt = &drifted
		}},
		{name: "sub-microsecond timestamp", edit: func(value *SavedViewPersistenceRecord) {
			value.UpdatedAt = value.UpdatedAt.Add(time.Nanosecond)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := stored
			test.edit(&candidate)
			if _, restoreErr := RestoreSavedViewRecord(
				stored.TenantID, stored.OwnerMembershipID, kernel.AggregateAlert, candidate,
			); restoreErr != ErrUnavailable {
				t.Fatalf("restore error = %v", restoreErr)
			}
		})
	}
}

func TestRestoreSavedViewSpecRoundTripsExactDynamicSemantics(t *testing.T) {
	fixture := newSavedViewServiceFixture(t)
	definitionID, err := kernel.NewEntityID(mustUUIDv7(t))
	if err != nil {
		t.Fatal(err)
	}
	key, err := kernel.NewKey("risk_score")
	if err != nil {
		t.Fatal(err)
	}
	pin, err := kernel.NewSavedViewDefinitionPin(
		definitionID, fixture.base.tenant, kernel.AggregateAlert, key, 7,
		sha256.Sum256([]byte("risk-score-definition-v7")),
	)
	if err != nil {
		t.Fatal(err)
	}
	filter, err := kernel.RestoreSavedViewCustomFilter(
		pin, customkernel.TypeDecimal, []byte(`10.5`),
	)
	if err != nil {
		t.Fatal(err)
	}
	filters, err := kernel.NewSavedViewFilters(kernel.SavedViewFiltersInput{
		Queue:  kernel.SavedViewQueueMyOperatorTeams,
		Custom: []kernel.SavedViewCustomFilter{filter},
	})
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := kernel.NewSavedViewCoreColumn(
		mustApplicationTicketKey(t, "ticket"), 320, true, kernel.SavedViewColumnPinnedStart,
	)
	if err != nil {
		t.Fatal(err)
	}
	dynamic, err := kernel.NewSavedViewDynamicColumn(
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
		[]kernel.SavedViewColumn{ticket, dynamic},
	)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalSavedViewSpec(fixture.base.tenant, kernel.AggregateAlert, spec)
	if err != nil {
		t.Fatal(err)
	}
	restored, digest, err := RestoreSavedViewSpec(
		fixture.base.tenantUUID, kernel.AggregateAlert, canonical,
	)
	if err != nil || digest != sha256.Sum256(canonical) {
		t.Fatalf("RestoreSavedViewSpec() error=%v digest=%x", err, digest)
	}
	reencoded, err := CanonicalSavedViewSpec(
		fixture.base.tenant, kernel.AggregateAlert, restored,
	)
	if err != nil || !bytes.Equal(reencoded, canonical) {
		t.Fatalf("restored canonical drift: %s / %v", reencoded, err)
	}
	custom := restored.Filters().Custom()
	if len(custom) != 1 || custom[0].Definition() != pin ||
		string(custom[0].CanonicalJSON()) != "10.5" {
		t.Fatalf("restored custom filter = %#v", custom)
	}
	ownedInput := append([]byte(nil), canonical...)
	ownedSpec, _, err := RestoreSavedViewSpec(
		fixture.base.tenantUUID, kernel.AggregateAlert, ownedInput,
	)
	if err != nil {
		t.Fatal(err)
	}
	ownedInput[0] ^= 0x01
	ownedReencoded, err := CanonicalSavedViewSpec(
		fixture.base.tenant, kernel.AggregateAlert, ownedSpec,
	)
	if err != nil || !bytes.Equal(ownedReencoded, canonical) {
		t.Fatal("restored saved-view spec retained caller-owned canonical bytes")
	}

	invalid := []struct {
		name string
		edit func(string) string
	}{
		{name: "leading whitespace", edit: func(value string) string { return " " + value }},
		{name: "trailing value", edit: func(value string) string { return value + "{}" }},
		{name: "duplicate field", edit: func(value string) string {
			return strings.Replace(value, `{"version":1`, `{"version":1,"version":1`, 1)
		}},
		{name: "nested duplicate field", edit: func(value string) string {
			return strings.Replace(value, `"queue":"my_operator_teams"`, `"queue":"my_operator_teams","queue":"my_operator_teams"`, 1)
		}},
		{name: "unknown field", edit: func(value string) string {
			return strings.Replace(value, `{"version":1`, `{"unknown":true,"version":1`, 1)
		}},
		{name: "noncanonical decimal", edit: func(value string) string {
			return strings.Replace(value, `"value":10.5`, `"value":10.500`, 1)
		}},
		{name: "collection reinterpretation", edit: func(value string) string {
			return strings.Replace(value, `"dataType":"decimal"`, `"dataType":"multi_select"`, 1)
		}},
		{name: "cross usage pin drift", edit: func(value string) string {
			return strings.Replace(
				value, `"key":"risk_score","version":7`,
				`"key":"risk_score","version":8`, 1,
			)
		}},
		{name: "missing dynamic definition", edit: func(value string) string {
			return strings.Replace(value, `"definition":{"id":`, `"definition":null,"ignored":{"id":`, 1)
		}},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			candidate := []byte(test.edit(string(canonical)))
			if bytes.Equal(candidate, canonical) {
				t.Fatal("test mutation did not alter canonical bytes")
			}
			if _, _, restoreErr := RestoreSavedViewSpec(
				fixture.base.tenantUUID, kernel.AggregateAlert, candidate,
			); restoreErr != ErrUnavailable {
				t.Fatalf("restore error = %v", restoreErr)
			}
		})
	}
}

func TestRestoreSavedViewSpecRejectsOversizedShapesBeforeTypedRestoration(t *testing.T) {
	fixture := newSavedViewServiceFixture(t)
	canonical, err := CanonicalSavedViewSpec(
		fixture.base.tenant, kernel.AggregateAlert, fixture.spec,
	)
	if err != nil {
		t.Fatal(err)
	}
	states := make([]string, maximumSavedViewStates+1)
	for index := range states {
		states[index] = fmt.Sprintf("state_%02d", index)
	}
	encodedStates, err := json.Marshal(states)
	if err != nil {
		t.Fatal(err)
	}
	oversized := bytes.Replace(
		canonical, []byte(`"states":[]`),
		append([]byte(`"states":`), encodedStates...), 1,
	)
	if bytes.Equal(oversized, canonical) {
		t.Fatal("oversized-state mutation did not alter canonical bytes")
	}
	if _, _, err := RestoreSavedViewSpec(
		fixture.base.tenantUUID, kernel.AggregateAlert, oversized,
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("oversized saved-view shape error = %v", err)
	}
}

func TestCanonicalSavedViewSpecNormalizesNilAndEmptyFilterSets(t *testing.T) {
	fixture := newSavedViewServiceFixture(t)
	build := func(states []kernel.Key, severities, priorities []string) []byte {
		t.Helper()
		filters, err := kernel.NewSavedViewFilters(kernel.SavedViewFiltersInput{
			States: states, Severities: severities, Priorities: priorities,
			Queue: kernel.SavedViewQueueAll,
		})
		if err != nil {
			t.Fatal(err)
		}
		spec, err := kernel.NewSavedViewSpec(
			fixture.base.tenant, kernel.AggregateAlert, filters,
			fixture.spec.Sort(), fixture.spec.Columns(),
		)
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := CanonicalSavedViewSpec(
			fixture.base.tenant, kernel.AggregateAlert, spec,
		)
		if err != nil {
			t.Fatal(err)
		}
		return canonical
	}
	left := build(nil, nil, nil)
	right := build([]kernel.Key{}, []string{}, []string{})
	if !bytes.Equal(left, right) || !bytes.Contains(left, []byte(`"severities":[]`)) ||
		!bytes.Contains(left, []byte(`"priorities":[]`)) {
		t.Fatalf("empty-set canonical drift: %s / %s", left, right)
	}
}

func FuzzRestoreSavedViewSpecIsCanonicalOrFailsClosed(f *testing.F) {
	fixture := newSavedViewServiceFixture(f)
	canonical, err := CanonicalSavedViewSpec(
		fixture.base.tenant, kernel.AggregateAlert, fixture.spec,
	)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(canonical)
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte(`{"version":1,"version":1}`))

	f.Fuzz(func(t *testing.T, candidate []byte) {
		if len(candidate) > maximumSavedViewSpecBytes+1 {
			return
		}
		restored, digest, restoreErr := RestoreSavedViewSpec(
			fixture.base.tenantUUID, kernel.AggregateAlert, candidate,
		)
		if restoreErr != nil {
			return
		}
		reencoded, encodeErr := CanonicalSavedViewSpec(
			fixture.base.tenant, kernel.AggregateAlert, restored,
		)
		if encodeErr != nil || !bytes.Equal(reencoded, candidate) ||
			digest != sha256.Sum256(candidate) {
			t.Fatalf(
				"accepted noncanonical saved-view document: candidate=%q reencoded=%q digest=%x error=%v",
				candidate, reencoded, digest, encodeErr,
			)
		}
	})
}
