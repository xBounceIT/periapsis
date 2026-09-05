package ticketing

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	customkernel "github.com/periapsis-im/periapsis/modules/customfields"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

func TestNormalizeSavedViewSpecInputAcceptsBoundedLosslessScalarsOnly(t *testing.T) {
	t.Parallel()
	fixture := newSavedViewServiceFixture(t)
	definitionID := mustUUIDv7(t)
	base := fixture.input
	base.Filters.Custom = []SavedViewCustomFilterInput{{
		DefinitionID: definitionID, ExpectedDefinitionVersion: 1,
		Operator: customkernel.FilterEqual,
	}}
	wideText, err := json.Marshal(strings.Repeat("😀", maximumSavedViewScalarRunes))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []json.RawMessage{
		wideText,
		json.RawMessage(strings.Repeat("9", 200)),
		json.RawMessage(`true`),
	} {
		candidate := base
		candidate.Filters.Custom = append([]SavedViewCustomFilterInput(nil), base.Filters.Custom...)
		candidate.Filters.Custom[0].Value = raw
		if _, err := NormalizeSavedViewSpecInput(candidate); err != nil {
			t.Fatalf("bounded scalar %s error = %v", raw[:min(len(raw), 32)], err)
		}
	}
	oversizedText, err := json.Marshal(strings.Repeat("😀", maximumSavedViewScalarRunes+1))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []json.RawMessage{
		nil, json.RawMessage(`null`), json.RawMessage(`[]`), json.RawMessage(`{}`),
		json.RawMessage(strings.Repeat("9", 257)), oversizedText,
	} {
		candidate := base
		candidate.Filters.Custom = append([]SavedViewCustomFilterInput(nil), base.Filters.Custom...)
		candidate.Filters.Custom[0].Value = raw
		if _, err := NormalizeSavedViewSpecInput(candidate); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("hostile scalar length %d error = %v, want invalid input", len(raw), err)
		}
	}
}

func TestSavedViewServiceAccessIsExplicitOperatorRouteIntent(t *testing.T) {
	fixture := newSavedViewServiceFixture(t)
	tests := []struct {
		name      string
		principal kernel.PrincipalKind
		allowed   bool
		want      error
	}{
		{name: "operator", principal: kernel.PrincipalOperator, allowed: true},
		{name: "customer denied", principal: kernel.PrincipalCustomer, allowed: true, want: ErrForbidden},
		{name: "service account denied", principal: kernel.PrincipalServiceAccount, allowed: true, want: ErrForbidden},
		{name: "permission denied", principal: kernel.PrincipalOperator, allowed: false, want: ErrForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := newFakeSavedViewRepository(fixture)
			repository.principal, repository.allowed = test.principal, test.allowed
			service := mustSavedViewService(t, repository)
			_, err := service.ListSavedViews(
				context.Background(), fixture.base.actor, fixture.base.tenantUUID,
				kernel.AggregateAlert, SavedViewListInput{},
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("ListSavedViews() error = %v, want %v", err, test.want)
			}
			if test.want != nil && repository.listCalls.Load() != 0 {
				t.Fatal("denied access reached the saved-view list repository")
			}
		})
	}

	repository := newFakeSavedViewRepository(fixture)
	wrong, err := NewSavedViewAccess(
		fixture.base.tenantUUID, fixture.base.actor.UserID, fixture.base.membershipUUID,
		kernel.AggregateCase, SavedViewCapabilityRead, kernel.PrincipalOperator, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	repository.accessOverride = &wrong
	service := mustSavedViewService(t, repository)
	if _, err := service.ListSavedViews(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, SavedViewListInput{},
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("mismatched route-intent access error = %v", err)
	}
}

func TestSavedViewServiceCreateReplayPrecedesGeneratedIDReservation(t *testing.T) {
	fixture := newSavedViewServiceFixture(t)
	repository := newFakeSavedViewRepository(fixture)
	service := mustSavedViewService(t, repository)
	input := SavedViewCreateInput{
		Name: "My triage queue", Spec: fixture.input,
		IdempotencyKey: "saved-view-create-attempt-0001",
	}
	first, err := service.CreateSavedView(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, input,
	)
	if err != nil || first.Replayed {
		t.Fatalf("first CreateSavedView() = (%s, %v)", first.Record, err)
	}
	second, err := service.CreateSavedView(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, input,
	)
	if err != nil || !second.Replayed || second.Record.View.ID() != first.Record.View.ID() {
		t.Fatalf("replayed CreateSavedView() = (%s, %v)", second.Record, err)
	}
	if repository.reserveCalls.Load() != 1 || repository.commitCalls.Load() != 1 {
		t.Fatalf(
			"create replay performed extra work: reserve=%d commit=%d",
			repository.reserveCalls.Load(), repository.commitCalls.Load(),
		)
	}
	repository.allowed = false
	if _, err := service.CreateSavedView(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, input,
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("revoked exact replay error = %v", err)
	}
	repository.allowed = true

	drifted := input
	drifted.Name = "Different queue"
	if _, err := service.CreateSavedView(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, drifted,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("idempotency payload drift error = %v", err)
	}
	if repository.reserveCalls.Load() != 1 {
		t.Fatal("payload drift reserved a second view ID")
	}
	sensitiveFilter := SavedViewCustomFilterInput{
		DefinitionID: fixture.viewID, ExpectedDefinitionVersion: 1,
		Operator: "eq\nforged-log-entry", Value: []byte(`"sensitive-filter-value"`),
	}
	sensitiveFilters := SavedViewFiltersInput{
		Queue: "all\nforged-log-entry", Search: "sensitive-search-value",
		Custom: []SavedViewCustomFilterInput{sensitiveFilter},
	}
	lifecycle := SavedViewLifecycleInput{
		ExpectedRevision: 1, IdempotencyKey: "sensitive-lifecycle-key",
	}
	listInput := SavedViewListInput{After: "sensitive-cursor", Limit: 20}
	binding, err := bindSavedViewCommand(
		input.IdempotencyKey, kernel.SavedViewCreate, fixture.base.tenantUUID,
		fixture.base.membershipUUID, kernel.AggregateAlert, nil, 0, input.Name,
		&first.Record.SpecDigest,
	)
	if err != nil {
		t.Fatal(err)
	}
	replayQuery := SavedViewReplayQuery{
		TenantID: fixture.base.tenantUUID, ActorID: fixture.base.actor.UserID,
		OwnerMembershipID: fixture.base.membershipUUID, Kind: kernel.AggregateAlert,
		Action: binding.Action, KeyHash: binding.KeyHash, Fingerprint: binding.Fingerprint,
	}
	digestPrefix := fmt.Sprintf("%x", first.Record.SpecDigest[:6])
	for _, secret := range []string{
		"My triage queue", "malware campaign", "saved-view-create-attempt-0001",
		"sensitive-filter-value", "sensitive-search-value", "sensitive-lifecycle-key",
		"sensitive-cursor", "forged-log-entry", digestPrefix,
	} {
		for _, rendered := range []string{
			fmt.Sprintf("%#v", input), fmt.Sprintf("%#v", first),
			fmt.Sprintf("%#v", first.Record), fmt.Sprintf("%#v", sensitiveFilter),
			fmt.Sprintf("%#v", sensitiveFilters), fmt.Sprintf("%#v", lifecycle),
			fmt.Sprintf("%#v", listInput), fmt.Sprintf("%#v", binding),
			fmt.Sprintf("%#v", replayQuery),
		} {
			if strings.Contains(rendered, secret) {
				t.Fatalf("saved-view diagnostic leaked %q: %s", secret, rendered)
			}
		}
	}
}

func TestSavedViewServiceReplaceReplaysBeforeLoadingAdvancedState(t *testing.T) {
	fixture := newSavedViewServiceFixture(t)
	repository := newFakeSavedViewRepository(fixture)
	repository.records[fixture.viewID] = fixture.record
	service := mustSavedViewService(t, repository)
	input := SavedViewReplaceInput{
		ExpectedRevision: 1, Name: "Escalated incidents", Spec: fixture.input,
		ExpectedETag:   SavedViewStrongETag(fixture.record),
		IdempotencyKey: "saved-view-replace-attempt-0001",
	}
	first, err := service.ReplaceSavedView(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, fixture.viewID, input,
	)
	if err != nil || first.Replayed || first.Record.View.Revision() != 2 {
		t.Fatalf("first ReplaceSavedView() = (%s, %v)", first.Record, err)
	}
	getsAfterFirst := repository.getCalls.Load()
	second, err := service.ReplaceSavedView(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, fixture.viewID, input,
	)
	if err != nil || !second.Replayed || second.Record.View.Revision() != 2 {
		t.Fatalf("replayed ReplaceSavedView() = (%s, %v)", second.Record, err)
	}
	if repository.getCalls.Load() != getsAfterFirst {
		t.Fatal("exact replacement replay loaded the already-advanced live aggregate")
	}

	repository.revokeAtCommit = true
	revoked := input
	revoked.ExpectedRevision = 2
	revoked.ExpectedETag = SavedViewStrongETag(repository.records[fixture.viewID])
	revoked.Name = "Revoked mutation"
	revoked.IdempotencyKey = "saved-view-replace-attempt-0002"
	if _, err := service.ReplaceSavedView(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, fixture.viewID, revoked,
	); !errors.Is(err, ErrForbidden) {
		t.Fatalf("commit-time revocation error = %v", err)
	}
}

func TestSavedViewServiceRejectsCrossOwnerAndDigestDivergence(t *testing.T) {
	fixture := newSavedViewServiceFixture(t)
	for _, test := range []struct {
		name   string
		mutate func(*SavedViewRecord)
		want   error
	}{
		{
			name: "foreign owner",
			mutate: func(record *SavedViewRecord) {
				foreign, _ := entityID(mustUUIDv7(t))
				rebuilt, err := kernel.NewSavedView(
					record.View.ID(), record.View.Tenant(), foreign, record.View.Kind(),
					record.View.Name(), record.View.Spec(), record.View.Status(), record.View.Revision(),
				)
				if err != nil {
					t.Fatal(err)
				}
				record.View = rebuilt
			},
			want: ErrNotFound,
		},
		{
			name: "digest drift", mutate: func(record *SavedViewRecord) { record.SpecDigest[0] ^= 0xff },
			want: ErrUnavailable,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := newFakeSavedViewRepository(fixture)
			record := fixture.record
			test.mutate(&record)
			repository.records[fixture.viewID] = record
			service := mustSavedViewService(t, repository)
			if _, err := service.GetSavedView(
				context.Background(), fixture.base.actor, fixture.base.tenantUUID,
				kernel.AggregateAlert, fixture.viewID,
			); !errors.Is(err, test.want) {
				t.Fatalf("GetSavedView() error = %v, want %v", err, test.want)
			}
		})
	}

	repository := newFakeSavedViewRepository(fixture)
	repository.getErr = ErrForbidden
	service := mustSavedViewService(t, repository)
	if _, err := service.GetSavedView(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, fixture.viewID,
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("repository ownership denial error = %v, want not found", err)
	}
}

func TestSavedViewCanonicalSpecDigestIsStableAndLayoutSensitive(t *testing.T) {
	fixture := newSavedViewServiceFixture(t)
	canonical, err := CanonicalSavedViewSpec(
		fixture.base.tenant, kernel.AggregateAlert, fixture.spec,
	)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := SavedViewSpecDigest(fixture.base.tenant, kernel.AggregateAlert, fixture.spec)
	if err != nil || digest != sha256.Sum256(canonical) {
		t.Fatalf("SavedViewSpecDigest() = (%x, %v)", digest, err)
	}
	if !strings.Contains(string(canonical), `"version":1`) ||
		!strings.Contains(string(canonical), `"queue":"all"`) {
		t.Fatalf("unexpected canonical saved-view encoding: %s", canonical)
	}

	columns := fixture.spec.Columns()
	columns[0], columns[1] = columns[1], columns[0]
	reordered, err := kernel.NewSavedViewSpec(
		fixture.base.tenant, kernel.AggregateAlert, fixture.spec.Filters(), fixture.spec.Sort(), columns,
	)
	if err != nil {
		t.Fatal(err)
	}
	reorderedDigest, err := SavedViewSpecDigest(
		fixture.base.tenant, kernel.AggregateAlert, reordered,
	)
	if err != nil || reorderedDigest == digest {
		t.Fatal("column order did not affect the saved-view digest")
	}
}

func TestSavedViewInputValidationFailsBeforeRepositoryResolution(t *testing.T) {
	fixture := newSavedViewServiceFixture(t)
	tests := []struct {
		name   string
		mutate func(*SavedViewSpecInput)
	}{
		{name: "missing columns", mutate: func(input *SavedViewSpecInput) { input.Columns = nil }},
		{name: "unknown queue", mutate: func(input *SavedViewSpecInput) { input.Filters.Queue = "global" }},
		{name: "duplicate severity", mutate: func(input *SavedViewSpecInput) { input.Filters.Severities = []string{"high", "high"} }},
		{name: "core null ordering", mutate: func(input *SavedViewSpecInput) { input.Sort.Nulls = "first" }},
		{name: "malformed dynamic definition", mutate: func(input *SavedViewSpecInput) {
			input.Columns[0].Source = SavedViewDefinitionCustomField
			input.Columns[0].CoreKey = ""
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := newFakeSavedViewRepository(fixture)
			service := mustSavedViewService(t, repository)
			input := fixture.input
			input.Columns = append([]SavedViewColumnInput(nil), fixture.input.Columns...)
			test.mutate(&input)
			_, err := service.CreateSavedView(
				context.Background(), fixture.base.actor, fixture.base.tenantUUID,
				kernel.AggregateAlert,
				SavedViewCreateInput{
					Name: "Invalid view", Spec: input,
					IdempotencyKey: "saved-view-invalid-attempt-0001",
				},
			)
			if !errors.Is(err, ErrInvalidInput) || repository.resolveSpecCalls.Load() != 0 {
				t.Fatalf("CreateSavedView() = %v, resolve calls=%d", err, repository.resolveSpecCalls.Load())
			}
		})
	}
}

func TestSavedViewServiceRejectsTerminalRevisionBeforeRepositoryWork(t *testing.T) {
	fixture := newSavedViewServiceFixture(t)
	repository := newFakeSavedViewRepository(fixture)
	service := mustSavedViewService(t, repository)

	if _, err := service.ReplaceSavedView(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, fixture.viewID,
		SavedViewReplaceInput{
			ExpectedRevision: maxResourceVersion, Name: "Terminal revision",
			Spec: fixture.input, IdempotencyKey: "saved-view-terminal-0001",
		},
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("terminal replacement error = %v", err)
	}
	if _, err := service.ArchiveSavedView(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, fixture.viewID,
		SavedViewLifecycleInput{
			ExpectedRevision: maxResourceVersion,
			IdempotencyKey:   "saved-view-terminal-0002",
		},
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("terminal archive error = %v", err)
	}
	if repository.accessCalls.Load() != 0 || repository.commitCalls.Load() != 0 {
		t.Fatalf(
			"terminal revision reached repository: access=%d commit=%d",
			repository.accessCalls.Load(), repository.commitCalls.Load(),
		)
	}
}

func TestSavedViewServiceArchivesStalePinsAndOwnsReturnedRecords(t *testing.T) {
	fixture := newSavedViewServiceFixture(t)
	repository := newFakeSavedViewRepository(fixture)
	repository.records[fixture.viewID] = fixture.record
	repository.stalePinsAtCommit = true
	service := mustSavedViewService(t, repository)

	archived, err := service.ArchiveSavedView(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, fixture.viewID,
		SavedViewLifecycleInput{
			ExpectedRevision: 1,
			ExpectedETag:     SavedViewStrongETag(fixture.record),
			IdempotencyKey:   "saved-view-stale-archive-0001",
		},
	)
	if err != nil || archived.Record.View.Status() != kernel.SavedViewArchived ||
		archived.Record.ArchivedAt == nil {
		t.Fatalf("ArchiveSavedView() = (%s, %v)", archived, err)
	}
	if repository.resolveSpecCalls.Load() != 0 {
		t.Fatal("stale archive attempted to resolve dynamic definitions")
	}
	storedArchivedAt := *repository.records[fixture.viewID].ArchivedAt
	*archived.Record.ArchivedAt = archived.Record.ArchivedAt.Add(time.Hour)
	if !repository.records[fixture.viewID].ArchivedAt.Equal(storedArchivedAt) {
		t.Fatal("archive response retained the repository-owned ArchivedAt pointer")
	}

	if _, err := service.RestoreSavedView(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, fixture.viewID,
		SavedViewLifecycleInput{
			ExpectedRevision: 2,
			ExpectedETag:     SavedViewStrongETag(repository.records[fixture.viewID]),
			IdempotencyKey:   "saved-view-stale-restore-0001",
		},
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale restore error = %v", err)
	}
	if repository.records[fixture.viewID].View.Status() != kernel.SavedViewArchived {
		t.Fatal("failed stale restore changed the archived record")
	}
}

func TestSavedViewServiceOwnsReturnedListStorage(t *testing.T) {
	fixture := newSavedViewServiceFixture(t)
	repository := newFakeSavedViewRepository(fixture)
	retained := SavedViewPage{Items: []SavedViewRecord{fixture.record}}
	repository.listOverride = &retained
	service := mustSavedViewService(t, repository)

	page, err := service.ListSavedViews(
		context.Background(), fixture.base.actor, fixture.base.tenantUUID,
		kernel.AggregateAlert, SavedViewListInput{},
	)
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("ListSavedViews() = (%s, %v)", page, err)
	}
	page.Items[0] = SavedViewRecord{}
	if retained.Items[0].View.ID() != fixture.record.View.ID() {
		t.Fatal("list response retained the repository-owned item slice")
	}
}

func TestSavedViewServiceCASAllowsOneConcurrentReplacement(t *testing.T) {
	fixture := newSavedViewServiceFixture(t)
	repository := newFakeSavedViewRepository(fixture)
	repository.records[fixture.viewID] = fixture.record
	service := mustSavedViewService(t, repository)

	start := make(chan struct{})
	results := make(chan error, 2)
	for index, name := range []string{"Concurrent view A", "Concurrent view B"} {
		index, name := index, name
		go func() {
			<-start
			_, err := service.ReplaceSavedView(
				context.Background(), fixture.base.actor, fixture.base.tenantUUID,
				kernel.AggregateAlert, fixture.viewID,
				SavedViewReplaceInput{
					ExpectedRevision: 1, Name: name, Spec: fixture.input,
					ExpectedETag:   SavedViewStrongETag(fixture.record),
					IdempotencyKey: fmt.Sprintf("saved-view-concurrent-%04d", index),
				},
			)
			results <- err
		}()
	}
	close(start)
	successes, conflicts := 0, 0
	for range 2 {
		switch err := <-results; {
		case err == nil:
			successes++
		case errors.Is(err, ErrPreconditionFailed):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent replacement error = %v", err)
		}
	}
	if successes != 1 || conflicts != 1 || repository.records[fixture.viewID].View.Revision() != 2 {
		t.Fatalf(
			"concurrent replacements: successes=%d conflicts=%d revision=%d",
			successes, conflicts, repository.records[fixture.viewID].View.Revision(),
		)
	}
}

type savedViewServiceFixture struct {
	base   serviceFixture
	viewID uuid.UUID
	input  SavedViewSpecInput
	spec   kernel.SavedViewSpec
	record SavedViewRecord
}

func newSavedViewServiceFixture(t testing.TB) savedViewServiceFixture {
	t.Helper()
	base := newServiceFixture(t)
	filters, err := kernel.NewSavedViewFilters(kernel.SavedViewFiltersInput{
		Queue: kernel.SavedViewQueueAll, Search: "malware campaign",
	})
	if err != nil {
		t.Fatal(err)
	}
	sortValue, err := kernel.NewSavedViewCoreSort(mustApplicationTicketKey(t, "updated_at"), kernel.SavedViewSortDescending)
	if err != nil {
		t.Fatal(err)
	}
	ticketColumn, err := kernel.NewSavedViewCoreColumn(
		mustApplicationTicketKey(t, "ticket"), 360, true, kernel.SavedViewColumnPinnedStart,
	)
	if err != nil {
		t.Fatal(err)
	}
	updatedColumn, err := kernel.NewSavedViewCoreColumn(
		mustApplicationTicketKey(t, "updated"), 200, true, kernel.SavedViewColumnUnpinned,
	)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := kernel.NewSavedViewSpec(
		base.tenant, kernel.AggregateAlert, filters, sortValue,
		[]kernel.SavedViewColumn{ticketColumn, updatedColumn},
	)
	if err != nil {
		t.Fatal(err)
	}
	viewID := mustUUIDv7(t)
	viewEntity, _ := entityID(viewID)
	owner, _ := entityID(base.membershipUUID)
	view, err := kernel.NewSavedView(
		viewEntity, base.tenant, owner, kernel.AggregateAlert, "My incidents",
		spec, kernel.SavedViewActive, 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := SavedViewSpecDigest(base.tenant, kernel.AggregateAlert, spec)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	return savedViewServiceFixture{
		base: base, viewID: viewID, spec: spec,
		input: SavedViewSpecInput{
			Filters: SavedViewFiltersInput{Queue: "all", Search: "malware campaign"},
			Sort: SavedViewSortInput{
				Source: SavedViewDefinitionCore, CoreKey: "updated_at",
				Direction: "desc", Nulls: "last",
			},
			Columns: []SavedViewColumnInput{
				{Source: SavedViewDefinitionCore, CoreKey: "ticket", Width: 360, Visible: true, Pin: "start"},
				{Source: SavedViewDefinitionCore, CoreKey: "updated", Width: 200, Visible: true, Pin: "none"},
			},
		},
		record: SavedViewRecord{View: view, SpecDigest: digest, CreatedAt: now, UpdatedAt: now},
	}
}

func mustApplicationTicketKey(t testing.TB, value string) kernel.Key {
	t.Helper()
	key, err := kernel.NewKey(value)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustSavedViewService(t testing.TB, repository SavedViewRepository) *SavedViewService {
	t.Helper()
	service, err := NewSavedViewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type fakeSavedViewReplayKey struct {
	tenant uuid.UUID
	actor  uuid.UUID
	owner  uuid.UUID
	kind   kernel.AggregateKind
	action kernel.SavedViewAction
	hash   [sha256.Size]byte
}

type fakeSavedViewReplay struct {
	fingerprint [sha256.Size]byte
	result      SavedViewMutationResult
}

type fakeSavedViewRepository struct {
	mu                sync.Mutex
	fixture           savedViewServiceFixture
	principal         kernel.PrincipalKind
	allowed           bool
	accessOverride    *SavedViewAccess
	spec              kernel.SavedViewSpec
	records           map[uuid.UUID]SavedViewRecord
	replays           map[fakeSavedViewReplayKey]fakeSavedViewReplay
	listOverride      *SavedViewPage
	revokeAtCommit    bool
	stalePinsAtCommit bool
	getErr            error
	accessCalls       atomic.Int32
	resolveSpecCalls  atomic.Int32
	reserveCalls      atomic.Int32
	listCalls         atomic.Int32
	getCalls          atomic.Int32
	commitCalls       atomic.Int32
}

func newFakeSavedViewRepository(fixture savedViewServiceFixture) *fakeSavedViewRepository {
	return &fakeSavedViewRepository{
		fixture: fixture, principal: kernel.PrincipalOperator, allowed: true,
		spec: fixture.spec, records: map[uuid.UUID]SavedViewRecord{},
		replays: map[fakeSavedViewReplayKey]fakeSavedViewReplay{},
	}
}

func (repository *fakeSavedViewRepository) ResolveSavedViewAccess(
	_ context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	capability SavedViewCapability,
) (SavedViewAccess, error) {
	repository.accessCalls.Add(1)
	if repository.accessOverride != nil {
		return *repository.accessOverride, nil
	}
	return NewSavedViewAccess(
		tenantID, actor.UserID, repository.fixture.base.membershipUUID,
		kind, capability, repository.principal, repository.allowed,
	)
}

func (repository *fakeSavedViewRepository) ResolveSavedViewSpec(
	_ context.Context,
	_ Actor,
	_ uuid.UUID,
	_ kernel.AggregateKind,
	_ SavedViewSpecInput,
	_ SavedViewAccess,
) (kernel.SavedViewSpec, error) {
	repository.resolveSpecCalls.Add(1)
	return repository.spec, nil
}

func (repository *fakeSavedViewRepository) ReserveSavedViewID(
	_ context.Context,
	_ uuid.UUID,
) (kernel.EntityID, error) {
	repository.reserveCalls.Add(1)
	return entityID(mustUUIDv7NoTest())
}

func (repository *fakeSavedViewRepository) ListSavedViews(
	_ context.Context,
	_ Actor,
	_ uuid.UUID,
	_ kernel.AggregateKind,
	_ SavedViewListInput,
	_ SavedViewAccess,
) (SavedViewPage, error) {
	repository.listCalls.Add(1)
	if repository.listOverride != nil {
		return *repository.listOverride, nil
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	page := SavedViewPage{}
	for _, record := range repository.records {
		page.Items = append(page.Items, record)
	}
	sort.Slice(page.Items, func(left, right int) bool {
		return page.Items[left].View.ID().String() < page.Items[right].View.ID().String()
	})
	return page, nil
}

func (repository *fakeSavedViewRepository) GetSavedView(
	_ context.Context,
	_ Actor,
	_ uuid.UUID,
	viewID uuid.UUID,
	_ SavedViewAccess,
) (SavedViewRecord, error) {
	repository.getCalls.Add(1)
	if repository.getErr != nil {
		return SavedViewRecord{}, repository.getErr
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	record, found := repository.records[viewID]
	if !found {
		return SavedViewRecord{}, ErrNotFound
	}
	return record, nil
}

func (repository *fakeSavedViewRepository) LookupSavedViewReplay(
	_ context.Context,
	query SavedViewReplayQuery,
) (SavedViewMutationResult, bool, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := fakeSavedViewReplayKey{
		tenant: query.TenantID, actor: query.ActorID, owner: query.OwnerMembershipID,
		kind: query.Kind, action: query.Action, hash: query.KeyHash,
	}
	replay, found := repository.replays[key]
	if !found {
		return SavedViewMutationResult{}, false, nil
	}
	if replay.fingerprint != query.Fingerprint {
		return SavedViewMutationResult{}, false, ErrConflict
	}
	return replay.result, true, nil
}

func (repository *fakeSavedViewRepository) CommitSavedView(
	_ context.Context,
	write SavedViewWrite,
) (SavedViewMutationResult, error) {
	repository.commitCalls.Add(1)
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if write.RequiredCapability != SavedViewCapabilityManage || repository.revokeAtCommit ||
		write.OwnerMembershipID != repository.fixture.base.membershipUUID {
		return SavedViewMutationResult{}, ErrForbidden
	}
	if repository.stalePinsAtCommit && write.Plan.Action() != kernel.SavedViewArchive {
		return SavedViewMutationResult{}, ErrConflict
	}
	next := write.Plan.Next()
	viewID := uuidFromEntity(next.ID())
	key := fakeSavedViewReplayKey{
		tenant: uuidFromEntity(next.Tenant()), actor: write.Actor.UserID,
		owner: write.OwnerMembershipID, kind: next.Kind(), action: write.Command.Action,
		hash: write.Command.KeyHash,
	}
	if replay, found := repository.replays[key]; found {
		if replay.fingerprint != write.Command.Fingerprint {
			return SavedViewMutationResult{}, ErrConflict
		}
		result := replay.result
		result.Replayed = true
		return result, nil
	}
	current, exists := repository.records[viewID]
	if write.Plan.Action() == kernel.SavedViewCreate {
		if exists || write.Plan.ExpectedRevision() != 0 {
			return SavedViewMutationResult{}, ErrConflict
		}
	} else if !exists || current.View.Revision() != write.Plan.ExpectedRevision() {
		return SavedViewMutationResult{}, ErrPreconditionFailed
	}
	record, err := fakeSavedViewRecord(next, current.CreatedAt)
	if err != nil {
		return SavedViewMutationResult{}, err
	}
	repository.records[viewID] = record
	result := SavedViewMutationResult{Record: record}
	repository.replays[key] = fakeSavedViewReplay{
		fingerprint: write.Command.Fingerprint, result: result,
	}
	return result, nil
}

func fakeSavedViewRecord(view kernel.SavedView, createdAt time.Time) (SavedViewRecord, error) {
	if createdAt.IsZero() {
		createdAt = time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	}
	updatedAt := createdAt.Add(time.Duration(view.Revision()) * time.Second)
	digest, err := SavedViewSpecDigest(view.Tenant(), view.Kind(), view.Spec())
	if err != nil {
		return SavedViewRecord{}, err
	}
	record := SavedViewRecord{
		View: view, SpecDigest: digest, CreatedAt: createdAt, UpdatedAt: updatedAt,
	}
	if view.Status() == kernel.SavedViewArchived {
		archivedAt := updatedAt
		record.ArchivedAt = &archivedAt
	}
	return record, nil
}

func mustUUIDv7NoTest() uuid.UUID {
	value, err := uuid.NewV7()
	if err != nil {
		panic(err)
	}
	return value
}
