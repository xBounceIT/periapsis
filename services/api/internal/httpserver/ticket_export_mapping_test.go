package httpserver

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func TestMapTicketExportJobPreservesImmutableSavedViewSnapshot(t *testing.T) {
	record, IDs, queryDigest, catalogDigest := savedViewTicketExportRecord(t, false)
	mapped, err := mapTicketExportJob(record)
	if err != nil {
		t.Fatalf("mapTicketExportJob() error = %v", err)
	}
	if mapped.Id != IDs.job || mapped.TenantId != IDs.tenant || mapped.RequesterUserId != IDs.requester ||
		mapped.OwnerMembershipId != IDs.owner || mapped.Kind != "case" || mapped.Audience != "operator" ||
		mapped.Comments != "public_and_private" || mapped.Format != "csv" || mapped.ProjectionVersion != 1 ||
		mapped.MaximumRows != 1_000 || mapped.MaximumBytes != 1_048_576 || mapped.MaximumAttempts != 5 ||
		mapped.State != "pending" || mapped.Revision != 1 || mapped.Attempts != 0 ||
		mapped.FailureCode != "none" || mapped.Artifact != nil || mapped.TerminalAt != nil {
		t.Fatalf("mapped job = %#v", mapped)
	}
	query := mapped.Query
	if query.Source != "saved_view" || query.QuerySha256 != queryDigest ||
		query.CatalogSha256 != catalogDigest || query.SavedView == nil ||
		query.SavedView.Id != IDs.view || query.SavedView.OwnerMembershipId != IDs.owner ||
		query.SavedView.Revision != 4 || query.SavedView.SpecSha256 != queryDigest ||
		query.EffectiveSpec.Filters.Queue != "all" || len(query.EffectiveSpec.Columns) != 1 {
		t.Fatalf("mapped query = %#v", query)
	}
	encoded, err := json.Marshal(mapped)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"worker", "fence", "lease", "objectKey", "downloadUrl"} {
		if strings.Contains(strings.ToLower(string(encoded)), strings.ToLower(forbidden)) {
			t.Fatalf("projection exposed %q: %s", forbidden, encoded)
		}
	}
}

func TestMapTicketExportJobPreservesEmptySuccessfulArtifact(t *testing.T) {
	record, IDs, _, _ := savedViewTicketExportRecord(t, true)
	mapped, err := mapTicketExportJob(record)
	if err != nil {
		t.Fatalf("mapTicketExportJob() error = %v", err)
	}
	if mapped.State != "succeeded" || mapped.Revision != 3 || mapped.Attempts != 1 ||
		mapped.TerminalAt == nil || mapped.Artifact == nil || mapped.Artifact.Id != IDs.artifact ||
		mapped.Artifact.Rows != 0 || mapped.Artifact.Bytes != 21 || len(mapped.Artifact.Sha256) != 64 ||
		!mapped.Artifact.ExpiresAt.Equal(mapped.ExpiresAt) {
		t.Fatalf("mapped succeeded job = %#v", mapped)
	}
}

func TestMapTicketExportProjectionFailsClosedForMalformedOrCustomerRecords(t *testing.T) {
	if _, err := mapTicketExportJob(application.AsyncExportRecord{}); err == nil {
		t.Fatal("mapTicketExportJob(zero) unexpectedly succeeded")
	}
	record, _, _, _ := savedViewTicketExportRecord(t, false)
	record.Query = application.AsyncExportQuerySnapshot{}
	if _, err := mapTicketExportJob(record); err == nil {
		t.Fatal("valid job with malformed query unexpectedly succeeded")
	}
	if _, err := mapTicketExportJob(customerTicketExportRecord(t)); err == nil {
		t.Fatal("customer export unexpectedly crossed the operator transport")
	}
}

func TestMapTicketExportMutationReceiptsBindRequestAndCancellation(t *testing.T) {
	record, IDs, _, _ := savedViewTicketExportRecord(t, false)
	definition := record.Job.Definition()
	pin := definition.SavedView()
	input := application.AsyncExportRequestInput{
		Audience: kernel.TicketExportAudienceOperator,
		Comments: kernel.TicketExportCommentsPublicAndPrivate,
		Source: application.AsyncExportSourceInput{
			SavedView: &application.AsyncExportSavedViewSourceInput{
				ID: IDs.view, ExpectedRevision: pin.Revision(), ExpectedSpecDigest: pin.Digest(),
			},
		},
		MaximumRows: definition.MaximumRows(), MaximumBytes: definition.MaximumBytes(),
		Retention: record.Job.ExpiresAt().Sub(record.Job.RequestedAt()),
	}
	result := application.AsyncExportResult{Record: record, Replayed: true}
	mapped, err := mapRequestedTicketExportMutationResult(
		result, IDs.tenant, IDs.requester, kernel.AggregateCase, input,
	)
	if err != nil || !mapped.Replayed || mapped.Job.Id != IDs.job {
		t.Fatalf("request mapping = %#v, %v", mapped, err)
	}

	divergent := input
	divergent.MaximumRows--
	if _, err := mapRequestedTicketExportMutationResult(
		result, IDs.tenant, IDs.requester, kernel.AggregateCase, divergent,
	); err == nil {
		t.Fatal("request receipt with divergent row bound unexpectedly succeeded")
	}
	divergent = input
	divergent.Source = application.AsyncExportSourceInput{Inline: &application.SavedViewSpecInput{}}
	if _, err := mapRequestedTicketExportMutationResult(
		result, IDs.tenant, IDs.requester, kernel.AggregateCase, divergent,
	); err == nil {
		t.Fatal("saved-view receipt for inline request unexpectedly succeeded")
	}

	cancelled, err := kernel.PlanTicketExportCancellation(
		record.Job, 1, record.Job.RequestedAt().Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	result.Record.Job = cancelled.Next()
	if _, err := mapCancelledTicketExportMutationResult(
		result, IDs.tenant, IDs.requester, kernel.AggregateCase, 1,
	); err != nil {
		t.Fatalf("cancel mapping error = %v", err)
	}
	if _, err := mapCancelledTicketExportMutationResult(
		result, IDs.tenant, IDs.requester, kernel.AggregateCase, 2,
	); err == nil {
		t.Fatal("cancel receipt with divergent revision unexpectedly succeeded")
	}
}

type ticketExportMappingIDs struct {
	job, tenant, requester, owner, view, worker, artifact uuid.UUID
}

func savedViewTicketExportRecord(
	t *testing.T,
	succeeded bool,
) (application.AsyncExportRecord, ticketExportMappingIDs, string, string) {
	t.Helper()
	IDs := ticketExportMappingIDs{
		job: mustTransportUUIDv7(t), tenant: mustTransportUUIDv7(t), requester: mustTransportUUIDv7(t),
		owner: mustTransportUUIDv7(t), view: mustTransportUUIDv7(t), worker: mustTransportUUIDv7(t),
		artifact: mustTransportUUIDv7(t),
	}
	spec := mustTicketExportSpec(t, IDs.tenant, kernel.AggregateCase)
	inline, err := application.NewAsyncExportQuerySnapshot(
		IDs.tenant, kernel.AggregateCase, kernel.TicketExportQueryInline, spec, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := kernel.NewTicketExportSavedViewPin(
		mustTicketExportEntity(t, IDs.view), mustTicketExportEntity(t, IDs.owner), 4, inline.QueryDigest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	query, err := application.NewAsyncExportQuerySnapshot(
		IDs.tenant, kernel.AggregateCase, kernel.TicketExportQuerySavedView, spec, &pin,
	)
	if err != nil {
		t.Fatal(err)
	}
	definition, err := kernel.NewTicketExportDefinition(kernel.TicketExportDefinitionInput{
		ID: mustTicketExportEntity(t, IDs.job), Tenant: mustTicketExportEntity(t, IDs.tenant),
		Requester: mustTicketExportEntity(t, IDs.requester), OwnerMembership: mustTicketExportEntity(t, IDs.owner),
		Kind: kernel.AggregateCase, Audience: kernel.TicketExportAudienceOperator,
		Comments: kernel.TicketExportCommentsPublicAndPrivate, QuerySource: kernel.TicketExportQuerySavedView,
		SavedView: &pin, QueryDigest: query.QueryDigest(), CatalogDigest: query.CatalogDigest(),
		ProjectionVersion: kernel.TicketExportProjectionVersion, Format: kernel.TicketExportCSV,
		MaximumRows: 1_000, MaximumBytes: 1_048_576, MaximumAttempts: kernel.TicketExportMaximumAttempts,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 26, 18, 0, 0, 123_456_000, time.UTC)
	expiresAt := now.Add(24 * time.Hour)
	created, err := kernel.PlanTicketExportCreation(definition, now, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	job := created.Next()
	if succeeded {
		fence := [32]byte{1, 2, 3}
		claimed, claimErr := kernel.PlanTicketExportClaim(
			job, mustTicketExportEntity(t, IDs.worker), fence, now.Add(time.Second), now.Add(5*time.Minute),
		)
		if claimErr != nil {
			t.Fatal(claimErr)
		}
		artifact, artifactErr := kernel.NewTicketExportArtifact(
			mustTicketExportEntity(t, IDs.artifact), [32]byte{9, 8, 7}, 0, 21, expiresAt,
		)
		if artifactErr != nil {
			t.Fatal(artifactErr)
		}
		finished, finishErr := kernel.PlanTicketExportSuccess(
			claimed.Next(), mustTicketExportEntity(t, IDs.worker), fence, artifact, now.Add(2*time.Second),
		)
		if finishErr != nil {
			t.Fatal(finishErr)
		}
		job = finished.Next()
	}
	return application.AsyncExportRecord{Job: job, Query: query}, IDs,
		ticketExportHexDigest(query.QueryDigest()), ticketExportHexDigest(query.CatalogDigest())
}

func ticketExportHexDigest(value [32]byte) string {
	return hex.EncodeToString(value[:])
}

func customerTicketExportRecord(t *testing.T) application.AsyncExportRecord {
	t.Helper()
	IDs := ticketExportMappingIDs{
		job: mustTransportUUIDv7(t), tenant: mustTransportUUIDv7(t), requester: mustTransportUUIDv7(t),
		owner: mustTransportUUIDv7(t), artifact: mustTransportUUIDv7(t),
	}
	contact := mustTransportUUIDv7(t)
	spec := mustTicketExportSpec(t, IDs.tenant, kernel.AggregateAlert)
	query, err := application.NewAsyncExportQuerySnapshot(
		IDs.tenant, kernel.AggregateAlert, kernel.TicketExportQueryInline, spec, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	contactEntity := mustTicketExportEntity(t, contact)
	definition, err := kernel.NewTicketExportDefinition(kernel.TicketExportDefinitionInput{
		ID: mustTicketExportEntity(t, IDs.job), Tenant: mustTicketExportEntity(t, IDs.tenant),
		Requester: mustTicketExportEntity(t, IDs.requester), OwnerMembership: mustTicketExportEntity(t, IDs.owner),
		CustomerContact: &contactEntity, Kind: kernel.AggregateAlert,
		Audience: kernel.TicketExportAudienceCustomer, Comments: kernel.TicketExportCommentsNone,
		QuerySource: kernel.TicketExportQueryInline, QueryDigest: query.QueryDigest(), CatalogDigest: query.CatalogDigest(),
		ProjectionVersion: kernel.TicketExportProjectionVersion, Format: kernel.TicketExportCSV,
		MaximumRows: 100, MaximumBytes: 1_024, MaximumAttempts: kernel.TicketExportMaximumAttempts,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 26, 18, 0, 0, 0, time.UTC)
	plan, err := kernel.PlanTicketExportCreation(definition, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return application.AsyncExportRecord{Job: plan.Next(), Query: query}
}

func mustTicketExportSpec(t *testing.T, tenantID uuid.UUID, kind kernel.AggregateKind) kernel.SavedViewSpec {
	t.Helper()
	filters, err := kernel.NewSavedViewFilters(kernel.SavedViewFiltersInput{Queue: kernel.SavedViewQueueAll})
	if err != nil {
		t.Fatal(err)
	}
	sortKey, err := kernel.NewKey("updated_at")
	if err != nil {
		t.Fatal(err)
	}
	sortPlan, err := kernel.NewSavedViewCoreSort(sortKey, kernel.SavedViewSortDescending)
	if err != nil {
		t.Fatal(err)
	}
	columnKey, err := kernel.NewKey("ticket")
	if err != nil {
		t.Fatal(err)
	}
	column, err := kernel.NewSavedViewCoreColumn(columnKey, 320, true, kernel.SavedViewColumnPinnedStart)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := kernel.NewSavedViewSpec(
		mustTicketExportEntity(t, tenantID), kind, filters, sortPlan, []kernel.SavedViewColumn{column},
	)
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func mustTicketExportEntity(t *testing.T, value uuid.UUID) kernel.EntityID {
	t.Helper()
	entity, err := kernel.NewEntityID([16]byte(value))
	if err != nil {
		t.Fatal(err)
	}
	return entity
}
