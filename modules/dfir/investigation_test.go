package dfir

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestTimelineEventPreservesForensicTimeContextAndOwnsLinks(t *testing.T) {
	actor := fixtureID(9)
	input := TimelineEventInput{
		ID: fixtureID(70), TenantID: fixtureID(1), CaseID: fixtureID(20),
		EventTime:        time.Date(2025, 10, 26, 1, 30, 0, 123_000, time.UTC),
		IngestedAt:       time.Date(2026, 8, 25, 13, 0, 0, 0, time.UTC),
		OriginalTimezone: "Europe/Rome", Precision: PrecisionMicrosecond,
		Source: "endpoint_sensor", Category: "process_start",
		Title: "Sensitive process execution", Description: "Private command details",
		ActorID: &actor, IOCIDs: []EntityID{fixtureID(72), fixtureID(71)},
		AssetIDs: []EntityID{fixtureID(73)}, EvidenceIDs: []EntityID{fixtureID(74)},
		Tags: []string{"triage", "execution"},
	}
	event, err := NewTimelineEvent(input)
	if err != nil {
		t.Fatalf("NewTimelineEvent() error = %v", err)
	}
	if event.EventTime() != input.EventTime || event.IngestedAt() != input.IngestedAt ||
		event.OriginalTimezone() != "Europe/Rome" || event.Precision() != PrecisionMicrosecond {
		t.Fatal("forensic time context drifted")
	}
	if got, want := event.IOCIDs(), []EntityID{fixtureID(71), fixtureID(72)}; !reflect.DeepEqual(got, want) {
		t.Fatalf("IOCIDs() = %v, want %v", got, want)
	}
	input.IOCIDs[0] = fixtureID(90)
	*input.ActorID = fixtureID(91)
	if event.IOCIDs()[1] != fixtureID(72) || event.ActorID() == nil || *event.ActorID() != fixtureID(9) {
		t.Fatal("timeline retained caller-owned identity storage")
	}
	for _, rendered := range []string{fmt.Sprint(event), fmt.Sprintf("%#v", event)} {
		for _, secret := range []string{event.Source(), event.Title(), event.Description(), event.OriginalTimezone()} {
			if strings.Contains(rendered, secret) {
				t.Fatalf("timeline formatting leaked %q: %q", secret, rendered)
			}
		}
	}
}

func TestTimelineEventRejectsAmbiguousTimeAndLinkShapes(t *testing.T) {
	valid := TimelineEventInput{
		ID: fixtureID(70), TenantID: fixtureID(1), CaseID: fixtureID(20),
		EventTime:        time.Date(2026, 8, 25, 13, 0, 0, 0, time.UTC),
		IngestedAt:       time.Date(2026, 8, 25, 12, 59, 0, 0, time.UTC),
		OriginalTimezone: "+02:00", Precision: PrecisionSecond,
		Source: "sensor", Category: "network_event", Title: "Observed event",
	}
	if _, err := NewTimelineEvent(valid); err != nil {
		t.Fatalf("event with source clock ahead of ingestion rejected: %v", err)
	}
	tests := []func(*TimelineEventInput){
		func(input *TimelineEventInput) { input.OriginalTimezone = "+14:30" },
		func(input *TimelineEventInput) { input.OriginalTimezone = "CET" },
		func(input *TimelineEventInput) { input.Precision = "nanosecond" },
		func(input *TimelineEventInput) { input.Source = "sensor\nspoof" },
		func(input *TimelineEventInput) { input.IOCIDs = []EntityID{fixtureID(71), fixtureID(71)} },
		func(input *TimelineEventInput) { invalid := EntityID{}; input.ActorID = &invalid },
	}
	for index, mutate := range tests {
		input := valid
		mutate(&input)
		if _, err := NewTimelineEvent(input); err == nil {
			t.Fatalf("invalid timeline case %d accepted", index)
		}
	}
}

func TestTimelineEventRequiresExactlyOneAlertOrCaseRoot(t *testing.T) {
	t.Parallel()
	input := TimelineEventInput{
		ID: fixtureID(75), TenantID: fixtureID(1), AlertID: fixtureID(21),
		EventTime:        time.Date(2026, 8, 25, 13, 0, 0, 0, time.UTC),
		IngestedAt:       time.Date(2026, 8, 25, 13, 0, 1, 0, time.UTC),
		OriginalTimezone: "UTC", Precision: PrecisionSecond,
		Source: "sensor", Category: "network_event", Title: "Observed event",
	}
	event, err := NewTimelineEvent(input)
	if err != nil || event.AlertID() != input.AlertID || event.CaseID() != (EntityID{}) {
		t.Fatalf("Alert timeline = (%s, %v)", event, err)
	}
	input.CaseID = fixtureID(20)
	if _, err := NewTimelineEvent(input); err == nil {
		t.Fatal("timeline with both Alert and Case roots was accepted")
	}
	input.AlertID = EntityID{}
	if event, err = NewTimelineEvent(input); err != nil || event.CaseID() != input.CaseID || event.AlertID() != (EntityID{}) {
		t.Fatalf("Case timeline = (%s, %v)", event, err)
	}
	input.CaseID = EntityID{}
	if _, err := NewTimelineEvent(input); err == nil {
		t.Fatal("timeline without an Alert or Case root was accepted")
	}
}

func TestTimelineEventBoundsReferencesToContract(t *testing.T) {
	t.Parallel()
	input := TimelineEventInput{
		ID: fixtureID(75), TenantID: fixtureID(1), AlertID: fixtureID(21),
		EventTime:        time.Date(2026, 8, 25, 13, 0, 0, 0, time.UTC),
		IngestedAt:       time.Date(2026, 8, 25, 13, 0, 1, 0, time.UTC),
		OriginalTimezone: "UTC", Precision: PrecisionSecond,
		Source: "sensor", Category: "network_event", Title: "Observed event",
		IOCIDs: make([]EntityID, maximumTimelineReferences+1),
	}
	for index := range input.IOCIDs {
		input.IOCIDs[index] = fixtureID(uint16(1_000 + index))
	}
	if _, err := NewTimelineEvent(input); err == nil {
		t.Fatal("timeline exceeding the contract reference bound was accepted")
	}
	input.IOCIDs = input.IOCIDs[:maximumTimelineReferences]
	if _, err := NewTimelineEvent(input); err != nil {
		t.Fatalf("timeline at the contract reference bound was rejected: %v", err)
	}
}

func TestRelationshipRejectsCrossTenantSelfAndOpaquePolymorphism(t *testing.T) {
	tenant := fixtureID(1)
	alert, err := NewEntityReference(tenant, EntityAlert, fixtureID(80))
	if err != nil {
		t.Fatal(err)
	}
	external, err := NewExternalEntityReference(tenant, "threat_feed", "private-feed-object")
	if err != nil {
		t.Fatal(err)
	}
	metadata := json.RawMessage(`{"confidence":90}`)
	relationship, err := NewRelationship(RelationshipInput{
		ID: fixtureID(82), TenantID: tenant, Source: alert, Target: external,
		RelationshipType: "corroborates", Metadata: metadata,
		CreatedBy: fixtureID(9), CreatedAt: time.Date(2026, 8, 25, 13, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	metadata[2] = 'X'
	if got := string(relationship.Metadata()); got != `{"confidence":90}` {
		t.Fatalf("relationship metadata = %s", got)
	}
	if rendered := fmt.Sprintf("%#v %#v", relationship, relationship.Target()); strings.Contains(rendered, "private-feed-object") {
		t.Fatalf("relationship formatting leaked external identifier: %q", rendered)
	}
	if _, err := NewRelationship(RelationshipInput{
		ID: fixtureID(83), TenantID: tenant, Source: alert, Target: alert,
		RelationshipType: "duplicates", CreatedBy: fixtureID(9),
		CreatedAt: time.Date(2026, 8, 25, 13, 0, 0, 0, time.UTC),
	}); err == nil {
		t.Fatal("self relationship was accepted")
	}
	otherTenantTarget, _ := NewEntityReference(fixtureID(2), EntityCase, fixtureID(81))
	if _, err := NewRelationship(RelationshipInput{
		ID: fixtureID(84), TenantID: tenant, Source: alert, Target: otherTenantTarget,
		RelationshipType: "related", CreatedBy: fixtureID(9),
		CreatedAt: time.Date(2026, 8, 25, 13, 0, 0, 0, time.UTC),
	}); err == nil {
		t.Fatal("cross-tenant relationship was accepted")
	}
	if _, err := NewEntityReference(tenant, EntityExternal, fixtureID(81)); err == nil {
		t.Fatal("external entity accepted an opaque local id")
	}
}

func TestRelationshipRetractionIsTerminalCASAndRestorable(t *testing.T) {
	t.Parallel()
	tenant := fixtureID(1)
	caseReference, _ := NewEntityReference(tenant, EntityCase, fixtureID(85))
	assetReference, _ := NewEntityReference(tenant, EntityAsset, fixtureID(86))
	createdAt := time.Date(2026, 8, 25, 13, 0, 0, 0, time.UTC)
	input := RelationshipInput{
		ID: fixtureID(87), TenantID: tenant, Source: caseReference, Target: assetReference,
		RelationshipType: "contains", CreatedBy: fixtureID(9), CreatedAt: createdAt,
	}
	relationship, err := NewRelationship(input)
	if err != nil || relationship.Version() != 1 || !relationship.Active() {
		t.Fatalf("new relationship = (%v, %v)", relationship, err)
	}
	retracted, err := relationship.Retract(1, RelationshipRetractionInput{
		ID: fixtureID(88), ActorID: fixtureID(10), Reason: "superseded evidence",
		OccurredAt: createdAt.Add(time.Microsecond),
	})
	if err != nil || retracted.Version() != 2 || retracted.Active() || relationship.Version() != 1 {
		t.Fatalf("relationship retract = (%v, %v)", retracted, err)
	}
	if _, err = relationship.Retract(2, RelationshipRetractionInput{
		ID: fixtureID(89), ActorID: fixtureID(10), Reason: "stale",
		OccurredAt: createdAt.Add(time.Microsecond),
	}); !errors.Is(err, ErrRelationshipConflict) {
		t.Fatalf("stale retraction error = %v", err)
	}
	if _, err = retracted.Retract(2, RelationshipRetractionInput{
		ID: fixtureID(89), ActorID: fixtureID(10), Reason: "second retraction",
		OccurredAt: createdAt.Add(2 * time.Microsecond),
	}); !errors.Is(err, ErrInvalidRelationship) {
		t.Fatalf("second retraction error = %v", err)
	}
	restoredInput := input
	restoredInput.Version = retracted.Version()
	restoredInput.Retractions = retracted.Retractions()
	restored, err := NewRelationship(restoredInput)
	if err != nil || restored.Active() || restored.Version() != 2 {
		t.Fatalf("restored relationship = (%v, %v)", restored, err)
	}
	restoredInput.Retractions[0].Reason = "split\u2029reason"
	if _, err = NewRelationship(restoredInput); !errors.Is(err, ErrInvalidRelationship) {
		t.Fatalf("unsafe restored retraction error = %v", err)
	}
}

func TestAttachmentInheritsVisibilityAndDownloadFailsClosed(t *testing.T) {
	tenant := fixtureID(1)
	subject, _ := NewEntityReference(tenant, EntityCase, fixtureID(20))
	input := AttachmentInput{
		ID: fixtureID(90), TenantID: tenant, Subject: subject,
		StorageObjectID: fixtureID(91), OriginalFilename: "private-evidence.txt",
		RequestedVisibility: VisibilityPublic, SubjectVisibility: VisibilityPrivate,
		UploadedBy: fixtureID(9), UploadedAt: time.Date(2026, 8, 25, 13, 0, 0, 0, time.UTC),
		ScanState: ScanAvailable,
	}
	attachment, err := NewAttachment(input)
	if err != nil {
		t.Fatal(err)
	}
	if attachment.Visibility() != VisibilityPrivate || attachment.CanIssueDownload(AudienceCustomer) ||
		!attachment.CanIssueDownload(AudienceOperator) || attachment.CanIssueDownload("future") {
		t.Fatal("attachment visibility/download policy did not fail closed")
	}
	if rendered := fmt.Sprintf("%#v", attachment); strings.Contains(rendered, attachment.OriginalFilename()) {
		t.Fatalf("attachment formatting leaked filename: %q", rendered)
	}
	input.SubjectVisibility = VisibilityPublic
	input.ScanState = ScanFailed
	attachment, err = NewAttachment(input)
	if err != nil || attachment.CanIssueDownload(AudienceOperator) {
		t.Fatal("scan-failed attachment was downloadable")
	}
	for _, filename := range []string{"../secret", `folder\\secret`, "line\nfeed", ".", ".."} {
		input.OriginalFilename = filename
		if _, err := NewAttachment(input); err == nil {
			t.Fatalf("unsafe filename %q accepted", filename)
		}
	}
	external, _ := NewExternalEntityReference(tenant, "feed", "object")
	input.OriginalFilename = "safe.txt"
	input.Subject = external
	if _, err := NewAttachment(input); err == nil {
		t.Fatal("attachment to unconstrained external subject was accepted")
	}
}
