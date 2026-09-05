package postgres

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func TestDFIRMutationSnapshotsRoundTripExactTypedProjections(t *testing.T) {
	t.Parallel()
	tenantID, caseID, alertID := alertTestUUID(101), alertTestUUID(102), alertTestUUID(103)
	tenant := entityID(tenantID)
	caseEntity := entityID(caseID)
	alertEntity := entityID(alertID)
	now := alertTestTime(0)

	indicator, err := kernel.NewIndicator(kernel.IndicatorInput{
		ID: alertTestEntityID(104), TenantID: tenant, Type: kernel.IndicatorDomain,
		Value: "Receipt.Example", Description: "initial immutable projection", Source: "analyst",
		Confidence: 87, TLP: kernel.TLPAmber, FirstSeen: now, LastSeen: now.Add(time.Second),
		Malicious: kernel.MaliciousSuspicious, Tags: []string{"receipt"},
		Enrichment: json.RawMessage(`{"source":"fixture"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	indicatorCoordinate := dfirMutationCoordinate{
		tenantID: tenantID, rootKind: dfirMutationRootAlert, rootID: alertID,
		operation: "dfir.ioc.replace", resourceKind: dfirMutationKindIOC,
		resourceID: uuid.UUID(indicator.ID().Bytes()), resultVersion: 2,
	}
	indicatorDocument, err := encodeDFIRIndicatorResult(indicatorCoordinate, indicator)
	if err != nil {
		t.Fatal(err)
	}
	restoredIndicator, err := decodeDFIRIndicatorResult(indicatorDocument, indicatorCoordinate)
	if err != nil || !sameDFIRIndicator(indicator, restoredIndicator) {
		t.Fatalf("IOC snapshot round trip = (%v, %v)", restoredIndicator, err)
	}

	asset, err := kernel.NewAsset(kernel.AssetInput{
		ID: alertTestEntityID(105), TenantID: tenant, Hostname: "Host.Example",
		IPAddresses: []string{"192.0.2.10"}, MACAddresses: []string{"02:00:5e:10:00:01"},
		AssetType: "endpoint", OperatingSystem: "test", Owner: "SOC", BusinessUnit: "security",
		Criticality: kernel.AssetCriticalityHigh, Environment: "production", ExternalID: "asset-105",
		Tags: []string{"receipt"}, FirstSeen: now, LastSeen: now.Add(time.Second),
		CustomAttributes: json.RawMessage(`{"zone":"restricted"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	assetCoordinate := dfirMutationCoordinate{
		tenantID: tenantID, rootKind: dfirMutationRootCase, rootID: caseID,
		operation: "dfir.asset.create", resourceKind: dfirMutationKindAsset,
		resourceID: uuid.UUID(asset.ID().Bytes()), resultVersion: 1,
	}
	assetDocument, err := encodeDFIRAssetResult(assetCoordinate, asset)
	if err != nil {
		t.Fatal(err)
	}
	restoredAsset, err := decodeDFIRAssetResult(assetDocument, assetCoordinate)
	if err != nil || !sameDFIRAsset(asset, restoredAsset) {
		t.Fatalf("asset snapshot round trip = (%v, %v)", restoredAsset, err)
	}

	event, err := kernel.NewTimelineEvent(kernel.TimelineEventInput{
		ID: alertTestEntityID(106), TenantID: tenant, AlertID: alertEntity,
		EventTime: now, IngestedAt: now.Add(time.Second), OriginalTimezone: "UTC",
		Precision: kernel.PrecisionSecond, Source: "analyst", Category: "investigation",
		Title: "receipt captured", Description: "historical timeline response",
		IOCIDs: []kernel.EntityID{indicator.ID()}, AssetIDs: []kernel.EntityID{asset.ID()}, Tags: []string{"receipt"},
	})
	if err != nil {
		t.Fatal(err)
	}
	timelineCoordinate := dfirMutationCoordinate{
		tenantID: tenantID, rootKind: dfirMutationRootAlert, rootID: alertID,
		operation: "dfir.timeline.create", resourceKind: dfirMutationKindTimeline,
		resourceID: uuid.UUID(event.ID().Bytes()), resultVersion: 1,
	}
	timelineDocument, err := encodeDFIRTimelineResult(timelineCoordinate, event)
	if err != nil {
		t.Fatal(err)
	}
	restoredEvent, err := decodeDFIRTimelineResult(timelineDocument, timelineCoordinate)
	if err != nil || !sameDFIRTimelineEvent(event, restoredEvent) {
		t.Fatalf("timeline snapshot round trip = (%v, %v)", restoredEvent, err)
	}

	source, err := kernel.NewEntityReference(tenant, kernel.EntityCase, caseEntity)
	if err != nil {
		t.Fatal(err)
	}
	target, err := kernel.NewExternalEntityReference(tenant, "host", "external-107")
	if err != nil {
		t.Fatal(err)
	}
	relationship, err := kernel.NewRelationship(kernel.RelationshipInput{
		ID: alertTestEntityID(107), TenantID: tenant, Source: source, Target: target,
		RelationshipType: "contains", Metadata: json.RawMessage(`{"confidence":90}`),
		CreatedBy: alertTestEntityID(108), CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	relationshipCoordinate := dfirMutationCoordinate{
		tenantID: tenantID, rootKind: dfirMutationRootCase, rootID: caseID,
		operation: "dfir.relationship.create", resourceKind: dfirMutationKindRelationship,
		resourceID: uuid.UUID(relationship.ID().Bytes()), resultVersion: 1,
	}
	relationshipDocument, err := encodeDFIRRelationshipResult(relationshipCoordinate, relationship)
	if err != nil {
		t.Fatal(err)
	}
	restoredRelationship, err := decodeDFIRRelationshipResult(relationshipDocument, relationshipCoordinate)
	if err != nil || !sameDFIRRelationship(relationship, restoredRelationship) {
		t.Fatalf("relationship snapshot round trip = (%v, %v)", restoredRelationship, err)
	}
	retractionID := alertTestEntityID(121)
	retracted, err := relationship.Retract(1, kernel.RelationshipRetractionInput{
		ID: retractionID, ActorID: alertTestEntityID(108), Reason: "duplicate link", OccurredAt: now.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	retractionUUID := uuid.UUID(retractionID.Bytes())
	retractionCoordinate := dfirMutationCoordinate{
		tenantID: tenantID, rootKind: dfirMutationRootCase, rootID: caseID,
		operation: "dfir.relationship.retract", resourceKind: dfirMutationKindRelationship,
		resourceID: uuid.UUID(relationship.ID().Bytes()), secondaryResourceID: &retractionUUID,
		resultVersion: 2,
	}
	retractionDocument, err := encodeDFIRRelationshipResult(retractionCoordinate, retracted)
	if err != nil {
		t.Fatal(err)
	}
	restoredRetraction, err := decodeDFIRRelationshipResult(retractionDocument, retractionCoordinate)
	if err != nil || !sameDFIRRelationship(retracted, restoredRetraction) {
		t.Fatalf("relationship retraction snapshot round trip = (%v, %v)", restoredRetraction, err)
	}
	driftedRetraction := retractionCoordinate
	wrongRetractionID := alertTestUUID(122)
	driftedRetraction.secondaryResourceID = &wrongRetractionID
	if _, err = decodeDFIRRelationshipResult(retractionDocument, driftedRetraction); err == nil {
		t.Fatal("relationship retraction caller-ID drift was accepted")
	}

	evidence, err := kernel.NewEvidence(kernel.EvidenceInput{
		ID: alertTestEntityID(109), TenantID: tenant, CaseID: caseEntity,
		StorageObjectID: alertTestEntityID(110), InitialCustodyEventID: alertTestEntityID(111),
		Title: "evidence receipt", Description: "immutable projection", EvidenceType: "disk_image",
		Classification: kernel.EvidenceRestricted, ContentSHA256: strings.Repeat("a", 64),
		SizeBytes: 4096, DetectedMIME: "application/octet-stream", CollectedAt: now,
		CollectedBy: alertTestEntityID(108), Source: "collector", ScanState: kernel.ScanAvailable,
	})
	if err != nil {
		t.Fatal(err)
	}
	evidenceCoordinate := dfirMutationCoordinate{
		tenantID: tenantID, rootKind: dfirMutationRootCase, rootID: caseID,
		operation: "dfir.evidence.create", resourceKind: dfirMutationKindEvidence,
		resourceID: uuid.UUID(evidence.ID().Bytes()), resultVersion: 1,
	}
	initialCustodyID := uuid.UUID(evidence.CustodyEvents()[0].ID().Bytes())
	evidenceCoordinate.secondaryResourceID = &initialCustodyID
	evidenceDocument, err := encodeDFIREvidenceResult(evidenceCoordinate, evidence)
	if err != nil {
		t.Fatal(err)
	}
	restoredEvidence, err := decodeDFIREvidenceResult(evidenceDocument, evidenceCoordinate)
	if err != nil || !sameDFIREvidence(evidence, restoredEvidence) {
		t.Fatalf("evidence snapshot round trip = (%v, %v)", restoredEvidence, err)
	}
}

func TestDFIRMutationSnapshotsRejectCoordinateAndShapeDrift(t *testing.T) {
	t.Parallel()
	coordinate := dfirMutationCoordinate{
		tenantID: alertTestUUID(112), rootKind: dfirMutationRootCase, rootID: alertTestUUID(113),
		operation: "dfir.ioc.replace", resourceKind: dfirMutationKindIOC,
		resourceID: alertTestUUID(114), resultVersion: kernel.MaximumResourceVersion,
	}
	indicator, err := kernel.NewIndicator(kernel.IndicatorInput{
		ID: entityID(coordinate.resourceID), TenantID: entityID(coordinate.tenantID), Type: kernel.IndicatorDomain,
		Value: "example.test", Source: "analyst", Confidence: 100, TLP: kernel.TLPRed,
		FirstSeen: alertTestTime(0), LastSeen: alertTestTime(0), Malicious: kernel.MaliciousConfirmed,
	})
	if err != nil {
		t.Fatal(err)
	}
	document, err := encodeDFIRIndicatorResult(coordinate, indicator)
	if err != nil {
		t.Fatal(err)
	}
	drifted := coordinate
	drifted.rootID = alertTestUUID(115)
	if _, err = decodeDFIRIndicatorResult(document, drifted); err == nil {
		t.Fatal("root-coordinate drift was accepted")
	}
	if _, err = decodeDFIRIndicatorResult(append(document, []byte(` {}`)...), coordinate); err == nil {
		t.Fatal("trailing snapshot content was accepted")
	}
	drifted = coordinate
	drifted.resultVersion = kernel.MaximumResourceVersion + 1
	if _, err = encodeDFIRIndicatorResult(drifted, indicator); err == nil {
		t.Fatal("non-JSON-safe terminal version was accepted")
	}
}

func TestPreparedUploadReceiptIsRedactedAndReplayRequiresLivePendingPair(t *testing.T) {
	t.Parallel()
	tenantID, caseID := alertTestUUID(116), alertTestUUID(117)
	storageID, attachmentID := alertTestEntityID(118), alertTestEntityID(119)
	tenant, creator := entityID(tenantID), alertTestEntityID(120)
	now := alertTestTime(0)
	storage, err := kernel.NewStorageObject(kernel.StorageObjectInput{
		ID: storageID, TenantID: tenant, Bucket: "sensitive-bucket", ObjectKey: tenantID.String() + "/" + storageID.String(),
		OriginalFilename: "forensic.bin", Classification: kernel.EvidenceRestricted,
		ExpectedSizeBytes: 4096, UploadExpiresAt: now.Add(15 * time.Minute), CreatedBy: creator, CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	subject, err := kernel.NewEntityReference(tenant, kernel.EntityCase, entityID(caseID))
	if err != nil {
		t.Fatal(err)
	}
	attachment, err := kernel.NewAttachment(kernel.AttachmentInput{
		ID: attachmentID, TenantID: tenant, Subject: subject, StorageObjectID: storageID,
		OriginalFilename: "forensic.bin", RequestedVisibility: kernel.VisibilityPrivate,
		SubjectVisibility: kernel.VisibilityPrivate, UploadedBy: creator, UploadedAt: now,
		ScanState: kernel.ScanPendingUpload,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondary := uuid.UUID(attachmentID.Bytes())
	coordinate := dfirMutationCoordinate{
		tenantID: tenantID, rootKind: dfirMutationRootCase, rootID: caseID,
		operation: "dfir.attachment.prepare", resourceKind: dfirMutationKindStorage,
		resourceID: uuid.UUID(storageID.Bytes()), secondaryResourceID: &secondary, resultVersion: 1,
	}
	document, err := encodeDFIRPreparedUploadResult(coordinate, storage, attachment)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"sensitive-bucket", storage.ObjectKey(), "application/octet-stream", "https://", "signature", "contentSha256"} {
		if strings.Contains(string(document), secret) {
			t.Fatalf("upload receipt leaked prohibited field %q: %s", secret, document)
		}
	}
	if !strings.Contains(string(document), "forensic.bin") {
		t.Fatal("exact attachment projection omitted originalFilename")
	}
	receipt, historicalAttachment, err := decodeDFIRPreparedUploadResult(document, coordinate)
	if err != nil {
		t.Fatal(err)
	}
	write := application.StorageWrite{Storage: storage, Attachment: attachment}
	if !validDFIRPreparedUploadReplay(receipt, historicalAttachment, storage, attachment, 1, write, now) {
		t.Fatal("fresh pending upload pair was not replay-eligible")
	}
	if validDFIRPreparedUploadReplay(receipt, historicalAttachment, storage, attachment, 2, write, now) {
		t.Fatal("mutated attachment version remained replay-eligible")
	}
	if validDFIRPreparedUploadReplay(receipt, historicalAttachment, storage, attachment, 1, write, storage.UploadExpiresAt()) {
		t.Fatal("expired upload remained replay-eligible")
	}
	uploaded, err := storage.MarkUploaded(1, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if validDFIRPreparedUploadReplay(receipt, historicalAttachment, uploaded, attachment, 1, write, now.Add(time.Second)) {
		t.Fatal("consumed upload remained replay-eligible")
	}
}
