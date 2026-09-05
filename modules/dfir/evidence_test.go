package dfir

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestEvidenceBuildsCanonicalTamperEvidentGenesis(t *testing.T) {
	input := validEvidenceInput()
	retention := input.CollectedAt.Add(24 * time.Hour)
	wantRetention := retention
	input.RetentionUntil = &retention
	evidence, err := NewEvidence(input)
	if err != nil {
		t.Fatalf("NewEvidence() error = %v", err)
	}
	if got, want := evidence.ContentSHA256(), strings.Repeat("ab", 32); got != want {
		t.Fatalf("ContentSHA256() = %q, want %q", got, want)
	}
	if got, want := evidence.DetectedMIME(), "application/pdf; charset=UTF-8"; got != want {
		t.Fatalf("DetectedMIME() = %q, want %q", got, want)
	}
	if evidence.Version() != 1 || len(evidence.CustodyEvents()) != 1 || !evidence.VerifyCustodyChain() {
		t.Fatal("new evidence did not create one valid genesis custody event")
	}
	events := evidence.CustodyEvents()
	if events[0].Action() != CustodyCollected || events[0].PreviousHash() == ([32]byte{}) ||
		events[0].EventHash() == ([32]byte{}) {
		t.Fatal("genesis custody event is not anchored and hashed")
	}
	*input.RetentionUntil = input.CollectedAt
	if got := evidence.RetentionUntil(); got == nil || !got.Equal(wantRetention) {
		t.Fatal("evidence retained caller-owned retention timestamp")
	}
}

func TestEvidenceRejectsUnverifiedOrIncoherentStorageState(t *testing.T) {
	for _, state := range []ScanState{ScanPendingUpload, ScanUploaded, ScanVerifying, ScanDeleted, "future"} {
		input := validEvidenceInput()
		input.ScanState = state
		if _, err := NewEvidence(input); err == nil {
			t.Fatalf("initial scan state %q was accepted", state)
		}
	}
	input := validEvidenceInput()
	input.ScanState = ScanRetained
	if _, err := NewEvidence(input); err == nil {
		t.Fatal("unretained retained-state evidence was accepted")
	}
}

func TestEvidenceCustodyIsImmutableVersionedAndReplaySafe(t *testing.T) {
	evidence := mustEvidence(t)
	at := evidence.CollectedAt().Add(time.Microsecond)
	access := CustodyEventInput{
		ID: fixtureID(51), ActorID: fixtureID(9), Action: CustodyAccessed,
		Reason: "forensic review", OccurredAt: at,
	}
	updated, err := evidence.AppendCustodyEvent(1, access)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Version() != 1 || len(evidence.CustodyEvents()) != 1 {
		t.Fatal("append mutated the original aggregate")
	}
	if updated.Version() != 2 || len(updated.CustodyEvents()) != 2 || !updated.VerifyCustodyChain() {
		t.Fatal("append did not create a valid versioned chain")
	}
	if _, err := updated.AppendCustodyEvent(1, CustodyEventInput{}); !errors.Is(err, ErrEvidenceConflict) {
		t.Fatalf("stale malformed command error = %v, want conflict", err)
	}
	access.ID = fixtureID(52)
	access.OccurredAt = at.Add(-time.Microsecond)
	if _, err := updated.AppendCustodyEvent(2, access); err == nil {
		t.Fatal("non-monotonic custody timestamp was accepted")
	}
	access.OccurredAt = at.Add(time.Microsecond)
	access.ID = fixtureID(51)
	if _, err := updated.AppendCustodyEvent(2, access); err == nil {
		t.Fatal("duplicate custody event id was accepted")
	}
}

func TestEvidenceLifecycleFailsClosedForScanRetentionHoldAndSeal(t *testing.T) {
	evidence := mustEvidence(t)
	base := evidence.CollectedAt()
	if evidence.CanIssueDownload() {
		t.Fatal("scanning evidence was downloadable")
	}

	available, err := evidence.ChangeScanState(1, CustodyEventInput{
		ID: fixtureID(52), ActorID: fixtureID(9), Action: CustodyScanStateChanged,
		Reason: "scanner clean", OccurredAt: base.Add(time.Microsecond),
	}, ScanAvailable)
	if err != nil || !available.CanIssueDownload() {
		t.Fatalf("clean evidence was not downloadable: %v", err)
	}
	if _, err := available.ChangeScanState(2, CustodyEventInput{
		ID: fixtureID(53), ActorID: fixtureID(9), Action: CustodyScanStateChanged,
		Reason: "invalid jump", OccurredAt: base.Add(2 * time.Microsecond),
	}, ScanScanning); err == nil {
		t.Fatal("invalid scan-state transition was accepted")
	}

	held, err := available.ChangeLegalHold(2, CustodyEventInput{
		ID: fixtureID(54), ActorID: fixtureID(9), Action: CustodyLegalHoldPlaced,
		Reason: "litigation hold", OccurredAt: base.Add(2 * time.Microsecond),
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := held.Destroy(3, CustodyEventInput{
		ID: fixtureID(55), ActorID: fixtureID(9), Action: CustodyDestroyed,
		Reason: "attempted deletion", OccurredAt: base.Add(3 * time.Microsecond),
	}); !errors.Is(err, ErrEvidenceRetention) {
		t.Fatalf("legal-hold destruction error = %v", err)
	}

	released, err := held.ChangeLegalHold(3, CustodyEventInput{
		ID: fixtureID(56), ActorID: fixtureID(9), Action: CustodyLegalHoldReleased,
		Reason: "hold released", OccurredAt: base.Add(3 * time.Microsecond),
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	retention := base.Add(time.Hour)
	retained, err := released.ChangeRetention(4, CustodyEventInput{
		ID: fixtureID(57), ActorID: fixtureID(9), Action: CustodyRetentionChanged,
		Reason: "policy retention", OccurredAt: base.Add(4 * time.Microsecond),
	}, &retention)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retained.Destroy(5, CustodyEventInput{
		ID: fixtureID(58), ActorID: fixtureID(9), Action: CustodyDestroyed,
		Reason: "too early", OccurredAt: base.Add(5 * time.Microsecond),
	}); !errors.Is(err, ErrEvidenceRetention) {
		t.Fatalf("retained destruction error = %v", err)
	}

	unretained, err := retained.ChangeRetention(5, CustodyEventInput{
		ID: fixtureID(59), ActorID: fixtureID(9), Action: CustodyRetentionChanged,
		Reason: "retention released", OccurredAt: base.Add(6 * time.Microsecond),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := unretained.AppendCustodyEvent(6, CustodyEventInput{
		ID: fixtureID(60), ActorID: fixtureID(9), Action: CustodySealed,
		Reason: "sealed for transport", OccurredAt: base.Add(7 * time.Microsecond),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sealed.Destroy(7, CustodyEventInput{
		ID: fixtureID(61), ActorID: fixtureID(9), Action: CustodyDestroyed,
		Reason: "sealed deletion", OccurredAt: base.Add(8 * time.Microsecond),
	}); !errors.Is(err, ErrEvidenceRetention) {
		t.Fatalf("sealed destruction error = %v", err)
	}
	unsealed, err := sealed.AppendCustodyEvent(7, CustodyEventInput{
		ID: fixtureID(62), ActorID: fixtureID(9), Action: CustodyUnsealed,
		Reason: "authorized unseal", OccurredAt: base.Add(8 * time.Microsecond),
	})
	if err != nil {
		t.Fatal(err)
	}
	destroyed, err := unsealed.Destroy(8, CustodyEventInput{
		ID: fixtureID(63), ActorID: fixtureID(9), Action: CustodyDestroyed,
		Reason: "authorized retention action", OccurredAt: base.Add(9 * time.Microsecond),
	})
	if err != nil || !destroyed.Destroyed() || destroyed.CanIssueDownload() || !destroyed.VerifyCustodyChain() {
		t.Fatalf("authorized destruction failed: %v", err)
	}
}

func TestEvidenceDetectsCustodyAndMetadataTampering(t *testing.T) {
	input := validEvidenceInput()
	input.ScanState = ScanAvailable
	evidence, err := NewEvidence(input)
	if err != nil || !evidence.CanIssueDownload() {
		t.Fatalf("available fixture failed: %v", err)
	}
	tamperedEvent := evidence
	tamperedEvent.custody = cloneCustodyForTest(evidence.custody)
	tamperedEvent.custody[0].reason = "rewritten history"
	if tamperedEvent.VerifyCustodyChain() {
		t.Fatal("rewritten custody reason passed verification")
	}
	if tamperedEvent.CanIssueDownload() {
		t.Fatal("invalid custody chain remained downloadable")
	}
	if _, err := tamperedEvent.AppendCustodyEvent(1, CustodyEventInput{}); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("mutation on invalid chain error = %v", err)
	}

	tamperedMetadata := evidence
	tamperedMetadata.title = "rewritten title"
	if tamperedMetadata.VerifyCustodyChain() {
		t.Fatal("rewritten anchored metadata passed verification")
	}
}

func TestEvidenceFormattingRedactsMetadataAndCustodyReason(t *testing.T) {
	evidence := mustEvidence(t)
	for _, rendered := range []string{fmt.Sprint(evidence), fmt.Sprintf("%#v", evidence)} {
		for _, secret := range []string{
			evidence.Title(), evidence.Description(), evidence.ContentSHA256(),
			evidence.DetectedMIME(), evidence.Source(),
		} {
			if strings.Contains(rendered, secret) {
				t.Fatalf("evidence formatting leaked %q: %q", secret, rendered)
			}
		}
	}
	event := evidence.CustodyEvents()[0]
	if rendered := fmt.Sprintf("%#v", event); strings.Contains(rendered, event.Reason()) {
		t.Fatalf("custody formatting leaked reason: %q", rendered)
	}
}

func TestEvidenceSnapshotRestoresAndRejectsCustodyProjectionTampering(t *testing.T) {
	evidence := mustEvidence(t)
	state := evidence.Snapshot()
	restored, err := RestoreEvidence(state)
	if err != nil || !restored.VerifyCustodyChain() || restored.Version() != evidence.Version() {
		t.Fatalf("restored evidence=%#v error=%v", restored, err)
	}
	for _, rendered := range []string{fmt.Sprint(state), fmt.Sprintf("%#v", state)} {
		for _, sensitive := range []string{state.Title, state.Description, state.ContentSHA256, state.Source} {
			if strings.Contains(rendered, sensitive) {
				t.Fatalf("evidence state formatting leaked %q: %q", sensitive, rendered)
			}
		}
	}

	state.CustodyEvents = append([]CustodyEventState(nil), state.CustodyEvents...)
	state.CustodyEvents[0].Reason = "rewritten after persistence"
	if _, err := RestoreEvidence(state); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("tampered custody projection error = %v", err)
	}
}

func TestEvidenceRejectsObjectLargerThanS3Limit(t *testing.T) {
	input := validEvidenceInput()
	input.SizeBytes = maximumStorageObjectBytes + 1
	if _, err := NewEvidence(input); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("oversized evidence error = %v", err)
	}
}

func TestEvidenceCustodyStopsAtSharedSnapshotBound(t *testing.T) {
	evidence := mustEvidence(t)
	base := evidence.CollectedAt()
	for sequence := uint64(2); sequence <= MaximumCustodyEvents; sequence++ {
		var err error
		evidence, err = evidence.AppendCustodyEvent(evidence.Version(), CustodyEventInput{
			ID: fixtureID(uint16(1_000 + sequence)), ActorID: fixtureID(9),
			Action: CustodyAccessed, Reason: "bounded forensic review",
			OccurredAt: base.Add(time.Duration(sequence) * time.Microsecond),
		})
		if err != nil {
			t.Fatalf("append custody sequence %d: %v", sequence, err)
		}
	}
	if evidence.Version() != MaximumCustodyEvents || uint64(len(evidence.CustodyEvents())) != MaximumCustodyEvents {
		t.Fatalf("bounded evidence = version %d, custody %d", evidence.Version(), len(evidence.CustodyEvents()))
	}
	if _, err := evidence.AppendCustodyEvent(evidence.Version(), CustodyEventInput{
		ID: fixtureID(2_100), ActorID: fixtureID(9), Action: CustodyAccessed,
		Reason: "overflow", OccurredAt: base.Add(time.Duration(MaximumCustodyEvents+1) * time.Microsecond),
	}); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("custody overflow error = %v", err)
	}
	state := evidence.Snapshot()
	state.CustodyEvents = append(state.CustodyEvents, state.CustodyEvents[len(state.CustodyEvents)-1])
	state.Version++
	if _, err := RestoreEvidence(state); !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("oversized restored custody error = %v", err)
	}
}

func mustEvidence(t *testing.T) Evidence {
	t.Helper()
	evidence, err := NewEvidence(validEvidenceInput())
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func validEvidenceInput() EvidenceInput {
	return EvidenceInput{
		ID: fixtureID(40), TenantID: fixtureID(1), CaseID: fixtureID(20),
		StorageObjectID: fixtureID(41), InitialCustodyEventID: fixtureID(50),
		Title: "Private disk image", Description: "Collected from affected endpoint",
		EvidenceType: "disk_image", Classification: EvidenceRestricted,
		ContentSHA256: strings.Repeat("AB", 32), SizeBytes: 1_048_576,
		DetectedMIME: "Application/PDF; Charset=UTF-8",
		CollectedAt:  time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC),
		CollectedBy:  fixtureID(9), Source: "endpoint private-host",
		ScanState: ScanScanning,
	}
}

func cloneCustodyForTest(values []CustodyEvent) []CustodyEvent {
	result := make([]CustodyEvent, len(values))
	copy(result, values)
	return result
}
