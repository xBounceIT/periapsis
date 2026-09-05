package dfir

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"mime"
	"slices"
	"strings"
	"time"
)

type EvidenceClassification string

const (
	EvidencePublic       EvidenceClassification = "public"
	EvidenceInternal     EvidenceClassification = "internal"
	EvidenceConfidential EvidenceClassification = "confidential"
	EvidenceRestricted   EvidenceClassification = "restricted"
)

func validEvidenceClassification(value EvidenceClassification) bool {
	return value == EvidencePublic || value == EvidenceInternal ||
		value == EvidenceConfidential || value == EvidenceRestricted
}

type ScanState string

const (
	ScanPendingUpload ScanState = "pending_upload"
	ScanUploaded      ScanState = "uploaded"
	ScanVerifying     ScanState = "verifying"
	ScanQuarantined   ScanState = "quarantined"
	ScanScanning      ScanState = "scanning"
	ScanAvailable     ScanState = "available"
	ScanRejected      ScanState = "rejected"
	ScanFailed        ScanState = "scan_failed"
	ScanRetained      ScanState = "retained"
	ScanDeleted       ScanState = "deleted"
)

func validScanState(value ScanState) bool {
	switch value {
	case ScanPendingUpload, ScanUploaded, ScanVerifying, ScanQuarantined,
		ScanScanning, ScanAvailable, ScanRejected, ScanFailed, ScanRetained, ScanDeleted:
		return true
	default:
		return false
	}
}

func validScanTransition(from, to ScanState) bool {
	switch from {
	case ScanPendingUpload:
		return to == ScanUploaded
	case ScanUploaded:
		return to == ScanVerifying
	case ScanVerifying:
		return to == ScanQuarantined || to == ScanRejected
	case ScanQuarantined:
		return to == ScanScanning
	case ScanScanning:
		return to == ScanAvailable || to == ScanRejected || to == ScanFailed
	case ScanFailed:
		return to == ScanScanning
	case ScanAvailable:
		return to == ScanRetained || to == ScanDeleted
	case ScanRetained:
		return to == ScanAvailable
	default:
		return false
	}
}

type CustodyAction string

const (
	CustodyCollected         CustodyAction = "collected"
	CustodyAccessed          CustodyAction = "accessed"
	CustodyTransferred       CustodyAction = "transferred"
	CustodySealed            CustodyAction = "sealed"
	CustodyUnsealed          CustodyAction = "unsealed"
	CustodyScanStateChanged  CustodyAction = "scan_state_changed"
	CustodyRetentionChanged  CustodyAction = "retention_changed"
	CustodyLegalHoldPlaced   CustodyAction = "legal_hold_placed"
	CustodyLegalHoldReleased CustodyAction = "legal_hold_released"
	CustodyDestroyed         CustodyAction = "destroyed"
)

func validCustodyAction(value CustodyAction) bool {
	switch value {
	case CustodyCollected, CustodyAccessed, CustodyTransferred, CustodySealed,
		CustodyUnsealed, CustodyScanStateChanged, CustodyRetentionChanged,
		CustodyLegalHoldPlaced, CustodyLegalHoldReleased, CustodyDestroyed:
		return true
	default:
		return false
	}
}

type EvidenceInput struct {
	ID                    EntityID
	TenantID              EntityID
	CaseID                EntityID
	StorageObjectID       EntityID
	InitialCustodyEventID EntityID
	Title                 string
	Description           string
	EvidenceType          string
	Classification        EvidenceClassification
	ContentSHA256         string
	SizeBytes             int64
	DetectedMIME          string
	CollectedAt           time.Time
	CollectedBy           EntityID
	Source                string
	RetentionUntil        *time.Time
	LegalHold             bool
	ScanState             ScanState
}

type CustodyEventInput struct {
	ID         EntityID
	ActorID    EntityID
	Action     CustodyAction
	Reason     string
	OccurredAt time.Time
}

type CustodyEvent struct {
	id           EntityID
	tenantID     EntityID
	evidenceID   EntityID
	sequence     uint64
	action       CustodyAction
	actorID      EntityID
	reason       string
	stateValue   string
	previousHash [32]byte
	eventHash    [32]byte
	occurredAt   time.Time
}

type CustodyEventState struct {
	ID           EntityID
	TenantID     EntityID
	EvidenceID   EntityID
	Sequence     uint64
	Action       CustodyAction
	ActorID      EntityID
	Reason       string
	StateValue   string
	PreviousHash [32]byte
	EventHash    [32]byte
	OccurredAt   time.Time
}

func (event CustodyEvent) ID() EntityID           { return event.id }
func (event CustodyEvent) TenantID() EntityID     { return event.tenantID }
func (event CustodyEvent) EvidenceID() EntityID   { return event.evidenceID }
func (event CustodyEvent) Sequence() uint64       { return event.sequence }
func (event CustodyEvent) Action() CustodyAction  { return event.action }
func (event CustodyEvent) ActorID() EntityID      { return event.actorID }
func (event CustodyEvent) Reason() string         { return event.reason }
func (event CustodyEvent) PreviousHash() [32]byte { return event.previousHash }
func (event CustodyEvent) EventHash() [32]byte    { return event.eventHash }
func (event CustodyEvent) OccurredAt() time.Time  { return event.occurredAt }
func (event CustodyEvent) StateValue() string     { return event.stateValue }
func (event CustodyEvent) Snapshot() CustodyEventState {
	return CustodyEventState{
		ID: event.id, TenantID: event.tenantID, EvidenceID: event.evidenceID,
		Sequence: event.sequence, Action: event.action, ActorID: event.actorID,
		Reason: event.reason, StateValue: event.stateValue,
		PreviousHash: event.previousHash, EventHash: event.eventHash, OccurredAt: event.occurredAt,
	}
}
func (event CustodyEvent) String() string {
	return fmt.Sprintf("dfir.CustodyEvent{sequence:%d,action:%s,reason:[REDACTED]}", event.sequence, event.action)
}
func (event CustodyEvent) GoString() string { return event.String() }

type Evidence struct {
	rootKind              evidenceRootKind
	id                    EntityID
	tenantID              EntityID
	caseID                EntityID
	storageObjectID       EntityID
	title                 string
	description           string
	evidenceType          string
	classification        EvidenceClassification
	contentSHA256         string
	sizeBytes             int64
	detectedMIME          string
	collectedAt           time.Time
	collectedBy           EntityID
	source                string
	retentionUntil        *time.Time
	legalHold             bool
	scanState             ScanState
	initialRetentionUntil *time.Time
	initialLegalHold      bool
	initialScanState      ScanState
	sealed                bool
	destroyed             bool
	version               uint64
	custody               []CustodyEvent
}

type evidenceRootKind uint8

const (
	evidenceCaseRoot evidenceRootKind = iota
	evidenceAlertRoot
)

// EvidenceState is the complete immutable-revision and custody-chain
// persistence representation. String and GoString redact every customer or
// evidence-derived value.
type EvidenceState struct {
	ID                    EntityID
	TenantID              EntityID
	CaseID                EntityID
	StorageObjectID       EntityID
	Title                 string
	Description           string
	EvidenceType          string
	Classification        EvidenceClassification
	ContentSHA256         string
	SizeBytes             int64
	DetectedMIME          string
	CollectedAt           time.Time
	CollectedBy           EntityID
	Source                string
	RetentionUntil        *time.Time
	LegalHold             bool
	ScanState             ScanState
	InitialRetentionUntil *time.Time
	InitialLegalHold      bool
	InitialScanState      ScanState
	Sealed                bool
	Destroyed             bool
	Version               uint64
	CustodyEvents         []CustodyEventState
}

func (state EvidenceState) String() string {
	return fmt.Sprintf(
		"dfir.EvidenceState{classification:%s,scanState:%s,version:%d,custody:%d,metadata:[REDACTED],hash:[REDACTED]}",
		state.Classification, state.ScanState, state.Version, len(state.CustodyEvents),
	)
}

func (state EvidenceState) GoString() string { return state.String() }

func NewEvidence(input EvidenceInput) (Evidence, error) {
	return newEvidence(input, evidenceCaseRoot)
}

func newEvidence(input EvidenceInput, rootKind evidenceRootKind) (Evidence, error) {
	contentHash, hashErr := normalizeHexDigest(input.ContentSHA256, sha256.Size)
	detectedMIME, mimeErr := normalizeMediaType(input.DetectedMIME)
	retention, retentionOK := canonicalOptionalInstant(input.RetentionUntil)
	if rootKind != evidenceCaseRoot && rootKind != evidenceAlertRoot ||
		!validEntityID(input.ID) || !validEntityID(input.TenantID) || !validEntityID(input.CaseID) ||
		!validEntityID(input.StorageObjectID) || !validEntityID(input.InitialCustodyEventID) ||
		!validSingleLineText(input.Title, 512, false) || !validOptionalText(input.Description, 16*1024) ||
		!validStableKey(input.EvidenceType) || !validEvidenceClassification(input.Classification) ||
		hashErr != nil || input.SizeBytes <= 0 || input.SizeBytes > maximumStorageObjectBytes ||
		mimeErr != nil || !validInstant(input.CollectedAt) ||
		!validEntityID(input.CollectedBy) || !validSingleLineText(input.Source, 512, false) ||
		!retentionOK || retention != nil && retention.Before(input.CollectedAt) || !validScanState(input.ScanState) ||
		!validInitialEvidenceScanState(input.ScanState) ||
		input.ScanState == ScanRetained && !input.LegalHold &&
			(retention == nil || !retention.After(input.CollectedAt)) {
		return Evidence{}, ErrInvalidEvidence
	}

	evidence := Evidence{
		rootKind: rootKind, id: input.ID, tenantID: input.TenantID, caseID: input.CaseID,
		storageObjectID: input.StorageObjectID,
		title:           input.Title, description: input.Description,
		evidenceType: input.EvidenceType, classification: input.Classification,
		contentSHA256: contentHash, sizeBytes: input.SizeBytes, detectedMIME: detectedMIME,
		collectedAt: input.CollectedAt, collectedBy: input.CollectedBy, source: input.Source,
		retentionUntil: retention, legalHold: input.LegalHold, scanState: input.ScanState,
		initialRetentionUntil: cloneInstant(retention), initialLegalHold: input.LegalHold,
		initialScanState: input.ScanState,
		version:          1,
	}
	initial := evidence.newCustodyEvent(
		input.InitialCustodyEventID,
		input.CollectedBy,
		CustodyCollected,
		"initial collection",
		"",
		input.CollectedAt,
		1,
		evidence.anchorHash(),
	)
	evidence.custody = []CustodyEvent{initial}
	return evidence, nil
}

func RestoreEvidence(state EvidenceState) (Evidence, error) {
	return restoreEvidence(state, evidenceCaseRoot)
}

func restoreEvidence(state EvidenceState, rootKind evidenceRootKind) (Evidence, error) {
	retentionUntil, retentionOK := canonicalOptionalInstant(state.RetentionUntil)
	initialRetentionUntil, initialRetentionOK := canonicalOptionalInstant(state.InitialRetentionUntil)
	if rootKind != evidenceCaseRoot && rootKind != evidenceAlertRoot ||
		!retentionOK || !initialRetentionOK || len(state.CustodyEvents) == 0 ||
		uint64(len(state.CustodyEvents)) > MaximumCustodyEvents {
		return Evidence{}, ErrInvalidEvidence
	}
	custody := make([]CustodyEvent, len(state.CustodyEvents))
	for index, event := range state.CustodyEvents {
		custody[index] = CustodyEvent{
			id: event.ID, tenantID: event.TenantID, evidenceID: event.EvidenceID,
			sequence: event.Sequence, action: event.Action, actorID: event.ActorID,
			reason: event.Reason, stateValue: event.StateValue,
			previousHash: event.PreviousHash, eventHash: event.EventHash, occurredAt: event.OccurredAt,
		}
	}
	evidence := Evidence{
		rootKind: rootKind, id: state.ID, tenantID: state.TenantID, caseID: state.CaseID,
		storageObjectID: state.StorageObjectID, title: state.Title, description: state.Description,
		evidenceType: state.EvidenceType, classification: state.Classification,
		contentSHA256: state.ContentSHA256, sizeBytes: state.SizeBytes,
		detectedMIME: state.DetectedMIME, collectedAt: state.CollectedAt,
		collectedBy: state.CollectedBy, source: state.Source,
		retentionUntil: retentionUntil, legalHold: state.LegalHold, scanState: state.ScanState,
		initialRetentionUntil: initialRetentionUntil, initialLegalHold: state.InitialLegalHold,
		initialScanState: state.InitialScanState, sealed: state.Sealed,
		destroyed: state.Destroyed, version: state.Version, custody: custody,
	}
	if !evidence.verifyCustodyChain(rootKind) {
		return Evidence{}, ErrInvalidEvidence
	}
	return evidence, nil
}

func (evidence Evidence) ID() EntityID                           { return evidence.id }
func (evidence Evidence) TenantID() EntityID                     { return evidence.tenantID }
func (evidence Evidence) CaseID() EntityID                       { return evidence.caseID }
func (evidence Evidence) StorageObjectID() EntityID              { return evidence.storageObjectID }
func (evidence Evidence) Title() string                          { return evidence.title }
func (evidence Evidence) Description() string                    { return evidence.description }
func (evidence Evidence) EvidenceType() string                   { return evidence.evidenceType }
func (evidence Evidence) Classification() EvidenceClassification { return evidence.classification }
func (evidence Evidence) ContentSHA256() string                  { return evidence.contentSHA256 }
func (evidence Evidence) SizeBytes() int64                       { return evidence.sizeBytes }
func (evidence Evidence) DetectedMIME() string                   { return evidence.detectedMIME }
func (evidence Evidence) CollectedAt() time.Time                 { return evidence.collectedAt }
func (evidence Evidence) CollectedBy() EntityID                  { return evidence.collectedBy }
func (evidence Evidence) Source() string                         { return evidence.source }
func (evidence Evidence) LegalHold() bool                        { return evidence.legalHold }
func (evidence Evidence) ScanState() ScanState                   { return evidence.scanState }
func (evidence Evidence) Sealed() bool                           { return evidence.sealed }
func (evidence Evidence) Destroyed() bool                        { return evidence.destroyed }
func (evidence Evidence) Version() uint64                        { return evidence.version }
func (evidence Evidence) RetentionUntil() *time.Time {
	return cloneInstant(evidence.retentionUntil)
}
func (evidence Evidence) CustodyEvents() []CustodyEvent { return slices.Clone(evidence.custody) }
func (evidence Evidence) Snapshot() EvidenceState {
	custody := make([]CustodyEventState, len(evidence.custody))
	for index, event := range evidence.custody {
		custody[index] = event.Snapshot()
	}
	return EvidenceState{
		ID: evidence.id, TenantID: evidence.tenantID, CaseID: evidence.caseID,
		StorageObjectID: evidence.storageObjectID, Title: evidence.title,
		Description: evidence.description, EvidenceType: evidence.evidenceType,
		Classification: evidence.classification, ContentSHA256: evidence.contentSHA256,
		SizeBytes: evidence.sizeBytes, DetectedMIME: evidence.detectedMIME,
		CollectedAt: evidence.collectedAt, CollectedBy: evidence.collectedBy, Source: evidence.source,
		RetentionUntil: cloneInstant(evidence.retentionUntil), LegalHold: evidence.legalHold,
		ScanState: evidence.scanState, InitialRetentionUntil: cloneInstant(evidence.initialRetentionUntil),
		InitialLegalHold: evidence.initialLegalHold, InitialScanState: evidence.initialScanState,
		Sealed: evidence.sealed, Destroyed: evidence.destroyed, Version: evidence.version,
		CustodyEvents: custody,
	}
}
func (evidence Evidence) CanIssueDownload() bool {
	return evidence.canIssueDownload(evidenceCaseRoot)
}

func (evidence Evidence) canIssueDownload(expectedRoot evidenceRootKind) bool {
	return evidence.verifyCustodyChain(expectedRoot) && !evidence.destroyed && evidence.scanState == ScanAvailable
}
func (evidence Evidence) String() string {
	return fmt.Sprintf(
		"dfir.Evidence{classification:%s,scanState:%s,sizeBytes:%d,version:%d,custody:%d,legalHold:%t,sealed:%t,destroyed:%t,metadata:[REDACTED],contentHash:[REDACTED]}",
		evidence.classification, evidence.scanState, evidence.sizeBytes, evidence.version,
		len(evidence.custody), evidence.legalHold, evidence.sealed, evidence.destroyed,
	)
}
func (evidence Evidence) GoString() string { return evidence.String() }

func (evidence Evidence) AppendCustodyEvent(expectedVersion uint64, input CustodyEventInput) (Evidence, error) {
	if err := evidence.requireExpectedVersion(expectedVersion); err != nil {
		return Evidence{}, err
	}
	if input.Action != CustodyAccessed && input.Action != CustodyTransferred &&
		input.Action != CustodySealed && input.Action != CustodyUnsealed {
		return Evidence{}, ErrInvalidEvidence
	}
	if input.Action == CustodySealed && evidence.sealed || input.Action == CustodyUnsealed && !evidence.sealed {
		return Evidence{}, ErrInvalidEvidence
	}
	updated, err := evidence.appendEvent(expectedVersion, input, "")
	if err != nil {
		return Evidence{}, err
	}
	if input.Action == CustodySealed {
		updated.sealed = true
	} else if input.Action == CustodyUnsealed {
		updated.sealed = false
	}
	return updated, nil
}

func (evidence Evidence) ChangeScanState(
	expectedVersion uint64,
	input CustodyEventInput,
	next ScanState,
) (Evidence, error) {
	if err := evidence.requireExpectedVersion(expectedVersion); err != nil {
		return Evidence{}, err
	}
	if input.Action != CustodyScanStateChanged || !validScanState(next) ||
		!validScanTransition(evidence.scanState, next) {
		return Evidence{}, ErrInvalidEvidence
	}
	if next == ScanDeleted && (evidence.legalHold || evidence.sealed ||
		evidence.retentionUntil != nil && evidence.retentionUntil.After(input.OccurredAt)) {
		return Evidence{}, ErrEvidenceRetention
	}
	if next == ScanRetained && !evidence.legalHold &&
		(evidence.retentionUntil == nil || !evidence.retentionUntil.After(input.OccurredAt)) {
		return Evidence{}, ErrInvalidEvidence
	}
	if evidence.scanState == ScanRetained && next == ScanAvailable &&
		(evidence.legalHold || evidence.retentionUntil != nil && evidence.retentionUntil.After(input.OccurredAt)) {
		return Evidence{}, ErrEvidenceRetention
	}
	updated, err := evidence.appendEvent(expectedVersion, input, string(next))
	if err != nil {
		return Evidence{}, err
	}
	updated.scanState = next
	if next == ScanDeleted {
		updated.destroyed = true
	}
	return updated, nil
}

func (evidence Evidence) ChangeLegalHold(
	expectedVersion uint64,
	input CustodyEventInput,
	enabled bool,
) (Evidence, error) {
	if err := evidence.requireExpectedVersion(expectedVersion); err != nil {
		return Evidence{}, err
	}
	wantAction := CustodyLegalHoldPlaced
	if !enabled {
		wantAction = CustodyLegalHoldReleased
	}
	if input.Action != wantAction || evidence.legalHold == enabled {
		return Evidence{}, ErrInvalidEvidence
	}
	updated, err := evidence.appendEvent(expectedVersion, input, fmt.Sprintf("%t", enabled))
	if err != nil {
		return Evidence{}, err
	}
	updated.legalHold = enabled
	return updated, nil
}

func (evidence Evidence) ChangeRetention(
	expectedVersion uint64,
	input CustodyEventInput,
	retentionUntil *time.Time,
) (Evidence, error) {
	if err := evidence.requireExpectedVersion(expectedVersion); err != nil {
		return Evidence{}, err
	}
	canonical, ok := canonicalOptionalInstant(retentionUntil)
	if input.Action != CustodyRetentionChanged || !ok ||
		canonical != nil && canonical.Before(evidence.collectedAt) ||
		equalInstants(evidence.retentionUntil, canonical) {
		return Evidence{}, ErrInvalidEvidence
	}
	stateValue := "none"
	if canonical != nil {
		stateValue = canonical.Format(time.RFC3339Nano)
	}
	updated, err := evidence.appendEvent(expectedVersion, input, stateValue)
	if err != nil {
		return Evidence{}, err
	}
	updated.retentionUntil = canonical
	return updated, nil
}

func (evidence Evidence) Destroy(expectedVersion uint64, input CustodyEventInput) (Evidence, error) {
	if err := evidence.requireExpectedVersion(expectedVersion); err != nil {
		return Evidence{}, err
	}
	if input.Action != CustodyDestroyed || !validCustodyEventInput(input) {
		return Evidence{}, ErrInvalidEvidence
	}
	if evidence.legalHold || evidence.sealed || evidence.destroyed || evidence.scanState != ScanAvailable ||
		evidence.retentionUntil != nil && evidence.retentionUntil.After(input.OccurredAt) {
		return Evidence{}, ErrEvidenceRetention
	}
	updated, err := evidence.appendEvent(expectedVersion, input, "")
	if err != nil {
		return Evidence{}, err
	}
	updated.destroyed = true
	updated.scanState = ScanDeleted
	return updated, nil
}

func (evidence Evidence) VerifyCustodyChain() bool {
	return evidence.verifyCustodyChain(evidenceCaseRoot)
}

func (evidence Evidence) verifyCustodyChain(expectedRoot evidenceRootKind) bool {
	if evidence.rootKind != expectedRoot || !validEvidence(evidence) {
		return false
	}
	previous := evidence.anchorHash()
	scanState := evidence.initialScanState
	legalHold := evidence.initialLegalHold
	retentionUntil := cloneInstant(evidence.initialRetentionUntil)
	sealed := false
	destroyed := false
	var previousTime time.Time
	for index, event := range evidence.custody {
		if event.sequence != uint64(index+1) || event.tenantID != evidence.tenantID ||
			event.evidenceID != evidence.id || event.previousHash != previous ||
			event.eventHash != calculateCustodyHash(event) || !validEntityID(event.id) ||
			!validEntityID(event.actorID) || !validCustodyAction(event.action) ||
			!validSingleLineText(event.reason, 2_000, false) || !validInstant(event.occurredAt) ||
			index > 0 && event.occurredAt.Before(previousTime) ||
			index == 0 && event.action != CustodyCollected || index > 0 && event.action == CustodyCollected {
			return false
		}
		switch event.action {
		case CustodyCollected, CustodyAccessed, CustodyTransferred:
			if event.stateValue != "" || destroyed {
				return false
			}
			if event.action == CustodyCollected && !event.occurredAt.Equal(evidence.collectedAt) {
				return false
			}
		case CustodySealed:
			if event.stateValue != "" || sealed || destroyed {
				return false
			}
			sealed = true
		case CustodyUnsealed:
			if event.stateValue != "" || !sealed || destroyed {
				return false
			}
			sealed = false
		case CustodyScanStateChanged:
			next := ScanState(event.stateValue)
			if destroyed || !validScanTransition(scanState, next) {
				return false
			}
			if next == ScanDeleted && (legalHold || sealed ||
				retentionUntil != nil && retentionUntil.After(event.occurredAt)) {
				return false
			}
			if next == ScanRetained && !legalHold &&
				(retentionUntil == nil || !retentionUntil.After(event.occurredAt)) {
				return false
			}
			if scanState == ScanRetained && next == ScanAvailable &&
				(legalHold || retentionUntil != nil && retentionUntil.After(event.occurredAt)) {
				return false
			}
			scanState = next
			if next == ScanDeleted {
				destroyed = true
			}
		case CustodyLegalHoldPlaced:
			if destroyed || legalHold || event.stateValue != "true" {
				return false
			}
			legalHold = true
		case CustodyLegalHoldReleased:
			if destroyed || !legalHold || event.stateValue != "false" {
				return false
			}
			legalHold = false
		case CustodyRetentionChanged:
			if destroyed {
				return false
			}
			if event.stateValue == "none" {
				retentionUntil = nil
			} else {
				parsed, err := time.Parse(time.RFC3339Nano, event.stateValue)
				if err != nil || !validInstant(parsed) || parsed.Before(evidence.collectedAt) {
					return false
				}
				retentionUntil = &parsed
			}
		case CustodyDestroyed:
			if event.stateValue != "" || destroyed || legalHold || sealed || scanState != ScanAvailable ||
				retentionUntil != nil && retentionUntil.After(event.occurredAt) {
				return false
			}
			destroyed = true
			scanState = ScanDeleted
		}
		previous = event.eventHash
		previousTime = event.occurredAt
	}
	return scanState == evidence.scanState && legalHold == evidence.legalHold &&
		equalInstants(retentionUntil, evidence.retentionUntil) && sealed == evidence.sealed &&
		destroyed == evidence.destroyed
}

func (evidence Evidence) appendEvent(
	expectedVersion uint64,
	input CustodyEventInput,
	stateValue string,
) (Evidence, error) {
	if err := evidence.requireExpectedVersion(expectedVersion); err != nil {
		return Evidence{}, err
	}
	if evidence.destroyed || !validCustodyEventInput(input) ||
		input.OccurredAt.Before(evidence.custody[len(evidence.custody)-1].occurredAt) ||
		evidence.version >= MaximumCustodyEvents {
		return Evidence{}, ErrInvalidEvidence
	}
	for _, existing := range evidence.custody {
		if existing.id == input.ID {
			return Evidence{}, ErrInvalidEvidence
		}
	}
	updated := evidence
	updated.retentionUntil = cloneInstant(evidence.retentionUntil)
	updated.initialRetentionUntil = cloneInstant(evidence.initialRetentionUntil)
	updated.custody = slices.Clone(evidence.custody)
	previous := updated.custody[len(updated.custody)-1].eventHash
	event := updated.newCustodyEvent(
		input.ID, input.ActorID, input.Action, input.Reason, stateValue,
		input.OccurredAt, uint64(len(updated.custody)+1), previous,
	)
	updated.custody = append(updated.custody, event)
	updated.version++
	return updated, nil
}

func (evidence Evidence) newCustodyEvent(
	id EntityID,
	actor EntityID,
	action CustodyAction,
	reason string,
	stateValue string,
	occurredAt time.Time,
	sequence uint64,
	previousHash [32]byte,
) CustodyEvent {
	event := CustodyEvent{
		id: id, tenantID: evidence.tenantID, evidenceID: evidence.id,
		sequence: sequence, action: action, actorID: actor,
		reason: reason, stateValue: stateValue,
		previousHash: previousHash, occurredAt: occurredAt,
	}
	event.eventHash = calculateCustodyHash(event)
	return event
}

func (evidence Evidence) anchorHash() [32]byte {
	hash := sha256.New()
	domain := "periapsis:dfir:evidence-anchor:v1"
	if evidence.rootKind == evidenceAlertRoot {
		domain = "periapsis:dfir:alert-evidence-anchor:v1"
	}
	writeHashField(hash, []byte(domain))
	writeHashField(hash, evidence.id.value[:])
	writeHashField(hash, evidence.tenantID.value[:])
	writeHashField(hash, evidence.caseID.value[:])
	writeHashField(hash, evidence.storageObjectID.value[:])
	for _, value := range []string{
		evidence.title, evidence.description, evidence.evidenceType, string(evidence.classification),
		evidence.contentSHA256, evidence.detectedMIME, evidence.source,
	} {
		writeHashField(hash, []byte(value))
	}
	writeHashUint64(hash, uint64(evidence.sizeBytes))
	writeHashUint64(hash, uint64(evidence.collectedAt.UnixMicro()))
	writeHashField(hash, evidence.collectedBy.value[:])
	writeHashField(hash, []byte(evidence.initialScanState))
	if evidence.initialRetentionUntil == nil {
		writeHashField(hash, nil)
	} else {
		writeHashField(hash, []byte(evidence.initialRetentionUntil.Format(time.RFC3339Nano)))
	}
	if evidence.initialLegalHold {
		writeHashField(hash, []byte{1})
	} else {
		writeHashField(hash, []byte{0})
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func calculateCustodyHash(event CustodyEvent) [32]byte {
	hash := sha256.New()
	writeHashField(hash, []byte("periapsis:dfir:custody-event:v1"))
	writeHashField(hash, event.previousHash[:])
	writeHashField(hash, event.id.value[:])
	writeHashField(hash, event.tenantID.value[:])
	writeHashField(hash, event.evidenceID.value[:])
	writeHashUint64(hash, event.sequence)
	writeHashField(hash, []byte(event.action))
	writeHashField(hash, event.actorID.value[:])
	writeHashField(hash, []byte(event.reason))
	writeHashField(hash, []byte(event.stateValue))
	writeHashUint64(hash, uint64(event.occurredAt.UnixMicro()))
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

type byteWriter interface {
	Write([]byte) (int, error)
}

func writeHashField(writer byteWriter, value []byte) {
	writeHashUint64(writer, uint64(len(value)))
	_, _ = writer.Write(value)
}

func writeHashUint64(writer byteWriter, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = writer.Write(encoded[:])
}

func normalizeMediaType(value string) (string, error) {
	if !validBoundedText(value, 512, false) {
		return "", ErrInvalidEvidence
	}
	mediaType, parameters, err := mime.ParseMediaType(value)
	if err != nil || !strings.Contains(mediaType, "/") {
		return "", ErrInvalidEvidence
	}
	return mime.FormatMediaType(strings.ToLower(mediaType), parameters), nil
}

func canonicalOptionalInstant(value *time.Time) (*time.Time, bool) {
	if value == nil {
		return nil, true
	}
	if !validInstant(*value) {
		return nil, false
	}
	copy := *value
	return &copy, true
}

func cloneInstant(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func equalInstants(left, right *time.Time) bool {
	return left == nil && right == nil || left != nil && right != nil && left.Equal(*right)
}

func validCustodyEventInput(input CustodyEventInput) bool {
	return validEntityID(input.ID) && validEntityID(input.ActorID) &&
		validCustodyAction(input.Action) && validSingleLineText(input.Reason, 2_000, false) &&
		validInstant(input.OccurredAt)
}

func (evidence Evidence) requireExpectedVersion(expectedVersion uint64) error {
	if !evidence.verifyCustodyChain(evidence.rootKind) {
		return ErrInvalidEvidence
	}
	if expectedVersion != evidence.version {
		return ErrEvidenceConflict
	}
	return nil
}

func validEvidence(evidence Evidence) bool {
	digest, digestErr := normalizeHexDigest(evidence.contentSHA256, sha256.Size)
	mediaType, mimeErr := normalizeMediaType(evidence.detectedMIME)
	return (evidence.rootKind == evidenceCaseRoot || evidence.rootKind == evidenceAlertRoot) &&
		validEntityID(evidence.id) && validEntityID(evidence.tenantID) &&
		validEntityID(evidence.caseID) && validEntityID(evidence.storageObjectID) &&
		validSingleLineText(evidence.title, 512, false) && validOptionalText(evidence.description, 16*1024) &&
		validStableKey(evidence.evidenceType) && validEvidenceClassification(evidence.classification) &&
		digestErr == nil && digest == evidence.contentSHA256 && evidence.sizeBytes >= 0 &&
		evidence.sizeBytes > 0 && evidence.sizeBytes <= maximumStorageObjectBytes && mimeErr == nil && mediaType == evidence.detectedMIME &&
		validInstant(evidence.collectedAt) &&
		validEntityID(evidence.collectedBy) && validSingleLineText(evidence.source, 512, false) &&
		validInitialEvidenceScanState(evidence.initialScanState) &&
		(evidence.initialRetentionUntil == nil || validInstant(*evidence.initialRetentionUntil) &&
			!evidence.initialRetentionUntil.Before(evidence.collectedAt)) &&
		(evidence.retentionUntil == nil || validInstant(*evidence.retentionUntil) &&
			!evidence.retentionUntil.Before(evidence.collectedAt)) &&
		evidence.version > 0 && evidence.version <= MaximumCustodyEvents && len(evidence.custody) > 0 &&
		uint64(len(evidence.custody)) == evidence.version && validScanState(evidence.scanState)
}

func validInitialEvidenceScanState(value ScanState) bool {
	switch value {
	case ScanQuarantined, ScanScanning, ScanAvailable, ScanRejected, ScanFailed, ScanRetained:
		return true
	default:
		return false
	}
}
