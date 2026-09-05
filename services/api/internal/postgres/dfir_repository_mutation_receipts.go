package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

const (
	dfirMutationRootCase  = "case"
	dfirMutationRootAlert = "alert"

	dfirMutationKindIOC          = "ioc"
	dfirMutationKindAsset        = "asset"
	dfirMutationKindTimeline     = "timeline_event"
	dfirMutationKindEvidence     = "evidence"
	dfirMutationKindRelationship = "relationship"
	dfirMutationKindStorage      = "storage_object"

	dfirMutationSnapshotSchemaVersion = 1
	maximumDFIRMutationSnapshotBytes  = 16 * 1024 * 1024
)

type dfirMutationCoordinate struct {
	tenantID            uuid.UUID
	rootKind            string
	rootID              uuid.UUID
	operation           string
	resourceKind        string
	resourceID          uuid.UUID
	secondaryResourceID *uuid.UUID
	resultVersion       uint64
}

type dfirMutationReservation struct {
	commandID uuid.UUID
	snapshot  []byte
	replayed  bool
}

type dfirMutationSnapshotEnvelope struct {
	SchemaVersion       int             `json:"schemaVersion"`
	TenantID            uuid.UUID       `json:"tenantId"`
	RootKind            string          `json:"rootKind"`
	RootID              uuid.UUID       `json:"rootId"`
	Operation           string          `json:"operation"`
	ResourceKind        string          `json:"resourceKind"`
	ResourceID          uuid.UUID       `json:"resourceId"`
	SecondaryResourceID *uuid.UUID      `json:"secondaryResourceId,omitempty"`
	ResultVersion       uint64          `json:"resultVersion"`
	Projection          json.RawMessage `json:"projection"`
}

type dfirIndicatorResultSnapshot struct {
	ID              uuid.UUID                   `json:"id"`
	TenantID        uuid.UUID                   `json:"tenantId"`
	Type            kernel.IndicatorType        `json:"type"`
	Value           string                      `json:"value"`
	NormalizedValue string                      `json:"normalizedValue"`
	Description     string                      `json:"description"`
	Source          string                      `json:"source"`
	Confidence      int                         `json:"confidence"`
	TLP             kernel.TrafficLightProtocol `json:"tlp"`
	FirstSeen       time.Time                   `json:"firstSeen"`
	LastSeen        time.Time                   `json:"lastSeen"`
	Malicious       kernel.MaliciousState       `json:"malicious"`
	Tags            []string                    `json:"tags"`
	Enrichment      json.RawMessage             `json:"enrichment,omitempty"`
}

type dfirAssetResultSnapshot struct {
	ID                 uuid.UUID               `json:"id"`
	TenantID           uuid.UUID               `json:"tenantId"`
	Hostname           string                  `json:"hostname"`
	NormalizedHostname string                  `json:"normalizedHostname"`
	FQDN               string                  `json:"fqdn"`
	NormalizedFQDN     string                  `json:"normalizedFqdn"`
	IPAddresses        []string                `json:"ipAddresses"`
	MACAddresses       []string                `json:"macAddresses"`
	AssetType          string                  `json:"assetType"`
	OperatingSystem    string                  `json:"operatingSystem"`
	Owner              string                  `json:"owner"`
	BusinessUnit       string                  `json:"businessUnit"`
	Criticality        kernel.AssetCriticality `json:"criticality"`
	Environment        string                  `json:"environment"`
	ExternalID         string                  `json:"externalId"`
	Tags               []string                `json:"tags"`
	FirstSeen          time.Time               `json:"firstSeen"`
	LastSeen           time.Time               `json:"lastSeen"`
	CustomAttributes   json.RawMessage         `json:"customAttributes,omitempty"`
}

type dfirTimelineResultSnapshot struct {
	ID               uuid.UUID                `json:"id"`
	TenantID         uuid.UUID                `json:"tenantId"`
	AlertID          *uuid.UUID               `json:"alertId,omitempty"`
	CaseID           *uuid.UUID               `json:"caseId,omitempty"`
	EventTime        time.Time                `json:"eventTime"`
	IngestedAt       time.Time                `json:"ingestedAt"`
	OriginalTimezone string                   `json:"originalTimezone"`
	Precision        kernel.TemporalPrecision `json:"precision"`
	Source           string                   `json:"source"`
	Category         string                   `json:"category"`
	Title            string                   `json:"title"`
	Description      string                   `json:"description"`
	ActorID          *uuid.UUID               `json:"actorId,omitempty"`
	IOCIDs           []uuid.UUID              `json:"iocIds"`
	AssetIDs         []uuid.UUID              `json:"assetIds"`
	EvidenceIDs      []uuid.UUID              `json:"evidenceIds"`
	Tags             []string                 `json:"tags"`
}

type dfirReferenceResultSnapshot struct {
	Kind         kernel.EntityKind `json:"kind"`
	ID           *uuid.UUID        `json:"id,omitempty"`
	ExternalType string            `json:"externalType,omitempty"`
	ExternalID   string            `json:"externalId,omitempty"`
}

type dfirRelationshipResultSnapshot struct {
	ID               uuid.UUID                                  `json:"id"`
	TenantID         uuid.UUID                                  `json:"tenantId"`
	Source           dfirReferenceResultSnapshot                `json:"source"`
	Target           dfirReferenceResultSnapshot                `json:"target"`
	RelationshipType string                                     `json:"relationshipType"`
	Metadata         json.RawMessage                            `json:"metadata,omitempty"`
	CreatedBy        uuid.UUID                                  `json:"createdBy"`
	CreatedAt        time.Time                                  `json:"createdAt"`
	Version          uint64                                     `json:"version,omitempty"`
	Retractions      []dfirRelationshipRetractionResultSnapshot `json:"retractions,omitempty"`
}

type dfirRelationshipRetractionResultSnapshot struct {
	ID             uuid.UUID `json:"id"`
	TenantID       uuid.UUID `json:"tenantId"`
	RelationshipID uuid.UUID `json:"relationshipId"`
	Sequence       uint64    `json:"sequence"`
	ActorID        uuid.UUID `json:"actorId"`
	Reason         string    `json:"reason"`
	OccurredAt     time.Time `json:"occurredAt"`
}

type dfirCustodyResultSnapshot struct {
	ID           uuid.UUID            `json:"id"`
	TenantID     uuid.UUID            `json:"tenantId"`
	EvidenceID   uuid.UUID            `json:"evidenceId"`
	Sequence     uint64               `json:"sequence"`
	Action       kernel.CustodyAction `json:"action"`
	ActorID      uuid.UUID            `json:"actorId"`
	Reason       string               `json:"reason"`
	StateValue   string               `json:"stateValue"`
	PreviousHash []byte               `json:"previousHash"`
	EventHash    []byte               `json:"eventHash"`
	OccurredAt   time.Time            `json:"occurredAt"`
}

type dfirEvidenceResultSnapshot struct {
	ID                    uuid.UUID                     `json:"id"`
	TenantID              uuid.UUID                     `json:"tenantId"`
	CaseID                uuid.UUID                     `json:"caseId"`
	StorageObjectID       uuid.UUID                     `json:"storageObjectId"`
	Title                 string                        `json:"title"`
	Description           string                        `json:"description"`
	EvidenceType          string                        `json:"evidenceType"`
	Classification        kernel.EvidenceClassification `json:"classification"`
	ContentSHA256         string                        `json:"contentSha256"`
	SizeBytes             int64                         `json:"sizeBytes"`
	DetectedMIME          string                        `json:"detectedMime"`
	CollectedAt           time.Time                     `json:"collectedAt"`
	CollectedBy           uuid.UUID                     `json:"collectedBy"`
	Source                string                        `json:"source"`
	RetentionUntil        *time.Time                    `json:"retentionUntil,omitempty"`
	LegalHold             bool                          `json:"legalHold"`
	ScanState             kernel.ScanState              `json:"scanState"`
	InitialRetentionUntil *time.Time                    `json:"initialRetentionUntil,omitempty"`
	InitialLegalHold      bool                          `json:"initialLegalHold"`
	InitialScanState      kernel.ScanState              `json:"initialScanState"`
	Sealed                bool                          `json:"sealed"`
	Destroyed             bool                          `json:"destroyed"`
	Version               uint64                        `json:"version"`
	CustodyEvents         []dfirCustodyResultSnapshot   `json:"custodyEvents"`
}

// The upload receipt deliberately omits bucket, object key, declared MIME,
// classification, size, content hash and every signed grant field. Those stay
// live and are checked before a replay may reach the signer.
type dfirPreparedUploadResultSnapshot struct {
	StorageID       uuid.UUID                    `json:"storageId"`
	TenantID        uuid.UUID                    `json:"tenantId"`
	CreatedBy       uuid.UUID                    `json:"createdBy"`
	CreatedAt       time.Time                    `json:"createdAt"`
	UploadExpiresAt time.Time                    `json:"uploadExpiresAt"`
	StorageVersion  uint64                       `json:"storageVersion"`
	StorageState    kernel.ScanState             `json:"storageState"`
	Attachment      dfirAttachmentResultSnapshot `json:"attachment"`
}

type dfirAttachmentResultSnapshot struct {
	ID               uuid.UUID                   `json:"id"`
	TenantID         uuid.UUID                   `json:"tenantId"`
	Subject          dfirReferenceResultSnapshot `json:"subject"`
	StorageObjectID  uuid.UUID                   `json:"storageObjectId"`
	OriginalFilename string                      `json:"originalFilename"`
	Visibility       kernel.Visibility           `json:"visibility"`
	UploadedBy       uuid.UUID                   `json:"uploadedBy"`
	UploadedAt       time.Time                   `json:"uploadedAt"`
	ScanState        kernel.ScanState            `json:"scanState"`
}

func reserveDFIRMutationCommand(
	ctx context.Context,
	tx databaseTransaction,
	newCommandID uuid.UUID,
	coordinate dfirMutationCoordinate,
	command application.CommandBinding,
) (dfirMutationReservation, error) {
	var result dfirMutationReservation
	var returnedResourceID uuid.UUID
	var returnedSecondaryID *uuid.UUID
	var returnedVersion int64
	if command.Operation != coordinate.operation || !validDFIRMutationCoordinate(coordinate) {
		return result, application.ErrRepositoryConflict
	}
	err := tx.QueryRow(ctx, `
		SELECT command_id, result_resource_id, result_secondary_resource_id,
		       result_version, result_snapshot, replayed
		FROM app.reserve_dfir_mutation_command_v1($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		newCommandID, coordinate.rootKind, coordinate.rootID, coordinate.operation,
		coordinate.resourceKind, coordinate.resourceID, coordinate.secondaryResourceID,
		int64(coordinate.resultVersion), command.KeyDigest[:], command.RequestDigest[:],
	).Scan(
		&result.commandID, &returnedResourceID, &returnedSecondaryID,
		&returnedVersion, &result.snapshot, &result.replayed,
	)
	if err != nil {
		// The Alert effects ABI mirrors reservations into a legacy ledger whose
		// unique result coordinate can reject a stale revision before Go's CAS
		// check. Exact historical replay is resolved by SQL before that insert.
		var databaseErr *pgconn.PgError
		if coordinate.rootKind == dfirMutationRootAlert &&
			(coordinate.operation == "dfir.ioc.replace" || coordinate.operation == "dfir.asset.replace") &&
			errors.As(err, &databaseErr) && databaseErr.Code == "23505" &&
			databaseErr.SchemaName == "public" && databaseErr.TableName == "alert_dfir_resource_commands" &&
			databaseErr.ConstraintName == "alert_dfir_resource_commands_result_key" {
			return dfirMutationReservation{}, application.ErrRepositoryPrecondition
		}
		return dfirMutationReservation{}, err
	}
	if result.commandID == uuid.Nil || returnedResourceID != coordinate.resourceID ||
		!sameOptionalUUID(returnedSecondaryID, coordinate.secondaryResourceID) ||
		returnedVersion != int64(coordinate.resultVersion) || result.replayed != (len(result.snapshot) != 0) {
		return dfirMutationReservation{}, unexpectedDFIRProjection("DFIR mutation command reservation mismatch")
	}
	return result, nil
}

func validDFIRMutationCoordinate(value dfirMutationCoordinate) bool {
	if !authorizationUUIDv7(value.tenantID) ||
		(value.rootKind != dfirMutationRootCase && value.rootKind != dfirMutationRootAlert) ||
		!authorizationUUIDv7(value.rootID) || !authorizationUUIDv7(value.resourceID) ||
		value.resultVersion == 0 || value.resultVersion > kernel.MaximumResourceVersion {
		return false
	}
	hasSecondary := value.secondaryResourceID != nil
	if hasSecondary && !authorizationUUIDv7(*value.secondaryResourceID) {
		return false
	}
	switch value.operation {
	case "dfir.ioc.create":
		return value.resourceKind == dfirMutationKindIOC && value.resultVersion == 1 && !hasSecondary
	case "dfir.ioc.replace":
		return value.resourceKind == dfirMutationKindIOC && value.resultVersion > 1 && !hasSecondary
	case "dfir.ioc.link", "dfir.ioc.unlink":
		return value.resourceKind == dfirMutationKindIOC && value.resultVersion > 1 && hasSecondary
	case "dfir.asset.create":
		return value.resourceKind == dfirMutationKindAsset && value.resultVersion == 1 && !hasSecondary
	case "dfir.asset.replace":
		return value.resourceKind == dfirMutationKindAsset && value.resultVersion > 1 && !hasSecondary
	case "dfir.asset.link", "dfir.asset.unlink":
		return value.resourceKind == dfirMutationKindAsset && value.resultVersion > 1 && hasSecondary
	case "dfir.timeline.create":
		return value.resourceKind == dfirMutationKindTimeline && value.resultVersion == 1 && !hasSecondary
	case "dfir.evidence.create":
		return value.rootKind == dfirMutationRootCase && value.resourceKind == dfirMutationKindEvidence &&
			value.resultVersion == 1 && hasSecondary
	case "dfir.evidence.custody.append":
		return value.rootKind == dfirMutationRootCase && value.resourceKind == dfirMutationKindEvidence &&
			value.resultVersion > 1 && value.resultVersion <= kernel.MaximumCustodyEvents && hasSecondary
	case "dfir.relationship.create":
		return value.rootKind == dfirMutationRootCase && value.resourceKind == dfirMutationKindRelationship &&
			value.resultVersion == 1 && !hasSecondary
	case "dfir.relationship.retract":
		return value.rootKind == dfirMutationRootCase && value.resourceKind == dfirMutationKindRelationship &&
			value.resultVersion > 1 && hasSecondary
	case "dfir.attachment.prepare":
		return value.resourceKind == dfirMutationKindStorage && value.resultVersion == 1 && hasSecondary
	default:
		return false
	}
}

func storeDFIRMutationResult(
	ctx context.Context,
	tx databaseTransaction,
	commandID uuid.UUID,
	document []byte,
) error {
	if commandID == uuid.Nil || len(document) == 0 || len(document) > maximumDFIRMutationSnapshotBytes {
		return application.ErrRepositoryConflict
	}
	var stored bool
	if err := tx.QueryRow(ctx, `SELECT app.store_dfir_mutation_command_result_v1($1, $2::jsonb)`,
		commandID, document).Scan(&stored); err != nil {
		return err
	}
	if !stored {
		return unexpectedDFIRProjection("DFIR mutation result was not stored")
	}
	return nil
}

func encodeDFIRMutationSnapshot(coordinate dfirMutationCoordinate, projection any) ([]byte, error) {
	if !validDFIRMutationCoordinate(coordinate) {
		return nil, application.ErrRepositoryConflict
	}
	projectionJSON, err := json.Marshal(projection)
	if err != nil || len(projectionJSON) == 0 || projectionJSON[0] != '{' {
		return nil, application.ErrRepositoryConflict
	}
	return json.Marshal(dfirMutationSnapshotEnvelope{
		SchemaVersion: dfirMutationSnapshotSchemaVersion,
		TenantID:      coordinate.tenantID,
		RootKind:      coordinate.rootKind, RootID: coordinate.rootID,
		Operation: coordinate.operation, ResourceKind: coordinate.resourceKind,
		ResourceID: coordinate.resourceID, SecondaryResourceID: coordinate.secondaryResourceID,
		ResultVersion: coordinate.resultVersion,
		Projection:    projectionJSON,
	})
}

func decodeDFIRMutationSnapshot(document []byte, coordinate dfirMutationCoordinate, target any) error {
	var envelope dfirMutationSnapshotEnvelope
	if err := decodeStrictDFIRMutationJSON(document, &envelope); err != nil ||
		envelope.SchemaVersion != dfirMutationSnapshotSchemaVersion || envelope.TenantID != coordinate.tenantID ||
		envelope.RootKind != coordinate.rootKind || envelope.RootID != coordinate.rootID ||
		envelope.Operation != coordinate.operation || envelope.ResourceKind != coordinate.resourceKind ||
		envelope.ResourceID != coordinate.resourceID ||
		!sameOptionalUUID(envelope.SecondaryResourceID, coordinate.secondaryResourceID) ||
		envelope.ResultVersion != coordinate.resultVersion ||
		envelope.ResultVersion == 0 || envelope.ResultVersion > kernel.MaximumResourceVersion {
		return unexpectedDFIRProjection("invalid DFIR mutation replay envelope")
	}
	if err := decodeStrictDFIRMutationJSON(envelope.Projection, target); err != nil {
		return unexpectedDFIRProjection("invalid DFIR mutation replay projection")
	}
	return nil
}

func decodeStrictDFIRMutationJSON(document []byte, target any) error {
	if len(document) == 0 || len(document) > maximumDFIRMutationSnapshotBytes {
		return errors.New("DFIR mutation replay snapshot size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("DFIR mutation replay snapshot has trailing data")
	}
	return nil
}

func encodeDFIRIndicatorResult(coordinate dfirMutationCoordinate, value kernel.Indicator) ([]byte, error) {
	return encodeDFIRMutationSnapshot(coordinate, dfirIndicatorSnapshot(value))
}

func decodeDFIRIndicatorResult(document []byte, coordinate dfirMutationCoordinate) (kernel.Indicator, error) {
	var projection dfirIndicatorResultSnapshot
	if err := decodeDFIRMutationSnapshot(document, coordinate, &projection); err != nil {
		return kernel.Indicator{}, err
	}
	result, err := restoreDFIRIndicatorSnapshot(projection)
	if err != nil || uuid.UUID(result.ID().Bytes()) != coordinate.resourceID ||
		uuid.UUID(result.TenantID().Bytes()) != coordinate.tenantID {
		return kernel.Indicator{}, unexpectedDFIRProjection("IOC replay identity mismatch")
	}
	return result, nil
}

func encodeDFIRAssetResult(coordinate dfirMutationCoordinate, value kernel.Asset) ([]byte, error) {
	return encodeDFIRMutationSnapshot(coordinate, dfirAssetSnapshot(value))
}

func decodeDFIRAssetResult(document []byte, coordinate dfirMutationCoordinate) (kernel.Asset, error) {
	var projection dfirAssetResultSnapshot
	if err := decodeDFIRMutationSnapshot(document, coordinate, &projection); err != nil {
		return kernel.Asset{}, err
	}
	result, err := restoreDFIRAssetSnapshot(projection)
	if err != nil || uuid.UUID(result.ID().Bytes()) != coordinate.resourceID ||
		uuid.UUID(result.TenantID().Bytes()) != coordinate.tenantID {
		return kernel.Asset{}, unexpectedDFIRProjection("asset replay identity mismatch")
	}
	return result, nil
}

func encodeDFIRTimelineResult(coordinate dfirMutationCoordinate, value kernel.TimelineEvent) ([]byte, error) {
	return encodeDFIRMutationSnapshot(coordinate, dfirTimelineSnapshot(value))
}

func decodeDFIRTimelineResult(document []byte, coordinate dfirMutationCoordinate) (kernel.TimelineEvent, error) {
	var projection dfirTimelineResultSnapshot
	if err := decodeDFIRMutationSnapshot(document, coordinate, &projection); err != nil {
		return kernel.TimelineEvent{}, err
	}
	result, err := restoreDFIRTimelineSnapshot(projection)
	if err != nil || uuid.UUID(result.ID().Bytes()) != coordinate.resourceID ||
		uuid.UUID(result.TenantID().Bytes()) != coordinate.tenantID ||
		coordinate.rootKind == dfirMutationRootCase && uuid.UUID(result.CaseID().Bytes()) != coordinate.rootID ||
		coordinate.rootKind == dfirMutationRootAlert && uuid.UUID(result.AlertID().Bytes()) != coordinate.rootID {
		return kernel.TimelineEvent{}, unexpectedDFIRProjection("timeline replay identity mismatch")
	}
	return result, nil
}

func encodeDFIRRelationshipResult(coordinate dfirMutationCoordinate, value kernel.Relationship) ([]byte, error) {
	return encodeDFIRMutationSnapshot(coordinate, dfirRelationshipSnapshot(value))
}

func decodeDFIRRelationshipResult(document []byte, coordinate dfirMutationCoordinate) (kernel.Relationship, error) {
	var projection dfirRelationshipResultSnapshot
	if err := decodeDFIRMutationSnapshot(document, coordinate, &projection); err != nil {
		return kernel.Relationship{}, err
	}
	result, err := restoreDFIRRelationshipSnapshot(projection)
	if err != nil || coordinate.rootKind != dfirMutationRootCase || uuid.UUID(result.ID().Bytes()) != coordinate.resourceID ||
		uuid.UUID(result.TenantID().Bytes()) != coordinate.tenantID ||
		result.Version() != coordinate.resultVersion {
		return kernel.Relationship{}, unexpectedDFIRProjection("relationship replay identity mismatch")
	}
	if coordinate.operation == "dfir.relationship.retract" {
		retractions := result.Retractions()
		if coordinate.secondaryResourceID == nil || len(retractions) != 1 ||
			uuid.UUID(retractions[0].ID.Bytes()) != *coordinate.secondaryResourceID {
			return kernel.Relationship{}, unexpectedDFIRProjection("relationship retraction replay coordinate mismatch")
		}
	}
	return result, nil
}

func encodeDFIREvidenceResult(coordinate dfirMutationCoordinate, value kernel.Evidence) ([]byte, error) {
	return encodeDFIRMutationSnapshot(coordinate, dfirEvidenceSnapshot(value))
}

func decodeDFIREvidenceResult(document []byte, coordinate dfirMutationCoordinate) (kernel.Evidence, error) {
	var projection dfirEvidenceResultSnapshot
	if err := decodeDFIRMutationSnapshot(document, coordinate, &projection); err != nil {
		return kernel.Evidence{}, err
	}
	result, err := restoreDFIREvidenceSnapshot(projection)
	if err != nil || uuid.UUID(result.ID().Bytes()) != coordinate.resourceID ||
		uuid.UUID(result.TenantID().Bytes()) != coordinate.tenantID ||
		uuid.UUID(result.CaseID().Bytes()) != coordinate.rootID || result.Version() != coordinate.resultVersion {
		return kernel.Evidence{}, unexpectedDFIRProjection("evidence replay identity mismatch")
	}
	return result, nil
}

func encodeDFIRPreparedUploadResult(
	coordinate dfirMutationCoordinate,
	storage kernel.StorageObject,
	attachment kernel.Attachment,
) ([]byte, error) {
	return encodeDFIRMutationSnapshot(coordinate, dfirPreparedUploadSnapshot(storage, attachment))
}

func decodeDFIRPreparedUploadResult(
	document []byte,
	coordinate dfirMutationCoordinate,
) (dfirPreparedUploadResultSnapshot, kernel.Attachment, error) {
	var projection dfirPreparedUploadResultSnapshot
	if err := decodeDFIRMutationSnapshot(document, coordinate, &projection); err != nil {
		return dfirPreparedUploadResultSnapshot{}, kernel.Attachment{}, err
	}
	attachment, err := restoreDFIRPreparedUploadAttachment(projection)
	if err != nil {
		return dfirPreparedUploadResultSnapshot{}, kernel.Attachment{}, err
	}
	if coordinate.secondaryResourceID == nil || projection.StorageID != coordinate.resourceID ||
		projection.TenantID != coordinate.tenantID || projection.Attachment.ID != *coordinate.secondaryResourceID ||
		projection.Attachment.TenantID != coordinate.tenantID ||
		projection.Attachment.StorageObjectID != coordinate.resourceID || projection.StorageVersion != 1 ||
		projection.StorageState != kernel.ScanPendingUpload {
		return dfirPreparedUploadResultSnapshot{}, kernel.Attachment{}, unexpectedDFIRProjection("upload replay identity mismatch")
	}
	return projection, attachment, nil
}

func sameOptionalUUID(left, right *uuid.UUID) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func dfirIndicatorSnapshot(value kernel.Indicator) dfirIndicatorResultSnapshot {
	return dfirIndicatorResultSnapshot{
		ID: uuid.UUID(value.ID().Bytes()), TenantID: uuid.UUID(value.TenantID().Bytes()),
		Type: value.Type(), Value: value.Value(), NormalizedValue: value.NormalizedValue(),
		Description: value.Description(), Source: value.Source(), Confidence: value.Confidence(),
		TLP: value.TLP(), FirstSeen: value.FirstSeen(), LastSeen: value.LastSeen(),
		Malicious: value.MaliciousState(), Tags: append([]string{}, value.Tags()...),
		Enrichment: canonicalJSONObject(value.Enrichment()),
	}
}

func restoreDFIRIndicatorSnapshot(value dfirIndicatorResultSnapshot) (kernel.Indicator, error) {
	id, err := parseDFIREntityID(value.ID)
	if err != nil {
		return kernel.Indicator{}, err
	}
	tenant, err := parseDFIREntityID(value.TenantID)
	if err != nil {
		return kernel.Indicator{}, err
	}
	result, err := kernel.NewIndicator(kernel.IndicatorInput{
		ID: id, TenantID: tenant, Type: value.Type, Value: value.Value,
		Description: value.Description, Source: value.Source, Confidence: value.Confidence,
		TLP: value.TLP, FirstSeen: canonicalAlertDatabaseTime(value.FirstSeen),
		LastSeen: canonicalAlertDatabaseTime(value.LastSeen), Malicious: value.Malicious,
		Tags: value.Tags, Enrichment: canonicalJSONObject(value.Enrichment),
	})
	if err != nil || result.NormalizedValue() != value.NormalizedValue {
		return kernel.Indicator{}, unexpectedDFIRProjection("non-canonical IOC replay snapshot")
	}
	return result, nil
}

func dfirAssetSnapshot(value kernel.Asset) dfirAssetResultSnapshot {
	ips := value.IPAddresses()
	ipValues := make([]string, len(ips))
	for index, address := range ips {
		ipValues[index] = address.Original()
	}
	macs := value.MACAddresses()
	macValues := make([]string, len(macs))
	for index, address := range macs {
		macValues[index] = address.Original()
	}
	return dfirAssetResultSnapshot{
		ID: uuid.UUID(value.ID().Bytes()), TenantID: uuid.UUID(value.TenantID().Bytes()),
		Hostname: value.Hostname(), NormalizedHostname: value.NormalizedHostname(),
		FQDN: value.FQDN(), NormalizedFQDN: value.NormalizedFQDN(),
		IPAddresses: ipValues, MACAddresses: macValues, AssetType: value.AssetType(),
		OperatingSystem: value.OperatingSystem(), Owner: value.Owner(), BusinessUnit: value.BusinessUnit(),
		Criticality: value.Criticality(), Environment: value.Environment(), ExternalID: value.ExternalID(),
		Tags: append([]string{}, value.Tags()...), FirstSeen: value.FirstSeen(), LastSeen: value.LastSeen(),
		CustomAttributes: canonicalJSONObject(value.CustomAttributes()),
	}
}

func restoreDFIRAssetSnapshot(value dfirAssetResultSnapshot) (kernel.Asset, error) {
	id, err := parseDFIREntityID(value.ID)
	if err != nil {
		return kernel.Asset{}, err
	}
	tenant, err := parseDFIREntityID(value.TenantID)
	if err != nil {
		return kernel.Asset{}, err
	}
	result, err := kernel.NewAsset(kernel.AssetInput{
		ID: id, TenantID: tenant, Hostname: value.Hostname, FQDN: value.FQDN,
		IPAddresses: value.IPAddresses, MACAddresses: value.MACAddresses,
		AssetType: value.AssetType, OperatingSystem: value.OperatingSystem,
		Owner: value.Owner, BusinessUnit: value.BusinessUnit, Criticality: value.Criticality,
		Environment: value.Environment, ExternalID: value.ExternalID, Tags: value.Tags,
		FirstSeen: canonicalAlertDatabaseTime(value.FirstSeen), LastSeen: canonicalAlertDatabaseTime(value.LastSeen),
		CustomAttributes: canonicalJSONObject(value.CustomAttributes),
	})
	if err != nil || result.NormalizedHostname() != value.NormalizedHostname || result.NormalizedFQDN() != value.NormalizedFQDN {
		return kernel.Asset{}, unexpectedDFIRProjection("non-canonical asset replay snapshot")
	}
	return result, nil
}

func dfirTimelineSnapshot(value kernel.TimelineEvent) dfirTimelineResultSnapshot {
	return dfirTimelineResultSnapshot{
		ID: uuid.UUID(value.ID().Bytes()), TenantID: uuid.UUID(value.TenantID().Bytes()),
		AlertID:   optionalKernelUUIDPointer(optionalDFIRRootID(value.AlertID())),
		CaseID:    optionalKernelUUIDPointer(optionalDFIRRootID(value.CaseID())),
		EventTime: value.EventTime(), IngestedAt: value.IngestedAt(), OriginalTimezone: value.OriginalTimezone(),
		Precision: value.Precision(), Source: value.Source(), Category: value.Category(), Title: value.Title(),
		Description: value.Description(), ActorID: optionalKernelUUIDPointer(value.ActorID()),
		IOCIDs: kernelUUIDs(value.IOCIDs()), AssetIDs: kernelUUIDs(value.AssetIDs()),
		EvidenceIDs: kernelUUIDs(value.EvidenceIDs()), Tags: append([]string{}, value.Tags()...),
	}
}

func restoreDFIRTimelineSnapshot(value dfirTimelineResultSnapshot) (kernel.TimelineEvent, error) {
	id, err := parseDFIREntityID(value.ID)
	if err != nil {
		return kernel.TimelineEvent{}, err
	}
	tenant, err := parseDFIREntityID(value.TenantID)
	if err != nil {
		return kernel.TimelineEvent{}, err
	}
	alert, err := parseOptionalDFIREntityID(value.AlertID)
	if err != nil {
		return kernel.TimelineEvent{}, err
	}
	caseID, err := parseOptionalDFIREntityID(value.CaseID)
	if err != nil {
		return kernel.TimelineEvent{}, err
	}
	actor, err := parseOptionalDFIREntityID(value.ActorID)
	if err != nil {
		return kernel.TimelineEvent{}, err
	}
	iocs, err := parseDFIREntityIDs(value.IOCIDs)
	if err != nil {
		return kernel.TimelineEvent{}, err
	}
	assets, err := parseDFIREntityIDs(value.AssetIDs)
	if err != nil {
		return kernel.TimelineEvent{}, err
	}
	evidence, err := parseDFIREntityIDs(value.EvidenceIDs)
	if err != nil {
		return kernel.TimelineEvent{}, err
	}
	result, err := kernel.NewTimelineEvent(kernel.TimelineEventInput{
		ID: id, TenantID: tenant, AlertID: dereferenceDFIRRootID(alert), CaseID: dereferenceDFIRRootID(caseID),
		EventTime: canonicalAlertDatabaseTime(value.EventTime), IngestedAt: canonicalAlertDatabaseTime(value.IngestedAt),
		OriginalTimezone: value.OriginalTimezone, Precision: value.Precision, Source: value.Source,
		Category: value.Category, Title: value.Title, Description: value.Description,
		ActorID: actor, IOCIDs: iocs, AssetIDs: assets, EvidenceIDs: evidence, Tags: value.Tags,
	})
	if err != nil {
		return kernel.TimelineEvent{}, unexpectedDFIRProjection("non-canonical timeline replay snapshot")
	}
	return result, nil
}

func dfirRelationshipSnapshot(value kernel.Relationship) dfirRelationshipResultSnapshot {
	retractions := value.Retractions()
	history := make([]dfirRelationshipRetractionResultSnapshot, len(retractions))
	for index, retraction := range retractions {
		history[index] = dfirRelationshipRetractionResultSnapshot{
			ID: uuid.UUID(retraction.ID.Bytes()), TenantID: uuid.UUID(retraction.TenantID.Bytes()),
			RelationshipID: uuid.UUID(retraction.RelationshipID.Bytes()), Sequence: retraction.Sequence,
			ActorID: uuid.UUID(retraction.ActorID.Bytes()), Reason: retraction.Reason,
			OccurredAt: retraction.OccurredAt,
		}
	}
	return dfirRelationshipResultSnapshot{
		ID: uuid.UUID(value.ID().Bytes()), TenantID: uuid.UUID(value.TenantID().Bytes()),
		Source: dfirReferenceSnapshot(value.Source()), Target: dfirReferenceSnapshot(value.Target()),
		RelationshipType: value.RelationshipType(), Metadata: canonicalJSONObject(value.Metadata()),
		CreatedBy: uuid.UUID(value.CreatedBy().Bytes()), CreatedAt: value.CreatedAt(),
		Version: value.Version(), Retractions: history,
	}
}

func restoreDFIRRelationshipSnapshot(value dfirRelationshipResultSnapshot) (kernel.Relationship, error) {
	id, err := parseDFIREntityID(value.ID)
	if err != nil {
		return kernel.Relationship{}, err
	}
	tenant, err := parseDFIREntityID(value.TenantID)
	if err != nil {
		return kernel.Relationship{}, err
	}
	createdBy, err := parseDFIREntityID(value.CreatedBy)
	if err != nil {
		return kernel.Relationship{}, err
	}
	source, err := restoreDFIRReferenceSnapshot(tenant, value.Source)
	if err != nil {
		return kernel.Relationship{}, err
	}
	target, err := restoreDFIRReferenceSnapshot(tenant, value.Target)
	if err != nil {
		return kernel.Relationship{}, err
	}
	history := make([]kernel.RelationshipRetractionState, len(value.Retractions))
	for index, retraction := range value.Retractions {
		retractionID, parseErr := parseDFIREntityID(retraction.ID)
		if parseErr != nil {
			return kernel.Relationship{}, parseErr
		}
		retractionTenant, parseErr := parseDFIREntityID(retraction.TenantID)
		if parseErr != nil {
			return kernel.Relationship{}, parseErr
		}
		relationshipID, parseErr := parseDFIREntityID(retraction.RelationshipID)
		if parseErr != nil {
			return kernel.Relationship{}, parseErr
		}
		actorID, parseErr := parseDFIREntityID(retraction.ActorID)
		if parseErr != nil {
			return kernel.Relationship{}, parseErr
		}
		history[index] = kernel.RelationshipRetractionState{
			ID: retractionID, TenantID: retractionTenant, RelationshipID: relationshipID,
			Sequence: retraction.Sequence, ActorID: actorID, Reason: retraction.Reason,
			OccurredAt: canonicalAlertDatabaseTime(retraction.OccurredAt),
		}
	}
	version := value.Version
	if version == 0 && len(history) == 0 {
		// Snapshot schema v1 originally omitted the immutable create version.
		version = 1
	}
	result, err := kernel.NewRelationship(kernel.RelationshipInput{
		ID: id, TenantID: tenant, Source: source, Target: target,
		RelationshipType: value.RelationshipType, Metadata: canonicalJSONObject(value.Metadata),
		CreatedBy: createdBy, CreatedAt: canonicalAlertDatabaseTime(value.CreatedAt),
		Version: version, Retractions: history,
	})
	if err != nil {
		return kernel.Relationship{}, unexpectedDFIRProjection("non-canonical relationship replay snapshot")
	}
	return result, nil
}

func dfirEvidenceSnapshot(value kernel.Evidence) dfirEvidenceResultSnapshot {
	state := value.Snapshot()
	custody := make([]dfirCustodyResultSnapshot, len(state.CustodyEvents))
	for index, event := range state.CustodyEvents {
		custody[index] = dfirCustodyResultSnapshot{
			ID: uuid.UUID(event.ID.Bytes()), TenantID: uuid.UUID(event.TenantID.Bytes()),
			EvidenceID: uuid.UUID(event.EvidenceID.Bytes()), Sequence: event.Sequence, Action: event.Action,
			ActorID: uuid.UUID(event.ActorID.Bytes()), Reason: event.Reason, StateValue: event.StateValue,
			PreviousHash: append([]byte(nil), event.PreviousHash[:]...), EventHash: append([]byte(nil), event.EventHash[:]...),
			OccurredAt: event.OccurredAt,
		}
	}
	return dfirEvidenceResultSnapshot{
		ID: uuid.UUID(state.ID.Bytes()), TenantID: uuid.UUID(state.TenantID.Bytes()), CaseID: uuid.UUID(state.CaseID.Bytes()),
		StorageObjectID: uuid.UUID(state.StorageObjectID.Bytes()), Title: state.Title, Description: state.Description,
		EvidenceType: state.EvidenceType, Classification: state.Classification, ContentSHA256: state.ContentSHA256,
		SizeBytes: state.SizeBytes, DetectedMIME: state.DetectedMIME, CollectedAt: state.CollectedAt,
		CollectedBy: uuid.UUID(state.CollectedBy.Bytes()), Source: state.Source,
		RetentionUntil: state.RetentionUntil, LegalHold: state.LegalHold, ScanState: state.ScanState,
		InitialRetentionUntil: state.InitialRetentionUntil, InitialLegalHold: state.InitialLegalHold,
		InitialScanState: state.InitialScanState, Sealed: state.Sealed, Destroyed: state.Destroyed,
		Version: state.Version, CustodyEvents: custody,
	}
}

func restoreDFIREvidenceSnapshot(value dfirEvidenceResultSnapshot) (kernel.Evidence, error) {
	id, err := parseDFIREntityID(value.ID)
	if err != nil {
		return kernel.Evidence{}, err
	}
	tenant, err := parseDFIREntityID(value.TenantID)
	if err != nil {
		return kernel.Evidence{}, err
	}
	caseID, err := parseDFIREntityID(value.CaseID)
	if err != nil {
		return kernel.Evidence{}, err
	}
	storage, err := parseDFIREntityID(value.StorageObjectID)
	if err != nil {
		return kernel.Evidence{}, err
	}
	collector, err := parseDFIREntityID(value.CollectedBy)
	if err != nil {
		return kernel.Evidence{}, err
	}
	custody := make([]kernel.CustodyEventState, len(value.CustodyEvents))
	for index, event := range value.CustodyEvents {
		if len(event.PreviousHash) != 32 || len(event.EventHash) != 32 {
			return kernel.Evidence{}, unexpectedDFIRProjection("invalid custody replay hash")
		}
		eventID, parseErr := parseDFIREntityID(event.ID)
		if parseErr != nil {
			return kernel.Evidence{}, parseErr
		}
		eventTenant, parseErr := parseDFIREntityID(event.TenantID)
		if parseErr != nil {
			return kernel.Evidence{}, parseErr
		}
		evidenceID, parseErr := parseDFIREntityID(event.EvidenceID)
		if parseErr != nil {
			return kernel.Evidence{}, parseErr
		}
		actor, parseErr := parseDFIREntityID(event.ActorID)
		if parseErr != nil {
			return kernel.Evidence{}, parseErr
		}
		custody[index] = kernel.CustodyEventState{
			ID: eventID, TenantID: eventTenant, EvidenceID: evidenceID, Sequence: event.Sequence,
			Action: event.Action, ActorID: actor, Reason: event.Reason, StateValue: event.StateValue,
			OccurredAt: canonicalAlertDatabaseTime(event.OccurredAt),
		}
		copy(custody[index].PreviousHash[:], event.PreviousHash)
		copy(custody[index].EventHash[:], event.EventHash)
	}
	result, err := kernel.RestoreEvidence(kernel.EvidenceState{
		ID: id, TenantID: tenant, CaseID: caseID, StorageObjectID: storage,
		Title: value.Title, Description: value.Description, EvidenceType: value.EvidenceType,
		Classification: value.Classification, ContentSHA256: value.ContentSHA256,
		SizeBytes: value.SizeBytes, DetectedMIME: value.DetectedMIME,
		CollectedAt: canonicalAlertDatabaseTime(value.CollectedAt), CollectedBy: collector,
		Source: value.Source, RetentionUntil: canonicalOptionalAlertDatabaseTime(value.RetentionUntil),
		LegalHold: value.LegalHold, ScanState: value.ScanState,
		InitialRetentionUntil: canonicalOptionalAlertDatabaseTime(value.InitialRetentionUntil),
		InitialLegalHold:      value.InitialLegalHold, InitialScanState: value.InitialScanState,
		Sealed: value.Sealed, Destroyed: value.Destroyed, Version: value.Version, CustodyEvents: custody,
	})
	if err != nil {
		return kernel.Evidence{}, unexpectedDFIRProjection("non-canonical evidence replay snapshot")
	}
	return result, nil
}

func dfirPreparedUploadSnapshot(storage kernel.StorageObject, attachment kernel.Attachment) dfirPreparedUploadResultSnapshot {
	return dfirPreparedUploadResultSnapshot{
		StorageID: uuid.UUID(storage.ID().Bytes()), TenantID: uuid.UUID(storage.TenantID().Bytes()),
		CreatedBy: uuid.UUID(storage.CreatedBy().Bytes()), CreatedAt: storage.CreatedAt(),
		UploadExpiresAt: storage.UploadExpiresAt(), StorageVersion: storage.Version(), StorageState: storage.State(),
		Attachment: dfirAttachmentResultSnapshot{
			ID: uuid.UUID(attachment.ID().Bytes()), TenantID: uuid.UUID(attachment.TenantID().Bytes()),
			Subject:          dfirReferenceSnapshot(attachment.Subject()),
			StorageObjectID:  uuid.UUID(attachment.StorageObjectID().Bytes()),
			OriginalFilename: attachment.OriginalFilename(), Visibility: attachment.Visibility(),
			UploadedBy: uuid.UUID(attachment.UploadedBy().Bytes()), UploadedAt: attachment.UploadedAt(),
			ScanState: attachment.ScanState(),
		},
	}
}

func restoreDFIRPreparedUploadAttachment(value dfirPreparedUploadResultSnapshot) (kernel.Attachment, error) {
	id, err := parseDFIREntityID(value.Attachment.ID)
	if err != nil {
		return kernel.Attachment{}, err
	}
	tenant, err := parseDFIREntityID(value.Attachment.TenantID)
	if err != nil {
		return kernel.Attachment{}, err
	}
	storage, err := parseDFIREntityID(value.Attachment.StorageObjectID)
	if err != nil {
		return kernel.Attachment{}, err
	}
	uploader, err := parseDFIREntityID(value.Attachment.UploadedBy)
	if err != nil {
		return kernel.Attachment{}, err
	}
	subject, err := restoreDFIRReferenceSnapshot(tenant, value.Attachment.Subject)
	if err != nil {
		return kernel.Attachment{}, err
	}
	result, err := kernel.NewAttachment(kernel.AttachmentInput{
		ID: id, TenantID: tenant, Subject: subject, StorageObjectID: storage,
		OriginalFilename:    value.Attachment.OriginalFilename,
		RequestedVisibility: value.Attachment.Visibility, SubjectVisibility: value.Attachment.Visibility,
		UploadedBy: uploader, UploadedAt: canonicalAlertDatabaseTime(value.Attachment.UploadedAt),
		ScanState: value.Attachment.ScanState,
	})
	if err != nil || result.Visibility() != value.Attachment.Visibility {
		return kernel.Attachment{}, unexpectedDFIRProjection("non-canonical upload attachment replay snapshot")
	}
	return result, nil
}

func dfirReferenceSnapshot(value kernel.EntityReference) dfirReferenceResultSnapshot {
	result := dfirReferenceResultSnapshot{Kind: value.Kind(), ExternalType: value.ExternalType(), ExternalID: value.ExternalID()}
	if value.Kind() != kernel.EntityExternal {
		id := uuid.UUID(value.ID().Bytes())
		result.ID = &id
	}
	return result
}

func restoreDFIRReferenceSnapshot(tenant kernel.EntityID, value dfirReferenceResultSnapshot) (kernel.EntityReference, error) {
	if value.Kind == kernel.EntityExternal {
		if value.ID != nil {
			return kernel.EntityReference{}, unexpectedDFIRProjection("invalid external DFIR reference snapshot")
		}
		result, err := kernel.NewExternalEntityReference(tenant, value.ExternalType, value.ExternalID)
		if err != nil {
			return kernel.EntityReference{}, unexpectedDFIRProjection("non-canonical external DFIR reference snapshot")
		}
		return result, nil
	}
	if value.ID == nil || value.ExternalType != "" || value.ExternalID != "" {
		return kernel.EntityReference{}, unexpectedDFIRProjection("invalid local DFIR reference snapshot")
	}
	id, err := parseDFIREntityID(*value.ID)
	if err != nil {
		return kernel.EntityReference{}, err
	}
	result, err := kernel.NewEntityReference(tenant, value.Kind, id)
	if err != nil {
		return kernel.EntityReference{}, unexpectedDFIRProjection("non-canonical local DFIR reference snapshot")
	}
	return result, nil
}

func parseDFIREntityIDs(values []uuid.UUID) ([]kernel.EntityID, error) {
	result := make([]kernel.EntityID, len(values))
	for index, value := range values {
		parsed, err := parseDFIREntityID(value)
		if err != nil {
			return nil, err
		}
		result[index] = parsed
	}
	return result, nil
}

func optionalDFIRRootID(value kernel.EntityID) *kernel.EntityID {
	if value == (kernel.EntityID{}) {
		return nil
	}
	copy := value
	return &copy
}

func dereferenceDFIRRootID(value *kernel.EntityID) kernel.EntityID {
	if value == nil {
		return kernel.EntityID{}
	}
	return *value
}
