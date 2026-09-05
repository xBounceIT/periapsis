package httpserver

import (
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func dfirEntityID(value uuid.UUID) (kernel.EntityID, error) {
	id, err := kernel.NewEntityID([16]byte(value))
	if err != nil {
		return kernel.EntityID{}, application.ErrInvalidInput
	}
	return id, nil
}

func dfirEntityIDs(values []uuid.UUID) ([]kernel.EntityID, error) {
	result := make([]kernel.EntityID, len(values))
	for index, value := range values {
		id, err := dfirEntityID(value)
		if err != nil {
			return nil, err
		}
		result[index] = id
	}
	return result, nil
}

func dfirDocument(value *contract.DfirBoundedDocument) (json.RawMessage, error) {
	if value == nil {
		return nil, nil
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > 64<<10 {
		return nil, application.ErrInvalidInput
	}
	return raw, nil
}

func dfirIndicatorInput(tenantID, id uuid.UUID, spec contract.DfirIndicatorSpec) (kernel.IndicatorInput, error) {
	tenant, err := dfirEntityID(tenantID)
	if err != nil {
		return kernel.IndicatorInput{}, err
	}
	entityID, err := dfirEntityID(id)
	if err != nil || !spec.Type.Valid() || !spec.Tlp.Valid() || !spec.Malicious.Valid() {
		return kernel.IndicatorInput{}, application.ErrInvalidInput
	}
	enrichment, err := dfirDocument(spec.Enrichment)
	if err != nil {
		return kernel.IndicatorInput{}, err
	}
	return kernel.IndicatorInput{
		ID: entityID, TenantID: tenant, Type: kernel.IndicatorType(spec.Type), Value: spec.Value,
		Description: spec.Description, Source: spec.Source, Confidence: spec.Confidence,
		TLP: kernel.TrafficLightProtocol(spec.Tlp), FirstSeen: spec.FirstSeen,
		LastSeen: spec.LastSeen, Malicious: kernel.MaliciousState(spec.Malicious),
		Tags: append([]string(nil), spec.Tags...), Enrichment: enrichment,
	}, nil
}

func dfirAssetInput(tenantID, id uuid.UUID, spec contract.DfirAssetSpec) (kernel.AssetInput, error) {
	tenant, err := dfirEntityID(tenantID)
	if err != nil {
		return kernel.AssetInput{}, err
	}
	entityID, err := dfirEntityID(id)
	if err != nil || !spec.Criticality.Valid() {
		return kernel.AssetInput{}, application.ErrInvalidInput
	}
	attributes, err := dfirDocument(spec.CustomAttributes)
	if err != nil {
		return kernel.AssetInput{}, err
	}
	return kernel.AssetInput{
		ID: entityID, TenantID: tenant, Hostname: spec.Hostname, FQDN: spec.Fqdn,
		IPAddresses: append([]string(nil), spec.IpAddresses...), MACAddresses: append([]string(nil), spec.MacAddresses...),
		AssetType: spec.AssetType, OperatingSystem: spec.OperatingSystem, Owner: spec.Owner,
		BusinessUnit: spec.BusinessUnit, Criticality: kernel.AssetCriticality(spec.Criticality),
		Environment: spec.Environment, ExternalID: spec.ExternalId, Tags: append([]string(nil), spec.Tags...),
		FirstSeen: spec.FirstSeen, LastSeen: spec.LastSeen, CustomAttributes: attributes,
	}, nil
}

func dfirTimelineInput(tenantID, caseID, eventID uuid.UUID, spec contract.DfirTimelineEventSpec, ingestedAt time.Time) (kernel.TimelineEventInput, error) {
	tenant, err := dfirEntityID(tenantID)
	if err != nil {
		return kernel.TimelineEventInput{}, err
	}
	caseEntity, err := dfirEntityID(caseID)
	if err != nil {
		return kernel.TimelineEventInput{}, err
	}
	id, err := dfirEntityID(eventID)
	if err != nil || !spec.Precision.Valid() {
		return kernel.TimelineEventInput{}, application.ErrInvalidInput
	}
	iocs, err := dfirEntityIDs(uuidSliceFromOpenAPI(spec.IocIds))
	if err != nil {
		return kernel.TimelineEventInput{}, err
	}
	assets, err := dfirEntityIDs(uuidSliceFromOpenAPI(spec.AssetIds))
	if err != nil {
		return kernel.TimelineEventInput{}, err
	}
	evidence, err := dfirEntityIDs(uuidSliceFromOpenAPI(spec.EvidenceIds))
	if err != nil {
		return kernel.TimelineEventInput{}, err
	}
	var actorID *kernel.EntityID
	if spec.ActorId != nil {
		value, parseErr := dfirEntityID(uuid.UUID(*spec.ActorId))
		if parseErr != nil {
			return kernel.TimelineEventInput{}, parseErr
		}
		actorID = &value
	}
	return kernel.TimelineEventInput{
		ID: id, TenantID: tenant, CaseID: caseEntity, EventTime: spec.EventTime, IngestedAt: ingestedAt,
		OriginalTimezone: spec.OriginalTimezone, Precision: kernel.TemporalPrecision(spec.Precision),
		Source: spec.Source, Category: spec.Category, Title: spec.Title, Description: spec.Description,
		ActorID: actorID, IOCIDs: iocs, AssetIDs: assets, EvidenceIDs: evidence,
		Tags: append([]string(nil), spec.Tags...),
	}, nil
}

func dfirTaskDraft(taskID uuid.UUID, spec contract.DfirTaskSpec) (application.TaskDraft, error) {
	id, idErr := dfirEntityID(taskID)
	assignee, assigneeErr := optionalDfirEntityID(spec.AssigneeId)
	team, teamErr := optionalDfirEntityID(spec.OperatorTeamId)
	sla, slaErr := optionalDfirEntityID(spec.SlaInstanceId)
	checklist, checklistErr := taskChecklistIntents(spec.Checklist)
	dueAt, dueErr := canonicalAlertTransportOptionalInstant(spec.DueAt)
	if idErr != nil || assigneeErr != nil || teamErr != nil || slaErr != nil || checklistErr != nil ||
		dueErr != nil || !spec.Priority.Valid() {
		return application.TaskDraft{}, application.ErrInvalidInput
	}
	return application.TaskDraft{
		ID: id, Title: spec.Title, Description: spec.Description,
		Priority: kernel.TaskPriority(spec.Priority), AssigneeID: assignee,
		OperatorTeamID: team, DueAt: dueAt, Checklist: checklist, SLAInstanceID: sla,
	}, nil
}

func taskChecklistIntents(values []contract.DfirTaskChecklistItemIntent) ([]application.TaskChecklistItemIntent, error) {
	result := make([]application.TaskChecklistItemIntent, len(values))
	for index, value := range values {
		id, err := dfirEntityID(uuid.UUID(value.Id))
		if err != nil {
			return nil, application.ErrInvalidInput
		}
		result[index] = application.TaskChecklistItemIntent{
			ID: id, Title: value.Title, Completed: value.Completed,
		}
	}
	return result, nil
}

func optionalDfirEntityID(value *uuid.UUID) (*kernel.EntityID, error) {
	if value == nil {
		return nil, nil
	}
	parsed, err := dfirEntityID(*value)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func dfirReference(tenantID uuid.UUID, value contract.DfirEntityReference) (kernel.EntityReference, error) {
	tenant, err := dfirEntityID(tenantID)
	if err != nil || !value.Kind.Valid() {
		return kernel.EntityReference{}, application.ErrInvalidInput
	}
	if value.Kind == contract.DfirEntityKindExternal {
		if value.Id != nil || value.ExternalType == nil || value.ExternalId == nil {
			return kernel.EntityReference{}, application.ErrInvalidInput
		}
		result, referenceErr := kernel.NewExternalEntityReference(tenant, *value.ExternalType, *value.ExternalId)
		if referenceErr != nil {
			return kernel.EntityReference{}, application.ErrInvalidInput
		}
		return result, nil
	}
	if value.Id == nil || value.ExternalType != nil || value.ExternalId != nil {
		return kernel.EntityReference{}, application.ErrInvalidInput
	}
	id, err := dfirEntityID(uuid.UUID(*value.Id))
	if err != nil {
		return kernel.EntityReference{}, err
	}
	result, err := kernel.NewEntityReference(tenant, kernel.EntityKind(value.Kind), id)
	if err != nil {
		return kernel.EntityReference{}, application.ErrInvalidInput
	}
	return result, nil
}

func mapDfirReference(value kernel.EntityReference) (contract.DfirEntityReference, error) {
	result := contract.DfirEntityReference{Kind: contract.DfirEntityKind(value.Kind())}
	if !result.Kind.Valid() {
		return contract.DfirEntityReference{}, application.ErrUnavailable
	}
	if value.Kind() == kernel.EntityExternal {
		externalType, externalID := contract.DfirStableKey(value.ExternalType()), value.ExternalID()
		result.ExternalType, result.ExternalId = &externalType, &externalID
		return result, nil
	}
	id, err := uuid.Parse(value.ID().String())
	if err != nil || id == uuid.Nil {
		return contract.DfirEntityReference{}, application.ErrUnavailable
	}
	result.Id = &id
	return result, nil
}

func mapDfirIndicator(value kernel.Indicator, caseID uuid.UUID, version uint64) (contract.DfirIndicator, error) {
	id, tenantID, err := phase4UUID(value.ID().String(), value.TenantID().String())
	if err != nil || !validDfirResourceVersion(version) {
		return contract.DfirIndicator{}, application.ErrUnavailable
	}
	enrichment, err := mapDfirDocument(value.Enrichment())
	if err != nil {
		return contract.DfirIndicator{}, err
	}
	return contract.DfirIndicator{Id: id, TenantId: tenantID, CaseId: caseID, Version: int64(version), Indicator: contract.DfirIndicatorSpec{
		Type: contract.DfirIndicatorType(value.Type()), Value: value.Value(), Description: value.Description(),
		Source: value.Source(), Confidence: value.Confidence(), Tlp: contract.DfirTlp(value.TLP()),
		FirstSeen: value.FirstSeen(), LastSeen: value.LastSeen(), Malicious: contract.DfirMaliciousState(value.MaliciousState()),
		Tags: nonNilStrings(value.Tags()), Enrichment: enrichment,
	}}, nil
}

func mapDfirAsset(value kernel.Asset, caseID uuid.UUID, version uint64) (contract.DfirAsset, error) {
	id, tenantID, err := phase4UUID(value.ID().String(), value.TenantID().String())
	if err != nil || !validDfirResourceVersion(version) {
		return contract.DfirAsset{}, application.ErrUnavailable
	}
	attributes, err := mapDfirDocument(value.CustomAttributes())
	if err != nil {
		return contract.DfirAsset{}, err
	}
	ips := make([]string, len(value.IPAddresses()))
	for index, address := range value.IPAddresses() {
		ips[index] = address.Original()
	}
	macs := make([]string, len(value.MACAddresses()))
	for index, address := range value.MACAddresses() {
		macs[index] = address.Original()
	}
	return contract.DfirAsset{Id: id, TenantId: tenantID, CaseId: caseID, Version: int64(version), Asset: contract.DfirAssetSpec{
		Hostname: value.Hostname(), Fqdn: value.FQDN(), IpAddresses: ips, MacAddresses: macs,
		AssetType: value.AssetType(), OperatingSystem: value.OperatingSystem(), Owner: value.Owner(),
		BusinessUnit: value.BusinessUnit(), Criticality: contract.DfirAssetCriticality(value.Criticality()),
		Environment: value.Environment(), ExternalId: value.ExternalID(), Tags: nonNilStrings(value.Tags()),
		FirstSeen: value.FirstSeen(), LastSeen: value.LastSeen(), CustomAttributes: attributes,
	}}, nil
}

func mapDfirTimeline(value kernel.TimelineEvent, version uint64) (contract.DfirTimelineEvent, error) {
	id, tenantID, err := phase4UUID(value.ID().String(), value.TenantID().String())
	caseID, parseErr := uuid.Parse(value.CaseID().String())
	if err != nil || parseErr != nil || !validDfirResourceVersion(version) {
		return contract.DfirTimelineEvent{}, application.ErrUnavailable
	}
	actorID := optionalOpenAPIUUID(value.ActorID())
	return contract.DfirTimelineEvent{Id: id, TenantId: tenantID, CaseId: caseID, IngestedAt: value.IngestedAt(), Version: int64(version), Event: contract.DfirTimelineEventSpec{
		EventTime: value.EventTime(), OriginalTimezone: value.OriginalTimezone(), Precision: contract.DfirTemporalPrecision(value.Precision()),
		Source: value.Source(), Category: value.Category(), Title: value.Title(), Description: value.Description(), ActorId: actorID,
		IocIds: openAPIUUIDs(value.IOCIDs()), AssetIds: openAPIUUIDs(value.AssetIDs()), EvidenceIds: openAPIUUIDs(value.EvidenceIDs()),
		Tags: nonNilStrings(value.Tags()),
	}}, nil
}

func mapDfirTask(value kernel.Task) (contract.DfirTask, error) {
	id, tenantID, err := phase4UUID(value.ID().String(), value.TenantID().String())
	caseID, parseErr := uuid.Parse(value.CaseID().String())
	if err != nil || parseErr != nil || value.Version() == 0 ||
		value.Version() > kernel.MaximumAlertResourceVersion {
		return contract.DfirTask{}, application.ErrUnavailable
	}
	checklist := make([]contract.DfirChecklistItem, len(value.Checklist()))
	for index, item := range value.Checklist() {
		itemID, parseErr := uuid.Parse(item.ID().String())
		if parseErr != nil {
			return contract.DfirTask{}, application.ErrUnavailable
		}
		checklist[index] = contract.DfirChecklistItem{Id: itemID, Title: item.Title(), Completed: item.Completed(), CompletedAt: item.CompletedAt(), CompletedBy: optionalOpenAPIUUID(item.CompletedBy())}
	}
	completion, err := mapDfirDocument(value.CompletionData())
	if err != nil {
		return contract.DfirTask{}, err
	}
	return contract.DfirTask{
		Id: id, TenantId: tenantID, CaseId: caseID, Title: value.Title(), Description: value.Description(),
		Status: contract.DfirTaskStatus(value.Status()), Priority: contract.DfirTaskPriority(value.Priority()),
		AssigneeId: optionalOpenAPIUUID(value.AssigneeID()), OperatorTeamId: optionalOpenAPIUUID(value.OperatorTeamID()),
		DueAt: value.DueAt(), Checklist: checklist, CompletedAt: value.CompletedAt(), CompletedBy: optionalOpenAPIUUID(value.CompletedBy()),
		CompletionData: completion, CommentIds: openAPIUUIDs(value.CommentIDs()), SlaInstanceId: optionalOpenAPIUUID(value.SLAInstanceID()),
		CreatedAt: value.CreatedAt(), UpdatedAt: value.UpdatedAt(), Version: int64(value.Version()),
	}, nil
}

func mapDfirRelationship(value kernel.Relationship) (contract.DfirRelationship, error) {
	id, tenantID, err := phase4UUID(value.ID().String(), value.TenantID().String())
	createdBy, parseErr := uuid.Parse(value.CreatedBy().String())
	source, sourceErr := mapDfirReference(value.Source())
	target, targetErr := mapDfirReference(value.Target())
	metadata, metadataErr := mapDfirDocument(value.Metadata())
	if err != nil || parseErr != nil || sourceErr != nil || targetErr != nil || metadataErr != nil ||
		!validDfirResourceVersion(value.Version()) {
		return contract.DfirRelationship{}, application.ErrUnavailable
	}
	retractions := value.Retractions()
	mappedRetractions := make([]contract.DfirRelationshipRetraction, len(retractions))
	for index, retraction := range retractions {
		retractionID, idErr := uuid.Parse(retraction.ID.String())
		retractionActor, actorErr := uuid.Parse(retraction.ActorID.String())
		if idErr != nil || actorErr != nil || retraction.TenantID != value.TenantID() ||
			retraction.RelationshipID != value.ID() || !validDfirResourceVersion(retraction.Sequence) {
			return contract.DfirRelationship{}, application.ErrUnavailable
		}
		mappedRetractions[index] = contract.DfirRelationshipRetraction{
			Id: retractionID, ActorId: retractionActor, Reason: retraction.Reason,
			OccurredAt: retraction.OccurredAt, Sequence: int64(retraction.Sequence),
		}
	}
	return contract.DfirRelationship{Id: id, TenantId: tenantID, Source: source, Target: target,
		RelationshipType: value.RelationshipType(), Metadata: metadata, CreatedBy: createdBy,
		CreatedAt: value.CreatedAt(), Version: int64(value.Version()), Active: value.Active(),
		Retractions: mappedRetractions}, nil
}

func mapDfirAttachment(value kernel.Attachment) (contract.DfirAttachment, error) {
	id, tenantID, err := phase4UUID(value.ID().String(), value.TenantID().String())
	storageID, storageErr := uuid.Parse(value.StorageObjectID().String())
	uploaderID, uploaderErr := uuid.Parse(value.UploadedBy().String())
	subject, subjectErr := mapDfirReference(value.Subject())
	if err != nil || storageErr != nil || uploaderErr != nil || subjectErr != nil {
		return contract.DfirAttachment{}, application.ErrUnavailable
	}
	return contract.DfirAttachment{Id: id, TenantId: tenantID, Subject: subject, StorageObjectId: storageID,
		OriginalFilename: value.OriginalFilename(), Visibility: contract.DfirVisibility(value.Visibility()),
		UploadedBy: uploaderID, UploadedAt: value.UploadedAt(), ScanState: contract.DfirScanState(value.ScanState())}, nil
}

func mapDfirEvidence(value kernel.Evidence) (contract.DfirEvidence, error) {
	id, tenantID, err := phase4UUID(value.ID().String(), value.TenantID().String())
	caseID, caseErr := uuid.Parse(value.CaseID().String())
	storageID, storageErr := uuid.Parse(value.StorageObjectID().String())
	collectorID, collectorErr := uuid.Parse(value.CollectedBy().String())
	if err != nil || caseErr != nil || storageErr != nil || collectorErr != nil || !validDfirResourceVersion(value.Version()) || !value.VerifyCustodyChain() {
		return contract.DfirEvidence{}, application.ErrUnavailable
	}
	custody := make([]contract.DfirCustodyEvent, len(value.CustodyEvents()))
	for index, event := range value.CustodyEvents() {
		eventID, eventErr := uuid.Parse(event.ID().String())
		actorID, actorErr := uuid.Parse(event.ActorID().String())
		if eventErr != nil || actorErr != nil || !validDfirResourceVersion(event.Sequence()) {
			return contract.DfirEvidence{}, application.ErrUnavailable
		}
		previous, digest := event.PreviousHash(), event.EventHash()
		custody[index] = contract.DfirCustodyEvent{Id: eventID, Sequence: int64(event.Sequence()), Action: contract.DfirCustodyAction(event.Action()),
			ActorId: actorID, Reason: event.Reason(), StateValue: event.StateValue(), PreviousHash: hex.EncodeToString(previous[:]), EventHash: hex.EncodeToString(digest[:]), OccurredAt: event.OccurredAt()}
	}
	return contract.DfirEvidence{Id: id, TenantId: tenantID, CaseId: caseID, StorageObjectId: storageID,
		Title: value.Title(), Description: value.Description(), EvidenceType: value.EvidenceType(), Classification: contract.DfirEvidenceClassification(value.Classification()),
		ContentSha256: value.ContentSHA256(), SizeBytes: value.SizeBytes(), DetectedMime: value.DetectedMIME(), CollectedAt: value.CollectedAt(),
		CollectedBy: collectorID, Source: value.Source(), RetentionUntil: value.RetentionUntil(), LegalHold: value.LegalHold(), ScanState: contract.DfirScanState(value.ScanState()),
		Sealed: value.Sealed(), Destroyed: value.Destroyed(), Version: int64(value.Version()), Custody: custody}, nil
}

func validDfirResourceVersion(value uint64) bool {
	return value >= 1 && value <= uint64(maximumExactJSONResourceVersion)
}

func mapDfirDocument(raw json.RawMessage) (*contract.DfirBoundedDocument, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var value contract.DfirBoundedDocument
	if len(raw) > 64<<10 || json.Unmarshal(raw, &value) != nil {
		return nil, application.ErrUnavailable
	}
	return &value, nil
}

func optionalOpenAPIUUID(value *kernel.EntityID) *uuid.UUID {
	if value == nil {
		return nil
	}
	parsed, err := uuid.Parse(value.String())
	if err != nil {
		return nil
	}
	return &parsed
}

func openAPIUUIDs(values []kernel.EntityID) []uuid.UUID {
	result := make([]uuid.UUID, len(values))
	for index, value := range values {
		result[index], _ = uuid.Parse(value.String())
	}
	return result
}

func uuidSliceFromOpenAPI(values []uuid.UUID) []uuid.UUID { return append([]uuid.UUID(nil), values...) }
