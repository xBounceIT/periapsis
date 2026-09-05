package httpserver

import (
	"encoding/hex"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func dfirAlertTimelineInput(
	tenantID uuid.UUID,
	alertID uuid.UUID,
	eventID uuid.UUID,
	spec contract.DfirAlertTimelineEventSpec,
) (kernel.TimelineEventInput, error) {
	tenant, tenantErr := dfirEntityID(tenantID)
	alert, alertErr := dfirEntityID(alertID)
	id, idErr := dfirEntityID(eventID)
	if tenantErr != nil || alertErr != nil || idErr != nil || !spec.Precision.Valid() {
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
	eventTime, err := canonicalAlertTransportInstant(spec.EventTime)
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
		ID: id, TenantID: tenant, AlertID: alert, EventTime: eventTime,
		OriginalTimezone: spec.OriginalTimezone, Precision: kernel.TemporalPrecision(spec.Precision),
		Source: spec.Source, Category: spec.Category, Title: spec.Title, Description: spec.Description,
		ActorID: actorID, IOCIDs: iocs, AssetIDs: assets, EvidenceIDs: evidence,
		Tags: append([]string(nil), spec.Tags...),
	}, nil
}

func mapDfirAlertWorkspace(
	tenantID uuid.UUID,
	alertID uuid.UUID,
	value application.AlertWorkspace,
	investigation application.AlertInvestigationWorkspace,
) (contract.DfirAlertWorkspace, error) {
	sharedResources, err := mapDfirSharedResources(value.SharedResources)
	if err != nil {
		return contract.DfirAlertWorkspace{}, err
	}
	result := contract.DfirAlertWorkspace{
		SharedResources: sharedResources,
		TenantId:        tenantID, AlertId: alertID,
		Indicators:    make([]contract.DfirAlertIndicator, len(value.Indicators)),
		Assets:        make([]contract.DfirAlertAsset, len(value.Assets)),
		Timeline:      make([]contract.DfirAlertTimelineEvent, len(value.Timeline)),
		Attachments:   make([]contract.DfirAttachment, len(value.Attachments)),
		Evidence:      make([]contract.DfirAlertEvidence, len(investigation.Evidence)),
		Tasks:         make([]contract.DfirAlertTask, len(investigation.Tasks)),
		Relationships: make([]contract.DfirAlertRelationship, len(investigation.Relationships)),
	}
	evidenceIDs := make(map[kernel.EntityID]struct{}, len(investigation.Evidence))
	for _, evidence := range investigation.Evidence {
		evidenceIDs[evidence.ID()] = struct{}{}
	}
	for index, item := range value.Indicators {
		result.Indicators[index], err = mapDfirAlertIndicator(item.Resource, alertID, item.Version)
		if err != nil {
			return contract.DfirAlertWorkspace{}, err
		}
	}
	for index, item := range value.Assets {
		result.Assets[index], err = mapDfirAlertAsset(item.Resource, alertID, item.Version)
		if err != nil {
			return contract.DfirAlertWorkspace{}, err
		}
	}
	for index, item := range value.Timeline {
		for _, evidenceID := range item.Resource.EvidenceIDs() {
			if _, exists := evidenceIDs[evidenceID]; !exists {
				return contract.DfirAlertWorkspace{}, application.ErrUnavailable
			}
		}
		result.Timeline[index], err = mapDfirAlertTimeline(item.Resource, item.Version)
		if err != nil {
			return contract.DfirAlertWorkspace{}, err
		}
	}
	for index, item := range value.Attachments {
		result.Attachments[index], err = mapDfirAttachment(item)
		if err != nil {
			return contract.DfirAlertWorkspace{}, err
		}
	}
	for index, item := range investigation.Evidence {
		result.Evidence[index], err = mapDfirAlertEvidence(item, tenantID, alertID)
		if err != nil {
			return contract.DfirAlertWorkspace{}, err
		}
	}
	for index, item := range investigation.Tasks {
		result.Tasks[index], err = mapDfirAlertTask(item, tenantID, alertID)
		if err != nil {
			return contract.DfirAlertWorkspace{}, err
		}
	}
	for index, item := range investigation.Relationships {
		result.Relationships[index], err = mapDfirAlertRelationship(item, tenantID, alertID)
		if err != nil {
			return contract.DfirAlertWorkspace{}, err
		}
	}
	return result, nil
}

func alertChecklistIntents(values []contract.DfirAlertChecklistItemIntent) ([]application.AlertChecklistItemIntent, error) {
	result := make([]application.AlertChecklistItemIntent, len(values))
	for index, value := range values {
		id, err := dfirEntityID(uuid.UUID(value.Id))
		if err != nil {
			return nil, application.ErrInvalidInput
		}
		result[index] = application.AlertChecklistItemIntent{
			ID: id, Title: value.Title, Completed: value.Completed,
		}
	}
	return result, nil
}

func alertTaskDraft(taskID uuid.UUID, value contract.DfirAlertTaskSpec) (application.AlertTaskDraft, error) {
	id, idErr := dfirEntityID(taskID)
	assignee, assigneeErr := optionalDfirEntityID(value.AssigneeId)
	team, teamErr := optionalDfirEntityID(value.OperatorTeamId)
	sla, slaErr := optionalDfirEntityID(value.SlaInstanceId)
	checklist, checklistErr := alertChecklistIntents(value.Checklist)
	dueAt, dueErr := canonicalAlertTransportOptionalInstant(value.DueAt)
	if idErr != nil || assigneeErr != nil || teamErr != nil || slaErr != nil || checklistErr != nil ||
		dueErr != nil || !value.Priority.Valid() {
		return application.AlertTaskDraft{}, application.ErrInvalidInput
	}
	return application.AlertTaskDraft{
		ID: id, Title: value.Title, Description: value.Description,
		Priority: kernel.TaskPriority(value.Priority), AssigneeID: assignee,
		OperatorTeamID: team, DueAt: dueAt, Checklist: checklist, SLAInstanceID: sla,
	}, nil
}

func mapDfirAlertEvidence(
	value kernel.AlertEvidence,
	tenantID uuid.UUID,
	alertID uuid.UUID,
) (contract.DfirAlertEvidence, error) {
	id, storedTenant, err := phase4UUID(value.ID().String(), value.TenantID().String())
	storedAlert, alertErr := uuid.Parse(value.AlertID().String())
	storageID, storageErr := uuid.Parse(value.StorageObjectID().String())
	collectorID, collectorErr := uuid.Parse(value.CollectedBy().String())
	if err != nil || alertErr != nil || storageErr != nil || collectorErr != nil ||
		storedTenant != tenantID || storedAlert != alertID || !validDfirResourceVersion(value.Version()) ||
		!value.VerifyCustodyChain() {
		return contract.DfirAlertEvidence{}, application.ErrUnavailable
	}
	custody := make([]contract.DfirCustodyEvent, len(value.CustodyEvents()))
	for index, event := range value.CustodyEvents() {
		eventID, eventErr := uuid.Parse(event.ID().String())
		actorID, actorErr := uuid.Parse(event.ActorID().String())
		if eventErr != nil || actorErr != nil || !validDfirResourceVersion(event.Sequence()) {
			return contract.DfirAlertEvidence{}, application.ErrUnavailable
		}
		previous, digest := event.PreviousHash(), event.EventHash()
		custody[index] = contract.DfirCustodyEvent{
			Id: eventID, Sequence: int64(event.Sequence()), Action: contract.DfirCustodyAction(event.Action()),
			ActorId: actorID, Reason: event.Reason(), StateValue: event.StateValue(),
			PreviousHash: hex.EncodeToString(previous[:]), EventHash: hex.EncodeToString(digest[:]),
			OccurredAt: event.OccurredAt(),
		}
	}
	return contract.DfirAlertEvidence{
		Id: id, TenantId: storedTenant, AlertId: storedAlert, StorageObjectId: storageID,
		Title: value.Title(), Description: value.Description(), EvidenceType: value.EvidenceType(),
		Classification: contract.DfirEvidenceClassification(value.Classification()),
		ContentSha256:  value.ContentSHA256(), SizeBytes: value.SizeBytes(), DetectedMime: value.DetectedMIME(),
		CollectedAt: value.CollectedAt(), CollectedBy: collectorID, Source: value.Source(),
		RetentionUntil: value.RetentionUntil(), LegalHold: value.LegalHold(),
		ScanState: contract.DfirScanState(value.ScanState()), Sealed: value.Sealed(), Destroyed: value.Destroyed(),
		Version: int64(value.Version()), Custody: custody,
	}, nil
}

func mapDfirAlertTask(
	value kernel.AlertTask,
	tenantID uuid.UUID,
	alertID uuid.UUID,
) (contract.DfirAlertTask, error) {
	id, storedTenant, err := phase4UUID(value.ID().String(), value.TenantID().String())
	storedAlert, alertErr := uuid.Parse(value.AlertID().String())
	if err != nil || alertErr != nil || storedTenant != tenantID || storedAlert != alertID ||
		!validDfirResourceVersion(value.Version()) {
		return contract.DfirAlertTask{}, application.ErrUnavailable
	}
	checklist := make([]contract.DfirChecklistItem, len(value.Checklist()))
	for index, item := range value.Checklist() {
		itemID, parseErr := uuid.Parse(item.ID().String())
		if parseErr != nil {
			return contract.DfirAlertTask{}, application.ErrUnavailable
		}
		checklist[index] = contract.DfirChecklistItem{
			Id: itemID, Title: item.Title(), Completed: item.Completed(),
			CompletedAt: item.CompletedAt(), CompletedBy: optionalOpenAPIUUID(item.CompletedBy()),
		}
	}
	completion, err := mapDfirDocument(value.CompletionData())
	if err != nil {
		return contract.DfirAlertTask{}, err
	}
	return contract.DfirAlertTask{
		Id: id, TenantId: storedTenant, AlertId: storedAlert, Title: value.Title(), Description: value.Description(),
		Status: contract.DfirTaskStatus(value.Status()), Priority: contract.DfirTaskPriority(value.Priority()),
		AssigneeId: optionalOpenAPIUUID(value.AssigneeID()), OperatorTeamId: optionalOpenAPIUUID(value.OperatorTeamID()),
		DueAt: value.DueAt(), Checklist: checklist, CompletedAt: value.CompletedAt(),
		CompletedBy: optionalOpenAPIUUID(value.CompletedBy()), CompletionData: completion,
		CommentIds: openAPIUUIDs(value.CommentIDs()), SlaInstanceId: optionalOpenAPIUUID(value.SLAInstanceID()),
		CreatedAt: value.CreatedAt(), UpdatedAt: value.UpdatedAt(), Version: int64(value.Version()),
	}, nil
}

func mapDfirAlertRelationship(
	value kernel.AlertRelationship,
	tenantID uuid.UUID,
	alertID uuid.UUID,
) (contract.DfirAlertRelationship, error) {
	id, storedTenant, err := phase4UUID(value.ID().String(), value.TenantID().String())
	storedAlert, alertErr := uuid.Parse(value.AlertID().String())
	createdBy, actorErr := uuid.Parse(value.CreatedBy().String())
	source, sourceErr := mapDfirReference(value.Source())
	target, targetErr := mapDfirReference(value.Target())
	metadata, metadataErr := mapDfirDocument(value.Metadata())
	if err != nil || alertErr != nil || actorErr != nil || sourceErr != nil || targetErr != nil ||
		metadataErr != nil || storedTenant != tenantID || storedAlert != alertID ||
		!validDfirResourceVersion(value.Version()) {
		return contract.DfirAlertRelationship{}, application.ErrUnavailable
	}
	retractions := value.Retractions()
	mappedRetractions := make([]contract.DfirAlertRelationshipRetraction, len(retractions))
	for index, retraction := range retractions {
		retractionID, idErr := uuid.Parse(retraction.ID.String())
		retractionActor, actorErr := uuid.Parse(retraction.ActorID.String())
		if idErr != nil || actorErr != nil || retraction.TenantID.String() != value.TenantID().String() ||
			retraction.RelationshipID != value.ID() || !validDfirResourceVersion(retraction.Sequence) {
			return contract.DfirAlertRelationship{}, application.ErrUnavailable
		}
		mappedRetractions[index] = contract.DfirAlertRelationshipRetraction{
			Id: retractionID, ActorId: retractionActor, Reason: retraction.Reason,
			OccurredAt: retraction.OccurredAt, Sequence: int64(retraction.Sequence),
		}
	}
	return contract.DfirAlertRelationship{
		Id: id, TenantId: storedTenant, AlertId: storedAlert, Source: source, Target: target,
		RelationshipType: value.RelationshipType(), Metadata: metadata, CreatedBy: createdBy,
		CreatedAt: value.CreatedAt(), Version: int64(value.Version()), Active: value.Active(),
		Retractions: mappedRetractions,
	}, nil
}

func canonicalAlertTransportOptionalInstant(value *time.Time) (*time.Time, error) {
	if value == nil {
		return nil, nil
	}
	canonical, err := canonicalAlertTransportInstant(*value)
	if err != nil {
		return nil, err
	}
	return &canonical, nil
}

func canonicalAlertTransportInstant(value time.Time) (time.Time, error) {
	canonical := value.UTC()
	if canonical.IsZero() || canonical.Nanosecond()%1_000 != 0 {
		return time.Time{}, application.ErrInvalidInput
	}
	if _, err := canonical.MarshalJSON(); err != nil {
		return time.Time{}, application.ErrInvalidInput
	}
	return canonical, nil
}

func mapDfirAlertIndicator(
	value kernel.Indicator,
	alertID uuid.UUID,
	version uint64,
) (contract.DfirAlertIndicator, error) {
	id, tenantID, err := phase4UUID(value.ID().String(), value.TenantID().String())
	if err != nil || alertID == uuid.Nil || !validDfirResourceVersion(version) {
		return contract.DfirAlertIndicator{}, application.ErrUnavailable
	}
	enrichment, err := mapDfirDocument(value.Enrichment())
	if err != nil {
		return contract.DfirAlertIndicator{}, err
	}
	return contract.DfirAlertIndicator{
		Id: id, TenantId: tenantID, AlertId: alertID, Version: int64(version),
		Indicator: contract.DfirIndicatorSpec{
			Type: contract.DfirIndicatorType(value.Type()), Value: value.Value(), Description: value.Description(),
			Source: value.Source(), Confidence: value.Confidence(), Tlp: contract.DfirTlp(value.TLP()),
			FirstSeen: value.FirstSeen(), LastSeen: value.LastSeen(),
			Malicious: contract.DfirMaliciousState(value.MaliciousState()),
			Tags:      nonNilStrings(value.Tags()), Enrichment: enrichment,
		},
	}, nil
}

func mapDfirAlertAsset(
	value kernel.Asset,
	alertID uuid.UUID,
	version uint64,
) (contract.DfirAlertAsset, error) {
	id, tenantID, err := phase4UUID(value.ID().String(), value.TenantID().String())
	if err != nil || alertID == uuid.Nil || !validDfirResourceVersion(version) {
		return contract.DfirAlertAsset{}, application.ErrUnavailable
	}
	attributes, err := mapDfirDocument(value.CustomAttributes())
	if err != nil {
		return contract.DfirAlertAsset{}, err
	}
	ips := make([]string, len(value.IPAddresses()))
	for index, address := range value.IPAddresses() {
		ips[index] = address.Original()
	}
	macs := make([]string, len(value.MACAddresses()))
	for index, address := range value.MACAddresses() {
		macs[index] = address.Original()
	}
	return contract.DfirAlertAsset{
		Id: id, TenantId: tenantID, AlertId: alertID, Version: int64(version),
		Asset: contract.DfirAssetSpec{
			Hostname: value.Hostname(), Fqdn: value.FQDN(), IpAddresses: ips, MacAddresses: macs,
			AssetType: value.AssetType(), OperatingSystem: value.OperatingSystem(), Owner: value.Owner(),
			BusinessUnit: value.BusinessUnit(), Criticality: contract.DfirAssetCriticality(value.Criticality()),
			Environment: value.Environment(), ExternalId: value.ExternalID(),
			Tags: nonNilStrings(value.Tags()), FirstSeen: value.FirstSeen(), LastSeen: value.LastSeen(),
			CustomAttributes: attributes,
		},
	}, nil
}

func mapDfirAlertTimeline(
	value kernel.TimelineEvent,
	version uint64,
) (contract.DfirAlertTimelineEvent, error) {
	id, tenantID, err := phase4UUID(value.ID().String(), value.TenantID().String())
	alertID, alertErr := uuid.Parse(value.AlertID().String())
	if err != nil || alertErr != nil || value.CaseID() != (kernel.EntityID{}) ||
		!validDfirResourceVersion(version) {
		return contract.DfirAlertTimelineEvent{}, application.ErrUnavailable
	}
	return contract.DfirAlertTimelineEvent{
		Id: id, TenantId: tenantID, AlertId: alertID, IngestedAt: value.IngestedAt(), Version: int64(version),
		Event: contract.DfirAlertTimelineEventSpec{
			EventTime: value.EventTime(), OriginalTimezone: value.OriginalTimezone(),
			Precision: contract.DfirTemporalPrecision(value.Precision()), Source: value.Source(),
			Category: value.Category(), Title: value.Title(), Description: value.Description(),
			ActorId: optionalOpenAPIUUID(value.ActorID()), IocIds: openAPIUUIDs(value.IOCIDs()),
			AssetIds: openAPIUUIDs(value.AssetIDs()), EvidenceIds: openAPIUUIDs(value.EvidenceIDs()),
			Tags: nonNilStrings(value.Tags()),
		},
	}, nil
}
