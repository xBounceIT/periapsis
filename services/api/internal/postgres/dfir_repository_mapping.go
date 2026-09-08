package postgres

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/dfir"
)

func parseDFIREntityID(value uuid.UUID) (kernel.EntityID, error) {
	result, err := kernel.NewEntityID([16]byte(value))
	if err != nil {
		return kernel.EntityID{}, unexpectedDFIRProjection("non-UUIDv7 identifier")
	}
	return result, nil
}

func parseOptionalDFIREntityID(value *uuid.UUID) (*kernel.EntityID, error) {
	if value == nil {
		return nil, nil
	}
	result, err := parseDFIREntityID(*value)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func loadDFIRIndicator(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	id uuid.UUID,
) (kernel.Indicator, uint64, error) {
	var storedID, storedTenant uuid.UUID
	var kind, value, normalized, description, source, tlp, malicious string
	var ipValue *string
	var confidence int32
	var firstSeen, lastSeen time.Time
	var tags []string
	var enrichment []byte
	var version int64
	err := tx.QueryRow(ctx, `
		SELECT id, tenant_id, type::text, value, normalized_value,
		       ip_value::text, description, source, confidence, tlp::text,
		       first_seen, last_seen, malicious_state::text, tags,
		       enrichment, version
		FROM public.dfir_iocs
		WHERE tenant_id = $1 AND id = $2 AND archived_at IS NULL`, tenantID, id).Scan(
		&storedID, &storedTenant, &kind, &value, &normalized, &ipValue,
		&description, &source, &confidence, &tlp, &firstSeen, &lastSeen,
		&malicious, &tags, &enrichment, &version,
	)
	if err != nil {
		return kernel.Indicator{}, 0, err
	}
	firstSeen = firstSeen.UTC()
	lastSeen = lastSeen.UTC()
	identifier, err := parseDFIREntityID(storedID)
	if err != nil {
		return kernel.Indicator{}, 0, err
	}
	tenant, err := parseDFIREntityID(storedTenant)
	if err != nil || !validDFIRDatabaseResourceVersion(version) || confidence < 0 || confidence > 100 {
		return kernel.Indicator{}, 0, unexpectedDFIRProjection("invalid IOC scalar")
	}
	indicator, err := kernel.NewIndicator(kernel.IndicatorInput{
		ID: identifier, TenantID: tenant, Type: kernel.IndicatorType(kind),
		Value: value, Description: description, Source: source,
		Confidence: int(confidence), TLP: kernel.TrafficLightProtocol(tlp),
		FirstSeen: firstSeen, LastSeen: lastSeen, Malicious: kernel.MaliciousState(malicious),
		Tags: tags, Enrichment: canonicalJSONObject(enrichment),
	})
	if err != nil || indicator.NormalizedValue() != normalized {
		return kernel.Indicator{}, 0, unexpectedDFIRProjection("non-canonical IOC")
	}
	isIP := indicator.Type() == kernel.IndicatorIPv4 || indicator.Type() == kernel.IndicatorIPv6
	if isIP != (ipValue != nil) || ipValue != nil && dfirInetHost(*ipValue) != indicator.NormalizedValue() {
		return kernel.Indicator{}, 0, unexpectedDFIRProjection("IOC address projection mismatch")
	}
	return indicator, uint64(version), nil
}

type dfirOriginalIdentifiers struct {
	Hostname     *string  `json:"hostname"`
	FQDN         *string  `json:"fqdn"`
	IPAddresses  []string `json:"ipAddresses"`
	MACAddresses []string `json:"macAddresses"`
}

func loadDFIRAsset(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	id uuid.UUID,
) (kernel.Asset, uint64, error) {
	var storedID, storedTenant uuid.UUID
	var hostname, normalizedHostname, fqdn, normalizedFQDN *string
	var normalizedIPs, normalizedMACs, normalizedMAC8s []string
	var originalJSON []byte
	var assetType, operatingSystem, owner, businessUnit, criticality, environment string
	var externalID *string
	var tags []string
	var firstSeen, lastSeen time.Time
	var customAttributes []byte
	var version int64
	err := tx.QueryRow(ctx, `
		SELECT id, tenant_id, hostname, normalized_hostname, fqdn, normalized_fqdn,
		       ARRAY(SELECT value::text FROM unnest(ip_addresses) AS value ORDER BY value::text),
		       ARRAY(SELECT value::text FROM unnest(mac_addresses) AS value ORDER BY value::text),
		       ARRAY(SELECT value::text FROM unnest(mac8_addresses) AS value ORDER BY value::text),
		       original_identifiers, asset_type, operating_system, owner, business_unit,
		       criticality::text, environment, external_id, tags, first_seen, last_seen,
		       custom_attributes, version
		FROM public.dfir_assets
		WHERE tenant_id = $1 AND id = $2 AND archived_at IS NULL`, tenantID, id).Scan(
		&storedID, &storedTenant, &hostname, &normalizedHostname, &fqdn, &normalizedFQDN,
		&normalizedIPs, &normalizedMACs, &normalizedMAC8s, &originalJSON,
		&assetType, &operatingSystem, &owner, &businessUnit, &criticality,
		&environment, &externalID, &tags, &firstSeen, &lastSeen, &customAttributes, &version,
	)
	if err != nil {
		return kernel.Asset{}, 0, err
	}
	firstSeen = firstSeen.UTC()
	lastSeen = lastSeen.UTC()
	identifier, err := parseDFIREntityID(storedID)
	if err != nil {
		return kernel.Asset{}, 0, err
	}
	tenant, err := parseDFIREntityID(storedTenant)
	if err != nil || !validDFIRDatabaseResourceVersion(version) {
		return kernel.Asset{}, 0, unexpectedDFIRProjection("invalid asset identity or version")
	}
	var original dfirOriginalIdentifiers
	if err = decodeDFIRJSON(originalJSON, &original); err != nil || original.IPAddresses == nil || original.MACAddresses == nil {
		return kernel.Asset{}, 0, unexpectedDFIRProjection("invalid original asset identifiers")
	}
	originalHostname, originalFQDN := "", ""
	if original.Hostname != nil {
		originalHostname = *original.Hostname
	}
	if original.FQDN != nil {
		originalFQDN = *original.FQDN
	}
	asset, err := kernel.NewAsset(kernel.AssetInput{
		ID: identifier, TenantID: tenant, Hostname: originalHostname, FQDN: originalFQDN,
		IPAddresses: original.IPAddresses, MACAddresses: original.MACAddresses,
		AssetType: assetType, OperatingSystem: operatingSystem, Owner: owner,
		BusinessUnit: businessUnit, Criticality: kernel.AssetCriticality(criticality),
		Environment: environment, ExternalID: dereferenceString(externalID), Tags: tags,
		FirstSeen: firstSeen, LastSeen: lastSeen, CustomAttributes: canonicalJSONObject(customAttributes),
	})
	if err != nil || !sameOptionalString(hostname, asset.Hostname()) ||
		!sameOptionalString(fqdn, asset.FQDN()) || !sameOptionalString(normalizedHostname, asset.NormalizedHostname()) ||
		!sameOptionalString(normalizedFQDN, asset.NormalizedFQDN()) {
		return kernel.Asset{}, 0, unexpectedDFIRProjection("non-canonical asset")
	}
	assetIPs := asset.IPAddresses()
	for index, address := range normalizedIPs {
		normalizedIPs[index] = dfirInetHost(address)
	}
	slices.Sort(normalizedIPs)
	expectedIPs := make([]string, len(assetIPs))
	for index, address := range assetIPs {
		expectedIPs[index] = address.Normalized()
	}
	slices.Sort(expectedIPs)
	assetMACs := asset.MACAddresses()
	expectedMACs := make([]string, 0, len(assetMACs))
	expectedMAC8s := make([]string, 0, len(assetMACs))
	for _, address := range assetMACs {
		if strings.Count(address.Normalized(), ":") == 5 {
			expectedMACs = append(expectedMACs, address.Normalized())
		} else {
			expectedMAC8s = append(expectedMAC8s, address.Normalized())
		}
	}
	slices.Sort(expectedMACs)
	slices.Sort(expectedMAC8s)
	if !slices.Equal(expectedIPs, normalizedIPs) || !slices.Equal(expectedMACs, normalizedMACs) ||
		!slices.Equal(expectedMAC8s, normalizedMAC8s) {
		return kernel.Asset{}, 0, unexpectedDFIRProjection("asset normalized identifiers mismatch")
	}
	return asset, uint64(version), nil
}

func loadDFIRTimelineEvent(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	id uuid.UUID,
) (kernel.TimelineEvent, uint64, error) {
	var storedID, storedTenant uuid.UUID
	var alertID, caseID *uuid.UUID
	var eventTime, ingestedAt time.Time
	var timezone, precision, source, category, title, description string
	var actorID *uuid.UUID
	var tags []string
	var version int64
	err := tx.QueryRow(ctx, `
		SELECT id, tenant_id, alert_id, case_id, event_time, ingested_at, original_timezone,
		       precision::text, source, category, title, description, actor_user_id,
		       tags, version
		FROM public.dfir_timeline_events
		WHERE tenant_id = $1 AND id = $2`, tenantID, id).Scan(
		&storedID, &storedTenant, &alertID, &caseID, &eventTime, &ingestedAt, &timezone,
		&precision, &source, &category, &title, &description, &actorID, &tags, &version,
	)
	if err != nil {
		return kernel.TimelineEvent{}, 0, err
	}
	identifier, err := parseDFIREntityID(storedID)
	if err != nil {
		return kernel.TimelineEvent{}, 0, err
	}
	tenant, err := parseDFIREntityID(storedTenant)
	if err != nil {
		return kernel.TimelineEvent{}, 0, err
	}
	alertEntity, alertErr := parseOptionalDFIREntityID(alertID)
	caseEntity, caseErr := parseOptionalDFIREntityID(caseID)
	if alertErr != nil || caseErr != nil || (alertEntity == nil) == (caseEntity == nil) ||
		!validDFIRDatabaseResourceVersion(version) {
		return kernel.TimelineEvent{}, 0, unexpectedDFIRProjection("invalid timeline identity or version")
	}
	actorEntity, err := parseOptionalDFIREntityID(actorID)
	if err != nil {
		return kernel.TimelineEvent{}, 0, err
	}
	iocIDs, err := loadDFIRLinkIDs(ctx, tx, "public.dfir_timeline_ioc_links", "ioc_id", tenantID, storedID)
	if err != nil {
		return kernel.TimelineEvent{}, 0, err
	}
	assetIDs, err := loadDFIRLinkIDs(ctx, tx, "public.dfir_timeline_asset_links", "asset_id", tenantID, storedID)
	if err != nil {
		return kernel.TimelineEvent{}, 0, err
	}
	evidenceIDs, err := loadDFIRLinkIDs(ctx, tx, "public.dfir_timeline_evidence_links", "evidence_id", tenantID, storedID)
	if err != nil {
		return kernel.TimelineEvent{}, 0, err
	}
	input := kernel.TimelineEventInput{
		ID: identifier, TenantID: tenant, EventTime: canonicalAlertDatabaseTime(eventTime),
		IngestedAt: canonicalAlertDatabaseTime(ingestedAt), OriginalTimezone: timezone, Precision: kernel.TemporalPrecision(precision),
		Source: source, Category: category, Title: title, Description: description,
		ActorID: actorEntity, IOCIDs: iocIDs, AssetIDs: assetIDs, EvidenceIDs: evidenceIDs, Tags: tags,
	}
	if alertEntity != nil {
		input.AlertID = *alertEntity
	} else {
		input.CaseID = *caseEntity
	}
	event, err := kernel.NewTimelineEvent(input)
	if err != nil {
		return kernel.TimelineEvent{}, 0, unexpectedDFIRProjection("non-canonical timeline event")
	}
	return event, uint64(version), nil
}

func loadDFIRLinkIDs(
	ctx context.Context,
	tx databaseTransaction,
	table string,
	column string,
	tenantID uuid.UUID,
	eventID uuid.UUID,
) ([]kernel.EntityID, error) {
	rows, err := tx.Query(ctx, "SELECT "+column+" FROM "+table+" WHERE tenant_id = $1 AND timeline_event_id = $2 ORDER BY "+column+" LIMIT 1001", tenantID, eventID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]kernel.EntityID, 0)
	for rows.Next() {
		var raw uuid.UUID
		if scanErr := rows.Scan(&raw); scanErr != nil {
			return nil, scanErr
		}
		identifier, parseErr := parseDFIREntityID(raw)
		if parseErr != nil {
			return nil, parseErr
		}
		result = append(result, identifier)
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	if len(result) > 1000 {
		return nil, unexpectedDFIRProjection("timeline link bound exceeded")
	}
	return result, nil
}

type dfirChecklistJSON struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Completed   bool    `json:"completed"`
	CompletedAt *string `json:"completedAt,omitempty"`
	CompletedBy *string `json:"completedBy,omitempty"`
}

func loadDFIRTask(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	caseID uuid.UUID,
	id uuid.UUID,
) (kernel.Task, error) {
	var storedID, storedTenant, storedCase uuid.UUID
	var title, description, status, priority string
	var assigneeID, teamID, teamEpochID *uuid.UUID
	var dueAt, completedAt *time.Time
	var checklistJSON []byte
	var completedBy *uuid.UUID
	var completionData []byte
	var commentIDs []uuid.UUID
	var slaID *uuid.UUID
	var createdAt, updatedAt time.Time
	var version int64
	err := tx.QueryRow(ctx, `
		SELECT id, tenant_id, case_id, title, description, status::text, priority::text,
		       assignee_user_id, operator_team_id, operator_team_epoch_id, due_at,
		       checklist, completed_at, completed_by_user_id, completion_data,
		       comment_ids, sla_instance_id, created_at, updated_at, version
		FROM public.dfir_tasks
		WHERE tenant_id = $1 AND case_id = $2 AND alert_id IS NULL AND id = $3`, tenantID, caseID, id).Scan(
		&storedID, &storedTenant, &storedCase, &title, &description, &status, &priority,
		&assigneeID, &teamID, &teamEpochID, &dueAt, &checklistJSON, &completedAt,
		&completedBy, &completionData, &commentIDs, &slaID, &createdAt, &updatedAt, &version,
	)
	if err != nil {
		return kernel.Task{}, err
	}
	if teamID == nil != (teamEpochID == nil) || assigneeID != nil && teamID == nil ||
		!validDFIRDatabaseResourceVersion(version) {
		return kernel.Task{}, unexpectedDFIRProjection("invalid task assignment or version")
	}
	identifier, err := parseDFIREntityID(storedID)
	if err != nil {
		return kernel.Task{}, err
	}
	tenant, err := parseDFIREntityID(storedTenant)
	if err != nil {
		return kernel.Task{}, err
	}
	caseEntity, err := parseDFIREntityID(storedCase)
	if err != nil {
		return kernel.Task{}, err
	}
	assignee, err := parseOptionalDFIREntityID(assigneeID)
	if err != nil {
		return kernel.Task{}, err
	}
	team, err := parseOptionalDFIREntityID(teamID)
	if err != nil {
		return kernel.Task{}, err
	}
	completer, err := parseOptionalDFIREntityID(completedBy)
	if err != nil {
		return kernel.Task{}, err
	}
	sla, err := parseOptionalDFIREntityID(slaID)
	if err != nil {
		return kernel.Task{}, err
	}
	var checklistRows []dfirChecklistJSON
	if err = decodeDFIRJSON(checklistJSON, &checklistRows); err != nil || len(checklistRows) > 100 {
		return kernel.Task{}, unexpectedDFIRProjection("invalid task checklist")
	}
	checklist := make([]kernel.ChecklistItem, len(checklistRows))
	for index, row := range checklistRows {
		itemID, parseErr := uuid.Parse(row.ID)
		if parseErr != nil {
			return kernel.Task{}, unexpectedDFIRProjection("invalid checklist identifier")
		}
		itemEntity, parseErr := parseDFIREntityID(itemID)
		if parseErr != nil {
			return kernel.Task{}, parseErr
		}
		var itemAt *time.Time
		if row.CompletedAt != nil {
			parsed, timeErr := time.Parse(time.RFC3339Nano, *row.CompletedAt)
			if timeErr != nil {
				return kernel.Task{}, unexpectedDFIRProjection("invalid checklist completion time")
			}
			itemAt = &parsed
		}
		var itemBy *kernel.EntityID
		if row.CompletedBy != nil {
			parsed, idErr := uuid.Parse(*row.CompletedBy)
			if idErr != nil {
				return kernel.Task{}, unexpectedDFIRProjection("invalid checklist completion actor")
			}
			itemBy, idErr = parseOptionalDFIREntityID(&parsed)
			if idErr != nil {
				return kernel.Task{}, idErr
			}
		}
		checklist[index], err = kernel.NewChecklistItem(kernel.ChecklistItemInput{
			ID: itemEntity, Title: row.Title, Completed: row.Completed,
			CompletedAt: canonicalOptionalAlertDatabaseTime(itemAt), CompletedBy: itemBy,
		})
		if err != nil {
			return kernel.Task{}, unexpectedDFIRProjection("non-canonical checklist item")
		}
	}
	comments := make([]kernel.EntityID, len(commentIDs))
	for index, value := range commentIDs {
		comments[index], err = parseDFIREntityID(value)
		if err != nil {
			return kernel.Task{}, err
		}
	}
	task, err := kernel.NewTask(kernel.TaskInput{
		ID: identifier, TenantID: tenant, CaseID: caseEntity, Title: title,
		Description: description, Status: kernel.TaskStatus(status), Priority: kernel.TaskPriority(priority),
		AssigneeID: assignee, OperatorTeamID: team, DueAt: canonicalOptionalAlertDatabaseTime(dueAt), Checklist: checklist,
		CompletedAt: canonicalOptionalAlertDatabaseTime(completedAt), CompletedBy: completer, CompletionData: canonicalJSONObject(completionData),
		CommentIDs: comments, SLAInstanceID: sla, CreatedAt: canonicalAlertDatabaseTime(createdAt), UpdatedAt: canonicalAlertDatabaseTime(updatedAt),
		Version: uint64(version),
	})
	if err != nil {
		return kernel.Task{}, unexpectedDFIRProjection("non-canonical task")
	}
	return task, nil
}

func loadDFIRStorageObject(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	id uuid.UUID,
) (kernel.StorageObject, error) {
	var storedID, storedTenant, createdBy uuid.UUID
	var bucket, objectKey, filename, classification, state string
	var expectedSizeBytes int64
	var uploadExpiresAt time.Time
	var digest []byte
	var sizeBytes *int64
	var detectedMIME *string
	var verifiedAt, retentionUntil *time.Time
	var legalHold bool
	var version int64
	var createdAt, updatedAt time.Time
	err := tx.QueryRow(ctx, `
		SELECT id, tenant_id, bucket, object_key, original_filename,
		       classification::text, expected_size_bytes, upload_expires_at,
		       created_by_membership_id, created_at, updated_at,
		       state::text, content_sha256, size_bytes, detected_mime, verified_at,
		       retention_until, legal_hold, version
		FROM public.dfir_storage_objects
		WHERE tenant_id = $1 AND id = $2`, tenantID, id).Scan(
		&storedID, &storedTenant, &bucket, &objectKey, &filename, &classification,
		&expectedSizeBytes, &uploadExpiresAt,
		&createdBy, &createdAt, &updatedAt, &state, &digest, &sizeBytes,
		&detectedMIME, &verifiedAt, &retentionUntil, &legalHold, &version,
	)
	if err != nil {
		return kernel.StorageObject{}, err
	}
	identifier, err := parseDFIREntityID(storedID)
	if err != nil {
		return kernel.StorageObject{}, err
	}
	tenant, err := parseDFIREntityID(storedTenant)
	if err != nil {
		return kernel.StorageObject{}, err
	}
	creator, err := parseDFIREntityID(createdBy)
	if err != nil || !validDFIRDatabaseResourceVersion(version) || len(digest) != 0 && len(digest) != 32 ||
		(sizeBytes == nil) != (len(digest) == 0) || (detectedMIME == nil) != (len(digest) == 0) ||
		(verifiedAt == nil) != (len(digest) == 0) {
		return kernel.StorageObject{}, unexpectedDFIRProjection("invalid storage object content projection")
	}
	contentHash, size, mediaType := "", int64(0), ""
	if len(digest) != 0 {
		contentHash, size, mediaType = hex.EncodeToString(digest), *sizeBytes, *detectedMIME
	}
	object, err := kernel.RestoreStorageObject(kernel.StorageObjectState{
		ID: identifier, TenantID: tenant, Bucket: bucket, ObjectKey: objectKey,
		OriginalFilename: filename, Classification: kernel.EvidenceClassification(classification),
		ExpectedSizeBytes: expectedSizeBytes, UploadExpiresAt: canonicalAlertDatabaseTime(uploadExpiresAt),
		CreatedBy: creator, CreatedAt: canonicalAlertDatabaseTime(createdAt), UpdatedAt: canonicalAlertDatabaseTime(updatedAt),
		State: kernel.ScanState(state), ContentSHA256: contentHash, SizeBytes: size,
		DetectedMIME: mediaType, VerifiedAt: canonicalOptionalAlertDatabaseTime(verifiedAt), RetentionUntil: canonicalOptionalAlertDatabaseTime(retentionUntil),
		LegalHold: legalHold, Version: uint64(version),
	})
	if err != nil {
		return kernel.StorageObject{}, unexpectedDFIRProjection("non-canonical storage object")
	}
	return object, nil
}

func loadDFIRAttachment(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	caseID uuid.UUID,
	id uuid.UUID,
) (kernel.Attachment, error) {
	return loadDFIRAttachmentForRoot(ctx, tx, tenantID, kernel.EntityCase, caseID, id)
}

func loadDFIRAlertAttachment(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	alertID uuid.UUID,
	id uuid.UUID,
) (kernel.Attachment, error) {
	return loadDFIRAttachmentForRoot(ctx, tx, tenantID, kernel.EntityAlert, alertID, id)
}

func loadDFIRAttachmentForRoot(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	rootKind kernel.EntityKind,
	rootID uuid.UUID,
	id uuid.UUID,
) (kernel.Attachment, error) {
	var storedID, storedTenant, storageID, uploadedBy uuid.UUID
	var subjectKind, filename, visibility, scanState string
	var alertID, directCaseID, iocID, assetID, evidenceID, taskID *uuid.UUID
	var uploadedAt time.Time
	var version int64
	err := tx.QueryRow(ctx, `
		SELECT id, tenant_id, subject_kind::text, alert_id, case_id, ioc_id,
		       asset_id, evidence_id, task_id, storage_object_id, original_filename,
		       visibility::text, scan_state::text, uploaded_by_membership_id,
		       uploaded_at, version
		FROM public.dfir_attachments
		WHERE tenant_id = $1 AND id = $2`, tenantID, id).Scan(
		&storedID, &storedTenant, &subjectKind, &alertID, &directCaseID, &iocID,
		&assetID, &evidenceID, &taskID, &storageID, &filename, &visibility,
		&scanState, &uploadedBy, &uploadedAt, &version,
	)
	if err != nil {
		return kernel.Attachment{}, err
	}
	if storedID != id || storedTenant != tenantID {
		return kernel.Attachment{}, unexpectedDFIRProjection("attachment identity or tenant mismatch")
	}
	nestedKind, nestedID, err := dfirAttachmentSubject(subjectKind, alertID, directCaseID, iocID, assetID, evidenceID, taskID)
	if err != nil {
		return kernel.Attachment{}, err
	}
	if !validDFIRDatabaseResourceVersion(version) {
		return kernel.Attachment{}, unexpectedDFIRProjection("attachment version is invalid")
	}
	identifier, err := parseDFIREntityID(storedID)
	if err != nil {
		return kernel.Attachment{}, err
	}
	tenant, err := parseDFIREntityID(storedTenant)
	if err != nil {
		return kernel.Attachment{}, err
	}
	storage, err := parseDFIREntityID(storageID)
	if err != nil {
		return kernel.Attachment{}, err
	}
	uploader, err := parseDFIREntityID(uploadedBy)
	if err != nil {
		return kernel.Attachment{}, err
	}
	var subject kernel.EntityReference
	if nestedKind == kernel.EntityExternal {
		return kernel.Attachment{}, unexpectedDFIRProjection("external attachment subject")
	}
	subjectID, err := parseDFIREntityID(nestedID)
	if err != nil {
		return kernel.Attachment{}, err
	}
	subject, err = kernel.NewEntityReference(tenant, nestedKind, subjectID)
	if err != nil {
		return kernel.Attachment{}, unexpectedDFIRProjection("invalid attachment subject")
	}
	inheritedVisibility := kernel.VisibilityPrivate
	switch rootKind {
	case kernel.EntityCase:
		var explicitlyLinked bool
		if nestedKind == kernel.EntityAlert || nestedKind == kernel.EntityIOC || nestedKind == kernel.EntityAsset {
			if resolveErr := tx.QueryRow(ctx, `SELECT EXISTS (
				SELECT 1 FROM public.dfir_attachment_case_links AS link
				WHERE link.tenant_id = $1 AND link.attachment_id = $2 AND link.case_id = $3
			)`, tenantID, storedID, rootID).Scan(&explicitlyLinked); resolveErr != nil {
				return kernel.Attachment{}, resolveErr
			}
		}
		if explicitlyLinked {
			record, resolveErr := loadDFIRCaseAccessRecord(ctx, tx, tenantID, rootID)
			if resolveErr != nil {
				return kernel.Attachment{}, resolveErr
			}
			if record.customerVisible && record.customerState {
				inheritedVisibility = kernel.VisibilityPublic
			}
			break
		}
		resolvedVisibility, resolveErr := resolveDFIRCaseSubject(ctx, tx, tenantID, rootID, subject)
		if resolveErr != nil {
			return kernel.Attachment{}, resolveErr
		}
		inheritedVisibility = resolvedVisibility
	case kernel.EntityAlert:
		resolvedVisibility, resolveErr := resolveDFIRAlertSubject(ctx, tx, tenantID, rootID, subject)
		if resolveErr != nil {
			return kernel.Attachment{}, resolveErr
		}
		inheritedVisibility = resolvedVisibility
	default:
		return kernel.Attachment{}, unexpectedDFIRProjection("attachment root is unsupported")
	}
	requested := kernel.Visibility(visibility)
	if requested == kernel.VisibilityPublic && inheritedVisibility == kernel.VisibilityPrivate {
		return kernel.Attachment{}, unexpectedDFIRProjection("attachment visibility exceeds subject visibility")
	}
	attachment, err := kernel.NewAttachment(kernel.AttachmentInput{
		ID: identifier, TenantID: tenant, Subject: subject, StorageObjectID: storage,
		OriginalFilename: filename, RequestedVisibility: requested,
		SubjectVisibility: inheritedVisibility, UploadedBy: uploader,
		UploadedAt: canonicalAlertDatabaseTime(uploadedAt), ScanState: kernel.ScanState(scanState),
	})
	if err != nil || attachment.Visibility() != requested {
		return kernel.Attachment{}, unexpectedDFIRProjection("non-canonical attachment")
	}
	return attachment, nil
}

func loadDFIRRelationship(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	caseID uuid.UUID,
	id uuid.UUID,
) (kernel.Relationship, error) {
	var storedID, storedTenant, createdBy uuid.UUID
	var sourceKind, targetKind, relationshipType string
	var sourceID, targetID *uuid.UUID
	var sourceExternalType, sourceExternalID, targetExternalType, targetExternalID *string
	var metadata []byte
	var createdAt time.Time
	var version int64
	err := tx.QueryRow(ctx, `
		SELECT id, tenant_id, source_kind::text, source_id, source_external_type,
		       source_external_id, target_kind::text, target_id, target_external_type,
		       target_external_id, relationship_type, metadata,
		       created_by_membership_id, created_at, version
		FROM public.dfir_relationships
		WHERE tenant_id = $1 AND case_id = $2 AND alert_id IS NULL AND id = $3`, tenantID, caseID, id).Scan(
		&storedID, &storedTenant, &sourceKind, &sourceID, &sourceExternalType,
		&sourceExternalID, &targetKind, &targetID, &targetExternalType,
		&targetExternalID, &relationshipType, &metadata, &createdBy, &createdAt, &version,
	)
	if err != nil {
		return kernel.Relationship{}, err
	}
	if version < 1 || version > int64(kernel.MaximumResourceVersion) {
		return kernel.Relationship{}, unexpectedDFIRProjection("invalid Case relationship version")
	}
	identifier, err := parseDFIREntityID(storedID)
	if err != nil {
		return kernel.Relationship{}, err
	}
	tenant, err := parseDFIREntityID(storedTenant)
	if err != nil {
		return kernel.Relationship{}, err
	}
	creator, err := parseDFIREntityID(createdBy)
	if err != nil {
		return kernel.Relationship{}, err
	}
	source, err := restoreDFIRReference(tenant, sourceKind, sourceID, sourceExternalType, sourceExternalID)
	if err != nil {
		return kernel.Relationship{}, err
	}
	target, err := restoreDFIRReference(tenant, targetKind, targetID, targetExternalType, targetExternalID)
	if err != nil {
		return kernel.Relationship{}, err
	}
	rows, err := tx.Query(ctx, `
		SELECT id, tenant_id, relationship_id, retracted_by_membership_id,
		       reason, prior_version, result_version, retracted_at
		FROM public.dfir_relationship_retractions
		WHERE tenant_id = $1 AND relationship_id = $2 AND case_id = $3 AND alert_id IS NULL
		ORDER BY result_version LIMIT 2`, tenantID, id, caseID)
	if err != nil {
		return kernel.Relationship{}, err
	}
	defer rows.Close()
	retractions := make([]kernel.RelationshipRetractionState, 0, 1)
	for rows.Next() {
		var retractionID, retractionTenant, relationshipID, actor uuid.UUID
		var reason string
		var priorVersion, resultVersion int64
		var occurredAt time.Time
		if scanErr := rows.Scan(
			&retractionID, &retractionTenant, &relationshipID, &actor,
			&reason, &priorVersion, &resultVersion, &occurredAt,
		); scanErr != nil {
			return kernel.Relationship{}, scanErr
		}
		if priorVersion != 1 || resultVersion != 2 {
			return kernel.Relationship{}, unexpectedDFIRProjection("invalid Case relationship retraction version")
		}
		retractionEntity, parseErr := parseDFIREntityID(retractionID)
		if parseErr != nil {
			return kernel.Relationship{}, parseErr
		}
		retractionTenantEntity, parseErr := parseDFIREntityID(retractionTenant)
		if parseErr != nil {
			return kernel.Relationship{}, parseErr
		}
		relationshipEntity, parseErr := parseDFIREntityID(relationshipID)
		if parseErr != nil {
			return kernel.Relationship{}, parseErr
		}
		actorEntity, parseErr := parseDFIREntityID(actor)
		if parseErr != nil {
			return kernel.Relationship{}, parseErr
		}
		retractions = append(retractions, kernel.RelationshipRetractionState{
			ID: retractionEntity, TenantID: retractionTenantEntity, RelationshipID: relationshipEntity,
			Sequence: 1, ActorID: actorEntity, Reason: reason,
			OccurredAt: canonicalAlertDatabaseTime(occurredAt),
		})
	}
	if rows.Err() != nil {
		return kernel.Relationship{}, rows.Err()
	}
	if version != int64(1+len(retractions)) {
		return kernel.Relationship{}, unexpectedDFIRProjection("Case relationship history cardinality mismatch")
	}
	result, err := kernel.NewRelationship(kernel.RelationshipInput{
		ID: identifier, TenantID: tenant, Source: source, Target: target,
		RelationshipType: relationshipType, Metadata: canonicalJSONObject(metadata),
		CreatedBy: creator, CreatedAt: canonicalAlertDatabaseTime(createdAt),
		Version: uint64(version), Retractions: retractions,
	})
	if err != nil {
		return kernel.Relationship{}, unexpectedDFIRProjection("non-canonical relationship")
	}
	return result, nil
}

func restoreDFIRReference(
	tenant kernel.EntityID,
	kind string,
	id *uuid.UUID,
	externalType *string,
	externalID *string,
) (kernel.EntityReference, error) {
	if kernel.EntityKind(kind) == kernel.EntityExternal {
		if id != nil || externalType == nil || externalID == nil {
			return kernel.EntityReference{}, unexpectedDFIRProjection("invalid external reference")
		}
		value, err := kernel.NewExternalEntityReference(tenant, *externalType, *externalID)
		if err != nil {
			return kernel.EntityReference{}, unexpectedDFIRProjection("non-canonical external reference")
		}
		return value, nil
	}
	if id == nil || externalType != nil || externalID != nil {
		return kernel.EntityReference{}, unexpectedDFIRProjection("invalid internal reference")
	}
	identifier, err := parseDFIREntityID(*id)
	if err != nil {
		return kernel.EntityReference{}, err
	}
	value, err := kernel.NewEntityReference(tenant, kernel.EntityKind(kind), identifier)
	if err != nil {
		return kernel.EntityReference{}, unexpectedDFIRProjection("non-canonical internal reference")
	}
	return value, nil
}

func loadDFIREvidence(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	caseID uuid.UUID,
	id uuid.UUID,
) (kernel.Evidence, error) {
	var storedID, storedTenant, storedCase, storageID, collectedBy uuid.UUID
	var title, description, evidenceType, classification, detectedMIME, source string
	var contentDigest, anchorHash, custodyHead []byte
	var sizeBytes int64
	var collectedAt time.Time
	var initialRetention, retention *time.Time
	var initialLegalHold, legalHold bool
	var initialScanState, scanState string
	var sealed, destroyed bool
	var custodyCount, version int64
	err := tx.QueryRow(ctx, `
		SELECT id, tenant_id, case_id, storage_object_id, title, description,
		       evidence_type, classification::text, content_sha256, size_bytes,
		       detected_mime, collected_at, collected_by_membership_id, source,
		       initial_retention_until, retention_until, initial_legal_hold,
		       legal_hold, initial_scan_state::text, scan_state::text, sealed,
		       destroyed, anchor_hash, custody_head_hash, custody_count, version
		FROM public.dfir_evidence
		WHERE tenant_id = $1 AND case_id = $2 AND id = $3`, tenantID, caseID, id).Scan(
		&storedID, &storedTenant, &storedCase, &storageID, &title, &description,
		&evidenceType, &classification, &contentDigest, &sizeBytes, &detectedMIME,
		&collectedAt, &collectedBy, &source, &initialRetention, &retention,
		&initialLegalHold, &legalHold, &initialScanState, &scanState, &sealed,
		&destroyed, &anchorHash, &custodyHead, &custodyCount, &version,
	)
	if err != nil {
		return kernel.Evidence{}, err
	}
	if len(contentDigest) != 32 || len(anchorHash) != 32 || len(custodyHead) != 32 ||
		version < 1 || version > int64(kernel.MaximumCustodyEvents) || custodyCount != version {
		return kernel.Evidence{}, unexpectedDFIRProjection("invalid evidence hash or version")
	}
	identifier, err := parseDFIREntityID(storedID)
	if err != nil {
		return kernel.Evidence{}, err
	}
	tenant, err := parseDFIREntityID(storedTenant)
	if err != nil {
		return kernel.Evidence{}, err
	}
	caseEntity, err := parseDFIREntityID(storedCase)
	if err != nil {
		return kernel.Evidence{}, err
	}
	storage, err := parseDFIREntityID(storageID)
	if err != nil {
		return kernel.Evidence{}, err
	}
	collector, err := parseDFIREntityID(collectedBy)
	if err != nil {
		return kernel.Evidence{}, err
	}
	custody, err := loadDFIRCustody(ctx, tx, tenantID, storedID, version)
	if err != nil {
		return kernel.Evidence{}, err
	}
	result, err := kernel.RestoreEvidence(kernel.EvidenceState{
		ID: identifier, TenantID: tenant, CaseID: caseEntity, StorageObjectID: storage,
		Title: title, Description: description, EvidenceType: evidenceType,
		Classification: kernel.EvidenceClassification(classification),
		ContentSHA256:  hex.EncodeToString(contentDigest), SizeBytes: sizeBytes,
		DetectedMIME: detectedMIME, CollectedAt: canonicalAlertDatabaseTime(collectedAt), CollectedBy: collector,
		Source: source, RetentionUntil: canonicalOptionalAlertDatabaseTime(retention), LegalHold: legalHold,
		ScanState: kernel.ScanState(scanState), InitialRetentionUntil: canonicalOptionalAlertDatabaseTime(initialRetention),
		InitialLegalHold: initialLegalHold, InitialScanState: kernel.ScanState(initialScanState),
		Sealed: sealed, Destroyed: destroyed, Version: uint64(version), CustodyEvents: custody,
	})
	events := result.CustodyEvents()
	if err != nil {
		// RestoreEvidence already checks the complete chain. Compare the stored
		// head separately below; the anchor is validated by the reconstructed
		// initial event and immutable evidence state.
		return kernel.Evidence{}, unexpectedDFIRProjection("invalid evidence custody chain")
	}
	if len(events) == 0 {
		return kernel.Evidence{}, unexpectedDFIRProjection("empty evidence custody chain")
	}
	initialPrevious := events[0].PreviousHash()
	head := events[len(events)-1].EventHash()
	if !bytes.Equal(initialPrevious[:], anchorHash) || !bytes.Equal(head[:], custodyHead) {
		return kernel.Evidence{}, unexpectedDFIRProjection("evidence custody head mismatch")
	}
	return result, nil
}

func validDFIRDatabaseResourceVersion(version int64) bool {
	return version > 0 && version <= int64(kernel.MaximumResourceVersion)
}

func loadDFIRCustody(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	evidenceID uuid.UUID,
	expected int64,
) ([]kernel.CustodyEventState, error) {
	rows, err := tx.Query(ctx, `
		SELECT event.id, event.tenant_id, event.evidence_id, event.sequence, event.action::text,
		       CASE WHEN evidence.alert_id IS NOT NULL THEN event.actor_id
		         ELSE coalesce(event.actor_membership_id, event.actor_service_account_id, event.actor_id) END,
		       event.reason, event.state_value, event.previous_hash, event.event_hash, event.occurred_at
		FROM public.dfir_custody_events AS event
		JOIN public.dfir_evidence AS evidence
		  ON evidence.tenant_id = event.tenant_id AND evidence.id = event.evidence_id
		WHERE event.tenant_id = $1 AND event.evidence_id = $2
		ORDER BY event.sequence LIMIT 1001`, tenantID, evidenceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]kernel.CustodyEventState, 0)
	for rows.Next() {
		var id, tenant, evidence, actor uuid.UUID
		var sequence int64
		var action, reason, stateValue string
		var previousHash, eventHash []byte
		var occurredAt time.Time
		if scanErr := rows.Scan(&id, &tenant, &evidence, &sequence, &action, &actor,
			&reason, &stateValue, &previousHash, &eventHash, &occurredAt); scanErr != nil {
			return nil, scanErr
		}
		if sequence < 1 || len(previousHash) != 32 || len(eventHash) != 32 {
			return nil, unexpectedDFIRProjection("invalid custody event scalar")
		}
		idEntity, parseErr := parseDFIREntityID(id)
		if parseErr != nil {
			return nil, parseErr
		}
		tenantEntity, parseErr := parseDFIREntityID(tenant)
		if parseErr != nil {
			return nil, parseErr
		}
		evidenceEntity, parseErr := parseDFIREntityID(evidence)
		if parseErr != nil {
			return nil, parseErr
		}
		actorEntity, parseErr := parseDFIREntityID(actor)
		if parseErr != nil {
			return nil, parseErr
		}
		var previous, eventHashArray [32]byte
		copy(previous[:], previousHash)
		copy(eventHashArray[:], eventHash)
		result = append(result, kernel.CustodyEventState{
			ID: idEntity, TenantID: tenantEntity, EvidenceID: evidenceEntity,
			Sequence: uint64(sequence), Action: kernel.CustodyAction(action),
			ActorID: actorEntity, Reason: reason, StateValue: stateValue,
			PreviousHash: previous, EventHash: eventHashArray, OccurredAt: canonicalAlertDatabaseTime(occurredAt),
		})
	}
	if rows.Err() != nil {
		return nil, rows.Err()
	}
	if int64(len(result)) != expected || uint64(len(result)) > kernel.MaximumCustodyEvents {
		return nil, unexpectedDFIRProjection("custody cardinality mismatch")
	}
	return result, nil
}

// PostgreSQL inet::text includes a host prefix, even for a single address.
// Reject network prefixes while preserving the kernel's canonical host form.
func dfirInetHost(value string) string {
	if address, err := netip.ParseAddr(value); err == nil {
		return address.String()
	}
	if prefix, err := netip.ParsePrefix(value); err == nil && prefix.Bits() == prefix.Addr().BitLen() {
		return prefix.Addr().String()
	}
	return ""
}

func canonicalJSONObject(value []byte) json.RawMessage {
	if len(value) == 0 || bytes.Equal(value, []byte("null")) {
		return nil
	}
	return slices.Clone(value)
}

func decodeDFIRJSON(value []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("JSON projection has trailing data")
	}
	return nil
}

func dereferenceString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func sameOptionalString(stored *string, canonical string) bool {
	if canonical == "" {
		return stored == nil
	}
	return stored != nil && *stored == canonical
}
