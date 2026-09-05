package dfir

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	_ "time/tzdata"
)

type TemporalPrecision string

const (
	PrecisionYear        TemporalPrecision = "year"
	PrecisionMonth       TemporalPrecision = "month"
	PrecisionDay         TemporalPrecision = "day"
	PrecisionHour        TemporalPrecision = "hour"
	PrecisionMinute      TemporalPrecision = "minute"
	PrecisionSecond      TemporalPrecision = "second"
	PrecisionMillisecond TemporalPrecision = "millisecond"
	PrecisionMicrosecond TemporalPrecision = "microsecond"
)

func validTemporalPrecision(value TemporalPrecision) bool {
	switch value {
	case PrecisionYear, PrecisionMonth, PrecisionDay, PrecisionHour, PrecisionMinute,
		PrecisionSecond, PrecisionMillisecond, PrecisionMicrosecond:
		return true
	default:
		return false
	}
}

type TimelineEventInput struct {
	ID               EntityID
	TenantID         EntityID
	AlertID          EntityID
	CaseID           EntityID
	EventTime        time.Time
	IngestedAt       time.Time
	OriginalTimezone string
	Precision        TemporalPrecision
	Source           string
	Category         string
	Title            string
	Description      string
	ActorID          *EntityID
	IOCIDs           []EntityID
	AssetIDs         []EntityID
	EvidenceIDs      []EntityID
	Tags             []string
}

type TimelineEvent struct {
	id               EntityID
	tenantID         EntityID
	alertID          EntityID
	caseID           EntityID
	eventTime        time.Time
	ingestedAt       time.Time
	originalTimezone string
	precision        TemporalPrecision
	source           string
	category         string
	title            string
	description      string
	actorID          *EntityID
	iocIDs           []EntityID
	assetIDs         []EntityID
	evidenceIDs      []EntityID
	tags             []string
}

const maximumTimelineReferences = 256

func NewTimelineEvent(input TimelineEventInput) (TimelineEvent, error) {
	actor, actorOK := canonicalOptionalEntityID(input.ActorID)
	iocIDs, iocOK := canonicalEntityIDs(input.IOCIDs, maximumTimelineReferences)
	assetIDs, assetOK := canonicalEntityIDs(input.AssetIDs, maximumTimelineReferences)
	evidenceIDs, evidenceOK := canonicalEntityIDs(input.EvidenceIDs, maximumTimelineReferences)
	tags, tagsOK := canonicalTags(input.Tags)
	rootValid := validEntityID(input.AlertID) != validEntityID(input.CaseID)
	if !validEntityID(input.ID) || !validEntityID(input.TenantID) || !rootValid ||
		!validInstant(input.EventTime) || !validInstant(input.IngestedAt) ||
		!validOriginalTimezone(input.OriginalTimezone) || !validTemporalPrecision(input.Precision) ||
		!validSingleLineText(input.Source, 512, false) || !validStableKey(input.Category) ||
		!validSingleLineText(input.Title, 512, false) || !validOptionalText(input.Description, 16*1024) ||
		!actorOK || !iocOK || !assetOK || !evidenceOK || !tagsOK {
		return TimelineEvent{}, ErrInvalidTimelineEvent
	}
	return TimelineEvent{
		id: input.ID, tenantID: input.TenantID, alertID: input.AlertID, caseID: input.CaseID,
		eventTime: input.EventTime, ingestedAt: input.IngestedAt,
		originalTimezone: input.OriginalTimezone, precision: input.Precision,
		source: input.Source, category: input.Category, title: input.Title,
		description: input.Description, actorID: actor,
		iocIDs: iocIDs, assetIDs: assetIDs, evidenceIDs: evidenceIDs, tags: tags,
	}, nil
}

func (event TimelineEvent) ID() EntityID                 { return event.id }
func (event TimelineEvent) TenantID() EntityID           { return event.tenantID }
func (event TimelineEvent) AlertID() EntityID            { return event.alertID }
func (event TimelineEvent) CaseID() EntityID             { return event.caseID }
func (event TimelineEvent) EventTime() time.Time         { return event.eventTime }
func (event TimelineEvent) IngestedAt() time.Time        { return event.ingestedAt }
func (event TimelineEvent) OriginalTimezone() string     { return event.originalTimezone }
func (event TimelineEvent) Precision() TemporalPrecision { return event.precision }
func (event TimelineEvent) Source() string               { return event.source }
func (event TimelineEvent) Category() string             { return event.category }
func (event TimelineEvent) Title() string                { return event.title }
func (event TimelineEvent) Description() string          { return event.description }
func (event TimelineEvent) ActorID() *EntityID           { return cloneEntityID(event.actorID) }
func (event TimelineEvent) IOCIDs() []EntityID           { return slices.Clone(event.iocIDs) }
func (event TimelineEvent) AssetIDs() []EntityID         { return slices.Clone(event.assetIDs) }
func (event TimelineEvent) EvidenceIDs() []EntityID      { return slices.Clone(event.evidenceIDs) }
func (event TimelineEvent) Tags() []string               { return slices.Clone(event.tags) }
func (event TimelineEvent) String() string {
	return fmt.Sprintf(
		"dfir.TimelineEvent{precision:%s,iocs:%d,assets:%d,evidence:%d,tags:%d,actor:%t,content:[REDACTED]}",
		event.precision, len(event.iocIDs), len(event.assetIDs), len(event.evidenceIDs),
		len(event.tags), event.actorID != nil,
	)
}
func (event TimelineEvent) GoString() string { return event.String() }

type EntityKind string

const (
	EntityAlert      EntityKind = "alert"
	EntityCase       EntityKind = "case"
	EntityIOC        EntityKind = "ioc"
	EntityAsset      EntityKind = "asset"
	EntityEvidence   EntityKind = "evidence"
	EntityTask       EntityKind = "task"
	EntityAttachment EntityKind = "attachment"
	EntityExternal   EntityKind = "external"
)

func validEntityKind(value EntityKind) bool {
	switch value {
	case EntityAlert, EntityCase, EntityIOC, EntityAsset, EntityEvidence,
		EntityTask, EntityAttachment, EntityExternal:
		return true
	default:
		return false
	}
}

type EntityReference struct {
	tenantID     EntityID
	kind         EntityKind
	id           EntityID
	externalType string
	externalID   string
}

func NewEntityReference(tenantID EntityID, kind EntityKind, id EntityID) (EntityReference, error) {
	if !validEntityID(tenantID) || !validEntityID(id) || !validEntityKind(kind) || kind == EntityExternal {
		return EntityReference{}, ErrInvalidRelationship
	}
	return EntityReference{tenantID: tenantID, kind: kind, id: id}, nil
}

func NewExternalEntityReference(
	tenantID EntityID,
	externalType string,
	externalID string,
) (EntityReference, error) {
	if !validEntityID(tenantID) || !validStableKey(externalType) ||
		!validSingleLineText(externalID, 2_048, false) {
		return EntityReference{}, ErrInvalidRelationship
	}
	return EntityReference{
		tenantID: tenantID, kind: EntityExternal,
		externalType: externalType, externalID: externalID,
	}, nil
}

func (reference EntityReference) TenantID() EntityID   { return reference.tenantID }
func (reference EntityReference) Kind() EntityKind     { return reference.kind }
func (reference EntityReference) ID() EntityID         { return reference.id }
func (reference EntityReference) ExternalType() string { return reference.externalType }
func (reference EntityReference) ExternalID() string   { return reference.externalID }
func (reference EntityReference) String() string {
	return fmt.Sprintf("dfir.EntityReference{kind:%s,valid:%t,identifier:[REDACTED]}",
		reference.kind, validEntityReference(reference))
}
func (reference EntityReference) GoString() string { return reference.String() }

type RelationshipInput struct {
	ID               EntityID
	TenantID         EntityID
	Source           EntityReference
	Target           EntityReference
	RelationshipType string
	Metadata         json.RawMessage
	CreatedBy        EntityID
	CreatedAt        time.Time
	Version          uint64
	Retractions      []RelationshipRetractionState
}

type RelationshipRetractionInput struct {
	ID         EntityID
	ActorID    EntityID
	Reason     string
	OccurredAt time.Time
}

type RelationshipRetractionState struct {
	ID             EntityID
	TenantID       EntityID
	RelationshipID EntityID
	Sequence       uint64
	ActorID        EntityID
	Reason         string
	OccurredAt     time.Time
}

func (state RelationshipRetractionState) String() string {
	return fmt.Sprintf(
		"dfir.RelationshipRetractionState{sequence:%d,reason:[REDACTED],identifiers:[REDACTED]}",
		state.Sequence,
	)
}

func (state RelationshipRetractionState) GoString() string { return state.String() }

type Relationship struct {
	id               EntityID
	tenantID         EntityID
	source           EntityReference
	target           EntityReference
	relationshipType string
	metadata         json.RawMessage
	createdBy        EntityID
	createdAt        time.Time
	version          uint64
	retractions      []RelationshipRetractionState
}

func NewRelationship(input RelationshipInput) (Relationship, error) {
	version := input.Version
	if version == 0 {
		version = 1
	}
	if !validEntityID(input.ID) || !validEntityID(input.TenantID) ||
		!validEntityReference(input.Source) || !validEntityReference(input.Target) ||
		input.Source.tenantID != input.TenantID || input.Target.tenantID != input.TenantID ||
		sameEntityReference(input.Source, input.Target) || !validStableKey(input.RelationshipType) ||
		!validEnrichment(input.Metadata) || !validEntityID(input.CreatedBy) ||
		!validInstant(input.CreatedAt) || version > maximumAggregateVersion || len(input.Retractions) > 1 ||
		version != uint64(1+len(input.Retractions)) {
		return Relationship{}, ErrInvalidRelationship
	}
	retractions := slices.Clone(input.Retractions)
	for index, retraction := range retractions {
		if !validEntityID(retraction.ID) || retraction.TenantID != input.TenantID ||
			retraction.RelationshipID != input.ID || retraction.Sequence != uint64(index+1) ||
			!validEntityID(retraction.ActorID) || !validSingleLineText(retraction.Reason, 2_000, false) ||
			strings.ContainsAny(retraction.Reason, "\u2028\u2029") ||
			!validInstant(retraction.OccurredAt) || retraction.OccurredAt.Before(input.CreatedAt) {
			return Relationship{}, ErrInvalidRelationship
		}
	}
	return Relationship{
		id: input.ID, tenantID: input.TenantID, source: input.Source, target: input.Target,
		relationshipType: input.RelationshipType,
		metadata:         slices.Clone(input.Metadata), createdBy: input.CreatedBy, createdAt: input.CreatedAt,
		version: version, retractions: retractions,
	}, nil
}

func (relationship Relationship) ID() EntityID             { return relationship.id }
func (relationship Relationship) TenantID() EntityID       { return relationship.tenantID }
func (relationship Relationship) Source() EntityReference  { return relationship.source }
func (relationship Relationship) Target() EntityReference  { return relationship.target }
func (relationship Relationship) RelationshipType() string { return relationship.relationshipType }
func (relationship Relationship) Metadata() json.RawMessage {
	return slices.Clone(relationship.metadata)
}
func (relationship Relationship) CreatedBy() EntityID  { return relationship.createdBy }
func (relationship Relationship) CreatedAt() time.Time { return relationship.createdAt }
func (relationship Relationship) Version() uint64      { return relationship.version }
func (relationship Relationship) Active() bool         { return len(relationship.retractions) == 0 }
func (relationship Relationship) Retractions() []RelationshipRetractionState {
	return slices.Clone(relationship.retractions)
}

// Retract appends the only terminal history record for a Case-rooted general
// relationship. The original relationship is never changed or deleted.
func (relationship Relationship) Retract(
	expectedVersion uint64,
	input RelationshipRetractionInput,
) (Relationship, error) {
	if expectedVersion != relationship.version {
		return Relationship{}, ErrRelationshipConflict
	}
	if !relationship.Active() || relationship.version >= maximumAggregateVersion ||
		!validEntityID(input.ID) || !validEntityID(input.ActorID) ||
		!validSingleLineText(input.Reason, 2_000, false) || strings.ContainsAny(input.Reason, "\u2028\u2029") ||
		!validInstant(input.OccurredAt) ||
		input.OccurredAt.Before(relationship.createdAt) {
		return Relationship{}, ErrInvalidRelationship
	}
	updated := relationship
	updated.version++
	updated.retractions = append(slices.Clone(relationship.retractions), RelationshipRetractionState{
		ID: input.ID, TenantID: relationship.tenantID, RelationshipID: relationship.id,
		Sequence: uint64(len(relationship.retractions) + 1), ActorID: input.ActorID,
		Reason: input.Reason, OccurredAt: input.OccurredAt,
	})
	return updated, nil
}

func (relationship Relationship) String() string {
	return fmt.Sprintf("dfir.Relationship{type:%s,source:%s,target:%s,version:%d,active:%t,metadata:%t}",
		relationship.relationshipType, relationship.source.kind, relationship.target.kind,
		relationship.version, relationship.Active(), len(relationship.metadata) > 0)
}
func (relationship Relationship) GoString() string { return relationship.String() }

type Visibility string

const (
	VisibilityPublic  Visibility = "public"
	VisibilityPrivate Visibility = "private"
)

func validVisibility(value Visibility) bool {
	return value == VisibilityPublic || value == VisibilityPrivate
}

type Audience string

const (
	AudienceOperator Audience = "operator"
	AudienceCustomer Audience = "customer"
)

type AttachmentInput struct {
	ID                  EntityID
	TenantID            EntityID
	Subject             EntityReference
	StorageObjectID     EntityID
	OriginalFilename    string
	RequestedVisibility Visibility
	SubjectVisibility   Visibility
	UploadedBy          EntityID
	UploadedAt          time.Time
	ScanState           ScanState
}

type Attachment struct {
	id               EntityID
	tenantID         EntityID
	subject          EntityReference
	storageObjectID  EntityID
	originalFilename string
	visibility       Visibility
	uploadedBy       EntityID
	uploadedAt       time.Time
	scanState        ScanState
}

func NewAttachment(input AttachmentInput) (Attachment, error) {
	if !validEntityID(input.ID) || !validEntityID(input.TenantID) ||
		!validEntityReference(input.Subject) || input.Subject.tenantID != input.TenantID ||
		input.Subject.kind == EntityExternal || !validEntityID(input.StorageObjectID) ||
		!validOriginalFilename(input.OriginalFilename) || !validVisibility(input.RequestedVisibility) ||
		!validVisibility(input.SubjectVisibility) || !validEntityID(input.UploadedBy) ||
		!validInstant(input.UploadedAt) || !validScanState(input.ScanState) ||
		input.ScanState == ScanDeleted && input.RequestedVisibility != VisibilityPrivate {
		return Attachment{}, ErrInvalidAttachment
	}
	visibility := input.RequestedVisibility
	if input.SubjectVisibility == VisibilityPrivate {
		visibility = VisibilityPrivate
	}
	return Attachment{
		id: input.ID, tenantID: input.TenantID, subject: input.Subject,
		storageObjectID: input.StorageObjectID, originalFilename: input.OriginalFilename,
		visibility: visibility, uploadedBy: input.UploadedBy,
		uploadedAt: input.UploadedAt, scanState: input.ScanState,
	}, nil
}

func (attachment Attachment) ID() EntityID              { return attachment.id }
func (attachment Attachment) TenantID() EntityID        { return attachment.tenantID }
func (attachment Attachment) Subject() EntityReference  { return attachment.subject }
func (attachment Attachment) StorageObjectID() EntityID { return attachment.storageObjectID }
func (attachment Attachment) OriginalFilename() string  { return attachment.originalFilename }
func (attachment Attachment) Visibility() Visibility    { return attachment.visibility }
func (attachment Attachment) UploadedBy() EntityID      { return attachment.uploadedBy }
func (attachment Attachment) UploadedAt() time.Time     { return attachment.uploadedAt }
func (attachment Attachment) ScanState() ScanState      { return attachment.scanState }
func (attachment Attachment) CanIssueDownload(audience Audience) bool {
	return attachment.scanState == ScanAvailable &&
		(audience == AudienceOperator || audience == AudienceCustomer && attachment.visibility == VisibilityPublic)
}
func (attachment Attachment) String() string {
	return fmt.Sprintf("dfir.Attachment{visibility:%s,scanState:%s,filename:[REDACTED]}",
		attachment.visibility, attachment.scanState)
}
func (attachment Attachment) GoString() string { return attachment.String() }

var timezoneOffsetPattern = regexp.MustCompile(`^[+-](?:0[0-9]|1[0-4]):[0-5][0-9]$`)

func validOriginalTimezone(value string) bool {
	if !validBoundedText(value, 128, false) {
		return false
	}
	if value == "UTC" || timezoneOffsetPattern.MatchString(value) {
		return value == "UTC" || value[1:3] != "14" || value[4:6] == "00"
	}
	if !strings.ContainsRune(value, '/') {
		return false
	}
	_, err := time.LoadLocation(value)
	return err == nil
}

func canonicalOptionalEntityID(value *EntityID) (*EntityID, bool) {
	if value == nil {
		return nil, true
	}
	if !validEntityID(*value) {
		return nil, false
	}
	copy := *value
	return &copy, true
}

func cloneEntityID(value *EntityID) *EntityID {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func canonicalEntityIDs(values []EntityID, maximum int) ([]EntityID, bool) {
	if len(values) > maximum {
		return nil, false
	}
	result := slices.Clone(values)
	for _, value := range result {
		if !validEntityID(value) {
			return nil, false
		}
	}
	slices.SortFunc(result, compareEntityID)
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, false
		}
	}
	return result, true
}

func validEntityReference(reference EntityReference) bool {
	if !validEntityID(reference.tenantID) || !validEntityKind(reference.kind) {
		return false
	}
	if reference.kind == EntityExternal {
		return reference.id == (EntityID{}) && validStableKey(reference.externalType) &&
			validSingleLineText(reference.externalID, 2_048, false)
	}
	return validEntityID(reference.id) && reference.externalType == "" && reference.externalID == ""
}

func sameEntityReference(left, right EntityReference) bool {
	return left.tenantID == right.tenantID && left.kind == right.kind && left.id == right.id &&
		left.externalType == right.externalType && left.externalID == right.externalID
}

func validOriginalFilename(value string) bool {
	return validSingleLineText(value, 255, false) && value != "." && value != ".." &&
		!strings.ContainsAny(value, `/\\`)
}
