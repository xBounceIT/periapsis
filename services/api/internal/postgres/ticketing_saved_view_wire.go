package postgres

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	customkernel "github.com/periapsis-im/periapsis/modules/customfields"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

const (
	maximumSavedViewResolveRequestBytes = 256 * 1024
	maximumSavedViewListRequestBytes    = 4 * 1024
	maximumSavedViewGetRequestBytes     = 2 * 1024
	maximumSavedViewReplayRequestBytes  = 4 * 1024
	maximumSavedViewCommitRequestBytes  = 512 * 1024

	maximumSavedViewSpecResponseBytes   = 512 * 1024
	maximumSavedViewRecordResponseBytes = 512 * 1024
	maximumSavedViewListResponseBytes   = 48 * 1024 * 1024
	maximumSavedViewWireDepth           = 16
	maximumSavedViewWireTokens          = 20_000
	maximumSavedViewRevision            = uint64(math.MaxInt32)
)

type savedViewResolveSpecRequestV1 struct {
	SchemaVersion     int                        `json:"schemaVersion"`
	TenantID          string                     `json:"tenantId"`
	ActorID           string                     `json:"actorId"`
	OwnerMembershipID string                     `json:"ownerMembershipId"`
	AggregateKind     string                     `json:"aggregateKind"`
	Filters           savedViewResolveFiltersV1  `json:"filters"`
	Sort              savedViewResolveSortV1     `json:"sort"`
	Columns           []savedViewResolveColumnV1 `json:"columns"`
}

func (savedViewResolveSpecRequestV1) String() string {
	return "savedViewResolveSpecRequestV1{identity:[REDACTED],spec:[REDACTED]}"
}

func (request savedViewResolveSpecRequestV1) GoString() string { return request.String() }

type savedViewResolveFiltersV1 struct {
	States          []string                         `json:"states"`
	Severities      []string                         `json:"severities"`
	Priorities      []string                         `json:"priorities"`
	AssignedTeamID  string                           `json:"assignedTeamId"`
	AssigneeUserID  string                           `json:"assigneeUserId"`
	ClaimedBy       string                           `json:"claimedBy"`
	Queue           string                           `json:"queue"`
	CustomerVisible *bool                            `json:"customerVisible"`
	Search          string                           `json:"search"`
	Custom          []savedViewResolveCustomFilterV1 `json:"custom"`
}

type savedViewResolveCustomFilterV1 struct {
	DefinitionID              string          `json:"definitionId"`
	ExpectedDefinitionVersion uint64          `json:"expectedDefinitionVersion"`
	Operator                  string          `json:"operator"`
	Value                     json.RawMessage `json:"value"`
}

type savedViewResolveSortV1 struct {
	Source                    string `json:"source"`
	CoreKey                   string `json:"coreKey"`
	DefinitionID              string `json:"definitionId"`
	ExpectedDefinitionVersion uint64 `json:"expectedDefinitionVersion"`
	Direction                 string `json:"direction"`
	Nulls                     string `json:"nulls"`
}

type savedViewResolveColumnV1 struct {
	Source                    string `json:"source"`
	CoreKey                   string `json:"coreKey"`
	DefinitionID              string `json:"definitionId"`
	ExpectedDefinitionVersion uint64 `json:"expectedDefinitionVersion"`
	Width                     uint16 `json:"width"`
	Visible                   bool   `json:"visible"`
	Pin                       string `json:"pin"`
}

type savedViewListRequestV1 struct {
	SchemaVersion     int    `json:"schemaVersion"`
	TenantID          string `json:"tenantId"`
	ActorID           string `json:"actorId"`
	OwnerMembershipID string `json:"ownerMembershipId"`
	AggregateKind     string `json:"aggregateKind"`
	AfterID           string `json:"afterId"`
	Limit             int    `json:"limit"`
	IncludeArchived   bool   `json:"includeArchived"`
}

func (savedViewListRequestV1) String() string {
	return "savedViewListRequestV1{identity:[REDACTED],cursor:[REDACTED]}"
}

func (request savedViewListRequestV1) GoString() string { return request.String() }

type savedViewGetRequestV1 struct {
	SchemaVersion     int    `json:"schemaVersion"`
	TenantID          string `json:"tenantId"`
	ActorID           string `json:"actorId"`
	OwnerMembershipID string `json:"ownerMembershipId"`
	AggregateKind     string `json:"aggregateKind"`
	ViewID            string `json:"viewId"`
}

func (savedViewGetRequestV1) String() string {
	return "savedViewGetRequestV1{identity:[REDACTED]}"
}

func (request savedViewGetRequestV1) GoString() string { return request.String() }

type savedViewReplayRequestV1 struct {
	SchemaVersion        int    `json:"schemaVersion"`
	TenantID             string `json:"tenantId"`
	ActorID              string `json:"actorId"`
	OwnerMembershipID    string `json:"ownerMembershipId"`
	AggregateKind        string `json:"aggregateKind"`
	Action               string `json:"action"`
	IdempotencyKeySHA256 string `json:"idempotencyKeySha256"`
}

func (savedViewReplayRequestV1) String() string {
	return "savedViewReplayRequestV1{identity:[REDACTED],command:[REDACTED]}"
}

func (request savedViewReplayRequestV1) GoString() string { return request.String() }

type savedViewCommitRequestV1 struct {
	SchemaVersion            int                    `json:"schemaVersion"`
	TenantID                 string                 `json:"tenantId"`
	ActorID                  string                 `json:"actorId"`
	OwnerMembershipID        string                 `json:"ownerMembershipId"`
	AggregateKind            string                 `json:"aggregateKind"`
	RequiredCapability       string                 `json:"requiredCapability"`
	Action                   string                 `json:"action"`
	ViewID                   string                 `json:"viewId"`
	ExpectedRevision         uint64                 `json:"expectedRevision"`
	NextRevision             uint64                 `json:"nextRevision"`
	Name                     string                 `json:"name"`
	Status                   string                 `json:"status"`
	SpecCanonicalBase64      string                 `json:"specCanonicalBase64"`
	SpecSHA256               string                 `json:"specSha256"`
	IdempotencyKeySHA256     string                 `json:"idempotencyKeySha256"`
	RequestFingerprintSHA256 string                 `json:"requestFingerprintSha256"`
	CommandID                string                 `json:"commandId"`
	AuditEventID             string                 `json:"auditEventId"`
	OutboxEventID            string                 `json:"outboxEventId"`
	Audit                    savedViewCommitAuditV1 `json:"audit"`
}

func (savedViewCommitRequestV1) String() string {
	return "savedViewCommitRequestV1{identity:[REDACTED],command:[REDACTED],spec:[REDACTED],audit:[REDACTED]}"
}

func (request savedViewCommitRequestV1) GoString() string { return request.String() }

type savedViewCommitAuditV1 struct {
	RequestID            string `json:"requestId"`
	CorrelationID        string `json:"correlationId"`
	RemoteAddress        string `json:"remoteAddress"`
	UserAgent            string `json:"userAgent"`
	AuthenticationMethod string `json:"authenticationMethod"`
}

type savedViewResolvedSpecResponseV1 struct {
	SchemaVersion       int    `json:"schemaVersion"`
	SpecCanonicalBase64 string `json:"specCanonicalBase64"`
	SpecSHA256          string `json:"specSha256"`
}

func (savedViewResolvedSpecResponseV1) String() string {
	return "savedViewResolvedSpecResponseV1{spec:[REDACTED]}"
}

func (response savedViewResolvedSpecResponseV1) GoString() string { return response.String() }

type savedViewListResponseV1 struct {
	SchemaVersion int               `json:"schemaVersion"`
	Records       []json.RawMessage `json:"records"`
	HasMore       *bool             `json:"hasMore"`
}

func (savedViewListResponseV1) String() string {
	return "savedViewListResponseV1{records:[REDACTED],cursor:[REDACTED]}"
}

func (response savedViewListResponseV1) GoString() string { return response.String() }

type savedViewGetResponseV1 struct {
	SchemaVersion int             `json:"schemaVersion"`
	Record        json.RawMessage `json:"record"`
}

func (savedViewGetResponseV1) String() string {
	return "savedViewGetResponseV1{record:[REDACTED]}"
}

func (response savedViewGetResponseV1) GoString() string { return response.String() }

type savedViewReplayResponseV1 struct {
	SchemaVersion            int             `json:"schemaVersion"`
	ActorID                  string          `json:"actorId"`
	OwnerMembershipID        string          `json:"ownerMembershipId"`
	Action                   string          `json:"action"`
	RequestFingerprintSHA256 string          `json:"requestFingerprintSha256"`
	Record                   json.RawMessage `json:"record"`
}

func (savedViewReplayResponseV1) String() string {
	return "savedViewReplayResponseV1{identity:[REDACTED],command:[REDACTED],record:[REDACTED]}"
}

func (response savedViewReplayResponseV1) GoString() string { return response.String() }

type savedViewCommitResponseV1 struct {
	SchemaVersion            int             `json:"schemaVersion"`
	ActorID                  string          `json:"actorId"`
	OwnerMembershipID        string          `json:"ownerMembershipId"`
	Action                   string          `json:"action"`
	RequestFingerprintSHA256 string          `json:"requestFingerprintSha256"`
	Replayed                 *bool           `json:"replayed"`
	Record                   json.RawMessage `json:"record"`
}

func (savedViewCommitResponseV1) String() string {
	return "savedViewCommitResponseV1{identity:[REDACTED],command:[REDACTED],record:[REDACTED]}"
}

func (response savedViewCommitResponseV1) GoString() string { return response.String() }

type savedViewRecordWireV1 struct {
	ID                  string          `json:"id"`
	TenantID            string          `json:"tenantId"`
	OwnerMembershipID   string          `json:"ownerMembershipId"`
	AggregateKind       string          `json:"aggregateKind"`
	Name                string          `json:"name"`
	SpecCanonicalBase64 string          `json:"specCanonicalBase64"`
	SpecSHA256          string          `json:"specSha256"`
	Status              string          `json:"status"`
	Revision            uint64          `json:"revision"`
	CreatedAt           time.Time       `json:"createdAt"`
	UpdatedAt           time.Time       `json:"updatedAt"`
	ArchivedAt          json.RawMessage `json:"archivedAt"`
}

func (savedViewRecordWireV1) String() string {
	return "savedViewRecordWireV1{identity:[REDACTED],spec:[REDACTED],metadata:[REDACTED]}"
}

func (record savedViewRecordWireV1) GoString() string { return record.String() }

func newSavedViewResolveSpecRequestFromValidated(
	tenantID uuid.UUID,
	actorID uuid.UUID,
	ownerMembershipID uuid.UUID,
	kind kernel.AggregateKind,
	input application.SavedViewSpecInput,
) (savedViewResolveSpecRequestV1, error) {
	if !authorizationUUIDv7(tenantID) || !authorizationUUIDv7(actorID) ||
		!authorizationUUIDv7(ownerMembershipID) ||
		!validSavedViewRepositoryKind(kind) {
		return savedViewResolveSpecRequestV1{}, application.ErrInvalidInput
	}
	custom := make([]savedViewResolveCustomFilterV1, len(input.Filters.Custom))
	for index, filter := range input.Filters.Custom {
		custom[index] = savedViewResolveCustomFilterV1{
			DefinitionID:              filter.DefinitionID.String(),
			ExpectedDefinitionVersion: filter.ExpectedDefinitionVersion,
			Operator:                  string(filter.Operator), Value: slices.Clone(filter.Value),
		}
	}
	columns := make([]savedViewResolveColumnV1, len(input.Columns))
	for index, column := range input.Columns {
		columns[index] = savedViewResolveColumnV1{
			Source: string(column.Source), CoreKey: column.CoreKey,
			DefinitionID:              savedViewOptionalUUIDPointer(column.DefinitionID),
			ExpectedDefinitionVersion: column.ExpectedDefinitionVersion,
			Width:                     column.Width, Visible: column.Visible, Pin: column.Pin,
		}
	}
	return savedViewResolveSpecRequestV1{
		SchemaVersion: 1, TenantID: tenantID.String(), ActorID: actorID.String(),
		OwnerMembershipID: ownerMembershipID.String(),
		AggregateKind:     kind.String(),
		Filters: savedViewResolveFiltersV1{
			States:         savedViewWireStringSlice(input.Filters.States),
			Severities:     savedViewWireStringSlice(input.Filters.Severities),
			Priorities:     savedViewWireStringSlice(input.Filters.Priorities),
			AssignedTeamID: savedViewOptionalUUIDPointer(input.Filters.AssignedTeamID),
			AssigneeUserID: savedViewOptionalUUIDPointer(input.Filters.AssigneeUserID),
			ClaimedBy:      savedViewOptionalUUIDPointer(input.Filters.ClaimedBy),
			Queue:          input.Filters.Queue, CustomerVisible: cloneSavedViewWireBool(input.Filters.CustomerVisible),
			Search: input.Filters.Search, Custom: custom,
		},
		Sort: savedViewResolveSortV1{
			Source: string(input.Sort.Source), CoreKey: input.Sort.CoreKey,
			DefinitionID:              savedViewOptionalUUIDPointer(input.Sort.DefinitionID),
			ExpectedDefinitionVersion: input.Sort.ExpectedDefinitionVersion,
			Direction:                 input.Sort.Direction, Nulls: input.Sort.Nulls,
		},
		Columns: columns,
	}, nil
}

func newSavedViewReplayRequest(
	query application.SavedViewReplayQuery,
) (savedViewReplayRequestV1, error) {
	if !authorizationUUIDv7(query.TenantID) || !authorizationUUIDv7(query.ActorID) ||
		!authorizationUUIDv7(query.OwnerMembershipID) || !validSavedViewRepositoryKind(query.Kind) ||
		!validSavedViewRepositoryAction(query.Action) || !nonzeroSavedViewDigest(query.KeyHash) ||
		!nonzeroSavedViewDigest(query.Fingerprint) {
		return savedViewReplayRequestV1{}, application.ErrConflict
	}
	return savedViewReplayRequestV1{
		SchemaVersion: 1, TenantID: query.TenantID.String(), ActorID: query.ActorID.String(),
		OwnerMembershipID: query.OwnerMembershipID.String(), AggregateKind: query.Kind.String(),
		Action: query.Action.String(), IdempotencyKeySHA256: encodeSavedViewDigest(query.KeyHash),
	}, nil
}

func newSavedViewCommitRequest(
	repository *TicketingRepository,
	write application.SavedViewWrite,
) (savedViewCommitRequestV1, kernel.SavedView, error) {
	if repository == nil || repository.newID == nil ||
		write.RequiredCapability != application.SavedViewCapabilityManage ||
		write.Command.Action != write.Plan.Action() || !validSavedViewRepositoryAction(write.Command.Action) ||
		!nonzeroSavedViewDigest(write.Command.KeyHash) || !nonzeroSavedViewDigest(write.Command.Fingerprint) {
		return savedViewCommitRequestV1{}, kernel.SavedView{}, application.ErrConflict
	}
	next := write.Plan.Next()
	tenantID, viewID := savedViewUUID(next.Tenant()), savedViewUUID(next.ID())
	if !authorizationUUIDv7(tenantID) || !authorizationUUIDv7(viewID) ||
		!authorizationUUIDv7(write.OwnerMembershipID) ||
		savedViewUUID(next.Owner()) != write.OwnerMembershipID ||
		!validSavedViewRepositoryKind(next.Kind()) || !validSavedViewCommitActor(write.Actor, tenantID) ||
		write.Audit != write.Actor.Audit || !validSavedViewCommitPlan(write.Plan) ||
		!application.SavedViewCommandMatchesPlan(write.Command, write.OwnerMembershipID, write.Plan) {
		return savedViewCommitRequestV1{}, kernel.SavedView{}, application.ErrForbidden
	}
	canonical, err := application.CanonicalSavedViewSpec(next.Tenant(), next.Kind(), next.Spec())
	if err != nil {
		return savedViewCommitRequestV1{}, kernel.SavedView{}, application.ErrConflict
	}
	digest := sha256.Sum256(canonical)
	identifiers, err := phase4NewIDs(repository.newID, 3)
	if err != nil {
		return savedViewCommitRequestV1{}, kernel.SavedView{}, application.ErrUnavailable
	}
	return savedViewCommitRequestV1{
		SchemaVersion: 1, TenantID: tenantID.String(), ActorID: write.Actor.UserID.String(),
		OwnerMembershipID: write.OwnerMembershipID.String(), AggregateKind: next.Kind().String(),
		RequiredCapability: string(write.RequiredCapability), Action: write.Command.Action.String(),
		ViewID: viewID.String(), ExpectedRevision: write.Plan.ExpectedRevision(),
		NextRevision: next.Revision(), Name: next.Name(), Status: next.Status().String(),
		SpecCanonicalBase64:      base64.RawStdEncoding.EncodeToString(canonical),
		SpecSHA256:               encodeSavedViewDigest(digest),
		IdempotencyKeySHA256:     encodeSavedViewDigest(write.Command.KeyHash),
		RequestFingerprintSHA256: encodeSavedViewDigest(write.Command.Fingerprint),
		CommandID:                identifiers[0].String(), AuditEventID: identifiers[1].String(),
		OutboxEventID: identifiers[2].String(),
		Audit: savedViewCommitAuditV1{
			RequestID: write.Audit.RequestID.String(), CorrelationID: write.Audit.CorrelationID.String(),
			RemoteAddress: write.Audit.RemoteAddress.String(), UserAgent: write.Audit.UserAgent,
			AuthenticationMethod: write.Actor.AuthenticationMethod,
		},
	}, next, nil
}

func validSavedViewCommitActor(actor application.Actor, tenantID uuid.UUID) bool {
	if !validAuthorizationRepositoryActor(savedViewAuthorizationActor(actor), tenantID) ||
		actor.Audit.RequestID == uuid.Nil || actor.Audit.RequestID.Variant() != uuid.RFC4122 ||
		actor.Audit.CorrelationID == uuid.Nil || actor.Audit.CorrelationID.Variant() != uuid.RFC4122 ||
		!actor.Audit.RemoteAddress.IsValid() || actor.Audit.RemoteAddress.Zone() != "" ||
		!validSavedViewWireText(actor.Audit.UserAgent, 512, false) {
		return false
	}
	return true
}

func validSavedViewCommitPlan(plan kernel.SavedViewPlan) bool {
	next := plan.Next()
	if !validSavedViewRevision(next.Revision()) || !validSavedViewWireText(next.Name(), 120, true) {
		return false
	}
	expected := plan.ExpectedRevision()
	switch plan.Action() {
	case kernel.SavedViewCreate:
		return expected == 0 && next.Revision() == 1 && next.Status() == kernel.SavedViewActive
	case kernel.SavedViewReplace:
		return expected > 0 && expected < maximumSavedViewRevision &&
			next.Revision() == expected+1 && next.Status() == kernel.SavedViewActive
	case kernel.SavedViewArchive:
		return expected > 0 && expected < maximumSavedViewRevision &&
			next.Revision() == expected+1 && next.Status() == kernel.SavedViewArchived
	case kernel.SavedViewRestore:
		return expected > 0 && expected < maximumSavedViewRevision &&
			next.Revision() == expected+1 && next.Status() == kernel.SavedViewActive
	default:
		return false
	}
}

func restoreSavedViewResolvedSpec(
	response []byte,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	input application.SavedViewSpecInput,
) (kernel.SavedViewSpec, error) {
	var wire savedViewResolvedSpecResponseV1
	if err := decodeExactSavedViewObject(
		response, maximumSavedViewSpecResponseBytes, &wire,
		"schemaVersion", "specCanonicalBase64", "specSha256",
	); err != nil || wire.SchemaVersion != 1 {
		return kernel.SavedViewSpec{}, application.ErrUnavailable
	}
	canonical, err := decodeSavedViewCanonical(wire.SpecCanonicalBase64)
	if err != nil {
		return kernel.SavedViewSpec{}, err
	}
	wireDigest, err := decodeSavedViewDigest(wire.SpecSHA256)
	if err != nil || sha256.Sum256(canonical) != wireDigest {
		return kernel.SavedViewSpec{}, application.ErrUnavailable
	}
	spec, digest, err := application.RestoreSavedViewSpec(tenantID, kind, canonical)
	if err != nil || digest != wireDigest || !savedViewResolvedSpecMatchesInput(spec, input) {
		return kernel.SavedViewSpec{}, application.ErrUnavailable
	}
	return spec, nil
}

func restoreSavedViewPage(
	response []byte,
	tenantID uuid.UUID,
	ownerMembershipID uuid.UUID,
	kind kernel.AggregateKind,
	after uuid.UUID,
	limit int,
	includeArchived bool,
) (application.SavedViewPage, error) {
	var wire savedViewListResponseV1
	if err := decodeExactSavedViewObject(
		response, maximumSavedViewListResponseBytes, &wire,
		"schemaVersion", "records", "hasMore",
	); err != nil || wire.SchemaVersion != 1 || wire.Records == nil || wire.HasMore == nil ||
		len(wire.Records) > limit || *wire.HasMore && len(wire.Records) == 0 {
		return application.SavedViewPage{}, application.ErrUnavailable
	}
	page := application.SavedViewPage{Items: make([]application.SavedViewRecord, len(wire.Records))}
	previous := after
	for index, raw := range wire.Records {
		record, err := restoreSavedViewRecordWire(raw, tenantID, ownerMembershipID, kind)
		if err != nil || !includeArchived && record.View.Status() == kernel.SavedViewArchived {
			return application.SavedViewPage{}, application.ErrUnavailable
		}
		current := savedViewUUID(record.View.ID())
		if previous != uuid.Nil && bytes.Compare(previous[:], current[:]) >= 0 {
			return application.SavedViewPage{}, application.ErrUnavailable
		}
		page.Items[index] = record
		previous = current
	}
	if *wire.HasMore {
		page.NextCursor = encodeSavedViewCursor(previous)
	}
	return page, nil
}

func restoreSavedViewGetResponse(
	response []byte,
	tenantID uuid.UUID,
	ownerMembershipID uuid.UUID,
	kind kernel.AggregateKind,
) (application.SavedViewRecord, error) {
	var wire savedViewGetResponseV1
	if err := decodeExactSavedViewObject(
		response, maximumSavedViewRecordResponseBytes, &wire, "schemaVersion", "record",
	); err != nil || wire.SchemaVersion != 1 || len(wire.Record) == 0 {
		return application.SavedViewRecord{}, application.ErrUnavailable
	}
	stored, err := decodeSavedViewRecordWire(wire.Record)
	if err != nil {
		return application.SavedViewRecord{}, err
	}
	identityMatches, err := savedViewRecordWireIdentityMatches(stored, tenantID, ownerMembershipID, kind)
	if err != nil {
		return application.SavedViewRecord{}, err
	}
	if !identityMatches {
		return application.SavedViewRecord{}, application.ErrNotFound
	}
	return restoreSavedViewRecordProjection(stored, tenantID, ownerMembershipID, kind)
}

func restoreSavedViewReplayResponse(
	response []byte,
	tenantID uuid.UUID,
	actorID uuid.UUID,
	ownerMembershipID uuid.UUID,
	kind kernel.AggregateKind,
	action kernel.SavedViewAction,
) (application.SavedViewMutationResult, [sha256.Size]byte, error) {
	var wire savedViewReplayResponseV1
	if err := decodeExactSavedViewObject(
		response, maximumSavedViewRecordResponseBytes, &wire,
		"schemaVersion", "actorId", "ownerMembershipId", "action",
		"requestFingerprintSha256", "record",
	); err != nil || wire.SchemaVersion != 1 || wire.Action != action.String() || len(wire.Record) == 0 {
		return application.SavedViewMutationResult{}, [sha256.Size]byte{}, application.ErrUnavailable
	}
	returnedActorID, err := parseSavedViewWireUUID(wire.ActorID)
	if err != nil || returnedActorID != actorID {
		return application.SavedViewMutationResult{}, [sha256.Size]byte{}, application.ErrUnavailable
	}
	returnedOwnerID, err := parseSavedViewWireUUID(wire.OwnerMembershipID)
	if err != nil || returnedOwnerID != ownerMembershipID {
		return application.SavedViewMutationResult{}, [sha256.Size]byte{}, application.ErrUnavailable
	}
	fingerprint, err := decodeSavedViewDigest(wire.RequestFingerprintSHA256)
	if err != nil {
		return application.SavedViewMutationResult{}, [sha256.Size]byte{}, err
	}
	record, err := restoreSavedViewRecordWire(wire.Record, tenantID, ownerMembershipID, kind)
	if err != nil {
		return application.SavedViewMutationResult{}, [sha256.Size]byte{}, err
	}
	return application.SavedViewMutationResult{Record: record, Replayed: true}, fingerprint, nil
}

func restoreSavedViewCommitResponse(
	response []byte,
	tenantID uuid.UUID,
	actorID uuid.UUID,
	ownerMembershipID uuid.UUID,
	action kernel.SavedViewAction,
	expectedFingerprint [sha256.Size]byte,
	next kernel.SavedView,
) (application.SavedViewMutationResult, error) {
	var wire savedViewCommitResponseV1
	if err := decodeExactSavedViewObject(
		response, maximumSavedViewRecordResponseBytes, &wire,
		"schemaVersion", "actorId", "ownerMembershipId", "action",
		"requestFingerprintSha256", "replayed", "record",
	); err != nil || wire.SchemaVersion != 1 || wire.Action != action.String() ||
		wire.Replayed == nil || len(wire.Record) == 0 {
		return application.SavedViewMutationResult{}, application.ErrUnavailable
	}
	returnedActorID, err := parseSavedViewWireUUID(wire.ActorID)
	if err != nil || returnedActorID != actorID {
		return application.SavedViewMutationResult{}, application.ErrUnavailable
	}
	returnedOwnerID, err := parseSavedViewWireUUID(wire.OwnerMembershipID)
	if err != nil || returnedOwnerID != ownerMembershipID {
		return application.SavedViewMutationResult{}, application.ErrUnavailable
	}
	returnedFingerprint, err := decodeSavedViewDigest(wire.RequestFingerprintSHA256)
	if err != nil {
		return application.SavedViewMutationResult{}, err
	}
	if subtle.ConstantTimeCompare(returnedFingerprint[:], expectedFingerprint[:]) != 1 {
		return application.SavedViewMutationResult{}, application.ErrConflict
	}
	record, err := restoreSavedViewRecordWire(wire.Record, tenantID, ownerMembershipID, next.Kind())
	if err != nil || !savedViewCommitProjectionMatches(record, next, action, *wire.Replayed) {
		return application.SavedViewMutationResult{}, application.ErrUnavailable
	}
	return application.SavedViewMutationResult{Record: record, Replayed: *wire.Replayed}, nil
}

func restoreSavedViewRecordWire(
	raw []byte,
	expectedTenantID uuid.UUID,
	expectedOwnerMembershipID uuid.UUID,
	expectedKind kernel.AggregateKind,
) (application.SavedViewRecord, error) {
	wire, err := decodeSavedViewRecordWire(raw)
	if err != nil {
		return application.SavedViewRecord{}, err
	}
	return restoreSavedViewRecordProjection(
		wire, expectedTenantID, expectedOwnerMembershipID, expectedKind,
	)
}

func decodeSavedViewRecordWire(raw []byte) (savedViewRecordWireV1, error) {
	var wire savedViewRecordWireV1
	if err := decodeExactSavedViewObject(
		raw, maximumSavedViewRecordResponseBytes, &wire,
		"id", "tenantId", "ownerMembershipId", "aggregateKind", "name",
		"specCanonicalBase64", "specSha256", "status", "revision",
		"createdAt", "updatedAt", "archivedAt",
	); err != nil {
		return savedViewRecordWireV1{}, application.ErrUnavailable
	}
	return wire, nil
}

func restoreSavedViewRecordProjection(
	wire savedViewRecordWireV1,
	expectedTenantID uuid.UUID,
	expectedOwnerMembershipID uuid.UUID,
	expectedKind kernel.AggregateKind,
) (application.SavedViewRecord, error) {
	id, err := parseSavedViewWireUUID(wire.ID)
	if err != nil {
		return application.SavedViewRecord{}, err
	}
	tenantID, err := parseSavedViewWireUUID(wire.TenantID)
	if err != nil {
		return application.SavedViewRecord{}, err
	}
	ownerMembershipID, err := parseSavedViewWireUUID(wire.OwnerMembershipID)
	if err != nil {
		return application.SavedViewRecord{}, err
	}
	canonical, err := decodeSavedViewCanonical(wire.SpecCanonicalBase64)
	if err != nil {
		return application.SavedViewRecord{}, err
	}
	digest, err := decodeSavedViewDigest(wire.SpecSHA256)
	if err != nil || sha256.Sum256(canonical) != digest {
		return application.SavedViewRecord{}, application.ErrUnavailable
	}
	archivedAt, err := decodeSavedViewArchivedAt(wire.ArchivedAt)
	if err != nil {
		return application.SavedViewRecord{}, err
	}
	createdAt, err := normalizeSavedViewWireTime(wire.CreatedAt)
	if err != nil {
		return application.SavedViewRecord{}, err
	}
	updatedAt, err := normalizeSavedViewWireTime(wire.UpdatedAt)
	if err != nil {
		return application.SavedViewRecord{}, err
	}
	return application.RestoreSavedViewRecord(
		expectedTenantID, expectedOwnerMembershipID, expectedKind,
		application.SavedViewPersistenceRecord{
			ID: id, TenantID: tenantID, OwnerMembershipID: ownerMembershipID,
			Kind: wire.AggregateKind, Name: wire.Name, SpecCanonical: canonical,
			SpecDigest: digest[:], Status: wire.Status, Revision: wire.Revision,
			CreatedAt: createdAt, UpdatedAt: updatedAt, ArchivedAt: archivedAt,
		},
	)
}

func savedViewRecordWireIdentityMatches(
	wire savedViewRecordWireV1,
	expectedTenantID uuid.UUID,
	expectedOwnerMembershipID uuid.UUID,
	expectedKind kernel.AggregateKind,
) (bool, error) {
	tenantID, err := parseSavedViewWireUUID(wire.TenantID)
	if err != nil {
		return false, err
	}
	ownerMembershipID, err := parseSavedViewWireUUID(wire.OwnerMembershipID)
	if err != nil {
		return false, err
	}
	if wire.AggregateKind != kernel.AggregateAlert.String() &&
		wire.AggregateKind != kernel.AggregateCase.String() {
		return false, application.ErrUnavailable
	}
	return tenantID == expectedTenantID && ownerMembershipID == expectedOwnerMembershipID &&
		wire.AggregateKind == expectedKind.String(), nil
}

func savedViewResolvedSpecMatchesInput(
	spec kernel.SavedViewSpec,
	input application.SavedViewSpecInput,
) bool {
	filters := spec.Filters()
	if !sameSavedViewKeys(filters.States(), input.Filters.States) ||
		!sameSavedViewStringSet(filters.Severities(), input.Filters.Severities) ||
		!sameSavedViewStringSet(filters.Priorities(), input.Filters.Priorities) ||
		!sameSavedViewEntity(filters.AssignedTeam(), input.Filters.AssignedTeamID) ||
		!sameSavedViewEntity(filters.Assignee(), input.Filters.AssigneeUserID) ||
		!sameSavedViewEntity(filters.ClaimedBy(), input.Filters.ClaimedBy) ||
		filters.Queue().String() != input.Filters.Queue ||
		!sameSavedViewBool(filters.CustomerVisible(), input.Filters.CustomerVisible) ||
		filters.Search() != input.Filters.Search ||
		!savedViewCustomFiltersMatchInput(filters.Custom(), input.Filters.Custom) {
		return false
	}
	if !savedViewSortMatchesInput(spec.Sort(), input.Sort) {
		return false
	}
	columns := spec.Columns()
	if len(columns) != len(input.Columns) {
		return false
	}
	for index := range columns {
		if !savedViewColumnMatchesInput(columns[index], input.Columns[index]) {
			return false
		}
	}
	return true
}

func savedViewCustomFiltersMatchInput(
	resolved []kernel.SavedViewCustomFilter,
	input []application.SavedViewCustomFilterInput,
) bool {
	if len(resolved) != len(input) {
		return false
	}
	requested := make(map[uuid.UUID]application.SavedViewCustomFilterInput, len(input))
	for _, filter := range input {
		requested[filter.DefinitionID] = filter
	}
	for _, filter := range resolved {
		pin := filter.Definition()
		candidate, found := requested[savedViewUUID(pin.ID())]
		if !found || pin.Version() != candidate.ExpectedDefinitionVersion ||
			!equivalentSavedViewScalarJSON(filter.CanonicalJSON(), candidate.Value, filter.DataType()) {
			return false
		}
	}
	return true
}

func savedViewSortMatchesInput(
	resolved kernel.SavedViewSort,
	input application.SavedViewSortInput,
) bool {
	if resolved.Source().String() != string(input.Source) ||
		resolved.Direction().String() != input.Direction || resolved.Nulls().String() != input.Nulls {
		return false
	}
	if key, core := resolved.CoreKey(); core {
		return input.Source == application.SavedViewDefinitionCore && input.DefinitionID == nil &&
			input.ExpectedDefinitionVersion == 0 && key.String() == input.CoreKey
	}
	pin, dynamic := resolved.Definition()
	return dynamic && input.Source != application.SavedViewDefinitionCore && input.DefinitionID != nil &&
		savedViewUUID(pin.ID()) == *input.DefinitionID && pin.Version() == input.ExpectedDefinitionVersion
}

func savedViewColumnMatchesInput(
	resolved kernel.SavedViewColumn,
	input application.SavedViewColumnInput,
) bool {
	if resolved.Source().String() != string(input.Source) || resolved.Width() != input.Width ||
		resolved.Visible() != input.Visible || resolved.Pin().String() != input.Pin {
		return false
	}
	if key, core := resolved.CoreKey(); core {
		return input.Source == application.SavedViewDefinitionCore && input.DefinitionID == nil &&
			input.ExpectedDefinitionVersion == 0 && key.String() == input.CoreKey
	}
	pin, dynamic := resolved.Definition()
	return dynamic && input.Source != application.SavedViewDefinitionCore && input.DefinitionID != nil &&
		savedViewUUID(pin.ID()) == *input.DefinitionID && pin.Version() == input.ExpectedDefinitionVersion
}

func savedViewCommitProjectionMatches(
	record application.SavedViewRecord,
	next kernel.SavedView,
	action kernel.SavedViewAction,
	replayed bool,
) bool {
	view := record.View
	if (!replayed || action != kernel.SavedViewCreate) && view.ID() != next.ID() ||
		view.Tenant() != next.Tenant() || view.Owner() != next.Owner() || view.Kind() != next.Kind() ||
		view.Name() != next.Name() || view.Status() != next.Status() || view.Revision() != next.Revision() {
		return false
	}
	digest, err := application.SavedViewSpecDigest(next.Tenant(), next.Kind(), next.Spec())
	return err == nil && record.SpecDigest == digest
}

func decodeExactSavedViewObject(
	raw []byte,
	maximum int,
	destination any,
	requiredFields ...string,
) error {
	if len(raw) == 0 || len(raw) > maximum || destination == nil ||
		validateSavedViewJSONTokens(raw) != nil {
		return application.ErrUnavailable
	}
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&fields); err != nil || decoder.Decode(&struct{}{}) != io.EOF || fields == nil ||
		len(fields) != len(requiredFields) {
		return application.ErrUnavailable
	}
	for _, field := range requiredFields {
		if _, exists := fields[field]; !exists {
			return application.ErrUnavailable
		}
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return application.ErrUnavailable
	}
	return nil
}

func validateSavedViewJSONTokens(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	tokens := 0
	nextToken := func() (json.Token, error) {
		if tokens >= maximumSavedViewWireTokens {
			return nil, application.ErrUnavailable
		}
		token, err := decoder.Token()
		if err != nil {
			return nil, application.ErrUnavailable
		}
		tokens++
		return token, nil
	}
	var visit func(int) error
	visit = func(depth int) error {
		if depth > maximumSavedViewWireDepth {
			return application.ErrUnavailable
		}
		token, err := nextToken()
		if err != nil {
			return err
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := nextToken()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return application.ErrUnavailable
				}
				if _, duplicate := seen[key]; duplicate {
					return application.ErrUnavailable
				}
				seen[key] = struct{}{}
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		default:
			return application.ErrUnavailable
		}
		if _, err := nextToken(); err != nil {
			return err
		}
		return nil
	}
	if err := visit(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return application.ErrUnavailable
	}
	return nil
}

func marshalSavedViewWire(value any, maximum int) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || len(encoded) > maximum {
		return nil, application.ErrInvalidInput
	}
	return encoded, nil
}

func decodeSavedViewCanonical(encoded string) ([]byte, error) {
	if encoded == "" || len(encoded) > base64.RawStdEncoding.EncodedLen(256*1024) {
		return nil, application.ErrUnavailable
	}
	decoded, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) == 0 || len(decoded) > 256*1024 ||
		base64.RawStdEncoding.EncodeToString(decoded) != encoded {
		return nil, application.ErrUnavailable
	}
	return decoded, nil
}

func encodeSavedViewDigest(digest [sha256.Size]byte) string {
	return hex.EncodeToString(digest[:])
}

func decodeSavedViewDigest(encoded string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	if len(encoded) != hex.EncodedLen(sha256.Size) || strings.ToLower(encoded) != encoded {
		return result, application.ErrUnavailable
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != encoded {
		return result, application.ErrUnavailable
	}
	copy(result[:], decoded)
	return result, nil
}

func parseSavedViewWireUUID(encoded string) (uuid.UUID, error) {
	identifier, err := uuid.Parse(encoded)
	if err != nil || !authorizationUUIDv7(identifier) || identifier.String() != encoded {
		return uuid.Nil, application.ErrUnavailable
	}
	return identifier, nil
}

func decodeSavedViewArchivedAt(raw json.RawMessage) (*time.Time, error) {
	if len(raw) == 0 {
		return nil, application.ErrUnavailable
	}
	if bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	var value time.Time
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, application.ErrUnavailable
	}
	normalized, err := normalizeSavedViewWireTime(value)
	if err != nil {
		return nil, err
	}
	return &normalized, nil
}

func normalizeSavedViewWireTime(value time.Time) (time.Time, error) {
	_, offset := value.Zone()
	if value.IsZero() || offset != 0 {
		return time.Time{}, application.ErrUnavailable
	}
	return value.UTC(), nil
}

func equivalentSavedViewScalarJSON(
	left json.RawMessage,
	right json.RawMessage,
	dataType customkernel.DataType,
) bool {
	leftValue, leftOK := decodeSavedViewScalar(left)
	rightValue, rightOK := decodeSavedViewScalar(right)
	if !leftOK || !rightOK {
		return false
	}
	if dataType == customkernel.TypeInteger || dataType == customkernel.TypeDecimal ||
		dataType == customkernel.TypeDuration {
		leftNumber, leftIsNumber := savedViewNumericScalarText(leftValue)
		rightNumber, rightIsNumber := savedViewNumericScalarText(rightValue)
		if !leftIsNumber || !rightIsNumber {
			return false
		}
		leftSign, leftDigits, leftScale, leftValid := normalizeSavedViewJSONNumber(leftNumber)
		rightSign, rightDigits, rightScale, rightValid := normalizeSavedViewJSONNumber(rightNumber)
		return leftValid && rightValid && leftSign == rightSign &&
			leftDigits == rightDigits && leftScale == rightScale
	}
	return leftValue == rightValue
}

func savedViewNumericScalarText(value any) (string, bool) {
	switch typed := value.(type) {
	case json.Number:
		return typed.String(), true
	case string:
		return typed, true
	default:
		return "", false
	}
}

func normalizeSavedViewJSONNumber(value string) (int, string, int64, bool) {
	if len(value) == 0 || len(value) > 1_024 {
		return 0, "", 0, false
	}
	sign := 1
	if value[0] == '-' {
		sign, value = -1, value[1:]
	}
	mantissa, exponentText := value, ""
	if index := strings.IndexAny(value, "eE"); index >= 0 {
		mantissa, exponentText = value[:index], value[index+1:]
	}
	if mantissa == "" || len(exponentText) > 7 {
		return 0, "", 0, false
	}
	exponent := int64(0)
	if exponentText != "" {
		parsed, err := strconv.ParseInt(exponentText, 10, 32)
		if err != nil || parsed < -1_000_000 || parsed > 1_000_000 {
			return 0, "", 0, false
		}
		exponent = parsed
	}
	fractionDigits := 0
	if point := strings.IndexByte(mantissa, '.'); point >= 0 {
		fractionDigits = len(mantissa) - point - 1
		mantissa = mantissa[:point] + mantissa[point+1:]
	}
	digits := strings.TrimLeft(mantissa, "0")
	if digits == "" {
		return 0, "0", 0, true
	}
	scale := exponent - int64(fractionDigits)
	for strings.HasSuffix(digits, "0") {
		digits = digits[:len(digits)-1]
		scale++
	}
	return sign, digits, scale, true
}

func decodeSavedViewScalar(raw json.RawMessage) (any, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return nil, false
	}
	switch value.(type) {
	case nil, bool, string, json.Number:
		return value, true
	default:
		return nil, false
	}
}

func sameSavedViewKeys(resolved []kernel.Key, requested []string) bool {
	if len(resolved) != len(requested) {
		return false
	}
	values := make([]string, len(resolved))
	for index, key := range resolved {
		values[index] = key.String()
	}
	return sameSavedViewStringSet(values, requested)
}

func sameSavedViewStringSet(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	leftCopy, rightCopy := slices.Clone(left), slices.Clone(right)
	slices.Sort(leftCopy)
	slices.Sort(rightCopy)
	return slices.Equal(leftCopy, rightCopy)
}

func sameSavedViewEntity(left *kernel.EntityID, right *uuid.UUID) bool {
	return left == nil && right == nil || left != nil && right != nil && savedViewUUID(*left) == *right
}

func sameSavedViewBool(left *bool, right *bool) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func savedViewOptionalUUIDPointer(value *uuid.UUID) string {
	if value == nil {
		return ""
	}
	return value.String()
}

func cloneSavedViewWireBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func savedViewWireStringSlice(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return slices.Clone(values)
}

func validSavedViewWireText(value string, maximum int, required bool) bool {
	if !utf8.ValidString(value) || len(value) > maximum || strings.TrimSpace(value) != value ||
		required && value == "" {
		return false
	}
	for _, character := range value {
		if character != '\n' && character != '\t' && unicode.IsControl(character) {
			return false
		}
	}
	return true
}
