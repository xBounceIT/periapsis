package postgres

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

const (
	ticketOperationsWireVersion       = 1
	maximumTicketOperationsRequest    = 2 * 1024 * 1024
	maximumTicketOperationsResponse   = 32 * 1024 * 1024
	maximumTicketOperationsWireTokens = 2_000_000
)

type ticketOperationsActorWireV1 struct {
	UserID               string `json:"userId"`
	SessionID            string `json:"sessionId"`
	ActiveTenantID       string `json:"activeTenantId"`
	AuthenticationMethod string `json:"authenticationMethod"`
}

type ticketOperationsAuditWireV1 struct {
	RequestID     string `json:"requestId"`
	CorrelationID string `json:"correlationId"`
	RemoteAddress string `json:"remoteAddress"`
	UserAgent     string `json:"userAgent"`
}

type ticketOperationsSavedViewWireV1 struct {
	ID         string `json:"id"`
	OwnerID    string `json:"ownerId"`
	Revision   uint64 `json:"revision"`
	SpecSHA256 string `json:"specSha256"`
}

type ticketOperationsQueryWireV1 struct {
	Source              string                           `json:"source"`
	SpecCanonicalBase64 string                           `json:"specCanonicalBase64"`
	QuerySHA256         string                           `json:"querySha256"`
	CatalogSHA256       string                           `json:"catalogSha256"`
	SavedView           *ticketOperationsSavedViewWireV1 `json:"savedView"`
}

type ticketOperationsTargetWireV1 struct {
	ID      string `json:"id"`
	Version uint64 `json:"version"`
}

type ticketOperationsBulkSelectionWireV1 struct {
	Source          string                           `json:"source"`
	ExplicitTargets []ticketOperationsTargetWireV1   `json:"explicitTargets"`
	QuerySHA256     string                           `json:"querySha256"`
	TargetSetSHA256 string                           `json:"targetSetSha256"`
	TargetCount     uint32                           `json:"targetCount"`
	SavedView       *ticketOperationsSavedViewWireV1 `json:"savedView"`
}

type ticketOperationsBulkMutationWireV1 struct {
	Action     string `json:"action"`
	Transition string `json:"transition"`
	To         string `json:"to"`
	TeamID     string `json:"teamId"`
	AssigneeID string `json:"assigneeId"`
}

type ticketOperationsBulkDefinitionWireV1 struct {
	ID                string                              `json:"id"`
	TenantID          string                              `json:"tenantId"`
	RequesterID       string                              `json:"requesterId"`
	OwnerMembershipID string                              `json:"ownerMembershipId"`
	Kind              string                              `json:"kind"`
	Selection         ticketOperationsBulkSelectionWireV1 `json:"selection"`
	Mutation          ticketOperationsBulkMutationWireV1  `json:"mutation"`
	ProjectionVersion uint64                              `json:"projectionVersion"`
	MaximumAttempts   uint8                               `json:"maximumAttempts"`
}

type ticketOperationsBulkProgressWireV1 struct {
	Total                uint32 `json:"total"`
	Succeeded            uint32 `json:"succeeded"`
	NoChange             uint32 `json:"noChange"`
	VersionConflict      uint32 `json:"versionConflict"`
	NotFoundOrHidden     uint32 `json:"notFoundOrHidden"`
	AuthorizationDenied  uint32 `json:"authorizationDenied"`
	Rejected             uint32 `json:"rejected"`
	Cancelled            uint32 `json:"cancelled"`
	AuthorizationRevoked uint32 `json:"authorizationRevoked"`
	InternalFailure      uint32 `json:"internalFailure"`
}

type ticketOperationsBulkJobWireV1 struct {
	Definition  ticketOperationsBulkDefinitionWireV1 `json:"definition"`
	State       string                               `json:"state"`
	Revision    uint64                               `json:"revision"`
	Progress    ticketOperationsBulkProgressWireV1   `json:"progress"`
	RequestedAt time.Time                            `json:"requestedAt"`
	UpdatedAt   time.Time                            `json:"updatedAt"`
	AvailableAt time.Time                            `json:"availableAt"`
	ExpiresAt   time.Time                            `json:"expiresAt"`
	ActiveBatch *bool                                `json:"activeBatch"`
	TerminalAt  *time.Time                           `json:"terminalAt"`
}

type ticketOperationsBulkRecordWireV1 struct {
	Job   ticketOperationsBulkJobWireV1 `json:"job"`
	Query *ticketOperationsQueryWireV1  `json:"query"`
}

type ticketOperationsExportDefinitionWireV1 struct {
	ID                string                           `json:"id"`
	TenantID          string                           `json:"tenantId"`
	RequesterID       string                           `json:"requesterId"`
	OwnerMembershipID string                           `json:"ownerMembershipId"`
	CustomerContactID string                           `json:"customerContactId"`
	Kind              string                           `json:"kind"`
	Audience          string                           `json:"audience"`
	CommentScope      string                           `json:"commentScope"`
	QuerySource       string                           `json:"querySource"`
	SavedView         *ticketOperationsSavedViewWireV1 `json:"savedView"`
	QuerySHA256       string                           `json:"querySha256"`
	CatalogSHA256     string                           `json:"catalogSha256"`
	ProjectionVersion uint64                           `json:"projectionVersion"`
	Format            string                           `json:"format"`
	MaximumRows       uint32                           `json:"maximumRows"`
	MaximumBytes      uint64                           `json:"maximumBytes"`
	MaximumAttempts   uint8                            `json:"maximumAttempts"`
}

type ticketOperationsExportLeaseWireV1 struct {
	WorkerID  string    `json:"workerId"`
	Fence     string    `json:"fenceSha256"`
	ClaimedAt time.Time `json:"claimedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type ticketOperationsExportArtifactWireV1 struct {
	ID        string    `json:"id"`
	SHA256    string    `json:"sha256"`
	Rows      uint32    `json:"rows"`
	Bytes     uint64    `json:"bytes"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type ticketOperationsExportJobWireV1 struct {
	Definition  ticketOperationsExportDefinitionWireV1 `json:"definition"`
	State       string                                 `json:"state"`
	Revision    uint64                                 `json:"revision"`
	Attempts    uint8                                  `json:"attempts"`
	FailureCode string                                 `json:"failureCode"`
	RequestedAt time.Time                              `json:"requestedAt"`
	UpdatedAt   time.Time                              `json:"updatedAt"`
	AvailableAt time.Time                              `json:"availableAt"`
	ExpiresAt   time.Time                              `json:"expiresAt"`
	Lease       *ticketOperationsExportLeaseWireV1     `json:"lease"`
	Artifact    *ticketOperationsExportArtifactWireV1  `json:"artifact"`
	TerminalAt  *time.Time                             `json:"terminalAt"`
}

type ticketOperationsExportRecordWireV1 struct {
	Job   ticketOperationsExportJobWireV1 `json:"job"`
	Query ticketOperationsQueryWireV1     `json:"query"`
}

func ticketOperationsActorWire(actor application.Actor) ticketOperationsActorWireV1 {
	return ticketOperationsActorWireV1{
		UserID: actor.UserID.String(), SessionID: actor.SessionID.String(),
		ActiveTenantID: actor.ActiveTenantID.String(), AuthenticationMethod: actor.AuthenticationMethod,
	}
}

func ticketOperationsAuditWire(audit application.AuditContext) ticketOperationsAuditWireV1 {
	return ticketOperationsAuditWireV1{
		RequestID: audit.RequestID.String(), CorrelationID: audit.CorrelationID.String(),
		RemoteAddress: audit.RemoteAddress.String(), UserAgent: audit.UserAgent,
	}
}

func marshalTicketOperations(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) == 0 || len(encoded) > maximumTicketOperationsRequest {
		return nil, application.ErrUnavailable
	}
	return encoded, nil
}

func decodeTicketOperations(document []byte, destination any) error {
	if len(document) == 0 || len(document) > maximumTicketOperationsResponse || destination == nil ||
		decoderTokenCount(document) > maximumTicketOperationsWireTokens {
		return application.ErrUnavailable
	}
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(document), maximumTicketOperationsResponse+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return application.ErrUnavailable
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return application.ErrUnavailable
	}
	return nil
}

func decoderTokenCount(document []byte) int {
	decoder := json.NewDecoder(bytes.NewReader(document))
	count := 0
	for {
		if _, err := decoder.Token(); err != nil {
			break
		}
		count++
		if count > maximumTicketOperationsWireTokens {
			break
		}
	}
	return count
}

func ticketOperationsEntity(value string) (kernel.EntityID, error) {
	id, err := uuid.Parse(value)
	if err != nil || id.Version() != 7 || id.String() != value {
		return kernel.EntityID{}, application.ErrUnavailable
	}
	var bytes [16]byte
	copy(bytes[:], id[:])
	result, err := kernel.NewEntityID(bytes)
	if err != nil {
		return kernel.EntityID{}, application.ErrUnavailable
	}
	return result, nil
}

func ticketOperationsInstant(value time.Time) (time.Time, error) {
	_, offset := value.Zone()
	if value.IsZero() || offset != 0 || value.Year() < 1970 || value.Year() > 9999 ||
		value.Nanosecond()%int(time.Microsecond) != 0 {
		return time.Time{}, application.ErrUnavailable
	}
	return value.UTC(), nil
}

func ticketOperationsOptionalInstant(value *time.Time) (*time.Time, error) {
	if value == nil {
		return nil, nil
	}
	normalized, err := ticketOperationsInstant(*value)
	if err != nil {
		return nil, err
	}
	return &normalized, nil
}

func ticketOperationsDigest(value string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || strings.ToLower(value) != value {
		return result, application.ErrUnavailable
	}
	copy(result[:], decoded)
	if result == ([sha256.Size]byte{}) {
		return [sha256.Size]byte{}, application.ErrUnavailable
	}
	return result, nil
}

func ticketOperationsKind(value string) (kernel.AggregateKind, error) {
	switch value {
	case kernel.AggregateAlert.String():
		return kernel.AggregateAlert, nil
	case kernel.AggregateCase.String():
		return kernel.AggregateCase, nil
	default:
		return 0, application.ErrUnavailable
	}
}

func ticketOperationsPrincipal(value string) (kernel.PrincipalKind, error) {
	switch value {
	case kernel.PrincipalOperator.String():
		return kernel.PrincipalOperator, nil
	case kernel.PrincipalCustomer.String():
		return kernel.PrincipalCustomer, nil
	case kernel.PrincipalServiceAccount.String():
		return kernel.PrincipalServiceAccount, nil
	default:
		return 0, application.ErrUnavailable
	}
}

func ticketOperationsAction(value string) (kernel.Action, error) {
	for _, action := range []kernel.Action{
		kernel.ActionTransition, kernel.ActionAssign, kernel.ActionTransfer,
		kernel.ActionClaim, kernel.ActionRelease,
	} {
		if action.String() == value {
			return action, nil
		}
	}
	return 0, application.ErrUnavailable
}

func ticketOperationsSavedView(
	wire *ticketOperationsSavedViewWireV1,
	export bool,
) (*kernel.TicketBulkSavedViewPin, *kernel.TicketExportSavedViewPin, error) {
	if wire == nil {
		return nil, nil, nil
	}
	id, err := ticketOperationsEntity(wire.ID)
	if err != nil {
		return nil, nil, err
	}
	owner, err := ticketOperationsEntity(wire.OwnerID)
	if err != nil {
		return nil, nil, err
	}
	digest, err := ticketOperationsDigest(wire.SpecSHA256)
	if err != nil {
		return nil, nil, err
	}
	if export {
		pin, pinErr := kernel.NewTicketExportSavedViewPin(id, owner, wire.Revision, digest)
		if pinErr != nil {
			return nil, nil, application.ErrUnavailable
		}
		return nil, &pin, nil
	}
	pin, pinErr := kernel.NewTicketBulkSavedViewPin(id, owner, wire.Revision, digest)
	if pinErr != nil {
		return nil, nil, application.ErrUnavailable
	}
	return &pin, nil, nil
}

func ticketOperationsBulkMutation(
	wire ticketOperationsBulkMutationWireV1,
) (kernel.TicketBulkMutation, error) {
	action, err := ticketOperationsAction(wire.Action)
	if err != nil {
		return kernel.TicketBulkMutation{}, err
	}
	switch action {
	case kernel.ActionTransition:
		transition, transitionErr := kernel.NewKey(wire.Transition)
		to, toErr := kernel.NewKey(wire.To)
		if transitionErr != nil || toErr != nil || wire.TeamID != "" || wire.AssigneeID != "" {
			return kernel.TicketBulkMutation{}, application.ErrUnavailable
		}
		mutation, createErr := kernel.NewTicketBulkTransition(transition, to)
		if createErr != nil {
			return kernel.TicketBulkMutation{}, application.ErrUnavailable
		}
		return mutation, nil
	case kernel.ActionAssign, kernel.ActionTransfer:
		if wire.Transition != "" || wire.To != "" {
			return kernel.TicketBulkMutation{}, application.ErrUnavailable
		}
		team, teamErr := ticketOperationsEntity(wire.TeamID)
		if teamErr != nil {
			return kernel.TicketBulkMutation{}, teamErr
		}
		var assignee *kernel.EntityID
		if wire.AssigneeID != "" {
			parsed, parseErr := ticketOperationsEntity(wire.AssigneeID)
			if parseErr != nil {
				return kernel.TicketBulkMutation{}, parseErr
			}
			assignee = &parsed
		}
		if action == kernel.ActionAssign {
			mutation, createErr := kernel.NewTicketBulkAssignment(team, assignee)
			if createErr != nil {
				return kernel.TicketBulkMutation{}, application.ErrUnavailable
			}
			return mutation, nil
		}
		mutation, createErr := kernel.NewTicketBulkTransfer(team, assignee)
		if createErr != nil {
			return kernel.TicketBulkMutation{}, application.ErrUnavailable
		}
		return mutation, nil
	case kernel.ActionClaim:
		if wire.Transition != "" || wire.To != "" || wire.AssigneeID != "" {
			return kernel.TicketBulkMutation{}, application.ErrUnavailable
		}
		team, teamErr := ticketOperationsEntity(wire.TeamID)
		if teamErr != nil {
			return kernel.TicketBulkMutation{}, teamErr
		}
		mutation, createErr := kernel.NewTicketBulkClaim(team)
		if createErr != nil {
			return kernel.TicketBulkMutation{}, application.ErrUnavailable
		}
		return mutation, nil
	case kernel.ActionRelease:
		if wire.Transition != "" || wire.To != "" || wire.TeamID != "" || wire.AssigneeID != "" {
			return kernel.TicketBulkMutation{}, application.ErrUnavailable
		}
		return kernel.NewTicketBulkRelease(), nil
	default:
		return kernel.TicketBulkMutation{}, application.ErrUnavailable
	}
}

func ticketOperationsBulkSelection(
	wire ticketOperationsBulkSelectionWireV1,
) (kernel.TicketBulkSelection, error) {
	switch wire.Source {
	case kernel.TicketBulkSelectionExplicit.String():
		if wire.QuerySHA256 != "" || wire.SavedView != nil || wire.TargetCount != uint32(len(wire.ExplicitTargets)) {
			return kernel.TicketBulkSelection{}, application.ErrUnavailable
		}
		targets := make([]kernel.TicketBulkTargetPin, len(wire.ExplicitTargets))
		for index, target := range wire.ExplicitTargets {
			id, err := ticketOperationsEntity(target.ID)
			if err != nil {
				return kernel.TicketBulkSelection{}, err
			}
			pin, err := kernel.NewTicketBulkTargetPin(id, target.Version)
			if err != nil {
				return kernel.TicketBulkSelection{}, application.ErrUnavailable
			}
			targets[index] = pin
		}
		selection, err := kernel.NewExplicitTicketBulkSelection(targets)
		if err != nil {
			return kernel.TicketBulkSelection{}, application.ErrUnavailable
		}
		targetDigest, err := ticketOperationsDigest(wire.TargetSetSHA256)
		if err != nil || selection.TargetSetDigest() != targetDigest || selection.TargetCount() != wire.TargetCount {
			return kernel.TicketBulkSelection{}, application.ErrUnavailable
		}
		return selection, nil
	case kernel.TicketBulkSelectionQuery.String():
		if wire.ExplicitTargets != nil {
			return kernel.TicketBulkSelection{}, application.ErrUnavailable
		}
		queryDigest, err := ticketOperationsDigest(wire.QuerySHA256)
		if err != nil {
			return kernel.TicketBulkSelection{}, err
		}
		targetDigest, err := ticketOperationsDigest(wire.TargetSetSHA256)
		if err != nil {
			return kernel.TicketBulkSelection{}, err
		}
		pin, _, err := ticketOperationsSavedView(wire.SavedView, false)
		if err != nil {
			return kernel.TicketBulkSelection{}, err
		}
		selection, err := kernel.NewQueryTicketBulkSelection(queryDigest, targetDigest, wire.TargetCount, pin)
		if err != nil {
			return kernel.TicketBulkSelection{}, application.ErrUnavailable
		}
		return selection, nil
	default:
		return kernel.TicketBulkSelection{}, application.ErrUnavailable
	}
}

func restoreTicketOperationsBulkJob(wire ticketOperationsBulkJobWireV1) (kernel.TicketBulkJob, error) {
	definitionWire := wire.Definition
	id, err := ticketOperationsEntity(definitionWire.ID)
	if err != nil {
		return kernel.TicketBulkJob{}, err
	}
	tenant, err := ticketOperationsEntity(definitionWire.TenantID)
	if err != nil {
		return kernel.TicketBulkJob{}, err
	}
	requester, err := ticketOperationsEntity(definitionWire.RequesterID)
	if err != nil {
		return kernel.TicketBulkJob{}, err
	}
	owner, err := ticketOperationsEntity(definitionWire.OwnerMembershipID)
	if err != nil {
		return kernel.TicketBulkJob{}, err
	}
	kind, err := ticketOperationsKind(definitionWire.Kind)
	if err != nil {
		return kernel.TicketBulkJob{}, err
	}
	selection, err := ticketOperationsBulkSelection(definitionWire.Selection)
	if err != nil {
		return kernel.TicketBulkJob{}, err
	}
	mutation, err := ticketOperationsBulkMutation(definitionWire.Mutation)
	if err != nil {
		return kernel.TicketBulkJob{}, err
	}
	definition, err := kernel.NewTicketBulkDefinition(kernel.TicketBulkDefinitionInput{
		ID: id, Tenant: tenant, Requester: requester, OwnerMembership: owner, Kind: kind,
		Selection: selection, Mutation: mutation, ProjectionVersion: definitionWire.ProjectionVersion,
		MaximumAttempts: definitionWire.MaximumAttempts,
	})
	if err != nil {
		return kernel.TicketBulkJob{}, application.ErrUnavailable
	}
	state, err := ticketOperationsBulkState(wire.State)
	if err != nil || wire.ActiveBatch == nil {
		return kernel.TicketBulkJob{}, application.ErrUnavailable
	}
	requestedAt, err := ticketOperationsInstant(wire.RequestedAt)
	if err != nil {
		return kernel.TicketBulkJob{}, err
	}
	updatedAt, err := ticketOperationsInstant(wire.UpdatedAt)
	if err != nil {
		return kernel.TicketBulkJob{}, err
	}
	availableAt, err := ticketOperationsInstant(wire.AvailableAt)
	if err != nil {
		return kernel.TicketBulkJob{}, err
	}
	expiresAt, err := ticketOperationsInstant(wire.ExpiresAt)
	if err != nil {
		return kernel.TicketBulkJob{}, err
	}
	terminalAt, err := ticketOperationsOptionalInstant(wire.TerminalAt)
	if err != nil {
		return kernel.TicketBulkJob{}, err
	}
	progress := wire.Progress
	job, err := kernel.RestoreTicketBulkJob(kernel.TicketBulkJobSnapshot{
		Definition: definition, State: state, Revision: wire.Revision,
		Progress: kernel.TicketBulkProgressSnapshot{
			Total: progress.Total, Succeeded: progress.Succeeded, NoChange: progress.NoChange,
			VersionConflict: progress.VersionConflict, NotFoundOrHidden: progress.NotFoundOrHidden,
			AuthorizationDenied: progress.AuthorizationDenied, Rejected: progress.Rejected,
			Cancelled: progress.Cancelled, AuthorizationRevoked: progress.AuthorizationRevoked,
			InternalFailure: progress.InternalFailure,
		},
		RequestedAt: requestedAt, UpdatedAt: updatedAt, AvailableAt: availableAt,
		ExpiresAt: expiresAt, ActiveBatch: *wire.ActiveBatch, TerminalAt: terminalAt,
	})
	if err != nil {
		return kernel.TicketBulkJob{}, application.ErrUnavailable
	}
	return job, nil
}

func ticketOperationsBulkState(value string) (kernel.TicketBulkState, error) {
	states := []kernel.TicketBulkState{
		kernel.TicketBulkPending, kernel.TicketBulkRunning, kernel.TicketBulkCancellationRequested,
		kernel.TicketBulkCompleted, kernel.TicketBulkFailed, kernel.TicketBulkCancelledState,
		kernel.TicketBulkAuthorizationRevokedState,
	}
	for _, state := range states {
		if state.String() == value {
			return state, nil
		}
	}
	return 0, application.ErrUnavailable
}

func restoreTicketOperationsQuery(
	wire ticketOperationsQueryWireV1,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	export bool,
) (application.TicketBulkQuerySnapshot, application.AsyncExportQuerySnapshot, error) {
	canonical, err := base64.RawStdEncoding.DecodeString(wire.SpecCanonicalBase64)
	if err != nil || base64.RawStdEncoding.EncodeToString(canonical) != wire.SpecCanonicalBase64 {
		return application.TicketBulkQuerySnapshot{}, application.AsyncExportQuerySnapshot{}, application.ErrUnavailable
	}
	spec, digest, err := application.RestoreSavedViewSpec(tenantID, kind, canonical)
	if err != nil {
		return application.TicketBulkQuerySnapshot{}, application.AsyncExportQuerySnapshot{}, application.ErrUnavailable
	}
	queryDigest, err := ticketOperationsDigest(wire.QuerySHA256)
	if err != nil || queryDigest != digest {
		return application.TicketBulkQuerySnapshot{}, application.AsyncExportQuerySnapshot{}, application.ErrUnavailable
	}
	catalogDigest, err := ticketOperationsDigest(wire.CatalogSHA256)
	if err != nil {
		return application.TicketBulkQuerySnapshot{}, application.AsyncExportQuerySnapshot{}, err
	}
	bulkPin, exportPin, err := ticketOperationsSavedView(wire.SavedView, export)
	if err != nil {
		return application.TicketBulkQuerySnapshot{}, application.AsyncExportQuerySnapshot{}, err
	}
	if export {
		source, err := ticketOperationsExportQuerySource(wire.Source)
		if err != nil {
			return application.TicketBulkQuerySnapshot{}, application.AsyncExportQuerySnapshot{}, err
		}
		query, err := application.NewAsyncExportQuerySnapshot(tenantID, kind, source, spec, exportPin)
		if err != nil || query.QueryDigest() != queryDigest || query.CatalogDigest() != catalogDigest {
			return application.TicketBulkQuerySnapshot{}, application.AsyncExportQuerySnapshot{}, application.ErrUnavailable
		}
		return application.TicketBulkQuerySnapshot{}, query, nil
	}
	source, err := ticketOperationsBulkQuerySource(wire.Source)
	if err != nil {
		return application.TicketBulkQuerySnapshot{}, application.AsyncExportQuerySnapshot{}, err
	}
	query, err := application.NewTicketBulkQuerySnapshot(tenantID, kind, source, spec, bulkPin)
	if err != nil || query.QueryDigest() != queryDigest || query.CatalogDigest() != catalogDigest {
		return application.TicketBulkQuerySnapshot{}, application.AsyncExportQuerySnapshot{}, application.ErrUnavailable
	}
	return query, application.AsyncExportQuerySnapshot{}, nil
}

func ticketOperationsBulkQuerySource(value string) (application.TicketBulkQuerySource, error) {
	switch value {
	case application.TicketBulkQueryInline.String():
		return application.TicketBulkQueryInline, nil
	case application.TicketBulkQuerySavedView.String():
		return application.TicketBulkQuerySavedView, nil
	default:
		return 0, application.ErrUnavailable
	}
}

func ticketOperationsExportQuerySource(value string) (kernel.TicketExportQuerySource, error) {
	switch value {
	case kernel.TicketExportQueryInline.String():
		return kernel.TicketExportQueryInline, nil
	case kernel.TicketExportQuerySavedView.String():
		return kernel.TicketExportQuerySavedView, nil
	default:
		return 0, application.ErrUnavailable
	}
}

func restoreTicketOperationsBulkRecord(
	wire ticketOperationsBulkRecordWireV1,
) (application.TicketBulkRecord, error) {
	job, err := restoreTicketOperationsBulkJob(wire.Job)
	if err != nil {
		return application.TicketBulkRecord{}, err
	}
	definition := job.Definition()
	var query *application.TicketBulkQuerySnapshot
	if wire.Query != nil {
		tenantID := uuid.UUID(definition.Tenant().Bytes())
		restored, _, err := restoreTicketOperationsQuery(*wire.Query, tenantID, definition.Kind(), false)
		if err != nil {
			return application.TicketBulkRecord{}, err
		}
		query = &restored
	}
	record := application.TicketBulkRecord{Job: job, Query: query}
	selection := definition.Selection()
	if (selection.Source() == kernel.TicketBulkSelectionQuery) != (query != nil) ||
		query != nil && query.QueryDigest() != selection.QueryDigest() {
		return application.TicketBulkRecord{}, application.ErrUnavailable
	}
	return record, nil
}

func restoreTicketOperationsExportJob(
	wire ticketOperationsExportJobWireV1,
) (kernel.TicketExportJob, error) {
	definitionWire := wire.Definition
	id, err := ticketOperationsEntity(definitionWire.ID)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	tenant, err := ticketOperationsEntity(definitionWire.TenantID)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	requester, err := ticketOperationsEntity(definitionWire.RequesterID)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	owner, err := ticketOperationsEntity(definitionWire.OwnerMembershipID)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	var contact *kernel.EntityID
	if definitionWire.CustomerContactID != "" {
		parsed, parseErr := ticketOperationsEntity(definitionWire.CustomerContactID)
		if parseErr != nil {
			return kernel.TicketExportJob{}, parseErr
		}
		contact = &parsed
	}
	kind, err := ticketOperationsKind(definitionWire.Kind)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	audience, err := ticketOperationsExportAudience(definitionWire.Audience)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	comments, err := ticketOperationsExportComments(definitionWire.CommentScope)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	querySource, err := ticketOperationsExportQuerySource(definitionWire.QuerySource)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	_, savedView, err := ticketOperationsSavedView(definitionWire.SavedView, true)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	queryDigest, err := ticketOperationsDigest(definitionWire.QuerySHA256)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	catalogDigest, err := ticketOperationsDigest(definitionWire.CatalogSHA256)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	if definitionWire.Format != kernel.TicketExportCSV.String() {
		return kernel.TicketExportJob{}, application.ErrUnavailable
	}
	definition, err := kernel.NewTicketExportDefinition(kernel.TicketExportDefinitionInput{
		ID: id, Tenant: tenant, Requester: requester, OwnerMembership: owner, CustomerContact: contact,
		Kind: kind, Audience: audience, Comments: comments, QuerySource: querySource,
		SavedView: savedView, QueryDigest: queryDigest, CatalogDigest: catalogDigest,
		ProjectionVersion: definitionWire.ProjectionVersion, Format: kernel.TicketExportCSV,
		MaximumRows: definitionWire.MaximumRows, MaximumBytes: definitionWire.MaximumBytes,
		MaximumAttempts: definitionWire.MaximumAttempts,
	})
	if err != nil {
		return kernel.TicketExportJob{}, application.ErrUnavailable
	}
	state, err := ticketOperationsExportState(wire.State)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	failure, err := ticketOperationsExportFailure(wire.FailureCode)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	var lease *kernel.TicketExportLease
	if wire.Lease != nil {
		worker, parseErr := ticketOperationsEntity(wire.Lease.WorkerID)
		fence, digestErr := ticketOperationsDigest(wire.Lease.Fence)
		claimedAt, claimedErr := ticketOperationsInstant(wire.Lease.ClaimedAt)
		expiresAt, expiresErr := ticketOperationsInstant(wire.Lease.ExpiresAt)
		if parseErr != nil || digestErr != nil || claimedErr != nil || expiresErr != nil {
			return kernel.TicketExportJob{}, application.ErrUnavailable
		}
		parsed, leaseErr := kernel.NewTicketExportLease(worker, fence, claimedAt, expiresAt)
		if leaseErr != nil {
			return kernel.TicketExportJob{}, application.ErrUnavailable
		}
		lease = &parsed
	}
	var artifact *kernel.TicketExportArtifact
	if wire.Artifact != nil {
		artifactID, parseErr := ticketOperationsEntity(wire.Artifact.ID)
		digest, digestErr := ticketOperationsDigest(wire.Artifact.SHA256)
		expiresAt, expiresErr := ticketOperationsInstant(wire.Artifact.ExpiresAt)
		if parseErr != nil || digestErr != nil || expiresErr != nil {
			return kernel.TicketExportJob{}, application.ErrUnavailable
		}
		parsed, artifactErr := kernel.NewTicketExportArtifact(
			artifactID, digest, wire.Artifact.Rows, wire.Artifact.Bytes, expiresAt,
		)
		if artifactErr != nil {
			return kernel.TicketExportJob{}, application.ErrUnavailable
		}
		artifact = &parsed
	}
	requestedAt, err := ticketOperationsInstant(wire.RequestedAt)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	updatedAt, err := ticketOperationsInstant(wire.UpdatedAt)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	availableAt, err := ticketOperationsInstant(wire.AvailableAt)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	expiresAt, err := ticketOperationsInstant(wire.ExpiresAt)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	terminalAt, err := ticketOperationsOptionalInstant(wire.TerminalAt)
	if err != nil {
		return kernel.TicketExportJob{}, err
	}
	job, err := kernel.RestoreTicketExportJob(kernel.TicketExportJobSnapshot{
		Definition: definition, State: state, Revision: wire.Revision, Attempts: wire.Attempts,
		FailureCode: failure, RequestedAt: requestedAt, UpdatedAt: updatedAt,
		AvailableAt: availableAt, ExpiresAt: expiresAt, Lease: lease,
		Artifact: artifact, TerminalAt: terminalAt,
	})
	if err != nil {
		return kernel.TicketExportJob{}, application.ErrUnavailable
	}
	return job, nil
}

func restoreTicketOperationsExportRecord(
	wire ticketOperationsExportRecordWireV1,
) (application.AsyncExportRecord, error) {
	job, err := restoreTicketOperationsExportJob(wire.Job)
	if err != nil {
		return application.AsyncExportRecord{}, err
	}
	definition := job.Definition()
	tenantID := uuid.UUID(definition.Tenant().Bytes())
	_, query, err := restoreTicketOperationsQuery(wire.Query, tenantID, definition.Kind(), true)
	if err != nil || query.QueryDigest() != definition.QueryDigest() ||
		query.CatalogDigest() != definition.CatalogDigest() || query.Source() != definition.QuerySource() {
		return application.AsyncExportRecord{}, application.ErrUnavailable
	}
	return application.AsyncExportRecord{Job: job, Query: query}, nil
}

func ticketOperationsExportAudience(value string) (kernel.TicketExportAudience, error) {
	switch value {
	case kernel.TicketExportAudienceOperator.String():
		return kernel.TicketExportAudienceOperator, nil
	case kernel.TicketExportAudienceCustomer.String():
		return kernel.TicketExportAudienceCustomer, nil
	default:
		return 0, application.ErrUnavailable
	}
}

func ticketOperationsExportComments(value string) (kernel.TicketExportCommentScope, error) {
	for _, scope := range []kernel.TicketExportCommentScope{
		kernel.TicketExportCommentsNone, kernel.TicketExportCommentsPublic,
		kernel.TicketExportCommentsPublicAndPrivate,
	} {
		if scope.String() == value {
			return scope, nil
		}
	}
	return 0, application.ErrUnavailable
}

func ticketOperationsExportState(value string) (kernel.TicketExportState, error) {
	for _, state := range []kernel.TicketExportState{
		kernel.TicketExportPending, kernel.TicketExportRunning, kernel.TicketExportCancellationRequested,
		kernel.TicketExportSucceeded, kernel.TicketExportFailed, kernel.TicketExportCancelledState,
	} {
		if state.String() == value {
			return state, nil
		}
	}
	return 0, application.ErrUnavailable
}

func ticketOperationsExportFailure(value string) (kernel.TicketExportFailureCode, error) {
	for _, code := range []kernel.TicketExportFailureCode{
		kernel.TicketExportFailureNone, kernel.TicketExportFailureTransientStorage,
		kernel.TicketExportFailureTransientDatabase, kernel.TicketExportFailureAuthorizationRevoked,
		kernel.TicketExportFailureSnapshotStale, kernel.TicketExportFailureOutputLimit,
		kernel.TicketExportFailureLeaseExpired, kernel.TicketExportFailureExpired,
		kernel.TicketExportFailureInternal,
	} {
		if code.String() == value {
			return code, nil
		}
	}
	return 0, application.ErrUnavailable
}

func ticketOperationsQueryWire(
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	source string,
	spec kernel.SavedViewSpec,
	savedView *ticketOperationsSavedViewWireV1,
	queryDigest [sha256.Size]byte,
	catalogDigest [sha256.Size]byte,
) (ticketOperationsQueryWireV1, error) {
	tenant, err := ticketOperationsEntity(tenantID.String())
	if err != nil {
		return ticketOperationsQueryWireV1{}, application.ErrUnavailable
	}
	canonical, err := application.CanonicalSavedViewSpec(tenant, kind, spec)
	if err != nil || sha256.Sum256(canonical) != queryDigest {
		return ticketOperationsQueryWireV1{}, application.ErrUnavailable
	}
	return ticketOperationsQueryWireV1{
		Source: source, SpecCanonicalBase64: base64.RawStdEncoding.EncodeToString(canonical),
		QuerySHA256: hex.EncodeToString(queryDigest[:]), CatalogSHA256: hex.EncodeToString(catalogDigest[:]),
		SavedView: savedView,
	}, nil
}

func ticketOperationsSavedViewWireBulk(
	pin *kernel.TicketBulkSavedViewPin,
) *ticketOperationsSavedViewWireV1 {
	if pin == nil {
		return nil
	}
	digest := pin.SpecDigest()
	return &ticketOperationsSavedViewWireV1{
		ID: pin.ID().String(), OwnerID: pin.Owner().String(), Revision: pin.Revision(),
		SpecSHA256: hex.EncodeToString(digest[:]),
	}
}

func ticketOperationsSavedViewWireExport(
	pin *kernel.TicketExportSavedViewPin,
) *ticketOperationsSavedViewWireV1 {
	if pin == nil {
		return nil
	}
	digest := pin.Digest()
	return &ticketOperationsSavedViewWireV1{
		ID: pin.ID().String(), OwnerID: pin.Owner().String(), Revision: pin.Revision(),
		SpecSHA256: hex.EncodeToString(digest[:]),
	}
}

func ticketOperationsBulkMutationWire(
	mutation kernel.TicketBulkMutation,
) (ticketOperationsBulkMutationWireV1, error) {
	wire := ticketOperationsBulkMutationWireV1{Action: mutation.Action().String()}
	switch mutation.Action() {
	case kernel.ActionTransition:
		transition, to, ok := mutation.Transition()
		if !ok {
			return wire, application.ErrUnavailable
		}
		wire.Transition, wire.To = transition.String(), to.String()
	case kernel.ActionAssign, kernel.ActionTransfer:
		team, assignee, ok := mutation.Assignment()
		if !ok {
			return wire, application.ErrUnavailable
		}
		wire.TeamID = team.String()
		if assignee != nil {
			wire.AssigneeID = assignee.String()
		}
	case kernel.ActionClaim:
		team, ok := mutation.ClaimTeam()
		if !ok {
			return wire, application.ErrUnavailable
		}
		wire.TeamID = team.String()
	case kernel.ActionRelease:
	default:
		return wire, application.ErrUnavailable
	}
	return wire, nil
}

func ticketOperationsBulkJobWire(job kernel.TicketBulkJob) (ticketOperationsBulkJobWireV1, error) {
	if err := kernel.ValidateTicketBulkJob(job); err != nil {
		return ticketOperationsBulkJobWireV1{}, application.ErrUnavailable
	}
	definition := job.Definition()
	selection := definition.Selection()
	selectionWire := ticketOperationsBulkSelectionWireV1{
		Source: selection.Source().String(), TargetCount: selection.TargetCount(),
		SavedView: ticketOperationsSavedViewWireBulk(selection.SavedView()),
	}
	queryDigest, targetDigest := selection.QueryDigest(), selection.TargetSetDigest()
	if queryDigest != ([sha256.Size]byte{}) {
		selectionWire.QuerySHA256 = hex.EncodeToString(queryDigest[:])
	}
	selectionWire.TargetSetSHA256 = hex.EncodeToString(targetDigest[:])
	if selection.Source() == kernel.TicketBulkSelectionExplicit {
		targets := selection.ExplicitTargets()
		selectionWire.ExplicitTargets = make([]ticketOperationsTargetWireV1, len(targets))
		for index, target := range targets {
			selectionWire.ExplicitTargets[index] = ticketOperationsTargetWireV1{
				ID: target.ID().String(), Version: target.Version(),
			}
		}
	}
	mutation, err := ticketOperationsBulkMutationWire(definition.Mutation())
	if err != nil {
		return ticketOperationsBulkJobWireV1{}, err
	}
	progress := job.Progress().Snapshot()
	active := job.ActiveBatch()
	return ticketOperationsBulkJobWireV1{
		Definition: ticketOperationsBulkDefinitionWireV1{
			ID: definition.ID().String(), TenantID: definition.Tenant().String(),
			RequesterID: definition.Requester().String(), OwnerMembershipID: definition.OwnerMembership().String(),
			Kind: definition.Kind().String(), Selection: selectionWire, Mutation: mutation,
			ProjectionVersion: definition.ProjectionVersion(), MaximumAttempts: definition.MaximumAttempts(),
		},
		State: job.State().String(), Revision: job.Revision(), Progress: ticketOperationsBulkProgressWireV1{
			Total: progress.Total, Succeeded: progress.Succeeded, NoChange: progress.NoChange,
			VersionConflict: progress.VersionConflict, NotFoundOrHidden: progress.NotFoundOrHidden,
			AuthorizationDenied: progress.AuthorizationDenied, Rejected: progress.Rejected,
			Cancelled: progress.Cancelled, AuthorizationRevoked: progress.AuthorizationRevoked,
			InternalFailure: progress.InternalFailure,
		}, RequestedAt: job.RequestedAt(), UpdatedAt: job.UpdatedAt(), AvailableAt: job.AvailableAt(),
		ExpiresAt: job.ExpiresAt(), ActiveBatch: &active, TerminalAt: job.TerminalAt(),
	}, nil
}

func ticketOperationsExportJobWire(job kernel.TicketExportJob) (ticketOperationsExportJobWireV1, error) {
	if err := kernel.ValidateTicketExportJob(job); err != nil {
		return ticketOperationsExportJobWireV1{}, application.ErrUnavailable
	}
	definition := job.Definition()
	queryDigest, catalogDigest := definition.QueryDigest(), definition.CatalogDigest()
	definitionWire := ticketOperationsExportDefinitionWireV1{
		ID: definition.ID().String(), TenantID: definition.Tenant().String(),
		RequesterID: definition.Requester().String(), OwnerMembershipID: definition.OwnerMembership().String(),
		Kind: definition.Kind().String(), Audience: definition.Audience().String(),
		CommentScope: definition.Comments().String(), QuerySource: definition.QuerySource().String(),
		SavedView:   ticketOperationsSavedViewWireExport(definition.SavedView()),
		QuerySHA256: hex.EncodeToString(queryDigest[:]), CatalogSHA256: hex.EncodeToString(catalogDigest[:]),
		ProjectionVersion: definition.ProjectionVersion(), Format: definition.Format().String(),
		MaximumRows: definition.MaximumRows(), MaximumBytes: definition.MaximumBytes(),
		MaximumAttempts: definition.MaximumAttempts(),
	}
	if contact := definition.CustomerContact(); contact != nil {
		definitionWire.CustomerContactID = contact.String()
	}
	wire := ticketOperationsExportJobWireV1{
		Definition: definitionWire, State: job.State().String(), Revision: job.Revision(),
		Attempts: job.Attempts(), FailureCode: job.FailureCode().String(),
		RequestedAt: job.RequestedAt(), UpdatedAt: job.UpdatedAt(), AvailableAt: job.AvailableAt(),
		ExpiresAt: job.ExpiresAt(), TerminalAt: job.TerminalAt(),
	}
	if lease := job.Lease(); lease != nil {
		fence := lease.Fence()
		wire.Lease = &ticketOperationsExportLeaseWireV1{
			WorkerID: lease.Worker().String(), Fence: hex.EncodeToString(fence[:]),
			ClaimedAt: lease.ClaimedAt(), ExpiresAt: lease.ExpiresAt(),
		}
	}
	if artifact := job.Artifact(); artifact != nil {
		digest := artifact.Digest()
		wire.Artifact = &ticketOperationsExportArtifactWireV1{
			ID: artifact.ID().String(), SHA256: hex.EncodeToString(digest[:]),
			Rows: artifact.Rows(), Bytes: artifact.Bytes(), ExpiresAt: artifact.ExpiresAt(),
		}
	}
	return wire, nil
}
