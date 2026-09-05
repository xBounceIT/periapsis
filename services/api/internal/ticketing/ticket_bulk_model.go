package ticketing

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

const TicketBulkWorkerPurpose = "ticket_bulk"

type TicketBulkCapability string

const (
	TicketBulkCapabilityRequest TicketBulkCapability = "ticket.bulk.request"
	TicketBulkCapabilityRead    TicketBulkCapability = "ticket.bulk.read"
	TicketBulkCapabilityCancel  TicketBulkCapability = "ticket.bulk.cancel"
)

func validTicketBulkCapability(capability TicketBulkCapability) bool {
	return capability == TicketBulkCapabilityRequest || capability == TicketBulkCapabilityRead ||
		capability == TicketBulkCapabilityCancel
}

// TicketBulkAccess is fresh authority evidence returned by persistence. It is
// deliberately opaque in diagnostics and never persisted as the job's future
// authority. Every commit rechecks the live membership and mutation grant.
type TicketBulkAccess struct {
	tenant     uuid.UUID
	actor      uuid.UUID
	membership uuid.UUID
	kind       kernel.AggregateKind
	capability TicketBulkCapability
	principal  kernel.PrincipalKind
	mutation   kernel.Action
	allowed    bool
}

func NewTicketBulkAccess(
	tenant uuid.UUID,
	actor uuid.UUID,
	membership uuid.UUID,
	kind kernel.AggregateKind,
	capability TicketBulkCapability,
	principal kernel.PrincipalKind,
	mutation kernel.Action,
	allowed bool,
) (TicketBulkAccess, error) {
	if !validWorkflowUUID(tenant) || !validWorkflowUUID(actor) || !validWorkflowUUID(membership) ||
		!validSavedViewKind(kind) || !validTicketBulkCapability(capability) ||
		principal != kernel.PrincipalOperator ||
		capability == TicketBulkCapabilityRequest && !validTicketBulkMutationAction(mutation) ||
		capability != TicketBulkCapabilityRequest && mutation != 0 {
		return TicketBulkAccess{}, ErrInvalidInput
	}
	return TicketBulkAccess{
		tenant: tenant, actor: actor, membership: membership, kind: kind,
		capability: capability, principal: principal, mutation: mutation, allowed: allowed,
	}, nil
}

func (access TicketBulkAccess) Tenant() uuid.UUID                { return access.tenant }
func (access TicketBulkAccess) Actor() uuid.UUID                 { return access.actor }
func (access TicketBulkAccess) Membership() uuid.UUID            { return access.membership }
func (access TicketBulkAccess) Kind() kernel.AggregateKind       { return access.kind }
func (access TicketBulkAccess) Capability() TicketBulkCapability { return access.capability }
func (access TicketBulkAccess) Principal() kernel.PrincipalKind  { return access.principal }
func (access TicketBulkAccess) MutationAction() kernel.Action    { return access.mutation }
func (access TicketBulkAccess) Allowed() bool                    { return access.allowed }
func (access TicketBulkAccess) String() string                   { return "TicketBulkAccess{authority:[REDACTED]}" }
func (access TicketBulkAccess) GoString() string                 { return access.String() }

type TicketBulkTargetInput struct {
	ID              uuid.UUID
	ExpectedVersion uint64
}

func (input TicketBulkTargetInput) String() string {
	return fmt.Sprintf("TicketBulkTargetInput{expected_version:%d,identity:[REDACTED]}", input.ExpectedVersion)
}
func (input TicketBulkTargetInput) GoString() string { return input.String() }

type TicketBulkSavedViewSourceInput struct {
	ID                 uuid.UUID
	ExpectedRevision   uint64
	ExpectedSpecDigest [sha256.Size]byte
}

func (input TicketBulkSavedViewSourceInput) String() string {
	return fmt.Sprintf(
		"TicketBulkSavedViewSourceInput{expected_revision:%d,identity:[REDACTED],digest:[REDACTED]}",
		input.ExpectedRevision,
	)
}
func (input TicketBulkSavedViewSourceInput) GoString() string { return input.String() }

type TicketBulkQuerySourceInput struct {
	Inline    *SavedViewSpecInput
	SavedView *TicketBulkSavedViewSourceInput
}

func (input TicketBulkQuerySourceInput) String() string {
	mode := "invalid"
	if input.Inline != nil && input.SavedView == nil {
		mode = "inline"
	} else if input.Inline == nil && input.SavedView != nil {
		mode = "saved_view"
	}
	return fmt.Sprintf("TicketBulkQuerySourceInput{mode:%s,query:[REDACTED]}", mode)
}
func (input TicketBulkQuerySourceInput) GoString() string { return input.String() }

type TicketBulkSelectionInput struct {
	Explicit []TicketBulkTargetInput
	Query    *TicketBulkQuerySourceInput
}

func (input TicketBulkSelectionInput) String() string {
	mode := "invalid"
	if input.Explicit != nil && input.Query == nil {
		mode = "explicit"
	} else if input.Explicit == nil && input.Query != nil {
		mode = "query"
	}
	return fmt.Sprintf(
		"TicketBulkSelectionInput{mode:%s,explicit_count:%d,selection:[REDACTED]}",
		mode, len(input.Explicit),
	)
}
func (input TicketBulkSelectionInput) GoString() string { return input.String() }

type TicketBulkMutationInput struct {
	Action     string
	Transition string
	To         string
	TeamID     uuid.UUID
	AssigneeID *uuid.UUID
}

func (input TicketBulkMutationInput) String() string {
	action := "invalid"
	if input.Action == kernel.ActionTransition.String() || input.Action == kernel.ActionAssign.String() ||
		input.Action == kernel.ActionTransfer.String() || input.Action == kernel.ActionClaim.String() ||
		input.Action == kernel.ActionRelease.String() {
		action = input.Action
	}
	return fmt.Sprintf("TicketBulkMutationInput{action:%s,payload:[REDACTED]}", action)
}
func (input TicketBulkMutationInput) GoString() string { return input.String() }

type TicketBulkRequestInput struct {
	Selection      TicketBulkSelectionInput
	Mutation       TicketBulkMutationInput
	Retention      time.Duration
	IdempotencyKey string
}

func (input TicketBulkRequestInput) String() string {
	return fmt.Sprintf(
		"TicketBulkRequestInput{selection:%s,mutation:%s,retention:%s,idempotency:[REDACTED]}",
		input.Selection, input.Mutation, input.Retention,
	)
}
func (input TicketBulkRequestInput) GoString() string { return input.String() }

type TicketBulkCancelInput struct {
	ExpectedRevision uint64
	IdempotencyKey   string
}

func (input TicketBulkCancelInput) String() string {
	return fmt.Sprintf(
		"TicketBulkCancelInput{expected_revision:%d,idempotency:[REDACTED]}",
		input.ExpectedRevision,
	)
}
func (input TicketBulkCancelInput) GoString() string { return input.String() }

type TicketBulkQuerySource uint8

const (
	TicketBulkQueryInline TicketBulkQuerySource = iota + 1
	TicketBulkQuerySavedView
)

func (source TicketBulkQuerySource) String() string {
	switch source {
	case TicketBulkQueryInline:
		return "inline"
	case TicketBulkQuerySavedView:
		return "saved_view"
	default:
		return "unknown"
	}
}

// TicketBulkQuerySnapshot is the effective, current-authority query shape.
// Target rows are still materialized inside CommitTicketBulkRequest so a
// pre-commit page race cannot change or partly expose the durable selection.
type TicketBulkQuerySnapshot struct {
	tenant        uuid.UUID
	kind          kernel.AggregateKind
	source        TicketBulkQuerySource
	spec          kernel.SavedViewSpec
	savedView     *kernel.TicketBulkSavedViewPin
	queryDigest   [sha256.Size]byte
	catalogDigest [sha256.Size]byte
}

func NewTicketBulkQuerySnapshot(
	tenant uuid.UUID,
	kind kernel.AggregateKind,
	source TicketBulkQuerySource,
	spec kernel.SavedViewSpec,
	savedView *kernel.TicketBulkSavedViewPin,
) (TicketBulkQuerySnapshot, error) {
	tenantEntity, err := entityID(tenant)
	if err != nil || !validSavedViewKind(kind) ||
		source != TicketBulkQueryInline && source != TicketBulkQuerySavedView ||
		kernel.ValidateSavedViewSpec(tenantEntity, kind, spec) != nil {
		return TicketBulkQuerySnapshot{}, ErrInvalidInput
	}
	queryDigest, err := SavedViewSpecDigest(tenantEntity, kind, spec)
	if err != nil {
		return TicketBulkQuerySnapshot{}, err
	}
	if source == TicketBulkQuerySavedView {
		if savedView == nil || savedView.Revision() > maxResourceVersion ||
			savedView.SpecDigest() != queryDigest {
			return TicketBulkQuerySnapshot{}, ErrInvalidInput
		}
	} else if savedView != nil {
		return TicketBulkQuerySnapshot{}, ErrInvalidInput
	}
	catalogDigest, err := asyncExportCatalogDigest(spec)
	if err != nil {
		return TicketBulkQuerySnapshot{}, err
	}
	return TicketBulkQuerySnapshot{
		tenant: tenant, kind: kind, source: source, spec: spec,
		savedView: cloneTicketBulkSavedViewPin(savedView), queryDigest: queryDigest,
		catalogDigest: catalogDigest,
	}, nil
}

func (snapshot TicketBulkQuerySnapshot) Tenant() uuid.UUID          { return snapshot.tenant }
func (snapshot TicketBulkQuerySnapshot) Kind() kernel.AggregateKind { return snapshot.kind }
func (snapshot TicketBulkQuerySnapshot) Source() TicketBulkQuerySource {
	return snapshot.source
}
func (snapshot TicketBulkQuerySnapshot) Spec() kernel.SavedViewSpec { return snapshot.spec }
func (snapshot TicketBulkQuerySnapshot) SavedView() *kernel.TicketBulkSavedViewPin {
	return cloneTicketBulkSavedViewPin(snapshot.savedView)
}
func (snapshot TicketBulkQuerySnapshot) QueryDigest() [sha256.Size]byte {
	return snapshot.queryDigest
}
func (snapshot TicketBulkQuerySnapshot) CatalogDigest() [sha256.Size]byte {
	return snapshot.catalogDigest
}
func (snapshot TicketBulkQuerySnapshot) String() string {
	return fmt.Sprintf(
		"TicketBulkQuerySnapshot{kind:%s,source:%s,columns:%d,query:[REDACTED],catalog:[REDACTED]}",
		snapshot.kind, snapshot.source, len(snapshot.spec.Columns()),
	)
}
func (snapshot TicketBulkQuerySnapshot) GoString() string { return snapshot.String() }

func normalizeTicketBulkQuerySnapshot(
	snapshot TicketBulkQuerySnapshot,
) (TicketBulkQuerySnapshot, bool) {
	rebuilt, err := NewTicketBulkQuerySnapshot(
		snapshot.tenant, snapshot.kind, snapshot.source, snapshot.spec, snapshot.savedView,
	)
	return rebuilt, err == nil && rebuilt.queryDigest == snapshot.queryDigest &&
		rebuilt.catalogDigest == snapshot.catalogDigest
}

type TicketBulkRecord struct {
	Job   kernel.TicketBulkJob
	Query *TicketBulkQuerySnapshot
}

func (record TicketBulkRecord) String() string {
	return fmt.Sprintf("TicketBulkRecord{job:%s,query:%t}", record.Job, record.Query != nil)
}
func (record TicketBulkRecord) GoString() string { return record.String() }

type TicketBulkResult struct {
	Record   TicketBulkRecord
	Replayed bool
}

func (result TicketBulkResult) String() string {
	return fmt.Sprintf("TicketBulkResult{record:%s,replayed:%t}", result.Record, result.Replayed)
}
func (result TicketBulkResult) GoString() string { return result.String() }

type TicketBulkTargetResultRecord struct {
	Sequence      uint32
	TargetID      uuid.UUID
	TargetVersion uint64
	Result        kernel.TicketBulkTargetResult
	RecordedAt    time.Time
}

func (record TicketBulkTargetResultRecord) String() string {
	return fmt.Sprintf(
		"TicketBulkTargetResultRecord{sequence:%d,target_version:%d,result:%s,identity:[REDACTED],time:[REDACTED]}",
		record.Sequence, record.TargetVersion, record.Result,
	)
}
func (record TicketBulkTargetResultRecord) GoString() string { return record.String() }

type TicketBulkResultPage struct {
	Items []TicketBulkTargetResultRecord
	Next  string
}

func (page TicketBulkResultPage) String() string {
	return fmt.Sprintf("TicketBulkResultPage{items:%d,next:%t,metadata:[REDACTED]}", len(page.Items), page.Next != "")
}
func (page TicketBulkResultPage) GoString() string { return page.String() }

type TicketBulkResultListInput struct {
	Limit int
	After string
}

func (input TicketBulkResultListInput) String() string {
	return fmt.Sprintf("TicketBulkResultListInput{limit:%d,cursor:[REDACTED]}", input.Limit)
}
func (input TicketBulkResultListInput) GoString() string { return input.String() }

func ticketBulkMutationFromInput(input TicketBulkMutationInput) (kernel.TicketBulkMutation, error) {
	switch input.Action {
	case kernel.ActionTransition.String():
		if input.TeamID != uuid.Nil || input.AssigneeID != nil {
			return kernel.TicketBulkMutation{}, ErrInvalidInput
		}
		transition, transitionErr := kernel.NewKey(input.Transition)
		to, toErr := kernel.NewKey(input.To)
		if transitionErr != nil || toErr != nil {
			return kernel.TicketBulkMutation{}, ErrInvalidInput
		}
		mutation, err := kernel.NewTicketBulkTransition(transition, to)
		return mutation, ticketBulkModelError(err)
	case kernel.ActionAssign.String(), kernel.ActionTransfer.String():
		if input.Transition != "" || input.To != "" {
			return kernel.TicketBulkMutation{}, ErrInvalidInput
		}
		team, err := entityID(input.TeamID)
		if err != nil {
			return kernel.TicketBulkMutation{}, ErrInvalidInput
		}
		assignee, err := optionalTicketBulkEntity(input.AssigneeID)
		if err != nil {
			return kernel.TicketBulkMutation{}, err
		}
		if input.Action == kernel.ActionAssign.String() {
			mutation, createErr := kernel.NewTicketBulkAssignment(team, assignee)
			return mutation, ticketBulkModelError(createErr)
		}
		mutation, createErr := kernel.NewTicketBulkTransfer(team, assignee)
		return mutation, ticketBulkModelError(createErr)
	case kernel.ActionClaim.String():
		if input.Transition != "" || input.To != "" || input.AssigneeID != nil {
			return kernel.TicketBulkMutation{}, ErrInvalidInput
		}
		team, err := entityID(input.TeamID)
		if err != nil {
			return kernel.TicketBulkMutation{}, ErrInvalidInput
		}
		mutation, createErr := kernel.NewTicketBulkClaim(team)
		return mutation, ticketBulkModelError(createErr)
	case kernel.ActionRelease.String():
		if input.Transition != "" || input.To != "" || input.TeamID != uuid.Nil || input.AssigneeID != nil {
			return kernel.TicketBulkMutation{}, ErrInvalidInput
		}
		return kernel.NewTicketBulkRelease(), nil
	default:
		return kernel.TicketBulkMutation{}, ErrInvalidInput
	}
}

func validTicketBulkMutationAction(action kernel.Action) bool {
	switch action {
	case kernel.ActionTransition, kernel.ActionAssign, kernel.ActionTransfer,
		kernel.ActionClaim, kernel.ActionRelease:
		return true
	default:
		return false
	}
}

func optionalTicketBulkEntity(value *uuid.UUID) (*kernel.EntityID, error) {
	if value == nil {
		return nil, nil
	}
	entity, err := entityID(*value)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return &entity, nil
}

func ticketBulkModelError(err error) error {
	if err != nil {
		return ErrInvalidInput
	}
	return nil
}

func ticketBulkExplicitSelection(
	targets []TicketBulkTargetInput,
) (kernel.TicketBulkSelection, error) {
	if len(targets) == 0 || len(targets) > kernel.TicketBulkMaximumExplicitRows {
		return kernel.TicketBulkSelection{}, ErrInvalidInput
	}
	pins := make([]kernel.TicketBulkTargetPin, len(targets))
	for index, target := range targets {
		id, err := entityID(target.ID)
		if err != nil || target.ExpectedVersion == 0 || target.ExpectedVersion > maxResourceVersion {
			return kernel.TicketBulkSelection{}, ErrInvalidInput
		}
		pin, err := kernel.NewTicketBulkTargetPin(id, target.ExpectedVersion)
		if err != nil {
			return kernel.TicketBulkSelection{}, ErrInvalidInput
		}
		pins[index] = pin
	}
	selection, err := kernel.NewExplicitTicketBulkSelection(pins)
	if err != nil {
		return kernel.TicketBulkSelection{}, ErrInvalidInput
	}
	return selection, nil
}

func cloneTicketBulkQuerySnapshot(
	value *TicketBulkQuerySnapshot,
) *TicketBulkQuerySnapshot {
	if value == nil {
		return nil
	}
	result := *value
	result.savedView = cloneTicketBulkSavedViewPin(value.savedView)
	return &result
}

func cloneTicketBulkSavedViewPin(
	value *kernel.TicketBulkSavedViewPin,
) *kernel.TicketBulkSavedViewPin {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneTicketBulkUUID(value *uuid.UUID) *uuid.UUID {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneTicketBulkSpecInput(value *SavedViewSpecInput) *SavedViewSpecInput {
	if value == nil {
		return nil
	}
	result := *value
	result.Filters.States = slices.Clone(value.Filters.States)
	result.Filters.Severities = slices.Clone(value.Filters.Severities)
	result.Filters.Priorities = slices.Clone(value.Filters.Priorities)
	result.Filters.AssignedTeamID = cloneTicketBulkUUID(value.Filters.AssignedTeamID)
	result.Filters.AssigneeUserID = cloneTicketBulkUUID(value.Filters.AssigneeUserID)
	result.Filters.ClaimedBy = cloneTicketBulkUUID(value.Filters.ClaimedBy)
	if value.Filters.CustomerVisible != nil {
		visible := *value.Filters.CustomerVisible
		result.Filters.CustomerVisible = &visible
	}
	result.Filters.Custom = make([]SavedViewCustomFilterInput, len(value.Filters.Custom))
	for index, filter := range value.Filters.Custom {
		result.Filters.Custom[index] = filter
		result.Filters.Custom[index].Value = slices.Clone(filter.Value)
	}
	result.Sort.DefinitionID = cloneTicketBulkUUID(value.Sort.DefinitionID)
	result.Columns = slices.Clone(value.Columns)
	for index := range result.Columns {
		result.Columns[index].DefinitionID = cloneTicketBulkUUID(value.Columns[index].DefinitionID)
	}
	return &result
}

func cloneTicketBulkSelectionInput(value TicketBulkSelectionInput) TicketBulkSelectionInput {
	result := value
	result.Explicit = slices.Clone(value.Explicit)
	result.Query = cloneTicketBulkQuerySourceInput(value.Query)
	return result
}

func cloneTicketBulkQuerySourceInput(
	value *TicketBulkQuerySourceInput,
) *TicketBulkQuerySourceInput {
	if value == nil {
		return nil
	}
	result := *value
	result.Inline = cloneTicketBulkSpecInput(value.Inline)
	if value.SavedView != nil {
		saved := *value.SavedView
		result.SavedView = &saved
	}
	return &result
}

func cloneTicketBulkMutationInput(value TicketBulkMutationInput) TicketBulkMutationInput {
	result := value
	result.AssigneeID = cloneTicketBulkUUID(value.AssigneeID)
	return result
}

func validTicketBulkTargetResult(value kernel.TicketBulkTargetResult) bool {
	return value >= kernel.TicketBulkTargetSucceeded &&
		value <= kernel.TicketBulkTargetInternalFailure
}
