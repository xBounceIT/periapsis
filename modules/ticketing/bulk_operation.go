package ticketing

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"slices"
)

const (
	TicketBulkProjectionVersion   = uint64(1)
	TicketBulkMaximumAttempts     = uint8(5)
	TicketBulkMaximumTargets      = uint32(100_000)
	TicketBulkMaximumExplicitRows = 1_000
)

var ErrInvalidTicketBulkOperation = errors.New("invalid ticket bulk operation")

// TicketBulkSelectionSource records whether the immutable target set came
// from exact rows supplied by the caller or from one server-resolved query.
type TicketBulkSelectionSource uint8

const (
	TicketBulkSelectionExplicit TicketBulkSelectionSource = iota + 1
	TicketBulkSelectionQuery
)

func (source TicketBulkSelectionSource) String() string {
	switch source {
	case TicketBulkSelectionExplicit:
		return "explicit"
	case TicketBulkSelectionQuery:
		return "query"
	default:
		return "unknown"
	}
}

// TicketBulkTargetPin prevents a background job from silently applying its
// mutation to a ticket version that the requester never selected.
type TicketBulkTargetPin struct {
	id      EntityID
	version uint64
}

func NewTicketBulkTargetPin(id EntityID, version uint64) (TicketBulkTargetPin, error) {
	if !validEntityID(id) || version == 0 || version > maxVersion {
		return TicketBulkTargetPin{}, ErrInvalidTicketBulkOperation
	}
	return TicketBulkTargetPin{id: id, version: version}, nil
}

func (pin TicketBulkTargetPin) ID() EntityID    { return pin.id }
func (pin TicketBulkTargetPin) Version() uint64 { return pin.version }
func (pin TicketBulkTargetPin) String() string {
	return fmt.Sprintf("TicketBulkTargetPin{version:%d,identity:[REDACTED]}", pin.version)
}
func (pin TicketBulkTargetPin) GoString() string { return pin.String() }

func validTicketBulkTargetPin(pin TicketBulkTargetPin) bool {
	rebuilt, err := NewTicketBulkTargetPin(pin.id, pin.version)
	return err == nil && rebuilt == pin
}

// TicketBulkSavedViewPin binds a query selection to the exact private view
// that contributed its stored query. The effective query digest is separate
// because it also includes current authority and dynamic-definition pins.
type TicketBulkSavedViewPin struct {
	id         EntityID
	owner      EntityID
	revision   uint64
	specDigest [32]byte
}

func NewTicketBulkSavedViewPin(
	id EntityID,
	owner EntityID,
	revision uint64,
	specDigest [32]byte,
) (TicketBulkSavedViewPin, error) {
	if !validEntityID(id) || !validEntityID(owner) || revision == 0 || revision > maxVersion ||
		specDigest == ([32]byte{}) {
		return TicketBulkSavedViewPin{}, ErrInvalidTicketBulkOperation
	}
	return TicketBulkSavedViewPin{
		id: id, owner: owner, revision: revision, specDigest: specDigest,
	}, nil
}

func (pin TicketBulkSavedViewPin) ID() EntityID         { return pin.id }
func (pin TicketBulkSavedViewPin) Owner() EntityID      { return pin.owner }
func (pin TicketBulkSavedViewPin) Revision() uint64     { return pin.revision }
func (pin TicketBulkSavedViewPin) SpecDigest() [32]byte { return pin.specDigest }
func (pin TicketBulkSavedViewPin) String() string {
	return fmt.Sprintf("TicketBulkSavedViewPin{revision:%d,metadata:[REDACTED]}", pin.revision)
}
func (pin TicketBulkSavedViewPin) GoString() string { return pin.String() }

func validTicketBulkSavedViewPin(pin TicketBulkSavedViewPin) bool {
	rebuilt, err := NewTicketBulkSavedViewPin(pin.id, pin.owner, pin.revision, pin.specDigest)
	return err == nil && rebuilt == pin
}

// TicketBulkSelection is the immutable selection committed with a job. Query
// targets are materialized by persistence before this value is constructed;
// workers use the target-set digest and never rerun the mutable list query.
type TicketBulkSelection struct {
	source          TicketBulkSelectionSource
	explicitTargets []TicketBulkTargetPin
	queryDigest     [32]byte
	targetSetDigest [32]byte
	targetCount     uint32
	savedView       *TicketBulkSavedViewPin
}

func NewExplicitTicketBulkSelection(targets []TicketBulkTargetPin) (TicketBulkSelection, error) {
	canonical, ok := canonicalTicketBulkTargets(targets)
	if !ok || len(canonical) == 0 || len(canonical) > TicketBulkMaximumExplicitRows {
		return TicketBulkSelection{}, ErrInvalidTicketBulkOperation
	}
	return TicketBulkSelection{
		source:          TicketBulkSelectionExplicit,
		explicitTargets: canonical,
		targetSetDigest: digestTicketBulkTargets(canonical),
		targetCount:     uint32(len(canonical)),
	}, nil
}

func NewQueryTicketBulkSelection(
	queryDigest [32]byte,
	targetSetDigest [32]byte,
	targetCount uint32,
	savedView *TicketBulkSavedViewPin,
) (TicketBulkSelection, error) {
	if queryDigest == ([32]byte{}) || targetSetDigest == ([32]byte{}) || targetCount == 0 ||
		targetCount > TicketBulkMaximumTargets ||
		savedView != nil && !validTicketBulkSavedViewPin(*savedView) {
		return TicketBulkSelection{}, ErrInvalidTicketBulkOperation
	}
	return TicketBulkSelection{
		source: TicketBulkSelectionQuery, queryDigest: queryDigest,
		targetSetDigest: targetSetDigest, targetCount: targetCount,
		savedView: cloneTicketBulkSavedViewPin(savedView),
	}, nil
}

func (selection TicketBulkSelection) Source() TicketBulkSelectionSource {
	return selection.source
}
func (selection TicketBulkSelection) ExplicitTargets() []TicketBulkTargetPin {
	return slices.Clone(selection.explicitTargets)
}
func (selection TicketBulkSelection) QueryDigest() [32]byte     { return selection.queryDigest }
func (selection TicketBulkSelection) TargetSetDigest() [32]byte { return selection.targetSetDigest }
func (selection TicketBulkSelection) TargetCount() uint32       { return selection.targetCount }
func (selection TicketBulkSelection) SavedView() *TicketBulkSavedViewPin {
	return cloneTicketBulkSavedViewPin(selection.savedView)
}
func (selection TicketBulkSelection) String() string {
	return fmt.Sprintf(
		"TicketBulkSelection{source:%s,target_count:%d,saved_view:%t,metadata:[REDACTED]}",
		selection.source, selection.targetCount, selection.savedView != nil,
	)
}
func (selection TicketBulkSelection) GoString() string { return selection.String() }

func validTicketBulkSelection(selection TicketBulkSelection) bool {
	switch selection.source {
	case TicketBulkSelectionExplicit:
		rebuilt, err := NewExplicitTicketBulkSelection(selection.explicitTargets)
		return err == nil && sameTicketBulkSelection(rebuilt, selection)
	case TicketBulkSelectionQuery:
		rebuilt, err := NewQueryTicketBulkSelection(
			selection.queryDigest, selection.targetSetDigest, selection.targetCount, selection.savedView,
		)
		return err == nil && sameTicketBulkSelection(rebuilt, selection)
	default:
		return false
	}
}

func sameTicketBulkSelection(left, right TicketBulkSelection) bool {
	return left.source == right.source && slices.Equal(left.explicitTargets, right.explicitTargets) &&
		left.queryDigest == right.queryDigest && left.targetSetDigest == right.targetSetDigest &&
		left.targetCount == right.targetCount && reflect.DeepEqual(left.savedView, right.savedView)
}

func canonicalTicketBulkTargets(targets []TicketBulkTargetPin) ([]TicketBulkTargetPin, bool) {
	if len(targets) > TicketBulkMaximumExplicitRows {
		return nil, false
	}
	result := slices.Clone(targets)
	for _, target := range result {
		if !validTicketBulkTargetPin(target) {
			return nil, false
		}
	}
	slices.SortFunc(result, func(left, right TicketBulkTargetPin) int {
		return compareEntityID(left.id, right.id)
	})
	for index := 1; index < len(result); index++ {
		if result[index-1].id == result[index].id {
			return nil, false
		}
	}
	return result, true
}

func digestTicketBulkTargets(targets []TicketBulkTargetPin) [32]byte {
	digest := sha256.New()
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(len(targets)))
	_, _ = digest.Write(encoded[:])
	for _, target := range targets {
		id := target.id.Bytes()
		_, _ = digest.Write(id[:])
		binary.BigEndian.PutUint64(encoded[:], target.version)
		_, _ = digest.Write(encoded[:])
	}
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result
}

// TicketBulkMutation is a closed mutation vocabulary. CommandFor expands it
// through the existing single-ticket constructors so bulk and direct paths
// cannot acquire different input validation.
type TicketBulkMutation struct {
	action     Action
	transition Key
	to         Key
	team       EntityID
	assignee   *EntityID
}

func NewTicketBulkTransition(transition, to Key) (TicketBulkMutation, error) {
	if !validKey(transition.value) || !validKey(to.value) {
		return TicketBulkMutation{}, ErrInvalidTicketBulkOperation
	}
	return TicketBulkMutation{action: ActionTransition, transition: transition, to: to}, nil
}

func NewTicketBulkAssignment(team EntityID, assignee *EntityID) (TicketBulkMutation, error) {
	return newTicketBulkAssignmentMutation(ActionAssign, team, assignee)
}

func NewTicketBulkTransfer(team EntityID, assignee *EntityID) (TicketBulkMutation, error) {
	return newTicketBulkAssignmentMutation(ActionTransfer, team, assignee)
}

func NewTicketBulkClaim(team EntityID) (TicketBulkMutation, error) {
	if !validEntityID(team) {
		return TicketBulkMutation{}, ErrInvalidTicketBulkOperation
	}
	return TicketBulkMutation{action: ActionClaim, team: team}, nil
}

func newTicketBulkAssignmentMutation(
	action Action,
	team EntityID,
	assignee *EntityID,
) (TicketBulkMutation, error) {
	if action != ActionAssign && action != ActionTransfer || !validEntityID(team) ||
		assignee != nil && !validEntityID(*assignee) {
		return TicketBulkMutation{}, ErrInvalidTicketBulkOperation
	}
	return TicketBulkMutation{
		action: action, team: team, assignee: cloneTicketBulkEntity(assignee),
	}, nil
}

func NewTicketBulkRelease() TicketBulkMutation {
	return TicketBulkMutation{action: ActionRelease}
}

func (mutation TicketBulkMutation) Action() Action { return mutation.action }
func (mutation TicketBulkMutation) Transition() (Key, Key, bool) {
	return mutation.transition, mutation.to, mutation.action == ActionTransition
}
func (mutation TicketBulkMutation) Assignment() (EntityID, *EntityID, bool) {
	return mutation.team, cloneTicketBulkEntity(mutation.assignee),
		mutation.action == ActionAssign || mutation.action == ActionTransfer
}
func (mutation TicketBulkMutation) ClaimTeam() (EntityID, bool) {
	return mutation.team, mutation.action == ActionClaim
}
func (mutation TicketBulkMutation) String() string {
	return fmt.Sprintf("TicketBulkMutation{action:%s,payload:[REDACTED]}", mutation.action)
}
func (mutation TicketBulkMutation) GoString() string { return mutation.String() }

func validTicketBulkMutation(mutation TicketBulkMutation) bool {
	switch mutation.action {
	case ActionTransition:
		rebuilt, err := NewTicketBulkTransition(mutation.transition, mutation.to)
		return err == nil && sameTicketBulkMutation(rebuilt, mutation)
	case ActionAssign:
		rebuilt, err := NewTicketBulkAssignment(mutation.team, mutation.assignee)
		return err == nil && sameTicketBulkMutation(rebuilt, mutation)
	case ActionTransfer:
		rebuilt, err := NewTicketBulkTransfer(mutation.team, mutation.assignee)
		return err == nil && sameTicketBulkMutation(rebuilt, mutation)
	case ActionClaim:
		rebuilt, err := NewTicketBulkClaim(mutation.team)
		return err == nil && sameTicketBulkMutation(rebuilt, mutation)
	case ActionRelease:
		return sameTicketBulkMutation(NewTicketBulkRelease(), mutation)
	default:
		return false
	}
}

func sameTicketBulkMutation(left, right TicketBulkMutation) bool {
	return left.action == right.action && left.transition == right.transition && left.to == right.to &&
		left.team == right.team && reflect.DeepEqual(left.assignee, right.assignee)
}

type TicketBulkCommand struct {
	action     Action
	transition TransitionCommand
	assign     AssignCommand
	claim      ClaimCommand
	release    ReleaseCommand
	transfer   TransferCommand
}

func (mutation TicketBulkMutation) CommandFor(
	tenant EntityID,
	target TicketBulkTargetPin,
) (TicketBulkCommand, error) {
	if !validTicketBulkMutation(mutation) || !validEntityID(tenant) || !validTicketBulkTargetPin(target) {
		return TicketBulkCommand{}, ErrInvalidTicketBulkOperation
	}
	switch mutation.action {
	case ActionTransition:
		command, err := NewTransitionCommand(
			tenant, target.id, target.version, mutation.transition, mutation.to, nil, nil,
		)
		if err != nil {
			return TicketBulkCommand{}, ErrInvalidTicketBulkOperation
		}
		return TicketBulkCommand{action: mutation.action, transition: command}, nil
	case ActionAssign:
		command, err := NewAssignCommand(tenant, target.id, target.version, mutation.team, mutation.assignee)
		if err != nil {
			return TicketBulkCommand{}, ErrInvalidTicketBulkOperation
		}
		return TicketBulkCommand{action: mutation.action, assign: command}, nil
	case ActionTransfer:
		command, err := NewTransferCommand(tenant, target.id, target.version, mutation.team, mutation.assignee)
		if err != nil {
			return TicketBulkCommand{}, ErrInvalidTicketBulkOperation
		}
		return TicketBulkCommand{action: mutation.action, transfer: command}, nil
	case ActionClaim:
		command, err := NewClaimCommand(tenant, target.id, target.version, mutation.team)
		if err != nil {
			return TicketBulkCommand{}, ErrInvalidTicketBulkOperation
		}
		return TicketBulkCommand{action: mutation.action, claim: command}, nil
	case ActionRelease:
		command, err := NewReleaseCommand(tenant, target.id, target.version)
		if err != nil {
			return TicketBulkCommand{}, ErrInvalidTicketBulkOperation
		}
		return TicketBulkCommand{action: mutation.action, release: command}, nil
	default:
		return TicketBulkCommand{}, ErrInvalidTicketBulkOperation
	}
}

func (command TicketBulkCommand) Action() Action { return command.action }
func (command TicketBulkCommand) TransitionCommand() (TransitionCommand, bool) {
	return command.transition, command.action == ActionTransition
}
func (command TicketBulkCommand) AssignCommand() (AssignCommand, bool) {
	return command.assign, command.action == ActionAssign
}
func (command TicketBulkCommand) ClaimCommand() (ClaimCommand, bool) {
	return command.claim, command.action == ActionClaim
}
func (command TicketBulkCommand) TransferCommand() (TransferCommand, bool) {
	return command.transfer, command.action == ActionTransfer
}
func (command TicketBulkCommand) ReleaseCommand() (ReleaseCommand, bool) {
	return command.release, command.action == ActionRelease
}
func (command TicketBulkCommand) String() string {
	return fmt.Sprintf("TicketBulkCommand{action:%s,payload:[REDACTED]}", command.action)
}
func (command TicketBulkCommand) GoString() string { return command.String() }

// TicketBulkDefinition contains only immutable request and selection pins.
// Live authorization is deliberately not serialized into this value.
type TicketBulkDefinition struct {
	id                EntityID
	tenant            EntityID
	requester         EntityID
	ownerMembership   EntityID
	kind              AggregateKind
	selection         TicketBulkSelection
	mutation          TicketBulkMutation
	projectionVersion uint64
	maximumAttempts   uint8
}

type TicketBulkDefinitionInput struct {
	ID                EntityID
	Tenant            EntityID
	Requester         EntityID
	OwnerMembership   EntityID
	Kind              AggregateKind
	Selection         TicketBulkSelection
	Mutation          TicketBulkMutation
	ProjectionVersion uint64
	MaximumAttempts   uint8
}

func (input TicketBulkDefinitionInput) String() string {
	return fmt.Sprintf(
		"TicketBulkDefinitionInput{kind:%s,action:%s,target_count:%d,projection_version:%d,maximum_attempts:%d,metadata:[REDACTED]}",
		input.Kind, input.Mutation.action, input.Selection.targetCount,
		input.ProjectionVersion, input.MaximumAttempts,
	)
}

func (input TicketBulkDefinitionInput) GoString() string { return input.String() }

func NewTicketBulkDefinition(input TicketBulkDefinitionInput) (TicketBulkDefinition, error) {
	if !validEntityID(input.ID) || !validEntityID(input.Tenant) || !validEntityID(input.Requester) ||
		!validEntityID(input.OwnerMembership) || !validAggregateKind(input.Kind) ||
		!validTicketBulkSelection(input.Selection) || !validTicketBulkMutation(input.Mutation) ||
		input.ProjectionVersion != TicketBulkProjectionVersion || input.MaximumAttempts == 0 ||
		input.MaximumAttempts > TicketBulkMaximumAttempts {
		return TicketBulkDefinition{}, ErrInvalidTicketBulkOperation
	}
	if _, ok := permissionFor(input.Kind, input.Mutation.action); !ok {
		return TicketBulkDefinition{}, ErrInvalidTicketBulkOperation
	}
	if input.Selection.savedView != nil && input.Selection.savedView.owner != input.OwnerMembership {
		return TicketBulkDefinition{}, ErrInvalidTicketBulkOperation
	}
	return TicketBulkDefinition{
		id: input.ID, tenant: input.Tenant, requester: input.Requester,
		ownerMembership: input.OwnerMembership, kind: input.Kind,
		selection:         cloneTicketBulkSelection(input.Selection),
		mutation:          cloneTicketBulkMutation(input.Mutation),
		projectionVersion: input.ProjectionVersion, maximumAttempts: input.MaximumAttempts,
	}, nil
}

func (definition TicketBulkDefinition) ID() EntityID              { return definition.id }
func (definition TicketBulkDefinition) Tenant() EntityID          { return definition.tenant }
func (definition TicketBulkDefinition) Requester() EntityID       { return definition.requester }
func (definition TicketBulkDefinition) OwnerMembership() EntityID { return definition.ownerMembership }
func (definition TicketBulkDefinition) Kind() AggregateKind       { return definition.kind }
func (definition TicketBulkDefinition) Selection() TicketBulkSelection {
	return cloneTicketBulkSelection(definition.selection)
}
func (definition TicketBulkDefinition) Mutation() TicketBulkMutation {
	return cloneTicketBulkMutation(definition.mutation)
}
func (definition TicketBulkDefinition) ProjectionVersion() uint64 {
	return definition.projectionVersion
}
func (definition TicketBulkDefinition) MaximumAttempts() uint8 { return definition.maximumAttempts }
func (definition TicketBulkDefinition) RequiredPermission() Permission {
	permission, _ := permissionFor(definition.kind, definition.mutation.action)
	return permission
}
func (definition TicketBulkDefinition) String() string {
	return fmt.Sprintf(
		"TicketBulkDefinition{kind:%s,action:%s,target_count:%d,metadata:[REDACTED]}",
		definition.kind, definition.mutation.action, definition.selection.targetCount,
	)
}
func (definition TicketBulkDefinition) GoString() string { return definition.String() }

func ValidateTicketBulkDefinition(definition TicketBulkDefinition) error {
	_, err := NewTicketBulkDefinition(TicketBulkDefinitionInput{
		ID: definition.id, Tenant: definition.tenant, Requester: definition.requester,
		OwnerMembership: definition.ownerMembership, Kind: definition.kind,
		Selection: definition.selection, Mutation: definition.mutation,
		ProjectionVersion: definition.projectionVersion, MaximumAttempts: definition.maximumAttempts,
	})
	return err
}

func cloneTicketBulkSelection(selection TicketBulkSelection) TicketBulkSelection {
	result := selection
	result.explicitTargets = slices.Clone(selection.explicitTargets)
	result.savedView = cloneTicketBulkSavedViewPin(selection.savedView)
	return result
}

func cloneTicketBulkMutation(mutation TicketBulkMutation) TicketBulkMutation {
	result := mutation
	result.assignee = cloneTicketBulkEntity(mutation.assignee)
	return result
}

func cloneTicketBulkSavedViewPin(value *TicketBulkSavedViewPin) *TicketBulkSavedViewPin {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneTicketBulkEntity(value *EntityID) *EntityID {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}
