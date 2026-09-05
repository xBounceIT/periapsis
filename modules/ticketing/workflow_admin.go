package ticketing

import (
	"errors"
	"fmt"
	"reflect"
)

const (
	maxWorkflowDisplayNameBytes = 120
	maxWorkflowDescriptionBytes = 1_000
)

var (
	ErrInvalidWorkflowAdministration = errors.New("invalid workflow administration state")
	ErrWorkflowRevisionConflict      = errors.New("workflow administration revision conflict")
	ErrWorkflowInactive              = errors.New("workflow is not active")
	ErrWorkflowDefaultArchive        = errors.New("default workflow cannot be archived")
	ErrWorkflowNoChange              = errors.New("workflow administration command has no change")
)

// WorkflowStatus is the closed lifecycle of a managed workflow. Archival only
// prevents future selection; published definitions remain immutable and usable
// by tickets already pinned to them.
type WorkflowStatus uint8

const (
	WorkflowActive WorkflowStatus = iota + 1
	WorkflowArchived
)

func (status WorkflowStatus) String() string {
	switch status {
	case WorkflowActive:
		return "active"
	case WorkflowArchived:
		return "archived"
	default:
		return "unknown"
	}
}

func validWorkflowStatus(status WorkflowStatus) bool {
	return status == WorkflowActive || status == WorkflowArchived
}

// ManagedWorkflow is the tenant-owned administration aggregate around the
// current immutable WorkflowDefinition. Revision is independent from the
// published definition version so metadata/default/archive changes can use
// optimistic concurrency without manufacturing an empty published version.
type ManagedWorkflow struct {
	tenant      EntityID
	key         Key
	displayName string
	description string
	isDefault   bool
	status      WorkflowStatus
	revision    uint64
	current     WorkflowDefinition
}

func NewManagedWorkflow(
	tenant EntityID,
	key Key,
	displayName string,
	description string,
	isDefault bool,
	status WorkflowStatus,
	revision uint64,
	current WorkflowDefinition,
) (ManagedWorkflow, error) {
	if !validEntityID(tenant) || !validWorkflowCatalogKey(key) ||
		!validText(displayName, maxWorkflowDisplayNameBytes, false) ||
		!validOptionalWorkflowText(description, maxWorkflowDescriptionBytes) ||
		!validWorkflowStatus(status) || revision == 0 || revision > maxVersion ||
		!validWorkflowDefinition(current) || status == WorkflowArchived && isDefault {
		return ManagedWorkflow{}, ErrInvalidWorkflowAdministration
	}
	return ManagedWorkflow{
		tenant: tenant, key: key, displayName: displayName, description: description,
		isDefault: isDefault, status: status, revision: revision,
		current: cloneWorkflowDefinition(current),
	}, nil
}

func (workflow ManagedWorkflow) Tenant() EntityID       { return workflow.tenant }
func (workflow ManagedWorkflow) ID() EntityID           { return workflow.current.id }
func (workflow ManagedWorkflow) Kind() AggregateKind    { return workflow.current.kind }
func (workflow ManagedWorkflow) Key() Key               { return workflow.key }
func (workflow ManagedWorkflow) DisplayName() string    { return workflow.displayName }
func (workflow ManagedWorkflow) Description() string    { return workflow.description }
func (workflow ManagedWorkflow) IsDefault() bool        { return workflow.isDefault }
func (workflow ManagedWorkflow) Status() WorkflowStatus { return workflow.status }
func (workflow ManagedWorkflow) Revision() uint64       { return workflow.revision }
func (workflow ManagedWorkflow) CurrentVersion() uint64 { return workflow.current.version }
func (workflow ManagedWorkflow) Current() WorkflowDefinition {
	return cloneWorkflowDefinition(workflow.current)
}

func (workflow ManagedWorkflow) String() string {
	return fmt.Sprintf(
		"ManagedWorkflow{kind:%s,status:%s,default:%t,published_version:%d,revision:%d,metadata:[REDACTED]}",
		workflow.Kind(), workflow.status, workflow.isDefault, workflow.CurrentVersion(), workflow.revision,
	)
}

func validManagedWorkflow(workflow ManagedWorkflow) bool {
	rebuilt, err := NewManagedWorkflow(
		workflow.tenant, workflow.key, workflow.displayName, workflow.description,
		workflow.isDefault, workflow.status, workflow.revision, workflow.current,
	)
	return err == nil && sameManagedWorkflow(rebuilt, workflow)
}

func validWorkflowCatalogKey(key Key) bool {
	value := key.value
	if !validKey(value) || len(value) < 3 {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validOptionalWorkflowText(value string, maximum int) bool {
	return value == "" || validText(value, maximum, false)
}

// WorkflowAdministrationAction is the closed command vocabulary persisted in
// idempotency, activity, and audit records.
type WorkflowAdministrationAction uint8

const (
	WorkflowAdministrationCreate WorkflowAdministrationAction = iota + 1
	WorkflowAdministrationPublish
	WorkflowAdministrationUpdateMetadata
	WorkflowAdministrationSetDefault
	WorkflowAdministrationArchive
	WorkflowAdministrationRestore
)

func (action WorkflowAdministrationAction) String() string {
	switch action {
	case WorkflowAdministrationCreate:
		return "create"
	case WorkflowAdministrationPublish:
		return "publish"
	case WorkflowAdministrationUpdateMetadata:
		return "update_metadata"
	case WorkflowAdministrationSetDefault:
		return "set_default"
	case WorkflowAdministrationArchive:
		return "archive"
	case WorkflowAdministrationRestore:
		return "restore"
	default:
		return "unknown"
	}
}

func validWorkflowAdministrationAction(action WorkflowAdministrationAction) bool {
	return action >= WorkflowAdministrationCreate && action <= WorkflowAdministrationRestore
}

// WorkflowAdministrationPlan is a deterministic CAS intent. Set-default may
// also carry the exact current default to displace in the same transaction.
// Create and publish plans append a new immutable definition; other commands
// retain the current definition byte-for-byte.
type WorkflowAdministrationPlan struct {
	action                   WorkflowAdministrationAction
	expectedRevision         uint64
	next                     ManagedWorkflow
	publishesDefinition      bool
	displacedDefault         ManagedWorkflow
	displacedDefaultExpected uint64
	hasDisplacedDefault      bool
}

func (plan WorkflowAdministrationPlan) Action() WorkflowAdministrationAction { return plan.action }
func (plan WorkflowAdministrationPlan) ExpectedRevision() uint64             { return plan.expectedRevision }
func (plan WorkflowAdministrationPlan) Next() ManagedWorkflow                { return cloneManagedWorkflow(plan.next) }
func (plan WorkflowAdministrationPlan) PublishesDefinition() bool            { return plan.publishesDefinition }

func (plan WorkflowAdministrationPlan) DisplacedDefault() (ManagedWorkflow, uint64, bool) {
	if !plan.hasDisplacedDefault {
		return ManagedWorkflow{}, 0, false
	}
	return cloneManagedWorkflow(plan.displacedDefault), plan.displacedDefaultExpected, true
}

func (plan WorkflowAdministrationPlan) String() string {
	return fmt.Sprintf(
		"WorkflowAdministrationPlan{action:%s,kind:%s,expected_revision:%d,next_revision:%d,published_version:%d,displaces_default:%t}",
		plan.action, plan.next.Kind(), plan.expectedRevision, plan.next.revision,
		plan.next.CurrentVersion(), plan.hasDisplacedDefault,
	)
}

func PlanWorkflowCreation(
	tenant EntityID,
	key Key,
	displayName string,
	description string,
	definition WorkflowDefinition,
) (WorkflowAdministrationPlan, error) {
	if !validWorkflowDefinition(definition) || definition.version != 1 {
		return WorkflowAdministrationPlan{}, ErrInvalidWorkflowAdministration
	}
	next, err := NewManagedWorkflow(
		tenant, key, displayName, description, false, WorkflowActive, 1, definition,
	)
	if err != nil {
		return WorkflowAdministrationPlan{}, err
	}
	return WorkflowAdministrationPlan{
		action: WorkflowAdministrationCreate, next: next, publishesDefinition: true,
	}, nil
}

func PlanWorkflowPublication(
	current ManagedWorkflow,
	expectedRevision uint64,
	definition WorkflowDefinition,
) (WorkflowAdministrationPlan, error) {
	if err := validateWorkflowAdministrationTarget(current, expectedRevision, true); err != nil {
		return WorkflowAdministrationPlan{}, err
	}
	if !validWorkflowDefinition(definition) || definition.id != current.ID() ||
		definition.kind != current.Kind() || current.CurrentVersion() == maxVersion ||
		definition.version != current.CurrentVersion()+1 {
		return WorkflowAdministrationPlan{}, ErrInvalidWorkflowAdministration
	}
	if sameWorkflowDesign(current.current, definition) {
		return WorkflowAdministrationPlan{}, ErrWorkflowNoChange
	}
	next, err := NewManagedWorkflow(
		current.tenant, current.key, current.displayName, current.description,
		current.isDefault, current.status, current.revision+1, definition,
	)
	if err != nil {
		return WorkflowAdministrationPlan{}, err
	}
	return WorkflowAdministrationPlan{
		action: WorkflowAdministrationPublish, expectedRevision: expectedRevision,
		next: next, publishesDefinition: true,
	}, nil
}

func PlanWorkflowMetadataUpdate(
	current ManagedWorkflow,
	expectedRevision uint64,
	displayName string,
	description string,
) (WorkflowAdministrationPlan, error) {
	if err := validateWorkflowAdministrationTarget(current, expectedRevision, true); err != nil {
		return WorkflowAdministrationPlan{}, err
	}
	if current.displayName == displayName && current.description == description {
		return WorkflowAdministrationPlan{}, ErrWorkflowNoChange
	}
	next, err := NewManagedWorkflow(
		current.tenant, current.key, displayName, description, current.isDefault,
		current.status, current.revision+1, current.current,
	)
	if err != nil {
		return WorkflowAdministrationPlan{}, err
	}
	return WorkflowAdministrationPlan{
		action: WorkflowAdministrationUpdateMetadata, expectedRevision: expectedRevision, next: next,
	}, nil
}

func PlanWorkflowSetDefault(
	current ManagedWorkflow,
	expectedRevision uint64,
	previousDefault *ManagedWorkflow,
) (WorkflowAdministrationPlan, error) {
	if err := validateWorkflowAdministrationTarget(current, expectedRevision, true); err != nil {
		return WorkflowAdministrationPlan{}, err
	}
	if current.isDefault {
		return WorkflowAdministrationPlan{}, ErrWorkflowNoChange
	}
	next, err := NewManagedWorkflow(
		current.tenant, current.key, current.displayName, current.description,
		true, current.status, current.revision+1, current.current,
	)
	if err != nil {
		return WorkflowAdministrationPlan{}, err
	}
	plan := WorkflowAdministrationPlan{
		action: WorkflowAdministrationSetDefault, expectedRevision: expectedRevision, next: next,
	}
	if previousDefault == nil {
		return plan, nil
	}
	previous := *previousDefault
	if !validManagedWorkflow(previous) || previous.tenant != current.tenant || previous.Kind() != current.Kind() ||
		previous.ID() == current.ID() || previous.status != WorkflowActive || !previous.isDefault ||
		previous.revision == maxVersion {
		return WorkflowAdministrationPlan{}, ErrInvalidWorkflowAdministration
	}
	displaced, rebuildErr := NewManagedWorkflow(
		previous.tenant, previous.key, previous.displayName, previous.description,
		false, previous.status, previous.revision+1, previous.current,
	)
	if rebuildErr != nil {
		return WorkflowAdministrationPlan{}, rebuildErr
	}
	plan.displacedDefault = displaced
	plan.displacedDefaultExpected = previous.revision
	plan.hasDisplacedDefault = true
	return plan, nil
}

func PlanWorkflowArchive(current ManagedWorkflow, expectedRevision uint64) (WorkflowAdministrationPlan, error) {
	if err := validateWorkflowAdministrationTarget(current, expectedRevision, true); err != nil {
		return WorkflowAdministrationPlan{}, err
	}
	if current.isDefault {
		return WorkflowAdministrationPlan{}, ErrWorkflowDefaultArchive
	}
	next, err := NewManagedWorkflow(
		current.tenant, current.key, current.displayName, current.description,
		false, WorkflowArchived, current.revision+1, current.current,
	)
	if err != nil {
		return WorkflowAdministrationPlan{}, err
	}
	return WorkflowAdministrationPlan{
		action: WorkflowAdministrationArchive, expectedRevision: expectedRevision, next: next,
	}, nil
}

func PlanWorkflowRestore(current ManagedWorkflow, expectedRevision uint64) (WorkflowAdministrationPlan, error) {
	if err := validateWorkflowAdministrationTarget(current, expectedRevision, false); err != nil {
		return WorkflowAdministrationPlan{}, err
	}
	if current.status != WorkflowArchived {
		return WorkflowAdministrationPlan{}, ErrWorkflowNoChange
	}
	next, err := NewManagedWorkflow(
		current.tenant, current.key, current.displayName, current.description,
		false, WorkflowActive, current.revision+1, current.current,
	)
	if err != nil {
		return WorkflowAdministrationPlan{}, err
	}
	return WorkflowAdministrationPlan{
		action: WorkflowAdministrationRestore, expectedRevision: expectedRevision, next: next,
	}, nil
}

func validateWorkflowAdministrationTarget(
	current ManagedWorkflow,
	expectedRevision uint64,
	requireActive bool,
) error {
	if !validManagedWorkflow(current) || expectedRevision == 0 || expectedRevision > maxVersion {
		return ErrInvalidWorkflowAdministration
	}
	if current.revision != expectedRevision {
		return ErrWorkflowRevisionConflict
	}
	if current.revision == maxVersion {
		return ErrWorkflowRevisionConflict
	}
	if requireActive && current.status != WorkflowActive {
		return ErrWorkflowInactive
	}
	return nil
}

func cloneManagedWorkflow(workflow ManagedWorkflow) ManagedWorkflow {
	result := workflow
	result.current = cloneWorkflowDefinition(workflow.current)
	return result
}

func cloneWorkflowDefinition(definition WorkflowDefinition) WorkflowDefinition {
	result := definition
	result.states = cloneStates(definition.states)
	result.transitions = cloneTransitions(definition.transitions)
	return result
}

func sameManagedWorkflow(left, right ManagedWorkflow) bool {
	return left.tenant == right.tenant && left.key == right.key &&
		left.displayName == right.displayName && left.description == right.description &&
		left.isDefault == right.isDefault && left.status == right.status &&
		left.revision == right.revision && sameWorkflowDefinition(left.current, right.current)
}

func sameWorkflowDefinition(left, right WorkflowDefinition) bool {
	return left.id == right.id && left.kind == right.kind && left.version == right.version &&
		left.initial == right.initial && reflect.DeepEqual(left.states, right.states) &&
		reflect.DeepEqual(left.transitions, right.transitions)
}

func sameWorkflowDesign(left, right WorkflowDefinition) bool {
	return left.kind == right.kind && left.initial == right.initial &&
		reflect.DeepEqual(left.states, right.states) && reflect.DeepEqual(left.transitions, right.transitions)
}
