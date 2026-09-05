package platform

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const maximumTenantLifecycleReasonBytes = 2 * 1024

var (
	ErrInvalidTenantLifecycle  = errors.New("invalid tenant lifecycle command")
	ErrTenantLifecycleConflict = errors.New("tenant lifecycle revision conflict")
	ErrTenantLifecycleNoChange = errors.New("tenant lifecycle command has no change")
)

type TenantLifecycleStatus string

const (
	TenantLifecycleActive    TenantLifecycleStatus = "active"
	TenantLifecycleSuspended TenantLifecycleStatus = "suspended"
)

func validTenantLifecycleStatus(status TenantLifecycleStatus) bool {
	return status == TenantLifecycleActive || status == TenantLifecycleSuspended
}

type TenantLifecycleAction string

const (
	TenantLifecycleSuspend    TenantLifecycleAction = "suspend"
	TenantLifecycleReactivate TenantLifecycleAction = "reactivate"
)

// TenantLifecycleCommand is the canonical, persistence-independent request.
// It contains no authority snapshot; repositories must resolve the actor's
// current platform permission again in the mutation transaction.
type TenantLifecycleCommand struct {
	tenantID        uuid.UUID
	target          TenantLifecycleStatus
	expectedVersion int32
	reason          string
}

func NewTenantLifecycleCommand(
	tenantID uuid.UUID,
	target TenantLifecycleStatus,
	expectedVersion int32,
	reason string,
) (TenantLifecycleCommand, error) {
	if !validPlatformTenantID(tenantID) || !validTenantLifecycleStatus(target) ||
		expectedVersion <= 0 || expectedVersion >= math.MaxInt32 ||
		!validTenantLifecycleReason(reason) {
		return TenantLifecycleCommand{}, ErrInvalidTenantLifecycle
	}
	return TenantLifecycleCommand{
		tenantID: tenantID, target: target, expectedVersion: expectedVersion, reason: reason,
	}, nil
}

func (command TenantLifecycleCommand) TenantID() uuid.UUID           { return command.tenantID }
func (command TenantLifecycleCommand) Target() TenantLifecycleStatus { return command.target }
func (command TenantLifecycleCommand) ExpectedVersion() int32        { return command.expectedVersion }
func (command TenantLifecycleCommand) Reason() string                { return command.reason }
func (command TenantLifecycleCommand) String() string {
	return fmt.Sprintf(
		"TenantLifecycleCommand{target:%s,expected_version:%d,metadata:[REDACTED]}",
		command.target, command.expectedVersion,
	)
}
func (command TenantLifecycleCommand) GoString() string { return command.String() }

func ValidateTenantLifecycleCommand(command TenantLifecycleCommand) error {
	rebuilt, err := NewTenantLifecycleCommand(
		command.tenantID, command.target, command.expectedVersion, command.reason,
	)
	if err != nil || rebuilt != command {
		return ErrInvalidTenantLifecycle
	}
	return nil
}

// TenantLifecyclePlan is the pure optimistic transition consumed by the
// platform database command. PostgreSQL must recheck permission, status, and
// ExpectedVersion and append platform audit in the same transaction.
type TenantLifecyclePlan struct {
	tenantID        uuid.UUID
	action          TenantLifecycleAction
	previous        TenantLifecycleStatus
	next            TenantLifecycleStatus
	expectedVersion int32
	nextVersion     int32
	reason          string
}

func PlanTenantLifecycleChange(
	tenantID uuid.UUID,
	current TenantLifecycleStatus,
	currentVersion int32,
	expectedVersion int32,
	target TenantLifecycleStatus,
	reason string,
) (TenantLifecyclePlan, error) {
	command, err := NewTenantLifecycleCommand(tenantID, target, expectedVersion, reason)
	if err != nil {
		return TenantLifecyclePlan{}, err
	}
	return PlanTenantLifecycleCommand(current, currentVersion, command)
}

func PlanTenantLifecycleCommand(
	current TenantLifecycleStatus,
	currentVersion int32,
	command TenantLifecycleCommand,
) (TenantLifecyclePlan, error) {
	if ValidateTenantLifecycleCommand(command) != nil || !validTenantLifecycleStatus(current) ||
		currentVersion <= 0 {
		return TenantLifecyclePlan{}, ErrInvalidTenantLifecycle
	}
	if currentVersion != command.expectedVersion {
		return TenantLifecyclePlan{}, ErrTenantLifecycleConflict
	}
	if current == command.target {
		return TenantLifecyclePlan{}, ErrTenantLifecycleNoChange
	}
	if currentVersion == math.MaxInt32 {
		return TenantLifecyclePlan{}, ErrInvalidTenantLifecycle
	}
	action := TenantLifecycleSuspend
	if current == TenantLifecycleSuspended && command.target == TenantLifecycleActive {
		action = TenantLifecycleReactivate
	} else if current != TenantLifecycleActive || command.target != TenantLifecycleSuspended {
		return TenantLifecyclePlan{}, ErrInvalidTenantLifecycle
	}
	return TenantLifecyclePlan{
		tenantID: command.tenantID, action: action, previous: current, next: command.target,
		expectedVersion: command.expectedVersion, nextVersion: currentVersion + 1, reason: command.reason,
	}, nil
}

func (plan TenantLifecyclePlan) TenantID() uuid.UUID             { return plan.tenantID }
func (plan TenantLifecyclePlan) Action() TenantLifecycleAction   { return plan.action }
func (plan TenantLifecyclePlan) Previous() TenantLifecycleStatus { return plan.previous }
func (plan TenantLifecyclePlan) Next() TenantLifecycleStatus     { return plan.next }
func (plan TenantLifecyclePlan) ExpectedVersion() int32          { return plan.expectedVersion }
func (plan TenantLifecyclePlan) NextVersion() int32              { return plan.nextVersion }
func (plan TenantLifecyclePlan) Reason() string                  { return plan.reason }
func (plan TenantLifecyclePlan) String() string {
	return fmt.Sprintf(
		"TenantLifecyclePlan{action:%s,previous:%s,next:%s,expected_version:%d,next_version:%d,metadata:[REDACTED]}",
		plan.action, plan.previous, plan.next, plan.expectedVersion, plan.nextVersion,
	)
}
func (plan TenantLifecyclePlan) GoString() string { return plan.String() }

func ValidateTenantLifecyclePlan(plan TenantLifecyclePlan) error {
	rebuilt, err := PlanTenantLifecycleChange(
		plan.tenantID, plan.previous, plan.expectedVersion, plan.expectedVersion,
		plan.next, plan.reason,
	)
	if err != nil || rebuilt != plan {
		return ErrInvalidTenantLifecycle
	}
	return nil
}

func validPlatformTenantID(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validTenantLifecycleReason(value string) bool {
	if value == "" || len(value) > maximumTenantLifecycleReasonBytes || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}
