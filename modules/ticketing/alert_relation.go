package ticketing

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxAlertRelationReasonBytes = 2_000

// AlertRelationKind describes evidence between two independent Alert
// aggregates. Neither kind authorizes field or state merging.
type AlertRelationKind uint8

const (
	AlertRelationDuplicateOf AlertRelationKind = iota + 1
	AlertRelationCorrelation
)

func ParseAlertRelationKind(value string) (AlertRelationKind, error) {
	switch value {
	case "duplicate_of":
		return AlertRelationDuplicateOf, nil
	case "correlation":
		return AlertRelationCorrelation, nil
	default:
		return 0, ErrInvalidEscalation
	}
}

// AlertRelationReason is immutable operator-authored plain text explaining an
// explicit Alert-to-Alert relation or its retraction. It intentionally accepts
// angle brackets as ordinary text while rejecting every control and bidi
// character so the value has one transport and persistence representation.
type AlertRelationReason struct {
	value string
}

func NewAlertRelationReason(value string) (AlertRelationReason, error) {
	if value == "" || len(value) > maxAlertRelationReasonBytes ||
		!utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return AlertRelationReason{}, ErrInvalidEscalation
	}
	for _, character := range value {
		if unicode.IsControl(character) || isDirectionalControl(character) {
			return AlertRelationReason{}, ErrInvalidEscalation
		}
	}
	return AlertRelationReason{value: value}, nil
}

func (reason AlertRelationReason) Value() string { return reason.value }
func (reason AlertRelationReason) String() string {
	return fmt.Sprintf("AlertRelationReason{bytes:%d,value:[REDACTED]}", len(reason.value))
}
func (reason AlertRelationReason) GoString() string { return reason.String() }

func validAlertRelationReason(reason AlertRelationReason) bool {
	validated, err := NewAlertRelationReason(reason.value)
	return err == nil && validated.value == reason.value
}

func (kind AlertRelationKind) String() string {
	switch kind {
	case AlertRelationDuplicateOf:
		return "duplicate_of"
	case AlertRelationCorrelation:
		return "correlation"
	default:
		return "unknown"
	}
}

// AlertRelationPlan is the closed, non-merging version transition for an
// explicit relation. Persistence still rechecks both CAS pins and authority.
type AlertRelationPlan struct {
	tenant                EntityID
	actor                 EntityID
	source                EntityID
	target                EntityID
	kind                  AlertRelationKind
	reason                AlertRelationReason
	previousSourceVersion uint64
	sourceVersion         uint64
	previousTargetVersion uint64
	targetVersion         uint64
}

func PlanAlertRelation(
	tenant EntityID,
	actor EntityID,
	source EntityID,
	target EntityID,
	kind AlertRelationKind,
	reason AlertRelationReason,
	expectedSourceVersion uint64,
	expectedTargetVersion uint64,
	authority AuthorizationSnapshot,
) (AlertRelationPlan, error) {
	if !validEntityID(tenant) || !validEntityID(actor) || !validEntityID(source) ||
		!validEntityID(target) || source == target ||
		kind < AlertRelationDuplicateOf || kind > AlertRelationCorrelation ||
		!validAlertRelationReason(reason) ||
		expectedSourceVersion == 0 || expectedSourceVersion >= maxVersion ||
		expectedTargetVersion == 0 || expectedTargetVersion >= maxVersion ||
		!validAuthorizationSnapshot(authority) || !authority.tenantAccess ||
		authority.tenant != tenant || authority.actor != actor ||
		authority.principal != PrincipalOperator ||
		!authority.hasPermission(PermissionAlertRead) ||
		!authority.hasPermission(PermissionAlertUpdate) {
		return AlertRelationPlan{}, ErrInvalidEscalation
	}
	return AlertRelationPlan{
		tenant: tenant, actor: actor, source: source, target: target,
		kind: kind, reason: reason,
		previousSourceVersion: expectedSourceVersion,
		sourceVersion:         expectedSourceVersion + 1,
		previousTargetVersion: expectedTargetVersion,
		targetVersion:         expectedTargetVersion + 1,
	}, nil
}

func (plan AlertRelationPlan) Tenant() EntityID              { return plan.tenant }
func (plan AlertRelationPlan) Actor() EntityID               { return plan.actor }
func (plan AlertRelationPlan) Source() EntityID              { return plan.source }
func (plan AlertRelationPlan) Target() EntityID              { return plan.target }
func (plan AlertRelationPlan) Kind() AlertRelationKind       { return plan.kind }
func (plan AlertRelationPlan) Reason() AlertRelationReason   { return plan.reason }
func (plan AlertRelationPlan) PreviousSourceVersion() uint64 { return plan.previousSourceVersion }
func (plan AlertRelationPlan) SourceVersion() uint64         { return plan.sourceVersion }
func (plan AlertRelationPlan) PreviousTargetVersion() uint64 { return plan.previousTargetVersion }
func (plan AlertRelationPlan) TargetVersion() uint64         { return plan.targetVersion }
func (plan AlertRelationPlan) String() string {
	return fmt.Sprintf(
		"AlertRelationPlan{kind:%s,source_version:%d,target_version:%d,reason:[REDACTED]}",
		plan.kind, plan.sourceVersion, plan.targetVersion,
	)
}
func (plan AlertRelationPlan) GoString() string { return plan.String() }
