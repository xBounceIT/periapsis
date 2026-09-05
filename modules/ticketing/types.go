package ticketing

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxKeyBytes              = 64
	maxWorkflowStates        = 64
	maxWorkflowTransitions   = 256
	maxRequirements          = 64
	maxCustomFieldValues     = 100
	maxCommentScalars        = 20_000
	maxEscalationReasonBytes = 2 * 1024
	maxEscalationAlerts      = 100
	maxCopiedItems           = 600
	maxAuthorityItems        = 1_024
	maxVersion               = uint64(math.MaxInt64)
)

var (
	ErrInvalidID         = errors.New("invalid ticketing entity id")
	ErrInvalidKey        = errors.New("invalid ticketing key")
	ErrInvalidWorkflow   = errors.New("invalid ticketing workflow")
	ErrInvalidTicket     = errors.New("invalid ticket snapshot")
	ErrInvalidAuthority  = errors.New("invalid authorization snapshot")
	ErrInvalidCommand    = errors.New("invalid ticketing command")
	ErrInvalidComment    = errors.New("invalid comment")
	ErrInvalidEscalation = errors.New("invalid alert escalation")
	ErrPlanDoesNotApply  = errors.New("ticketing mutation plan does not apply")
)

// EntityID is a validated RFC 9562 UUIDv7. It is comparable and safe as a map key.
// The constructor is the only supported way to obtain a non-zero value.
type EntityID struct {
	value [16]byte
}

func NewEntityID(value [16]byte) (EntityID, error) {
	if value[6]>>4 != 7 || value[8]&0xc0 != 0x80 {
		return EntityID{}, ErrInvalidID
	}
	return EntityID{value: value}, nil
}

func (id EntityID) Bytes() [16]byte { return id.value }

func (id EntityID) String() string {
	v := id.value
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		v[0:4], v[4:6], v[6:8], v[8:10], v[10:16])
}

func validEntityID(id EntityID) bool {
	return id.value[6]>>4 == 7 && id.value[8]&0xc0 == 0x80
}

func compareEntityID(left, right EntityID) int {
	return bytes.Compare(left.value[:], right.value[:])
}

// Key is the canonical identifier used for workflow states, roles, and custom fields.
// It deliberately accepts only a small ASCII vocabulary so ordering and equality do not
// depend on locale or Unicode normalization.
type Key struct {
	value string
}

func NewKey(value string) (Key, error) {
	if !validKey(value) {
		return Key{}, ErrInvalidKey
	}
	return Key{value: value}, nil
}

func (key Key) String() string { return key.value }

func validKey(value string) bool {
	if len(value) == 0 || len(value) > maxKeyBytes || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '_' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}

type AggregateKind uint8

const (
	AggregateAlert AggregateKind = iota + 1
	AggregateCase
)

func (kind AggregateKind) String() string {
	switch kind {
	case AggregateAlert:
		return "alert"
	case AggregateCase:
		return "case"
	default:
		return "unknown"
	}
}

func validAggregateKind(kind AggregateKind) bool {
	return kind == AggregateAlert || kind == AggregateCase
}

type Action uint8

const (
	ActionCreate Action = iota + 1
	ActionTransition
	ActionAssign
	ActionClaim
	ActionRelease
	ActionTransfer
	ActionEscalate
	ActionLink
)

func (action Action) String() string {
	switch action {
	case ActionCreate:
		return "create"
	case ActionTransition:
		return "transition"
	case ActionAssign:
		return "assign"
	case ActionClaim:
		return "claim"
	case ActionRelease:
		return "release"
	case ActionTransfer:
		return "transfer"
	case ActionEscalate:
		return "escalate"
	case ActionLink:
		return "link"
	default:
		return "unknown"
	}
}

func validAction(action Action) bool {
	return action >= ActionCreate && action <= ActionLink
}

// TransitionIntent constrains an otherwise allowlisted workflow transition to
// the semantics promised by an explicit HTTP command. The empty value keeps
// the generic transition command backward compatible.
type TransitionIntent string

const (
	TransitionIntentAny    TransitionIntent = ""
	TransitionIntentClose  TransitionIntent = "close"
	TransitionIntentReopen TransitionIntent = "reopen"
)

func (intent TransitionIntent) String() string { return string(intent) }

func validTransitionIntent(intent TransitionIntent) bool {
	return intent == TransitionIntentAny || intent == TransitionIntentClose || intent == TransitionIntentReopen
}

// Permission is the closed ticketing permission vocabulary. Every public
// constructor rejects values outside these constants.
type Permission uint8

const (
	PermissionAlertCreate Permission = iota + 1
	PermissionAlertRead
	PermissionAlertUpdate
	PermissionAlertAssign
	PermissionAlertClaim
	PermissionAlertEscalate
	PermissionAlertCommentPublic
	PermissionAlertCommentPrivate
	PermissionCaseCreate
	PermissionCaseUpdate
	PermissionCaseClaim
	PermissionCaseTransfer
	PermissionCaseTransition
	PermissionCaseCommentPublic
	PermissionCaseCommentPrivate
	PermissionPortalCommentPublic
)

var knownPermissions = [...]Permission{
	PermissionAlertCreate,
	PermissionAlertRead,
	PermissionAlertUpdate,
	PermissionAlertAssign,
	PermissionAlertClaim,
	PermissionAlertEscalate,
	PermissionAlertCommentPublic,
	PermissionAlertCommentPrivate,
	PermissionCaseCreate,
	PermissionCaseUpdate,
	PermissionCaseClaim,
	PermissionCaseTransfer,
	PermissionCaseTransition,
	PermissionCaseCommentPublic,
	PermissionCaseCommentPrivate,
	PermissionPortalCommentPublic,
}

func ParsePermission(value string) (Permission, error) {
	for _, permission := range knownPermissions {
		if permission.String() == value {
			return permission, nil
		}
	}
	return Permission(0), ErrInvalidAuthority
}

func (permission Permission) String() string {
	switch permission {
	case PermissionAlertCreate:
		return "alert.create"
	case PermissionAlertRead:
		return "alert.read"
	case PermissionAlertUpdate:
		return "alert.update"
	case PermissionAlertAssign:
		return "alert.assign"
	case PermissionAlertClaim:
		return "alert.claim"
	case PermissionAlertEscalate:
		return "alert.escalate"
	case PermissionAlertCommentPublic:
		return "alert.comment.public"
	case PermissionAlertCommentPrivate:
		return "alert.comment.private"
	case PermissionCaseCreate:
		return "case.create"
	case PermissionCaseUpdate:
		return "case.update"
	case PermissionCaseClaim:
		return "case.claim"
	case PermissionCaseTransfer:
		return "case.transfer"
	case PermissionCaseTransition:
		return "case.transition"
	case PermissionCaseCommentPublic:
		return "case.comment.public"
	case PermissionCaseCommentPrivate:
		return "case.comment.private"
	case PermissionPortalCommentPublic:
		return "portal.comment.public"
	default:
		return "unknown"
	}
}

func validPermission(permission Permission) bool {
	return permission >= PermissionAlertCreate && permission <= PermissionPortalCommentPublic
}

func permissionBelongsToKind(permission Permission, kind AggregateKind) bool {
	if !validPermission(permission) || !validAggregateKind(kind) {
		return false
	}
	return kind == AggregateAlert && strings.HasPrefix(permission.String(), "alert.") ||
		kind == AggregateCase && strings.HasPrefix(permission.String(), "case.")
}

func permissionFor(kind AggregateKind, action Action) (Permission, bool) {
	switch kind {
	case AggregateAlert:
		switch action {
		case ActionCreate:
			return PermissionAlertCreate, true
		case ActionTransition:
			return PermissionAlertUpdate, true
		case ActionAssign, ActionTransfer:
			return PermissionAlertAssign, true
		case ActionClaim, ActionRelease:
			return PermissionAlertClaim, true
		case ActionEscalate:
			return PermissionAlertEscalate, true
		}
	case AggregateCase:
		switch action {
		case ActionCreate:
			return PermissionCaseCreate, true
		case ActionTransition:
			return PermissionCaseTransition, true
		case ActionAssign, ActionTransfer:
			return PermissionCaseTransfer, true
		case ActionClaim, ActionRelease:
			return PermissionCaseClaim, true
		case ActionLink:
			return PermissionCaseUpdate, true
		}
	}
	return Permission(0), false
}

type PrincipalKind uint8

const (
	PrincipalOperator PrincipalKind = iota + 1
	PrincipalCustomer
	PrincipalServiceAccount
)

func (kind PrincipalKind) String() string {
	switch kind {
	case PrincipalOperator:
		return "operator"
	case PrincipalCustomer:
		return "customer"
	case PrincipalServiceAccount:
		return "service_account"
	default:
		return "unknown"
	}
}

func validPrincipalKind(kind PrincipalKind) bool {
	return kind >= PrincipalOperator && kind <= PrincipalServiceAccount
}

type Visibility uint8

const (
	VisibilityInternal Visibility = iota + 1
	VisibilityCustomer
)

func (visibility Visibility) String() string {
	switch visibility {
	case VisibilityInternal:
		return "internal"
	case VisibilityCustomer:
		return "customer"
	default:
		return "unknown"
	}
}

func validVisibility(visibility Visibility) bool {
	return visibility == VisibilityInternal || visibility == VisibilityCustomer
}

type Effect uint8

const (
	EffectActivity Effect = iota + 1
	EffectAudit
	EffectSLA
	EffectNotification
)

func (effect Effect) String() string {
	switch effect {
	case EffectActivity:
		return "activity"
	case EffectAudit:
		return "audit"
	case EffectSLA:
		return "sla"
	case EffectNotification:
		return "notification"
	default:
		return "unknown"
	}
}

// EffectPlan is a closed, canonical side-effect set. Every mutation must create
// activity and audit records; SLA and notification triggers are declarative options.
type EffectPlan struct {
	mask uint8
}

func NewEffectPlan(effects ...Effect) (EffectPlan, error) {
	if len(effects) < 2 || len(effects) > 4 {
		return EffectPlan{}, ErrInvalidWorkflow
	}
	var mask uint8
	for _, effect := range effects {
		if effect < EffectActivity || effect > EffectNotification {
			return EffectPlan{}, ErrInvalidWorkflow
		}
		bit := uint8(1 << (effect - 1))
		if mask&bit != 0 {
			return EffectPlan{}, ErrInvalidWorkflow
		}
		mask |= bit
	}
	required := uint8(1<<(EffectActivity-1) | 1<<(EffectAudit-1))
	if mask&required != required {
		return EffectPlan{}, ErrInvalidWorkflow
	}
	return EffectPlan{mask: mask}, nil
}

func (plan EffectPlan) Effects() []Effect {
	result := make([]Effect, 0, 4)
	for effect := EffectActivity; effect <= EffectNotification; effect++ {
		if plan.mask&uint8(1<<(effect-1)) != 0 {
			result = append(result, effect)
		}
	}
	return result
}

func validEffectPlan(plan EffectPlan) bool {
	required := uint8(1<<(EffectActivity-1) | 1<<(EffectAudit-1))
	allowed := uint8(1<<(EffectNotification) - 1)
	return plan.mask&required == required && plan.mask&^allowed == 0
}

func canonicalKeys(values []Key, maximum int) ([]Key, bool) {
	if len(values) > maximum {
		return nil, false
	}
	result := slices.Clone(values)
	for _, value := range result {
		if !validKey(value.value) {
			return nil, false
		}
	}
	slices.SortFunc(result, func(left, right Key) int {
		return strings.Compare(left.value, right.value)
	})
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, false
		}
	}
	return result, true
}

func canonicalPermissions(values []Permission, maximum int) ([]Permission, bool) {
	if len(values) > maximum {
		return nil, false
	}
	result := slices.Clone(values)
	for _, value := range result {
		if !validPermission(value) {
			return nil, false
		}
	}
	slices.SortFunc(result, func(left, right Permission) int {
		return int(left) - int(right)
	})
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, false
		}
	}
	return result, true
}

func canonicalIDs(values []EntityID, maximum int) ([]EntityID, bool) {
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

func validText(value string, maximum int, rejectHTML bool) bool {
	if len(value) == 0 || len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	if rejectHTML && strings.ContainsAny(value, "<>") {
		return false
	}
	for _, character := range value {
		if character == '\n' || character == '\t' {
			continue
		}
		if unicode.IsControl(character) || isDirectionalControl(character) {
			return false
		}
	}
	return true
}

func isDirectionalControl(character rune) bool {
	return character == '\u200e' || character == '\u200f' ||
		character >= '\u202a' && character <= '\u202e' ||
		character >= '\u2066' && character <= '\u2069'
}

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%1_000 == 0
}
