package sla

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/sla"
)

type PrincipalKind string

const (
	PrincipalOperator PrincipalKind = "operator"
	PrincipalCustomer PrincipalKind = "customer"
)

type Actor struct {
	TenantID             uuid.UUID
	PrincipalID          uuid.UUID
	MembershipID         uuid.UUID
	SessionID            uuid.UUID
	AuthenticationMethod string
	Kind                 PrincipalKind
}

func (actor Actor) String() string {
	return fmt.Sprintf("sla.Actor{kind:%s,identity:[REDACTED]}", actor.Kind)
}
func (actor Actor) GoString() string { return actor.String() }

type Capability string

const (
	CapabilityRead            Capability = "sla.read"
	CapabilityManage          Capability = "sla.manage"
	CapabilitySimulate        Capability = "sla.simulate"
	CapabilityAlertRead       Capability = "alert.read"
	CapabilityCaseRead        Capability = "case.read"
	CapabilityPortalAlertRead Capability = "portal.alert.read"
	CapabilityPortalCaseRead  Capability = "portal.case.read"
	CapabilityAlertOverride   Capability = "alert.sla.override"
	CapabilityCaseOverride    Capability = "case.sla.override"
)

type Scope string

const (
	ScopeOwn          Scope = "own"
	ScopeAssigned     Scope = "assigned"
	ScopeOperatorTeam Scope = "operator_team"
	ScopeTenant       Scope = "tenant"
)

type Audience string

const (
	AudienceOperator Audience = "operator"
	AudienceCustomer Audience = "customer"
)

type Resource struct {
	ObjectType kernel.ObjectType
	ObjectID   kernel.EntityID
}

func (resource Resource) String() string {
	return fmt.Sprintf("sla.Resource{objectType:%s,identity:[REDACTED]}", resource.ObjectType)
}
func (resource Resource) GoString() string { return resource.String() }

type Authority struct {
	TenantID        uuid.UUID
	PrincipalID     uuid.UUID
	MembershipID    uuid.UUID
	Capability      Capability
	Resource        Resource
	Scope           Scope
	Audience        Audience
	Allowed         bool
	RoleKeys        []kernel.Key
	PermissionEpoch uint64
	SubjectEpoch    uint64
	EvaluatedAt     time.Time
	ValidUntil      time.Time
}

func (authority Authority) String() string {
	return fmt.Sprintf(
		"sla.Authority{capability:%s,scope:%s,audience:%s,allowed:%t,epochs:[REDACTED],identity:[REDACTED]}",
		authority.Capability, authority.Scope, authority.Audience, authority.Allowed,
	)
}
func (authority Authority) GoString() string { return authority.String() }

type AuditContext struct {
	RequestID     uuid.UUID
	CorrelationID uuid.UUID
	IPAddress     string
	UserAgent     string
	AuthMethod    string
}

func (audit AuditContext) String() string   { return "sla.AuditContext{[REDACTED]}" }
func (audit AuditContext) GoString() string { return audit.String() }

type MutationEnvelope struct {
	IdempotencyKey string
	Audit          AuditContext
}

func (envelope MutationEnvelope) String() string {
	return "sla.MutationEnvelope{idempotency:[REDACTED],audit:[REDACTED]}"
}
func (envelope MutationEnvelope) GoString() string { return envelope.String() }

type CommandBinding struct {
	KeyDigest     [32]byte
	RequestDigest [32]byte
}

func (binding CommandBinding) String() string   { return "sla.CommandBinding{[REDACTED]}" }
func (binding CommandBinding) GoString() string { return binding.String() }

type CalendarPublishCommand struct {
	Input                 kernel.BusinessCalendarInput
	ExpectedActiveVersion uint64
	Envelope              MutationEnvelope
}

func (command CalendarPublishCommand) String() string {
	return fmt.Sprintf("sla.CalendarPublishCommand{expectedVersion:%d,payload:[REDACTED]}", command.ExpectedActiveVersion)
}
func (command CalendarPublishCommand) GoString() string { return command.String() }

type PolicyPublishCommand struct {
	Input                 kernel.PolicyInput
	ExpectedActiveVersion uint64
	Envelope              MutationEnvelope
}

func (command PolicyPublishCommand) String() string {
	return fmt.Sprintf("sla.PolicyPublishCommand{expectedVersion:%d,payload:[REDACTED]}", command.ExpectedActiveVersion)
}
func (command PolicyPublishCommand) GoString() string { return command.String() }

type ColumnPublishCommand struct {
	Input                 kernel.ColumnDefinitionInput
	ExpectedActiveVersion uint64
	Envelope              MutationEnvelope
}

func (command ColumnPublishCommand) String() string {
	return fmt.Sprintf("sla.ColumnPublishCommand{expectedVersion:%d,payload:[REDACTED]}", command.ExpectedActiveVersion)
}
func (command ColumnPublishCommand) GoString() string { return command.String() }

type ArchiveKind string

const (
	ArchiveCalendar ArchiveKind = "calendar"
	ArchivePolicy   ArchiveKind = "policy"
	ArchiveColumn   ArchiveKind = "column"
)

type ArchiveCommand struct {
	Kind            ArchiveKind
	ID              kernel.EntityID
	ExpectedVersion uint64
	Reason          string
	Envelope        MutationEnvelope
}

func (command ArchiveCommand) String() string {
	return fmt.Sprintf("sla.ArchiveCommand{kind:%s,expectedVersion:%d,reason:[REDACTED],identity:[REDACTED]}", command.Kind, command.ExpectedVersion)
}
func (command ArchiveCommand) GoString() string { return command.String() }

type PublicationResult[T any] struct {
	Value           T
	ResourceVersion uint64
	CreatedAt       time.Time
	UpdatedAt       time.Time
	ArchivedAt      *time.Time
	Replayed        bool
}

const (
	defaultConfigurationPageLimit = 50
	maximumConfigurationPageLimit = 200
)

type ConfigurationListInput struct {
	Limit           int
	After           string
	IncludeArchived bool
}

type CalendarRecord struct {
	Value           kernel.BusinessCalendar
	ResourceVersion uint64
	CreatedAt       time.Time
	UpdatedAt       time.Time
	ArchivedAt      *time.Time
}

type CalendarPage struct {
	Items      []CalendarRecord
	NextCursor string
}

type PolicyRecord struct {
	Value           kernel.Policy
	ResourceVersion uint64
	CreatedAt       time.Time
	UpdatedAt       time.Time
	ArchivedAt      *time.Time
}

type PolicyPage struct {
	Items      []PolicyRecord
	NextCursor string
}

type ColumnRecord struct {
	Value           kernel.ColumnDefinition
	ResourceVersion uint64
	CreatedAt       time.Time
	UpdatedAt       time.Time
	ArchivedAt      *time.Time
}

type ColumnPage struct {
	Items      []ColumnRecord
	NextCursor string
}

func StrongConfigurationETag(kind ArchiveKind, id kernel.EntityID, resourceVersion uint64) string {
	if !validArchiveKind(kind) || !validKernelID(id) || resourceVersion == 0 || resourceVersion >= uint64(math.MaxInt64) {
		return ""
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf("periapsis:sla-etag:v1:%s:%s:%d", kind, id.String(), resourceVersion)))
	return `"sla-` + base64.RawURLEncoding.EncodeToString(digest[:16]) + "-v" + strconv.FormatUint(resourceVersion, 10) + `"`
}

// ParseStrongConfigurationETag extracts the version only after validating the
// complete resource-bound validator. Weak, wildcard, list, non-canonical, and
// cross-resource validators fail closed.
func ParseStrongConfigurationETag(value string, kind ArchiveKind, id kernel.EntityID) (uint64, error) {
	return parseStrongVersionETag(value, "sla-", func(version uint64) string {
		return StrongConfigurationETag(kind, id, version)
	})
}

func StrongObjectSLAETag(slaInstanceID kernel.EntityID, aggregateVersion uint64) string {
	if !validKernelID(slaInstanceID) || aggregateVersion == 0 || aggregateVersion >= uint64(math.MaxInt64) {
		return ""
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf(
		"periapsis:sla-object-etag:v1:%s:%d", slaInstanceID.String(), aggregateVersion,
	)))
	return `"sla-object-` + base64.RawURLEncoding.EncodeToString(digest[:16]) + "-v" + strconv.FormatUint(aggregateVersion, 10) + `"`
}

// StrongCustomerObjectSLAETag is deliberately opaque: customer projections
// omit internal aggregate identifiers and versions, and the validator must not
// reintroduce either through its textual shape.
func StrongCustomerObjectSLAETag(slaInstanceID kernel.EntityID, aggregateVersion uint64) string {
	if !validKernelID(slaInstanceID) || aggregateVersion == 0 || aggregateVersion >= uint64(math.MaxInt64) {
		return ""
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf(
		"periapsis:sla-customer-object-etag:v1:%s:%d", slaInstanceID.String(), aggregateVersion,
	)))
	return `"sla-customer-` + base64.RawURLEncoding.EncodeToString(digest[:16]) + `"`
}

// ParseStrongObjectSLAETag extracts an aggregate version from an exact
// SLA-instance-bound strong validator.
func ParseStrongObjectSLAETag(value string, slaInstanceID kernel.EntityID) (uint64, error) {
	return parseStrongVersionETag(value, "sla-object-", func(version uint64) string {
		return StrongObjectSLAETag(slaInstanceID, version)
	})
}

func parseStrongVersionETag(value, prefix string, expected func(uint64) string) (uint64, error) {
	if len(value) < len(prefix)+8 || len(value) > 96 || value[0] != '"' || value[len(value)-1] != '"' ||
		!strings.HasPrefix(value[1:], prefix) || strings.ContainsAny(value, ",\r\n\t ") {
		return 0, ErrInvalidInput
	}
	body := value[1 : len(value)-1]
	separator := strings.LastIndex(body, "-v")
	if separator <= len(prefix) || separator+2 >= len(body) {
		return 0, ErrInvalidInput
	}
	digits := body[separator+2:]
	if len(digits) > 1 && digits[0] == '0' {
		return 0, ErrInvalidInput
	}
	version, err := strconv.ParseUint(digits, 10, 64)
	if err != nil || version == 0 || version >= uint64(math.MaxInt64) || expected(version) != value {
		return 0, ErrInvalidInput
	}
	return version, nil
}

type SimulationCommand struct {
	PolicyID      kernel.EntityID
	PolicyVersion uint64
	Snapshot      kernel.FactSnapshot
	SLAInstanceID kernel.EntityID
	ObjectID      kernel.EntityID
	CreatedAt     time.Time
	EvaluateAt    time.Time
	Bindings      []kernel.SimulationMetricBinding
	Events        []kernel.MetricEvent
}

func (command SimulationCommand) String() string {
	return fmt.Sprintf("sla.SimulationCommand{policyVersion:%d,events:%d,payload:[REDACTED]}", command.PolicyVersion, len(command.Events))
}
func (command SimulationCommand) GoString() string { return command.String() }

type SimulationResult struct {
	Result kernel.SimulationResult
	Digest [32]byte
}

type ObjectProjectionCommand struct {
	ObjectType kernel.ObjectType
	ObjectID   kernel.EntityID
	At         time.Time
}

func (command ObjectProjectionCommand) String() string {
	return fmt.Sprintf("sla.ObjectProjectionCommand{objectType:%s,at:%s,identity:[REDACTED]}", command.ObjectType, command.At.Format(time.RFC3339))
}
func (command ObjectProjectionCommand) GoString() string { return command.String() }

type MetricProjection struct {
	MetricID           kernel.EntityID
	MetricInstanceID   kernel.EntityID
	MetricVersion      uint64
	Key                kernel.Key
	Label              string
	CustomerVisible    bool
	State              kernel.MetricState
	StartedAt          *time.Time
	PausedAt           *time.Time
	DueAt              *time.Time
	RemainingSeconds   int64
	ConsumedPercentage float64
	BreachedAt         *time.Time
	CompletedAt        *time.Time
}

type ColumnProjection struct {
	ColumnID        kernel.EntityID
	Key             kernel.Key
	Label           string
	Calculation     kernel.ColumnCalculation
	Format          kernel.ColumnFormat
	CustomerVisible bool
	State           kernel.MetricState
	Instant         *time.Time
	Duration        *time.Duration
	Percentage      *float64
	StyleKey        kernel.Key
	MaterializedAt  time.Time
}

type ObjectProjection struct {
	TenantID         uuid.UUID
	Audience         Audience
	ObjectType       kernel.ObjectType
	ObjectID         kernel.EntityID
	SLAInstanceID    kernel.EntityID
	AggregateVersion uint64
	PolicyID         kernel.EntityID
	PolicyVersion    uint64
	Metrics          []MetricProjection
	Columns          []ColumnProjection
	ProjectedAt      time.Time
}

func (projection ObjectProjection) String() string {
	return fmt.Sprintf(
		"sla.ObjectProjection{policyVersion:%d,metrics:%d,columns:%d,identity:[REDACTED],values:[REDACTED]}",
		projection.PolicyVersion, len(projection.Metrics), len(projection.Columns),
	)
}
func (projection ObjectProjection) GoString() string { return projection.String() }

type ObjectProjectionState struct {
	SLAInstanceID    kernel.EntityID
	AggregateVersion uint64
	PolicyID         kernel.EntityID
	PolicyVersion    uint64
	Metrics          []kernel.MetricWork
}

func (state ObjectProjectionState) String() string {
	return fmt.Sprintf(
		"sla.ObjectProjectionState{aggregateVersion:%d,policyVersion:%d,metrics:%d,identity:[REDACTED],values:[REDACTED]}",
		state.AggregateVersion, state.PolicyVersion, len(state.Metrics),
	)
}
func (state ObjectProjectionState) GoString() string { return state.String() }

type EventCommand struct {
	Actor      Actor
	ObjectType kernel.ObjectType
	Event      kernel.MetricEvent
	Origin     string
	OriginID   kernel.EntityID
	Envelope   MutationEnvelope
}

func (command EventCommand) String() string {
	return fmt.Sprintf("sla.EventCommand{actor:%s,objectType:%s,origin:%s,event:[REDACTED],audit:[REDACTED]}", command.Actor.Kind, command.ObjectType, command.Origin)
}
func (command EventCommand) GoString() string { return command.String() }

type EventStateMode string

const (
	EventStateExisting   EventStateMode = "existing"
	EventStateUnassigned EventStateMode = "unassigned"
)

// EventState is loaded and locked by the repository in the event transaction.
// Existing aggregates carry their optimistic aggregate version and only their
// version-pinned metric work. An unassigned object carries one atomic
// fact/configuration snapshot and an aggregate version of zero instead.
type EventState struct {
	Mode             EventStateMode
	AggregateVersion uint64
	Metrics          []kernel.MetricWork
	Snapshot         *kernel.FactSnapshot
	Policies         []kernel.Policy
	Calendars        []kernel.BusinessCalendar
	Columns          []kernel.ColumnDefinition
}

func (state EventState) String() string {
	return fmt.Sprintf(
		"sla.EventState{mode:%s,aggregateVersion:%d,metrics:%d,policies:%d,identity:[REDACTED],values:[REDACTED]}",
		state.Mode, state.AggregateVersion, len(state.Metrics), len(state.Policies),
	)
}
func (state EventState) GoString() string { return state.String() }

// EventPlan explicitly represents all three durable event outcomes: update an
// existing aggregate, assign and update a new aggregate, or record a valid
// no-policy decision. Engine is nil only for the no-policy outcome.
type EventPlan struct {
	Assignment               *kernel.AssignmentPlan
	Engine                   *kernel.EnginePlan
	ExpectedAggregateVersion uint64
	NextAggregateVersion     uint64
}

func (plan EventPlan) String() string {
	return fmt.Sprintf(
		"sla.EventPlan{assigned:%t,evaluated:%t,payload:[REDACTED]}",
		plan.Assignment != nil, plan.Engine != nil,
	)
}
func (plan EventPlan) GoString() string { return plan.String() }

type EventOutcome string

const (
	EventOutcomeNoPolicy EventOutcome = "no_policy"
	EventOutcomeAssigned EventOutcome = "assigned"
	EventOutcomeUpdated  EventOutcome = "updated"
)

// EventReceipt is the only replay representation returned by a repository.
// Command binds the receipt to the exact idempotency key and request payload;
// the planner output is intentionally absent so a replay cannot reconstruct or
// execute business logic from mutable configuration.
type EventReceipt struct {
	Command          CommandBinding
	EventID          kernel.EntityID
	TenantID         uuid.UUID
	ObjectType       kernel.ObjectType
	ObjectID         kernel.EntityID
	Outcome          EventOutcome
	SLAInstanceID    *kernel.EntityID
	AggregateVersion uint64
	PolicyID         *kernel.EntityID
	PolicyVersion    uint64
}

func (receipt EventReceipt) String() string {
	return fmt.Sprintf(
		"sla.EventReceipt{outcome:%s,aggregateVersion:%d,identity:[REDACTED],binding:[REDACTED]}",
		receipt.Outcome, receipt.AggregateVersion,
	)
}
func (receipt EventReceipt) GoString() string { return receipt.String() }

type EventResult struct {
	Receipt  EventReceipt
	Replayed bool
}

type OverrideRequest struct {
	ObjectType               kernel.ObjectType
	ObjectID                 kernel.EntityID
	SLAInstanceID            kernel.EntityID
	MetricInstanceID         kernel.EntityID
	ExpectedMetricVersion    uint64
	ExpectedAggregateVersion uint64
	Intent                   OverrideIntent
	Envelope                 MutationEnvelope
}

func (request OverrideRequest) String() string {
	return fmt.Sprintf(
		"sla.OverrideRequest{objectType:%s,expectedMetricVersion:%d,expectedAggregateVersion:%d,intent:%s,identity:[REDACTED]}",
		request.ObjectType, request.ExpectedMetricVersion, request.ExpectedAggregateVersion, request.Intent.Kind,
	)
}
func (request OverrideRequest) GoString() string { return request.String() }

type OverrideIntent struct {
	ID                         kernel.EntityID
	Kind                       kernel.OverrideKind
	Reason                     string
	Extension                  time.Duration
	NewPolicyID                kernel.EntityID
	NewPolicyVersion           uint64
	ReplacementCalendarID      kernel.EntityID
	ReplacementCalendarVersion uint64
	SimulationDigest           [32]byte
}

func (intent OverrideIntent) String() string {
	return fmt.Sprintf("sla.OverrideIntent{kind:%s,reason:[REDACTED],targets:[REDACTED]}", intent.Kind)
}
func (intent OverrideIntent) GoString() string { return intent.String() }

type OverrideState struct {
	Metric               *kernel.MetricWork
	Metrics              []kernel.MetricWork
	AggregateVersion     uint64
	ReplacementCalendar  *kernel.BusinessCalendar
	ReplacementPolicy    *kernel.Policy
	ReplacementCalendars []kernel.BusinessCalendar
	ReplacementColumns   []kernel.ColumnDefinition
	SimulationDigest     [32]byte
	OccurredAt           time.Time
}

func (state OverrideState) String() string {
	return fmt.Sprintf(
		"sla.OverrideState{aggregateVersion:%d,metric:%t,metrics:%d,calendarReplacement:%t,policyReplacement:%t,identity:[REDACTED],values:[REDACTED]}",
		state.AggregateVersion, state.Metric != nil, len(state.Metrics), state.ReplacementCalendar != nil, state.ReplacementPolicy != nil,
	)
}
func (state OverrideState) GoString() string { return state.String() }

type OverridePlan struct {
	Instance                 kernel.MetricInstance
	Record                   *kernel.OverrideRecord
	Materialization          *kernel.EnginePlan
	Policy                   *kernel.PolicyOverridePlan
	ExpectedAggregateVersion uint64
	NextAggregateVersion     uint64
	Changed                  bool
}

func (plan OverridePlan) String() string {
	return fmt.Sprintf(
		"sla.OverridePlan{changed:%t,materialized:%t,policyReplacement:%t,identity:[REDACTED],values:[REDACTED]}",
		plan.Changed, plan.Materialization != nil, plan.Policy != nil,
	)
}
func (plan OverridePlan) GoString() string { return plan.String() }

type OverrideOutcome string

const (
	OverrideOutcomeMetricUpdated OverrideOutcome = "metric_updated"
	OverrideOutcomePolicyChanged OverrideOutcome = "policy_changed"
)

// OverrideReceipt is a redacted, payload-bound representation of the durable
// mutation. CurrentVersion is the metric version for metric overrides and the
// SLA aggregate version for a policy replacement; AggregateVersion is always
// the post-mutation SLA aggregate version.
type OverrideReceipt struct {
	Command          CommandBinding
	OverrideID       kernel.EntityID
	TenantID         uuid.UUID
	ObjectType       kernel.ObjectType
	ObjectID         kernel.EntityID
	Outcome          OverrideOutcome
	Kind             kernel.OverrideKind
	SLAInstanceID    kernel.EntityID
	MetricInstanceID *kernel.EntityID
	PreviousVersion  uint64
	CurrentVersion   uint64
	AggregateVersion uint64
	PolicyID         kernel.EntityID
	PolicyVersion    uint64
	ActorID          kernel.EntityID
	PermissionEpoch  uint64
	SubjectEpoch     uint64
	OccurredAt       time.Time
	SimulationDigest [32]byte
}

func (receipt OverrideReceipt) String() string {
	return fmt.Sprintf(
		"sla.OverrideReceipt{outcome:%s,kind:%s,currentVersion:%d,identity:[REDACTED],binding:[REDACTED]}",
		receipt.Outcome, receipt.Kind, receipt.CurrentVersion,
	)
}
func (receipt OverrideReceipt) GoString() string { return receipt.String() }

type OverrideResult struct {
	Receipt  OverrideReceipt
	Replayed bool
}

var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$`)

func normalizeConfigurationList(input ConfigurationListInput) (ConfigurationListInput, error) {
	if input.Limit < 0 || input.Limit > maximumConfigurationPageLimit || !validConfigurationCursor(input.After) {
		return ConfigurationListInput{}, ErrInvalidInput
	}
	if input.Limit == 0 {
		input.Limit = defaultConfigurationPageLimit
	}
	return input, nil
}

func validConfigurationCursor(value string) bool {
	if value == "" {
		return true
	}
	_, _, err := DecodeConfigurationCursor(value)
	return err == nil
}

// EncodeConfigurationCursor returns the canonical opaque cursor for the
// immutable inventory ordering tuple (key, id).
func EncodeConfigurationCursor(key kernel.Key, id kernel.EntityID) string {
	if key.String() == "" || !validKernelID(id) || len(key.String()) > 255 {
		return ""
	}
	identifier := id.Bytes()
	payload := make([]byte, 0, 2+len(key.String())+len(identifier))
	payload = append(payload, 1, byte(len(key.String())))
	payload = append(payload, key.String()...)
	payload = append(payload, identifier[:]...)
	return base64.RawURLEncoding.EncodeToString(payload)
}

// DecodeConfigurationCursor rejects non-canonical structural values. A valid
// tuple is only a page position and carries no authorization.
func DecodeConfigurationCursor(value string) (kernel.Key, kernel.EntityID, error) {
	if value == "" || len(value) > 112 {
		return kernel.Key{}, kernel.EntityID{}, ErrInvalidInput
	}
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(payload) < 19 || payload[0] != 1 || int(payload[1])+18 != len(payload) ||
		base64.RawURLEncoding.EncodeToString(payload) != value {
		return kernel.Key{}, kernel.EntityID{}, ErrInvalidInput
	}
	key, err := kernel.NewKey(string(payload[2 : 2+int(payload[1])]))
	if err != nil {
		return kernel.Key{}, kernel.EntityID{}, ErrInvalidInput
	}
	var identifier [16]byte
	copy(identifier[:], payload[len(payload)-16:])
	id, err := kernel.NewEntityID(identifier)
	if err != nil {
		return kernel.Key{}, kernel.EntityID{}, ErrInvalidInput
	}
	return key, id, nil
}

func bindCommand(operation, key string, requestDigest [32]byte) (CommandBinding, error) {
	if !validToken(operation, 128) || !idempotencyKeyPattern.MatchString(key) || requestDigest == ([32]byte{}) {
		return CommandBinding{}, ErrInvalidInput
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("periapsis:sla-command-key:v1\x00"))
	_, _ = hash.Write([]byte(operation))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(key))
	var keyDigest [32]byte
	copy(keyDigest[:], hash.Sum(nil))
	return CommandBinding{KeyDigest: keyDigest, RequestDigest: requestDigest}, nil
}

func validActor(actor Actor, tenantID uuid.UUID) bool {
	return validUUIDv7(tenantID) && actor.TenantID == tenantID && validUUIDv7(actor.PrincipalID) &&
		validUUIDv7(actor.MembershipID) && validUUIDv7(actor.SessionID) &&
		validToken(actor.AuthenticationMethod, 64) &&
		(actor.Kind == PrincipalOperator || actor.Kind == PrincipalCustomer)
}

func validAuthority(actor Actor, tenantID uuid.UUID, capability Capability, authority Authority) bool {
	if !validActor(actor, tenantID) || authority.TenantID != tenantID || authority.PrincipalID != actor.PrincipalID ||
		authority.MembershipID != actor.MembershipID || authority.Capability != capability || !authority.Allowed ||
		authority.PermissionEpoch == 0 || authority.PermissionEpoch >= uint64(math.MaxInt64) ||
		authority.SubjectEpoch == 0 || authority.SubjectEpoch >= uint64(math.MaxInt64) ||
		!validInstant(authority.EvaluatedAt) || !validInstant(authority.ValidUntil) ||
		!authority.ValidUntil.After(authority.EvaluatedAt) {
		return false
	}
	roles := authority.RoleKeys
	for index, role := range roles {
		if role.String() == "" || index > 0 && roles[index-1].String() >= role.String() {
			return false
		}
	}
	return actor.Kind == PrincipalOperator && authority.Audience == AudienceOperator ||
		actor.Kind == PrincipalCustomer && authority.Audience == AudienceCustomer && len(authority.RoleKeys) == 0
}

func validManageAuthority(actor Actor, tenantID uuid.UUID, capability Capability, authority Authority) bool {
	return actor.Kind == PrincipalOperator && authority.Scope == ScopeTenant && authority.Resource == (Resource{}) &&
		validAuthority(actor, tenantID, capability, authority)
}

func validObjectAuthority(
	actor Actor,
	tenantID uuid.UUID,
	capability Capability,
	resource Resource,
	authority Authority,
) bool {
	validScope := authority.Scope == ScopeOwn || authority.Scope == ScopeAssigned ||
		authority.Scope == ScopeOperatorTeam || authority.Scope == ScopeTenant
	if actor.Kind == PrincipalCustomer {
		validScope = authority.Scope == ScopeOwn
	}
	return validScope && authority.Resource == resource && validAuthority(actor, tenantID, capability, authority)
}

func validEnvelope(envelope MutationEnvelope) bool {
	return idempotencyKeyPattern.MatchString(envelope.IdempotencyKey) && validAudit(envelope.Audit)
}

func validAudit(audit AuditContext) bool {
	if !validUUIDv7(audit.RequestID) || !validUUIDv7(audit.CorrelationID) ||
		!validSingleLine(audit.UserAgent, 512, true) || !validToken(audit.AuthMethod, 64) {
		return false
	}
	address, err := netip.ParseAddr(audit.IPAddress)
	return err == nil && address.IsValid() && address.String() == audit.IPAddress
}

func validUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Year() >= 1970 && value.Year() <= 9999 &&
		value.Nanosecond()%1_000 == 0
}

func validSingleLine(value string, maximum int, optional bool) bool {
	if value == "" {
		return optional
	}
	if len(value) > maximum || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == '\u200e' || character == '\u200f' ||
			character >= '\u202a' && character <= '\u202e' || character >= '\u2066' && character <= '\u2069' {
			return false
		}
	}
	return true
}

func validToken(value string, maximum int) bool {
	if !validSingleLine(value, maximum, false) {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validReason(value string) bool {
	if len(value) < 3 || len(value) > 2_000 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character == '\n' || character == '\t' {
			continue
		}
		if unicode.IsControl(character) || character == '\u200e' || character == '\u200f' ||
			character >= '\u202a' && character <= '\u202e' || character >= '\u2066' && character <= '\u2069' {
			return false
		}
	}
	return true
}

func canonicalRoleKeys(values []kernel.Key) ([]kernel.Key, bool) {
	if len(values) > 128 {
		return nil, false
	}
	result := slices.Clone(values)
	slices.SortFunc(result, func(left, right kernel.Key) int { return strings.Compare(left.String(), right.String()) })
	for index, value := range result {
		if value.String() == "" || index > 0 && result[index-1].String() == value.String() {
			return nil, false
		}
	}
	return result, true
}

func repositoryError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrRepositoryForbidden):
		return ErrForbidden
	case errors.Is(err, ErrRepositoryNotFound):
		return ErrNotFound
	case errors.Is(err, ErrRepositoryConflict):
		return ErrConflict
	case errors.Is(err, ErrRepositoryPrecondition):
		return ErrPreconditionFailed
	default:
		return ErrUnavailable
	}
}
