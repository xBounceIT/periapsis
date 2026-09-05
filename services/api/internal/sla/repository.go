package sla

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/sla"
)

type CalendarPublication struct {
	Actor                 Actor
	Calendar              kernel.BusinessCalendar
	ExpectedActiveVersion uint64
	Command               CommandBinding
	Audit                 AuditContext
}

func (publication CalendarPublication) String() string {
	return fmt.Sprintf(
		"sla.CalendarPublication{expectedVersion:%d,identity:[REDACTED],payload:[REDACTED]}",
		publication.ExpectedActiveVersion,
	)
}
func (publication CalendarPublication) GoString() string { return publication.String() }

type PolicyPublication struct {
	Actor                 Actor
	Policy                kernel.Policy
	ExpectedActiveVersion uint64
	Command               CommandBinding
	Audit                 AuditContext
}

func (publication PolicyPublication) String() string {
	return fmt.Sprintf(
		"sla.PolicyPublication{expectedVersion:%d,identity:[REDACTED],payload:[REDACTED]}",
		publication.ExpectedActiveVersion,
	)
}
func (publication PolicyPublication) GoString() string { return publication.String() }

type ColumnPublication struct {
	Actor                 Actor
	Column                kernel.ColumnDefinition
	ExpectedActiveVersion uint64
	Command               CommandBinding
	Audit                 AuditContext
}

func (publication ColumnPublication) String() string {
	return fmt.Sprintf(
		"sla.ColumnPublication{expectedVersion:%d,identity:[REDACTED],payload:[REDACTED]}",
		publication.ExpectedActiveVersion,
	)
}
func (publication ColumnPublication) GoString() string { return publication.String() }

type ArchiveWrite struct {
	Actor           Actor
	TenantID        uuid.UUID
	Kind            ArchiveKind
	ID              kernel.EntityID
	ExpectedVersion uint64
	Reason          string
	Command         CommandBinding
	Audit           AuditContext
}

func (write ArchiveWrite) String() string {
	return fmt.Sprintf(
		"sla.ArchiveWrite{kind:%s,expectedVersion:%d,identity:[REDACTED],reason:[REDACTED],binding:[REDACTED]}",
		write.Kind, write.ExpectedVersion,
	)
}
func (write ArchiveWrite) GoString() string { return write.String() }

type EventTransaction struct {
	TenantID uuid.UUID
	Command  EventCommand
	Binding  CommandBinding
	Plan     func(EventState) (EventPlan, error)
}

func (transaction EventTransaction) String() string {
	return fmt.Sprintf(
		"sla.EventTransaction{objectType:%s,planner:%t,identity:[REDACTED],payload:[REDACTED],binding:[REDACTED]}",
		transaction.Command.ObjectType, transaction.Plan != nil,
	)
}
func (transaction EventTransaction) GoString() string { return transaction.String() }

type OverrideTransaction struct {
	Actor     Actor
	TenantID  uuid.UUID
	Authority Authority
	Request   OverrideRequest
	Binding   CommandBinding
	Plan      func(OverrideState) (OverridePlan, error)
}

func (transaction OverrideTransaction) String() string {
	return fmt.Sprintf(
		"sla.OverrideTransaction{objectType:%s,kind:%s,planner:%t,identity:[REDACTED],payload:[REDACTED],binding:[REDACTED]}",
		transaction.Request.ObjectType, transaction.Request.Intent.Kind, transaction.Plan != nil,
	)
}
func (transaction OverrideTransaction) GoString() string { return transaction.String() }

// Repository implementations must resolve authorization from live tenant
// state and recheck it inside every mutation transaction. TransactEvent and
// TransactOverride invoke Plan only for a fresh command, then persist the plan,
// payload-bound receipt, audit, and outbox effects atomically or roll back all
// of them. Exact replay returns the stored receipt without invoking Plan.
type Repository interface {
	ResolveAuthority(context.Context, Actor, uuid.UUID, Capability, Resource) (Authority, error)
	ListCalendars(context.Context, Actor, uuid.UUID, ConfigurationListInput, Authority) (CalendarPage, error)
	GetCalendar(context.Context, Actor, uuid.UUID, kernel.EntityID, Authority) (CalendarRecord, error)
	PublishCalendar(context.Context, CalendarPublication) (PublicationResult[kernel.BusinessCalendar], error)
	ListPolicies(context.Context, Actor, uuid.UUID, ConfigurationListInput, Authority) (PolicyPage, error)
	GetPolicy(context.Context, Actor, uuid.UUID, kernel.EntityID, Authority) (PolicyRecord, error)
	LoadPolicyCalendars(context.Context, Actor, uuid.UUID, kernel.Policy) ([]kernel.BusinessCalendar, error)
	PublishPolicy(context.Context, PolicyPublication) (PublicationResult[kernel.Policy], error)
	ListColumns(context.Context, Actor, uuid.UUID, ConfigurationListInput, Authority) (ColumnPage, error)
	GetColumn(context.Context, Actor, uuid.UUID, kernel.EntityID, Authority) (ColumnRecord, error)
	LoadMetricDefinition(context.Context, Actor, uuid.UUID, kernel.EntityID) (kernel.MetricDefinition, error)
	PublishColumn(context.Context, ColumnPublication) (PublicationResult[kernel.ColumnDefinition], error)
	Archive(context.Context, ArchiveWrite) (uint64, bool, error)
	LoadSimulation(context.Context, Actor, uuid.UUID, kernel.EntityID, uint64) (kernel.Policy, []kernel.BusinessCalendar, error)
	LoadObjectProjection(context.Context, Actor, uuid.UUID, Resource, Authority) (ObjectProjectionState, error)
	TransactEvent(context.Context, EventTransaction) (EventResult, error)
	TransactOverride(context.Context, OverrideTransaction) (OverrideResult, error)
}
