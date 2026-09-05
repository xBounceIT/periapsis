// Package securityaudit implements deny-by-default, read-only audit-log use cases.
package securityaudit

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

var (
	ErrForbidden    = errors.New("audit access forbidden")
	ErrInvalidInput = errors.New("invalid audit request")
	ErrUnavailable  = errors.New("audit service unavailable")
)

type ActorType string

const (
	ActorUser           ActorType = "user"
	ActorServiceAccount ActorType = "service_account"
	ActorSystem         ActorType = "system"
)

type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeDenied  Outcome = "denied"
)

// Event is a redacted security-audit projection. TenantID is nil only for the
// independent platform audit stream. Before and After are canonical JSON
// objects even when their database columns are NULL. JSON documents remain
// encoded so callers cannot mutate repository-owned maps after validation.
type Event struct {
	ID                    uuid.UUID
	TenantID              *uuid.UUID
	Sequence              uint64
	OccurredAt            time.Time
	ActorType             ActorType
	ActorUserID           *uuid.UUID
	ActorServiceAccountID *uuid.UUID
	ImpersonatedByUserID  *uuid.UUID
	Action                string
	ResourceType          string
	ResourceID            *uuid.UUID
	RequestID             *uuid.UUID
	CorrelationID         *uuid.UUID
	IPAddress             *netip.Addr
	UserAgent             *string
	AuthenticationMethod  *string
	Outcome               Outcome
	Reason                *string
	Before                json.RawMessage
	After                 json.RawMessage
	Metadata              json.RawMessage
	PreviousHash          string
	EventHash             string
}

// Query is a stable, forward-only sequence page. All filters are exact except
// ActionPrefix and Search. Search is compiled by the repository against an
// allowlisted set of non-secret textual columns; it is never raw SQL.
type Query struct {
	AfterSequence         uint64
	Limit                 int
	OccurredFrom          *time.Time
	OccurredBefore        *time.Time
	ActorType             *ActorType
	ActorUserID           *uuid.UUID
	ActorServiceAccountID *uuid.UUID
	ActionPrefix          string
	ResourceType          string
	ResourceID            *uuid.UUID
	RequestID             *uuid.UUID
	CorrelationID         *uuid.UUID
	Outcome               *Outcome
	Search                string
}

type Page struct {
	Items        []Event
	NextSequence *uint64
}

type TenantReadParams struct {
	Actor         authorization.Actor
	TenantID      uuid.UUID
	Permission    authorization.TenantPermission
	Query         Query
	AccessAuditID uuid.UUID
	Audit         authorization.AuditContext
}

type PlatformReadParams struct {
	Session       authentication.Session
	Permission    authorization.Permission
	Query         Query
	AccessAuditID uuid.UUID
	Event         authentication.EventContext
}

type Verification struct {
	EventCount           uint64
	LastSequence         uint64
	FirstInvalidSequence *uint64
	HeadValid            bool
	Valid                bool
	VerifiedAt           time.Time
}

type TenantVerifyParams struct {
	Actor         authorization.Actor
	TenantID      uuid.UUID
	Permission    authorization.TenantPermission
	AccessAuditID uuid.UUID
	Audit         authorization.AuditContext
}

type PlatformVerifyParams struct {
	Session       authentication.Session
	Permission    authorization.Permission
	AccessAuditID uuid.UUID
	Event         authentication.EventContext
}

type Repository interface {
	ListTenantEvents(context.Context, TenantReadParams) ([]Event, error)
	ListPlatformEvents(context.Context, PlatformReadParams) ([]Event, error)
	VerifyTenantChain(context.Context, TenantVerifyParams) (Verification, error)
	VerifyPlatformChain(context.Context, PlatformVerifyParams) (Verification, error)
}

type AuthorityResolver interface {
	ResolveAuthority(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error)
}
