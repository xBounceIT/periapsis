package alert

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/serviceaccount"
)

type CreatePayload struct {
	WorkflowID       *uuid.UUID
	ExternalID       *string
	DeduplicationKey *string
	Title            string
	Description      *string
	Severity         Severity
	Priority         string
	Category         string
	Classification   *string
	Source           string
	SourceType       string
	Tags             []string
	CustomFields     map[string]any
	RawPayload       map[string]any
	CustomerVisible  bool
	DetectedAt       time.Time
	AssignedTeamID   *uuid.UUID
	AssigneeUserID   *uuid.UUID
	KeyDigest        [32]byte
	RequestDigest    [32]byte
}

type CreateAsHumanParams struct {
	Actor        authorization.Actor
	MembershipID uuid.UUID
	TenantID     uuid.UUID
	Payload      CreatePayload
	Audit        authorization.AuditContext
}

type CreateAsServiceAccountParams struct {
	Credential serviceaccount.PresentedCredential
	TenantID   uuid.UUID
	Payload    CreatePayload
	Audit      authorization.AuditContext
}

// Repository keeps authorization and mutation in one database transaction.
// CreateAsHuman rechecks the exact live human authority while holding the
// tenant authorization lock. CreateAsServiceAccount authenticates Credential,
// resolves its exact live authority/CIDR intersection, and mutates through one
// bounded SECURITY DEFINER entry point. Exact replays return the original
// Alert without duplicating activity, audit, outbox, or command rows.
type Repository interface {
	ResolveHumanAuthority(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error)
	CreateAsHuman(context.Context, CreateAsHumanParams) (IdempotentCreateResult, error)
	CreateAsServiceAccount(context.Context, CreateAsServiceAccountParams) (IdempotentCreateResult, error)
}
