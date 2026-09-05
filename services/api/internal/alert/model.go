// Package alert implements the Alert application boundary.
package alert

import (
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type Severity string

const (
	SeverityInformational Severity = "informational"
	SeverityLow           Severity = "low"
	SeverityMedium        Severity = "medium"
	SeverityHigh          Severity = "high"
	SeverityCritical      Severity = "critical"
)

type Status string

const (
	StatusNew        Status = "new"
	StatusInProgress Status = "in_progress"
	StatusClosed     Status = "closed"
)

// Alert retains exclusive human-or-machine creator attribution. CreatedByUserID
// is kept during the rolling compatibility window and must match the human
// membership when present.
type Alert struct {
	ID                        uuid.UUID
	TenantID                  uuid.UUID
	Number                    string
	WorkflowID                uuid.UUID
	WorkflowVersion           int64
	StateKey                  string
	CustomerVisible           bool
	ExternalID                *string
	DeduplicationKey          *string
	Title                     string
	Description               *string
	Status                    Status
	Severity                  Severity
	Priority                  string
	Category                  string
	Classification            *string
	Source                    string
	SourceType                string
	Tags                      []string
	CustomFields              map[string]any
	CustomerCustomFields      map[string]any
	RawPayload                map[string]any
	AssignedTeamID            *uuid.UUID
	AssigneeUserID            *uuid.UUID
	ClaimedByUserID           *uuid.UUID
	CreatedByUserID           *uuid.UUID
	CreatedByMembershipID     *uuid.UUID
	CreatedByServiceAccountID *uuid.UUID
	DetectedAt                time.Time
	ReceivedAt                time.Time
	AcknowledgedAt            *time.Time
	ClosedAt                  *time.Time
	AssignedAt                *time.Time
	FirstResponseAt           *time.Time
	ResolvedAt                *time.Time
	ClaimedAt                 *time.Time
	CreatedAt                 time.Time
	UpdatedAt                 time.Time
	Version                   int64
}

type CreateInput struct {
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
	IdempotencyKey   string
	Audit            authorization.AuditContext
}

type BearerCreateInput struct {
	CreateInput
	Token string
}

type IdempotentCreateResult struct {
	Alert    Alert
	Replayed bool
}
