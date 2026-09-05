// Package platformidentitybinding implements the explicit tenant-admission
// control plane for platform-owned identity providers. Bindings are created
// disabled and become executable only through their audited access epoch.
package platformidentitybinding

import (
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
)

type TenantStatus string

const (
	TenantStatusActive    TenantStatus = "active"
	TenantStatusSuspended TenantStatus = "suspended"
)

type JITMode string

const (
	JITModeDisabled JITMode = "disabled"
	JITModeCreate   JITMode = "create"
)

type NoMatchPolicy string

const (
	NoMatchPolicyDeny               NoMatchPolicy = "deny"
	NoMatchPolicyProviderAccessOnly NoMatchPolicy = "provider_access_only"
)

// TenantSummary is the bounded tenant projection exposed with a binding. It
// deliberately excludes configuration, memberships, and authorization data.
type TenantSummary struct {
	ID      uuid.UUID
	Slug    string
	Name    string
	Status  TenantStatus
	Version int64
}

// Binding is a safe platform-administration projection. The access epoch is
// present exactly while the explicit tenant admission is active.
type Binding struct {
	ID                   uuid.UUID
	ProviderID           uuid.UUID
	Tenant               TenantSummary
	LoginKey             string
	ProfilePriority      int
	JITMode              JITMode
	NoMatchPolicy        NoMatchPolicy
	Enabled              bool
	ActivationAvailable  bool
	AuthRevision         int64
	MappingRevision      int64
	CurrentAccessEpochID *uuid.UUID
	ArchivedAt           *time.Time
	Version              int64
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

type BindingPage struct {
	Items      []Binding
	NextCursor *uuid.UUID
}

type ListInput struct {
	After           *uuid.UUID
	Limit           int
	IncludeArchived bool
}

type CreateInput struct {
	TenantID        uuid.UUID
	LoginKey        string
	ProfilePriority int
	Reason          string
	IdempotencyKey  string
	Event           authentication.EventContext
}

type UpdateInput struct {
	LoginKey          string
	ProfilePriority   int
	Reason            string
	ExpectedEntityTag *string
	Event             authentication.EventContext
}

type ArchiveInput struct {
	Reason            string
	ExpectedEntityTag *string
	Event             authentication.EventContext
}

type ActivateInput struct {
	JITMode           JITMode
	NoMatchPolicy     NoMatchPolicy
	Reason            string
	ExpectedEntityTag *string
	Event             authentication.EventContext
}

type DeactivateInput struct {
	Reason            string
	ExpectedEntityTag *string
	Event             authentication.EventContext
}
