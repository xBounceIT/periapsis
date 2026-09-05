package tenantsettings

import (
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

// Settings is the complete safe tenant branding and regional projection.
// Other administration domains remain independently versioned aggregates.
type Settings struct {
	TenantID     uuid.UUID
	BrandName    string
	BrandMark    string
	PrimaryColor string
	AccentColor  string
	Timezone     string
	Locale       string
	Version      int32
	UpdatedAt    time.Time
}

type UpdateInput struct {
	ExpectedVersion int32
	BrandName       string
	BrandMark       string
	PrimaryColor    string
	AccentColor     string
	Timezone        string
	Locale          string
	Reason          string
	Event           authentication.EventContext
}

type ReadParams struct {
	Actor    authorization.Actor
	TenantID uuid.UUID
}

type UpdateParams struct {
	Actor           authorization.Actor
	TenantID        uuid.UUID
	ExpectedVersion int32
	BrandName       string
	BrandMark       string
	PrimaryColor    string
	AccentColor     string
	Timezone        string
	Locale          string
	Reason          string
	AuditID         uuid.UUID
	Event           authentication.EventContext
}
