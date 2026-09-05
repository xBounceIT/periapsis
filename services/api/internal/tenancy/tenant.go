// Package tenancy contains tenant lifecycle domain rules.
package tenancy

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

var tenantSlugPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Tenant is the platform-owned root for a customer security boundary.
type Tenant struct {
	ID        uuid.UUID
	Slug      string
	Name      string
	Timezone  string
	Locale    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CreateInput contains values accepted by the tenant creation use case.
type CreateInput struct {
	Slug     string
	Name     string
	Timezone string
	Locale   string
}

// Repository persists tenants without exposing transport or pgx details to the domain.
type Repository interface {
	Create(context.Context, Tenant) (Tenant, error)
	Get(context.Context, uuid.UUID) (Tenant, error)
	List(context.Context, int, *uuid.UUID) ([]Tenant, error)
}

// IDGenerator provides ordered identifiers at the application boundary.
type IDGenerator func() (uuid.UUID, error)

// Clock makes timestamps deterministic in tests and transactional use cases.
type Clock func() time.Time

// Service enforces tenant lifecycle rules before persistence.
type Service struct {
	repository Repository
	newID      IDGenerator
	now        Clock
}

// NewService creates a tenant application service.
func NewService(repository Repository, newID IDGenerator, now Clock) *Service {
	return &Service{repository: repository, newID: newID, now: now}
}

// Create validates and persists a tenant. Authorization is intentionally required by the future transport boundary.
func (s *Service) Create(ctx context.Context, input CreateInput) (Tenant, error) {
	name := strings.TrimSpace(input.Name)
	slug := strings.ToLower(strings.TrimSpace(input.Slug))
	timezone := strings.TrimSpace(input.Timezone)
	locale := strings.TrimSpace(input.Locale)

	if name == "" || len([]rune(name)) > 160 {
		return Tenant{}, errors.New("tenant name must contain between 1 and 160 characters")
	}
	if !tenantSlugPattern.MatchString(slug) {
		return Tenant{}, errors.New("tenant slug must be a lowercase DNS label")
	}
	if timezone == "" {
		timezone = "UTC"
	}
	if _, err := time.LoadLocation(timezone); err != nil {
		return Tenant{}, errors.New("tenant timezone must be a valid IANA timezone")
	}
	if locale == "" {
		locale = "en"
	}
	if len(locale) > 35 {
		return Tenant{}, errors.New("tenant locale is too long")
	}

	id, err := s.newID()
	if err != nil {
		return Tenant{}, errors.New("generate tenant identifier")
	}
	if id.Version() != 7 {
		return Tenant{}, errors.New("tenant identifier must be UUIDv7")
	}
	now := s.now().UTC()
	tenant := Tenant{
		ID:        id,
		Slug:      slug,
		Name:      name,
		Timezone:  timezone,
		Locale:    locale,
		CreatedAt: now,
		UpdatedAt: now,
	}
	return s.repository.Create(ctx, tenant)
}

// NewUUIDv7 returns a time-ordered UUID using the maintained google/uuid implementation.
func NewUUIDv7() (uuid.UUID, error) {
	return uuid.NewV7()
}
