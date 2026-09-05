// Package platform implements explicitly authorized platform-level use cases.
package platform

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/text/language"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

const maximumPageSize = 100

var slugPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var localePattern = regexp.MustCompile(`^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$`)

type Repository interface {
	ListTenants(context.Context, ListTenantsParams) ([]authentication.Tenant, error)
	CreateTenant(context.Context, CreateTenantParams) (authentication.Tenant, error)
}

type ListTenantsParams struct {
	ActorID uuid.UUID
	After   *uuid.UUID
	Limit   int32
}

type CreateTenantParams struct {
	ID                   uuid.UUID
	MembershipID         uuid.UUID
	ActorID              uuid.UUID
	Slug                 string
	Name                 string
	Timezone             string
	Locale               string
	AuthenticationMethod string
	Event                authentication.EventContext
}

type CreateTenantInput struct {
	Slug     string
	Name     string
	Timezone string
	Locale   string
	Event    authentication.EventContext
}

type TenantPage struct {
	Items      []authentication.Tenant
	NextCursor *uuid.UUID
}

type Service struct {
	repository Repository
	evaluator  authorization.Evaluator
	newID      func() (uuid.UUID, error)
}

func NewService(repository Repository) (*Service, error) {
	if repository == nil {
		return nil, errors.New("platform repository is required")
	}
	return &Service{repository: repository, evaluator: authorization.Evaluator{}, newID: uuid.NewV7}, nil
}

func (s *Service) ListTenants(
	ctx context.Context,
	session authentication.Session,
	after *uuid.UUID,
	pageSize int,
) (TenantPage, error) {
	if err := s.evaluator.Require(session.Permissions, authorization.PermissionPlatformTenantRead); err != nil {
		return TenantPage{}, authentication.ErrForbidden
	}
	if pageSize == 0 {
		pageSize = 50
	}
	if pageSize < 1 || pageSize > maximumPageSize || after != nil && *after == uuid.Nil {
		return TenantPage{}, authentication.ErrInvalidInput
	}
	rows, err := s.repository.ListTenants(ctx, ListTenantsParams{
		ActorID: session.User.ID,
		After:   after,
		Limit:   int32(pageSize + 1),
	})
	if err != nil {
		if errors.Is(err, authentication.ErrForbidden) {
			return TenantPage{}, authentication.ErrForbidden
		}
		if errors.Is(err, authentication.ErrInvalidInput) {
			return TenantPage{}, authentication.ErrInvalidInput
		}
		return TenantPage{}, authentication.ErrUnavailable
	}
	page := TenantPage{Items: rows}
	if len(rows) > pageSize {
		next := rows[pageSize-1].ID
		page.Items = rows[:pageSize]
		page.NextCursor = &next
	}
	return page, nil
}

func (s *Service) CreateTenant(
	ctx context.Context,
	session authentication.Session,
	input CreateTenantInput,
) (authentication.Tenant, error) {
	if err := s.evaluator.Require(session.Permissions, authorization.PermissionPlatformTenantCreate); err != nil {
		return authentication.Tenant{}, authentication.ErrForbidden
	}
	slug := strings.ToLower(strings.TrimSpace(input.Slug))
	name := strings.TrimSpace(input.Name)
	locale := strings.TrimSpace(input.Locale)
	timezone := strings.TrimSpace(input.Timezone)
	if !slugPattern.MatchString(slug) || !validName(name) || !validTimezone(timezone) || !validLocale(locale) {
		return authentication.Tenant{}, authentication.ErrInvalidInput
	}
	tenantID, err := s.newID()
	if err != nil {
		return authentication.Tenant{}, authentication.ErrUnavailable
	}
	membershipID, err := s.newID()
	if err != nil {
		return authentication.Tenant{}, authentication.ErrUnavailable
	}
	tenant, err := s.repository.CreateTenant(ctx, CreateTenantParams{
		ID: tenantID, MembershipID: membershipID, ActorID: session.User.ID,
		Slug: slug, Name: name, Timezone: timezone, Locale: locale,
		AuthenticationMethod: session.AuthenticationMethod, Event: input.Event,
	})
	if err != nil {
		switch {
		case errors.Is(err, authentication.ErrForbidden):
			return authentication.Tenant{}, authentication.ErrForbidden
		case errors.Is(err, authentication.ErrConflict):
			return authentication.Tenant{}, authentication.ErrConflict
		case errors.Is(err, authentication.ErrInvalidInput):
			return authentication.Tenant{}, authentication.ErrInvalidInput
		default:
			return authentication.Tenant{}, authentication.ErrUnavailable
		}
	}
	return tenant, nil
}

func validName(value string) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) < 1 || utf8.RuneCountInString(value) > 160 {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validTimezone(value string) bool {
	if value == "" || value == "Local" || len(value) > 64 {
		return false
	}
	_, err := time.LoadLocation(value)
	return err == nil
}

func validLocale(value string) bool {
	baseText, _, _ := strings.Cut(value, "-")
	if len(value) > 35 || strings.EqualFold(baseText, "und") || !localePattern.MatchString(value) {
		return false
	}
	tag, err := language.Parse(value)
	if err != nil {
		return false
	}
	base, confidence := tag.Base()
	return confidence != language.No && base.String() != "und"
}
