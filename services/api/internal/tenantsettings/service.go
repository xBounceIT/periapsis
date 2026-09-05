package tenantsettings

import (
	"context"
	"errors"
	"math"
	"reflect"
	"regexp"
	"strings"
	"time"
	_ "time/tzdata"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/text/language"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

var (
	brandMarkPattern  = regexp.MustCompile(`^[A-Z0-9]{1,4}$`)
	brandColorPattern = regexp.MustCompile(`^#[0-9a-f]{6}$`)
	localePattern     = regexp.MustCompile(`^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$`)
)

type TenantAuthorityResolver interface {
	GetTenantAuthority(context.Context, authorization.Actor, uuid.UUID) (authorization.TenantAuthority, error)
}

type Service struct {
	repository Repository
	authority  TenantAuthorityResolver
	evaluator  authorization.Evaluator
	newID      func() (uuid.UUID, error)
	now        func() time.Time
}

func NewService(repository Repository, authority TenantAuthorityResolver) (*Service, error) {
	if interfaceIsNil(repository) || interfaceIsNil(authority) {
		return nil, errors.New("tenant settings repository and authority resolver are required")
	}
	return &Service{
		repository: repository,
		authority:  authority,
		evaluator:  authorization.Evaluator{},
		newID:      uuid.NewV7,
		now:        time.Now,
	}, nil
}

func (service *Service) Get(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
) (Settings, error) {
	actor, err := service.require(ctx, session, tenantID, authorization.TenantPermissionSettingsRead)
	if err != nil {
		return Settings{}, err
	}
	settings, err := service.repository.Get(ctx, ReadParams{Actor: actor, TenantID: tenantID})
	if err != nil {
		return Settings{}, mapDependencyError(err)
	}
	if validateSettings(settings, tenantID, service.now()) != nil {
		return Settings{}, ErrUnavailable
	}
	return settings, nil
}

func (service *Service) Update(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	input UpdateInput,
) (Settings, error) {
	actor, err := service.require(
		ctx,
		session,
		tenantID,
		authorization.TenantPermissionSettingsRead,
		authorization.TenantPermissionSettingsManage,
	)
	if err != nil {
		return Settings{}, err
	}
	normalized, err := normalizeUpdate(input)
	if err != nil {
		return Settings{}, err
	}
	auditID, err := service.newID()
	if err != nil || !validUUIDv7(auditID) {
		return Settings{}, ErrUnavailable
	}
	settings, err := service.repository.Update(ctx, UpdateParams{
		Actor: actor, TenantID: tenantID, ExpectedVersion: normalized.ExpectedVersion,
		BrandName: normalized.BrandName, BrandMark: normalized.BrandMark,
		PrimaryColor: normalized.PrimaryColor, AccentColor: normalized.AccentColor,
		Timezone: normalized.Timezone, Locale: normalized.Locale,
		Reason: normalized.Reason, AuditID: auditID, Event: normalized.Event,
	})
	if err != nil {
		return Settings{}, mapDependencyError(err)
	}
	if validateSettings(settings, tenantID, service.now()) != nil ||
		settings.Version != normalized.ExpectedVersion+1 {
		return Settings{}, ErrUnavailable
	}
	return settings, nil
}

func (service *Service) require(
	ctx context.Context,
	session authentication.Session,
	tenantID uuid.UUID,
	permissions ...authorization.TenantPermission,
) (authorization.Actor, error) {
	if service == nil || interfaceIsNil(service.repository) || interfaceIsNil(service.authority) ||
		service.newID == nil || service.now == nil || interfaceIsNil(ctx) || len(permissions) == 0 ||
		!validSession(session, tenantID, service.now()) {
		return authorization.Actor{}, ErrForbidden
	}
	actor := authorization.Actor{
		UserID: session.User.ID, SessionID: session.ID, ActiveTenantID: tenantID,
		AuthenticationMethod: session.AuthenticationMethod,
	}
	authority, err := service.authority.GetTenantAuthority(ctx, actor, tenantID)
	if err != nil {
		return authorization.Actor{}, mapDependencyError(err)
	}
	for _, permission := range permissions {
		if service.evaluator.RequireTenant(
			authority,
			permission,
			authorization.ResourceContext{TenantID: tenantID},
		) != nil {
			return authorization.Actor{}, ErrForbidden
		}
	}
	return actor, nil
}

func normalizeUpdate(input UpdateInput) (UpdateInput, error) {
	input.BrandName = strings.TrimSpace(input.BrandName)
	input.BrandMark = strings.ToUpper(strings.TrimSpace(input.BrandMark))
	input.PrimaryColor = strings.ToLower(strings.TrimSpace(input.PrimaryColor))
	input.AccentColor = strings.ToLower(strings.TrimSpace(input.AccentColor))
	input.Timezone = strings.TrimSpace(input.Timezone)
	input.Locale = strings.TrimSpace(input.Locale)
	input.Reason = strings.TrimSpace(input.Reason)
	if input.ExpectedVersion < 1 || input.ExpectedVersion >= math.MaxInt32 ||
		!validBrandName(input.BrandName) || !brandMarkPattern.MatchString(input.BrandMark) ||
		!brandColorPattern.MatchString(input.PrimaryColor) ||
		!brandColorPattern.MatchString(input.AccentColor) ||
		input.PrimaryColor == input.AccentColor || !validTimezone(input.Timezone) ||
		!validLocale(input.Locale) || !validReason(input.Reason) ||
		!validEvent(input.Event) {
		return UpdateInput{}, ErrInvalidInput
	}
	return input, nil
}

func validateSettings(settings Settings, tenantID uuid.UUID, now time.Time) error {
	if !validUUIDv7(settings.TenantID) || settings.TenantID != tenantID ||
		!validBrandName(settings.BrandName) || !brandMarkPattern.MatchString(settings.BrandMark) ||
		!brandColorPattern.MatchString(settings.PrimaryColor) ||
		!brandColorPattern.MatchString(settings.AccentColor) ||
		settings.PrimaryColor == settings.AccentColor || !validTimezone(settings.Timezone) ||
		!validLocale(settings.Locale) || settings.Version < 1 ||
		settings.UpdatedAt.IsZero() || settings.UpdatedAt.After(now.UTC().Add(time.Second)) {
		return ErrUnavailable
	}
	return nil
}

func validSession(session authentication.Session, tenantID uuid.UUID, now time.Time) bool {
	return validUUIDv7(tenantID) && validUUIDv7(session.ID) && validUUIDv7(session.User.ID) &&
		session.ActiveTenantID != nil && *session.ActiveTenantID == tenantID &&
		validAuthenticationMethod(session.AuthenticationMethod) && session.RevokedAt == nil &&
		session.IdleExpiresAt.After(now) && session.AbsoluteExpiresAt.After(now)
}

func validAuthenticationMethod(value string) bool {
	switch value {
	case "bootstrap_totp", "totp", "recovery_code", "ldap", "oidc", "saml", "passkey":
		return true
	default:
		return false
	}
}

func validBrandName(value string) bool {
	if !utf8.ValidString(value) || value != strings.TrimSpace(value) ||
		utf8.RuneCountInString(value) < 1 || utf8.RuneCountInString(value) > 80 {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			return false
		}
	}
	return true
}

func validReason(value string) bool {
	if !utf8.ValidString(value) || value != strings.TrimSpace(value) ||
		len([]byte(value)) < 1 || len([]byte(value)) > 2048 {
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

func validEvent(event authentication.EventContext) bool {
	return validUUIDv7(event.RequestID) && validUUIDv7(event.CorrelationID) &&
		event.RemoteAddress.IsValid() && len(event.UserAgent) >= 1 && len(event.UserAgent) <= 1024 &&
		utf8.ValidString(event.UserAgent)
}

func validUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func mapDependencyError(err error) error {
	switch {
	case errors.Is(err, ErrInvalidInput), errors.Is(err, authentication.ErrInvalidInput),
		errors.Is(err, authorization.ErrInvalidInput):
		return ErrInvalidInput
	case errors.Is(err, ErrForbidden), errors.Is(err, authentication.ErrForbidden),
		errors.Is(err, authorization.ErrForbidden):
		return ErrForbidden
	case errors.Is(err, ErrNotFound), errors.Is(err, authentication.ErrNotFound),
		errors.Is(err, authorization.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, ErrConflict), errors.Is(err, authentication.ErrConflict),
		errors.Is(err, authorization.ErrConflict):
		return ErrConflict
	default:
		return ErrUnavailable
	}
}

func interfaceIsNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
