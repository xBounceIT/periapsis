package platform

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

func TestServiceDeniesPlatformTenantOperationsWithoutExplicitPermission(t *testing.T) {
	repository := &stubRepository{}
	service, err := NewService(repository)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	session := authentication.Session{User: authentication.User{ID: uuid.Must(uuid.NewV7())}}

	if _, err := service.ListTenants(context.Background(), session, nil, 50); !errors.Is(err, authentication.ErrForbidden) {
		t.Fatalf("ListTenants() error = %v, want forbidden", err)
	}
	if _, err := service.CreateTenant(context.Background(), session, CreateTenantInput{
		Slug: "acme", Name: "Acme", Timezone: "UTC", Locale: "en",
	}); !errors.Is(err, authentication.ErrForbidden) {
		t.Fatalf("CreateTenant() error = %v, want forbidden", err)
	}
	if repository.called {
		t.Fatal("repository was reached after authorization denial")
	}
}

func TestCreateTenantPreservesDatabasePermissionRecheck(t *testing.T) {
	repository := &stubRepository{createErr: authentication.ErrForbidden}
	service, _ := NewService(repository)
	session := authentication.Session{
		User:        authentication.User{ID: uuid.Must(uuid.NewV7())},
		Permissions: []authorization.Permission{authorization.PermissionPlatformTenantCreate},
	}

	_, err := service.CreateTenant(context.Background(), session, CreateTenantInput{
		Slug: "acme", Name: "Acme", Timezone: "UTC", Locale: "en",
	})
	if !errors.Is(err, authentication.ErrForbidden) {
		t.Fatalf("CreateTenant() error = %v, want DB recheck denial", err)
	}
}

func TestPlatformOperationsPreserveRepositoryInputRejection(t *testing.T) {
	repository := &stubRepository{
		createErr: authentication.ErrInvalidInput,
		listErr:   authentication.ErrInvalidInput,
	}
	service, _ := NewService(repository)
	session := authentication.Session{
		User: authentication.User{ID: uuid.Must(uuid.NewV7())},
		AuthenticationMethod: "totp",
		Permissions: []authorization.Permission{
			authorization.PermissionPlatformTenantRead,
			authorization.PermissionPlatformTenantCreate,
		},
	}
	if _, err := service.ListTenants(context.Background(), session, nil, 50);
		!errors.Is(err, authentication.ErrInvalidInput) {
		t.Fatalf("ListTenants() error = %v, want invalid input", err)
	}
	_, err := service.CreateTenant(context.Background(), session, CreateTenantInput{
		Slug: "acme", Name: "Acme", Timezone: "UTC", Locale: "en",
	})
	if !errors.Is(err, authentication.ErrInvalidInput) {
		t.Fatalf("CreateTenant() error = %v, want invalid input", err)
	}
}

func TestTimezoneRequiresStableIANAIdentity(t *testing.T) {
	if !validTimezone("Europe/Rome") || !validTimezone("UTC") {
		t.Fatal("valid IANA timezone was rejected")
	}
	if validTimezone("Local") || validTimezone("Europe/Not_A_Zone") {
		t.Fatal("process-local or unknown timezone was accepted")
	}
}

func TestTenantNameRejectsDatabaseControlCharacters(t *testing.T) {
	for _, name := range []string{"Acme\x00SOC", "Acme\nSOC", "Acme\u0085SOC"} {
		if validName(name) {
			t.Fatalf("tenant name %q containing a control character was accepted", name)
		}
	}
}

func TestLocaleMatchesTheHTTPContractAndHasKnownBaseLanguage(t *testing.T) {
	for _, locale := range []string{"en", "it-IT", "sr-Latn-RS"} {
		if !validLocale(locale) {
			t.Fatalf("validLocale(%q) = false", locale)
		}
	}
	for _, locale := range []string{"x-private", "und-US", "e-US", "english-US", "en_US"} {
		if validLocale(locale) {
			t.Fatalf("validLocale(%q) = true", locale)
		}
	}
}

type stubRepository struct {
	called    bool
	createErr error
	listErr   error
}

func (r *stubRepository) ListTenants(context.Context, ListTenantsParams) ([]authentication.Tenant, error) {
	r.called = true
	return nil, r.listErr
}

func (r *stubRepository) CreateTenant(context.Context, CreateTenantParams) (authentication.Tenant, error) {
	r.called = true
	return authentication.Tenant{}, r.createErr
}
