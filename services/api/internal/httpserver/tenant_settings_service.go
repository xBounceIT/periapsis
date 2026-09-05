package httpserver

import (
	"context"
	"reflect"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/tenantsettings"
)

// TenantSettingsService is the tenant-scoped safe branding and regional
// settings boundary. The concrete service resolves live authority before the
// repository repeats the session, tenant, permission, and CAS checks in SQL.
type TenantSettingsService interface {
	Get(context.Context, authentication.Session, uuid.UUID) (tenantsettings.Settings, error)
	Update(context.Context, authentication.Session, uuid.UUID, tenantsettings.UpdateInput) (tenantsettings.Settings, error)
}

type unavailableTenantSettingsService struct{}

func (unavailableTenantSettingsService) Get(
	context.Context,
	authentication.Session,
	uuid.UUID,
) (tenantsettings.Settings, error) {
	return tenantsettings.Settings{}, tenantsettings.ErrUnavailable
}

func (unavailableTenantSettingsService) Update(
	context.Context,
	authentication.Session,
	uuid.UUID,
	tenantsettings.UpdateInput,
) (tenantsettings.Settings, error) {
	return tenantsettings.Settings{}, tenantsettings.ErrUnavailable
}

func tenantSettingsServiceIsNil(service TenantSettingsService) bool {
	if service == nil {
		return true
	}
	value := reflect.ValueOf(service)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

var _ TenantSettingsService = unavailableTenantSettingsService{}
