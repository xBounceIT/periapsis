package httpserver

import (
	"context"
	"reflect"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoperations"
)

// PlatformOperationsService is the tenantless control-plane boundary. Its
// concrete repository repeats session, epoch, permission, MFA, and audit checks
// in the same database transaction as each projection or mutation.
type PlatformOperationsService interface {
	ListUsers(context.Context, authentication.Session, platformoperations.ListUsersInput) (platformoperations.UserPage, error)
	GetSettings(context.Context, authentication.Session, platformoperations.ReadInput) (platformoperations.GlobalSettings, error)
	UpdateSettings(context.Context, authentication.Session, platformoperations.UpdateSettingsInput) (platformoperations.GlobalSettings, error)
	GetHealth(context.Context, authentication.Session, platformoperations.ReadInput) (platformoperations.Health, error)
	ListQueues(context.Context, authentication.Session, platformoperations.ReadInput) (platformoperations.QueueSnapshot, error)
	ListFailedNotifications(context.Context, authentication.Session, platformoperations.ListFailedNotificationsInput) (platformoperations.FailedNotificationPage, error)
	ListFeatureFlags(context.Context, authentication.Session, platformoperations.ReadInput) (platformoperations.FeatureFlagList, error)
	UpdateFeatureFlag(context.Context, authentication.Session, platformoperations.UpdateFeatureFlagInput) (platformoperations.FeatureFlag, error)
}

type unavailablePlatformOperationsService struct{}

func (unavailablePlatformOperationsService) ListUsers(
	context.Context, authentication.Session, platformoperations.ListUsersInput,
) (platformoperations.UserPage, error) {
	return platformoperations.UserPage{}, platformoperations.ErrUnavailable
}

func (unavailablePlatformOperationsService) GetSettings(
	context.Context, authentication.Session, platformoperations.ReadInput,
) (platformoperations.GlobalSettings, error) {
	return platformoperations.GlobalSettings{}, platformoperations.ErrUnavailable
}

func (unavailablePlatformOperationsService) UpdateSettings(
	context.Context, authentication.Session, platformoperations.UpdateSettingsInput,
) (platformoperations.GlobalSettings, error) {
	return platformoperations.GlobalSettings{}, platformoperations.ErrUnavailable
}

func (unavailablePlatformOperationsService) GetHealth(
	context.Context, authentication.Session, platformoperations.ReadInput,
) (platformoperations.Health, error) {
	return platformoperations.Health{}, platformoperations.ErrUnavailable
}

func (unavailablePlatformOperationsService) ListQueues(
	context.Context, authentication.Session, platformoperations.ReadInput,
) (platformoperations.QueueSnapshot, error) {
	return platformoperations.QueueSnapshot{}, platformoperations.ErrUnavailable
}

func (unavailablePlatformOperationsService) ListFailedNotifications(
	context.Context, authentication.Session, platformoperations.ListFailedNotificationsInput,
) (platformoperations.FailedNotificationPage, error) {
	return platformoperations.FailedNotificationPage{}, platformoperations.ErrUnavailable
}

func (unavailablePlatformOperationsService) ListFeatureFlags(
	context.Context, authentication.Session, platformoperations.ReadInput,
) (platformoperations.FeatureFlagList, error) {
	return platformoperations.FeatureFlagList{}, platformoperations.ErrUnavailable
}

func (unavailablePlatformOperationsService) UpdateFeatureFlag(
	context.Context, authentication.Session, platformoperations.UpdateFeatureFlagInput,
) (platformoperations.FeatureFlag, error) {
	return platformoperations.FeatureFlag{}, platformoperations.ErrUnavailable
}

func platformOperationsServiceIsNil(service PlatformOperationsService) bool {
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

var _ PlatformOperationsService = unavailablePlatformOperationsService{}
