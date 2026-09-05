package platformoperations

import "context"

type Repository interface {
	ListUsers(context.Context, ListUsersParams) (UserPage, error)
	GetSettings(context.Context, ReadSettingsParams) (GlobalSettings, error)
	UpdateSettings(context.Context, UpdateSettingsParams) (GlobalSettings, error)
	GetHealth(context.Context, ReadHealthParams) (Health, error)
	ListQueues(context.Context, ReadQueueParams) (QueueSnapshot, error)
	ListFailedNotifications(context.Context, ListFailedNotificationsParams) (FailedNotificationPage, error)
	ListFeatureFlags(context.Context, ReadFeatureFlagsParams) (FeatureFlagList, error)
	UpdateFeatureFlag(context.Context, UpdateFeatureFlagParams) (FeatureFlag, error)
}
