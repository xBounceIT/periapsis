package platformoperations

import (
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
)

const (
	ProjectionVersion                   int32  = 1
	FlagPlatformFailedNotificationsView string = "platform_failed_notifications_view"
)

type LiveSessionSummary struct {
	Method           string `json:"method"`
	LiveSessionCount int32  `json:"liveSessionCount"`
}

type User struct {
	ID                                 uuid.UUID            `json:"id"`
	Email                              *string              `json:"email"`
	DisplayName                        string               `json:"displayName"`
	Active                             bool                 `json:"active"`
	PlatformRoles                      []string             `json:"platformRoles"`
	ActiveTenantMembershipCount        int32                `json:"activeTenantMembershipCount"`
	TotalTenantMembershipCount         int32                `json:"totalTenantMembershipCount"`
	LiveSessionsByAuthenticationMethod []LiveSessionSummary `json:"liveSessionsByAuthenticationMethod"`
}

type UserPage struct {
	ProjectionVersion int32      `json:"projectionVersion"`
	Items             []User     `json:"items"`
	NextCursor        *uuid.UUID `json:"nextCursor"`
}

type GlobalSettings struct {
	PlatformName    string
	DefaultLocale   string
	DefaultTimezone string
	SupportURL      *string
	Version         int32
	UpdatedAt       time.Time
}

type QueueSource struct {
	Key                  string `json:"key"`
	PendingCount         int64  `json:"pendingCount"`
	InFlightCount        int64  `json:"inFlightCount"`
	FailedCount          int64  `json:"failedCount"`
	OldestPendingSeconds int64  `json:"oldestPendingSeconds"`
}

type QueueSnapshot struct {
	ProjectionVersion int32         `json:"projectionVersion"`
	CheckedAt         time.Time     `json:"checkedAt"`
	Sources           []QueueSource `json:"sources"`
}

type HealthCheck struct {
	Key                  string `json:"key"`
	Status               string `json:"status"`
	PendingCount         *int64 `json:"pendingCount,omitempty"`
	FailedCount          *int64 `json:"failedCount,omitempty"`
	OldestPendingSeconds *int64 `json:"oldestPendingSeconds,omitempty"`
}

type Health struct {
	ProjectionVersion int32         `json:"projectionVersion"`
	CheckedAt         time.Time     `json:"checkedAt"`
	Status            string        `json:"status"`
	Checks            []HealthCheck `json:"checks"`
}

type FeatureFlag struct {
	Key       string    `json:"key"`
	Enabled   bool      `json:"enabled"`
	Version   int32     `json:"version"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type FeatureFlagList struct {
	ProjectionVersion int32         `json:"projectionVersion"`
	Items             []FeatureFlag `json:"items"`
}

type FailedNotification struct {
	ID           uuid.UUID `json:"id"`
	TenantID     uuid.UUID `json:"tenantId"`
	Channel      string    `json:"channel"`
	FailureClass string    `json:"failureClass"`
	FailureCode  string    `json:"failureCode"`
	FailureAt    time.Time `json:"failureAt"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
	AttemptCount int32     `json:"attemptCount"`
}

type FailedNotificationCursor struct {
	FailureAt time.Time `json:"failureAt"`
	ID        uuid.UUID `json:"id"`
}

type FailedNotificationPage struct {
	ProjectionVersion int32                     `json:"projectionVersion"`
	Items             []FailedNotification      `json:"items"`
	NextCursor        *FailedNotificationCursor `json:"nextCursor"`
}

type ReadInput struct {
	Event authentication.EventContext
}

type ListUsersInput struct {
	After *uuid.UUID
	Limit int32
	Event authentication.EventContext
}

type ListFailedNotificationsInput struct {
	After *FailedNotificationCursor
	Limit int32
	Event authentication.EventContext
}

type UpdateSettingsInput struct {
	ExpectedVersion int32
	PlatformName    string
	DefaultLocale   string
	DefaultTimezone string
	SupportURL      *string
	Reason          string
	Event           authentication.EventContext
}

type UpdateFeatureFlagInput struct {
	Key             string
	ExpectedVersion int32
	Enabled         bool
	Reason          string
	Event           authentication.EventContext
}

type ReadParams struct {
	Session authentication.Session
	AuditID uuid.UUID
	Event   authentication.EventContext
}

type ListUsersParams struct {
	ReadParams
	After    *uuid.UUID
	Limit    int32
	Validate func(UserPage) (UserPage, error)
}

type ListFailedNotificationsParams struct {
	ReadParams
	After    *FailedNotificationCursor
	Limit    int32
	Validate func(FailedNotificationPage) (FailedNotificationPage, error)
}

type ReadQueueParams struct {
	ReadParams
	Validate func(QueueSnapshot) (QueueSnapshot, error)
}

type ReadHealthParams struct {
	ReadParams
	Validate func(Health) (Health, error)
}

type ReadSettingsParams struct {
	ReadParams
	Validate func(GlobalSettings) (GlobalSettings, error)
}

type ReadFeatureFlagsParams struct {
	ReadParams
	Validate func(FeatureFlagList) (FeatureFlagList, error)
}

type UpdateSettingsParams struct {
	ReadParams
	ExpectedVersion int32
	PlatformName    string
	DefaultLocale   string
	DefaultTimezone string
	SupportURL      *string
	Reason          string
	Validate        func(GlobalSettings) (GlobalSettings, error)
}

type UpdateFeatureFlagParams struct {
	ReadParams
	Key             string
	ExpectedVersion int32
	Enabled         bool
	Reason          string
	Validate        func(FeatureFlag) (FeatureFlag, error)
}
