package platformoperations

import (
	"bytes"
	"context"
	"errors"
	"math"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"
	_ "time/tzdata"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

var localePattern = regexp.MustCompile(`^[a-z]{2,3}(?:-[A-Z]{2})?$`)

type Service struct {
	repository Repository
	evaluator  authorization.Evaluator
	newID      func() (uuid.UUID, error)
	now        func() time.Time
}

func NewService(repository Repository) (*Service, error) {
	if interfaceIsNil(repository) {
		return nil, errors.New("platform operations repository is required")
	}
	return &Service{
		repository: repository,
		evaluator:  authorization.Evaluator{},
		newID:      uuid.NewV7,
		now:        time.Now,
	}, nil
}

func (service *Service) ListUsers(
	ctx context.Context,
	session authentication.Session,
	input ListUsersInput,
) (UserPage, error) {
	if err := service.require(ctx, session, authorization.PermissionPlatformUserRead); err != nil {
		return UserPage{}, err
	}
	if input.Limit < 1 || input.Limit > 100 || !validEvent(input.Event) ||
		input.After != nil && !validUUIDv7(*input.After) {
		return UserPage{}, ErrInvalidInput
	}
	auditID, err := service.auditID()
	if err != nil {
		return UserPage{}, err
	}
	page, err := service.repository.ListUsers(ctx, ListUsersParams{
		ReadParams: ReadParams{Session: session, AuditID: auditID, Event: input.Event},
		After:      input.After, Limit: input.Limit,
		Validate: func(page UserPage) (UserPage, error) {
			return validateUserPage(page)
		},
	})
	if err != nil {
		return UserPage{}, mapDependencyError(err)
	}
	return validateUserPage(page)
}

func (service *Service) GetSettings(
	ctx context.Context,
	session authentication.Session,
	input ReadInput,
) (GlobalSettings, error) {
	if err := service.require(ctx, session, authorization.PermissionPlatformSettingsRead); err != nil {
		return GlobalSettings{}, err
	}
	auditID, err := service.readAuditID(input.Event)
	if err != nil {
		return GlobalSettings{}, err
	}
	settings, err := service.repository.GetSettings(ctx, ReadSettingsParams{
		ReadParams: ReadParams{Session: session, AuditID: auditID, Event: input.Event},
		Validate: func(settings GlobalSettings) (GlobalSettings, error) {
			return validateSettings(settings, service.now().UTC())
		},
	})
	if err != nil {
		return GlobalSettings{}, mapDependencyError(err)
	}
	return validateSettings(settings, service.now().UTC())
}

func (service *Service) UpdateSettings(
	ctx context.Context,
	session authentication.Session,
	input UpdateSettingsInput,
) (GlobalSettings, error) {
	if err := service.require(ctx, session,
		authorization.PermissionPlatformSettingsRead,
		authorization.PermissionPlatformSettingsManage,
	); err != nil {
		return GlobalSettings{}, err
	}
	normalized, err := normalizeSettingsUpdate(input)
	if err != nil {
		return GlobalSettings{}, err
	}
	auditID, err := service.auditID()
	if err != nil {
		return GlobalSettings{}, err
	}
	settings, err := service.repository.UpdateSettings(ctx, UpdateSettingsParams{
		ReadParams:      ReadParams{Session: session, AuditID: auditID, Event: normalized.Event},
		ExpectedVersion: normalized.ExpectedVersion, PlatformName: normalized.PlatformName,
		DefaultLocale: normalized.DefaultLocale, DefaultTimezone: normalized.DefaultTimezone,
		SupportURL: normalized.SupportURL, Reason: normalized.Reason,
		Validate: func(settings GlobalSettings) (GlobalSettings, error) {
			validated, validateErr := validateSettings(settings, service.now().UTC())
			if validateErr != nil || settings.Version != normalized.ExpectedVersion+1 {
				return GlobalSettings{}, ErrUnavailable
			}
			return validated, nil
		},
	})
	if err != nil {
		return GlobalSettings{}, mapDependencyError(err)
	}
	validated, err := validateSettings(settings, service.now().UTC())
	if err != nil || validated.Version != normalized.ExpectedVersion+1 {
		return GlobalSettings{}, ErrUnavailable
	}
	return validated, nil
}

func (service *Service) GetHealth(
	ctx context.Context,
	session authentication.Session,
	input ReadInput,
) (Health, error) {
	if err := service.require(ctx, session, authorization.PermissionPlatformOperationsRead); err != nil {
		return Health{}, err
	}
	auditID, err := service.readAuditID(input.Event)
	if err != nil {
		return Health{}, err
	}
	health, err := service.repository.GetHealth(ctx, ReadHealthParams{
		ReadParams: ReadParams{Session: session, AuditID: auditID, Event: input.Event},
		Validate: func(health Health) (Health, error) {
			return validateHealth(health, service.now().UTC())
		},
	})
	if err != nil {
		return Health{}, mapDependencyError(err)
	}
	return validateHealth(health, service.now().UTC())
}

func (service *Service) ListQueues(
	ctx context.Context,
	session authentication.Session,
	input ReadInput,
) (QueueSnapshot, error) {
	if err := service.require(ctx, session, authorization.PermissionPlatformOperationsRead); err != nil {
		return QueueSnapshot{}, err
	}
	auditID, err := service.readAuditID(input.Event)
	if err != nil {
		return QueueSnapshot{}, err
	}
	queues, err := service.repository.ListQueues(ctx, ReadQueueParams{
		ReadParams: ReadParams{Session: session, AuditID: auditID, Event: input.Event},
		Validate: func(snapshot QueueSnapshot) (QueueSnapshot, error) {
			return validateQueueSnapshot(snapshot, service.now().UTC())
		},
	})
	if err != nil {
		return QueueSnapshot{}, mapDependencyError(err)
	}
	return validateQueueSnapshot(queues, service.now().UTC())
}

func (service *Service) ListFailedNotifications(
	ctx context.Context,
	session authentication.Session,
	input ListFailedNotificationsInput,
) (FailedNotificationPage, error) {
	if err := service.require(ctx, session, authorization.PermissionPlatformOperationsRead); err != nil {
		return FailedNotificationPage{}, err
	}
	if input.Limit < 1 || input.Limit > 100 || !validEvent(input.Event) ||
		input.After != nil && (!validUUIDv7(input.After.ID) || input.After.FailureAt.IsZero()) {
		return FailedNotificationPage{}, ErrInvalidInput
	}
	auditID, err := service.auditID()
	if err != nil {
		return FailedNotificationPage{}, err
	}
	page, err := service.repository.ListFailedNotifications(ctx, ListFailedNotificationsParams{
		ReadParams: ReadParams{Session: session, AuditID: auditID, Event: input.Event},
		After:      input.After, Limit: input.Limit,
		Validate: func(page FailedNotificationPage) (FailedNotificationPage, error) {
			return validateFailedNotificationPage(page, service.now().UTC())
		},
	})
	if err != nil {
		return FailedNotificationPage{}, mapDependencyError(err)
	}
	return validateFailedNotificationPage(page, service.now().UTC())
}

func (service *Service) ListFeatureFlags(
	ctx context.Context,
	session authentication.Session,
	input ReadInput,
) (FeatureFlagList, error) {
	if err := service.require(ctx, session, authorization.PermissionPlatformFeatureFlagRead); err != nil {
		return FeatureFlagList{}, err
	}
	auditID, err := service.readAuditID(input.Event)
	if err != nil {
		return FeatureFlagList{}, err
	}
	flags, err := service.repository.ListFeatureFlags(ctx, ReadFeatureFlagsParams{
		ReadParams: ReadParams{Session: session, AuditID: auditID, Event: input.Event},
		Validate: func(flags FeatureFlagList) (FeatureFlagList, error) {
			return validateFeatureFlagList(flags, service.now().UTC())
		},
	})
	if err != nil {
		return FeatureFlagList{}, mapDependencyError(err)
	}
	return validateFeatureFlagList(flags, service.now().UTC())
}

func (service *Service) UpdateFeatureFlag(
	ctx context.Context,
	session authentication.Session,
	input UpdateFeatureFlagInput,
) (FeatureFlag, error) {
	if err := service.require(ctx, session,
		authorization.PermissionPlatformFeatureFlagRead,
		authorization.PermissionPlatformFeatureFlagManage,
	); err != nil {
		return FeatureFlag{}, err
	}
	input.Key = strings.TrimSpace(input.Key)
	input.Reason = strings.TrimSpace(input.Reason)
	if input.Key != FlagPlatformFailedNotificationsView || input.ExpectedVersion < 1 ||
		input.ExpectedVersion >= math.MaxInt32 || !validReason(input.Reason) || !validEvent(input.Event) {
		return FeatureFlag{}, ErrInvalidInput
	}
	auditID, err := service.auditID()
	if err != nil {
		return FeatureFlag{}, err
	}
	flag, err := service.repository.UpdateFeatureFlag(ctx, UpdateFeatureFlagParams{
		ReadParams: ReadParams{Session: session, AuditID: auditID, Event: input.Event},
		Key:        input.Key, ExpectedVersion: input.ExpectedVersion,
		Enabled: input.Enabled, Reason: input.Reason,
		Validate: func(flag FeatureFlag) (FeatureFlag, error) {
			validated, validateErr := validateFeatureFlag(flag, service.now().UTC())
			if validateErr != nil || flag.Version != input.ExpectedVersion+1 {
				return FeatureFlag{}, ErrUnavailable
			}
			return validated, nil
		},
	})
	if err != nil {
		return FeatureFlag{}, mapDependencyError(err)
	}
	validated, err := validateFeatureFlag(flag, service.now().UTC())
	if err != nil || validated.Version != input.ExpectedVersion+1 {
		return FeatureFlag{}, ErrUnavailable
	}
	return validated, nil
}

func (service *Service) require(
	ctx context.Context,
	session authentication.Session,
	permissions ...authorization.Permission,
) error {
	if service == nil || interfaceIsNil(service.repository) || service.newID == nil ||
		service.now == nil || ctx == nil || len(permissions) == 0 ||
		!validPlatformSession(session, service.now().UTC()) {
		return ErrForbidden
	}
	for _, permission := range permissions {
		if service.evaluator.Require(session.Permissions, permission) != nil {
			return ErrForbidden
		}
	}
	return nil
}

func (service *Service) readAuditID(event authentication.EventContext) (uuid.UUID, error) {
	if !validEvent(event) {
		return uuid.Nil, ErrInvalidInput
	}
	return service.auditID()
}

func (service *Service) auditID() (uuid.UUID, error) {
	id, err := service.newID()
	if err != nil || !validUUIDv7(id) {
		return uuid.Nil, ErrUnavailable
	}
	return id, nil
}

func normalizeSettingsUpdate(input UpdateSettingsInput) (UpdateSettingsInput, error) {
	input.PlatformName = strings.TrimSpace(input.PlatformName)
	input.DefaultLocale = strings.TrimSpace(input.DefaultLocale)
	input.DefaultTimezone = strings.TrimSpace(input.DefaultTimezone)
	input.Reason = strings.TrimSpace(input.Reason)
	if input.SupportURL != nil {
		normalized := strings.TrimSpace(*input.SupportURL)
		input.SupportURL = &normalized
	}
	if input.ExpectedVersion < 1 || input.ExpectedVersion >= math.MaxInt32 ||
		!validSafeText(input.PlatformName, 1, 120) ||
		!localePattern.MatchString(input.DefaultLocale) ||
		!validTimezone(input.DefaultTimezone) || !validSupportURL(input.SupportURL) ||
		!validReason(input.Reason) || !validEvent(input.Event) {
		return UpdateSettingsInput{}, ErrInvalidInput
	}
	return input, nil
}

func validateUserPage(page UserPage) (UserPage, error) {
	if page.ProjectionVersion != ProjectionVersion || len(page.Items) > 100 ||
		page.NextCursor != nil && !validUUIDv7(*page.NextCursor) {
		return UserPage{}, ErrUnavailable
	}
	var previousUserID uuid.UUID
	for index := range page.Items {
		user := &page.Items[index]
		if !validUUIDv7(user.ID) || !validSafeText(user.DisplayName, 1, 256) ||
			user.ActiveTenantMembershipCount < 0 || user.TotalTenantMembershipCount < 0 ||
			user.ActiveTenantMembershipCount > user.TotalTenantMembershipCount ||
			len(user.PlatformRoles) > 32 || len(user.LiveSessionsByAuthenticationMethod) > 7 {
			return UserPage{}, ErrUnavailable
		}
		if index > 0 && bytes.Compare(previousUserID[:], user.ID[:]) >= 0 {
			return UserPage{}, ErrUnavailable
		}
		previousUserID = user.ID
		if user.Email != nil && !validSafeText(*user.Email, 3, 320) {
			return UserPage{}, ErrUnavailable
		}
		for roleIndex, role := range user.PlatformRoles {
			if !validKey(role, 128) || roleIndex > 0 && user.PlatformRoles[roleIndex-1] >= role {
				return UserPage{}, ErrUnavailable
			}
		}
		for methodIndex, summary := range user.LiveSessionsByAuthenticationMethod {
			if !knownStoredAuthenticationMethod(summary.Method) || summary.LiveSessionCount < 1 ||
				methodIndex > 0 &&
					user.LiveSessionsByAuthenticationMethod[methodIndex-1].Method >= summary.Method {
				return UserPage{}, ErrUnavailable
			}
		}
	}
	if page.NextCursor != nil &&
		(len(page.Items) == 0 || *page.NextCursor != page.Items[len(page.Items)-1].ID) {
		return UserPage{}, ErrUnavailable
	}
	return cloneUserPage(page), nil
}

func validateSettings(settings GlobalSettings, now time.Time) (GlobalSettings, error) {
	if !validSafeText(settings.PlatformName, 1, 120) ||
		!localePattern.MatchString(settings.DefaultLocale) ||
		!validTimezone(settings.DefaultTimezone) || !validSupportURL(settings.SupportURL) ||
		settings.Version < 1 || settings.UpdatedAt.IsZero() ||
		settings.UpdatedAt.After(now.Add(time.Second)) {
		return GlobalSettings{}, ErrUnavailable
	}
	return cloneSettings(settings), nil
}

var queueKeys = []string{
	"outbox", "notification_delivery", "ticket_bulk", "ticket_export",
	"ticket_export_cleanup", "tenant_audit_export", "platform_audit_export",
	"sla_evaluation", "sla_trigger_action", "sla_event_ingress",
	"dfir_evidence_scan", "dfir_evidence_cleanup", "ldap_sync",
}

func validateQueueSnapshot(snapshot QueueSnapshot, now time.Time) (QueueSnapshot, error) {
	if snapshot.ProjectionVersion != ProjectionVersion || snapshot.CheckedAt.IsZero() ||
		snapshot.CheckedAt.After(now.Add(time.Second)) || len(snapshot.Sources) != len(queueKeys) {
		return QueueSnapshot{}, ErrUnavailable
	}
	for index, expected := range queueKeys {
		source := snapshot.Sources[index]
		if source.Key != expected || source.PendingCount < 0 || source.InFlightCount < 0 ||
			source.FailedCount < 0 || source.OldestPendingSeconds < 0 {
			return QueueSnapshot{}, ErrUnavailable
		}
	}
	snapshot.Sources = append([]QueueSource(nil), snapshot.Sources...)
	return snapshot, nil
}

func validateHealth(health Health, now time.Time) (Health, error) {
	if health.ProjectionVersion != ProjectionVersion || health.CheckedAt.IsZero() ||
		health.CheckedAt.After(now.Add(time.Second)) || !knownHealthStatus(health.Status) ||
		len(health.Checks) != 4 {
		return Health{}, ErrUnavailable
	}
	expected := []string{"database", "platform_audit_chain", "queue_backlog", "queue_failures"}
	degraded := false
	for index, key := range expected {
		check := health.Checks[index]
		if check.Key != key || !knownHealthStatus(check.Status) ||
			!validHealthCheckShape(index, check) {
			return Health{}, ErrUnavailable
		}
		degraded = degraded || check.Status == "degraded"
	}
	if (health.Status == "degraded") != degraded {
		return Health{}, ErrUnavailable
	}
	health.Checks = append([]HealthCheck(nil), health.Checks...)
	return health, nil
}

func validHealthCheckShape(index int, check HealthCheck) bool {
	switch index {
	case 0, 1:
		return check.PendingCount == nil && check.FailedCount == nil &&
			check.OldestPendingSeconds == nil
	case 2:
		return check.PendingCount != nil && *check.PendingCount >= 0 &&
			check.FailedCount == nil && check.OldestPendingSeconds != nil &&
			*check.OldestPendingSeconds >= 0
	case 3:
		return check.PendingCount == nil && check.FailedCount != nil &&
			*check.FailedCount >= 0 && check.OldestPendingSeconds == nil
	default:
		return false
	}
}

func validateFeatureFlagList(flags FeatureFlagList, now time.Time) (FeatureFlagList, error) {
	if flags.ProjectionVersion != ProjectionVersion || len(flags.Items) != 1 {
		return FeatureFlagList{}, ErrUnavailable
	}
	flag, err := validateFeatureFlag(flags.Items[0], now)
	if err != nil {
		return FeatureFlagList{}, err
	}
	flags.Items = []FeatureFlag{flag}
	return flags, nil
}

func validateFeatureFlag(flag FeatureFlag, now time.Time) (FeatureFlag, error) {
	if flag.Key != FlagPlatformFailedNotificationsView || flag.Version < 1 ||
		flag.UpdatedAt.IsZero() || flag.UpdatedAt.After(now.Add(time.Second)) {
		return FeatureFlag{}, ErrUnavailable
	}
	return flag, nil
}

func validateFailedNotificationPage(
	page FailedNotificationPage,
	now time.Time,
) (FailedNotificationPage, error) {
	if page.ProjectionVersion != ProjectionVersion || len(page.Items) > 100 ||
		page.NextCursor != nil && (!validUUIDv7(page.NextCursor.ID) || page.NextCursor.FailureAt.IsZero()) {
		return FailedNotificationPage{}, ErrUnavailable
	}
	var previous FailedNotification
	for index, item := range page.Items {
		if !validUUIDv7(item.ID) || !validUUIDv7(item.TenantID) ||
			!knownNotificationChannel(item.Channel) || !knownFailureClass(item.FailureClass) ||
			!knownFailureCode(item.FailureCode) || item.FailureAt.IsZero() ||
			item.FailureAt.After(now.Add(time.Second)) || item.CreatedAt.IsZero() ||
			item.UpdatedAt.IsZero() || item.UpdatedAt.After(now.Add(time.Second)) ||
			item.CreatedAt.After(item.FailureAt) || item.FailureAt.After(item.UpdatedAt) ||
			item.AttemptCount < 0 {
			return FailedNotificationPage{}, ErrUnavailable
		}
		if index > 0 && !failedNotificationTupleBefore(item, previous) {
			return FailedNotificationPage{}, ErrUnavailable
		}
		previous = item
	}
	if page.NextCursor != nil {
		if len(page.Items) == 0 {
			return FailedNotificationPage{}, ErrUnavailable
		}
		last := page.Items[len(page.Items)-1]
		if page.NextCursor.ID != last.ID || !page.NextCursor.FailureAt.Equal(last.FailureAt) {
			return FailedNotificationPage{}, ErrUnavailable
		}
	}
	page.Items = append([]FailedNotification(nil), page.Items...)
	if page.NextCursor != nil {
		cursor := *page.NextCursor
		page.NextCursor = &cursor
	}
	return page, nil
}

func validPlatformSession(session authentication.Session, now time.Time) bool {
	return validUUIDv7(session.ID) && validUUIDv7(session.User.ID) &&
		session.ActiveTenantID == nil && session.RevokedAt == nil &&
		knownHighAssuranceAuthenticationMethod(session.AuthenticationMethod) &&
		session.IdleExpiresAt.After(now) && session.AbsoluteExpiresAt.After(now)
}

func validEvent(event authentication.EventContext) bool {
	return validUUIDv7(event.RequestID) && validUUIDv7(event.CorrelationID) &&
		event.RemoteAddress.IsValid() && event.RemoteAddress.Zone() == "" &&
		validSafeText(event.UserAgent, 1, 512)
}

func validReason(value string) bool {
	if len(value) < 1 || len(value) > 500 || value != strings.TrimSpace(value) {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x20 || value[index] > 0x7e || value[index] == ',' {
			return false
		}
	}
	return true
}

func validSafeText(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) || value != strings.TrimSpace(value) {
		return false
	}
	length := utf8.RuneCountInString(value)
	if length < minimum || length > maximum {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			return false
		}
	}
	return true
}

func validSupportURL(value *string) bool {
	if value == nil {
		return true
	}
	if !validSafeText(*value, 9, 2048) || strings.ContainsFunc(*value, unicode.IsSpace) {
		return false
	}
	parsed, err := url.Parse(*value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" &&
		parsed.Hostname() != "" && parsed.User == nil && parsed.Opaque == ""
}

func validTimezone(value string) bool {
	if !validSafeText(value, 1, 64) || value == "Local" {
		return false
	}
	_, err := time.LoadLocation(value)
	return err == nil
}

func validKey(value string, maximum int) bool {
	return validSafeText(value, 1, maximum) &&
		!strings.ContainsFunc(value, func(character rune) bool {
			return !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
				character == '_' || character == '.' || character == '-')
		})
}

func knownHighAssuranceAuthenticationMethod(value string) bool {
	switch value {
	case "bootstrap_totp", "totp", "passkey", "oidc", "saml", "ldap":
		return true
	default:
		return false
	}
}

func knownStoredAuthenticationMethod(value string) bool {
	return value == "recovery_code" || knownHighAssuranceAuthenticationMethod(value)
}

func failedNotificationTupleBefore(current, previous FailedNotification) bool {
	if current.FailureAt.Before(previous.FailureAt) {
		return true
	}
	return current.FailureAt.Equal(previous.FailureAt) && bytes.Compare(current.ID[:], previous.ID[:]) < 0
}

func knownHealthStatus(value string) bool { return value == "healthy" || value == "degraded" }

func knownNotificationChannel(value string) bool { return value == "email" || value == "webhook" }

func knownFailureClass(value string) bool {
	switch value {
	case "authentication", "connectivity", "rate_limited", "render", "security",
		"timeout", "tls", "unknown", "submission_uncertain":
		return true
	default:
		return false
	}
}

func knownFailureCode(value string) bool {
	switch value {
	case "retry_scheduled", "terminal_failure", "submission_uncertain",
		"configuration_revoked", "tenant_suspended", "unknown":
		return true
	default:
		return false
	}
}

func cloneUserPage(page UserPage) UserPage {
	page.Items = append([]User(nil), page.Items...)
	for index := range page.Items {
		user := &page.Items[index]
		user.PlatformRoles = append([]string(nil), user.PlatformRoles...)
		user.LiveSessionsByAuthenticationMethod = append(
			[]LiveSessionSummary(nil), user.LiveSessionsByAuthenticationMethod...,
		)
		if user.Email != nil {
			email := *user.Email
			user.Email = &email
		}
	}
	if page.NextCursor != nil {
		cursor := *page.NextCursor
		page.NextCursor = &cursor
	}
	return page
}

func cloneSettings(settings GlobalSettings) GlobalSettings {
	if settings.SupportURL != nil {
		value := *settings.SupportURL
		settings.SupportURL = &value
	}
	return settings
}

func validUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func mapDependencyError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
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
