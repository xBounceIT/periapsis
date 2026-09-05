package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/services/api/internal/platformoperations"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

const maximumPlatformOperationsDocumentBytes = 256 * 1024

type PlatformOperationsRepository struct {
	begin transactionBeginner
}

func NewPlatformOperationsRepository(pool *pgxpool.Pool) *PlatformOperationsRepository {
	return &PlatformOperationsRepository{begin: poolTransactionBeginner(pool)}
}

var _ platformoperations.Repository = (*PlatformOperationsRepository)(nil)

func (repository *PlatformOperationsRepository) ListUsers(
	ctx context.Context,
	params platformoperations.ListUsersParams,
) (platformoperations.UserPage, error) {
	if params.Validate == nil || params.Limit < 1 || params.Limit > 100 ||
		params.After != nil && !authorizationUUIDv7(*params.After) {
		return platformoperations.UserPage{}, platformoperations.ErrInvalidInput
	}
	return withPlatformOperationsTransaction(ctx, repository, params.ReadParams,
		func(queries *dbsql.Queries, event auditArguments) (platformoperations.UserPage, error) {
			document, err := queries.ListPlatformUsersOperation(ctx, dbsql.ListPlatformUsersOperationParams{
				SessionID: toDatabaseUUID(params.Session.ID), AfterUserID: optionalDatabaseUUID(params.After),
				PageLimit: params.Limit, AuditID: toDatabaseUUID(params.AuditID),
				RequestID: event.requestID, CorrelationID: event.correlationID,
				IpAddress: params.Event.RemoteAddress.Unmap(), UserAgent: params.Event.UserAgent,
			})
			if err != nil {
				return platformoperations.UserPage{}, err
			}
			page, err := decodePlatformOperationsDocument[platformoperations.UserPage](document)
			if err != nil {
				return platformoperations.UserPage{}, err
			}
			return params.Validate(page)
		})
}

func (repository *PlatformOperationsRepository) GetSettings(
	ctx context.Context,
	params platformoperations.ReadSettingsParams,
) (platformoperations.GlobalSettings, error) {
	if params.Validate == nil {
		return platformoperations.GlobalSettings{}, platformoperations.ErrInvalidInput
	}
	return withPlatformOperationsTransaction(ctx, repository, params.ReadParams,
		func(queries *dbsql.Queries, event auditArguments) (platformoperations.GlobalSettings, error) {
			row, err := queries.GetPlatformGlobalSettingsOperation(ctx,
				dbsql.GetPlatformGlobalSettingsOperationParams{
					SessionID: toDatabaseUUID(params.Session.ID), AuditID: toDatabaseUUID(params.AuditID),
					RequestID: event.requestID, CorrelationID: event.correlationID,
					IpAddress: params.Event.RemoteAddress.Unmap(), UserAgent: params.Event.UserAgent,
				})
			if err != nil {
				return platformoperations.GlobalSettings{}, err
			}
			settings, err := mapPlatformGlobalSettings(
				row.PlatformName, row.DefaultLocale, row.DefaultTimezone,
				row.SupportUrl, row.Version, row.UpdatedAt.Time,
			)
			if err != nil {
				return platformoperations.GlobalSettings{}, err
			}
			return params.Validate(settings)
		})
}

func (repository *PlatformOperationsRepository) UpdateSettings(
	ctx context.Context,
	params platformoperations.UpdateSettingsParams,
) (platformoperations.GlobalSettings, error) {
	if params.Validate == nil || params.ExpectedVersion < 1 {
		return platformoperations.GlobalSettings{}, platformoperations.ErrInvalidInput
	}
	return withPlatformOperationsTransaction(ctx, repository, params.ReadParams,
		func(queries *dbsql.Queries, event auditArguments) (platformoperations.GlobalSettings, error) {
			row, err := queries.UpdatePlatformGlobalSettingsOperation(ctx,
				dbsql.UpdatePlatformGlobalSettingsOperationParams{
					SessionID: toDatabaseUUID(params.Session.ID), ExpectedVersion: params.ExpectedVersion,
					PlatformName: params.PlatformName, DefaultLocale: params.DefaultLocale,
					DefaultTimezone: params.DefaultTimezone, SupportUrl: params.SupportURL,
					Reason: params.Reason, AuditID: toDatabaseUUID(params.AuditID),
					RequestID: event.requestID, CorrelationID: event.correlationID,
					IpAddress: params.Event.RemoteAddress.Unmap(), UserAgent: params.Event.UserAgent,
				})
			if err != nil {
				return platformoperations.GlobalSettings{}, err
			}
			settings, err := mapPlatformGlobalSettings(
				row.PlatformName, row.DefaultLocale, row.DefaultTimezone,
				row.SupportUrl, row.Version, row.UpdatedAt.Time,
			)
			if err != nil {
				return platformoperations.GlobalSettings{}, err
			}
			return params.Validate(settings)
		})
}

func (repository *PlatformOperationsRepository) GetHealth(
	ctx context.Context,
	params platformoperations.ReadHealthParams,
) (platformoperations.Health, error) {
	if params.Validate == nil {
		return platformoperations.Health{}, platformoperations.ErrInvalidInput
	}
	return readPlatformOperationsDocument(ctx, repository, params.ReadParams, params.Validate,
		func(queries *dbsql.Queries, event auditArguments) ([]byte, error) {
			return queries.GetPlatformOperationHealth(ctx, dbsql.GetPlatformOperationHealthParams{
				SessionID: toDatabaseUUID(params.Session.ID), AuditID: toDatabaseUUID(params.AuditID),
				RequestID: event.requestID, CorrelationID: event.correlationID,
				IpAddress: params.Event.RemoteAddress.Unmap(), UserAgent: params.Event.UserAgent,
			})
		})
}

func (repository *PlatformOperationsRepository) ListQueues(
	ctx context.Context,
	params platformoperations.ReadQueueParams,
) (platformoperations.QueueSnapshot, error) {
	if params.Validate == nil {
		return platformoperations.QueueSnapshot{}, platformoperations.ErrInvalidInput
	}
	return readPlatformOperationsDocument(ctx, repository, params.ReadParams, params.Validate,
		func(queries *dbsql.Queries, event auditArguments) ([]byte, error) {
			return queries.ListPlatformOperationQueues(ctx, dbsql.ListPlatformOperationQueuesParams{
				SessionID: toDatabaseUUID(params.Session.ID), AuditID: toDatabaseUUID(params.AuditID),
				RequestID: event.requestID, CorrelationID: event.correlationID,
				IpAddress: params.Event.RemoteAddress.Unmap(), UserAgent: params.Event.UserAgent,
			})
		})
}

func (repository *PlatformOperationsRepository) ListFailedNotifications(
	ctx context.Context,
	params platformoperations.ListFailedNotificationsParams,
) (platformoperations.FailedNotificationPage, error) {
	if params.Validate == nil || params.Limit < 1 || params.Limit > 100 {
		return platformoperations.FailedNotificationPage{}, platformoperations.ErrInvalidInput
	}
	var afterAt time.Time
	var afterID *uuid.UUID
	if params.After != nil {
		if !authorizationUUIDv7(params.After.ID) || params.After.FailureAt.IsZero() {
			return platformoperations.FailedNotificationPage{}, platformoperations.ErrInvalidInput
		}
		afterAt = params.After.FailureAt
		afterID = &params.After.ID
	}
	return withPlatformOperationsTransaction(ctx, repository, params.ReadParams,
		func(queries *dbsql.Queries, event auditArguments) (platformoperations.FailedNotificationPage, error) {
			document, err := queries.ListPlatformFailedNotifications(ctx,
				dbsql.ListPlatformFailedNotificationsParams{
					SessionID: toDatabaseUUID(params.Session.ID), AfterFailureAt: databaseTime(afterAt),
					AfterDeliveryID: optionalDatabaseUUID(afterID), PageLimit: params.Limit,
					AuditID: toDatabaseUUID(params.AuditID), RequestID: event.requestID,
					CorrelationID: event.correlationID, IpAddress: params.Event.RemoteAddress.Unmap(),
					UserAgent: params.Event.UserAgent,
				})
			if err != nil {
				return platformoperations.FailedNotificationPage{}, err
			}
			page, err := decodePlatformOperationsDocument[platformoperations.FailedNotificationPage](document)
			if err != nil {
				return platformoperations.FailedNotificationPage{}, err
			}
			return params.Validate(page)
		})
}

func (repository *PlatformOperationsRepository) ListFeatureFlags(
	ctx context.Context,
	params platformoperations.ReadFeatureFlagsParams,
) (platformoperations.FeatureFlagList, error) {
	if params.Validate == nil {
		return platformoperations.FeatureFlagList{}, platformoperations.ErrInvalidInput
	}
	return readPlatformOperationsDocument(ctx, repository, params.ReadParams, params.Validate,
		func(queries *dbsql.Queries, event auditArguments) ([]byte, error) {
			return queries.ListPlatformFeatureFlags(ctx, dbsql.ListPlatformFeatureFlagsParams{
				SessionID: toDatabaseUUID(params.Session.ID), AuditID: toDatabaseUUID(params.AuditID),
				RequestID: event.requestID, CorrelationID: event.correlationID,
				IpAddress: params.Event.RemoteAddress.Unmap(), UserAgent: params.Event.UserAgent,
			})
		})
}

func (repository *PlatformOperationsRepository) UpdateFeatureFlag(
	ctx context.Context,
	params platformoperations.UpdateFeatureFlagParams,
) (platformoperations.FeatureFlag, error) {
	if params.Validate == nil || params.ExpectedVersion < 1 {
		return platformoperations.FeatureFlag{}, platformoperations.ErrInvalidInput
	}
	return withPlatformOperationsTransaction(ctx, repository, params.ReadParams,
		func(queries *dbsql.Queries, event auditArguments) (platformoperations.FeatureFlag, error) {
			row, err := queries.UpdatePlatformFeatureFlag(ctx, dbsql.UpdatePlatformFeatureFlagParams{
				SessionID: toDatabaseUUID(params.Session.ID), FlagKey: params.Key,
				ExpectedVersion: params.ExpectedVersion, Enabled: params.Enabled, Reason: params.Reason,
				AuditID: toDatabaseUUID(params.AuditID), RequestID: event.requestID,
				CorrelationID: event.correlationID, IpAddress: params.Event.RemoteAddress.Unmap(),
				UserAgent: params.Event.UserAgent,
			})
			if err != nil {
				return platformoperations.FeatureFlag{}, err
			}
			updatedAt, err := domainTime(row.UpdatedAt)
			if err != nil {
				return platformoperations.FeatureFlag{}, err
			}
			return params.Validate(platformoperations.FeatureFlag{
				Key: row.Key, Enabled: row.Enabled, Version: row.Version, UpdatedAt: updatedAt,
			})
		})
}

func readPlatformOperationsDocument[T any](
	ctx context.Context,
	repository *PlatformOperationsRepository,
	params platformoperations.ReadParams,
	validate func(T) (T, error),
	read func(*dbsql.Queries, auditArguments) ([]byte, error),
) (T, error) {
	var zero T
	if validate == nil || read == nil {
		return zero, platformoperations.ErrInvalidInput
	}
	return withPlatformOperationsTransaction(ctx, repository, params,
		func(queries *dbsql.Queries, event auditArguments) (T, error) {
			document, err := read(queries, event)
			if err != nil {
				return zero, err
			}
			value, err := decodePlatformOperationsDocument[T](document)
			if err != nil {
				return zero, err
			}
			return validate(value)
		})
}

func withPlatformOperationsTransaction[T any](
	ctx context.Context,
	repository *PlatformOperationsRepository,
	params platformoperations.ReadParams,
	work func(*dbsql.Queries, auditArguments) (T, error),
) (T, error) {
	var zero T
	event, err := eventArguments(params.Event)
	if err != nil || repository == nil || repository.begin == nil || ctx == nil || work == nil ||
		!authorizationUUIDv7(params.Session.ID) || !authorizationUUIDv7(params.Session.User.ID) ||
		!authorizationUUIDv7(params.AuditID) || params.Session.ActiveTenantID != nil {
		return zero, platformoperations.ErrInvalidInput
	}
	result, err := withinTransaction(ctx, repository.begin, func(tx databaseTransaction) (T, error) {
		queries := dbsql.New(tx)
		installed, installErr := queries.SetUserContext(ctx, dbsql.SetUserContextParams{
			UserID: toDatabaseUUID(params.Session.User.ID),
		})
		if installErr != nil || installed != params.Session.User.ID.String() {
			return zero, platformoperations.ErrUnavailable
		}
		if err := installPersistedTraceContext(ctx, tx); err != nil {
			return zero, platformoperations.ErrUnavailable
		}
		return work(queries, event)
	})
	if err != nil {
		return zero, mapPlatformOperationsDatabaseError(err)
	}
	return result, nil
}

func decodePlatformOperationsDocument[T any](document []byte) (T, error) {
	var zero T
	if len(document) < 2 || len(document) > maximumPlatformOperationsDocumentBytes || !json.Valid(document) {
		return zero, errors.New("database returned malformed platform operations document")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var value T
	if err := decoder.Decode(&value); err != nil {
		return zero, fmt.Errorf("decode platform operations document: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return zero, errors.New("database returned trailing platform operations document")
	}
	return value, nil
}

func mapPlatformGlobalSettings(
	platformName string,
	defaultLocale string,
	defaultTimezone string,
	supportURL string,
	version int32,
	updatedAt time.Time,
) (platformoperations.GlobalSettings, error) {
	if platformName == "" || defaultLocale == "" || defaultTimezone == "" ||
		version < 1 || updatedAt.IsZero() {
		return platformoperations.GlobalSettings{}, errors.New("database returned malformed platform settings")
	}
	var optionalSupportURL *string
	if supportURL != "" {
		value := supportURL
		optionalSupportURL = &value
	}
	return platformoperations.GlobalSettings{
		PlatformName: platformName, DefaultLocale: defaultLocale,
		DefaultTimezone: defaultTimezone, SupportURL: optionalSupportURL,
		Version: version, UpdatedAt: updatedAt.UTC(),
	}, nil
}

func mapPlatformOperationsDatabaseError(err error) error {
	switch postgresCode(err) {
	case "22023", "23514":
		return platformoperations.ErrInvalidInput
	case "42501":
		return platformoperations.ErrForbidden
	case "P0002":
		return platformoperations.ErrNotFound
	case "40001":
		return platformoperations.ErrConflict
	default:
		return mapCommonDatabaseError(err)
	}
}
