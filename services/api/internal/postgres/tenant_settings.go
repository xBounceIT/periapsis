package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
	"github.com/periapsis-im/periapsis/services/api/internal/tenantsettings"
)

type TenantSettingsRepository struct {
	begin transactionBeginner
}

func NewTenantSettingsRepository(pool *pgxpool.Pool) *TenantSettingsRepository {
	return &TenantSettingsRepository{begin: poolTransactionBeginner(pool)}
}

func (repository *TenantSettingsRepository) Get(
	ctx context.Context,
	params tenantsettings.ReadParams,
) (tenantsettings.Settings, error) {
	if repository == nil || repository.begin == nil ||
		!validAuthorizationRepositoryActor(params.Actor, params.TenantID) {
		return tenantsettings.Settings{}, tenantsettings.ErrInvalidInput
	}
	return withinTransaction(ctx, repository.begin, func(tx databaseTransaction) (tenantsettings.Settings, error) {
		queries := dbsql.New(tx)
		if err := installTenantSettingsContext(ctx, queries, params.Actor, params.TenantID); err != nil {
			return tenantsettings.Settings{}, err
		}
		row, err := queries.GetTenantSettings(ctx, dbsql.GetTenantSettingsParams{
			SessionID:            toDatabaseUUID(params.Actor.SessionID),
			AuthenticationMethod: params.Actor.AuthenticationMethod,
		})
		if err != nil {
			return tenantsettings.Settings{}, mapTenantSettingsDatabaseError(err)
		}
		return mapTenantSettings(
			row.TenantID, row.BrandName, row.BrandMark, row.PrimaryColor,
			row.AccentColor, row.Timezone, row.Locale, row.Version, row.UpdatedAt,
		)
	})
}

func (repository *TenantSettingsRepository) Update(
	ctx context.Context,
	params tenantsettings.UpdateParams,
) (tenantsettings.Settings, error) {
	event, err := eventArguments(params.Event)
	if err != nil || repository == nil || repository.begin == nil ||
		!validAuthorizationRepositoryActor(params.Actor, params.TenantID) ||
		!authorizationUUIDv7(params.AuditID) {
		return tenantsettings.Settings{}, tenantsettings.ErrInvalidInput
	}
	return withinTransaction(ctx, repository.begin, func(tx databaseTransaction) (tenantsettings.Settings, error) {
		queries := dbsql.New(tx)
		if err := installTenantSettingsContext(ctx, queries, params.Actor, params.TenantID); err != nil {
			return tenantsettings.Settings{}, err
		}
		row, err := queries.UpdateTenantSettings(ctx, dbsql.UpdateTenantSettingsParams{
			SessionID:            toDatabaseUUID(params.Actor.SessionID),
			AuthenticationMethod: params.Actor.AuthenticationMethod,
			ExpectedVersion:      params.ExpectedVersion,
			BrandName:            params.BrandName, BrandMark: params.BrandMark,
			PrimaryColor: params.PrimaryColor, AccentColor: params.AccentColor,
			Timezone: params.Timezone, Locale: params.Locale, Reason: params.Reason,
			AuditID: toDatabaseUUID(params.AuditID), RequestID: event.requestID,
			CorrelationID: event.correlationID, IpAddress: params.Event.RemoteAddress,
			UserAgent: params.Event.UserAgent,
		})
		if err != nil {
			return tenantsettings.Settings{}, mapTenantSettingsDatabaseError(err)
		}
		settings, err := mapTenantSettings(
			row.TenantID, row.BrandName, row.BrandMark, row.PrimaryColor,
			row.AccentColor, row.Timezone, row.Locale, row.Version, row.UpdatedAt,
		)
		if err != nil || settings.TenantID != params.TenantID ||
			settings.Version != params.ExpectedVersion+1 {
			return tenantsettings.Settings{}, errors.New("database returned unexpected tenant settings")
		}
		return settings, nil
	})
}

type tenantSettingsContextQueries interface {
	SetTenantContext(context.Context, dbsql.SetTenantContextParams) (*dbsql.SetTenantContextRow, error)
}

func installTenantSettingsContext(
	ctx context.Context,
	queries tenantSettingsContextQueries,
	actor authorization.Actor,
	tenantID uuid.UUID,
) error {
	installed, err := queries.SetTenantContext(ctx, dbsql.SetTenantContextParams{
		TenantID: toDatabaseUUID(tenantID), UserID: toDatabaseUUID(actor.UserID),
	})
	if err != nil {
		return mapTenantSettingsDatabaseError(err)
	}
	if installed == nil || installed.TenantID != tenantID.String() ||
		installed.UserID != actor.UserID.String() {
		return errors.New("database installed unexpected tenant settings context")
	}
	return nil
}

func mapTenantSettings(
	tenantValue pgtype.UUID,
	brandName string,
	brandMark string,
	primaryColor string,
	accentColor string,
	timezone string,
	locale string,
	version int32,
	updatedValue pgtype.Timestamptz,
) (tenantsettings.Settings, error) {
	tenantID, err := domainUUID(tenantValue)
	if err != nil {
		return tenantsettings.Settings{}, err
	}
	updatedAt, err := domainTime(updatedValue)
	if err != nil {
		return tenantsettings.Settings{}, err
	}
	if brandName == "" || brandMark == "" || primaryColor == "" || accentColor == "" ||
		timezone == "" || locale == "" || version < 1 {
		return tenantsettings.Settings{}, errors.New("database returned malformed tenant settings")
	}
	return tenantsettings.Settings{
		TenantID: tenantID, BrandName: brandName, BrandMark: brandMark,
		PrimaryColor: primaryColor, AccentColor: accentColor,
		Timezone: timezone, Locale: locale, Version: version, UpdatedAt: updatedAt,
	}, nil
}

func mapTenantSettingsDatabaseError(err error) error {
	switch postgresCode(err) {
	case "22023", "23514":
		return tenantsettings.ErrInvalidInput
	case "42501":
		return tenantsettings.ErrForbidden
	case "P0002":
		return tenantsettings.ErrNotFound
	case "40001":
		return tenantsettings.ErrConflict
	default:
		return mapCommonDatabaseError(err)
	}
}
