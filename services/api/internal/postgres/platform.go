package postgres

import (
	"context"
	"crypto/sha256"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/platform"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

// PlatformRepository implements platform-global tenant operations while still
// installing the live user context in every transaction for DB authorization.
type PlatformRepository struct {
	begin transactionBeginner
	newID func() (uuid.UUID, error)
}

func NewPlatformRepository(pool *pgxpool.Pool) *PlatformRepository {
	return &PlatformRepository{begin: poolTransactionBeginner(pool), newID: uuid.NewV7}
}

func (r *PlatformRepository) ListTenants(
	ctx context.Context,
	params platform.ListTenantsParams,
) ([]authentication.Tenant, error) {
	if params.ActorID == uuid.Nil || params.Limit < 1 || params.Limit > 101 ||
		params.After != nil && *params.After == uuid.Nil {
		return nil, authentication.ErrInvalidInput
	}
	return withinTransaction(ctx, r.begin, func(tx databaseTransaction) ([]authentication.Tenant, error) {
		queries := dbsql.New(tx)
		if err := setUserContext(ctx, queries, params.ActorID); err != nil {
			return nil, err
		}
		rows, err := queries.ListPlatformTenants(ctx, dbsql.ListPlatformTenantsParams{
			AfterID: optionalDatabaseUUID(params.After), PageSize: params.Limit,
		})
		if err != nil {
			if postgresCode(err) == "42501" {
				return nil, authentication.ErrForbidden
			}
			return nil, mapCommonDatabaseError(err)
		}
		items := make([]authentication.Tenant, 0, len(rows))
		for _, row := range rows {
			item, mapErr := mapPlatformTenant(
				row.ID, row.Slug, row.Name, row.Status, row.Timezone, row.Locale,
				row.Version, row.CreatedAt, row.UpdatedAt,
			)
			if mapErr != nil {
				return nil, mapErr
			}
			items = append(items, item)
		}
		return items, nil
	})
}

func (r *PlatformRepository) CreateTenant(
	ctx context.Context,
	params platform.CreateTenantParams,
) (authentication.Tenant, error) {
	event, err := eventArguments(params.Event)
	if err != nil || params.ID == uuid.Nil || params.MembershipID == uuid.Nil ||
		params.ActorID == uuid.Nil || params.Slug == "" || params.Name == "" ||
		params.Timezone == "" || params.Locale == "" || params.AuthenticationMethod == "" {
		return authentication.Tenant{}, authentication.ErrInvalidInput
	}
	auditID, err := r.newID()
	if err != nil {
		return authentication.Tenant{}, err
	}
	return withinTransaction(ctx, r.begin, func(tx databaseTransaction) (authentication.Tenant, error) {
		queries := dbsql.New(tx)
		if setErr := setUserContext(ctx, queries, params.ActorID); setErr != nil {
			return authentication.Tenant{}, setErr
		}
		row, queryErr := queries.CreatePlatformTenant(ctx, dbsql.CreatePlatformTenantParams{
			TenantID: toDatabaseUUID(params.ID), MembershipID: toDatabaseUUID(params.MembershipID),
			Slug: params.Slug, Name: params.Name, Timezone: params.Timezone, Locale: params.Locale,
			AuditID: toDatabaseUUID(auditID), RequestID: event.requestID,
			CorrelationID: event.correlationID, IpAddress: params.Event.RemoteAddress,
			UserAgent: params.Event.UserAgent, AuthenticationMethod: params.AuthenticationMethod,
		})
		if queryErr != nil {
			if postgresCode(queryErr) == "42501" {
				return authentication.Tenant{}, authentication.ErrForbidden
			}
			return authentication.Tenant{}, mapCommonDatabaseError(queryErr)
		}
		tenant, queryErr := mapPlatformTenant(
			row.ID, row.Slug, row.Name, row.Status, row.Timezone, row.Locale,
			row.Version, row.CreatedAt, row.UpdatedAt,
		)
		if queryErr != nil {
			return authentication.Tenant{}, queryErr
		}
		if tenant.ID != params.ID {
			return authentication.Tenant{}, errors.New("database returned an unexpected tenant")
		}
		return tenant, nil
	})
}

// ChangeTenantLifecycle performs the platform control-plane transition through
// one SECURITY DEFINER command. The transaction-local user context is the only
// actor authority accepted by PostgreSQL; the function rechecks the live
// platform permission, locks the tenant revision, mutates it, and appends the
// tamper-evident platform audit event atomically.
func (r *PlatformRepository) ChangeTenantLifecycle(
	ctx context.Context,
	params platform.ChangeTenantLifecycleParams,
) (platform.TenantLifecycleReceipt, error) {
	event, err := eventArguments(params.Event)
	if err != nil || r == nil || r.begin == nil || r.newID == nil ||
		platform.ValidateTenantLifecycleCommand(params.Command) != nil ||
		!platformLifecycleUUIDv7(params.ActorID) || !platformLifecycleUUIDv7(params.SessionID) ||
		!validPlatformLifecycleAuthenticationMethod(params.AuthenticationMethod) {
		return platform.TenantLifecycleReceipt{}, authentication.ErrInvalidInput
	}
	auditID, err := r.newID()
	if err != nil || auditID == uuid.Nil || auditID.Version() != 7 || auditID.Variant() != uuid.RFC4122 {
		return platform.TenantLifecycleReceipt{}, authentication.ErrUnavailable
	}

	return withinTransaction(ctx, r.begin, func(tx databaseTransaction) (platform.TenantLifecycleReceipt, error) {
		queries := dbsql.New(tx)
		if err := setUserContext(ctx, queries, params.ActorID); err != nil {
			return platform.TenantLifecycleReceipt{}, err
		}
		row, err := queries.ChangePlatformTenantLifecycle(ctx, dbsql.ChangePlatformTenantLifecycleParams{
			SessionID: toDatabaseUUID(params.SessionID), TenantID: toDatabaseUUID(params.Command.TenantID()),
			Target: dbsql.TenantStatus(params.Command.Target()), ExpectedVersion: params.Command.ExpectedVersion(),
			Reason: params.Command.Reason(), AuditID: toDatabaseUUID(auditID),
			RequestID: event.requestID, CorrelationID: event.correlationID,
			IpAddress: params.Event.RemoteAddress, UserAgent: params.Event.UserAgent,
			AuthenticationMethod: params.AuthenticationMethod,
		})
		if err != nil {
			switch postgresCode(err) {
			case "42501":
				return platform.TenantLifecycleReceipt{}, authentication.ErrForbidden
			case "P0002":
				return platform.TenantLifecycleReceipt{}, authentication.ErrNotFound
			case "40001":
				return platform.TenantLifecycleReceipt{}, platform.ErrTenantLifecycleConflict
			case "22023", "23514":
				return platform.TenantLifecycleReceipt{}, platform.ErrInvalidTenantLifecycle
			default:
				return platform.TenantLifecycleReceipt{}, err
			}
		}
		tenantID, err := domainUUID(row.TenantID)
		if err != nil {
			return platform.TenantLifecycleReceipt{}, err
		}
		updatedAt, err := domainTime(row.UpdatedAt)
		if err != nil {
			return platform.TenantLifecycleReceipt{}, err
		}
		receipt, err := platform.RestoreTenantLifecycleReceipt(platform.TenantLifecycleReceiptInput{
			TenantID: tenantID, Previous: platform.TenantLifecycleStatus(row.PreviousStatus),
			Current: platform.TenantLifecycleStatus(row.Status), Version: row.Version,
			UpdatedAt: updatedAt, Replayed: row.Replayed,
		})
		if err != nil || receipt.TenantID() != params.Command.TenantID() ||
			receipt.Current() != params.Command.Target() ||
			receipt.Version() != params.Command.ExpectedVersion()+1 {
			return platform.TenantLifecycleReceipt{}, authentication.ErrUnavailable
		}
		return receipt, nil
	})
}

// AuthorizePlatformTenantAccess creates ordinary tenant authority through one
// database-owned command. PostgreSQL rechecks the live super-admin role,
// dedicated permission, source session freshness, tenant version and absence
// of any existing membership before coupling both audit streams atomically.
func (r *PlatformRepository) AuthorizePlatformTenantAccess(
	ctx context.Context,
	params platform.AuthorizePlatformTenantAccessParams,
) (platform.PlatformTenantAccessReceipt, error) {
	event, err := eventArguments(params.Event)
	if err != nil || r == nil || r.begin == nil || r.newID == nil ||
		platform.ValidatePlatformTenantAccessCommand(params.Command) != nil ||
		!platformLifecycleUUIDv7(params.ActorID) || !platformLifecycleUUIDv7(params.SessionID) ||
		!validPlatformTenantAccessAuthenticationMethod(params.AuthenticationMethod) ||
		params.Event.UserAgent == "" {
		return platform.PlatformTenantAccessReceipt{}, authentication.ErrInvalidInput
	}

	identifiers := make([]uuid.UUID, 4)
	for index := range identifiers {
		identifiers[index], err = r.newID()
		if err != nil || !platformLifecycleUUIDv7(identifiers[index]) {
			return platform.PlatformTenantAccessReceipt{}, authentication.ErrUnavailable
		}
	}
	idempotencyDigest := sha256.Sum256([]byte(params.Command.IdempotencyKey()))

	return withinTransaction(ctx, r.begin, func(tx databaseTransaction) (platform.PlatformTenantAccessReceipt, error) {
		queries := dbsql.New(tx)
		if err := setUserContext(ctx, queries, params.ActorID); err != nil {
			return platform.PlatformTenantAccessReceipt{}, err
		}
		row, err := queries.AuthorizePlatformTenantAccess(ctx, dbsql.AuthorizePlatformTenantAccessParams{
			SessionID:             toDatabaseUUID(params.SessionID),
			TenantID:              toDatabaseUUID(params.Command.TenantID()),
			MembershipID:          toDatabaseUUID(identifiers[0]),
			RoleGrantID:           toDatabaseUUID(identifiers[1]),
			ExpectedTenantVersion: params.Command.ExpectedVersion(),
			Reason:                params.Command.Reason(), IdempotencyKeyDigest: idempotencyDigest[:],
			PlatformAuditEventID: toDatabaseUUID(identifiers[2]),
			TenantAuditEventID:   toDatabaseUUID(identifiers[3]),
			RequestID:            event.requestID, CorrelationID: event.correlationID,
			IpAddress: params.Event.RemoteAddress, UserAgent: params.Event.UserAgent,
			AuthenticationMethod: params.AuthenticationMethod,
		})
		if err != nil {
			switch postgresCode(err) {
			case "42501":
				return platform.PlatformTenantAccessReceipt{}, authentication.ErrForbidden
			case "P0002":
				return platform.PlatformTenantAccessReceipt{}, authentication.ErrNotFound
			case "40001":
				return platform.PlatformTenantAccessReceipt{}, platform.ErrPlatformTenantAccessPreconditionFailed
			case "23505":
				return platform.PlatformTenantAccessReceipt{}, platform.ErrPlatformTenantAccessConflict
			case "22023", "23514":
				return platform.PlatformTenantAccessReceipt{}, platform.ErrInvalidPlatformTenantAccess
			default:
				return platform.PlatformTenantAccessReceipt{}, err
			}
		}
		tenantID, err := domainUUID(row.TenantID)
		if err != nil {
			return platform.PlatformTenantAccessReceipt{}, err
		}
		membershipID, err := domainUUID(row.MembershipID)
		if err != nil {
			return platform.PlatformTenantAccessReceipt{}, err
		}
		userID, err := domainUUID(row.UserID)
		if err != nil {
			return platform.PlatformTenantAccessReceipt{}, err
		}
		authorizedAt, err := domainTime(row.AuthorizedAt)
		if err != nil {
			return platform.PlatformTenantAccessReceipt{}, err
		}
		receipt, err := platform.RestorePlatformTenantAccessReceipt(platform.PlatformTenantAccessReceiptInput{
			TenantID: tenantID, MembershipID: membershipID, UserID: userID,
			TenantVersion: row.TenantVersion, MembershipRevision: row.MembershipRevision,
			AuthorizationRevision: row.AuthorizationRevision,
			AuthorizedAt:          authorizedAt, Replayed: row.Replayed,
		})
		if err != nil || receipt.TenantID() != params.Command.TenantID() ||
			receipt.UserID() != params.ActorID || receipt.TenantVersion() != params.Command.ExpectedVersion() {
			return platform.PlatformTenantAccessReceipt{}, authentication.ErrUnavailable
		}
		return receipt, nil
	})
}

func platformLifecycleUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func validPlatformLifecycleAuthenticationMethod(value string) bool {
	switch value {
	case "bootstrap_totp", "oidc", "passkey", "recovery_code", "saml", "totp":
		return true
	default:
		return false
	}
}

func validPlatformTenantAccessAuthenticationMethod(value string) bool {
	switch value {
	case "bootstrap_totp", "ldap", "oidc", "passkey", "saml", "totp":
		return true
	default:
		return false
	}
}

func mapPlatformTenant(
	idValue pgtype.UUID,
	slug string,
	name string,
	status string,
	timezone string,
	locale string,
	version int32,
	createdValue pgtype.Timestamptz,
	updatedValue pgtype.Timestamptz,
) (authentication.Tenant, error) {
	identifier, err := domainUUID(idValue)
	if err != nil {
		return authentication.Tenant{}, err
	}
	createdAt, err := domainTime(createdValue)
	if err != nil {
		return authentication.Tenant{}, err
	}
	updatedAt, err := domainTime(updatedValue)
	if err != nil {
		return authentication.Tenant{}, err
	}
	if slug == "" || name == "" || status == "" || timezone == "" || locale == "" || version < 1 {
		return authentication.Tenant{}, errors.New("database returned an invalid tenant")
	}
	return authentication.Tenant{
		ID: identifier, Slug: slug, Name: name, Status: status,
		Timezone: timezone, Locale: locale, Version: version, CreatedAt: createdAt, UpdatedAt: updatedAt,
	}, nil
}
