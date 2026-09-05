package postgres

import (
	"context"
	"errors"
	"fmt"
	"math"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
	"github.com/periapsis-im/periapsis/services/api/internal/ticketnumbering"
)

type TicketNumberingRepository struct {
	begin transactionBeginner
}

func NewTicketNumberingRepository(pool *pgxpool.Pool) *TicketNumberingRepository {
	return &TicketNumberingRepository{begin: poolTransactionBeginner(pool)}
}

func (repository *TicketNumberingRepository) Current(
	ctx context.Context,
	params ticketnumbering.ReadParams,
) (kernel.NumberingPolicy, error) {
	if repository == nil || repository.begin == nil ||
		!validAuthorizationRepositoryActor(params.Actor, params.TenantID) {
		return kernel.NumberingPolicy{}, ticketnumbering.ErrRepositoryInvalidInput
	}
	databaseKind, err := ticketNumberingDatabaseKind(params.Kind)
	if err != nil {
		return kernel.NumberingPolicy{}, err
	}
	return withinTransaction(ctx, repository.begin, func(tx databaseTransaction) (kernel.NumberingPolicy, error) {
		queries := dbsql.New(tx)
		if err := installTicketNumberingContext(ctx, queries, params.Actor, params.TenantID); err != nil {
			return kernel.NumberingPolicy{}, err
		}
		row, err := queries.GetTenantTicketNumberingPolicy(ctx, dbsql.GetTenantTicketNumberingPolicyParams{
			SessionID:            toDatabaseUUID(params.Actor.SessionID),
			AuthenticationMethod: params.Actor.AuthenticationMethod,
			AggregateKind:        databaseKind,
		})
		if err != nil {
			return kernel.NumberingPolicy{}, mapTicketNumberingDatabaseError(err)
		}
		return mapTicketNumberingPolicy(
			row.VersionID, row.TenantID, row.AggregateKind, row.Version,
			row.Prefix, row.Separator, row.Period, row.Width, row.Start,
			row.PublishedByMembershipID, row.PublishedAt,
		)
	})
}

func (repository *TicketNumberingRepository) Replace(
	ctx context.Context,
	params ticketnumbering.ReplaceParams,
) (ticketnumbering.ReplaceResult, error) {
	if repository == nil || repository.begin == nil || params.BuildPlan == nil ||
		params.ValidateResult == nil || !validAuthorizationRepositoryActor(params.Actor, params.TenantID) ||
		params.ExpectedVersion < 1 || params.ExpectedVersion > math.MaxInt32 ||
		params.Command.Operation != "ticket_numbering.policy.replace" {
		return ticketnumbering.ReplaceResult{}, ticketnumbering.ErrRepositoryInvalidInput
	}
	databaseKind, err := ticketNumberingDatabaseKind(params.Kind)
	if err != nil {
		return ticketnumbering.ReplaceResult{}, err
	}
	event, err := eventArguments(params.Audit)
	if err != nil {
		return ticketnumbering.ReplaceResult{}, ticketnumbering.ErrRepositoryInvalidInput
	}
	return withinTransaction(ctx, repository.begin, func(tx databaseTransaction) (ticketnumbering.ReplaceResult, error) {
		queries := dbsql.New(tx)
		if err := installTicketNumberingContext(ctx, queries, params.Actor, params.TenantID); err != nil {
			return ticketnumbering.ReplaceResult{}, err
		}
		prepared, err := queries.PrepareReplaceTenantTicketNumberingPolicy(
			ctx,
			dbsql.PrepareReplaceTenantTicketNumberingPolicyParams{
				SessionID:            toDatabaseUUID(params.Actor.SessionID),
				AuthenticationMethod: params.Actor.AuthenticationMethod,
				AggregateKind:        databaseKind,
				KeyDigest:            params.Command.KeyDigest[:],
				RequestDigest:        params.Command.RequestDigest[:],
			},
		)
		if err != nil {
			return ticketnumbering.ReplaceResult{}, mapTicketNumberingDatabaseError(err)
		}
		current, err := mapTicketNumberingPolicy(
			prepared.VersionID, prepared.TenantID, prepared.AggregateKind,
			prepared.Version, prepared.Prefix, prepared.Separator,
			prepared.Period, prepared.Width, prepared.Start,
			prepared.PublishedByMembershipID, prepared.PublishedAt,
		)
		if err != nil {
			return ticketnumbering.ReplaceResult{}, err
		}
		if prepared.Replayed {
			result := ticketnumbering.ReplaceResult{Policy: current, Replayed: true}
			if err := params.ValidateResult(result); err != nil {
				return ticketnumbering.ReplaceResult{}, err
			}
			return result, nil
		}

		plan, err := params.BuildPlan(current)
		if err != nil {
			return ticketnumbering.ReplaceResult{}, err
		}
		next := plan.Next()
		if plan.ExpectedVersion() != params.ExpectedVersion ||
			next.Tenant() != current.Tenant() || next.Kind() != current.Kind() ||
			next.Version() != current.Version()+1 {
			return ticketnumbering.ReplaceResult{}, errors.New("ticket numbering plan does not match locked policy")
		}
		auditID, err := uuid.NewV7()
		if err != nil {
			return ticketnumbering.ReplaceResult{}, err
		}
		nextVersionUUID := uuid.UUID(next.VersionID().Bytes())
		namespace := next.NamespaceDigest()
		databasePeriod, err := ticketNumberingDatabasePeriod(next.Spec().Period())
		if err != nil || next.Version() > math.MaxInt32 || next.Spec().Start() > math.MaxInt64 {
			return ticketnumbering.ReplaceResult{}, ticketnumbering.ErrRepositoryInvalidInput
		}
		row, err := queries.CommitReplaceTenantTicketNumberingPolicy(
			ctx,
			dbsql.CommitReplaceTenantTicketNumberingPolicyParams{
				SessionID:            toDatabaseUUID(params.Actor.SessionID),
				AuthenticationMethod: params.Actor.AuthenticationMethod,
				AggregateKind:        databaseKind,
				ExpectedVersion:      int32(params.ExpectedVersion),
				KeyDigest:            params.Command.KeyDigest[:],
				RequestDigest:        params.Command.RequestDigest[:],
				VersionID:            toDatabaseUUID(nextVersionUUID),
				ResultVersion:        int32(next.Version()),
				Prefix:               next.Spec().Prefix(),
				Separator:            next.Spec().Separator(),
				Period:               databasePeriod,
				Width:                int32(next.Spec().Width()),
				Start:                int64(next.Spec().Start()),
				NamespaceDigest:      namespace[:],
				PublishedAt:          pgtype.Timestamptz{Time: next.PublishedAt(), Valid: true},
				Reason:               params.Reason,
				AuditID:              toDatabaseUUID(auditID),
				RequestID:            event.requestID,
				CorrelationID:        event.correlationID,
				IpAddress:            params.Audit.RemoteAddress,
				UserAgent:            params.Audit.UserAgent,
			},
		)
		if err != nil {
			return ticketnumbering.ReplaceResult{}, mapTicketNumberingDatabaseError(err)
		}
		committed, err := mapTicketNumberingPolicy(
			row.VersionID, row.TenantID, row.AggregateKind, row.Version,
			row.Prefix, row.Separator, row.Period, row.Width, row.Start,
			row.PublishedByMembershipID, row.PublishedAt,
		)
		if err != nil || !kernel.SameNumberingPolicy(committed, next) {
			return ticketnumbering.ReplaceResult{}, errors.New("database returned unexpected ticket numbering policy")
		}
		result := ticketnumbering.ReplaceResult{Policy: committed}
		if err := params.ValidateResult(result); err != nil {
			return ticketnumbering.ReplaceResult{}, err
		}
		return result, nil
	})
}

type tenantActorContextQueries interface {
	SetTenantContext(context.Context, dbsql.SetTenantContextParams) (*dbsql.SetTenantContextRow, error)
}

func installTicketNumberingContext(
	ctx context.Context,
	queries tenantActorContextQueries,
	actor authorization.Actor,
	tenantID uuid.UUID,
) error {
	return mapTicketNumberingDatabaseError(
		installTenantActorContext(ctx, queries, actor, tenantID),
	)
}

func installTenantActorContext(
	ctx context.Context,
	queries tenantActorContextQueries,
	actor authorization.Actor,
	tenantID uuid.UUID,
) error {
	installed, err := queries.SetTenantContext(ctx, dbsql.SetTenantContextParams{
		TenantID: toDatabaseUUID(tenantID), UserID: toDatabaseUUID(actor.UserID),
	})
	if err != nil {
		return err
	}
	if installed == nil || installed.TenantID != tenantID.String() ||
		installed.UserID != actor.UserID.String() {
		return errors.New("database installed unexpected tenant actor context")
	}
	return nil
}

func mapTicketNumberingPolicy(
	versionValue pgtype.UUID,
	tenantValue pgtype.UUID,
	kindValue string,
	versionValueNumber int32,
	prefix string,
	separator string,
	periodValue string,
	width int32,
	start int64,
	publisherValue pgtype.UUID,
	publishedValue pgtype.Timestamptz,
) (kernel.NumberingPolicy, error) {
	versionUUID, err := domainUUID(versionValue)
	if err != nil {
		return kernel.NumberingPolicy{}, err
	}
	tenantUUID, err := domainUUID(tenantValue)
	if err != nil {
		return kernel.NumberingPolicy{}, err
	}
	publishedAt, err := domainTime(publishedValue)
	if err != nil || versionValueNumber < 1 || width < 4 || width > 12 || start < 1 {
		return kernel.NumberingPolicy{}, errors.New("database returned malformed ticket numbering policy")
	}
	versionID, err := kernel.NewEntityID([16]byte(versionUUID))
	if err != nil {
		return kernel.NumberingPolicy{}, err
	}
	tenantID, err := kernel.NewEntityID([16]byte(tenantUUID))
	if err != nil {
		return kernel.NumberingPolicy{}, err
	}
	kind, err := ticketNumberingKernelKind(kindValue)
	if err != nil {
		return kernel.NumberingPolicy{}, err
	}
	period, err := ticketNumberingKernelPeriod(periodValue)
	if err != nil {
		return kernel.NumberingPolicy{}, err
	}
	spec, err := kernel.NewNumberingPolicySpec(
		prefix, separator, period, uint8(width), uint64(start),
	)
	if err != nil {
		return kernel.NumberingPolicy{}, err
	}
	if !publisherValue.Valid {
		if versionValueNumber != 1 {
			return kernel.NumberingPolicy{}, errors.New("non-default ticket numbering policy has no publisher")
		}
		return kernel.RestoreSystemNumberingPolicy(
			versionID, tenantID, kind, spec, publishedAt,
		)
	}
	publisherUUID, err := domainUUID(publisherValue)
	if err != nil {
		return kernel.NumberingPolicy{}, err
	}
	publisherID, err := kernel.NewEntityID([16]byte(publisherUUID))
	if err != nil {
		return kernel.NumberingPolicy{}, err
	}
	return kernel.NewNumberingPolicy(
		versionID, tenantID, kind, uint64(versionValueNumber), spec,
		publisherID, publishedAt,
	)
}

func ticketNumberingDatabaseKind(kind kernel.AggregateKind) (dbsql.TicketAggregateKind, error) {
	switch kind {
	case kernel.AggregateAlert:
		return dbsql.TicketAggregateKindAlert, nil
	case kernel.AggregateCase:
		return dbsql.TicketAggregateKindCase, nil
	default:
		return "", ticketnumbering.ErrRepositoryInvalidInput
	}
}

func ticketNumberingKernelKind(value string) (kernel.AggregateKind, error) {
	switch value {
	case "alert":
		return kernel.AggregateAlert, nil
	case "case":
		return kernel.AggregateCase, nil
	default:
		return 0, fmt.Errorf("unknown ticket numbering aggregate kind %q", value)
	}
}

func ticketNumberingDatabasePeriod(period kernel.NumberingPeriod) (dbsql.TicketNumberingPeriod, error) {
	switch period {
	case kernel.NumberingPeriodAnnual:
		return dbsql.TicketNumberingPeriodAnnual, nil
	case kernel.NumberingPeriodNone:
		return dbsql.TicketNumberingPeriodLifetime, nil
	default:
		return "", ticketnumbering.ErrRepositoryInvalidInput
	}
}

func ticketNumberingKernelPeriod(value string) (kernel.NumberingPeriod, error) {
	switch value {
	case "annual":
		return kernel.NumberingPeriodAnnual, nil
	case "lifetime":
		return kernel.NumberingPeriodNone, nil
	default:
		return 0, fmt.Errorf("unknown ticket numbering period %q", value)
	}
}

func mapTicketNumberingDatabaseError(err error) error {
	switch postgresCode(err) {
	case "22023", "23514":
		return ticketnumbering.ErrRepositoryInvalidInput
	case "42501":
		return ticketnumbering.ErrRepositoryForbidden
	case "P0002":
		return ticketnumbering.ErrRepositoryNotFound
	case "40001":
		return ticketnumbering.ErrRepositoryPrecondition
	case "23505":
		return ticketnumbering.ErrRepositoryConflict
	default:
		return mapCommonDatabaseError(err)
	}
}
