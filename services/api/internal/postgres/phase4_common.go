package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

// phase4Authority installs the RLS actor context and resolves the live
// authorization projection inside the caller's transaction. Mutation adapters
// use this helper rather than trusting an access result produced by an earlier
// transaction.
func phase4Authority(
	ctx context.Context,
	tx databaseTransaction,
	actor authorization.Actor,
	tenantID uuid.UUID,
) (authorization.TenantAuthority, error) {
	if tx == nil || !authorizationUUIDv7(tenantID) ||
		!validAuthorizationRepositoryActor(actor, tenantID) {
		return authorization.TenantAuthority{}, authorization.ErrForbidden
	}
	queries := dbsql.New(tx)
	installed, err := queries.SetTenantContext(ctx, dbsql.SetTenantContextParams{
		TenantID: toDatabaseUUID(tenantID), UserID: toDatabaseUUID(actor.UserID),
	})
	if err != nil {
		return authorization.TenantAuthority{}, mapAuthorizationDatabaseError(err)
	}
	if installed == nil || installed.TenantID != tenantID.String() || installed.UserID != actor.UserID.String() {
		return authorization.TenantAuthority{}, errors.New("database installed an unexpected phase 4 tenant context")
	}
	contextRow, err := queries.GetCurrentTenantAuthorizationContext(ctx)
	if err != nil {
		return authorization.TenantAuthority{}, mapAuthorizationDatabaseError(err)
	}
	authorityRows, err := queries.ResolveCurrentTenantHumanAuthority(
		ctx, dbsql.ResolveCurrentTenantHumanAuthorityParams{PageSize: authorizationPermissionHydrationLimit},
	)
	if err != nil {
		return authorization.TenantAuthority{}, mapAuthorizationDatabaseError(err)
	}
	teamRows, err := queries.ResolveCurrentTenantOperatorTeams(
		ctx, dbsql.ResolveCurrentTenantOperatorTeamsParams{PageSize: operatorTeamHydrationLimit},
	)
	if err != nil {
		return authorization.TenantAuthority{}, mapAuthorizationDatabaseError(err)
	}
	grantRows, err := queries.ResolveCurrentTenantHumanRoleGrantPaths(
		ctx, dbsql.ResolveCurrentTenantHumanRoleGrantPathsParams{PageSize: authorizationRolePathHydrationLimit},
	)
	if err != nil {
		return authorization.TenantAuthority{}, mapAuthorizationDatabaseError(err)
	}
	return mapResolvedTenantAuthority(actor, tenantID, contextRow, authorityRows, teamRows, grantRows)
}

func validPhase4Authority(authority authorization.TenantAuthority, membershipID uuid.UUID) bool {
	return authority.TenantID != uuid.Nil && authority.MembershipID == membershipID &&
		authority.MembershipStatus == authorization.MembershipStatusActive &&
		authority.Principal.Kind == authorization.PrincipalKindHuman &&
		authority.Principal.ID != uuid.Nil
}

func phase4HasPermission(
	authority authorization.TenantAuthority,
	permission string,
	scope authorization.Scope,
) bool {
	return slices.ContainsFunc(authority.Permissions, func(candidate authorization.ScopedPermission) bool {
		return string(candidate.Permission) == permission && candidate.Scope == scope
	})
}

func phase4NewIDs(generator func() (uuid.UUID, error), count int) ([]uuid.UUID, error) {
	if generator == nil || count < 1 || count > 32 {
		return nil, errors.New("phase 4 identifier generator is invalid")
	}
	result := make([]uuid.UUID, count)
	seen := make(map[uuid.UUID]struct{}, count)
	for index := range result {
		identifier, err := generator()
		if err != nil {
			return nil, fmt.Errorf("generate phase 4 identifier: %w", err)
		}
		if !authorizationUUIDv7(identifier) {
			return nil, errors.New("phase 4 identifier generator returned a non-UUIDv7 value")
		}
		if _, duplicate := seen[identifier]; duplicate {
			return nil, errors.New("phase 4 identifier generator returned a duplicate value")
		}
		seen[identifier] = struct{}{}
		result[index] = identifier
	}
	return result, nil
}

type phase4MutationEffects struct {
	PermissionKey        string
	Action               string
	ResourceType         string
	ResourceID           uuid.UUID
	ResourceVersion      int64
	CaseID               *uuid.UUID
	ActivityID           *uuid.UUID
	ActivityResourceKind *string
	ActivityResourceID   *uuid.UUID
	Summary              string
	Before               any
	After                any
	Metadata             any
	AuditEventID         uuid.UUID
	OutboxEventID        uuid.UUID
	RequestID            uuid.UUID
	CorrelationID        uuid.UUID
	IPAddress            netip.Addr
	UserAgent            string
	AuthenticationMethod string
}

func appendPhase4MutationEffects(
	ctx context.Context,
	tx databaseTransaction,
	effect phase4MutationEffects,
) error {
	before, err := phase4JSON(effect.Before)
	if err != nil {
		return err
	}
	after, err := phase4JSON(effect.After)
	if err != nil {
		return err
	}
	metadata, err := phase4JSON(effect.Metadata)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		SELECT app.append_phase4_mutation_effects_v1(
			$1, $2, $3, $4, $5, $6, $7,
			$8::public.dfir_entity_kind, $9, $10,
			$11::jsonb, $12::jsonb, $13::jsonb,
			$14, $15, $16, $17, $18::inet, $19, $20
		)`,
		effect.PermissionKey, effect.Action, effect.ResourceType,
		effect.ResourceID, effect.ResourceVersion, effect.CaseID, effect.ActivityID,
		effect.ActivityResourceKind, effect.ActivityResourceID, effect.Summary,
		before, after, metadata, effect.AuditEventID, effect.OutboxEventID,
		effect.RequestID, effect.CorrelationID, effect.IPAddress,
		effect.UserAgent, effect.AuthenticationMethod,
	)
	return err
}

func phase4JSON(value any) ([]byte, error) {
	if value == nil {
		return []byte(`{}`), nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode redacted phase 4 journal projection: %w", err)
	}
	if len(encoded) > 32*1024 {
		return nil, errors.New("redacted phase 4 journal projection is oversized")
	}
	return encoded, nil
}

func phase4ReadOptions() pgx.TxOptions {
	return pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}
}

func phase4WriteOptions() pgx.TxOptions {
	return pgx.TxOptions{IsoLevel: pgx.Serializable}
}
