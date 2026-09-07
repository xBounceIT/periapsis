// Package postgres provides pgx-backed infrastructure adapters.
package postgres

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	trustedRuntimeACL = `array['periapsis_api', 'periapsis_migrator', 'periapsis_worker']::text[]`
	trustedReleaseACL = `array[
       'periapsis_api', 'periapsis_migrator',
       'periapsis_notification_readiness_owner', 'periapsis_worker'
     ]::text[]`
	trustedAPIACL         = `array['periapsis_api', 'periapsis_migrator']::text[]`
	trustedOwnerACL       = `array['periapsis_migrator']::text[]`
	trustedSLARotationACL = `array[
       'periapsis_migrator', 'periapsis_sla_readiness_owner'
     ]::text[]`
	trustedRuntimeConfig = `array[
       'search_path=pg_catalog, public, app',
       'quote_all_identifiers=off', 'TimeZone=UTC',
       'DateStyle=ISO, YMD', 'IntervalStyle=postgres',
       'extra_float_digits=3', 'bytea_output=hex',
       'standard_conforming_strings=on', 'lc_numeric=C'
     ]::text[]`
)

const schemaCompatibilityQuery = `
with expected_trusted_function(
  ordinal, function_key, signature, expected_language,
  expected_config, expected_result, expected_acl_roles
) as (
  values
    (1, 'compatibility', 'app.schema_compatibility_v57()', 'plpgsql', array[
       'search_path=pg_catalog',
       'app.schema_compatibility_fingerprint=' || $1::text
     ]::text[],
     'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)',
     ` + trustedRuntimeACL + `),
    (2, 'retired', 'app.schema_compatibility_v49()', 'plpgsql', array[
       'search_path=pg_catalog',
       'app.schema_compatibility_fingerprint=RETIRED'
     ]::text[],
     'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)',
     ` + trustedOwnerACL + `),
    (3, 'convergence',
     'app.private_v47_migration_convergence_schema_readiness_v1()',
     'plpgsql', array['search_path=pg_catalog, public, app']::text[],
     'boolean', ` + trustedOwnerACL + `),
    (4, 'journal', 'app.private_schema_compatibility_journal_v57()',
     'plpgsql', array['search_path=pg_catalog, public, app']::text[],
     'TABLE(applied_count bigint, latest_created_at bigint, latest_rows bigint, latest_hash text, migration_fingerprint text)',
     ` + trustedOwnerACL + `),
    (5, 'dependency',
     'app.private_release_runtime_dependency_surface_hash_v57()',
     'sql', ` + trustedRuntimeConfig + `, 'text', ` + trustedOwnerACL + `),
    (6, 'private_release',
     'app.private_release_runtime_schema_readiness_v57()',
     'plpgsql', array['search_path=pg_catalog, public, app']::text[],
     'boolean', ` + trustedOwnerACL + `),
    (7, 'release', 'app.release_runtime_schema_readiness_v57()',
     'plpgsql', array['search_path=pg_catalog, public, app']::text[],
     'boolean', ` + trustedReleaseACL + `),
    (8, 'federated', 'app.federated_authentication_schema_readiness_v57()',
     'plpgsql', array['search_path=pg_catalog, public, app']::text[],
     'boolean', ` + trustedAPIACL + `),
    (9, 'oidc', 'app.platform_oidc_direct_runtime_schema_readiness_v57()',
     'plpgsql', array['search_path=pg_catalog, public, app']::text[],
     'boolean', ` + trustedAPIACL + `),
    (10, 'saml', 'app.platform_saml_direct_runtime_schema_readiness_v57()',
     'plpgsql', array['search_path=pg_catalog, public, app']::text[],
     'boolean', ` + trustedAPIACL + `),
    (11, 'local_account',
     'app.platform_local_account_runtime_schema_readiness_v57()',
     'plpgsql', array['search_path=pg_catalog, public, app']::text[],
     'boolean', ` + trustedAPIACL + `),
    (12, 'ticket_bulk', 'app.ticket_bulk_runtime_schema_readiness_v57()',
     'plpgsql', array['search_path=pg_catalog, public, app']::text[],
     'boolean', ` + trustedRuntimeACL + `),
    (13, 'ticket_export', 'app.ticket_export_runtime_schema_readiness_v57()',
     'plpgsql', array['search_path=pg_catalog, public, app']::text[],
     'boolean', ` + trustedRuntimeACL + `),
    (14, 'ticket_metadata',
     'app.ticket_metadata_runtime_schema_readiness_v57()',
     'plpgsql', array['search_path=pg_catalog, public, app']::text[],
     'boolean', ` + trustedAPIACL + `),
    (15, 'sla_rotation', 'app.private_rotate_sla_readiness_v48()',
     'plpgsql', array['search_path=pg_catalog, public, app']::text[],
     'void', ` + trustedSLARotationACL + `),
    (16, 'retired_v50', 'app.schema_compatibility_v50()', 'plpgsql', array[
       'search_path=pg_catalog',
       'app.schema_compatibility_fingerprint=RETIRED'
     ]::text[],
     'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)',
     ` + trustedOwnerACL + `),
    (17, 'retired_v51', 'app.schema_compatibility_v51()', 'plpgsql', array[
       'search_path=pg_catalog',
       'app.schema_compatibility_fingerprint=RETIRED'
     ]::text[],
     'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)',
     ` + trustedOwnerACL + `),
    (18, 'api_aggregate', 'app.api_runtime_schema_readiness_v57()',
     'plpgsql', array['search_path=pg_catalog, public, app']::text[],
     'boolean[]', ` + trustedAPIACL + `),
    (19, 'retired_v52', 'app.schema_compatibility_v52()', 'plpgsql', array[
       'search_path=pg_catalog',
       'app.schema_compatibility_fingerprint=RETIRED'
     ]::text[],
     'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)',
     ` + trustedOwnerACL + `),
    (20, 'retired_v53', 'app.schema_compatibility_v53()', 'plpgsql', array[
       'search_path=pg_catalog',
       'app.schema_compatibility_fingerprint=RETIRED'
     ]::text[],
     'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)',
     ` + trustedOwnerACL + `),
    (21, 'retired_v54', 'app.schema_compatibility_v54()', 'plpgsql', array[
       'search_path=pg_catalog',
       'app.schema_compatibility_fingerprint=RETIRED'
     ]::text[],
     'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)',
     ` + trustedOwnerACL + `),
    (22, 'retired_v55', 'app.schema_compatibility_v55()', 'plpgsql', array[
       'search_path=pg_catalog',
       'app.schema_compatibility_fingerprint=RETIRED'
     ]::text[],
     'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)',
     ` + trustedOwnerACL + `),
    (23, 'retired_v56', 'app.schema_compatibility_v56()', 'plpgsql', array[
       'search_path=pg_catalog',
       'app.schema_compatibility_fingerprint=RETIRED'
     ]::text[],
     'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)',
     ` + trustedOwnerACL + `)
),
actual_trusted_function as (
  select expected.ordinal, expected.function_key,
         pg_catalog.encode(
           pg_catalog.sha256(pg_catalog.convert_to(function.prosrc, 'UTF8')),
           'hex'
         ) as source_hash,
         function.oid is not null
           and owner.rolname = case when expected.function_key = 'sla_rotation'
             then 'periapsis_sla_readiness_owner'
             else 'periapsis_migrator' end
           and language.lanname = expected.expected_language
           and function.prokind = 'f'
           and function.provolatile = case
             when expected.function_key = 'sla_rotation' then 'v'::"char"
             else 's'::"char" end
           and function.prosecdef
           and not function.proisstrict
           and not function.proleakproof
           and function.proparallel = 'u'
           and function.pronargs = 0
           and function.pronargdefaults = 0
           and function.proargtypes = ''::pg_catalog.oidvector
           and function.proargdefaults is null
           and function.provariadic = 0
           and function.prosupport = 0
           and function.proretset = (expected.function_key in (
             'compatibility', 'retired', 'retired_v50', 'retired_v51', 'retired_v52', 'retired_v53', 'retired_v54', 'retired_v55', 'retired_v56', 'journal'
           ))
           and function.procost = 100::real
           and function.prorows = case when function.proretset
             then 1000::real else 0::real end
           and function.protrftypes is null
           and function.probin is null
           and function.prosqlbody is null
           and case when expected.function_key = 'journal' then
             function.proallargtypes is not distinct from array[
               'bigint'::pg_catalog.regtype, 'bigint'::pg_catalog.regtype,
               'bigint'::pg_catalog.regtype, 'text'::pg_catalog.regtype,
               'text'::pg_catalog.regtype
             ]::pg_catalog.oid[]
             and function.proargmodes is not distinct from
               array['t', 't', 't', 't', 't']::"char"[]
             and function.proargnames is not distinct from array[
               'applied_count', 'latest_created_at', 'latest_rows',
               'latest_hash', 'migration_fingerprint'
             ]::text[]
           when function.proretset then
             function.proallargtypes is not distinct from array[
               'bigint'::pg_catalog.regtype, 'bigint'::pg_catalog.regtype,
               'text'::pg_catalog.regtype, 'text'::pg_catalog.regtype
             ]::pg_catalog.oid[]
             and function.proargmodes is not distinct from
               array['t', 't', 't', 't']::"char"[]
             and function.proargnames is not distinct from array[
               'applied_count', 'latest_created_at', 'latest_hash',
               'migration_fingerprint'
             ]::text[]
           else
             function.proallargtypes is null
             and function.proargmodes is null
             and function.proargnames is null
           end
           and function.proconfig is not distinct from expected.expected_config
           and pg_catalog.pg_get_function_result(function.oid) =
             expected.expected_result
           and case when function.oid is null then false else (
             select count(*) = pg_catalog.cardinality(
                    expected.expected_acl_roles
                  )
                and pg_catalog.array_agg(
                  coalesce(grantee.rolname::text, 'PUBLIC')
                  order by coalesce(grantee.rolname::text, 'PUBLIC')
                    collate "C"
                ) is not distinct from expected.expected_acl_roles
                and coalesce(bool_and(
                  function_acl.grantor = function.proowner
                  and function_acl.privilege_type = 'EXECUTE'
                  and not function_acl.is_grantable
                ), false)
             from pg_catalog.aclexplode(case
               when pg_catalog.cardinality(coalesce(
                 function.proacl,
                 pg_catalog.acldefault('f', function.proowner)
               )) > 0 then coalesce(
                 function.proacl,
                 pg_catalog.acldefault('f', function.proowner)
               )
               else null::pg_catalog.aclitem[]
             end) as function_acl
             left join pg_catalog.pg_roles as grantee
               on grantee.oid = function_acl.grantee
           ) end as catalog_ready
  from expected_trusted_function as expected
  left join pg_catalog.pg_proc as function
    on function.oid = pg_catalog.to_regprocedure(expected.signature)
  left join pg_catalog.pg_roles as owner on owner.oid = function.proowner
  left join pg_catalog.pg_language as language
    on language.oid = function.prolang
),
trusted_function_state as (
  select array_agg(source_hash order by ordinal) as source_hashes,
         count(*) = 23 and coalesce(bool_and(catalog_ready), false)
           as catalog_ready
  from actual_trusted_function
)
select applied_count, latest_created_at, latest_hash, migration_fingerprint,
       app.api_runtime_schema_readiness_v57() AS array,
       trusted.source_hashes,
       trusted.catalog_ready
from app.schema_compatibility_v57()
cross join trusted_function_state as trusted
`

var expectedTrustedFunctionSourceHashes = [...]string{
	expectedSchemaCompatibilityV57SourceHash,
	expectedRetiredSchemaCompatibilityV49SourceHash,
	expectedPrivateV47MigrationConvergenceSchemaReadinessV1SourceHash,
	expectedPrivateSchemaCompatibilityJournalV57SourceHash,
	expectedPrivateReleaseRuntimeDependencySurfaceHashV57SourceHash,
	expectedPrivateReleaseRuntimeReadinessV57SourceHash,
	expectedReleaseRuntimeReadinessV57SourceHash,
	expectedFederatedAuthenticationReadinessV57SourceHash,
	expectedPlatformOIDCDirectRuntimeReadinessV57SourceHash,
	expectedPlatformSAMLDirectRuntimeReadinessV57SourceHash,
	expectedPlatformLocalAccountRuntimeReadinessV57SourceHash,
	expectedTicketBulkRuntimeReadinessV57SourceHash,
	expectedTicketExportRuntimeReadinessV57SourceHash,
	expectedTicketMetadataRuntimeReadinessV57SourceHash,
	expectedPrivateRotateSLAReadinessV48SourceHash,
	expectedRetiredSchemaCompatibilityV50SourceHash,
	expectedRetiredSchemaCompatibilityV51SourceHash,
	expectedAPIRuntimeReadinessV57SourceHash,
	expectedRetiredSchemaCompatibilityV52SourceHash,
	expectedRetiredSchemaCompatibilityV53SourceHash,
	expectedRetiredSchemaCompatibilityV54SourceHash,
	expectedRetiredSchemaCompatibilityV55SourceHash,
	expectedRetiredSchemaCompatibilityV56SourceHash,
}

// SchemaQuerier is implemented by pgxpool.Pool and keeps readiness checks testable.
type SchemaQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// HealthChecker checks PostgreSQL connectivity without exposing error details.
type HealthChecker struct {
	pool SchemaQuerier
}

// NewHealthChecker returns a PostgreSQL health checker.
func NewHealthChecker(pool SchemaQuerier) HealthChecker {
	return HealthChecker{pool: pool}
}

type verifiedRuntimeKey struct{}

type verifiedRuntime struct {
	pool  *pgxpool.Pool
	probe context.Context
}

// CheckWithContext shares the fully attested V57 projection only with repository
// readiness checks in this bounded probe and against this exact connection pool.
// Request authorization and ordinary repository operations never use this evidence.
func (c HealthChecker) CheckWithContext(ctx context.Context) (context.Context, []DependencyCheck) {
	ctx = context.WithValue(ctx, verifiedRuntimeKey{}, verifiedRuntime{})
	checks := c.Check(ctx)
	pool, ok := c.pool.(*pgxpool.Pool)
	deadline, bounded := ctx.Deadline()
	if ok && pool != nil && bounded && time.Until(deadline) <= 30*time.Second &&
		ctx.Err() == nil && len(checks) == 1 && checks[0].Ready {
		ctx = context.WithValue(ctx, verifiedRuntimeKey{}, verifiedRuntime{pool: pool, probe: ctx})
	}
	return ctx, checks
}

func runtimeVerifiedInProbe(ctx context.Context, queryer any) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	pool, ok := queryer.(*pgxpool.Pool)
	evidence, _ := ctx.Value(verifiedRuntimeKey{}).(verifiedRuntime)
	return ok && pool != nil && evidence.pool == pool && evidence.probe != nil && evidence.probe.Err() == nil
}

// Check reports PostgreSQL connectivity and exact current migration compatibility.
func (c HealthChecker) Check(ctx context.Context) []DependencyCheck {
	startedAt := time.Now()
	var appliedCount int64
	var latestCreatedAt pgtype.Int8
	var latestHash pgtype.Text
	var migrationFingerprint pgtype.Text
	var runtimeReady []bool
	var trustedFunctionSourceHashes []string
	var trustedFunctionCatalogReady bool
	err := c.pool.QueryRow(
		ctx, schemaCompatibilityQuery, expectedMigrationFingerprint,
	).Scan(
		&appliedCount,
		&latestCreatedAt,
		&latestHash,
		&migrationFingerprint,
		&runtimeReady,
		&trustedFunctionSourceHashes,
		&trustedFunctionCatalogReady,
	)
	ready := err == nil &&
		latestCreatedAt.Valid &&
		latestHash.Valid &&
		migrationFingerprint.Valid &&
		len(runtimeReady) == 8 &&
		!slices.Contains(runtimeReady, false) &&
		slices.Equal(trustedFunctionSourceHashes, expectedTrustedFunctionSourceHashes[:]) &&
		trustedFunctionCatalogReady &&
		appliedCount == expectedMigrationCount &&
		latestCreatedAt.Int64 == expectedMigrationCreatedAt &&
		latestHash.String == expectedMigrationHash &&
		migrationFingerprint.String == expectedMigrationFingerprint
	failure := ""
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(ctx.Err(), context.DeadlineExceeded):
		failure = "deadline_exceeded"
	case err != nil:
		failure = "query_unavailable"
	case !trustedFunctionCatalogReady || !slices.Equal(trustedFunctionSourceHashes, expectedTrustedFunctionSourceHashes[:]):
		failure = "trusted_functions_changed"
	case len(runtimeReady) != 8 || slices.Contains(runtimeReady, false):
		failure = "runtime_schema_unavailable"
	case !ready:
		failure = "migration_state_changed"
	}
	return []DependencyCheck{{
		Name:    "postgresql",
		Ready:   ready,
		Latency: time.Since(startedAt),
		Failure: failure,
	}}
}

// DependencyCheck is a non-sensitive result suitable for readiness responses.
type DependencyCheck struct {
	Name    string
	Ready   bool
	Latency time.Duration
	Failure string
}

// UnconfiguredHealthChecker keeps development liveness available while readiness fails closed.
type UnconfiguredHealthChecker struct{}

// Check reports that the required database is unavailable.
func (UnconfiguredHealthChecker) Check(context.Context) []DependencyCheck {
	return []DependencyCheck{{Name: "postgresql", Ready: false}}
}
