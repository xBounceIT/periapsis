// Package postgres provides pgx-backed worker infrastructure adapters.
package postgres

import (
	"context"
	"slices"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/periapsis-im/periapsis/modules/identity"
)

const (
	trustedRuntimeACL = `array['periapsis_api', 'periapsis_migrator', 'periapsis_worker']::text[]`
	trustedReleaseACL = `array[
       'periapsis_api', 'periapsis_migrator',
       'periapsis_notification_readiness_owner', 'periapsis_worker'
     ]::text[]`
	trustedWorkerACL      = `array['periapsis_migrator', 'periapsis_worker']::text[]`
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
    (1, 'compatibility', 'app.schema_compatibility_v49()', 'plpgsql', array[
       'search_path=pg_catalog',
       'app.schema_compatibility_fingerprint=' || $4::text
     ]::text[],
     'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)',
     ` + trustedRuntimeACL + `),
    (2, 'retired', 'app.schema_compatibility_v48()', 'plpgsql', array[
       'search_path=pg_catalog',
       'app.schema_compatibility_fingerprint=RETIRED'
     ]::text[],
     'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)',
     ` + trustedOwnerACL + `),
    (3, 'convergence',
     'app.private_v47_migration_convergence_schema_readiness_v1()',
     'plpgsql', array['search_path=pg_catalog, public, app']::text[],
     'boolean', ` + trustedOwnerACL + `),
    (4, 'journal', 'app.private_schema_compatibility_journal_v49()',
     'plpgsql', array['search_path=pg_catalog, public, app']::text[],
     'TABLE(applied_count bigint, latest_created_at bigint, latest_rows bigint, latest_hash text, migration_fingerprint text)',
     ` + trustedOwnerACL + `),
    (5, 'dependency',
     'app.private_release_runtime_dependency_surface_hash_v49()',
     'sql', ` + trustedRuntimeConfig + `, 'text', ` + trustedOwnerACL + `),
    (6, 'private_release',
     'app.private_release_runtime_schema_readiness_v49()',
     'plpgsql', array['search_path=pg_catalog, public, app']::text[],
     'boolean', ` + trustedOwnerACL + `),
    (7, 'release', 'app.release_runtime_schema_readiness_v49()',
     'plpgsql', array['search_path=pg_catalog, public, app']::text[],
     'boolean', ` + trustedReleaseACL + `),
    (8, 'sla_trigger_action',
     'app.sla_trigger_action_runtime_schema_readiness_v49()',
     'plpgsql', array['search_path=pg_catalog, public, app']::text[],
     'boolean', ` + trustedWorkerACL + `),
    (9, 'sla_object_event_ingress',
     'app.sla_object_event_ingress_schema_readiness_v49()',
     'plpgsql', array['search_path=pg_catalog, public, app']::text[],
     'boolean', ` + trustedWorkerACL + `),
    (10, 'ticket_bulk', 'app.ticket_bulk_runtime_schema_readiness_v49()',
     'plpgsql', array['search_path=pg_catalog, public, app']::text[],
     'boolean', ` + trustedRuntimeACL + `),
    (11, 'ticket_export', 'app.ticket_export_runtime_schema_readiness_v49()',
     'plpgsql', array['search_path=pg_catalog, public, app']::text[],
     'boolean', ` + trustedRuntimeACL + `),
    (12, 'sla_rotation', 'app.private_rotate_sla_readiness_v48()',
     'plpgsql', array['search_path=pg_catalog, public, app']::text[],
     'void', ` + trustedSLARotationACL + `)
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
             'compatibility', 'retired', 'journal'
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
         count(*) = 12 and coalesce(bool_and(catalog_ready), false)
           as catalog_ready
  from actual_trusted_function
)
select applied_count, latest_created_at, latest_hash, migration_fingerprint,
       app.verify_identity_keyring_v3($1::integer[], $2::bytea[], $3::integer),
       ARRAY[
         app.release_runtime_schema_readiness_v49(),
         app.sla_trigger_action_runtime_schema_readiness_v49(),
         app.sla_object_event_ingress_schema_readiness_v49(),
         app.ticket_bulk_runtime_schema_readiness_v49(),
         app.ticket_export_runtime_schema_readiness_v49()
       ]::boolean[],
       trusted.source_hashes,
       trusted.catalog_ready
from app.schema_compatibility_v49()
cross join trusted_function_state as trusted
`

var expectedTrustedFunctionSourceHashes = [...]string{
	expectedSchemaCompatibilityV49SourceHash,
	expectedRetiredSchemaCompatibilityV48SourceHash,
	expectedPrivateV47MigrationConvergenceSchemaReadinessV1SourceHash,
	expectedPrivateSchemaCompatibilityJournalV49SourceHash,
	expectedPrivateReleaseRuntimeDependencySurfaceHashV49SourceHash,
	expectedPrivateReleaseRuntimeReadinessV49SourceHash,
	expectedReleaseRuntimeReadinessV49SourceHash,
	expectedSLATriggerActionRuntimeReadinessV49SourceHash,
	expectedSLAObjectEventIngressReadinessV49SourceHash,
	expectedTicketBulkRuntimeReadinessV49SourceHash,
	expectedTicketExportRuntimeReadinessV49SourceHash,
	expectedPrivateRotateSLAReadinessV48SourceHash,
}

// SchemaQuerier is implemented by pgxpool.Pool and keeps readiness checks testable.
type SchemaQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// HealthChecker checks PostgreSQL connectivity and schema compatibility.
type HealthChecker struct {
	pool             SchemaQuerier
	keyVersions      []int32
	keyVerifiers     [][]byte
	activeKeyVersion int32
}

// NewHealthChecker returns a fail-closed PostgreSQL health checker.
func NewHealthChecker(pool SchemaQuerier, evidence identity.ReadinessEvidence) HealthChecker {
	checker := HealthChecker{
		pool:             pool,
		keyVersions:      make([]int32, 0, len(evidence.Versions)),
		keyVerifiers:     make([][]byte, 0, len(evidence.Versions)),
		activeKeyVersion: int32(evidence.ActiveVersion),
	}
	for _, version := range evidence.Versions {
		checker.keyVersions = append(checker.keyVersions, int32(version.KeyVersion))
		checker.keyVerifiers = append(checker.keyVerifiers, append([]byte(nil), version.Verifier[:]...))
	}
	return checker
}

// Check reports whether the exact current migration state supported by this binary is applied.
func (c HealthChecker) Check(ctx context.Context) bool {
	var appliedCount int64
	var latestCreatedAt pgtype.Int8
	var latestHash pgtype.Text
	var migrationFingerprint pgtype.Text
	var identityKeyringReady bool
	var runtimeReady []bool
	var trustedFunctionSourceHashes []string
	var trustedFunctionCatalogReady bool
	err := c.pool.QueryRow(
		ctx,
		schemaCompatibilityQuery,
		c.keyVersions,
		c.keyVerifiers,
		c.activeKeyVersion,
		expectedMigrationFingerprint,
	).Scan(
		&appliedCount,
		&latestCreatedAt,
		&latestHash,
		&migrationFingerprint,
		&identityKeyringReady,
		&runtimeReady,
		&trustedFunctionSourceHashes,
		&trustedFunctionCatalogReady,
	)
	return err == nil &&
		latestCreatedAt.Valid &&
		latestHash.Valid &&
		migrationFingerprint.Valid &&
		identityKeyringReady &&
		len(runtimeReady) == 5 &&
		!slices.Contains(runtimeReady, false) &&
		slices.Equal(trustedFunctionSourceHashes, expectedTrustedFunctionSourceHashes[:]) &&
		trustedFunctionCatalogReady &&
		appliedCount == expectedMigrationCount &&
		latestCreatedAt.Int64 == expectedMigrationCreatedAt &&
		latestHash.String == expectedMigrationHash &&
		migrationFingerprint.String == expectedMigrationFingerprint
}
