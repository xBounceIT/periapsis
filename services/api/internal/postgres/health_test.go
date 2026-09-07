package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestHealthCheckerRequiresExactSchemaCompatibility(t *testing.T) {
	testError := errors.New("query failed")
	tests := []struct {
		name      string
		mutate    func(*stubSchemaRow)
		wantReady bool
	}{
		{name: "exact v55 state", wantReady: true},
		{name: "empty journal", mutate: func(row *stubSchemaRow) {
			row.appliedCount = 0
			row.latestCreatedAt = pgtype.Int8{}
			row.latestHash = pgtype.Text{}
			row.fingerprint = pgtype.Text{}
		}},
		{name: "stale migration count", mutate: func(row *stubSchemaRow) {
			row.appliedCount--
		}},
		{name: "stale migration timestamp", mutate: func(row *stubSchemaRow) {
			row.latestCreatedAt.Int64--
		}},
		{name: "newer migration state", mutate: func(row *stubSchemaRow) {
			row.appliedCount++
			row.latestCreatedAt.Int64++
		}},
		{name: "divergent migration hash", mutate: func(row *stubSchemaRow) {
			row.latestHash.String = "unexpected"
		}},
		{name: "earlier migration fingerprint drift", mutate: func(row *stubSchemaRow) {
			row.fingerprint.String = "unexpected"
		}},
		{name: "runtime readiness cardinality drift", mutate: func(row *stubSchemaRow) {
			row.runtimeReady = row.runtimeReady[:len(row.runtimeReady)-1]
		}},
		{name: "trusted source cardinality drift", mutate: func(row *stubSchemaRow) {
			row.sourceHashes = row.sourceHashes[:len(row.sourceHashes)-1]
		}},
		{name: "retired v50 source removed", mutate: func(row *stubSchemaRow) {
			row.sourceHashes = slices.Delete(row.sourceHashes, 15, 16)
		}},
		{name: "retired v50 source tampered", mutate: func(row *stubSchemaRow) {
			row.sourceHashes[15] = "unexpected"
		}},
		{name: "retired v51 source removed", mutate: func(row *stubSchemaRow) {
			row.sourceHashes = slices.Delete(row.sourceHashes, 16, 17)
		}},
		{name: "retired v51 source tampered", mutate: func(row *stubSchemaRow) {
			row.sourceHashes[16] = "unexpected"
		}},
		{name: "api aggregate source removed", mutate: func(row *stubSchemaRow) {
			row.sourceHashes = slices.Delete(row.sourceHashes, 17, 18)
		}},
		{name: "api aggregate source tampered despite all-true readiness", mutate: func(row *stubSchemaRow) {
			row.sourceHashes[17] = "unexpected"
		}},
		{name: "trusted function catalog drift", mutate: func(row *stubSchemaRow) {
			row.catalogReady = false
		}},
		{name: "query failure", mutate: func(row *stubSchemaRow) {
			row.err = testError
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			row := exactStubSchemaRow()
			if test.mutate != nil {
				test.mutate(&row)
			}
			checks := NewHealthChecker(&stubSchemaQuerier{row: row}).Check(context.Background())
			if len(checks) != 1 || checks[0].Name != "postgresql" || checks[0].Ready != test.wantReady {
				t.Fatalf("checks = %#v, want one postgresql ready=%t", checks, test.wantReady)
			}
		})
	}
}

func TestHealthCheckerClassifiesReadinessFailuresWithoutQueryDetails(t *testing.T) {
	for _, test := range []struct {
		failure string
		mutate  func(*stubSchemaRow)
	}{
		{"deadline_exceeded", func(row *stubSchemaRow) { row.err = context.DeadlineExceeded }},
		{"query_unavailable", func(row *stubSchemaRow) { row.err = errors.New("private-query-canary") }},
		{"trusted_functions_changed", func(row *stubSchemaRow) { row.catalogReady = false }},
		{"runtime_schema_unavailable", func(row *stubSchemaRow) { row.runtimeReady[0] = false }},
		{"migration_state_changed", func(row *stubSchemaRow) { row.appliedCount = 0 }},
	} {
		t.Run(test.failure, func(t *testing.T) {
			row := exactStubSchemaRow()
			test.mutate(&row)
			check := NewHealthChecker(&stubSchemaQuerier{row: row}).Check(context.Background())[0]
			if check.Ready || check.Failure != test.failure {
				t.Fatalf("readiness failure = %q", check.Failure)
			}
		})
	}
}

func TestHealthCheckerRequiresEveryV55RuntimeAndTrustedRoot(t *testing.T) {
	for index := range 8 {
		t.Run(fmt.Sprintf("runtime_%02d", index+1), func(t *testing.T) {
			row := exactStubSchemaRow()
			row.runtimeReady[index] = false
			if NewHealthChecker(&stubSchemaQuerier{row: row}).Check(context.Background())[0].Ready {
				t.Fatalf("runtime readiness index %d was not required", index)
			}
		})
	}
	for index := range expectedTrustedFunctionSourceHashes {
		t.Run(fmt.Sprintf("source_%02d", index+1), func(t *testing.T) {
			row := exactStubSchemaRow()
			row.sourceHashes[index] = "unexpected"
			if NewHealthChecker(&stubSchemaQuerier{row: row}).Check(context.Background())[0].Ready {
				t.Fatalf("trusted source index %d was not required", index)
			}
		})
	}
}

func TestHealthCheckerPassesExpectedMigrationFingerprintAsFirstArgument(t *testing.T) {
	querier := &stubSchemaQuerier{row: exactStubSchemaRow()}
	checks := NewHealthChecker(querier).Check(context.Background())
	if len(checks) != 1 || !checks[0].Ready {
		t.Fatalf("checks = %#v, want one ready check", checks)
	}
	if querier.query != schemaCompatibilityQuery || len(querier.args) != 1 {
		t.Fatalf("health query/arguments = (%t, %d)", querier.query == schemaCompatibilityQuery, len(querier.args))
	}
	if got, ok := querier.args[0].(string); !ok || got != expectedMigrationFingerprint {
		t.Fatalf("QueryRow arg $1 = %#v, want expected migration fingerprint", querier.args[0])
	}
}

func TestSchemaCompatibilityQuerySealsV55TrustedSet(t *testing.T) {
	if len(expectedTrustedFunctionSourceHashes) != 21 {
		t.Fatalf("trusted source hash count = %d, want 21", len(expectedTrustedFunctionSourceHashes))
	}
	if expectedTrustedFunctionSourceHashes[15] != expectedRetiredSchemaCompatibilityV50SourceHash {
		t.Fatal("retired v50 root is not bound to its exact generated source hash")
	}
	if expectedTrustedFunctionSourceHashes[16] != expectedRetiredSchemaCompatibilityV51SourceHash {
		t.Fatal("retired v51 root is not bound to its exact generated source hash")
	}
	if expectedTrustedFunctionSourceHashes[17] != expectedAPIRuntimeReadinessV55SourceHash {
		t.Fatal("api aggregate is not bound to its exact generated source hash")
	}
	for _, required := range []string{
		"from app.schema_compatibility_v55()",
		"'app.schema_compatibility_fingerprint=' || $1::text",
		"(2, 'retired', 'app.schema_compatibility_v49()'",
		"(16, 'retired_v50', 'app.schema_compatibility_v50()'",
		"(17, 'retired_v51', 'app.schema_compatibility_v51()'",
		"(18, 'api_aggregate', 'app.api_runtime_schema_readiness_v55()'",
		"app.api_runtime_schema_readiness_v55() AS array",
		"'boolean[]', " + trustedAPIACL,
		"'app.schema_compatibility_fingerprint=RETIRED'",
		"'journal'",
		"'latest_rows',",
		"owner.rolname = case when expected.function_key = 'sla_rotation'",
		"function.provolatile = case",
		"pg_catalog.sha256(pg_catalog.convert_to(function.prosrc, 'UTF8'))",
		"function.pronargdefaults = 0",
		"function.proargtypes = ''::pg_catalog.oidvector",
		"function.proargdefaults is null",
		"function.provariadic = 0",
		"function.prosupport = 0",
		"function.proretset = (expected.function_key in (",
		"'compatibility', 'retired', 'retired_v50', 'retired_v51', 'retired_v52', 'retired_v53', 'retired_v54', 'journal'",
		"function.procost = 100::real",
		"function.prorows = case when function.proretset",
		"function.protrftypes is null",
		"function.probin is null",
		"function.prosqlbody is null",
		"function.proallargtypes is not distinct from array[",
		"function.proargmodes is not distinct from",
		"function.proargnames is not distinct from array[",
		"count(*) = pg_catalog.cardinality(",
		"pg_catalog.array_agg(",
		"collate \"C\"",
		"pg_catalog.aclexplode(case",
		"else null::pg_catalog.aclitem[]",
		"pg_catalog.acldefault('f', function.proowner)",
		"pg_catalog.to_regprocedure(expected.signature)",
		"is not distinct from expected.expected_acl_roles",
		"function_acl.grantor = function.proowner",
		"function_acl.privilege_type = 'EXECUTE'",
		"not function_acl.is_grantable",
		"array_agg(source_hash order by ordinal)",
		"count(*) = 21 and coalesce(bool_and(catalog_ready), false)",
		trustedAPIACL,
		trustedSLARotationACL,
		"app.federated_authentication_schema_readiness_v55()",
		"app.platform_oidc_direct_runtime_schema_readiness_v55()",
		"app.platform_saml_direct_runtime_schema_readiness_v55()",
		"app.platform_local_account_runtime_schema_readiness_v55()",
		"app.ticket_bulk_runtime_schema_readiness_v55()",
		"app.ticket_export_runtime_schema_readiness_v55()",
		"app.ticket_metadata_runtime_schema_readiness_v55()",
		"app.private_rotate_sla_readiness_v48()",
	} {
		if !strings.Contains(schemaCompatibilityQuery, required) {
			t.Fatalf("schema compatibility query is missing %q", required)
		}
	}

	if got := strings.Count(schemaCompatibilityQuery, trustedRuntimeACL); got != 3 {
		t.Fatalf("runtime trusted-root ACL count = %d, want 3", got)
	}
	if got := strings.Count(schemaCompatibilityQuery, trustedReleaseACL); got != 1 {
		t.Fatalf("release trusted-root ACL count = %d, want 1", got)
	}
	if got := strings.Count(schemaCompatibilityQuery, trustedOwnerACL); got != 10 {
		t.Fatalf("owner-only trusted-root ACL count = %d, want 10", got)
	}
	if got := strings.Count(schemaCompatibilityQuery, trustedAPIACL); got != 6 {
		t.Fatalf("API-only trusted-root ACL count = %d, want 6", got)
	}
	if got := strings.Count(schemaCompatibilityQuery, trustedSLARotationACL); got != 1 {
		t.Fatalf("SLA rotation trusted-root ACL count = %d, want 1", got)
	}

	roots := []struct {
		name  string
		count int
	}{
		{"app.schema_compatibility_v49()", 1},
		{"app.schema_compatibility_v50()", 1},
		{"app.schema_compatibility_v51()", 1},
		{"app.schema_compatibility_v55()", 2},
		{"app.api_runtime_schema_readiness_v55()", 2},
		{"app.private_v47_migration_convergence_schema_readiness_v1()", 1},
		{"app.private_schema_compatibility_journal_v55()", 1},
		{"app.private_release_runtime_dependency_surface_hash_v55()", 1},
		{"app.private_release_runtime_schema_readiness_v55()", 1},
		{"app.release_runtime_schema_readiness_v55()", 1},
		{"app.federated_authentication_schema_readiness_v55()", 1},
		{"app.platform_oidc_direct_runtime_schema_readiness_v55()", 1},
		{"app.platform_saml_direct_runtime_schema_readiness_v55()", 1},
		{"app.platform_local_account_runtime_schema_readiness_v55()", 1},
		{"app.ticket_bulk_runtime_schema_readiness_v55()", 1},
		{"app.ticket_export_runtime_schema_readiness_v55()", 1},
		{"app.ticket_metadata_runtime_schema_readiness_v55()", 1},
		{"app.private_rotate_sla_readiness_v48()", 1},
	}
	for _, root := range roots {
		if got := strings.Count(schemaCompatibilityQuery, root.name); got != root.count {
			t.Fatalf("%s reference count = %d, want %d", root.name, got, root.count)
		}
	}
	if strings.Contains(schemaCompatibilityQuery, "from app.schema_compatibility_v49()") {
		t.Fatal("health query directly calls retired schema compatibility v49")
	}
	if strings.Contains(schemaCompatibilityQuery, "from app.schema_compatibility_v50()") {
		t.Fatal("health query directly calls retired schema compatibility v50")
	}
	if strings.Contains(schemaCompatibilityQuery, "from app.schema_compatibility_v51()") {
		t.Fatal("health query directly calls retired schema compatibility v51")
	}
	for _, stale := range []string{
		"app.platform_identity_runtime_schema_readiness_v13()",
		"app.platform_oidc_direct_runtime_schema_readiness_v9()",
		"app.platform_saml_direct_runtime_schema_readiness_v6()",
		"app.mfa_policy_administration_schema_readiness_v7()",
		"app.ticket_mutation_runtime_schema_readiness_v2()",
		"app.ticket_watcher_runtime_schema_readiness_v2()",
	} {
		if strings.Contains(schemaCompatibilityQuery, stale) {
			t.Fatalf("health query retains stale trusted root %q", stale)
		}
	}
}

func exactStubSchemaRow() stubSchemaRow {
	runtimeReady := make([]bool, 8)
	for index := range runtimeReady {
		runtimeReady[index] = true
	}
	return stubSchemaRow{
		appliedCount:    expectedMigrationCount,
		latestCreatedAt: pgtype.Int8{Int64: expectedMigrationCreatedAt, Valid: true},
		latestHash:      pgtype.Text{String: expectedMigrationHash, Valid: true},
		fingerprint:     pgtype.Text{String: expectedMigrationFingerprint, Valid: true},
		runtimeReady:    runtimeReady,
		sourceHashes:    slices.Clone(expectedTrustedFunctionSourceHashes[:]),
		catalogReady:    true,
	}
}

type stubSchemaQuerier struct {
	row   pgx.Row
	query string
	args  []any
}

func (q *stubSchemaQuerier) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	q.query = query
	q.args = append([]any(nil), args...)
	return q.row
}

type stubSchemaRow struct {
	appliedCount    int64
	latestCreatedAt pgtype.Int8
	latestHash      pgtype.Text
	fingerprint     pgtype.Text
	runtimeReady    []bool
	sourceHashes    []string
	catalogReady    bool
	err             error
}

func (r stubSchemaRow) Scan(destinations ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(destinations) != 7 {
		return fmt.Errorf("Scan destination count = %d, want 7", len(destinations))
	}
	*destinations[0].(*int64) = r.appliedCount
	*destinations[1].(*pgtype.Int8) = r.latestCreatedAt
	*destinations[2].(*pgtype.Text) = r.latestHash
	*destinations[3].(*pgtype.Text) = r.fingerprint
	*destinations[4].(*[]bool) = slices.Clone(r.runtimeReady)
	*destinations[5].(*[]string) = slices.Clone(r.sourceHashes)
	*destinations[6].(*bool) = r.catalogReady
	return nil
}
