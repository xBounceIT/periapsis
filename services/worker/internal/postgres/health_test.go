package postgres

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/periapsis-im/periapsis/modules/identity"
)

func TestHealthCheckerRequiresExactSchemaCompatibility(t *testing.T) {
	testError := errors.New("query failed")
	tests := []struct {
		name      string
		mutate    func(*stubSchemaRow)
		wantReady bool
	}{
		{name: "exact v52 state", wantReady: true},
		{name: "identity keyring mismatch", mutate: func(row *stubSchemaRow) {
			row.keyringReady = false
		}},
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
			row.sourceHashes = slices.Delete(row.sourceHashes, 12, 13)
		}},
		{name: "retired v50 source tampered", mutate: func(row *stubSchemaRow) {
			row.sourceHashes[12] = "unexpected"
		}},
		{name: "retired v51 source removed", mutate: func(row *stubSchemaRow) {
			row.sourceHashes = slices.Delete(row.sourceHashes, 13, 14)
		}},
		{name: "retired v51 source tampered", mutate: func(row *stubSchemaRow) {
			row.sourceHashes[13] = "unexpected"
		}},
		{name: "worker aggregate source removed", mutate: func(row *stubSchemaRow) {
			row.sourceHashes = slices.Delete(row.sourceHashes, 14, 15)
		}},
		{name: "worker aggregate source tampered despite all-true readiness", mutate: func(row *stubSchemaRow) {
			row.sourceHashes[14] = "unexpected"
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
			checker := NewHealthChecker(&stubSchemaQuerier{row: row}, testIdentityReadinessEvidence())
			if got := checker.Check(context.Background()); got != test.wantReady {
				t.Fatalf("ready = %t, want %t", got, test.wantReady)
			}
		})
	}
}

func TestHealthCheckerRequiresEveryV52RuntimeAndTrustedRoot(t *testing.T) {
	for index := range 5 {
		t.Run(fmt.Sprintf("runtime_%02d", index+1), func(t *testing.T) {
			row := exactStubSchemaRow()
			row.runtimeReady[index] = false
			checker := NewHealthChecker(&stubSchemaQuerier{row: row}, testIdentityReadinessEvidence())
			if checker.Check(context.Background()) {
				t.Fatalf("runtime readiness index %d was not required", index)
			}
		})
	}
	for index := range expectedTrustedFunctionSourceHashes {
		t.Run(fmt.Sprintf("source_%02d", index+1), func(t *testing.T) {
			row := exactStubSchemaRow()
			row.sourceHashes[index] = "unexpected"
			checker := NewHealthChecker(&stubSchemaQuerier{row: row}, testIdentityReadinessEvidence())
			if checker.Check(context.Background()) {
				t.Fatalf("trusted source index %d was not required", index)
			}
		})
	}
}

func TestHealthCheckerPassesKeyringEvidenceAndExpectedMigrationFingerprint(t *testing.T) {
	querier := &stubSchemaQuerier{row: exactStubSchemaRow()}
	checker := NewHealthChecker(querier, testIdentityReadinessEvidence())
	if !checker.Check(context.Background()) {
		t.Fatal("Check() = false, want true")
	}
	if querier.query != schemaCompatibilityQuery || len(querier.args) != 4 {
		t.Fatalf("health query/arguments = (%t, %d)", querier.query == schemaCompatibilityQuery, len(querier.args))
	}
	if !reflect.DeepEqual(querier.args[0], checker.keyVersions) ||
		!reflect.DeepEqual(querier.args[1], checker.keyVerifiers) {
		t.Fatal("health query did not bind exact keyring evidence")
	}
	if got, ok := querier.args[2].(int32); !ok || got != checker.activeKeyVersion {
		t.Fatalf("QueryRow arg $3 = %#v, want %d", querier.args[2], checker.activeKeyVersion)
	}
	if got, ok := querier.args[3].(string); !ok || got != expectedMigrationFingerprint {
		t.Fatalf("QueryRow arg $4 = %#v, want expected migration fingerprint", querier.args[3])
	}
}

func TestSchemaCompatibilityQuerySealsV52TrustedSet(t *testing.T) {
	if len(expectedTrustedFunctionSourceHashes) != 15 {
		t.Fatalf("trusted source hash count = %d, want 15", len(expectedTrustedFunctionSourceHashes))
	}
	if expectedTrustedFunctionSourceHashes[12] != expectedRetiredSchemaCompatibilityV50SourceHash {
		t.Fatal("retired v50 root is not bound to its exact generated source hash")
	}
	if expectedTrustedFunctionSourceHashes[13] != expectedRetiredSchemaCompatibilityV51SourceHash {
		t.Fatal("retired v51 root is not bound to its exact generated source hash")
	}
	if expectedTrustedFunctionSourceHashes[14] != expectedWorkerRuntimeReadinessV52SourceHash {
		t.Fatal("worker aggregate is not bound to its exact generated source hash")
	}
	for _, required := range []string{
		"from app.schema_compatibility_v52()",
		"'app.schema_compatibility_fingerprint=' || $4::text",
		"(2, 'retired', 'app.schema_compatibility_v49()'",
		"(13, 'retired_v50', 'app.schema_compatibility_v50()'",
		"(14, 'retired_v51', 'app.schema_compatibility_v51()'",
		"(15, 'worker_aggregate', 'app.worker_runtime_schema_readiness_v52()'",
		"app.worker_runtime_schema_readiness_v52() AS array",
		"'boolean[]', " + trustedWorkerACL,
		"'app.schema_compatibility_fingerprint=RETIRED'",
		"'journal'",
		"'latest_rows',",
		"app.verify_identity_keyring_v3($1::integer[], $2::bytea[], $3::integer)",
		"owner.rolname = case when expected.function_key = 'sla_rotation'",
		"function.provolatile = case",
		"pg_catalog.sha256(pg_catalog.convert_to(function.prosrc, 'UTF8'))",
		"function.pronargdefaults = 0",
		"function.proargtypes = ''::pg_catalog.oidvector",
		"function.proargdefaults is null",
		"function.provariadic = 0",
		"function.prosupport = 0",
		"function.proretset = (expected.function_key in (",
		"'compatibility', 'retired', 'retired_v50', 'retired_v51', 'journal'",
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
		"count(*) = 15 and coalesce(bool_and(catalog_ready), false)",
		trustedWorkerACL,
		trustedSLARotationACL,
		"app.sla_trigger_action_runtime_schema_readiness_v52()",
		"app.sla_object_event_ingress_schema_readiness_v52()",
		"app.ticket_bulk_runtime_schema_readiness_v52()",
		"app.ticket_export_runtime_schema_readiness_v52()",
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
	if got := strings.Count(schemaCompatibilityQuery, trustedOwnerACL); got != 7 {
		t.Fatalf("owner-only trusted-root ACL count = %d, want 7", got)
	}
	if got := strings.Count(schemaCompatibilityQuery, trustedWorkerACL); got != 3 {
		t.Fatalf("worker trusted-root ACL count = %d, want 3", got)
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
		{"app.schema_compatibility_v52()", 2},
		{"app.worker_runtime_schema_readiness_v52()", 2},
		{"app.private_v47_migration_convergence_schema_readiness_v1()", 1},
		{"app.private_schema_compatibility_journal_v52()", 1},
		{"app.private_release_runtime_dependency_surface_hash_v52()", 1},
		{"app.private_release_runtime_schema_readiness_v52()", 1},
		{"app.release_runtime_schema_readiness_v52()", 1},
		{"app.sla_trigger_action_runtime_schema_readiness_v52()", 1},
		{"app.sla_object_event_ingress_schema_readiness_v52()", 1},
		{"app.ticket_bulk_runtime_schema_readiness_v52()", 1},
		{"app.ticket_export_runtime_schema_readiness_v52()", 1},
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

func testIdentityReadinessEvidence() identity.ReadinessEvidence {
	return identity.ReadinessEvidence{
		ActiveVersion: 1,
		Versions:      []identity.VersionVerifier{{KeyVersion: 1, Verifier: [32]byte{1}}},
	}
}

func exactStubSchemaRow() stubSchemaRow {
	runtimeReady := make([]bool, 5)
	for index := range runtimeReady {
		runtimeReady[index] = true
	}
	return stubSchemaRow{
		appliedCount:    expectedMigrationCount,
		latestCreatedAt: pgtype.Int8{Int64: expectedMigrationCreatedAt, Valid: true},
		latestHash:      pgtype.Text{String: expectedMigrationHash, Valid: true},
		fingerprint:     pgtype.Text{String: expectedMigrationFingerprint, Valid: true},
		keyringReady:    true,
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
	keyringReady    bool
	runtimeReady    []bool
	sourceHashes    []string
	catalogReady    bool
	err             error
}

func (r stubSchemaRow) Scan(destinations ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(destinations) != 8 {
		return fmt.Errorf("Scan destination count = %d, want 8", len(destinations))
	}
	*destinations[0].(*int64) = r.appliedCount
	*destinations[1].(*pgtype.Int8) = r.latestCreatedAt
	*destinations[2].(*pgtype.Text) = r.latestHash
	*destinations[3].(*pgtype.Text) = r.fingerprint
	*destinations[4].(*bool) = r.keyringReady
	*destinations[5].(*[]bool) = slices.Clone(r.runtimeReady)
	*destinations[6].(*[]string) = slices.Clone(r.sourceHashes)
	*destinations[7].(*bool) = r.catalogReady
	return nil
}
