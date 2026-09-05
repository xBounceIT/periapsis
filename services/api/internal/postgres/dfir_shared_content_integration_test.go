package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

// This test commits synthetic fixtures and real repository transactions. Its
// caller must supply a fresh, owned clone and dispose of that exact clone after
// the run. It never creates databases, changes global roles, or touches a template.
func TestDFIRSharedContentReplacementsPostgreSQL(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("PERIAPSIS_DFIR_SHARED_CONTENT_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("PERIAPSIS_DFIR_SHARED_CONTENT_TEST_DATABASE_URL is not configured")
	}
	expectedDirectory := strings.TrimSpace(os.Getenv("PERIAPSIS_DFIR_SHARED_CONTENT_EXPECTED_DATA_DIRECTORY"))
	if expectedDirectory == "" {
		t.Fatal("the shared-content test requires an explicit owned cluster directory pin")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin := sharedContentPool(t, ctx, databaseURL, false)
	defer admin.Close()
	var databaseName, dataDirectory string
	var tenantCount int64
	if err := admin.QueryRow(ctx, `SELECT current_database(), current_setting('data_directory'),
		(SELECT count(*) FROM public.tenants)`).Scan(&databaseName, &dataDirectory, &tenantCount); err != nil {
		t.Fatalf("inspect owned shared-content clone: %v", err)
	}
	normalizeDirectory := func(value string) string { return strings.TrimRight(strings.ReplaceAll(value, `\`, "/"), "/") }
	if !regexp.MustCompile(`^periapsis_dfir_shared_content_[a-z0-9_]{1,32}$`).MatchString(databaseName) ||
		tenantCount != 0 || normalizeDirectory(dataDirectory) != normalizeDirectory(expectedDirectory) {
		t.Fatal("shared-content clone ownership, directory, or fresh-tenant guard failed")
	}
	runtime := sharedContentPool(t, ctx, databaseURL, true)
	defer runtime.Close()
	checks := NewHealthChecker(runtime).Check(ctx)
	if len(checks) != 1 || !checks[0].Ready {
		t.Fatal("shared-content clone does not match current generated schema/readiness expectations")
	}

	fixture := seedSharedContentFixture(t, ctx, admin)
	repository := NewDFIRRepository(runtime)
	for _, kind := range []kernel.EntityKind{kernel.EntityIOC, kernel.EntityAsset} {
		for _, rootKind := range []kernel.EntityKind{kernel.EntityCase, kernel.EntityAlert} {
			t.Run(string(kind)+"_through_"+string(rootKind), func(t *testing.T) {
				resourceID := fixture.iocID
				capability := application.CapabilityIOCManage
				if kind == kernel.EntityAsset {
					resourceID, capability = fixture.assetID, application.CapabilityAssetManage
				}
				rootID := fixture.firstCaseID
				if rootKind == kernel.EntityAlert {
					rootID = fixture.alertID
				}
				version := sharedContentVersion(t, ctx, admin, fixture.tenantID, kind, resourceID)
				first := sharedContentWrite(t, fixture, kind, rootKind, rootID, resourceID, version, "first")
				firstResult, replayed, err := first.apply(ctx, repository)
				if err != nil || replayed || firstResult != first.marker {
					t.Fatalf("first actual repository replacement = marker %q, replayed %t, error %v", firstResult, replayed, err)
				}
				if got := sharedContentVersion(t, ctx, admin, fixture.tenantID, kind, resourceID); got != version+1 {
					t.Fatalf("committed version = %d, want %d", got, version+1)
				}
				assertSharedContentActivities(t, ctx, admin, fixture, kind, resourceID, version+1)
				originalReceipt := sharedContentReceipt(t, ctx, admin, fixture, first.base.Command)

				second := sharedContentWrite(t, fixture, kind, rootKind, rootID, resourceID, version+1, "later")
				if marker, replay, writeErr := second.apply(ctx, repository); writeErr != nil || replay || marker != second.marker {
					t.Fatalf("later replacement = marker %q, replayed %t, error %v", marker, replay, writeErr)
				}
				assertSharedContentActivities(t, ctx, admin, fixture, kind, resourceID, version+2)
				beforeReplay := sharedContentSnapshot(t, ctx, admin, fixture.tenantID)
				if marker, replay, replayErr := first.apply(ctx, repository); replayErr != nil || !replay || marker != first.marker {
					t.Fatalf("historical replay returned later state: marker %q, replayed %t, error %v", marker, replay, replayErr)
				}
				assertSharedContentSnapshot(t, beforeReplay, sharedContentSnapshot(t, ctx, admin, fixture.tenantID))
				if !bytes.Equal(originalReceipt, sharedContentReceipt(t, ctx, admin, fixture, first.base.Command)) {
					t.Fatal("historical immutable receipt changed after later replacement/replay")
				}

				stale := sharedContentWrite(t, fixture, kind, rootKind, rootID, resourceID, version, "stale")
				if _, _, staleErr := stale.apply(ctx, repository); !errors.Is(staleErr, application.ErrRepositoryPrecondition) {
					t.Fatalf("stale CAS = %v, want repository precondition", staleErr)
				}
				assertSharedContentSnapshot(t, beforeReplay, sharedContentSnapshot(t, ctx, admin, fixture.tenantID))

				setSharedContentScope(t, ctx, admin, fixture, "operator_team")
				t.Cleanup(func() { setSharedContentScope(t, ctx, admin, fixture, "tenant") })
				assertSharedContentPathAccess(t, ctx, repository, fixture, capability, rootKind, rootID)
				if _, accessErr := repository.ResolveAccess(ctx, fixture.actor, fixture.tenantID, capability,
					application.ResourceScope{CaseID: entityID(fixture.secondCaseID)}); !errors.Is(accessErr, application.ErrRepositoryForbidden) {
					t.Fatalf("non-path Case must independently lose manage authority: %v", accessErr)
				}
				deniedBefore := sharedContentSnapshot(t, ctx, admin, fixture.tenantID)
				denied := sharedContentWrite(t, fixture, kind, rootKind, rootID, resourceID, version+2, "denied")
				for _, attempt := range []sharedContentMutation{denied, first} {
					if _, _, deniedErr := attempt.apply(ctx, repository); !errors.Is(deniedErr, application.ErrRepositoryForbidden) {
						t.Fatalf("non-path revocation allowed fresh write or historical replay: %v", deniedErr)
					}
					assertSharedContentSnapshot(t, deniedBefore, sharedContentSnapshot(t, ctx, admin, fixture.tenantID))
				}
				setSharedContentScope(t, ctx, admin, fixture, "tenant")
				if marker, replay, replayErr := first.apply(ctx, repository); replayErr != nil || !replay || marker != first.marker {
					t.Fatalf("restored authority did not restore exact historical replay: %q, %t, %v", marker, replay, replayErr)
				}
				if marker, replay, writeErr := denied.apply(ctx, repository); writeErr != nil || replay || marker != denied.marker {
					t.Fatalf("denied command left residue after restoration: %q, %t, %v", marker, replay, writeErr)
				}
				assertSharedContentActivities(t, ctx, admin, fixture, kind, resourceID, version+3)
			})
		}
	}
}

func sharedContentPool(t testing.TB, ctx context.Context, databaseURL string, runtime bool) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal("shared-content database URL is invalid")
	}
	config.MaxConns = 2
	config.ConnConfig.RuntimeParams["timezone"] = "UTC"
	config.ConnConfig.RuntimeParams["statement_timeout"] = "15000"
	config.ConnConfig.RuntimeParams["lock_timeout"] = "5000"
	config.AfterConnect = func(ctx context.Context, connection *pgx.Conn) error {
		connection.TypeMap().RegisterType(&pgtype.Type{Name: "timestamptz", OID: pgtype.TimestamptzOID,
			Codec: &pgtype.TimestamptzCodec{ScanLocation: time.UTC}})
		if runtime {
			_, err := connection.Exec(ctx, `SET ROLE "periapsis_api"`)
			return err
		}
		return nil
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("could not initialize shared-content database pool")
	}
	return pool
}

type sharedContentFixture struct {
	dfirSharedAttachmentFixture
	actor  application.Actor
	roleID uuid.UUID
}

func seedSharedContentFixture(t testing.TB, ctx context.Context, admin *pgxpool.Pool) sharedContentFixture {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatalf("begin shared-content fixture: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE "periapsis_migrator"`); err != nil {
		t.Fatalf("set shared-content fixture role: %v", err)
	}
	fixture := sharedContentFixture{dfirSharedAttachmentFixture: seedDFIRSharedAttachmentFixture(t, ctx, tx), roleID: mustDFIRSharedAttachmentUUID(t)}
	fixture.actor = application.Actor{TenantID: fixture.tenantID, ActiveTenantID: fixture.tenantID,
		UserID: mustDFIRSharedAttachmentUUID(t), MembershipID: mustDFIRSharedAttachmentUUID(t),
		SessionID: mustDFIRSharedAttachmentUUID(t), AuthenticationMethod: "totp", Kind: application.PrincipalHuman}
	setDFIRSharedAttachmentFixtureContext(t, ctx, tx, fixture.tenantID, fixture.userID)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, query, args...); err != nil {
			t.Fatalf("seed scoped shared-content fixture: %v", err)
		}
	}
	exec(`INSERT INTO public.users(id,email,display_name,active) VALUES($1,$2,'Shared content scoped operator',true)`,
		fixture.actor.UserID, "shared-content-"+fixture.actor.UserID.String()+"@example.invalid")
	exec(`INSERT INTO public.tenant_memberships(id,tenant_id,user_id,role,status) VALUES($1,$2,$3,'analyst','active')`,
		fixture.actor.MembershipID, fixture.tenantID, fixture.actor.UserID)
	exec(`INSERT INTO public.tenant_user_profiles(tenant_id,membership_id,user_id,display_name,email)
		VALUES($1,$2,$3,'Shared content scoped operator',$4)`, fixture.tenantID, fixture.actor.MembershipID,
		fixture.actor.UserID, "shared-content-"+fixture.actor.UserID.String()+"@example.invalid")
	exec(`INSERT INTO public.tenant_roles(id,tenant_id,key,display_name,description,system_role,protected_role,principal_kind,created_by_membership_id)
		VALUES($1,$2,$3,'Shared content writer','Isolated replacement scope proof',false,false,'human',$4)`,
		fixture.roleID, fixture.tenantID, "shared_content_"+strings.ReplaceAll(fixture.roleID.String(), "-", ""), fixture.membershipID)
	exec(`INSERT INTO public.tenant_role_permissions(tenant_id,role_id,permission_id,scope)
		SELECT $1,$2,id,'tenant' FROM public.tenant_permissions WHERE key IN ('dfir.ioc.manage','dfir.asset.manage')`, fixture.tenantID, fixture.roleID)
	exec(`INSERT INTO public.tenant_membership_role_grants(id,tenant_id,membership_id,role_id,source_id,granted_by_membership_id,grant_reason)
		SELECT $1,$2,$3,$4,id,$5,'Shared content integration' FROM public.tenant_authorization_sources
		WHERE tenant_id=$2 AND key='manual' AND retired_at IS NULL`, mustDFIRSharedAttachmentUUID(t), fixture.tenantID,
		fixture.actor.MembershipID, fixture.roleID, fixture.membershipID)
	teamID, epochID := mustDFIRSharedAttachmentUUID(t), mustDFIRSharedAttachmentUUID(t)
	exec(`INSERT INTO public.operator_teams(id,key,display_name,description,created_by_user_id)
		VALUES($1,$2,'Shared content team','Isolated scope fixture',$3)`, teamID, "shared_content_"+strings.ReplaceAll(teamID.String(), "-", ""), fixture.userID)
	exec(`INSERT INTO public.operator_team_assignment_epochs(id,tenant_id,operator_team_id,assigned_by_membership_id,assignment_reason)
		VALUES($1,$2,$3,$4,'Shared content assignment')`, epochID, fixture.tenantID, teamID, fixture.membershipID)
	exec(`INSERT INTO public.operator_team_roster_entries(id,tenant_id,assignment_epoch_id,membership_id,source_id,granted_by_membership_id,grant_reason)
		SELECT $1,$2,$3,$4,id,$5,'Shared content roster' FROM public.tenant_authorization_sources
		WHERE tenant_id=$2 AND key='manual' AND retired_at IS NULL`, mustDFIRSharedAttachmentUUID(t), fixture.tenantID,
		epochID, fixture.actor.MembershipID, fixture.membershipID)
	exec(`UPDATE public.cases SET assigned_team_id=$1,assigned_team_epoch_id=$2 WHERE tenant_id=$3 AND id=$4`,
		teamID, epochID, fixture.tenantID, fixture.firstCaseID)
	exec(`UPDATE public.alerts SET assigned_team_id=$1,assigned_team_epoch_id=$2 WHERE tenant_id=$3 AND id=$4`,
		teamID, epochID, fixture.tenantID, fixture.alertID)
	exec(`UPDATE public.tenant_authorization_states SET revision=revision+1,updated_at=transaction_timestamp() WHERE tenant_id=$1`, fixture.tenantID)
	exec(`INSERT INTO public.auth_sessions(id,user_id,rotation_family_id,active_tenant_id,token_digest,csrf_secret_digest,
		authentication_method,mfa_satisfied_at,last_seen_at,idle_expires_at,absolute_expires_at,created_at)
		VALUES($1,$2,$3,$4,$5,$6,'totp',date_trunc('milliseconds',transaction_timestamp())-interval '2 minutes',
		date_trunc('milliseconds',transaction_timestamp()),date_trunc('milliseconds',transaction_timestamp())+interval '1 hour',
		date_trunc('milliseconds',transaction_timestamp())+interval '8 hours',date_trunc('milliseconds',transaction_timestamp())-interval '10 minutes')`,
		fixture.actor.SessionID, fixture.actor.UserID, mustDFIRSharedAttachmentUUID(t), fixture.tenantID,
		sharedContentDigest("token:"+fixture.actor.SessionID.String()), sharedContentDigest("csrf:"+fixture.actor.SessionID.String()))
	exec(`INSERT INTO public.dfir_ioc_links(id,tenant_id,ioc_id,alert_id,created_by_membership_id)
		VALUES($1,$2,$3,$4,$5)`, mustDFIRSharedAttachmentUUID(t), fixture.tenantID, fixture.iocID, fixture.alertID, fixture.membershipID)
	exec(`INSERT INTO public.dfir_asset_links(id,tenant_id,asset_id,alert_id,created_by_membership_id)
		VALUES($1,$2,$3,$4,$5)`, mustDFIRSharedAttachmentUUID(t), fixture.tenantID, fixture.assetID, fixture.alertID, fixture.membershipID)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit shared-content synthetic fixture: %v", err)
	}
	return fixture
}

func sharedContentDigest(value string) []byte {
	digest := sha256.Sum256([]byte(value))
	return digest[:]
}

type sharedContentMutation struct {
	base      application.BaseWrite
	marker    string
	indicator kernel.Indicator
	asset     kernel.Asset
	kind      kernel.EntityKind
	version   uint64
}

func sharedContentWrite(t testing.TB, fixture sharedContentFixture, kind, rootKind kernel.EntityKind,
	rootID, resourceID uuid.UUID, version uint64, label string,
) sharedContentMutation {
	t.Helper()
	key := mustDFIRSharedAttachmentUUID(t).String()
	marker := "shared-content-" + label + "-" + key
	operation := "dfir." + string(kind) + ".replace"
	request, err := json.Marshal([]any{fixture.tenantID, rootKind, rootID, resourceID, version, marker})
	if err != nil {
		t.Fatal(err)
	}
	base := application.BaseWrite{Actor: fixture.actor,
		Command: application.CommandBinding{Operation: operation, KeyDigest: sha256.Sum256([]byte(key)), RequestDigest: sha256.Sum256(request)},
		Audit: application.AuditContext{RequestID: mustDFIRSharedAttachmentUUID(t), CorrelationID: mustDFIRSharedAttachmentUUID(t),
			IPAddress: netip.MustParseAddr("192.0.2.41"), UserAgent: "Periapsis shared content integration", AuthenticationMethod: "totp"}}
	if rootKind == kernel.EntityCase {
		base.CaseID = entityID(rootID)
	} else {
		base.AlertID = entityID(rootID)
	}
	mutation := sharedContentMutation{base: base, marker: marker, kind: kind, version: version}
	if kind == kernel.EntityIOC {
		mutation.indicator, err = kernel.NewIndicator(kernel.IndicatorInput{ID: entityID(resourceID), TenantID: entityID(fixture.tenantID),
			Type: kernel.IndicatorDomain, Value: "shared-ioc.example", Description: marker, Source: "integration", Confidence: 80,
			TLP: kernel.TLPAmber, FirstSeen: fixture.observedAt, LastSeen: fixture.observedAt, Malicious: kernel.MaliciousSuspicious})
	} else {
		mutation.asset, err = kernel.NewAsset(kernel.AssetInput{ID: entityID(resourceID), TenantID: entityID(fixture.tenantID),
			AssetType: "endpoint", Criticality: kernel.AssetCriticalityHigh, Environment: "test", ExternalID: "shared-asset",
			Owner: marker, FirstSeen: fixture.observedAt, LastSeen: fixture.observedAt})
	}
	if err != nil {
		t.Fatalf("construct replacement domain resource: %v", err)
	}
	return mutation
}

func (mutation sharedContentMutation) apply(ctx context.Context, repository *DFIRRepository) (string, bool, error) {
	if mutation.kind == kernel.EntityIOC {
		result, err := repository.ReplaceIndicator(ctx, application.IndicatorWrite{BaseWrite: mutation.base,
			Indicator: mutation.indicator, ExpectedVersion: mutation.version})
		return result.Resource.Description(), result.Replayed, err
	}
	result, err := repository.ReplaceAsset(ctx, application.AssetWrite{BaseWrite: mutation.base, Asset: mutation.asset, ExpectedVersion: mutation.version})
	return result.Resource.Owner(), result.Replayed, err
}

func sharedContentVersion(t testing.TB, ctx context.Context, admin *pgxpool.Pool, tenantID uuid.UUID, kind kernel.EntityKind, resourceID uuid.UUID) uint64 {
	t.Helper()
	query := `SELECT version FROM public.dfir_iocs WHERE tenant_id=$1 AND id=$2`
	if kind == kernel.EntityAsset {
		query = `SELECT version FROM public.dfir_assets WHERE tenant_id=$1 AND id=$2`
	}
	var version uint64
	if err := admin.QueryRow(ctx, query, tenantID, resourceID).Scan(&version); err != nil {
		t.Fatalf("load committed resource revision: %v", err)
	}
	return version
}

func sharedContentReceipt(t testing.TB, ctx context.Context, admin *pgxpool.Pool, fixture sharedContentFixture, command application.CommandBinding) []byte {
	t.Helper()
	var receipt []byte
	if err := admin.QueryRow(ctx, `SELECT to_jsonb(result)::text FROM public.dfir_mutation_commands AS command
		JOIN public.dfir_mutation_command_results AS result ON result.tenant_id=command.tenant_id AND result.command_id=command.command_id
		WHERE command.tenant_id=$1 AND command.actor_user_id=$2 AND command.operation=$3 AND command.key_digest=$4`,
		fixture.tenantID, fixture.actor.UserID, command.Operation, command.KeyDigest[:]).Scan(&receipt); err != nil {
		t.Fatalf("load exact immutable replacement receipt: %v", err)
	}
	return receipt
}

func assertSharedContentActivities(t testing.TB, ctx context.Context, admin *pgxpool.Pool, fixture sharedContentFixture, kind kernel.EntityKind, resourceID uuid.UUID, version uint64) {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT 'case',case_id::text,details::text FROM public.dfir_activities
		WHERE tenant_id=$1 AND resource_id=$2 AND action=$3 AND case_id IS NOT NULL AND details->>'resourceVersion'=$4
		UNION ALL SELECT 'alert',alert_id::text,details::text FROM public.ticket_activities
		WHERE tenant_id=$1 AND details->>'resourceId'=$5 AND kind=$3 AND alert_id IS NOT NULL AND details->>'resourceVersion'=$4`,
		fixture.tenantID, resourceID, "dfir."+string(kind)+".replaced", fmt.Sprint(version), resourceID.String())
	if err != nil {
		t.Fatalf("read exact shared activity roots: %v", err)
	}
	defer rows.Close()
	var roots []string
	for rows.Next() {
		var rootKind, rootID, details string
		if err := rows.Scan(&rootKind, &rootID, &details); err != nil {
			t.Fatal(err)
		}
		roots = append(roots, rootKind+":"+rootID)
		for _, hidden := range []string{fixture.firstCaseID.String(), fixture.secondCaseID.String(), fixture.alertID.String(), "shared-content-"} {
			if strings.Contains(details, hidden) {
				t.Fatal("shared activity exposed another root or replacement content")
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := []string{"case:" + fixture.firstCaseID.String(), "case:" + fixture.secondCaseID.String(), "alert:" + fixture.alertID.String()}
	slices.Sort(roots)
	slices.Sort(want)
	if !slices.Equal(roots, want) {
		t.Fatalf("activity roots = %v, want exactly %v", roots, want)
	}
}

func sharedContentSnapshot(t testing.TB, ctx context.Context, admin *pgxpool.Pool, tenantID uuid.UUID) map[string][sha256.Size]byte {
	t.Helper()
	result := make(map[string][sha256.Size]byte)
	for _, table := range []string{"dfir_iocs", "dfir_assets", "dfir_ioc_links", "dfir_asset_links", "dfir_shared_resource_link_events",
		"dfir_mutation_resource_ids", "dfir_mutation_replay_keys", "dfir_mutation_commands", "dfir_mutation_command_results",
		"alert_dfir_resource_commands", "alert_dfir_resource_command_results",
		"dfir_activities", "ticket_activities", "audit_events", "audit_chain_heads", "outbox_events", "cases", "alerts"} {
		var document string
		query := `SELECT coalesce(jsonb_agg(to_jsonb(record) ORDER BY to_jsonb(record)::text),'[]'::jsonb)::text FROM ` +
			(pgx.Identifier{"public", table}).Sanitize() + ` AS record WHERE tenant_id=$1`
		if err := admin.QueryRow(ctx, query, tenantID).Scan(&document); err != nil {
			t.Fatalf("snapshot %s: %v", table, err)
		}
		result[table] = sha256.Sum256([]byte(document))
	}
	return result
}

func assertSharedContentSnapshot(t testing.TB, before, after map[string][sha256.Size]byte) {
	t.Helper()
	if !reflect.DeepEqual(before, after) {
		for table, digest := range before {
			if after[table] != digest {
				t.Errorf("denial/replay changed tenant table %s", table)
			}
		}
		t.FailNow()
	}
}

func setSharedContentScope(t testing.TB, ctx context.Context, admin *pgxpool.Pool, fixture sharedContentFixture, scope string) {
	t.Helper()
	if scope != "tenant" && scope != "operator_team" {
		t.Fatal("invalid synthetic scope mutation")
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE "periapsis_migrator"`); err != nil {
		t.Fatal(err)
	}
	tag, err := tx.Exec(ctx, `UPDATE public.tenant_role_permissions SET scope=$1::public.authorization_scope WHERE tenant_id=$2 AND role_id=$3`,
		scope, fixture.tenantID, fixture.roleID)
	if err != nil || tag.RowsAffected() != 2 {
		t.Fatalf("change exact scoped permissions: rows %d, %v", tag.RowsAffected(), err)
	}
	if _, err := tx.Exec(ctx, `UPDATE public.tenant_authorization_states SET revision=revision+1,updated_at=transaction_timestamp() WHERE tenant_id=$1`, fixture.tenantID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit synthetic scope change: %v", err)
	}
}

func assertSharedContentPathAccess(t testing.TB, ctx context.Context, repository *DFIRRepository, fixture sharedContentFixture,
	capability application.Capability, rootKind kernel.EntityKind, rootID uuid.UUID,
) {
	t.Helper()
	var err error
	if rootKind == kernel.EntityCase {
		_, err = repository.ResolveAccess(ctx, fixture.actor, fixture.tenantID, capability, application.ResourceScope{CaseID: entityID(rootID)})
	} else {
		_, err = repository.ResolveAlertAccess(ctx, fixture.actor, fixture.tenantID, capability, application.AlertResourceScope{AlertID: entityID(rootID)})
	}
	if err != nil {
		t.Fatalf("revocation incorrectly removed the requested path permission: %v", err)
	}
}
