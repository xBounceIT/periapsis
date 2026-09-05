package postgres

import (
	"context"
	"crypto/sha256"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/worker/internal/identitysync"
)

func TestLDAPSyncRepositoryLiveFencedABI(t *testing.T) {
	databaseURL := os.Getenv("PERIAPSIS_TEST_DATABASE_ADMIN_URL")
	if databaseURL == "" {
		t.Skip("PERIAPSIS_TEST_DATABASE_ADMIN_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("create admin pool: %v", err)
	}
	defer admin.Close()
	tenantID, bindingID := beginLiveLDAPSyncRun(t, ctx, admin)

	runtimeConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("parse runtime pool config: %v", err)
	}
	runtimeConfig.AfterConnect = func(ctx context.Context, connection *pgx.Conn) error {
		_, err := connection.Exec(ctx, "set role periapsis_worker")
		return err
	}
	runtime, err := pgxpool.NewWithConfig(ctx, runtimeConfig)
	if err != nil {
		t.Fatalf("create worker pool: %v", err)
	}
	defer runtime.Close()
	repository := NewLDAPSyncRepository(runtime)
	proof := identitysync.ClaimProof{ID: liveV7(t), ReceiptDigest: sha256.Sum256([]byte("opaque-live-receipt"))}
	claim, err := repository.Claim(ctx, proof, 30)
	if err != nil {
		t.Fatalf("Claim() error = %v", err)
	}
	if claim == nil || claim.TenantID != tenantID || claim.BindingID != bindingID ||
		claim.Proof != proof || claim.Status != "enumerating" {
		t.Fatalf("Claim() = %v", claim)
	}
	defer claim.ClearSensitive()

	subjectDigest := [32]byte{0x51}
	observationDigest := [32]byte{0x61}
	observationID := liveV7(t)
	matchedIdentity, err := repository.Stage(ctx, *claim, identitysync.StagedObservation{
		ObservationID: observationID, Ordinal: 1, DigestKeyVersion: 1,
		SubjectDigest: subjectDigest, ObservationDigest: observationDigest,
	})
	if err != nil || matchedIdentity != nil {
		t.Fatalf("Stage() = %v, %v", matchedIdentity, err)
	}
	cursor := [32]byte{0x71}
	enumerationAudit := liveAudit(t)
	enumeration, err := repository.CompleteEnumeration(
		ctx, *claim, claim.Version, true, false, &cursor, nil, enumerationAudit,
	)
	if err != nil || enumeration.Status != "applying" ||
		enumeration.ObservedCount != 1 || !enumeration.AbsenceAllowed {
		t.Fatalf("CompleteEnumeration() = %+v, %v", enumeration, err)
	}
	claim.Version = enumeration.Version
	claim.Status = enumeration.Status
	projection, err := repository.Planning(ctx, *claim, observationID, []identity.SubjectAlias{{
		KeyVersion: 1, Digest: subjectDigest,
	}})
	if err != nil || projection.RunID != claim.RunID || projection.TenantID != tenantID ||
		projection.ObservationID != observationID || projection.Fence != claim.Fence ||
		projection.ProviderID != claim.ProviderID || projection.BindingID != bindingID {
		t.Fatalf("Planning() = %+v, %v", projection, err)
	}
	denial := "no_mapping"
	applyAudit := liveAudit(t)
	applicationID := liveV7(t)
	apply := identitysync.ApplyRequest{
		ObservationID: observationID, ApplicationID: applicationID,
		PlanDigest: observationDigest, Decision: "denied", DenialCategory: &denial,
		MatchedEpochIDs: []uuid.UUID{}, ObservedAt: time.Now().UTC().Truncate(time.Microsecond),
		AuditEventID: applyAudit.EventID, RequestID: applyAudit.RequestID,
		CorrelationID: applyAudit.CorrelationID,
	}
	application, err := repository.Apply(ctx, *claim, apply)
	if err != nil || application.ApplicationID != applicationID ||
		application.Decision != "denied" || application.ExternalIdentityID != nil ||
		application.UserID != nil || application.MembershipID != nil ||
		application.AccessGrantID != nil || application.Replayed {
		t.Fatalf("Apply() = %+v, %v", application, err)
	}
	replayedApplication, err := repository.Apply(ctx, *claim, apply)
	if err != nil || !replayedApplication.Replayed || replayedApplication.ApplicationID != applicationID {
		t.Fatalf("replayed Apply() = %+v, %v", replayedApplication, err)
	}
	failAudit := liveAudit(t)
	terminal, err := repository.Fail(ctx, *claim, claim.Version, "apply_error", failAudit)
	if err != nil || terminal.Status != "failed" || terminal.Replayed {
		t.Fatalf("Fail() = %+v, %v", terminal, err)
	}
	replayedTerminal, err := repository.Fail(ctx, *claim, claim.Version, "apply_error", failAudit)
	if err != nil || replayedTerminal.Status != "failed" || !replayedTerminal.Replayed ||
		replayedTerminal.Version != terminal.Version {
		t.Fatalf("replayed Fail() = %+v, %v", replayedTerminal, err)
	}
}

func beginLiveLDAPSyncRun(
	t *testing.T,
	ctx context.Context,
	admin *pgxpool.Pool,
) (uuid.UUID, uuid.UUID) {
	t.Helper()
	var tenantText, bindingText string
	err := admin.QueryRow(ctx, `
select binding.tenant_id::text, binding.id::text
from public.tenant_auth_provider_bindings as binding
join public.tenant_ldap_provider_configs as configuration
  on configuration.tenant_id = binding.tenant_id
 and configuration.provider_id = binding.provider_id
where binding.enabled and binding.archived_at is null
  and configuration.sync_interval_seconds is not null
  and not exists (
    select 1 from public.tenant_ldap_sync_runs as run
    where run.tenant_id = binding.tenant_id and run.binding_id = binding.id
      and run.status in ('queued', 'enumerating', 'applying')
  )
order by binding.tenant_id, binding.id
limit 1
`).Scan(&tenantText, &bindingText)
	if err != nil {
		t.Fatalf("locate live LDAP binding: %v", err)
	}
	tenantID, err := uuid.Parse(tenantText)
	if err != nil {
		t.Fatalf("parse tenant ID: %v", err)
	}
	bindingID, err := uuid.Parse(bindingText)
	if err != nil {
		t.Fatalf("parse binding ID: %v", err)
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatalf("begin scheduled-run transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, `select set_config('app.tenant_id', $1, true)`, tenantID.String()); err != nil {
		t.Fatalf("install tenant context: %v", err)
	}
	identifiers := []uuid.UUID{liveV7(t), liveV7(t), liveV7(t), liveV7(t)}
	var startedID string
	err = tx.QueryRow(ctx, `
select sync_run_id::text
from app.begin_tenant_ldap_scheduled_sync_run_v1(
  $1::uuid, $2::uuid, 'worker adapter live proof',
  $3::uuid, $4::uuid, $5::uuid, 'Periapsis worker adapter live proof'
)
`, identifiers[0], bindingID, identifiers[1], identifiers[2], identifiers[3]).Scan(&startedID)
	if err != nil {
		t.Fatalf("queue scheduled run: %v", err)
	}
	if startedID != identifiers[0].String() {
		t.Fatalf("started run ID = %s, want %s", startedID, identifiers[0])
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit scheduled run: %v", err)
	}
	return tenantID, bindingID
}

func liveAudit(t *testing.T) identitysync.AuditIDs {
	t.Helper()
	return identitysync.AuditIDs{
		EventID: liveV7(t), RequestID: liveV7(t), CorrelationID: liveV7(t),
	}
}

func liveV7(t *testing.T) uuid.UUID {
	t.Helper()
	value, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7() error = %v", err)
	}
	return value
}
