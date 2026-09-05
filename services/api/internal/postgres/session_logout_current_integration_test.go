package postgres

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/sessionlogout"
)

// The caller owns a fresh, fully migrated clone and disposes of that exact clone.
// This test commits synthetic fixtures, not a login ceremony or upstream SLO.
// Runtime connections install only the API role, never authentication GUCs.
func TestSessionLogoutRepositoryFreshConnectionPostgreSQL(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("PERIAPSIS_SESSION_LOGOUT_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("PERIAPSIS_SESSION_LOGOUT_TEST_DATABASE_URL is not configured")
	}
	expectedDirectory := strings.TrimSpace(os.Getenv("PERIAPSIS_SESSION_LOGOUT_EXPECTED_DATA_DIRECTORY"))
	if expectedDirectory == "" {
		t.Fatal("session logout requires an explicit owned cluster directory pin")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin := sessionLogoutCurrentPool(t, ctx, databaseURL, false)
	defer admin.Close()
	var databaseName, dataDirectory string
	var tenantCount int64
	if err := admin.QueryRow(ctx, `SELECT current_database(), current_setting('data_directory'),
		(SELECT count(*) FROM public.tenants)`).Scan(&databaseName, &dataDirectory, &tenantCount); err != nil {
		t.Fatalf("inspect owned logout clone: %v", err)
	}
	normalize := func(value string) string { return strings.TrimRight(strings.ReplaceAll(value, `\`, "/"), "/") }
	if !sessionLogoutCurrentDatabaseName.MatchString(databaseName) || tenantCount != 0 || normalize(dataDirectory) != normalize(expectedDirectory) {
		t.Fatal("logout clone name, directory, or fresh-tenant guard failed")
	}
	runtime := sessionLogoutCurrentPool(t, ctx, databaseURL, true)
	defer runtime.Close()
	checks := NewHealthChecker(runtime).Check(ctx)
	if len(checks) != 1 || !checks[0].Ready {
		t.Fatal("logout clone does not match the current generated schema/readiness requirements")
	}
	runtimePID := assertSessionLogoutCurrentContext(t, ctx, runtime, 0)
	first := seedAuthorizationIntegrationFixture(t, ctx, admin)
	second := seedAuthorizationIntegrationFixture(t, ctx, admin)
	fixtures := []sessionLogoutCurrentFixture{
		seedSessionLogoutCurrentFixture(t, ctx, admin, first.tenantID, first.adminUserID),
		seedSessionLogoutCurrentFixture(t, ctx, admin, second.tenantID, second.adminUserID),
		seedSessionLogoutCurrentFixture(t, ctx, admin, uuid.Nil, first.adminUserID),
	}
	repository := NewFederatedAuthRepository(runtime)
	for index, fixture := range fixtures {
		name := []string{"first_tenant", "second_tenant_same_pool", "platform_local_same_pool"}[index]
		t.Run(name, func(t *testing.T) {
			credential, err := repository.ResolveSessionForLogout(ctx, fixture.tokenDigest)
			if err != nil || credential != fixture.credential(t) {
				t.Fatalf("resolve the exact stored session credential: %v", err)
			}
			assertSessionLogoutCurrentContext(t, ctx, runtime, runtimePID)
			command := sessionLogoutCurrentCommand(t, credential)
			before := sessionLogoutCurrentSnapshot(t, ctx, admin, fixture.userID)
			for _, mutation := range []struct {
				name   string
				change func(*sessionlogout.LocalRevokeCommand)
			}{
				{"wrong_user", func(value *sessionlogout.LocalRevokeCommand) {
					value.Credential.UserID = sessionLogoutCurrentEntity(t, second.targetUserID)
				}},
				{"wrong_tenant", func(value *sessionlogout.LocalRevokeCommand) {
					value.Credential.TenantID = sessionLogoutCurrentEntity(t, sessionLogoutCurrentUUID(t))
				}},
				{"wrong_digest", func(value *sessionlogout.LocalRevokeCommand) {
					value.Credential.TokenDigest = sessionLogoutCurrentDigest(t)
				}},
			} {
				t.Run(mutation.name, func(t *testing.T) {
					invalid := command
					mutation.change(&invalid)
					result, revokeErr := repository.RevokeLocalSession(ctx, invalid)
					if !errors.Is(revokeErr, sessionlogout.ErrUnavailable) || result != (sessionlogout.LocalRevokeSnapshot{}) {
						t.Fatalf("unattested credential returned a logout result: %v", revokeErr)
					}
					assertSessionLogoutCurrentSnapshot(t, before, sessionLogoutCurrentSnapshot(t, ctx, admin, fixture.userID))
					assertSessionLogoutCurrentContext(t, ctx, runtime, runtimePID)
				})
			}

			result, err := repository.RevokeLocalSession(ctx, command)
			if err != nil || result.Category != sessionlogout.LocalOnly || result.OperationRunID != command.OperationRunID ||
				result.SessionID != credential.SessionID || result.UserID != credential.UserID || result.TenantID != credential.TenantID ||
				result.PreviousVersion != 1 || result.RevokedAt.IsZero() || result.ContinuationID != (identity.EntityID{}) ||
				!result.RequestedAt.Equal(command.RequestedAt) {
				t.Fatalf("fresh API repository logout must revoke locally with an exact receipt: %v", err)
			}
			assertSessionLogoutCurrentContext(t, ctx, runtime, runtimePID)
			assertSessionLogoutCurrentEffects(t, ctx, admin, fixture, command, result)
			after := sessionLogoutCurrentSnapshot(t, ctx, admin, fixture.userID)
			replayed, err := repository.RevokeLocalSession(ctx, command)
			if err != nil || !reflect.DeepEqual(replayed, result) {
				t.Fatalf("exact logout replay changed its original receipt: %v", err)
			}
			assertSessionLogoutCurrentSnapshot(t, after, sessionLogoutCurrentSnapshot(t, ctx, admin, fixture.userID))
			assertSessionLogoutCurrentContext(t, ctx, runtime, runtimePID)
			freshRetry := sessionLogoutCurrentCommand(t, credential)
			repeated, err := repository.RevokeLocalSession(ctx, freshRetry)
			if err != nil || repeated.Category != sessionlogout.LocalOnly || !repeated.RevokedAt.Equal(result.RevokedAt) {
				t.Fatalf("already-revoked session retry changed local revocation: %v", err)
			}
			assertSessionLogoutCurrentSnapshot(t, after, sessionLogoutCurrentSnapshot(t, ctx, admin, fixture.userID))
			assertSessionLogoutCurrentContext(t, ctx, runtime, runtimePID)
		})
	}
	if t.Failed() {
		return
	}
	t.Run("cancelled_audit_rolls_back_revocation_and_context", func(t *testing.T) {
		fixture := fixtures[0]
		credential := fixture.credential(t)
		credential.SessionID = sessionLogoutCurrentEntity(t, fixture.unrelatedID)
		credential.TokenDigest, credential.CSRFDigest = fixture.unrelatedToken, fixture.unrelatedCSRF
		command := sessionLogoutCurrentCommand(t, credential)
		before := sessionLogoutCurrentSnapshot(t, ctx, admin, fixture.userID)
		locker, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = locker.Rollback(ctx) }()
		var lockerPID int32
		if err := locker.QueryRow(ctx, `SELECT pg_backend_pid() FROM public.audit_chain_heads WHERE tenant_id=$1 FOR UPDATE`, fixture.tenantID).Scan(&lockerPID); err != nil {
			t.Fatalf("hold the actual tenant audit head: %v", err)
		}
		requestContext, stopRequest := context.WithTimeout(ctx, 10*time.Second)
		defer stopRequest()
		finished := make(chan error, 1)
		go func() {
			_, revokeErr := repository.RevokeLocalSession(requestContext, command)
			finished <- revokeErr
		}()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		wait := time.NewTimer(5 * time.Second)
		defer wait.Stop()
		blocked := false
		for !blocked {
			select {
			case err := <-finished:
				t.Fatalf("logout returned before reaching its locked audit writer: %v", err)
			case <-wait.C:
				t.Fatal("logout did not reach the locked audit writer within the bounded wait")
			case <-ticker.C:
				if err := admin.QueryRow(ctx, `SELECT $1::integer=ANY(pg_blocking_pids($2::integer))`, lockerPID, runtimePID).Scan(&blocked); err != nil {
					t.Fatal(err)
				}
			}
		}
		stopRequest()
		select {
		case err := <-finished:
			if !errors.Is(err, sessionlogout.ErrUnavailable) {
				t.Fatalf("cancelled audit writer returned %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("cancelled logout did not terminate")
		}
		if err := locker.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		assertSessionLogoutCurrentSnapshot(t, before, sessionLogoutCurrentSnapshot(t, ctx, admin, fixture.userID))
		// pgx may replace a cancelled connection; either returned or new connections
		// must be context-free. Ordinary rejected commands above reuse the same PID.
		runtimePID = assertSessionLogoutCurrentContext(t, ctx, runtime, 0)
		if _, err := repository.RevokeLocalSession(ctx, command); err != nil {
			t.Fatalf("pool reuse after rollback cannot complete the original logout: %v", err)
		}
		assertSessionLogoutCurrentContext(t, ctx, runtime, runtimePID)
	})
}

var sessionLogoutCurrentDatabaseName = regexp.MustCompile(`^periapsis_session_logout_[a-z0-9_]{1,32}$`)

func sessionLogoutCurrentPool(t *testing.T, ctx context.Context, databaseURL string, runtime bool) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal("invalid session logout test database URL")
	}
	if (config.ConnConfig.Host != "127.0.0.1" && config.ConnConfig.Host != "::1" && config.ConnConfig.Host != "localhost") ||
		!sessionLogoutCurrentDatabaseName.MatchString(config.ConnConfig.Database) || len(config.ConnConfig.Fallbacks) > 0 {
		t.Fatal("session logout test requires one explicit loopback disposable database")
	}
	config.MaxConns = 2
	config.ConnConfig.RuntimeParams = map[string]string{"timezone": "UTC", "statement_timeout": "15s"}
	if runtime {
		config.MaxConns = 1
	}
	config.AfterConnect = func(connectContext context.Context, connection *pgx.Conn) error {
		connection.TypeMap().RegisterType(&pgtype.Type{Name: "timestamptz", OID: pgtype.TimestamptzOID, Codec: &pgtype.TimestamptzCodec{ScanLocation: time.UTC}})
		if runtime {
			_, roleErr := connection.Exec(connectContext, `SET ROLE "periapsis_api"`)
			return roleErr
		}
		return nil
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal("cannot create session logout test pool")
	}
	return pool
}

func assertSessionLogoutCurrentContext(t *testing.T, ctx context.Context, pool *pgxpool.Pool, expectedPID int32) int32 {
	t.Helper()
	var role, tenantContext, userContext string
	var pid int32
	var superuser, bypassRLS bool
	err := pool.QueryRow(ctx, `SELECT current_user, pg_backend_pid(),
		coalesce(current_setting('app.tenant_id',true),''), coalesce(current_setting('app.user_id',true),''),
		rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user`).Scan(&role, &pid, &tenantContext, &userContext, &superuser, &bypassRLS)
	if err != nil || role != "periapsis_api" || superuser || bypassRLS || tenantContext != "" || userContext != "" || expectedPID != 0 && pid != expectedPID {
		t.Fatalf("API connection role, GUC isolation, or expected backend reuse failed: %v", err)
	}
	return pid
}

type sessionLogoutCurrentFixture struct {
	tenantID, userID, sessionID, familyID, siblingID, unrelatedID uuid.UUID
	tokenDigest, csrfDigest, unrelatedToken, unrelatedCSRF        [sha256.Size]byte
}

func (fixture sessionLogoutCurrentFixture) credential(t *testing.T) sessionlogout.Credential {
	t.Helper()
	return sessionlogout.Credential{SessionID: sessionLogoutCurrentEntity(t, fixture.sessionID), UserID: sessionLogoutCurrentEntity(t, fixture.userID),
		TenantID: sessionLogoutCurrentEntity(t, fixture.tenantID), TokenDigest: fixture.tokenDigest, CSRFDigest: fixture.csrfDigest}
}

func seedSessionLogoutCurrentFixture(t *testing.T, ctx context.Context, admin *pgxpool.Pool, tenantID, userID uuid.UUID) sessionLogoutCurrentFixture {
	t.Helper()
	fixture := sessionLogoutCurrentFixture{tenantID: tenantID, userID: userID, sessionID: sessionLogoutCurrentUUID(t), familyID: sessionLogoutCurrentUUID(t),
		siblingID: sessionLogoutCurrentUUID(t), unrelatedID: sessionLogoutCurrentUUID(t), tokenDigest: sessionLogoutCurrentDigest(t), csrfDigest: sessionLogoutCurrentDigest(t),
		unrelatedToken: sessionLogoutCurrentDigest(t), unrelatedCSRF: sessionLogoutCurrentDigest(t)}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE "periapsis_migrator"`); err != nil {
		t.Fatal(err)
	}
	var tenantValue any
	if tenantID != uuid.Nil {
		tenantValue = tenantID
	}
	for _, session := range []struct {
		id, family  uuid.UUID
		token, csrf [sha256.Size]byte
	}{
		{fixture.sessionID, fixture.familyID, fixture.tokenDigest, fixture.csrfDigest},
		{fixture.siblingID, fixture.familyID, sessionLogoutCurrentDigest(t), sessionLogoutCurrentDigest(t)},
		{fixture.unrelatedID, sessionLogoutCurrentUUID(t), fixture.unrelatedToken, fixture.unrelatedCSRF},
	} {
		if _, err := tx.Exec(ctx, `INSERT INTO public.auth_sessions
			(id,user_id,rotation_family_id,active_tenant_id,token_digest,csrf_secret_digest,authentication_method,
			 mfa_satisfied_at,last_seen_at,idle_expires_at,absolute_expires_at,created_at)
			VALUES($1,$2,$3,$4,$5,$6,'totp',date_trunc('second',transaction_timestamp())-interval '2 minutes',
			 date_trunc('second',transaction_timestamp()),date_trunc('second',transaction_timestamp())+interval '1 hour',
			 date_trunc('second',transaction_timestamp())+interval '8 hours',date_trunc('second',transaction_timestamp())-interval '10 minutes')`,
			session.id, userID, session.family, tenantValue, session.token[:], session.csrf[:]); err != nil {
			t.Fatalf("insert synthetic logout session: %v", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit synthetic logout sessions: %v", err)
	}
	return fixture
}

func sessionLogoutCurrentCommand(t *testing.T, credential sessionlogout.Credential) sessionlogout.LocalRevokeCommand {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	return sessionlogout.LocalRevokeCommand{
		OperationRunID: sessionLogoutCurrentEntity(t, sessionLogoutCurrentUUID(t)), Credential: credential,
		RequestUpstream: true, RequestDigest: sessionLogoutCurrentDigest(t), RequestedAt: now,
		ContinuationID: sessionLogoutCurrentEntity(t, sessionLogoutCurrentUUID(t)), ContinuationDigest: sessionLogoutCurrentDigest(t), ContinuationExpiresAt: now.Add(time.Minute),
		Audit: sessionlogout.EventContext{RequestID: sessionLogoutCurrentEntity(t, sessionLogoutCurrentUUID(t)), CorrelationID: sessionLogoutCurrentEntity(t, sessionLogoutCurrentUUID(t)),
			RemoteAddress: netip.MustParseAddr("192.0.2.40"), UserAgent: "session-logout-current-integration"},
	}
}

func assertSessionLogoutCurrentEffects(t *testing.T, ctx context.Context, admin *pgxpool.Pool, fixture sessionLogoutCurrentFixture, command sessionlogout.LocalRevokeCommand, result sessionlogout.LocalRevokeSnapshot) {
	t.Helper()
	var revoked, untouched, commands, continuations int
	if err := admin.QueryRow(ctx, `SELECT
		(SELECT count(*)::integer FROM public.auth_sessions WHERE id=ANY($1::uuid[]) AND revoked_at=$2 AND revoke_reason='totp_local_logout'),
		(SELECT count(*)::integer FROM public.auth_sessions WHERE id=$3 AND revoked_at IS NULL),
		(SELECT count(*)::integer FROM public.tenant_oidc_logout_commands WHERE operation_run_id=$4 AND session_id=$5 AND expected_version=1),
		(SELECT count(*)::integer FROM public.session_logout_continuations WHERE operation_run_id=$4)`,
		[]uuid.UUID{fixture.sessionID, fixture.siblingID}, result.RevokedAt, fixture.unrelatedID, uuid.UUID(command.OperationRunID), fixture.sessionID).
		Scan(&revoked, &untouched, &commands, &continuations); err != nil || revoked != 2 || untouched != 1 || commands != 1 || continuations != 0 {
		t.Fatalf("revocation family, immutable command, or local-only continuation effects disagree: %v", err)
	}
	query := `SELECT count(*)::integer,coalesce(bool_and(actor_type='user' AND actor_user_id=$2 AND request_id=$3 AND correlation_id=$4
		AND outcome='success' AND authentication_method='totp' AND metadata=$5::jsonb),false)
		FROM public.audit_events WHERE resource_type='auth_session' AND resource_id=$1 AND action='tenant.identity.session_local_logout' AND tenant_id=$6`
	arguments := []any{fixture.sessionID, fixture.userID, uuid.UUID(command.Audit.RequestID), uuid.UUID(command.Audit.CorrelationID),
		`{"upstream_requested":true,"continuation_created":false,"material_present":false,"material_disclosed":false}`}
	if fixture.tenantID == uuid.Nil {
		query = `SELECT count(*)::integer,coalesce(bool_and(actor_type='user' AND actor_user_id=$2 AND request_id=$3 AND correlation_id=$4
			AND outcome='success' AND authentication_method='totp' AND metadata=$5::jsonb),false)
			FROM public.platform_audit_events WHERE resource_type='auth_session' AND resource_id=$1 AND action='platform.identity.session_local_logout'`
	} else {
		arguments = append(arguments, fixture.tenantID)
	}
	var auditCount int
	var exactAudit bool
	if err := admin.QueryRow(ctx, query, arguments...).Scan(&auditCount, &exactAudit); err != nil || auditCount != 1 || !exactAudit {
		t.Fatalf("logout did not commit exactly one redacted audit for the authenticated actor: %v", err)
	}
}

func sessionLogoutCurrentSnapshot(t *testing.T, ctx context.Context, admin *pgxpool.Pool, userID uuid.UUID) []byte {
	t.Helper()
	var snapshot []byte
	if err := admin.QueryRow(ctx, `SELECT jsonb_build_object(
		'sessions',(SELECT jsonb_agg(jsonb_build_object('id',id,'revokedAt',revoked_at,'reason',revoke_reason) ORDER BY id) FROM public.auth_sessions WHERE user_id=$1),
		'commands',(SELECT jsonb_agg(to_jsonb(command)-'request_digest' ORDER BY operation_run_id) FROM public.tenant_oidc_logout_commands command WHERE session_id IN (SELECT id FROM public.auth_sessions WHERE user_id=$1)),
		'continuations',(SELECT jsonb_agg(to_jsonb(continuation)-'token_digest' ORDER BY id) FROM public.session_logout_continuations continuation WHERE user_id=$1),
		'audit',(SELECT jsonb_agg(to_jsonb(audit) ORDER BY id) FROM public.audit_events audit WHERE actor_user_id=$1 AND action='tenant.identity.session_local_logout'),
		'platformAudit',(SELECT jsonb_agg(to_jsonb(audit) ORDER BY id) FROM public.platform_audit_events audit WHERE actor_user_id=$1 AND action='platform.identity.session_local_logout'))`, userID).Scan(&snapshot); err != nil {
		t.Fatalf("read bounded synthetic logout effects: %v", err)
	}
	return snapshot
}

func assertSessionLogoutCurrentSnapshot(t *testing.T, before, after []byte) {
	t.Helper()
	var first, second any
	if json.Unmarshal(before, &first) != nil || json.Unmarshal(after, &second) != nil || !reflect.DeepEqual(first, second) {
		t.Fatal("rejected, replayed, or cancelled logout changed committed effects")
	}
}

func sessionLogoutCurrentUUID(t *testing.T) uuid.UUID {
	t.Helper()
	value, err := uuid.NewV7()
	if err != nil {
		t.Fatal("cannot create synthetic logout identity")
	}
	return value
}

func sessionLogoutCurrentEntity(t *testing.T, value uuid.UUID) identity.EntityID {
	t.Helper()
	if value == uuid.Nil {
		return identity.EntityID{}
	}
	if value.Version() != 7 || value.Variant() != uuid.RFC4122 {
		t.Fatal("invalid synthetic logout identity")
	}
	return identity.EntityID(value)
}

func sessionLogoutCurrentDigest(t *testing.T) [sha256.Size]byte {
	t.Helper()
	var value [sha256.Size]byte
	if _, err := rand.Read(value[:]); err != nil || bytes.Equal(value[:], make([]byte, sha256.Size)) {
		t.Fatal("cannot create synthetic session digest")
	}
	return value
}
