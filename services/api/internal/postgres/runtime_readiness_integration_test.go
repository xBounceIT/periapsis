package postgres

import (
	"context"
	"crypto/rand"
	"os"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

func TestRuntimeRepositoryReadinessPostgreSQL(t *testing.T) {
	databaseURL := os.Getenv("PERIAPSIS_READINESS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("PERIAPSIS_READINESS_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pool := authorizationIntegrationPool(t, ctx, databaseURL, "periapsis_api")
	defer pool.Close()
	federated := NewFederatedAuthRepository(pool)
	local, err := NewPlatformLocalAccountRepository(pool)
	if err != nil {
		t.Fatal(err)
	}
	saml, err := NewPlatformSAMLRepository(pool, "https://app.example.test")
	if err != nil {
		t.Fatal(err)
	}
	repositories := map[string]func(context.Context) error{
		"federated":         federated.CheckFederatedAuthenticationReadiness,
		"oidc":              federated.ReadyDirectPlatformOIDC,
		"saml":              saml.ReadyDirectPlatformSAML,
		"local accounts":    local.ReadyPlatformLocalAccounts,
		"ticket operations": NewTicketingRepository(pool).ReadyTicketOperations,
	}
	for name, ready := range repositories {
		t.Run(name, func(t *testing.T) {
			if err := ready(ctx); err != nil {
				t.Fatalf("current repository readiness failed: %v", err)
			}
		})
	}
	t.Run("aggregate probe reuses verified results", func(t *testing.T) {
		probe, finish := context.WithTimeout(ctx, 10*time.Second)
		defer finish()
		probe, checks := NewHealthChecker(pool).CheckWithContext(probe)
		if len(checks) != 1 || !checks[0].Ready || !runtimeVerifiedInProbe(probe, pool) {
			t.Fatal("full schema attestation did not establish probe evidence")
		}
		acquisitions := pool.Stat().AcquireCount()
		for name, ready := range repositories {
			if err := ready(probe); err != nil {
				t.Fatalf("%s failed inside verified probe: %v", name, err)
			}
		}
		if pool.Stat().AcquireCount() != acquisitions {
			t.Fatal("repository repeated database work already covered by the aggregate")
		}
	})
	var retiredCallable bool
	if err := pool.QueryRow(ctx, `SELECT has_function_privilege(current_user,
		'app.federated_authentication_schema_readiness_v51()', 'EXECUTE')`).Scan(&retiredCallable); err != nil {
		t.Fatal("cannot check retired readiness privileges")
	}
	if retiredCallable {
		t.Fatal("the retired readiness ABI must remain inaccessible")
	}
	t.Run("identity verification tolerates a short session write lock", func(t *testing.T) {
		admin := authorizationIntegrationPool(t, ctx, databaseURL, "")
		defer admin.Close()
		writer, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = writer.Rollback(ctx) }()
		if _, err := writer.Exec(ctx, "LOCK TABLE public.auth_sessions IN ROW EXCLUSIVE MODE"); err != nil {
			t.Fatal(err)
		}
		reader, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// All keyring bindings created by the proof roll back with this transaction.
		defer func() { _ = reader.Rollback(ctx) }()
		var root [32]byte
		if _, err := rand.Read(root[:]); err != nil {
			t.Fatal(err)
		}
		defer clear(root[:])
		keyring, err := identity.NewKeyring(1, map[int16][]byte{1: root[:]})
		if err != nil {
			t.Fatal(err)
		}
		evidence, err := keyring.ReadinessEvidence()
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			for i := range evidence.Versions {
				clear(evidence.Versions[i].Verifier[:])
			}
		}()
		databaseVerifier := NewIdentityKeyringEvidenceVerifier(reader)
		verified, err := databaseVerifier.VerifyIdentityKeyring(ctx, evidence)
		if err != nil || verified {
			t.Fatalf("NOWAIT verification must deny the held write lock: verified=%t error=%v", verified, err)
		}
		verifier, err := identityprovider.NewKeyringReadinessVerifier(databaseVerifier, keyring)
		if err != nil {
			t.Fatal(err)
		}
		released := make(chan error, 1)
		time.AfterFunc(75*time.Millisecond, func() { released <- writer.Rollback(ctx) })
		verifyErr := verifier.Verify(ctx)
		if err := <-released; err != nil {
			t.Fatal(err)
		}
		if verifyErr != nil {
			t.Fatalf("verification did not recover after the session writer released: %v", verifyErr)
		}
	})
}
