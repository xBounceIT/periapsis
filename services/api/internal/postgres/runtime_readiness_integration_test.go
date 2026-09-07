package postgres

import (
	"context"
	"os"
	"testing"
	"time"
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
	for name, ready := range map[string]func(context.Context) error{
		"federated":         federated.CheckFederatedAuthenticationReadiness,
		"oidc":              federated.ReadyDirectPlatformOIDC,
		"saml":              saml.ReadyDirectPlatformSAML,
		"local accounts":    local.ReadyPlatformLocalAccounts,
		"ticket operations": NewTicketingRepository(pool).ReadyTicketOperations,
	} {
		t.Run(name, func(t *testing.T) {
			if err := ready(ctx); err != nil {
				t.Fatalf("current repository readiness failed: %v", err)
			}
		})
	}
	var retiredCallable bool
	if err := pool.QueryRow(ctx, `SELECT has_function_privilege(current_user,
		'app.federated_authentication_schema_readiness_v51()', 'EXECUTE')`).Scan(&retiredCallable); err != nil {
		t.Fatal("cannot check retired readiness privileges")
	}
	if retiredCallable {
		t.Fatal("the retired readiness ABI must remain inaccessible")
	}
}
