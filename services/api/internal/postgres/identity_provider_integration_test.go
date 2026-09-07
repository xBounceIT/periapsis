package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

const identityProviderIntegrationDatabaseURL = "PERIAPSIS_IDENTITY_PROVIDER_TEST_DATABASE_URL"

type identityProviderIntegrationFixture struct {
	tenantID, foreignTenantID       uuid.UUID
	adminUserID, foreignAdminUserID uuid.UUID
	deniedUserID                    uuid.UUID
	adminMembershipID               uuid.UUID
	foreignAdminMembershipID        uuid.UUID
	deniedMembershipID              uuid.UUID
}

func TestIdentityProviderRepositoryAndServicePostgreSQL(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv(identityProviderIntegrationDatabaseURL))
	if databaseURL == "" {
		t.Skipf("%s is not set", identityProviderIntegrationDatabaseURL)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	adminPool := identityProviderIntegrationPool(t, ctx, databaseURL, "")
	defer adminPool.Close()
	fixture := seedIdentityProviderIntegrationFixture(t, ctx, adminPool)

	runtimePool := identityProviderIntegrationPool(t, ctx, databaseURL, "periapsis_api")
	defer runtimePool.Close()
	var runtimeRole string
	if err := runtimePool.QueryRow(ctx, `SELECT current_user`).Scan(&runtimeRole); err != nil || runtimeRole != "periapsis_api" {
		t.Fatalf("runtime database role = %q, error = %v", runtimeRole, err)
	}

	keySource := []byte("0123456789abcdef0123456789abcdef")
	keyring, err := identity.NewKeyring(1, map[int16][]byte{1: keySource})
	clear(keySource)
	if err != nil {
		t.Fatalf("create identity keyring: %v", err)
	}
	var keyVersionExisted bool
	if err := adminPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.identity_keyring_versions WHERE key_version = 1)`).Scan(&keyVersionExisted); err != nil {
		t.Fatalf("inspect identity key version fixture ownership: %v", err)
	}
	readiness, err := identityprovider.NewKeyringReadinessVerifier(NewIdentityKeyringEvidenceVerifier(runtimePool), keyring)
	if err != nil {
		t.Fatalf("construct identity keyring readiness: %v", err)
	}
	if err := readiness.Verify(ctx); err != nil {
		t.Fatalf("bind identity keyring readiness: %v", err)
	}
	if !keyVersionExisted {
		t.Cleanup(func() { cleanupIdentityProviderIntegrationKey(t, databaseURL, keyring) })
	}
	t.Cleanup(func() { cleanupIdentityProviderIntegrationFixture(t, databaseURL, fixture) })

	validator, err := ldapclient.New(ldapclient.Options{
		Resolver: net.DefaultResolver, Dialer: &net.Dialer{}, MaxConcurrent: 8,
	})
	if err != nil {
		t.Fatalf("create LDAP validation policy: %v", err)
	}
	diagnostics := &identityProviderIntegrationDiagnostics{
		t: t, adminPool: adminPool, tenantID: fixture.tenantID, validator: validator,
		expectedSecret: "second-integration-secret",
	}
	repository := NewIdentityProviderRepository(runtimePool)
	service, err := identityprovider.NewService(repository, keyring, diagnostics)
	if err != nil {
		t.Fatalf("create identity-provider service: %v", err)
	}
	adminActor := identityProviderIntegrationActor(t, fixture.tenantID, fixture.adminUserID)
	foreignAdminActor := identityProviderIntegrationActor(t, fixture.foreignTenantID, fixture.foreignAdminUserID)
	deniedActor := identityProviderIntegrationActor(t, fixture.tenantID, fixture.deniedUserID)
	configuration, endpoints := identityProviderIntegrationDocuments()
	// The current API must persist the policy consumed by JIT and reconciliation,
	// rather than the disabled-only policy accepted by the historical foundation ABI.
	configuration.JITMode = identityprovider.JITModeCreate
	configuration.NoMatchPolicy = identityprovider.NoMatchPolicyProviderAccessOnly
	configuration.DeprovisionMode = identityprovider.DeprovisionModeGrace
	configuration.DeprovisionGraceSeconds = 60
	syncInterval := 300
	configuration.SyncIntervalSeconds = &syncInterval

	createAudit := identityProviderIntegrationAudit(t)
	createInput := identityprovider.CreateInput{
		Key: "integration_ldap", DisplayName: "Integration LDAP", Description: "Live PostgreSQL vertical slice.",
		Configuration: configuration, Endpoints: endpoints,
		IdempotencyKey: "identity-provider-integration-create", Audit: createAudit,
	}
	created, err := service.Create(ctx, adminActor, fixture.tenantID, createInput)
	if err != nil || created.Version != 1 || created.Replayed {
		t.Fatalf("create provider = %+v, %v", created, err)
	}
	configured, err := service.Get(ctx, adminActor, fixture.tenantID, created.ProviderID)
	if err != nil || configured.Configuration.JITMode != configuration.JITMode ||
		configured.Configuration.NoMatchPolicy != configuration.NoMatchPolicy ||
		configured.Configuration.DeprovisionMode != configuration.DeprovisionMode ||
		configured.Configuration.DeprovisionGraceSeconds != 60 ||
		configured.Configuration.SyncIntervalSeconds == nil || *configured.Configuration.SyncIntervalSeconds != syncInterval {
		t.Fatalf("read created LDAP runtime policy: %v", err)
	}
	replayed, err := service.Create(ctx, adminActor, fixture.tenantID, createInput)
	if err != nil || !replayed.Replayed || replayed.ProviderID != created.ProviderID || replayed.Version != 1 {
		t.Fatalf("exact create replay = %+v, %v", replayed, err)
	}
	driftedCreate := createInput
	driftedCreate.DisplayName = "Payload drift"
	if _, err := service.Create(ctx, adminActor, fixture.tenantID, driftedCreate); !errors.Is(err, identityprovider.ErrConflict) {
		t.Fatalf("payload-bound replay error = %v, want conflict", err)
	}
	assertIdentityProviderIntegrationAudit(t, ctx, adminPool, fixture.tenantID, created.ProviderID, createAudit, "tenant.identity_provider.created")

	page, err := service.List(ctx, adminActor, fixture.tenantID, identityprovider.ListInput{})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != created.ProviderID || page.Items[0].BindSecretConfigured {
		t.Fatalf("initial provider page = %+v, %v", page, err)
	}
	if _, err := service.List(ctx, deniedActor, fixture.tenantID, identityprovider.ListInput{}); !errors.Is(err, identityprovider.ErrForbidden) {
		t.Fatalf("permission-denied service list error = %v", err)
	}
	if _, err := repository.List(ctx, identityprovider.ListParams{
		HumanParams: identityprovider.HumanParams{Actor: deniedActor, MembershipID: fixture.deniedMembershipID, TenantID: fixture.tenantID},
		Limit:       1,
	}); !errors.Is(err, identityprovider.ErrForbidden) {
		t.Fatalf("permission-denied database list error = %v", err)
	}
	if _, err := repository.Get(ctx, identityprovider.GetParams{
		HumanParams: identityprovider.HumanParams{Actor: foreignAdminActor, MembershipID: fixture.foreignAdminMembershipID, TenantID: fixture.foreignTenantID},
		ProviderID:  created.ProviderID,
	}); !errors.Is(err, identityprovider.ErrNotFound) {
		t.Fatalf("cross-tenant database get error = %v", err)
	}
	if _, err := service.Get(ctx, adminActor, fixture.foreignTenantID, created.ProviderID); !errors.Is(err, identityprovider.ErrForbidden) {
		t.Fatalf("cross-tenant service get error = %v", err)
	}
	for _, test := range []struct {
		name   string
		human  identityprovider.HumanParams
		change func(*identityprovider.Configuration)
		want   error
	}{
		{name: "permission denied", human: identityprovider.HumanParams{Actor: deniedActor, MembershipID: fixture.deniedMembershipID, TenantID: fixture.tenantID}, want: identityprovider.ErrForbidden},
		{name: "foreign tenant", human: identityprovider.HumanParams{Actor: foreignAdminActor, MembershipID: fixture.foreignAdminMembershipID, TenantID: fixture.foreignTenantID}, want: identityprovider.ErrNotFound},
		{name: "certificate verification required", change: func(config *identityprovider.Configuration) { config.VerifyCertificate = false }, want: identityprovider.ErrInvalidInput},
		{name: "grace period constrained", change: func(config *identityprovider.Configuration) { config.DeprovisionGraceSeconds = -1 }, want: identityprovider.ErrConflict},
	} {
		t.Run("V2 database rejects "+test.name, func(t *testing.T) {
			human := test.human
			if human.TenantID == uuid.Nil {
				human = identityprovider.HumanParams{Actor: adminActor, MembershipID: fixture.adminMembershipID, TenantID: fixture.tenantID}
			}
			attempt := configuration
			if test.change != nil {
				test.change(&attempt)
			}
			if _, err := repository.Update(ctx, identityprovider.UpdateParams{
				HumanParams: human, ProviderID: created.ProviderID, ExpectedVersion: 1,
				Key: createInput.Key, DisplayName: createInput.DisplayName, Description: createInput.Description,
				Configuration: attempt, Endpoints: endpoints, Audit: identityProviderIntegrationAudit(t), OccurredAt: time.Now().UTC().Truncate(time.Microsecond),
			}); !errors.Is(err, test.want) {
				t.Fatalf("V2 database rejection = %v, want %v", err, test.want)
			}
		})
	}
	unchanged, err := service.Get(ctx, adminActor, fixture.tenantID, created.ProviderID)
	if err != nil || unchanged.Version != 1 || !unchanged.Configuration.VerifyCertificate || unchanged.Configuration.DeprovisionGraceSeconds != 60 {
		t.Fatalf("rejected V2 mutations changed the provider: %v", err)
	}

	versionTag := identityProviderIntegrationETag(t, 1)
	if _, err := service.Update(ctx, adminActor, fixture.tenantID, created.ProviderID, identityprovider.UpdateInput{
		Key: createInput.Key, DisplayName: createInput.DisplayName, Description: createInput.Description,
		Enabled: true, Configuration: configuration, Endpoints: endpoints,
		ExpectedEntityTag: &versionTag, Audit: identityProviderIntegrationAudit(t),
	}); !errors.Is(err, identityprovider.ErrConflict) {
		t.Fatalf("enable without bind secret error = %v, want conflict", err)
	}
	updateAudit := identityProviderIntegrationAudit(t)
	configuration.JITMode = identityprovider.JITModeExistingIdentity
	configuration.NoMatchPolicy = identityprovider.NoMatchPolicyDeny
	configuration.DeprovisionMode = identityprovider.DeprovisionModeImmediate
	configuration.DeprovisionGraceSeconds = 0
	configuration.SyncIntervalSeconds = nil
	updatedVersion, err := service.Update(ctx, adminActor, fixture.tenantID, created.ProviderID, identityprovider.UpdateInput{
		Key: createInput.Key, DisplayName: "Integration LDAP updated", Description: createInput.Description,
		Configuration: configuration, Endpoints: endpoints, ExpectedEntityTag: &versionTag, Audit: updateAudit,
	})
	if err != nil || updatedVersion != 2 {
		t.Fatalf("update provider version = %d, error = %v", updatedVersion, err)
	}
	configured, err = service.Get(ctx, adminActor, fixture.tenantID, created.ProviderID)
	if err != nil || configured.Configuration.JITMode != configuration.JITMode ||
		configured.Configuration.NoMatchPolicy != configuration.NoMatchPolicy ||
		configured.Configuration.DeprovisionMode != configuration.DeprovisionMode ||
		configured.Configuration.DeprovisionGraceSeconds != 0 || configured.Configuration.SyncIntervalSeconds != nil {
		t.Fatalf("read updated LDAP runtime policy: %v", err)
	}
	if _, err := service.Update(ctx, adminActor, fixture.tenantID, created.ProviderID, identityprovider.UpdateInput{
		Key: createInput.Key, DisplayName: "Stale update", Description: createInput.Description,
		Configuration: configuration, Endpoints: endpoints, ExpectedEntityTag: &versionTag,
		Audit: identityProviderIntegrationAudit(t),
	}); !errors.Is(err, identityprovider.ErrPreconditionFailed) {
		t.Fatalf("stale If-Match error = %v", err)
	}
	assertIdentityProviderIntegrationAudit(t, ctx, adminPool, fixture.tenantID, created.ProviderID, updateAudit, "tenant.identity_provider.updated")

	firstSecret := []byte("first-integration-secret")
	versionTag = identityProviderIntegrationETag(t, 2)
	firstSecretAudit := identityProviderIntegrationAudit(t)
	updatedVersion, err = service.RotateBindSecret(ctx, adminActor, fixture.tenantID, created.ProviderID, identityprovider.RotateBindSecretInput{
		Secret: firstSecret, ExpectedEntityTag: &versionTag, Audit: firstSecretAudit,
	})
	if err != nil || updatedVersion != 3 || !identityProviderIntegrationAllZero(firstSecret) {
		t.Fatalf("first secret rotation = version %d, error %v, plaintext cleared %t", updatedVersion, err, identityProviderIntegrationAllZero(firstSecret))
	}
	firstSecretID, firstCiphertext := identityProviderIntegrationSecretRow(t, ctx, adminPool, fixture.tenantID, created.ProviderID)
	if bytes.Contains(firstCiphertext, []byte("first-integration-secret")) {
		t.Fatal("plaintext appeared in persisted ciphertext")
	}

	secondSecret := []byte(diagnostics.expectedSecret)
	versionTag = identityProviderIntegrationETag(t, 3)
	secondSecretAudit := identityProviderIntegrationAudit(t)
	updatedVersion, err = service.RotateBindSecret(ctx, adminActor, fixture.tenantID, created.ProviderID, identityprovider.RotateBindSecretInput{
		Secret: secondSecret, ExpectedEntityTag: &versionTag, Audit: secondSecretAudit,
	})
	if err != nil || updatedVersion != 4 || !identityProviderIntegrationAllZero(secondSecret) {
		t.Fatalf("second secret rotation = version %d, error %v, plaintext cleared %t", updatedVersion, err, identityProviderIntegrationAllZero(secondSecret))
	}
	secondSecretID, secondCiphertext := identityProviderIntegrationSecretRow(t, ctx, adminPool, fixture.tenantID, created.ProviderID)
	if secondSecretID != firstSecretID || bytes.Equal(secondCiphertext, firstCiphertext) || bytes.Contains(secondCiphertext, []byte(diagnostics.expectedSecret)) {
		t.Fatalf("secret identity/ciphertext rotation invariant failed: ids %s/%s", firstSecretID, secondSecretID)
	}
	assertIdentityProviderIntegrationNoPlaintext(t, ctx, adminPool, fixture.tenantID, diagnostics.expectedSecret)
	assertIdentityProviderIntegrationAudit(t, ctx, adminPool, fixture.tenantID, created.ProviderID, secondSecretAudit, "tenant.identity_provider.bind_secret_rotated")

	versionTag = identityProviderIntegrationETag(t, 4)
	updatedVersion, err = service.Update(ctx, adminActor, fixture.tenantID, created.ProviderID, identityprovider.UpdateInput{
		Key: createInput.Key, DisplayName: "Integration LDAP updated", Description: createInput.Description,
		Enabled: true, Configuration: configuration, Endpoints: endpoints,
		ExpectedEntityTag: &versionTag, Audit: identityProviderIntegrationAudit(t),
	})
	if err != nil || updatedVersion != 5 {
		t.Fatalf("enable ready provider = version %d, error %v", updatedVersion, err)
	}

	connectionResult, err := service.TestConnection(ctx, adminActor, fixture.tenantID, created.ProviderID, identityprovider.TestInput{Audit: identityProviderIntegrationAudit(t)})
	if err != nil || connectionResult.Outcome != identityprovider.TestOutcomeSuccess || connectionResult.Category != identityprovider.TestCategorySuccess {
		t.Fatalf("connection diagnostic = %+v, %v", connectionResult, err)
	}
	bindResult, err := service.TestBind(ctx, adminActor, fixture.tenantID, created.ProviderID, identityprovider.TestInput{Audit: identityProviderIntegrationAudit(t)})
	if err != nil || bindResult.Outcome != identityprovider.TestOutcomeSuccess || !diagnostics.bindSecretMatched {
		t.Fatalf("bind diagnostic = %+v, error %v, secret matched %t", bindResult, err, diagnostics.bindSecretMatched)
	}
	assertIdentityProviderIntegrationCompletedRun(t, ctx, adminPool, fixture.tenantID, connectionResult.TestRunID, "success")
	assertIdentityProviderIntegrationCompletedRun(t, ctx, adminPool, fixture.tenantID, bindResult.TestRunID, "success")

	cancelContext, cancelDiagnostic := context.WithCancel(ctx)
	diagnostics.cancelOnConnectionCall = diagnostics.connectionCalls + 1
	diagnostics.cancel = cancelDiagnostic
	cancelAudit := identityProviderIntegrationAudit(t)
	if _, err := service.TestConnection(cancelContext, adminActor, fixture.tenantID, created.ProviderID, identityprovider.TestInput{Audit: cancelAudit}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled diagnostic error = %v", err)
	}
	var cancelledRunID uuid.UUID
	if err := adminPool.QueryRow(ctx, `
		SELECT id FROM public.tenant_ldap_provider_test_runs
		WHERE tenant_id = $1 AND provider_id = $2 AND request_id = $3`,
		fixture.tenantID, created.ProviderID, cancelAudit.RequestID,
	).Scan(&cancelledRunID); err != nil {
		t.Fatalf("load cancelled diagnostic run: %v", err)
	}
	assertIdentityProviderIntegrationCompletedRun(t, ctx, adminPool, fixture.tenantID, cancelledRunID, "cancelled")
	diagnostics.cancel = nil
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := service.TestConnection(ctx, adminActor, fixture.tenantID, created.ProviderID, identityprovider.TestInput{Audit: identityProviderIntegrationAudit(t)}); err != nil {
			t.Fatalf("diagnostic within actor rate cap %d: %v", attempt, err)
		}
	}
	if _, err := service.TestConnection(ctx, adminActor, fixture.tenantID, created.ProviderID, identityprovider.TestInput{Audit: identityProviderIntegrationAudit(t)}); !errors.Is(err, identityprovider.ErrRateLimited) {
		t.Fatalf("diagnostic actor rate cap error = %v", err)
	}

	versionTag = identityProviderIntegrationETag(t, 5)
	updatedVersion, err = service.Update(ctx, adminActor, fixture.tenantID, created.ProviderID, identityprovider.UpdateInput{
		Key: createInput.Key, DisplayName: "Integration LDAP updated", Description: createInput.Description,
		Configuration: configuration, Endpoints: endpoints, ExpectedEntityTag: &versionTag,
		Audit: identityProviderIntegrationAudit(t),
	})
	if err != nil || updatedVersion != 6 {
		t.Fatalf("disable provider = version %d, error %v", updatedVersion, err)
	}
	versionTag = identityProviderIntegrationETag(t, 6)
	clearAudit := identityProviderIntegrationAudit(t)
	updatedVersion, err = service.ClearBindSecret(ctx, adminActor, fixture.tenantID, created.ProviderID, identityprovider.ClearBindSecretInput{
		Reason: "Credential retired after integration test.", ExpectedEntityTag: &versionTag, Audit: clearAudit,
	})
	if err != nil || updatedVersion != 7 {
		t.Fatalf("clear bind secret = version %d, error %v", updatedVersion, err)
	}
	var remainingSecrets int
	if err := adminPool.QueryRow(ctx, `SELECT count(*) FROM public.tenant_ldap_provider_secrets WHERE tenant_id = $1 AND provider_id = $2`, fixture.tenantID, created.ProviderID).Scan(&remainingSecrets); err != nil || remainingSecrets != 0 {
		t.Fatalf("remaining bind secrets = %d, error %v", remainingSecrets, err)
	}
	assertIdentityProviderIntegrationAudit(t, ctx, adminPool, fixture.tenantID, created.ProviderID, clearAudit, "tenant.identity_provider.bind_secret_cleared")

	versionTag = identityProviderIntegrationETag(t, 7)
	archiveAudit := identityProviderIntegrationAudit(t)
	updatedVersion, err = service.Archive(ctx, adminActor, fixture.tenantID, created.ProviderID, identityprovider.ArchiveInput{
		Reason: "Foundation integration complete.", ExpectedEntityTag: &versionTag, Audit: archiveAudit,
	})
	if err != nil || updatedVersion != 8 {
		t.Fatalf("archive provider = version %d, error %v", updatedVersion, err)
	}
	archived, err := service.Get(ctx, adminActor, fixture.tenantID, created.ProviderID)
	if err != nil || archived.ArchivedAt == nil || archived.ArchiveReason == nil || archived.Enabled || archived.Version != 8 {
		t.Fatalf("archived provider = %+v, %v", archived, err)
	}
	archivedPage, err := service.List(ctx, adminActor, fixture.tenantID, identityprovider.ListInput{IncludeArchived: true})
	if err != nil || len(archivedPage.Items) != 1 || archivedPage.Items[0].ArchivedAt == nil {
		t.Fatalf("archived provider page = %+v, %v", archivedPage, err)
	}
	assertIdentityProviderIntegrationAudit(t, ctx, adminPool, fixture.tenantID, created.ProviderID, archiveAudit, "tenant.identity_provider.archived")
}

type identityProviderIntegrationDiagnostics struct {
	t                      *testing.T
	adminPool              *pgxpool.Pool
	tenantID               uuid.UUID
	validator              *ldapclient.Client
	expectedSecret         string
	bindSecretMatched      bool
	connectionCalls        int
	cancelOnConnectionCall int
	cancel                 context.CancelFunc
}

func (d *identityProviderIntegrationDiagnostics) ValidateConfiguration(configuration ldapclient.Configuration) error {
	return d.validator.ValidateConfiguration(configuration)
}

func (d *identityProviderIntegrationDiagnostics) TestConnection(ctx context.Context, configuration ldapclient.Configuration) (ldapclient.Diagnostic, error) {
	d.connectionCalls++
	d.assertCommittedBegin(ctx)
	if d.cancel != nil && d.connectionCalls == d.cancelOnConnectionCall {
		d.cancel()
		return ldapclient.Diagnostic{Outcome: ldapclient.OutcomeFailure, Category: ldapclient.CategoryCancelled, Duration: time.Millisecond}, nil
	}
	return ldapclient.Diagnostic{Outcome: ldapclient.OutcomeSuccess, Category: ldapclient.CategorySuccess, EndpointPriority: configuration.Endpoints[0].Priority, Duration: time.Millisecond}, nil
}

func (d *identityProviderIntegrationDiagnostics) TestBind(ctx context.Context, configuration ldapclient.Configuration, _ string, secret []byte) (ldapclient.Diagnostic, error) {
	defer clear(secret)
	d.assertCommittedBegin(ctx)
	d.bindSecretMatched = string(secret) == d.expectedSecret
	return ldapclient.Diagnostic{Outcome: ldapclient.OutcomeSuccess, Category: ldapclient.CategorySuccess, EndpointPriority: configuration.Endpoints[0].Priority, Duration: 2 * time.Millisecond}, nil
}

func (d *identityProviderIntegrationDiagnostics) assertCommittedBegin(ctx context.Context) {
	d.t.Helper()
	var running int
	if err := d.adminPool.QueryRow(ctx, `
		SELECT count(*) FROM public.tenant_ldap_provider_test_runs
		WHERE tenant_id = $1 AND status = 'started'`, d.tenantID,
	).Scan(&running); err != nil || running != 1 {
		d.t.Fatalf("diagnostic observed committed begin rows = %d, error = %v", running, err)
	}
}

func identityProviderIntegrationPool(t *testing.T, ctx context.Context, databaseURL, role string) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("parse identity-provider integration database URL: %v", err)
	}
	config.MaxConns = 4
	config.ConnConfig.RuntimeParams["statement_timeout"] = "20s"
	if role != "" {
		config.AfterConnect = func(connectContext context.Context, connection *pgx.Conn) error {
			_, connectErr := connection.Exec(connectContext, fmt.Sprintf(`SET ROLE %s`, pgx.Identifier{role}.Sanitize()))
			return connectErr
		}
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("create identity-provider integration pool: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("connect identity-provider integration database: %v", err)
	}
	return pool
}

func seedIdentityProviderIntegrationFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool) identityProviderIntegrationFixture {
	t.Helper()
	fixture := identityProviderIntegrationFixture{
		tenantID: identityProviderIntegrationUUID(t), foreignTenantID: identityProviderIntegrationUUID(t),
		adminUserID: identityProviderIntegrationUUID(t), foreignAdminUserID: identityProviderIntegrationUUID(t),
		deniedUserID: identityProviderIntegrationUUID(t), adminMembershipID: identityProviderIntegrationUUID(t),
		foreignAdminMembershipID: identityProviderIntegrationUUID(t), deniedMembershipID: identityProviderIntegrationUUID(t),
	}
	suffix := strings.ReplaceAll(fixture.tenantID.String(), "-", "")
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin identity-provider fixture: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE "periapsis_migrator"`); err != nil {
		t.Fatalf("set fixture role: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.tenants (id, slug, name) VALUES
		($1, $2, 'Identity provider integration'), ($3, $4, 'Foreign identity provider integration')`,
		fixture.tenantID, "identity-provider-go-"+suffix[len(suffix)-10:], fixture.foreignTenantID, "identity-provider-foreign-go-"+suffix[len(suffix)-10:],
	); err != nil {
		t.Fatalf("insert identity-provider tenants: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.audit_chain_heads (tenant_id) VALUES ($1), ($2)`, fixture.tenantID, fixture.foreignTenantID); err != nil {
		t.Fatalf("insert audit heads: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.users (id, email, display_name) VALUES
		($1, $2, 'Identity provider administrator'),
		($3, $4, 'Foreign identity provider administrator'),
		($5, $6, 'Identity provider denied user')`,
		fixture.adminUserID, "identity-provider-admin-"+suffix[len(suffix)-10:]+"@example.invalid",
		fixture.foreignAdminUserID, "identity-provider-foreign-"+suffix[len(suffix)-10:]+"@example.invalid",
		fixture.deniedUserID, "identity-provider-denied-"+suffix[len(suffix)-10:]+"@example.invalid",
	); err != nil {
		t.Fatalf("insert identity-provider users: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.tenant_memberships (id, tenant_id, user_id, role, status) VALUES
		($1, $2, $3, 'tenant_admin', 'active'),
		($4, $5, $6, 'tenant_admin', 'active'),
		($7, $2, $8, 'read_only', 'active')`,
		fixture.adminMembershipID, fixture.tenantID, fixture.adminUserID,
		fixture.foreignAdminMembershipID, fixture.foreignTenantID, fixture.foreignAdminUserID,
		fixture.deniedMembershipID, fixture.deniedUserID,
	); err != nil {
		t.Fatalf("insert identity-provider memberships: %v", err)
	}
	if _, err := tx.Exec(ctx, `SELECT app.seed_tenant_authorization($1, $2), app.seed_tenant_authorization($3, $4)`, fixture.tenantID, fixture.adminMembershipID, fixture.foreignTenantID, fixture.foreignAdminMembershipID); err != nil {
		t.Fatalf("seed identity-provider authorization: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit identity-provider fixture: %v", err)
	}
	return fixture
}

func cleanupIdentityProviderIntegrationFixture(t *testing.T, databaseURL string, fixture identityProviderIntegrationFixture) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool := identityProviderIntegrationPool(t, ctx, databaseURL, "")
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Errorf("begin identity-provider cleanup: %v", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Errorf("disable fixture triggers: %v", err)
		return
	}
	tenantIDs := []uuid.UUID{fixture.tenantID, fixture.foreignTenantID}
	statements := []string{
		`DELETE FROM public.tenant_ldap_provider_test_runs WHERE tenant_id = ANY($1)`,
		`DELETE FROM public.tenant_ldap_provider_secrets WHERE tenant_id = ANY($1)`,
		`DELETE FROM public.tenant_ldap_provider_urls WHERE tenant_id = ANY($1)`,
		`DELETE FROM public.tenant_ldap_provider_configs WHERE tenant_id = ANY($1)`,
		`DELETE FROM public.tenant_auth_providers WHERE tenant_id = ANY($1)`,
		`DELETE FROM public.audit_events WHERE tenant_id = ANY($1)`,
		`DELETE FROM public.tenant_authorization_commands WHERE tenant_id = ANY($1)`,
		`DELETE FROM public.tenant_security_group_role_grants WHERE tenant_id = ANY($1)`,
		`DELETE FROM public.tenant_security_group_memberships WHERE tenant_id = ANY($1)`,
		`DELETE FROM public.tenant_security_groups WHERE tenant_id = ANY($1)`,
		`DELETE FROM public.tenant_role_delegation_ceilings WHERE tenant_id = ANY($1)`,
		`DELETE FROM public.tenant_role_permissions WHERE tenant_id = ANY($1)`,
		`DELETE FROM public.tenant_membership_role_grants WHERE tenant_id = ANY($1)`,
		`DELETE FROM public.tenant_roles WHERE tenant_id = ANY($1)`,
		`DELETE FROM public.tenant_authorization_sources WHERE tenant_id = ANY($1)`,
		`DELETE FROM public.tenant_authorization_states WHERE tenant_id = ANY($1)`,
		`DELETE FROM public.tenant_memberships WHERE tenant_id = ANY($1)`,
		`DELETE FROM public.audit_chain_heads WHERE tenant_id = ANY($1)`,
		`DELETE FROM public.tenants WHERE id = ANY($1)`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement, tenantIDs); err != nil {
			t.Errorf("identity-provider cleanup %q: %v", statement, err)
			return
		}
	}
	userIDs := []uuid.UUID{fixture.adminUserID, fixture.foreignAdminUserID, fixture.deniedUserID}
	if _, err := tx.Exec(ctx, `DELETE FROM public.users WHERE id = ANY($1)`, userIDs); err != nil {
		t.Errorf("delete identity-provider users: %v", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		t.Errorf("commit identity-provider cleanup: %v", err)
	}
}

func cleanupIdentityProviderIntegrationKey(t *testing.T, databaseURL string, keyring identity.Keyring) {
	t.Helper()
	evidence, err := keyring.ReadinessEvidence()
	if err != nil || len(evidence.Versions) != 1 {
		t.Errorf("read key cleanup evidence: %v", err)
		return
	}
	defer clear(evidence.Versions[0].Verifier[:])
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool := identityProviderIntegrationPool(t, ctx, databaseURL, "")
	defer pool.Close()
	if _, err := pool.Exec(ctx, `DELETE FROM public.identity_keyring_versions WHERE key_version = $1 AND verifier = $2 AND NOT EXISTS (SELECT 1 FROM public.tenant_ldap_provider_secrets WHERE key_version = $1)`, int(evidence.Versions[0].KeyVersion), evidence.Versions[0].Verifier[:]); err != nil {
		t.Errorf("cleanup identity key version: %v", err)
	}
}

func identityProviderIntegrationDocuments() (identityprovider.Configuration, []identityprovider.Endpoint) {
	return identityprovider.Configuration{
		Template: identityprovider.ProviderTemplateCustom, VerifyCertificate: true,
		ConnectTimeoutMS: 1000, OperationTimeoutMS: 2000, BindDN: "cn=bind,dc=example,dc=com",
		UserBaseDN: "ou=users,dc=example,dc=com", UserSearchFilter: "(uid={username})",
		PageSize: 100, MaxPages: 10, MaxEntries: 1000, MaxResponseBytes: 1048576,
		ReferralMode: identityprovider.ReferralModeDisabled, NestedGroupMode: identityprovider.NestedGroupModeDisabled,
		MaxGroups: 100, FirstNameAttribute: "givenName", LastNameAttribute: "sn", DisplayNameAttribute: "displayName",
		UsernameAttribute: "uid", ImmutableSubjectAttribute: "entryUUID", ImmutableSubjectFormat: identityprovider.SubjectFormatEntryUUID,
		AccountStatusMode: identityprovider.AccountStatusModeNone, JITMode: identityprovider.JITModeDisabled,
		NoMatchPolicy: identityprovider.NoMatchPolicyDeny, DeprovisionMode: identityprovider.DeprovisionModeRetain,
	}, []identityprovider.Endpoint{{Priority: 1, Host: "ldap.example.com", Port: 636, Transport: ldapclient.TransportLDAPS, TLSServerName: "ldap.example.com", Enabled: true}}
}

func identityProviderIntegrationActor(t *testing.T, tenantID, userID uuid.UUID) authorization.Actor {
	t.Helper()
	return authorization.Actor{UserID: userID, SessionID: identityProviderIntegrationUUID(t), ActiveTenantID: tenantID, AuthenticationMethod: "totp"}
}

func identityProviderIntegrationAudit(t *testing.T) authorization.AuditContext {
	t.Helper()
	return authorization.AuditContext{
		RequestID: identityProviderIntegrationUUID(t), CorrelationID: identityProviderIntegrationUUID(t),
		RemoteAddress: netip.MustParseAddr("192.0.2.61"), UserAgent: "Periapsis identity-provider PostgreSQL integration test",
	}
}

func identityProviderIntegrationUUID(t *testing.T) uuid.UUID {
	t.Helper()
	value, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("generate UUIDv7: %v", err)
	}
	return value
}

func identityProviderIntegrationETag(t *testing.T, version int64) string {
	t.Helper()
	value, err := identityprovider.EntityTag(version)
	if err != nil {
		t.Fatalf("create provider ETag: %v", err)
	}
	return value
}

func identityProviderIntegrationSecretRow(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, providerID uuid.UUID) (uuid.UUID, []byte) {
	t.Helper()
	var secretID uuid.UUID
	var ciphertext []byte
	var nonce []byte
	var keyVersion int
	if err := pool.QueryRow(ctx, `SELECT id, secret_ciphertext, secret_nonce, key_version FROM public.tenant_ldap_provider_secrets WHERE tenant_id = $1 AND provider_id = $2`, tenantID, providerID).Scan(&secretID, &ciphertext, &nonce, &keyVersion); err != nil {
		t.Fatalf("read encrypted bind-secret row: %v", err)
	}
	if secretID.Version() != 7 || len(ciphertext) < 17 || len(nonce) != 12 || keyVersion != 1 {
		t.Fatalf("encrypted bind-secret envelope = id %s ciphertext %d nonce %d key %d", secretID, len(ciphertext), len(nonce), keyVersion)
	}
	return secretID, ciphertext
}

func assertIdentityProviderIntegrationNoPlaintext(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID, plaintext string) {
	t.Helper()
	var matches int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM public.audit_events
		WHERE tenant_id = $1 AND (coalesce(before::text, '') || coalesce(after::text, '') || metadata::text) LIKE '%' || $2 || '%'`, tenantID, plaintext,
	).Scan(&matches); err != nil || matches != 0 {
		t.Fatalf("plaintext audit matches = %d, error = %v", matches, err)
	}
}

func assertIdentityProviderIntegrationAudit(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, providerID uuid.UUID, audit authorization.AuditContext, action string) {
	t.Helper()
	var matches int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM public.audit_events
		WHERE tenant_id = $1 AND resource_id = $2 AND request_id = $3 AND correlation_id = $4 AND action = $5`,
		tenantID, providerID, audit.RequestID, audit.CorrelationID, action,
	).Scan(&matches); err != nil || matches != 1 {
		t.Fatalf("audit %s matches = %d, error = %v", action, matches, err)
	}
}

func assertIdentityProviderIntegrationCompletedRun(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, runID uuid.UUID, category string) {
	t.Helper()
	var status, actualCategory string
	var version int
	if err := pool.QueryRow(ctx, `SELECT status, category, version FROM public.tenant_ldap_provider_test_runs WHERE tenant_id = $1 AND id = $2`, tenantID, runID).Scan(&status, &actualCategory, &version); err != nil {
		t.Fatalf("read diagnostic run %s: %v", runID, err)
	}
	if status != "completed" || actualCategory != category || version != 2 {
		t.Fatalf("diagnostic run %s = status %s category %s version %d", runID, status, actualCategory, version)
	}
}

func identityProviderIntegrationAllZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
