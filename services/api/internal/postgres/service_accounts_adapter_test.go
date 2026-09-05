package postgres

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
	"github.com/periapsis-im/periapsis/services/api/internal/serviceaccount"
)

type serviceAccountQueriesStub struct {
	serviceAccountQueries
	tenantID     uuid.UUID
	actorID      uuid.UUID
	setCalls     int
	accountRow   *dbsql.GetTenantServiceAccountRow
	createResult *dbsql.CreateTenantServiceAccountRow
	createCalls  int

	roleGrantRow *dbsql.GetTenantServiceAccountRoleGrantRow
	grantResult  *dbsql.GrantTenantServiceAccountRoleRow
	grantCalls   int
	revokeParams dbsql.RevokeTenantServiceAccountRoleGrantParams
	revokeCalls  int

	issueResult  *dbsql.IssueTenantAPICredentialRow
	issueParams  dbsql.IssueTenantAPICredentialParams
	issueDigest  []byte
	issueCalls   int
	rotateResult *dbsql.RotateTenantAPICredentialRow
	rotateParams dbsql.RotateTenantAPICredentialParams
	rotateDigest []byte
	rotateCalls  int
	credential   *dbsql.GetTenantAPICredentialRow
	getCalls     int
	order        []string
}

func (s *serviceAccountQueriesStub) CreateTenantServiceAccount(
	_ context.Context,
	_ dbsql.CreateTenantServiceAccountParams,
) (*dbsql.CreateTenantServiceAccountRow, error) {
	s.createCalls++
	return s.createResult, nil
}

func (s *serviceAccountQueriesStub) GetTenantServiceAccount(
	context.Context,
	dbsql.GetTenantServiceAccountParams,
) (*dbsql.GetTenantServiceAccountRow, error) {
	return s.accountRow, nil
}

func (s *serviceAccountQueriesStub) SetTenantContext(
	_ context.Context,
	params dbsql.SetTenantContextParams,
) (*dbsql.SetTenantContextRow, error) {
	s.setCalls++
	s.order = append(s.order, "set")
	s.tenantID = uuid.UUID(params.TenantID.Bytes)
	s.actorID = uuid.UUID(params.UserID.Bytes)
	return &dbsql.SetTenantContextRow{TenantID: s.tenantID.String(), UserID: s.actorID.String()}, nil
}

func (s *serviceAccountQueriesStub) GetTenantServiceAccountRoleGrant(
	context.Context,
	dbsql.GetTenantServiceAccountRoleGrantParams,
) (*dbsql.GetTenantServiceAccountRoleGrantRow, error) {
	return s.roleGrantRow, nil
}

func (s *serviceAccountQueriesStub) GrantTenantServiceAccountRole(
	_ context.Context,
	_ dbsql.GrantTenantServiceAccountRoleParams,
) (*dbsql.GrantTenantServiceAccountRoleRow, error) {
	s.grantCalls++
	return s.grantResult, nil
}

func (s *serviceAccountQueriesStub) RevokeTenantServiceAccountRoleGrant(
	_ context.Context,
	params dbsql.RevokeTenantServiceAccountRoleGrantParams,
) (int32, error) {
	s.revokeCalls++
	s.revokeParams = params
	return params.ExpectedVersion + 1, nil
}

func (s *serviceAccountQueriesStub) IssueTenantAPICredential(
	_ context.Context,
	params dbsql.IssueTenantAPICredentialParams,
) (*dbsql.IssueTenantAPICredentialRow, error) {
	s.issueCalls++
	s.order = append(s.order, "issue")
	s.issueParams = params
	s.issueDigest = append([]byte(nil), params.SecretDigest...)
	return s.issueResult, nil
}

func (s *serviceAccountQueriesStub) GetTenantAPICredential(
	context.Context,
	dbsql.GetTenantAPICredentialParams,
) (*dbsql.GetTenantAPICredentialRow, error) {
	s.getCalls++
	s.order = append(s.order, "get")
	return s.credential, nil
}

func (s *serviceAccountQueriesStub) RotateTenantAPICredential(
	_ context.Context,
	params dbsql.RotateTenantAPICredentialParams,
) (*dbsql.RotateTenantAPICredentialRow, error) {
	s.rotateCalls++
	s.order = append(s.order, "rotate")
	s.rotateParams = params
	s.rotateDigest = append([]byte(nil), params.SecretDigest...)
	return s.rotateResult, nil
}

func TestServiceAccountRoleGrantRevokeRechecksStrongProjectionInSerializableTransaction(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	serviceAccountID := uuid.Must(uuid.NewV7())
	grantID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	membershipID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	row := validServiceAccountRoleGrantTestRow(serviceAccountID, grantID, actor.UserID, membershipID, now)
	grant, err := mapGotServiceAccountRoleGrant(tenantID, serviceAccountID, row)
	if err != nil {
		t.Fatalf("mapGotServiceAccountRoleGrant() error = %v", err)
	}
	entityTag, err := serviceaccount.RoleGrantEntityTag(grant)
	if err != nil {
		t.Fatalf("RoleGrantEntityTag() error = %v", err)
	}
	queries := &serviceAccountQueriesStub{roleGrantRow: row}
	tx := &recordingTransaction{}
	var options pgx.TxOptions
	repository := &ServiceAccountRepository{
		begin: func(_ context.Context, value pgx.TxOptions) (databaseTransaction, error) {
			options = value
			return tx, nil
		},
		queryFactory: func(databaseTransaction) serviceAccountQueries { return queries },
	}
	err = repository.RevokeRoleGrant(context.Background(), serviceaccount.RevokeRoleGrantParams{
		HumanParams: serviceaccount.HumanParams{Actor: actor, MembershipID: membershipID, TenantID: tenantID},
		Audit:       serviceAccountAdapterTestAudit(), OccurredAt: now, ServiceAccountID: serviceAccountID,
		GrantID: grantID, Reason: "Rotation complete", ExpectedEntityTag: entityTag,
	})
	if err != nil {
		t.Fatalf("RevokeRoleGrant() error = %v", err)
	}
	if options.IsoLevel != pgx.Serializable || queries.setCalls != 1 || queries.revokeCalls != 1 ||
		queries.revokeParams.ExpectedVersion != row.Version || !tx.committed {
		t.Fatalf("options=%+v set=%d revoke=%d params=%+v committed=%t", options, queries.setCalls, queries.revokeCalls, queries.revokeParams, tx.committed)
	}
}

func TestServiceAccountCreateRejectsNonFreshReadback(t *testing.T) {
	t.Parallel()

	tenantID, serviceAccountID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	membershipID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	row := validServiceAccountTestRow(serviceAccountID, actor.UserID, membershipID, now)
	row.UpdatedAt = databaseTime(now.Add(time.Microsecond))
	queries := &serviceAccountQueriesStub{
		createResult: &dbsql.CreateTenantServiceAccountRow{ResultResourceID: toDatabaseUUID(serviceAccountID), ResultVersion: 1},
		accountRow:   row,
	}
	tx := &recordingTransaction{}
	repository := &ServiceAccountRepository{
		begin:        func(context.Context, pgx.TxOptions) (databaseTransaction, error) { return tx, nil },
		queryFactory: func(databaseTransaction) serviceAccountQueries { return queries },
	}
	_, err := repository.CreateAccount(context.Background(), serviceaccount.CreateAccountParams{
		HumanParams: serviceaccount.HumanParams{Actor: actor, MembershipID: membershipID, TenantID: tenantID},
		Audit:       serviceAccountAdapterTestAudit(), OccurredAt: now, ServiceAccountID: serviceAccountID,
		Key: "alert_collector", DisplayName: "Alert Collector", Description: "Ingest only",
	})
	if !errors.Is(err, serviceaccount.ErrUnavailable) || queries.createCalls != 1 || tx.committed || !tx.rolledBack {
		t.Fatalf("CreateAccount() error=%v calls=%d committed=%t rolledBack=%t", err, queries.createCalls, tx.committed, tx.rolledBack)
	}
}

func TestServiceAccountGrantRejectsNonFreshReadback(t *testing.T) {
	t.Parallel()

	tenantID, serviceAccountID, grantID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	membershipID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	row := validServiceAccountRoleGrantTestRow(serviceAccountID, grantID, actor.UserID, membershipID, now)
	row.GrantedAt = databaseTime(now)
	row.UpdatedAt = databaseTime(now.Add(time.Microsecond))
	roleID := uuid.UUID(row.RoleID.Bytes)
	queries := &serviceAccountQueriesStub{
		grantResult:  &dbsql.GrantTenantServiceAccountRoleRow{ResultResourceID: toDatabaseUUID(grantID), ResultVersion: 1},
		roleGrantRow: row,
	}
	tx := &recordingTransaction{}
	repository := &ServiceAccountRepository{
		begin:        func(context.Context, pgx.TxOptions) (databaseTransaction, error) { return tx, nil },
		queryFactory: func(databaseTransaction) serviceAccountQueries { return queries },
	}
	_, err := repository.GrantRole(context.Background(), serviceaccount.GrantRoleParams{
		HumanParams: serviceaccount.HumanParams{Actor: actor, MembershipID: membershipID, TenantID: tenantID},
		Audit:       serviceAccountAdapterTestAudit(), OccurredAt: now, ServiceAccountID: serviceAccountID,
		GrantID: grantID, RoleID: roleID, Reason: "Automation ingest",
	})
	if !errors.Is(err, serviceaccount.ErrUnavailable) || queries.grantCalls != 1 || tx.committed || !tx.rolledBack {
		t.Fatalf("GrantRole() error=%v calls=%d committed=%t rolledBack=%t", err, queries.grantCalls, tx.committed, tx.rolledBack)
	}
}

func TestServiceAccountRoleGrantRevokeRejectsSameVersionDifferentProjection(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	serviceAccountID := uuid.Must(uuid.NewV7())
	grantID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	membershipID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	row := validServiceAccountRoleGrantTestRow(serviceAccountID, grantID, actor.UserID, membershipID, now)
	grant, _ := mapGotServiceAccountRoleGrant(tenantID, serviceAccountID, row)
	grant.Role.DisplayName = "Stale role projection"
	staleTag, err := serviceaccount.RoleGrantEntityTag(grant)
	if err != nil {
		t.Fatalf("RoleGrantEntityTag() error = %v", err)
	}
	queries := &serviceAccountQueriesStub{roleGrantRow: row}
	tx := &recordingTransaction{}
	repository := &ServiceAccountRepository{
		begin:        func(context.Context, pgx.TxOptions) (databaseTransaction, error) { return tx, nil },
		queryFactory: func(databaseTransaction) serviceAccountQueries { return queries },
	}
	err = repository.RevokeRoleGrant(context.Background(), serviceaccount.RevokeRoleGrantParams{
		HumanParams: serviceaccount.HumanParams{Actor: actor, MembershipID: membershipID, TenantID: tenantID},
		Audit:       serviceAccountAdapterTestAudit(), OccurredAt: now, ServiceAccountID: serviceAccountID,
		GrantID: grantID, Reason: "Rotation complete", ExpectedEntityTag: staleTag,
	})
	if !errors.Is(err, serviceaccount.ErrPreconditionFailed) || queries.revokeCalls != 0 || tx.committed || !tx.rolledBack {
		t.Fatalf("RevokeRoleGrant() error=%v calls=%d committed=%t rolledBack=%t", err, queries.revokeCalls, tx.committed, tx.rolledBack)
	}
}

func TestServiceAccountRoleGrantRevokeRejectsInactiveCurrentGrant(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	serviceAccountID := uuid.Must(uuid.NewV7())
	grantID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	membershipID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	row := validServiceAccountRoleGrantTestRow(serviceAccountID, grantID, actor.UserID, membershipID, now)
	row.GrantState = string(serviceaccount.RoleGrantStateExpired)
	grant, err := mapGotServiceAccountRoleGrant(tenantID, serviceAccountID, row)
	if err != nil {
		t.Fatalf("mapGotServiceAccountRoleGrant() error = %v", err)
	}
	entityTag, err := serviceaccount.RoleGrantEntityTag(grant)
	if err != nil {
		t.Fatalf("RoleGrantEntityTag() error = %v", err)
	}
	queries := &serviceAccountQueriesStub{roleGrantRow: row}
	tx := &recordingTransaction{}
	repository := &ServiceAccountRepository{
		begin:        func(context.Context, pgx.TxOptions) (databaseTransaction, error) { return tx, nil },
		queryFactory: func(databaseTransaction) serviceAccountQueries { return queries },
	}

	err = repository.RevokeRoleGrant(context.Background(), serviceaccount.RevokeRoleGrantParams{
		HumanParams: serviceaccount.HumanParams{Actor: actor, MembershipID: membershipID, TenantID: tenantID},
		Audit:       serviceAccountAdapterTestAudit(), OccurredAt: now, ServiceAccountID: serviceAccountID,
		GrantID: grantID, Reason: "Rotation complete", ExpectedEntityTag: entityTag,
	})
	if !errors.Is(err, serviceaccount.ErrConflict) || queries.revokeCalls != 0 || tx.committed || !tx.rolledBack {
		t.Fatalf("RevokeRoleGrant() error=%v calls=%d committed=%t rolledBack=%t", err, queries.revokeCalls, tx.committed, tx.rolledBack)
	}
}

func TestServiceAccountCredentialReplayReturnsOnlyRedactedMetadata(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	serviceAccountID := uuid.Must(uuid.NewV7())
	credentialID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	membershipID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	queries := &serviceAccountQueriesStub{
		issueResult: &dbsql.IssueTenantAPICredentialRow{
			ResultCredentialID: toDatabaseUUID(credentialID), ResultVersion: 1, Replayed: true,
		},
		credential: validServiceAccountCredentialTestRow(serviceAccountID, credentialID, actor.UserID, membershipID, now),
	}
	tx := &recordingTransaction{}
	repository := &ServiceAccountRepository{
		begin:        func(context.Context, pgx.TxOptions) (databaseTransaction, error) { return tx, nil },
		queryFactory: func(databaseTransaction) serviceAccountQueries { return queries },
	}
	write := serviceaccount.CredentialWrite{
		CredentialID: credentialID, Label: "Automation", FormatVersion: 1,
		Material: serviceaccount.PresentedCredential{KeyVersion: 7}, ExpiresAt: now.Add(24 * time.Hour),
		Permissions: []authorization.ScopedPermission{{Permission: authorization.TenantPermissionAlertCreate, Scope: authorization.ScopeTenant}},
		Networks:    []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}
	copy(write.Material.Locator[:], []byte("0123456789abcdef"))
	for index := range write.Material.Digest {
		write.Material.Digest[index] = byte(index + 1)
		write.KeyDigest[index] = byte(index + 2)
		write.RequestDigest[index] = byte(index + 3)
	}
	result, err := repository.IssueCredential(context.Background(), serviceaccount.IssueCredentialParams{
		HumanParams: serviceaccount.HumanParams{Actor: actor, MembershipID: membershipID, TenantID: tenantID},
		Audit:       serviceAccountAdapterTestAudit(), OccurredAt: now, ServiceAccountID: serviceAccountID, Write: write,
	})
	if err != nil {
		t.Fatalf("IssueCredential() error = %v", err)
	}
	if !result.Replayed || result.Credential.ID != credentialID || queries.issueCalls != 1 || queries.getCalls != 1 ||
		!tx.committed || !equalBytes(queries.issueParams.Locator, write.Material.Locator[:]) ||
		!equalBytes(queries.issueDigest, write.Material.Digest[:]) || !allZeroBytes(queries.issueParams.SecretDigest) {
		t.Fatalf("result=%+v calls=(%d,%d) committed=%t params=%+v", result, queries.issueCalls, queries.getCalls, tx.committed, queries.issueParams)
	}
}

func TestDatabaseCredentialWriteAcceptsPostgreSQLCIDROrder(t *testing.T) {
	t.Parallel()

	write := serviceaccount.CredentialWrite{
		CredentialID: uuid.Must(uuid.NewV7()), Label: "Native CIDR order", FormatVersion: 1,
		Material:  serviceaccount.PresentedCredential{KeyVersion: 1},
		ExpiresAt: time.Now().UTC().Truncate(time.Microsecond).Add(24 * time.Hour),
		Permissions: []authorization.ScopedPermission{{
			Permission: authorization.TenantPermissionAlertCreate,
			Scope:      authorization.ScopeTenant,
		}},
		Networks: []netip.Prefix{
			netip.MustParsePrefix("2.0.0.0/8"),
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("10.0.0.0/9"),
			netip.MustParsePrefix("10.128.0.0/9"),
			netip.MustParsePrefix("2001:db8::/32"),
		},
	}
	databaseWrite, err := databaseServiceAccountCredentialWrite(&write)
	if err != nil {
		t.Fatalf("databaseServiceAccountCredentialWrite() error = %v", err)
	}
	if !reflect.DeepEqual(databaseWrite.networks, write.Networks) {
		t.Fatalf("database networks = %v, want %v", databaseWrite.networks, write.Networks)
	}
}

func TestServiceAccountCredentialIssueRejectsNonFreshReadbackAndClearsVerifier(t *testing.T) {
	t.Parallel()

	tenantID, serviceAccountID, credentialID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	membershipID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	credential := validServiceAccountCredentialTestRow(serviceAccountID, credentialID, actor.UserID, membershipID, now)
	credential.UpdatedAt = databaseTime(now.Add(time.Microsecond))
	queries := &serviceAccountQueriesStub{
		issueResult: &dbsql.IssueTenantAPICredentialRow{
			ResultCredentialID: toDatabaseUUID(credentialID), ResultVersion: 1,
		},
		credential: credential,
	}
	tx := &recordingTransaction{}
	repository := &ServiceAccountRepository{
		begin:        func(context.Context, pgx.TxOptions) (databaseTransaction, error) { return tx, nil },
		queryFactory: func(databaseTransaction) serviceAccountQueries { return queries },
	}
	write := serviceaccount.CredentialWrite{
		CredentialID: credentialID, Label: "Automation", FormatVersion: 1,
		Material: serviceaccount.PresentedCredential{KeyVersion: 7}, ExpiresAt: now.Add(24 * time.Hour),
		Permissions: []authorization.ScopedPermission{{Permission: authorization.TenantPermissionAlertCreate, Scope: authorization.ScopeTenant}},
		Networks:    []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}
	for index := range write.Material.Digest {
		write.Material.Digest[index] = byte(index + 1)
	}
	_, err := repository.IssueCredential(context.Background(), serviceaccount.IssueCredentialParams{
		HumanParams: serviceaccount.HumanParams{Actor: actor, MembershipID: membershipID, TenantID: tenantID},
		Audit:       serviceAccountAdapterTestAudit(), OccurredAt: now, ServiceAccountID: serviceAccountID, Write: write,
	})
	if !errors.Is(err, serviceaccount.ErrUnavailable) || tx.committed || !tx.rolledBack ||
		!equalBytes(queries.issueDigest, write.Material.Digest[:]) || !allZeroBytes(queries.issueParams.SecretDigest) {
		t.Fatalf("IssueCredential() error=%v committed=%t rolledBack=%t digest=%x retained=%x", err, tx.committed, tx.rolledBack, queries.issueDigest, queries.issueParams.SecretDigest)
	}
}

func allZeroBytes(values []byte) bool {
	for _, value := range values {
		if value != 0 {
			return false
		}
	}
	return true
}

func TestServiceAccountCredentialRotationReplayMutatesBeforeRedactedRead(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	serviceAccountID := uuid.Must(uuid.NewV7())
	predecessorID := uuid.Must(uuid.NewV7())
	replacementID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	membershipID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	credential := validServiceAccountCredentialTestRow(serviceAccountID, replacementID, actor.UserID, membershipID, now)
	credential.RotatedFromCredentialID = toDatabaseUUID(predecessorID)
	queries := &serviceAccountQueriesStub{
		rotateResult: &dbsql.RotateTenantAPICredentialRow{
			ResultCredentialID: toDatabaseUUID(replacementID), ResultVersion: 1, Replayed: true,
		},
		credential: credential,
	}
	tx := &recordingTransaction{}
	repository := &ServiceAccountRepository{
		begin:        func(context.Context, pgx.TxOptions) (databaseTransaction, error) { return tx, nil },
		queryFactory: func(databaseTransaction) serviceAccountQueries { return queries },
	}
	write := serviceaccount.CredentialWrite{
		CredentialID: replacementID, Label: "Automation", FormatVersion: 1,
		Material: serviceaccount.PresentedCredential{KeyVersion: 7}, ExpiresAt: now.Add(24 * time.Hour),
		Permissions: []authorization.ScopedPermission{{Permission: authorization.TenantPermissionAlertCreate, Scope: authorization.ScopeTenant}},
		Networks:    []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}
	copy(write.Material.Locator[:], []byte("fedcba9876543210"))
	for index := range write.Material.Digest {
		write.Material.Digest[index] = byte(index + 11)
	}
	result, err := repository.RotateCredential(context.Background(), serviceaccount.RotateCredentialParams{
		HumanParams: serviceaccount.HumanParams{Actor: actor, MembershipID: membershipID, TenantID: tenantID},
		Audit:       serviceAccountAdapterTestAudit(), OccurredAt: now, ServiceAccountID: serviceAccountID,
		PreviousCredentialID: predecessorID, ExpectedVersion: 1, Reason: "Scheduled rotation", Write: write,
	})
	if err != nil {
		t.Fatalf("RotateCredential() error = %v", err)
	}
	if !result.Replayed || queries.rotateCalls != 1 || queries.getCalls != 1 ||
		!reflect.DeepEqual(queries.order, []string{"set", "rotate", "get"}) || !tx.committed ||
		queries.rotateParams.RotatedFromCredentialID != toDatabaseUUID(predecessorID) ||
		!equalBytes(queries.rotateDigest, write.Material.Digest[:]) || !allZeroBytes(queries.rotateParams.SecretDigest) {
		t.Fatalf("result=%+v order=%v calls=(%d,%d) committed=%t params=%+v", result, queries.order, queries.rotateCalls, queries.getCalls, tx.committed, queries.rotateParams)
	}
}

func TestGeneratedCredentialReadRowsCannotContainAuthenticationMaterial(t *testing.T) {
	for _, rowType := range []reflect.Type{
		reflect.TypeOf(dbsql.GetTenantAPICredentialRow{}),
		reflect.TypeOf(dbsql.ListTenantAPICredentialsRow{}),
	} {
		for fieldIndex := range rowType.NumField() {
			fieldName := rowType.Field(fieldIndex).Name
			for _, forbidden := range []string{"Locator", "Secret", "Digest", "Token"} {
				if strings.Contains(fieldName, forbidden) {
					t.Fatalf("generated redacted read row %s unexpectedly contains %s", rowType.Name(), fieldName)
				}
			}
		}
	}
}

func TestServiceAccountCredentialMappingCanonicalizesDatabaseNetworkOrder(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	serviceAccountID := uuid.Must(uuid.NewV7())
	credentialID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	row := validServiceAccountCredentialTestRow(
		serviceAccountID, credentialID, uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), now,
	)
	row.Networks = []netip.Prefix{
		netip.MustParsePrefix("2.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/9"),
		netip.MustParsePrefix("10.128.0.0/9"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2001:db8::/48"),
		netip.MustParsePrefix("2001:db8:1::/48"),
	}
	credential, err := mapGotServiceAccountCredential(tenantID, serviceAccountID, row)
	if err != nil {
		t.Fatalf("mapGotServiceAccountCredential() error = %v", err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("2.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/9"),
		netip.MustParsePrefix("10.128.0.0/9"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2001:db8::/48"),
		netip.MustParsePrefix("2001:db8:1::/48"),
	}
	if !reflect.DeepEqual(credential.Networks, want) {
		t.Fatalf("credential.Networks = %v, want %v", credential.Networks, want)
	}
}

func TestServiceAccountCredentialMappingRejectsUseAfterExpiry(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	serviceAccountID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	row := validServiceAccountCredentialTestRow(
		serviceAccountID, uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), now,
	)
	row.LastUsedAt = databaseTime(now.Add(25 * time.Hour))
	row.LastUsedIp = netip.MustParseAddr("198.51.100.29")
	row.UpdatedAt = databaseTime(now.Add(26 * time.Hour))

	if _, err := mapGotServiceAccountCredential(tenantID, serviceAccountID, row); !errors.Is(err, serviceaccount.ErrUnavailable) {
		t.Fatalf("mapGotServiceAccountCredential() error = %v, want unavailable", err)
	}
}

func TestServiceAccountCredentialMappingRejectsUseAfterRevocation(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	serviceAccountID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	row := validServiceAccountCredentialTestRow(
		serviceAccountID, uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), now,
	)
	row.LastUsedAt = databaseTime(now.Add(30 * time.Minute))
	row.LastUsedIp = netip.MustParseAddr("198.51.100.29")
	row.RevokedAt = databaseTime(now.Add(20 * time.Minute))
	row.RevokedByMembershipID = toDatabaseUUID(uuid.Must(uuid.NewV7()))
	row.RevokedByUserID = toDatabaseUUID(uuid.Must(uuid.NewV7()))
	row.RevokeReason = "credential replaced"
	row.CredentialState = string(serviceaccount.CredentialStateRevoked)
	row.UpdatedAt = databaseTime(now.Add(40 * time.Minute))

	if _, err := mapGotServiceAccountCredential(tenantID, serviceAccountID, row); !errors.Is(err, serviceaccount.ErrUnavailable) {
		t.Fatalf("mapGotServiceAccountCredential() error = %v, want unavailable", err)
	}
}

func TestServiceAccountDatabaseErrorsMapVersionAndReplayConflicts(t *testing.T) {
	versionErr := &pgconn.PgError{Code: "40001", Message: serviceAccountCredentialVersionConflictMessage}
	replayErr := &pgconn.PgError{Code: "23505", ConstraintName: "tenant_api_credential_commands_replay_key"}
	if !errors.Is(mapServiceAccountDatabaseError(versionErr), serviceaccount.ErrPreconditionFailed) {
		t.Fatalf("version conflict mapping = %v", mapServiceAccountDatabaseError(versionErr))
	}
	if !errors.Is(mapServiceAccountDatabaseError(replayErr), serviceaccount.ErrConflict) {
		t.Fatalf("replay conflict mapping = %v", mapServiceAccountDatabaseError(replayErr))
	}
}

func validServiceAccountRoleGrantTestRow(
	serviceAccountID, grantID, actorID, membershipID uuid.UUID,
	now time.Time,
) *dbsql.GetTenantServiceAccountRoleGrantRow {
	return &dbsql.GetTenantServiceAccountRoleGrantRow{
		GrantID: toDatabaseUUID(grantID), ServiceAccountID: toDatabaseUUID(serviceAccountID),
		RoleID: toDatabaseUUID(uuid.Must(uuid.NewV7())), RoleKey: "alert_ingest",
		RoleDisplayName: "Alert ingest", SourceID: toDatabaseUUID(uuid.Must(uuid.NewV7())),
		SourceKind: string(authorization.AuthorizationSourceManual), SourceKey: "manual",
		GrantedByMembershipID: toDatabaseUUID(membershipID), GrantedByUserID: toDatabaseUUID(actorID),
		GrantReason: "Automation ingest", GrantedAt: databaseTime(now.Add(-time.Hour)),
		GrantState: string(serviceaccount.RoleGrantStateActive), Version: 1, UpdatedAt: databaseTime(now),
	}
}

func validServiceAccountTestRow(
	serviceAccountID, actorID, membershipID uuid.UUID,
	now time.Time,
) *dbsql.GetTenantServiceAccountRow {
	return &dbsql.GetTenantServiceAccountRow{
		ServiceAccountID: toDatabaseUUID(serviceAccountID), AccountKey: "alert_collector",
		DisplayName: "Alert Collector", Description: "Ingest only",
		CreatedByMembershipID: toDatabaseUUID(membershipID), CreatedByUserID: toDatabaseUUID(actorID),
		Version: 1, CreatedAt: databaseTime(now), UpdatedAt: databaseTime(now),
	}
}

func validServiceAccountCredentialTestRow(
	serviceAccountID, credentialID, actorID, membershipID uuid.UUID,
	now time.Time,
) *dbsql.GetTenantAPICredentialRow {
	return &dbsql.GetTenantAPICredentialRow{
		CredentialID: toDatabaseUUID(credentialID), ServiceAccountID: toDatabaseUUID(serviceAccountID),
		Label: "Automation", FormatVersion: 1, KeyVersion: 7,
		IssuedByMembershipID: toDatabaseUUID(membershipID), IssuedByUserID: toDatabaseUUID(actorID),
		IssuedAt: databaseTime(now), ExpiresAt: databaseTime(now.Add(24 * time.Hour)),
		CredentialState: string(serviceaccount.CredentialStateActive), Version: 1, UpdatedAt: databaseTime(now),
		PermissionKeys:   []string{string(authorization.TenantPermissionAlertCreate)},
		PermissionScopes: []string{string(authorization.ScopeTenant)},
		Networks:         []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}
}

func serviceAccountAdapterTestAudit() authorization.AuditContext {
	return authorization.AuditContext{
		RequestID: uuid.New(), CorrelationID: uuid.New(),
		RemoteAddress: netip.MustParseAddr("192.0.2.44"), UserAgent: "service-account adapter test",
	}
}
