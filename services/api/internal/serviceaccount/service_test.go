package serviceaccount

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type serviceRepositoryStub struct {
	authority        authorization.TenantAuthority
	resolveErr       error
	issueResult      CredentialMutationResult
	issueErr         error
	rotateResult     CredentialMutationResult
	rotateErr        error
	issueParams      *IssueCredentialParams
	rotateParams     *RotateCredentialParams
	getCredential    int
	credential       CredentialMetadata
	revokeCredential *RevokeCredentialParams
	account          Account
	archiveParams    *ArchiveAccountParams
	createParams     *CreateAccountParams
	createdAccount   Account
	updateParams     *UpdateAccountParams
	updatedAccount   Account
	mutateIssue      func(*CredentialMetadata)
	roleGrant        RoleGrant
	grantedRole      RoleGrant
	grantRole        *GrantRoleParams
	revokeRole       *RevokeRoleGrantParams
}

func (s *serviceRepositoryStub) ResolveHumanAuthority(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
	return s.authority, s.resolveErr
}

func (*serviceRepositoryStub) ListAccounts(context.Context, ListAccountsParams) ([]Account, error) {
	return nil, nil
}

func (s *serviceRepositoryStub) GetAccount(context.Context, GetAccountParams) (Account, error) {
	if s.account.ID == uuid.Nil {
		return Account{}, ErrNotFound
	}
	return s.account, nil
}

func (s *serviceRepositoryStub) CreateAccount(_ context.Context, params CreateAccountParams) (Account, error) {
	s.createParams = &params
	if s.createdAccount.ID != uuid.Nil {
		return s.createdAccount, nil
	}
	return storedAccount(params), nil
}

func (s *serviceRepositoryStub) UpdateAccount(_ context.Context, params UpdateAccountParams) (Account, error) {
	s.updateParams = &params
	if s.updatedAccount.ID == uuid.Nil {
		return Account{}, ErrNotFound
	}
	return s.updatedAccount, nil
}

func (s *serviceRepositoryStub) ArchiveAccount(_ context.Context, params ArchiveAccountParams) error {
	s.archiveParams = &params
	return nil
}

func (*serviceRepositoryStub) ListRoleGrants(context.Context, ListRoleGrantsParams) ([]RoleGrant, error) {
	return nil, nil
}

func (s *serviceRepositoryStub) GetRoleGrant(context.Context, GetRoleGrantParams) (RoleGrant, error) {
	if s.roleGrant.ID == uuid.Nil {
		return RoleGrant{}, ErrNotFound
	}
	return s.roleGrant, nil
}

func (s *serviceRepositoryStub) GrantRole(_ context.Context, params GrantRoleParams) (RoleGrant, error) {
	s.grantRole = &params
	if s.grantedRole.ID != uuid.Nil {
		return s.grantedRole, nil
	}
	return RoleGrant{}, ErrNotFound
}

func (s *serviceRepositoryStub) RevokeRoleGrant(_ context.Context, params RevokeRoleGrantParams) error {
	s.revokeRole = &params
	return nil
}

func (*serviceRepositoryStub) ListCredentials(context.Context, ListCredentialsParams) ([]CredentialMetadata, error) {
	return nil, nil
}

func (s *serviceRepositoryStub) GetCredential(context.Context, GetCredentialParams) (CredentialMetadata, error) {
	s.getCredential++
	if s.credential.ID != uuid.Nil {
		return s.credential, nil
	}
	return CredentialMetadata{}, ErrNotFound
}

func (s *serviceRepositoryStub) IssueCredential(_ context.Context, params IssueCredentialParams) (CredentialMutationResult, error) {
	s.issueParams = &params
	if s.issueResult.Credential.ID == uuid.Nil && s.issueErr == nil {
		s.issueResult.Credential = storedCredential(params.HumanParams, params.ServiceAccountID, params.Write, params.OccurredAt, nil)
	}
	if s.mutateIssue != nil {
		s.mutateIssue(&s.issueResult.Credential)
	}
	return s.issueResult, s.issueErr
}

func (s *serviceRepositoryStub) RotateCredential(_ context.Context, params RotateCredentialParams) (CredentialMutationResult, error) {
	s.rotateParams = &params
	if s.rotateResult.Credential.ID == uuid.Nil && s.rotateErr == nil {
		s.rotateResult.Credential = storedCredential(params.HumanParams, params.ServiceAccountID, params.Write, params.OccurredAt, &params.PreviousCredentialID)
	}
	return s.rotateResult, s.rotateErr
}

func (s *serviceRepositoryStub) RevokeCredential(_ context.Context, params RevokeCredentialParams) error {
	s.revokeCredential = &params
	return nil
}

func TestIssueCredentialReturnsSecretOnceAndPassesOnlyDerivedMaterial(t *testing.T) {
	t.Parallel()

	tenantID, userID, membershipID, accountID := serviceTestID(1), serviceTestID(2), serviceTestID(3), serviceTestID(4)
	repository := &serviceRepositoryStub{authority: humanServiceAuthority(
		tenantID, userID, membershipID, authorization.TenantPermissionServiceAccountCredentialManage,
	)}
	service := testAdministrationService(t, repository)
	credentialID := serviceTestID(5)
	service.newID = func() (uuid.UUID, error) { return credentialID, nil }
	now := service.now()
	input := IssueCredentialInput{
		Label: "  collector key  ", ExpiresAt: now.Add(30 * 24 * time.Hour),
		Permissions:    []authorization.ScopedPermission{{Permission: authorization.TenantPermissionAlertCreate, Scope: authorization.ScopeTenant}},
		Networks:       []netip.Prefix{netip.MustParsePrefix("2001:db8:2::/48"), netip.MustParsePrefix("192.0.2.77/24")},
		IdempotencyKey: "credential-issue-retry-0001", Audit: serviceAudit(6),
	}
	actor := serviceActor(userID, tenantID)

	secret, err := service.IssueCredential(context.Background(), actor, tenantID, accountID, input)
	if err != nil {
		t.Fatalf("IssueCredential() error = %v", err)
	}
	if secret.Credential.ID != credentialID || !strings.HasPrefix(secret.Token, credentialFormatPrefix+".") {
		t.Fatalf("secret result = %#v", secret)
	}
	if repository.issueParams == nil {
		t.Fatal("repository did not receive issue command")
	}
	write := repository.issueParams.Write
	if write.Material.Digest == ([32]byte{}) || write.Material.Locator == ([16]byte{}) || write.KeyDigest == ([32]byte{}) || write.RequestDigest == ([32]byte{}) {
		t.Fatalf("derived command material = %#v", write)
	}
	if write.Label != "collector key" || !reflect.DeepEqual(write.Networks, []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8:2::/48"),
	}) {
		t.Fatalf("normalized write = %#v", write)
	}
	writeType := reflect.TypeOf(write)
	for _, forbidden := range []string{"Token", "Secret", "Plaintext"} {
		if _, exists := writeType.FieldByName(forbidden); exists {
			t.Fatalf("CredentialWrite exposes %s", forbidden)
		}
	}
}

func TestIssueCredentialExactReplayReturnsMetadataErrorWithoutToken(t *testing.T) {
	t.Parallel()

	tenantID, userID, membershipID, accountID := serviceTestID(10), serviceTestID(11), serviceTestID(12), serviceTestID(13)
	replacementID := serviceTestID(14)
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	repository := &serviceRepositoryStub{authority: humanServiceAuthority(
		tenantID, userID, membershipID, authorization.TenantPermissionServiceAccountCredentialManage,
	)}
	write := CredentialWrite{
		CredentialID: replacementID, Label: "existing", FormatVersion: 1,
		Material: PresentedCredential{KeyVersion: 1}, ExpiresAt: now.Add(24 * time.Hour),
		Permissions: []authorization.ScopedPermission{{Permission: authorization.TenantPermissionAlertCreate, Scope: authorization.ScopeTenant}},
	}
	repository.issueResult = CredentialMutationResult{
		Credential: storedCredential(HumanParams{TenantID: tenantID, MembershipID: membershipID}, accountID, write, now, nil),
		Replayed:   true,
	}
	service := testAdministrationService(t, repository)
	input := IssueCredentialInput{
		Label: "existing", ExpiresAt: now.Add(24 * time.Hour), Permissions: write.Permissions,
		IdempotencyKey: "credential-issue-retry-0002", Audit: serviceAudit(15),
	}

	secret, err := service.IssueCredential(context.Background(), serviceActor(userID, tenantID), tenantID, accountID, input)
	if secret.Token != "" || !errors.Is(err, ErrOneTimeSecretAlreadyIssued) {
		t.Fatalf("IssueCredential() = (%#v, %v)", secret, err)
	}
	var replay *OneTimeSecretAlreadyIssuedError
	if !errors.As(err, &replay) || replay.CredentialID != replacementID || replay.ServiceAccountID != accountID {
		t.Fatalf("replay error = %#v", replay)
	}
}

func TestCredentialMutationRequiresExactHumanPermission(t *testing.T) {
	t.Parallel()

	tenantID, userID, membershipID, accountID := serviceTestID(20), serviceTestID(21), serviceTestID(22), serviceTestID(23)
	repository := &serviceRepositoryStub{authority: humanServiceAuthority(
		tenantID, userID, membershipID, authorization.TenantPermissionServiceAccountRead,
	)}
	service := testAdministrationService(t, repository)
	input := IssueCredentialInput{
		Label: "collector", ExpiresAt: service.now().Add(24 * time.Hour),
		Permissions:    []authorization.ScopedPermission{{Permission: authorization.TenantPermissionAlertCreate, Scope: authorization.ScopeTenant}},
		IdempotencyKey: "credential-issue-retry-0003", Audit: serviceAudit(24),
	}

	if _, err := service.IssueCredential(context.Background(), serviceActor(userID, tenantID), tenantID, accountID, input); !errors.Is(err, ErrForbidden) {
		t.Fatalf("IssueCredential() error = %v", err)
	}
	if repository.issueParams != nil {
		t.Fatal("repository mutation ran without credential.manage")
	}
}

func TestRotateReplayDoesNotPreloadRevokedPredecessor(t *testing.T) {
	t.Parallel()

	tenantID, userID, membershipID, accountID := serviceTestID(30), serviceTestID(31), serviceTestID(32), serviceTestID(33)
	previousID, replacementID := serviceTestID(34), serviceTestID(35)
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	repository := &serviceRepositoryStub{authority: humanServiceAuthority(
		tenantID, userID, membershipID, authorization.TenantPermissionServiceAccountCredentialManage,
	)}
	write := CredentialWrite{
		CredentialID: replacementID, Label: "replacement", FormatVersion: 1,
		Material: PresentedCredential{KeyVersion: 1}, ExpiresAt: now.Add(48 * time.Hour),
		Permissions: []authorization.ScopedPermission{{Permission: authorization.TenantPermissionAlertCreate, Scope: authorization.ScopeTenant}},
	}
	repository.rotateResult = CredentialMutationResult{
		Credential: storedCredential(HumanParams{TenantID: tenantID, MembershipID: membershipID}, accountID, write, now, &previousID),
		Replayed:   true,
	}
	service := testAdministrationService(t, repository)
	version := int64(4)
	input := RotateCredentialInput{
		Label: "replacement", ExpiresAt: now.Add(48 * time.Hour), Permissions: write.Permissions,
		Reason: "scheduled rotation", IdempotencyKey: "credential-rotate-retry-0001",
		ExpectedVersion: &version, Audit: serviceAudit(36),
	}

	_, err := service.RotateCredential(context.Background(), serviceActor(userID, tenantID), tenantID, accountID, previousID, input)
	if !errors.Is(err, ErrOneTimeSecretAlreadyIssued) || repository.getCredential != 0 || repository.rotateParams == nil {
		t.Fatalf("RotateCredential() error = %v, get calls = %d, params = %#v", err, repository.getCredential, repository.rotateParams)
	}
}

func TestCreateAccountNormalizesAndBindsMembership(t *testing.T) {
	t.Parallel()

	tenantID, userID, membershipID := serviceTestID(40), serviceTestID(41), serviceTestID(42)
	repository := &serviceRepositoryStub{authority: humanServiceAuthority(
		tenantID, userID, membershipID, authorization.TenantPermissionServiceAccountManage,
	)}
	service := testAdministrationService(t, repository)
	accountID := serviceTestID(43)
	service.newID = func() (uuid.UUID, error) { return accountID, nil }

	account, err := service.CreateAccount(context.Background(), serviceActor(userID, tenantID), tenantID, CreateAccountInput{
		Key: "alert_collector", DisplayName: "  Alert Collector  ", Description: "  Ingest only  ", Audit: serviceAudit(44),
	})
	if err != nil {
		t.Fatalf("CreateAccount() error = %v", err)
	}
	if account.ID != accountID || repository.createParams == nil ||
		repository.createParams.MembershipID != membershipID || repository.createParams.DisplayName != "Alert Collector" ||
		repository.createParams.Description != "Ingest only" {
		t.Fatalf("account = %#v, params = %#v", account, repository.createParams)
	}
}

func TestCreateAccountRejectsNonFreshProjection(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func(*Account)
	}{
		{name: "advanced version", mutate: func(value *Account) { value.Version = 2 }},
		{name: "advanced update timestamp", mutate: func(value *Account) { value.UpdatedAt = value.CreatedAt.Add(time.Microsecond) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			tenantID, userID, membershipID := serviceTestID(80), serviceTestID(81), serviceTestID(82)
			accountID := serviceTestID(83)
			now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
			created := Account{
				ID: accountID, TenantID: tenantID, Key: "alert_collector", DisplayName: "Alert Collector",
				Description: "Ingest only", State: AccountStateActive, CreatedByMembershipID: membershipID,
				Version: 1, CreatedAt: now, UpdatedAt: now,
			}
			test.mutate(&created)
			repository := &serviceRepositoryStub{
				authority:      humanServiceAuthority(tenantID, userID, membershipID, authorization.TenantPermissionServiceAccountManage),
				createdAccount: created,
			}
			service := testAdministrationService(t, repository)
			service.newID = func() (uuid.UUID, error) { return accountID, nil }
			if _, err := service.CreateAccount(
				context.Background(), serviceActor(userID, tenantID), tenantID,
				CreateAccountInput{Key: "alert_collector", DisplayName: "Alert Collector", Description: "Ingest only", Audit: serviceAudit(84)},
			); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("CreateAccount() error = %v, want unavailable", err)
			}
		})
	}
}

func TestUpdateAccountRequiresExactPostState(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name   string
		mutate func(*Account)
	}{
		{name: "key changed", mutate: func(value *Account) { value.Key = "other_collector" }},
		{name: "unpatched field changed", mutate: func(value *Account) { value.Description = "unexpected" }},
		{name: "creator changed", mutate: func(value *Account) { value.CreatedByMembershipID = serviceTestID(99) }},
		{name: "creation time changed", mutate: func(value *Account) { value.CreatedAt = value.CreatedAt.Add(time.Minute) }},
		{name: "version skipped", mutate: func(value *Account) { value.Version++ }},
		{name: "update time regressed", mutate: func(value *Account) { value.UpdatedAt = value.CreatedAt.Add(30 * time.Minute) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			tenantID, userID, membershipID := serviceTestID(85), serviceTestID(86), serviceTestID(87)
			accountID := serviceTestID(88)
			current := Account{
				ID: accountID, TenantID: tenantID, Key: "alert_collector", DisplayName: "Alert Collector",
				Description: "Ingest only", State: AccountStateActive, CreatedByMembershipID: membershipID,
				Version: 3, CreatedAt: createdAt, UpdatedAt: createdAt.Add(time.Hour),
			}
			updated := current
			updated.DisplayName = "Updated Collector"
			updated.Version = 4
			updated.UpdatedAt = createdAt.Add(2 * time.Hour)
			test.mutate(&updated)
			repository := &serviceRepositoryStub{
				authority: humanServiceAuthority(tenantID, userID, membershipID, authorization.TenantPermissionServiceAccountManage),
				account:   current, updatedAccount: updated,
			}
			service := testAdministrationService(t, repository)
			version := current.Version
			displayName := "Updated Collector"
			if _, err := service.UpdateAccount(
				context.Background(), serviceActor(userID, tenantID), tenantID, accountID,
				UpdateAccountInput{DisplayName: &displayName, ExpectedVersion: &version, Audit: serviceAudit(89)},
			); !errors.Is(err, ErrUnavailable) || repository.updateParams == nil {
				t.Fatalf("UpdateAccount() error = %v, params = %#v", err, repository.updateParams)
			}
		})
	}

	tenantID, userID, membershipID := serviceTestID(90), serviceTestID(91), serviceTestID(92)
	accountID := serviceTestID(93)
	current := Account{
		ID: accountID, TenantID: tenantID, Key: "alert_collector", DisplayName: "Alert Collector",
		State: AccountStateActive, CreatedByMembershipID: membershipID, Version: maximumResourceVersion,
		CreatedAt: createdAt, UpdatedAt: createdAt.Add(time.Hour),
	}
	repository := &serviceRepositoryStub{
		authority: humanServiceAuthority(tenantID, userID, membershipID, authorization.TenantPermissionServiceAccountManage),
		account:   current,
	}
	service := testAdministrationService(t, repository)
	version := current.Version
	displayName := "Updated Collector"
	if _, err := service.UpdateAccount(
		context.Background(), serviceActor(userID, tenantID), tenantID, accountID,
		UpdateAccountInput{DisplayName: &displayName, ExpectedVersion: &version, Audit: serviceAudit(94)},
	); !errors.Is(err, ErrConflict) || repository.updateParams != nil {
		t.Fatalf("exhausted UpdateAccount() error = %v, params = %#v", err, repository.updateParams)
	}
}

func TestVersionExhaustionFailsBeforeRepositoryMutation(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	tenantID, userID, membershipID := serviceTestID(120), serviceTestID(121), serviceTestID(122)
	accountID, grantID, roleID, credentialID := serviceTestID(123), serviceTestID(124), serviceTestID(125), serviceTestID(126)
	actor := serviceActor(userID, tenantID)

	t.Run("archive account", func(t *testing.T) {
		repository := &serviceRepositoryStub{
			authority: humanServiceAuthority(tenantID, userID, membershipID, authorization.TenantPermissionServiceAccountManage),
			account: Account{
				ID: accountID, TenantID: tenantID, Key: "alert_collector", DisplayName: "Alert Collector",
				State: AccountStateActive, CreatedByMembershipID: membershipID, Version: maximumResourceVersion,
				CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
			},
		}
		service := testAdministrationService(t, repository)
		version := int64(maximumResourceVersion)
		err := service.ArchiveAccount(context.Background(), actor, tenantID, accountID, ArchiveAccountInput{
			Reason: "retired", ExpectedVersion: &version, Audit: serviceAudit(127),
		})
		if !errors.Is(err, ErrConflict) || repository.archiveParams != nil {
			t.Fatalf("ArchiveAccount() error = %v, params = %#v", err, repository.archiveParams)
		}
	})

	t.Run("revoke role grant", func(t *testing.T) {
		grant := storedRoleGrant(tenantID, accountID, grantID, roleID, membershipID, userID)
		grant.Version = maximumResourceVersion
		entityTag, err := RoleGrantEntityTag(grant)
		if err != nil {
			t.Fatalf("RoleGrantEntityTag() error = %v", err)
		}
		repository := &serviceRepositoryStub{
			authority: humanServiceAuthority(
				tenantID, userID, membershipID,
				authorization.TenantPermissionServiceAccountManage,
				authorization.TenantPermissionRoleGrant,
			),
			roleGrant: grant,
		}
		service := testAdministrationService(t, repository)
		err = service.RevokeRoleGrant(context.Background(), actor, tenantID, accountID, grantID, RevokeRoleGrantInput{
			Reason: "superseded", ExpectedEntityTag: &entityTag, Audit: serviceAudit(129),
		})
		if !errors.Is(err, ErrConflict) || repository.revokeRole != nil {
			t.Fatalf("RevokeRoleGrant() error = %v, params = %#v", err, repository.revokeRole)
		}
	})

	t.Run("rotate credential", func(t *testing.T) {
		repository := &serviceRepositoryStub{authority: humanServiceAuthority(
			tenantID, userID, membershipID, authorization.TenantPermissionServiceAccountCredentialManage,
		)}
		service := testAdministrationService(t, repository)
		version := int64(maximumResourceVersion)
		_, err := service.RotateCredential(context.Background(), actor, tenantID, accountID, credentialID, RotateCredentialInput{
			Label: "replacement", ExpiresAt: now.Add(time.Hour),
			Permissions: []authorization.ScopedPermission{{Permission: authorization.TenantPermissionAlertCreate, Scope: authorization.ScopeTenant}},
			Reason:      "scheduled rotation", IdempotencyKey: "credential-rotate-exhausted-0001",
			ExpectedVersion: &version, Audit: serviceAudit(131),
		})
		if !errors.Is(err, ErrConflict) || repository.rotateParams != nil {
			t.Fatalf("RotateCredential() error = %v, params = %#v", err, repository.rotateParams)
		}
	})

	t.Run("revoke credential", func(t *testing.T) {
		repository := &serviceRepositoryStub{
			authority: humanServiceAuthority(
				tenantID, userID, membershipID, authorization.TenantPermissionServiceAccountCredentialManage,
			),
			credential: CredentialMetadata{
				ID: credentialID, TenantID: tenantID, ServiceAccountID: accountID,
				Label: "collector", FormatVersion: int16(credentialFormatVersion), KeyVersion: 1,
				Permissions:          []authorization.ScopedPermission{{Permission: authorization.TenantPermissionAlertCreate, Scope: authorization.ScopeTenant}},
				IssuedByMembershipID: membershipID, IssuedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
				State: CredentialStateActive, Version: maximumResourceVersion, UpdatedAt: now,
			},
		}
		service := testAdministrationService(t, repository)
		version := int64(maximumResourceVersion)
		err := service.RevokeCredential(context.Background(), actor, tenantID, accountID, credentialID, RevokeCredentialInput{
			Reason: "retired", ExpectedVersion: &version, Audit: serviceAudit(133),
		})
		if !errors.Is(err, ErrConflict) || repository.revokeCredential != nil {
			t.Fatalf("RevokeCredential() error = %v, params = %#v", err, repository.revokeCredential)
		}
	})
}

func TestIssueCredentialRejectsNonFreshProjection(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func(*CredentialMetadata)
	}{
		{name: "advanced version", mutate: func(value *CredentialMetadata) { value.Version = 2 }},
		{name: "already used", mutate: func(value *CredentialMetadata) {
			usedAt := value.IssuedAt.Add(time.Minute)
			usedIP := netip.MustParseAddr("198.51.100.70")
			value.LastUsedAt, value.LastUsedIP, value.UpdatedAt = &usedAt, &usedIP, usedAt
		}},
		{name: "advanced update timestamp", mutate: func(value *CredentialMetadata) { value.UpdatedAt = value.IssuedAt.Add(time.Minute) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			tenantID, userID, membershipID, accountID := serviceTestID(100), serviceTestID(101), serviceTestID(102), serviceTestID(103)
			repository := &serviceRepositoryStub{
				authority:   humanServiceAuthority(tenantID, userID, membershipID, authorization.TenantPermissionServiceAccountCredentialManage),
				mutateIssue: test.mutate,
			}
			service := testAdministrationService(t, repository)
			service.newID = func() (uuid.UUID, error) { return serviceTestID(104), nil }
			if secret, err := service.IssueCredential(
				context.Background(), serviceActor(userID, tenantID), tenantID, accountID,
				IssueCredentialInput{
					Label: "collector", ExpiresAt: service.now().Add(time.Hour),
					Permissions:    []authorization.ScopedPermission{{Permission: authorization.TenantPermissionAlertCreate, Scope: authorization.ScopeTenant}},
					IdempotencyKey: "credential-fresh-boundary", Audit: serviceAudit(105),
				},
			); !errors.Is(err, ErrUnavailable) || secret.Token != "" {
				t.Fatalf("IssueCredential() = (%#v, %v), want unavailable without token", secret, err)
			}
		})
	}
}

func TestGrantRoleRejectsFreshProjectionNotOwnedByAPI(t *testing.T) {
	t.Parallel()

	tenantID, userID, membershipID := serviceTestID(45), serviceTestID(46), serviceTestID(47)
	accountID, grantID, roleID := serviceTestID(48), serviceTestID(49), serviceTestID(50)
	repository := &serviceRepositoryStub{authority: humanServiceAuthority(
		tenantID, userID, membershipID,
		authorization.TenantPermissionServiceAccountManage,
		authorization.TenantPermissionRoleGrant,
	)}
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	repository.grantedRole = storedRoleGrant(tenantID, accountID, grantID, roleID, membershipID, userID)
	repository.grantedRole.Version = 1
	repository.grantedRole.SourceKind = authorization.AuthorizationSourceIdentityMapping
	repository.grantedRole.SourceKey = "identity:ldap"
	repository.grantedRole.SourceAuthoritative = true
	repository.grantedRole.ManagedByServiceAccountAPI = false
	service := testAdministrationService(t, repository)
	service.now = func() time.Time { return now }
	service.newID = func() (uuid.UUID, error) { return grantID, nil }

	if _, err := service.GrantRole(
		context.Background(), serviceActor(userID, tenantID), tenantID, accountID,
		GrantRoleInput{RoleID: roleID, Reason: "collector authority", Audit: serviceAudit(51)},
	); !errors.Is(err, ErrUnavailable) || repository.grantRole == nil {
		t.Fatalf("GrantRole() error = %v, params = %#v", err, repository.grantRole)
	}
}

func TestGrantRoleRejectsNonFreshOrMisattributedProjection(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func(*RoleGrant)
	}{
		{name: "advanced version", mutate: func(value *RoleGrant) { value.Version = 2 }},
		{name: "advanced update timestamp", mutate: func(value *RoleGrant) { value.UpdatedAt = value.GrantedAt.Add(time.Microsecond) }},
		{name: "different membership", mutate: func(value *RoleGrant) { value.GrantedByMembershipID = serviceTestID(119) }},
		{name: "different user", mutate: func(value *RoleGrant) { value.GrantedByUserID = serviceTestID(120) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			tenantID, userID, membershipID := serviceTestID(106), serviceTestID(107), serviceTestID(108)
			accountID, grantID, roleID := serviceTestID(109), serviceTestID(110), serviceTestID(111)
			grant := storedRoleGrant(tenantID, accountID, grantID, roleID, membershipID, userID)
			grant.Version = 1
			test.mutate(&grant)
			repository := &serviceRepositoryStub{
				authority: humanServiceAuthority(
					tenantID, userID, membershipID,
					authorization.TenantPermissionServiceAccountManage,
					authorization.TenantPermissionRoleGrant,
				),
				grantedRole: grant,
			}
			service := testAdministrationService(t, repository)
			service.newID = func() (uuid.UUID, error) { return grantID, nil }
			if _, err := service.GrantRole(
				context.Background(), serviceActor(userID, tenantID), tenantID, accountID,
				GrantRoleInput{RoleID: roleID, Reason: "collector authority", Audit: serviceAudit(112)},
			); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("GrantRole() error = %v, want unavailable", err)
			}
		})
	}
}

func TestRevokeRoleGrantRequiresCompleteCurrentRepresentationTag(t *testing.T) {
	t.Parallel()

	tenantID, userID, membershipID := serviceTestID(50), serviceTestID(51), serviceTestID(52)
	accountID, grantID, roleID := serviceTestID(53), serviceTestID(54), serviceTestID(55)
	repository := &serviceRepositoryStub{authority: humanServiceAuthority(
		tenantID, userID, membershipID,
		authorization.TenantPermissionServiceAccountManage,
		authorization.TenantPermissionRoleGrant,
	)}
	repository.roleGrant = storedRoleGrant(tenantID, accountID, grantID, roleID, membershipID, userID)
	service := testAdministrationService(t, repository)
	etag, err := RoleGrantEntityTag(repository.roleGrant)
	if err != nil {
		t.Fatalf("RoleGrantEntityTag() error = %v", err)
	}

	if err := service.RevokeRoleGrant(
		context.Background(), serviceActor(userID, tenantID), tenantID, accountID, grantID,
		RevokeRoleGrantInput{Reason: "superseded", ExpectedEntityTag: &etag, Audit: serviceAudit(56)},
	); err != nil {
		t.Fatalf("RevokeRoleGrant() error = %v", err)
	}
	if repository.revokeRole == nil || repository.revokeRole.ExpectedEntityTag != etag ||
		repository.revokeRole.Reason != "superseded" {
		t.Fatalf("revoke params = %#v", repository.revokeRole)
	}

	repository.revokeRole = nil
	stale := repository.roleGrant
	stale.Role.DisplayName = "Previous role name"
	staleTag, err := RoleGrantEntityTag(stale)
	if err != nil {
		t.Fatalf("stale RoleGrantEntityTag() error = %v", err)
	}
	if err := service.RevokeRoleGrant(
		context.Background(), serviceActor(userID, tenantID), tenantID, accountID, grantID,
		RevokeRoleGrantInput{Reason: "superseded", ExpectedEntityTag: &staleTag, Audit: serviceAudit(58)},
	); !errors.Is(err, ErrPreconditionFailed) || repository.revokeRole != nil {
		t.Fatalf("stale RevokeRoleGrant() error = %v, params = %#v", err, repository.revokeRole)
	}
	staleOwnership := repository.roleGrant
	staleOwnership.SourceKind = authorization.AuthorizationSourceIdentityMapping
	staleOwnership.SourceKey = "identity:ldap"
	staleOwnership.SourceAuthoritative = true
	staleOwnership.ManagedByServiceAccountAPI = false
	if !validRoleGrant(staleOwnership, tenantID, accountID) {
		t.Fatal("stale ownership fixture is not a valid public role-grant representation")
	}
	staleOwnershipTag, err := RoleGrantEntityTag(staleOwnership)
	if err != nil {
		t.Fatalf("stale ownership RoleGrantEntityTag() error = %v", err)
	}
	if err := service.RevokeRoleGrant(
		context.Background(), serviceActor(userID, tenantID), tenantID, accountID, grantID,
		RevokeRoleGrantInput{Reason: "superseded", ExpectedEntityTag: &staleOwnershipTag, Audit: serviceAudit(59)},
	); !errors.Is(err, ErrPreconditionFailed) || repository.revokeRole != nil {
		t.Fatalf("stale ownership RevokeRoleGrant() error = %v, params = %#v", err, repository.revokeRole)
	}

	repository.roleGrant.State = RoleGrantStateExpired
	expiredTag, err := RoleGrantEntityTag(repository.roleGrant)
	if err != nil {
		t.Fatalf("expired RoleGrantEntityTag() error = %v", err)
	}
	if err := service.RevokeRoleGrant(
		context.Background(), serviceActor(userID, tenantID), tenantID, accountID, grantID,
		RevokeRoleGrantInput{Reason: "superseded", ExpectedEntityTag: &expiredTag, Audit: serviceAudit(60)},
	); !errors.Is(err, ErrConflict) || repository.revokeRole != nil {
		t.Fatalf("expired RevokeRoleGrant() error = %v, params = %#v", err, repository.revokeRole)
	}
}

func TestCredentialValidationRejectsWiderOrDuplicateAuthority(t *testing.T) {
	t.Parallel()

	valid := authorization.ScopedPermission{Permission: authorization.TenantPermissionAlertCreate, Scope: authorization.ScopeTenant}
	for name, values := range map[string][]authorization.ScopedPermission{
		"empty":           {},
		"duplicate":       {valid, valid},
		"human admin":     {{Permission: authorization.TenantPermissionServiceAccountManage, Scope: authorization.ScopeTenant}},
		"different scope": {{Permission: authorization.TenantPermissionAlertCreate, Scope: authorization.ScopeOwn}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizeCredentialPermissions(values); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("normalizeCredentialPermissions() error = %v", err)
			}
		})
	}
}

func TestProjectionValidationRejectsImpossibleLiveStates(t *testing.T) {
	t.Parallel()

	tenantID, accountID := serviceTestID(70), serviceTestID(71)
	grant := storedRoleGrant(
		tenantID, accountID, serviceTestID(72), serviceTestID(73), serviceTestID(74), serviceTestID(75),
	)
	retiredAt := grant.GrantedAt.Add(time.Minute)
	grant.SourceRetiredAt = &retiredAt
	grant.ManagedByServiceAccountAPI = false
	if validRoleGrant(grant, tenantID, accountID) {
		t.Fatal("active role grant with a retired source was accepted")
	}

	issuedAt := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	credential := CredentialMetadata{
		ID: serviceTestID(76), TenantID: tenantID, ServiceAccountID: accountID,
		Label: "collector", FormatVersion: int16(credentialFormatVersion), KeyVersion: 1,
		Permissions:          []authorization.ScopedPermission{{Permission: authorization.TenantPermissionAlertCreate, Scope: authorization.ScopeTenant}},
		IssuedByMembershipID: serviceTestID(77), IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(time.Hour),
		State: CredentialStateExpired, Version: 2, UpdatedAt: issuedAt.Add(2 * time.Hour),
	}
	lastUsedAt := credential.ExpiresAt.Add(time.Microsecond)
	lastUsedIP := netip.MustParseAddr("198.51.100.20")
	credential.LastUsedAt, credential.LastUsedIP = &lastUsedAt, &lastUsedIP
	if validCredential(credential, tenantID, accountID) {
		t.Fatal("credential used after its exclusive expiry was accepted")
	}
	lastUsedAt = issuedAt.Add(30 * time.Minute)
	credential.LastUsedAt = &lastUsedAt
	credential.UpdatedAt = issuedAt.Add(15 * time.Minute)
	if validCredential(credential, tenantID, accountID) {
		t.Fatal("credential use newer than its representation was accepted")
	}

	revokedAt := issuedAt.Add(20 * time.Minute)
	lastUsedAt = issuedAt.Add(30 * time.Minute)
	revokedMembershipID, revokedUserID := serviceTestID(78), serviceTestID(79)
	revokeReason := "credential replaced"
	credential.State = CredentialStateRevoked
	credential.RevokedAt = &revokedAt
	credential.RevokedByMembershipID = &revokedMembershipID
	credential.RevokedByUserID = &revokedUserID
	credential.RevokeReason = &revokeReason
	credential.LastUsedAt = &lastUsedAt
	credential.UpdatedAt = issuedAt.Add(40 * time.Minute)
	if validCredential(credential, tenantID, accountID) {
		t.Fatal("credential use after revocation was accepted")
	}
}

func TestProjectionValidationRejectsNonCanonicalStoredTimes(t *testing.T) {
	t.Parallel()

	tenantID, accountID := serviceTestID(121), serviceTestID(122)
	membershipID, userID := serviceTestID(123), serviceTestID(124)
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	nonUTC := func(value time.Time) time.Time {
		return value.In(time.FixedZone("database-offset-zero", 0))
	}
	subMicrosecond := func(value time.Time) time.Time { return value.Add(time.Nanosecond) }

	account := Account{
		ID: accountID, TenantID: tenantID, Key: "alert_collector", DisplayName: "Alert Collector",
		State: AccountStateActive, CreatedByMembershipID: membershipID, Version: 1,
		CreatedAt: now, UpdatedAt: now,
	}
	archivedAccount := account
	archivedAt := now.Add(time.Hour)
	archiveReason := "retired"
	archivedAccount.State = AccountStateArchived
	archivedAccount.ArchivedAt = &archivedAt
	archivedAccount.ArchivedByMembershipID = &membershipID
	archivedAccount.ArchiveReason = &archiveReason
	archivedAccount.UpdatedAt = archivedAt

	grant := storedRoleGrant(tenantID, accountID, serviceTestID(125), serviceTestID(126), membershipID, userID)
	expiresAt := now.Add(time.Hour)
	grant.ExpiresAt = &expiresAt
	expiredGrant := grant
	retiredAt := now.Add(30 * time.Minute)
	expiredGrant.State = RoleGrantStateExpired
	expiredGrant.SourceRetiredAt = &retiredAt
	expiredGrant.ManagedByServiceAccountAPI = false
	revokedGrant := grant
	grantRevokedAt := now.Add(20 * time.Minute)
	grantRevokeReason := "superseded"
	revokedGrant.State = RoleGrantStateRevoked
	revokedGrant.RevokedAt = &grantRevokedAt
	revokedGrant.RevokedByMembershipID = &membershipID
	revokedGrant.RevokedByUserID = &userID
	revokedGrant.RevokeReason = &grantRevokeReason
	revokedGrant.UpdatedAt = grantRevokedAt

	credential := CredentialMetadata{
		ID: serviceTestID(127), TenantID: tenantID, ServiceAccountID: accountID,
		Label: "collector", FormatVersion: int16(credentialFormatVersion), KeyVersion: 1,
		Permissions:          []authorization.ScopedPermission{{Permission: authorization.TenantPermissionAlertCreate, Scope: authorization.ScopeTenant}},
		IssuedByMembershipID: membershipID, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		State: CredentialStateActive, Version: 1, UpdatedAt: now,
	}
	usedCredential := credential
	lastUsedAt := now.Add(10 * time.Minute)
	lastUsedIP := netip.MustParseAddr("198.51.100.29")
	usedCredential.LastUsedAt = &lastUsedAt
	usedCredential.LastUsedIP = &lastUsedIP
	usedCredential.UpdatedAt = lastUsedAt
	revokedCredential := usedCredential
	credentialRevokedAt := now.Add(20 * time.Minute)
	credentialRevokeReason := "replaced"
	revokedCredential.State = CredentialStateRevoked
	revokedCredential.RevokedAt = &credentialRevokedAt
	revokedCredential.RevokedByMembershipID = &membershipID
	revokedCredential.RevokedByUserID = &userID
	revokedCredential.RevokeReason = &credentialRevokeReason
	revokedCredential.UpdatedAt = credentialRevokedAt

	tests := []struct {
		name  string
		valid func() bool
	}{
		{name: "account creation location", valid: func() bool {
			value := account
			value.CreatedAt = nonUTC(value.CreatedAt)
			return validAccount(value, tenantID)
		}},
		{name: "account update precision", valid: func() bool {
			value := account
			value.UpdatedAt = subMicrosecond(value.UpdatedAt)
			return validAccount(value, tenantID)
		}},
		{name: "account archive location", valid: func() bool {
			value := archivedAccount
			changed := nonUTC(*value.ArchivedAt)
			value.ArchivedAt = &changed
			return validAccount(value, tenantID)
		}},
		{name: "grant creation location", valid: func() bool {
			value := grant
			value.GrantedAt = nonUTC(value.GrantedAt)
			return validRoleGrant(value, tenantID, accountID)
		}},
		{name: "grant update precision", valid: func() bool {
			value := grant
			value.UpdatedAt = subMicrosecond(value.UpdatedAt)
			return validRoleGrant(value, tenantID, accountID)
		}},
		{name: "grant expiry location", valid: func() bool {
			value := grant
			changed := nonUTC(*value.ExpiresAt)
			value.ExpiresAt = &changed
			return validRoleGrant(value, tenantID, accountID)
		}},
		{name: "grant source retirement precision", valid: func() bool {
			value := expiredGrant
			changed := subMicrosecond(*value.SourceRetiredAt)
			value.SourceRetiredAt = &changed
			return validRoleGrant(value, tenantID, accountID)
		}},
		{name: "grant revocation location", valid: func() bool {
			value := revokedGrant
			changed := nonUTC(*value.RevokedAt)
			value.RevokedAt = &changed
			return validRoleGrant(value, tenantID, accountID)
		}},
		{name: "credential issue location", valid: func() bool {
			value := credential
			value.IssuedAt = nonUTC(value.IssuedAt)
			return validCredential(value, tenantID, accountID)
		}},
		{name: "credential expiry precision", valid: func() bool {
			value := credential
			value.ExpiresAt = subMicrosecond(value.ExpiresAt)
			return validCredential(value, tenantID, accountID)
		}},
		{name: "credential update location", valid: func() bool {
			value := credential
			value.UpdatedAt = nonUTC(value.UpdatedAt)
			return validCredential(value, tenantID, accountID)
		}},
		{name: "credential last-use precision", valid: func() bool {
			value := usedCredential
			changed := subMicrosecond(*value.LastUsedAt)
			value.LastUsedAt = &changed
			value.UpdatedAt = changed
			return validCredential(value, tenantID, accountID)
		}},
		{name: "credential revocation location", valid: func() bool {
			value := revokedCredential
			changed := nonUTC(*value.RevokedAt)
			value.RevokedAt = &changed
			return validCredential(value, tenantID, accountID)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if test.valid() {
				t.Fatal("non-canonical stored timestamp was accepted")
			}
		})
	}
}

func testAdministrationService(t *testing.T, repository Repository) *Service {
	t.Helper()
	random := bytes.NewReader(bytes.Repeat([]byte{0xA5}, 512))
	keyring, err := newCredentialKeyring(1, map[int16][]byte{1: bytes.Repeat([]byte{0x91}, 32)}, random)
	if err != nil {
		t.Fatalf("newCredentialKeyring() error = %v", err)
	}
	service, err := NewService(repository, keyring)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	service.now = func() time.Time { return time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC) }
	return service
}

func humanServiceAuthority(tenantID, userID, membershipID uuid.UUID, permissions ...authorization.TenantPermission) authorization.TenantAuthority {
	grants := make([]authorization.ScopedPermission, len(permissions))
	for index, permission := range permissions {
		grants[index] = authorization.ScopedPermission{Permission: permission, Scope: authorization.ScopeTenant}
	}
	return authorization.TenantAuthority{
		TenantID: tenantID, Principal: authorization.TenantPrincipal{ID: userID, Kind: authorization.PrincipalKindHuman},
		MembershipID: membershipID, MembershipStatus: authorization.MembershipStatusActive,
		LegacyRole: authorization.LegacyMembershipRoleTenantAdmin, Permissions: grants,
		EvaluatedAt: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC),
	}
}

func serviceActor(userID, tenantID uuid.UUID) authorization.Actor {
	return authorization.Actor{
		UserID: userID, SessionID: serviceTestID(250), ActiveTenantID: tenantID, AuthenticationMethod: "local_password_totp",
	}
}

func serviceAudit(seed byte) authorization.AuditContext {
	return authorization.AuditContext{
		RequestID: serviceTestID(seed), CorrelationID: serviceTestID(seed + 1),
		RemoteAddress: netip.MustParseAddr("198.51.100.20"), UserAgent: "service-account-test",
	}
}

func storedAccount(params CreateAccountParams) Account {
	return Account{
		ID: params.ServiceAccountID, TenantID: params.TenantID, Key: params.Key,
		DisplayName: params.DisplayName, Description: params.Description, State: AccountStateActive,
		CreatedByMembershipID: params.MembershipID, Version: 1,
		CreatedAt: params.OccurredAt, UpdatedAt: params.OccurredAt,
	}
}

func storedCredential(human HumanParams, serviceAccountID uuid.UUID, write CredentialWrite, issuedAt time.Time, rotatedFrom *uuid.UUID) CredentialMetadata {
	return CredentialMetadata{
		ID: write.CredentialID, TenantID: human.TenantID, ServiceAccountID: serviceAccountID,
		Label: write.Label, FormatVersion: write.FormatVersion, KeyVersion: write.Material.KeyVersion,
		Permissions:          append([]authorization.ScopedPermission(nil), write.Permissions...),
		Networks:             append([]netip.Prefix(nil), write.Networks...),
		IssuedByMembershipID: human.MembershipID, IssuedAt: issuedAt, ExpiresAt: write.ExpiresAt,
		RotatedFromCredentialID: rotatedFrom, State: CredentialStateActive,
		Version: 1, UpdatedAt: issuedAt,
	}
}

func storedRoleGrant(tenantID, accountID, grantID, roleID, membershipID, userID uuid.UUID) RoleGrant {
	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	return RoleGrant{
		ID: grantID, TenantID: tenantID, ServiceAccountID: accountID,
		Role:     RoleSummary{ID: roleID, Key: "alert_ingest", DisplayName: "Alert ingest", System: false},
		SourceID: serviceTestID(249), SourceKind: authorization.AuthorizationSourceManual,
		SourceKey: "manual", SourceAuthoritative: false,
		GrantedByMembershipID: membershipID, GrantedByUserID: userID,
		GrantReason: "collector authority", GrantedAt: now, State: RoleGrantStateActive,
		Version: 3, UpdatedAt: now, ManagedByServiceAccountAPI: true,
	}
}

func serviceTestID(last byte) uuid.UUID {
	value := uuid.MustParse("00000000-0000-7000-8000-000000000000")
	value[15] = last
	return value
}
