package serviceaccount

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type Service struct {
	repository Repository
	evaluator  authorization.Evaluator
	keyring    CredentialKeyring
	now        func() time.Time
	newID      func() (uuid.UUID, error)
}

func NewService(repository Repository, keyring CredentialKeyring) (*Service, error) {
	if repository == nil {
		return nil, errors.New("service-account repository is required")
	}
	if keyring.activeVersion < 1 || len(keyring.keys) == 0 {
		return nil, errors.New("API credential keyring is required")
	}
	return &Service{
		repository: repository,
		evaluator:  authorization.Evaluator{},
		keyring:    keyring,
		now:        time.Now,
		newID:      uuid.NewV7,
	}, nil
}

func (s *Service) ListAccounts(ctx context.Context, actor authorization.Actor, tenantID uuid.UUID, input ListAccountsInput) (AccountPage, error) {
	page, err := normalizedPage(input.PageInput)
	if err != nil {
		return AccountPage{}, err
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionServiceAccountRead)
	if err != nil {
		return AccountPage{}, err
	}
	rows, err := s.repository.ListAccounts(ctx, ListAccountsParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		After:       page.After, Limit: int32(page.Limit + 1), IncludeArchived: input.IncludeArchived,
	})
	if err != nil {
		return AccountPage{}, mapRepositoryError(err)
	}
	for _, row := range rows {
		if !validAccount(row, tenantID) || !input.IncludeArchived && row.State == AccountStateArchived {
			return AccountPage{}, ErrUnavailable
		}
	}
	items, next, err := boundedPage(rows, page.After, page.Limit, func(value Account) uuid.UUID { return value.ID })
	if err != nil {
		return AccountPage{}, err
	}
	return AccountPage{Items: items, NextCursor: next}, nil
}

func (s *Service) GetAccount(ctx context.Context, actor authorization.Actor, tenantID, serviceAccountID uuid.UUID) (Account, error) {
	if !validUUIDv7(serviceAccountID) {
		return Account{}, ErrInvalidInput
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionServiceAccountRead)
	if err != nil {
		return Account{}, err
	}
	return s.loadAccount(ctx, actor, authority.MembershipID, tenantID, serviceAccountID)
}

func (s *Service) CreateAccount(ctx context.Context, actor authorization.Actor, tenantID uuid.UUID, input CreateAccountInput) (Account, error) {
	normalized, err := normalizeCreateAccount(input)
	if err != nil {
		return Account{}, err
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionServiceAccountManage)
	if err != nil {
		return Account{}, err
	}
	now, err := s.currentTime()
	if err != nil {
		return Account{}, err
	}
	serviceAccountID, err := s.nextID()
	if err != nil {
		return Account{}, err
	}
	account, err := s.repository.CreateAccount(ctx, CreateAccountParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		Audit:       normalized.Audit, OccurredAt: now, ServiceAccountID: serviceAccountID,
		Key: normalized.Key, DisplayName: normalized.DisplayName, Description: normalized.Description,
	})
	if err != nil {
		return Account{}, mapRepositoryError(err)
	}
	if !validAccount(account, tenantID) || account.ID != serviceAccountID || account.State != AccountStateActive ||
		account.Key != normalized.Key || account.DisplayName != normalized.DisplayName ||
		account.Description != normalized.Description || account.CreatedByMembershipID != authority.MembershipID ||
		account.Version != 1 || !account.UpdatedAt.Equal(account.CreatedAt) {
		return Account{}, ErrUnavailable
	}
	return account, nil
}

func (s *Service) UpdateAccount(ctx context.Context, actor authorization.Actor, tenantID, serviceAccountID uuid.UUID, input UpdateAccountInput) (Account, error) {
	normalized, version, err := normalizeUpdateAccount(serviceAccountID, input)
	if err != nil {
		return Account{}, err
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionServiceAccountManage)
	if err != nil {
		return Account{}, err
	}
	current, err := s.loadAccount(ctx, actor, authority.MembershipID, tenantID, serviceAccountID)
	if err != nil {
		return Account{}, err
	}
	if current.Version != version {
		return Account{}, ErrPreconditionFailed
	}
	if current.State == AccountStateArchived {
		return Account{}, ErrConflict
	}
	if current.Version >= maximumResourceVersion {
		return Account{}, ErrConflict
	}
	now, err := s.currentTime()
	if err != nil {
		return Account{}, err
	}
	account, err := s.repository.UpdateAccount(ctx, UpdateAccountParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		Audit:       normalized.Audit, OccurredAt: now, ServiceAccountID: serviceAccountID,
		DisplayName: normalized.DisplayName, Description: normalized.Description, ExpectedVersion: version,
	})
	if err != nil {
		return Account{}, mapRepositoryError(err)
	}
	expectedDisplayName, expectedDescription := current.DisplayName, current.Description
	if normalized.DisplayName != nil {
		expectedDisplayName = *normalized.DisplayName
	}
	if normalized.Description != nil {
		expectedDescription = *normalized.Description
	}
	if !validAccount(account, tenantID) || account.ID != serviceAccountID || account.State != AccountStateActive ||
		account.Key != current.Key || account.DisplayName != expectedDisplayName || account.Description != expectedDescription ||
		account.CreatedByMembershipID != current.CreatedByMembershipID || !account.CreatedAt.Equal(current.CreatedAt) ||
		account.Version != current.Version+1 || account.UpdatedAt.Before(current.UpdatedAt) {
		return Account{}, ErrUnavailable
	}
	return account, nil
}

func (s *Service) ArchiveAccount(ctx context.Context, actor authorization.Actor, tenantID, serviceAccountID uuid.UUID, input ArchiveAccountInput) error {
	normalized, version, err := normalizeArchiveAccount(serviceAccountID, input)
	if err != nil {
		return err
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionServiceAccountManage)
	if err != nil {
		return err
	}
	current, err := s.loadAccount(ctx, actor, authority.MembershipID, tenantID, serviceAccountID)
	if err != nil {
		return err
	}
	if current.Version != version {
		return ErrPreconditionFailed
	}
	if current.State == AccountStateArchived {
		return ErrConflict
	}
	if current.Version >= maximumResourceVersion {
		return ErrConflict
	}
	now, err := s.currentTime()
	if err != nil {
		return err
	}
	return mapRepositoryError(s.repository.ArchiveAccount(ctx, ArchiveAccountParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		Audit:       normalized.Audit, OccurredAt: now, ServiceAccountID: serviceAccountID,
		Reason: normalized.Reason, ExpectedVersion: version,
	}))
}

func (s *Service) ListRoleGrants(ctx context.Context, actor authorization.Actor, tenantID, serviceAccountID uuid.UUID, input ListRoleGrantsInput) (RoleGrantPage, error) {
	if !validUUIDv7(serviceAccountID) {
		return RoleGrantPage{}, ErrInvalidInput
	}
	page, err := normalizedPage(input.PageInput)
	if err != nil {
		return RoleGrantPage{}, err
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionServiceAccountRead)
	if err != nil {
		return RoleGrantPage{}, err
	}
	rows, err := s.repository.ListRoleGrants(ctx, ListRoleGrantsParams{
		HumanParams:      HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		ServiceAccountID: serviceAccountID, After: page.After, Limit: int32(page.Limit + 1), IncludeRevoked: input.IncludeRevoked,
	})
	if err != nil {
		return RoleGrantPage{}, mapRepositoryError(err)
	}
	for _, row := range rows {
		if !validRoleGrant(row, tenantID, serviceAccountID) || !input.IncludeRevoked && row.State == RoleGrantStateRevoked {
			return RoleGrantPage{}, ErrUnavailable
		}
	}
	items, next, err := boundedPage(rows, page.After, page.Limit, func(value RoleGrant) uuid.UUID { return value.ID })
	if err != nil {
		return RoleGrantPage{}, err
	}
	return RoleGrantPage{Items: items, NextCursor: next}, nil
}

func (s *Service) GetRoleGrant(ctx context.Context, actor authorization.Actor, tenantID, serviceAccountID, grantID uuid.UUID) (RoleGrant, error) {
	if !validUUIDv7(serviceAccountID) || !validUUIDv7(grantID) {
		return RoleGrant{}, ErrInvalidInput
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionServiceAccountRead)
	if err != nil {
		return RoleGrant{}, err
	}
	return s.loadRoleGrant(ctx, actor, authority.MembershipID, tenantID, serviceAccountID, grantID)
}

func (s *Service) GrantRole(ctx context.Context, actor authorization.Actor, tenantID, serviceAccountID uuid.UUID, input GrantRoleInput) (RoleGrant, error) {
	normalized, err := normalizeGrantRole(serviceAccountID, input)
	if err != nil {
		return RoleGrant{}, err
	}
	authority, err := s.resolveAndRequireAll(ctx, actor, tenantID,
		authorization.TenantPermissionServiceAccountManage,
		authorization.TenantPermissionRoleGrant,
	)
	if err != nil {
		return RoleGrant{}, err
	}
	now, err := s.currentTime()
	if err != nil {
		return RoleGrant{}, err
	}
	if normalized.ExpiresAt != nil && !normalized.ExpiresAt.After(now) {
		return RoleGrant{}, ErrInvalidInput
	}
	grantID, err := s.nextID()
	if err != nil {
		return RoleGrant{}, err
	}
	grant, err := s.repository.GrantRole(ctx, GrantRoleParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		Audit:       normalized.Audit, OccurredAt: now, ServiceAccountID: serviceAccountID,
		GrantID: grantID, RoleID: normalized.RoleID, Reason: normalized.Reason, ExpiresAt: normalized.ExpiresAt,
	})
	if err != nil {
		return RoleGrant{}, mapRepositoryError(err)
	}
	if !validRoleGrant(grant, tenantID, serviceAccountID) || grant.ID != grantID ||
		grant.Role.ID != normalized.RoleID || grant.State != RoleGrantStateActive ||
		!grant.ManagedByServiceAccountAPI ||
		grant.GrantedByMembershipID != authority.MembershipID || grant.GrantedByUserID != actor.UserID ||
		grant.Version != 1 || !grant.UpdatedAt.Equal(grant.GrantedAt) ||
		grant.GrantReason != normalized.Reason || !equalOptionalTime(grant.ExpiresAt, normalized.ExpiresAt) {
		return RoleGrant{}, ErrUnavailable
	}
	return grant, nil
}

func (s *Service) RevokeRoleGrant(ctx context.Context, actor authorization.Actor, tenantID, serviceAccountID, grantID uuid.UUID, input RevokeRoleGrantInput) error {
	normalized, _, err := normalizeRevokeRoleGrant(serviceAccountID, grantID, input)
	if err != nil {
		return err
	}
	authority, err := s.resolveAndRequireAll(ctx, actor, tenantID,
		authorization.TenantPermissionServiceAccountManage,
		authorization.TenantPermissionRoleGrant,
	)
	if err != nil {
		return err
	}
	current, err := s.loadRoleGrant(ctx, actor, authority.MembershipID, tenantID, serviceAccountID, grantID)
	if err != nil {
		return err
	}
	currentEntityTag, err := RoleGrantEntityTag(current)
	if err != nil {
		return ErrUnavailable
	}
	if currentEntityTag != *normalized.ExpectedEntityTag {
		return ErrPreconditionFailed
	}
	if current.State != RoleGrantStateActive || !current.ManagedByServiceAccountAPI {
		return ErrConflict
	}
	if current.Version >= maximumResourceVersion {
		return ErrConflict
	}
	now, err := s.currentTime()
	if err != nil {
		return err
	}
	return mapRepositoryError(s.repository.RevokeRoleGrant(ctx, RevokeRoleGrantParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		Audit:       normalized.Audit, OccurredAt: now, ServiceAccountID: serviceAccountID,
		GrantID: grantID, Reason: normalized.Reason, ExpectedEntityTag: *normalized.ExpectedEntityTag,
	}))
}

func (s *Service) ListCredentials(ctx context.Context, actor authorization.Actor, tenantID, serviceAccountID uuid.UUID, input ListCredentialsInput) (CredentialPage, error) {
	if !validUUIDv7(serviceAccountID) {
		return CredentialPage{}, ErrInvalidInput
	}
	page, err := normalizedPage(input.PageInput)
	if err != nil {
		return CredentialPage{}, err
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionServiceAccountRead)
	if err != nil {
		return CredentialPage{}, err
	}
	rows, err := s.repository.ListCredentials(ctx, ListCredentialsParams{
		HumanParams:      HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		ServiceAccountID: serviceAccountID, After: page.After, Limit: int32(page.Limit + 1), IncludeRevoked: input.IncludeRevoked,
	})
	if err != nil {
		return CredentialPage{}, mapRepositoryError(err)
	}
	for _, row := range rows {
		if !validCredential(row, tenantID, serviceAccountID) || !input.IncludeRevoked && row.State == CredentialStateRevoked {
			return CredentialPage{}, ErrUnavailable
		}
	}
	items, next, err := boundedPage(rows, page.After, page.Limit, func(value CredentialMetadata) uuid.UUID { return value.ID })
	if err != nil {
		return CredentialPage{}, err
	}
	return CredentialPage{Items: items, NextCursor: next}, nil
}

func (s *Service) GetCredential(ctx context.Context, actor authorization.Actor, tenantID, serviceAccountID, credentialID uuid.UUID) (CredentialMetadata, error) {
	if !validUUIDv7(serviceAccountID) || !validUUIDv7(credentialID) {
		return CredentialMetadata{}, ErrInvalidInput
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionServiceAccountRead)
	if err != nil {
		return CredentialMetadata{}, err
	}
	return s.loadCredential(ctx, actor, authority.MembershipID, tenantID, serviceAccountID, credentialID)
}

func (s *Service) IssueCredential(ctx context.Context, actor authorization.Actor, tenantID, serviceAccountID uuid.UUID, input IssueCredentialInput) (CredentialSecret, error) {
	normalized, err := normalizeIssueCredential(serviceAccountID, input)
	if err != nil {
		return CredentialSecret{}, err
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionServiceAccountCredentialManage)
	if err != nil {
		return CredentialSecret{}, err
	}
	now, err := s.currentTime()
	if err != nil {
		return CredentialSecret{}, err
	}
	if !validCredentialExpiry(now, normalized.ExpiresAt) {
		return CredentialSecret{}, ErrInvalidInput
	}
	credentialID, err := s.nextID()
	if err != nil {
		return CredentialSecret{}, err
	}
	issued, err := s.keyring.Issue()
	if err != nil {
		return CredentialSecret{}, ErrUnavailable
	}
	defer clear(issued.Digest[:])
	write := CredentialWrite{
		CredentialID: credentialID, Label: normalized.Label,
		FormatVersion: int16(credentialFormatVersion), Material: issued.PresentedCredential,
		ExpiresAt:   normalized.ExpiresAt,
		Permissions: append([]authorization.ScopedPermission(nil), normalized.Permissions...),
		Networks:    append([]netip.Prefix(nil), normalized.Networks...),
		KeyDigest:   digestCredentialIdempotencyKey(normalized.IdempotencyKey),
		RequestDigest: digestCredentialRequest(
			"service_account.credential.issue", serviceAccountID, uuid.Nil, 0,
			normalized.Label, normalized.ExpiresAt, normalized.Permissions, normalized.Networks, "",
		),
	}
	defer clear(write.Material.Digest[:])
	result, err := s.repository.IssueCredential(ctx, IssueCredentialParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		Audit:       normalized.Audit, OccurredAt: now, ServiceAccountID: serviceAccountID, Write: write,
	})
	if err != nil {
		issued.Token = ""
		return CredentialSecret{}, mapRepositoryError(err)
	}
	if !validCredential(result.Credential, tenantID, serviceAccountID) {
		issued.Token = ""
		return CredentialSecret{}, ErrUnavailable
	}
	if result.Replayed {
		issued.Token = ""
		return CredentialSecret{}, &OneTimeSecretAlreadyIssuedError{
			ServiceAccountID: serviceAccountID,
			CredentialID:     result.Credential.ID,
			Version:          result.Credential.Version,
		}
	}
	if !credentialMatchesWrite(result.Credential, write, authority.MembershipID, nil) {
		issued.Token = ""
		return CredentialSecret{}, ErrUnavailable
	}
	return CredentialSecret{Credential: result.Credential, Token: issued.Token}, nil
}

func (s *Service) RotateCredential(ctx context.Context, actor authorization.Actor, tenantID, serviceAccountID, previousCredentialID uuid.UUID, input RotateCredentialInput) (CredentialSecret, error) {
	normalized, version, err := normalizeRotateCredential(serviceAccountID, previousCredentialID, input)
	if err != nil {
		return CredentialSecret{}, err
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionServiceAccountCredentialManage)
	if err != nil {
		return CredentialSecret{}, err
	}
	if version >= maximumResourceVersion {
		return CredentialSecret{}, ErrConflict
	}
	now, err := s.currentTime()
	if err != nil {
		return CredentialSecret{}, err
	}
	if !validCredentialExpiry(now, normalized.ExpiresAt) {
		return CredentialSecret{}, ErrInvalidInput
	}
	credentialID, err := s.nextID()
	if err != nil {
		return CredentialSecret{}, err
	}
	issued, err := s.keyring.Issue()
	if err != nil {
		return CredentialSecret{}, ErrUnavailable
	}
	defer clear(issued.Digest[:])
	write := CredentialWrite{
		CredentialID: credentialID, Label: normalized.Label,
		FormatVersion: int16(credentialFormatVersion), Material: issued.PresentedCredential,
		ExpiresAt:   normalized.ExpiresAt,
		Permissions: append([]authorization.ScopedPermission(nil), normalized.Permissions...),
		Networks:    append([]netip.Prefix(nil), normalized.Networks...),
		KeyDigest:   digestCredentialIdempotencyKey(normalized.IdempotencyKey),
		RequestDigest: digestCredentialRequest(
			"service_account.credential.rotate", serviceAccountID, previousCredentialID, version,
			normalized.Label, normalized.ExpiresAt, normalized.Permissions, normalized.Networks, normalized.Reason,
		),
	}
	defer clear(write.Material.Digest[:])
	result, err := s.repository.RotateCredential(ctx, RotateCredentialParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		Audit:       normalized.Audit, OccurredAt: now, ServiceAccountID: serviceAccountID,
		PreviousCredentialID: previousCredentialID, ExpectedVersion: version, Reason: normalized.Reason, Write: write,
	})
	if err != nil {
		issued.Token = ""
		return CredentialSecret{}, mapRepositoryError(err)
	}
	if !validCredential(result.Credential, tenantID, serviceAccountID) {
		issued.Token = ""
		return CredentialSecret{}, ErrUnavailable
	}
	if result.Replayed {
		issued.Token = ""
		return CredentialSecret{}, &OneTimeSecretAlreadyIssuedError{
			ServiceAccountID: serviceAccountID,
			CredentialID:     result.Credential.ID,
			Version:          result.Credential.Version,
		}
	}
	if !credentialMatchesWrite(result.Credential, write, authority.MembershipID, &previousCredentialID) {
		issued.Token = ""
		return CredentialSecret{}, ErrUnavailable
	}
	return CredentialSecret{Credential: result.Credential, Token: issued.Token}, nil
}

func (s *Service) RevokeCredential(ctx context.Context, actor authorization.Actor, tenantID, serviceAccountID, credentialID uuid.UUID, input RevokeCredentialInput) error {
	normalized, version, err := normalizeRevokeCredential(serviceAccountID, credentialID, input)
	if err != nil {
		return err
	}
	authority, err := s.resolveAndRequire(ctx, actor, tenantID, authorization.TenantPermissionServiceAccountCredentialManage)
	if err != nil {
		return err
	}
	current, err := s.loadCredential(ctx, actor, authority.MembershipID, tenantID, serviceAccountID, credentialID)
	if err != nil {
		return err
	}
	if current.Version != version {
		return ErrPreconditionFailed
	}
	if current.State == CredentialStateRevoked {
		return ErrConflict
	}
	if current.Version >= maximumResourceVersion {
		return ErrConflict
	}
	now, err := s.currentTime()
	if err != nil {
		return err
	}
	return mapRepositoryError(s.repository.RevokeCredential(ctx, RevokeCredentialParams{
		HumanParams: HumanParams{Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID},
		Audit:       normalized.Audit, OccurredAt: now, ServiceAccountID: serviceAccountID,
		CredentialID: credentialID, Reason: normalized.Reason, ExpectedVersion: version,
	}))
}

func (s *Service) resolveAndRequire(ctx context.Context, actor authorization.Actor, tenantID uuid.UUID, permission authorization.TenantPermission) (authorization.TenantAuthority, error) {
	return s.resolveAndRequireAll(ctx, actor, tenantID, permission)
}

func (s *Service) resolveAndRequireAll(ctx context.Context, actor authorization.Actor, tenantID uuid.UUID, permissions ...authorization.TenantPermission) (authorization.TenantAuthority, error) {
	if !validUUIDv7(tenantID) {
		return authorization.TenantAuthority{}, ErrInvalidInput
	}
	if !validUUIDv7(actor.UserID) || !validUUIDv7(actor.SessionID) || !validUUIDv7(actor.ActiveTenantID) ||
		actor.ActiveTenantID != tenantID || !validText(actor.AuthenticationMethod, 1, 64) {
		return authorization.TenantAuthority{}, ErrForbidden
	}
	authority, err := s.repository.ResolveHumanAuthority(ctx, authorization.ResolveAuthorityParams{Actor: actor, TenantID: tenantID})
	if err != nil {
		return authorization.TenantAuthority{}, mapRepositoryError(err)
	}
	if authority.TenantID != tenantID || authority.Principal.ID != actor.UserID ||
		authority.Principal.Kind != authorization.PrincipalKindHuman || !validUUIDv7(authority.MembershipID) {
		return authorization.TenantAuthority{}, ErrUnavailable
	}
	resource := authorization.ResourceContext{TenantID: tenantID}
	for _, permission := range permissions {
		if err := s.evaluator.RequireTenant(authority, permission, resource); err != nil {
			return authorization.TenantAuthority{}, ErrForbidden
		}
	}
	return authority, nil
}

func (s *Service) loadAccount(ctx context.Context, actor authorization.Actor, membershipID, tenantID, serviceAccountID uuid.UUID) (Account, error) {
	value, err := s.repository.GetAccount(ctx, GetAccountParams{
		HumanParams:      HumanParams{Actor: actor, MembershipID: membershipID, TenantID: tenantID},
		ServiceAccountID: serviceAccountID,
	})
	if err != nil {
		return Account{}, mapRepositoryError(err)
	}
	if value.ID != serviceAccountID || !validAccount(value, tenantID) {
		return Account{}, ErrUnavailable
	}
	return value, nil
}

func (s *Service) loadRoleGrant(ctx context.Context, actor authorization.Actor, membershipID, tenantID, serviceAccountID, grantID uuid.UUID) (RoleGrant, error) {
	value, err := s.repository.GetRoleGrant(ctx, GetRoleGrantParams{
		HumanParams:      HumanParams{Actor: actor, MembershipID: membershipID, TenantID: tenantID},
		ServiceAccountID: serviceAccountID, GrantID: grantID,
	})
	if err != nil {
		return RoleGrant{}, mapRepositoryError(err)
	}
	if value.ID != grantID || !validRoleGrant(value, tenantID, serviceAccountID) {
		return RoleGrant{}, ErrUnavailable
	}
	return value, nil
}

func (s *Service) loadCredential(ctx context.Context, actor authorization.Actor, membershipID, tenantID, serviceAccountID, credentialID uuid.UUID) (CredentialMetadata, error) {
	value, err := s.repository.GetCredential(ctx, GetCredentialParams{
		HumanParams:      HumanParams{Actor: actor, MembershipID: membershipID, TenantID: tenantID},
		ServiceAccountID: serviceAccountID, CredentialID: credentialID,
	})
	if err != nil {
		return CredentialMetadata{}, mapRepositoryError(err)
	}
	if value.ID != credentialID || !validCredential(value, tenantID, serviceAccountID) {
		return CredentialMetadata{}, ErrUnavailable
	}
	return value, nil
}

func (s *Service) currentTime() (time.Time, error) {
	value := s.now().UTC().Truncate(time.Microsecond)
	if value.IsZero() {
		return time.Time{}, ErrUnavailable
	}
	if _, err := value.MarshalJSON(); err != nil {
		return time.Time{}, ErrUnavailable
	}
	return value, nil
}

func (s *Service) nextID() (uuid.UUID, error) {
	value, err := s.newID()
	if err != nil || !validUUIDv7(value) {
		return uuid.Nil, ErrUnavailable
	}
	return value, nil
}

func validCredentialExpiry(now, expiresAt time.Time) bool {
	return expiresAt.After(now) && !expiresAt.After(now.Add(maximumCredentialAge))
}

func credentialMatchesWrite(value CredentialMetadata, write CredentialWrite, issuerMembershipID uuid.UUID, rotatedFrom *uuid.UUID) bool {
	return value.ID == write.CredentialID && value.Label == write.Label &&
		value.FormatVersion == write.FormatVersion && value.KeyVersion == write.Material.KeyVersion &&
		value.ExpiresAt.Equal(write.ExpiresAt) && equalPermissions(value.Permissions, write.Permissions) &&
		equalNetworks(value.Networks, write.Networks) && value.IssuedByMembershipID == issuerMembershipID &&
		value.State == CredentialStateActive && value.Version == 1 && value.LastUsedAt == nil && value.LastUsedIP == nil &&
		value.UpdatedAt.Equal(value.IssuedAt) && equalOptionalUUID(value.RotatedFromCredentialID, rotatedFrom)
}

func equalOptionalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func equalOptionalUUID(left, right *uuid.UUID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func mapRepositoryError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, authorization.ErrDenied), errors.Is(err, authorization.ErrForbidden), errors.Is(err, ErrForbidden):
		return ErrForbidden
	case errors.Is(err, authorization.ErrInvalidInput), errors.Is(err, ErrInvalidInput):
		return ErrInvalidInput
	case errors.Is(err, authorization.ErrNotFound), errors.Is(err, ErrNotFound):
		return ErrNotFound
	case errors.Is(err, authorization.ErrConflict), errors.Is(err, ErrConflict):
		return ErrConflict
	case errors.Is(err, authorization.ErrPreconditionRequired), errors.Is(err, ErrPreconditionRequired):
		return ErrPreconditionRequired
	case errors.Is(err, authorization.ErrPreconditionFailed), errors.Is(err, ErrPreconditionFailed):
		return ErrPreconditionFailed
	case errors.Is(err, authorization.ErrUnavailable), errors.Is(err, ErrUnavailable):
		return ErrUnavailable
	default:
		return ErrUnavailable
	}
}
