package platformidentityprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"reflect"
	"strings"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

type Service struct {
	repository      Repository
	samlRepository  SAMLAdministrationRepository
	evaluator       authorization.Evaluator
	keyring         identity.Keyring
	endpoints       canonicalEndpointPolicy
	saml            SAMLAdministrationOptions
	ldapDiagnostics LDAPDiagnosticClient
	newID           func() (uuid.UUID, error)
}

func NewService(
	repository Repository,
	keyring identity.Keyring,
	publicOrigin string,
	samlOptions ...SAMLAdministrationOptions,
) (*Service, error) {
	if interfaceIsNil(repository) {
		return nil, errors.New("platform identity-provider repository is required")
	}
	if keyring.ActiveVersion() < 1 || len(keyring.Versions()) < 1 {
		return nil, errors.New("identity keyring is required")
	}
	endpoints, err := newCanonicalEndpointPolicy(publicOrigin)
	if err != nil {
		return nil, errors.New("platform identity-provider public origin is required")
	}
	service := &Service{
		repository: repository, evaluator: authorization.Evaluator{}, keyring: keyring,
		endpoints: endpoints, newID: uuid.NewV7,
	}
	if len(samlOptions) > 1 {
		return nil, errors.New("at most one SAML administration option set is accepted")
	}
	if len(samlOptions) == 1 {
		samlRepository, ok := repository.(SAMLAdministrationRepository)
		if !ok || !validSAMLAdministrationOptions(samlOptions[0]) {
			return nil, errors.New("complete SAML administration dependencies are required")
		}
		service.samlRepository = samlRepository
		service.saml = samlOptions[0]
	}
	return service, nil
}

func (service *Service) List(
	ctx context.Context,
	session authentication.Session,
	input ListInput,
) (ProviderPage, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityProviderRead); err != nil {
		return ProviderPage{}, err
	}
	if !validSession(session) {
		return ProviderPage{}, authentication.ErrUnavailable
	}
	if err := serviceContextError(ctx); err != nil {
		return ProviderPage{}, err
	}
	normalized, err := normalizeList(input)
	if err != nil {
		return ProviderPage{}, err
	}
	rows, err := service.repository.List(ctx, ListParams{
		SessionParams: sessionParams(session), After: normalized.After,
		Limit: int32(normalized.Limit + 1), IncludeArchived: normalized.IncludeArchived,
	})
	if err != nil {
		return ProviderPage{}, mapRepositoryError(err)
	}
	if len(rows) > normalized.Limit+1 {
		return ProviderPage{}, authentication.ErrUnavailable
	}
	for index := range rows {
		if !validProviderSummary(rows[index]) || !normalized.IncludeArchived && rows[index].ArchivedAt != nil ||
			index > 0 && bytes.Compare(rows[index-1].ID[:], rows[index].ID[:]) >= 0 ||
			normalized.After != nil && bytes.Compare(rows[index].ID[:], normalized.After[:]) <= 0 {
			return ProviderPage{}, authentication.ErrUnavailable
		}
	}
	page := ProviderPage{Items: make([]ProviderSummary, min(len(rows), normalized.Limit))}
	for index := range page.Items {
		page.Items[index] = cloneProviderSummary(rows[index])
	}
	if len(rows) > normalized.Limit {
		next := page.Items[len(page.Items)-1].ID
		page.NextCursor = &next
	}
	return page, nil
}

func (service *Service) Get(
	ctx context.Context,
	session authentication.Session,
	providerID uuid.UUID,
) (Provider, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityProviderRead); err != nil {
		return Provider{}, err
	}
	if !validSession(session) {
		return Provider{}, authentication.ErrUnavailable
	}
	if err := serviceContextError(ctx); err != nil {
		return Provider{}, err
	}
	if !validUUIDv7(providerID) {
		return Provider{}, authentication.ErrInvalidInput
	}
	provider, err := service.repository.Get(ctx, GetParams{
		SessionParams: sessionParams(session), ProviderID: providerID,
	})
	if err != nil {
		return Provider{}, mapRepositoryError(err)
	}
	if provider.ID != providerID || !validProvider(provider, service.endpoints) {
		return Provider{}, authentication.ErrUnavailable
	}
	return cloneProvider(provider), nil
}

func (service *Service) Create(
	ctx context.Context,
	session authentication.Session,
	input CreateInput,
) (CreateResult, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityProviderManage); err != nil {
		return CreateResult{}, err
	}
	if err := service.require(session, authorization.PermissionPlatformIdentityProviderRead); err != nil {
		return CreateResult{}, err
	}
	if !validSession(session) {
		return CreateResult{}, authentication.ErrUnavailable
	}
	if err := serviceContextError(ctx); err != nil {
		return CreateResult{}, err
	}
	normalized, kind, requestDigest, err := normalizeCreate(input, service.endpoints)
	if err != nil {
		return CreateResult{}, err
	}
	commandID, err := service.newID()
	if err != nil || !validUUIDv7(commandID) {
		return CreateResult{}, authentication.ErrUnavailable
	}
	providerID, err := service.newID()
	if err != nil || !validUUIDv7(providerID) {
		return CreateResult{}, authentication.ErrUnavailable
	}
	if ldapConfiguration, ok := normalized.Configuration.(LDAPCreateConfiguration); ok {
		for index := range ldapConfiguration.Endpoints {
			endpointID, idErr := service.newID()
			if idErr != nil || !validUUIDv7(endpointID) {
				return CreateResult{}, authentication.ErrUnavailable
			}
			ldapConfiguration.Endpoints[index].ID = endpointID
		}
		normalized.Configuration = ldapConfiguration
	}
	keyDigest := sha256.Sum256([]byte(normalized.IdempotencyKey))
	validateResult := func(result CreateResult) (CreateResult, error) {
		validated, validationErr := validateCreateResult(result, service.endpoints)
		provider := validated.Provider()
		if validationErr != nil || provider.Kind != kind ||
			!providerMatchesCreateConfiguration(provider, normalized.Configuration) ||
			!validated.Replayed() && (validated.ProviderID() != providerID ||
				provider.Key != normalized.Key || provider.DisplayName != normalized.DisplayName ||
				provider.Description != normalized.Description || !initialProviderProjection(provider)) {
			return CreateResult{}, authentication.ErrUnavailable
		}
		return validated, nil
	}
	result, err := service.repository.Create(ctx, CreateParams{
		SessionParams: sessionParams(session), CommandID: commandID, ProviderID: providerID, Kind: kind,
		Key: normalized.Key, DisplayName: normalized.DisplayName, Description: normalized.Description,
		Configuration: cloneCreateConfiguration(normalized.Configuration), KeyDigest: keyDigest,
		RequestDigest: requestDigest, Reason: normalized.Reason, Event: normalized.Event,
		ValidateResult: validateResult,
	})
	clear(keyDigest[:])
	clear(requestDigest[:])
	if err != nil {
		return CreateResult{}, mapRepositoryError(err)
	}
	return validateResult(result)
}

func (service *Service) Update(
	ctx context.Context,
	session authentication.Session,
	providerID uuid.UUID,
	input UpdateInput,
) (UpdateResult, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityProviderManage); err != nil {
		return UpdateResult{}, err
	}
	if err := service.require(session, authorization.PermissionPlatformIdentityProviderRead); err != nil {
		return UpdateResult{}, err
	}
	if !validSession(session) {
		return UpdateResult{}, authentication.ErrUnavailable
	}
	if err := serviceContextError(ctx); err != nil {
		return UpdateResult{}, err
	}
	normalized, expectedVersion, err := normalizeUpdate(providerID, input)
	if err != nil {
		return UpdateResult{}, err
	}
	validateResult := func(result UpdateResult) (UpdateResult, error) {
		validated, validationErr := validateUpdateResult(result, service.endpoints)
		provider := validated.Provider()
		if validationErr != nil || validated.ProviderID() != providerID ||
			validated.Version() != expectedVersion+1 || provider.ArchivedAt != nil ||
			provider.Key != normalized.Key || provider.DisplayName != normalized.DisplayName ||
			provider.Description != normalized.Description {
			return UpdateResult{}, authentication.ErrUnavailable
		}
		return validated, nil
	}
	result, err := service.repository.Update(ctx, UpdateParams{
		SessionParams: sessionParams(session), ProviderID: providerID, ExpectedVersion: expectedVersion,
		Key: normalized.Key, DisplayName: normalized.DisplayName, Description: normalized.Description,
		Reason: normalized.Reason, Event: normalized.Event, ValidateResult: validateResult,
	})
	if err != nil {
		return UpdateResult{}, mapRepositoryError(err)
	}
	return validateResult(result)
}

func (service *Service) UpdateLDAP(
	ctx context.Context,
	session authentication.Session,
	providerID uuid.UUID,
	input UpdateLDAPInput,
) (UpdateResult, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityProviderManage); err != nil {
		return UpdateResult{}, err
	}
	if err := service.require(session, authorization.PermissionPlatformIdentityProviderRead); err != nil {
		return UpdateResult{}, err
	}
	repository, ok := service.repository.(LDAPAdministrationRepository)
	if !ok || !validSession(session) {
		return UpdateResult{}, authentication.ErrUnavailable
	}
	if err := serviceContextError(ctx); err != nil {
		return UpdateResult{}, err
	}
	metadata, expectedVersion, err := normalizeUpdate(providerID, UpdateInput{
		Key: input.Key, DisplayName: input.DisplayName, Description: input.Description,
		Reason: input.Reason, ExpectedEntityTag: input.ExpectedEntityTag, Event: input.Event,
	})
	if err != nil {
		return UpdateResult{}, err
	}
	configuration, err := normalizeLDAPCreateConfiguration(LDAPCreateConfiguration{
		Configuration: input.Configuration, Endpoints: cloneLDAPEndpoints(input.Endpoints),
	}, true)
	if err != nil {
		return UpdateResult{}, err
	}
	validateResult := func(result UpdateResult) (UpdateResult, error) {
		validated, validationErr := validateUpdateResult(result, service.endpoints)
		provider := validated.Provider()
		if validationErr != nil || validated.ProviderID() != providerID ||
			validated.Version() != expectedVersion+1 || provider.Kind != ProviderKindLDAP ||
			provider.Key != metadata.Key || provider.DisplayName != metadata.DisplayName ||
			provider.Description != metadata.Description || provider.LDAP == nil ||
			!ldapConfigurationsEqual(provider.LDAP.Configuration, configuration.Configuration) ||
			!ldapEndpointsEqual(provider.LDAP.Endpoints, configuration.Endpoints, true) {
			return UpdateResult{}, authentication.ErrUnavailable
		}
		return validated, nil
	}
	result, err := repository.UpdateLDAP(ctx, UpdateLDAPParams{
		SessionParams: sessionParams(session), ProviderID: providerID, ExpectedVersion: expectedVersion,
		Key: metadata.Key, DisplayName: metadata.DisplayName, Description: metadata.Description,
		Configuration: configuration.Configuration, Endpoints: configuration.Endpoints,
		Reason: metadata.Reason, Event: metadata.Event, ValidateResult: validateResult,
	})
	if err != nil {
		return UpdateResult{}, mapRepositoryError(err)
	}
	return validateResult(result)
}

func (service *Service) ReplaceLDAPBindSecret(
	ctx context.Context,
	session authentication.Session,
	providerID uuid.UUID,
	input ReplaceLDAPBindSecretInput,
) (SecretMutationReceipt, error) {
	defer clear(input.Secret)
	if err := service.require(session, authorization.PermissionPlatformIdentityProviderManage); err != nil {
		return SecretMutationReceipt{}, err
	}
	repository, ok := service.repository.(LDAPAdministrationRepository)
	if !ok || !validSession(session) {
		return SecretMutationReceipt{}, authentication.ErrUnavailable
	}
	version, err := normalizeVersioned(providerID, input.ExpectedEntityTag, input.Event)
	input.Reason = strings.TrimSpace(input.Reason)
	if err != nil || len(input.Secret) < 1 || len(input.Secret) > 8*1024-16 || !validReason(input.Reason) {
		return SecretMutationReceipt{}, authentication.ErrInvalidInput
	}
	secretID, err := service.newID()
	if err != nil || !validUUIDv7(secretID) {
		return SecretMutationReceipt{}, authentication.ErrUnavailable
	}
	envelope, err := service.keyring.EncryptBindSecret(identity.BindSecretContext{
		Provider: identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: identity.EntityID(providerID),
		},
		SecretID: identity.EntityID(secretID),
	}, input.Secret)
	if err != nil {
		return SecretMutationReceipt{}, authentication.ErrUnavailable
	}
	defer clear(envelope.Ciphertext)
	receipt, err := repository.ReplaceLDAPBindSecret(ctx, ReplaceLDAPBindSecretParams{
		SessionParams: sessionParams(session), ProviderID: providerID, ExpectedVersion: version,
		Secret: EncryptedLDAPBindSecret{SecretID: secretID, Envelope: envelope},
		Reason: input.Reason, Event: input.Event,
	})
	if err != nil {
		return SecretMutationReceipt{}, mapRepositoryError(err)
	}
	if receipt.ProviderID() != providerID || receipt.Version() != version+1 ||
		receipt.SecretRevision() < 1 {
		return SecretMutationReceipt{}, authentication.ErrUnavailable
	}
	return receipt, nil
}

func (service *Service) PutLDAPMapping(
	ctx context.Context,
	session authentication.Session,
	providerID, mappingID uuid.UUID,
	input PutLDAPMappingInput,
) (UpdateResult, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityPolicyManage); err != nil {
		return UpdateResult{}, err
	}
	if err := service.require(session, authorization.PermissionPlatformIdentityProviderRead); err != nil {
		return UpdateResult{}, err
	}
	repository, ok := service.repository.(LDAPAdministrationRepository)
	input.MatcherValue = strings.TrimSpace(input.MatcherValue)
	input.Notes = strings.TrimSpace(input.Notes)
	input.Reason = strings.TrimSpace(input.Reason)
	if !ok || !validSession(session) {
		return UpdateResult{}, authentication.ErrUnavailable
	}
	if !validUUIDv7(providerID) || !validUUIDv7(mappingID) || !validUUIDv7(input.PlatformRoleID) ||
		!validEvent(input.Event) || !validReason(input.Reason) || !validText(input.Notes, 0, 1000) ||
		input.Priority < 0 || input.Priority > 1_000_000 ||
		(input.ExpectedVersion != nil &&
			(*input.ExpectedVersion < 1 || *input.ExpectedVersion > maximumExpectedMutationVersion)) {
		return UpdateResult{}, authentication.ErrInvalidInput
	}
	matcherKind, caseMode, ok := ldapMatcherDomain(input.MatcherType, input.CaseSensitive)
	if !ok {
		return UpdateResult{}, authentication.ErrInvalidInput
	}
	if _, err := identity.CompileLDAPGroupMatcher(identity.LDAPGroupMatcherSpec{
		Kind: matcherKind, CaseMode: caseMode, Pattern: input.MatcherValue,
	}); err != nil {
		return UpdateResult{}, authentication.ErrInvalidInput
	}
	if input.ReconciliationMode != identityprovider.ReconciliationAdditive &&
		input.ReconciliationMode != identityprovider.ReconciliationAuthoritative {
		return UpdateResult{}, authentication.ErrInvalidInput
	}
	validateResult := func(result UpdateResult) (UpdateResult, error) {
		validated, validationErr := validateUpdateResult(result, service.endpoints)
		provider := validated.Provider()
		if validationErr != nil || provider.Kind != ProviderKindLDAP ||
			validated.ProviderID() != providerID || provider.LDAP == nil {
			return UpdateResult{}, authentication.ErrUnavailable
		}
		return validated, nil
	}
	result, err := repository.PutLDAPMapping(ctx, PutLDAPMappingParams{
		SessionParams: sessionParams(session), ProviderID: providerID, MappingID: mappingID,
		ExpectedVersion: input.ExpectedVersion, MatcherType: input.MatcherType,
		MatcherValue: input.MatcherValue, CaseSensitive: input.CaseSensitive, Priority: input.Priority,
		PlatformRoleID: input.PlatformRoleID, ReconciliationMode: input.ReconciliationMode,
		Enabled: input.Enabled, Notes: input.Notes, Reason: input.Reason, Event: input.Event,
		ValidateResult: validateResult,
	})
	if err != nil {
		return UpdateResult{}, mapRepositoryError(err)
	}
	return validateResult(result)
}

func (service *Service) SetLDAPLoginState(
	ctx context.Context,
	session authentication.Session,
	providerID uuid.UUID,
	input SetLDAPLoginStateInput,
) (UpdateResult, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityPolicyManage); err != nil {
		return UpdateResult{}, err
	}
	if err := service.require(session, authorization.PermissionPlatformIdentityProviderRead); err != nil {
		return UpdateResult{}, err
	}
	repository, ok := service.repository.(LDAPAdministrationRepository)
	version, err := normalizeVersioned(providerID, input.ExpectedEntityTag, input.Event)
	input.Reason = strings.TrimSpace(input.Reason)
	if !ok || !validSession(session) {
		return UpdateResult{}, authentication.ErrUnavailable
	}
	if err != nil || !validReason(input.Reason) {
		return UpdateResult{}, authentication.ErrInvalidInput
	}
	validateResult := func(result UpdateResult) (UpdateResult, error) {
		validated, validationErr := validateUpdateResult(result, service.endpoints)
		provider := validated.Provider()
		if validationErr != nil || provider.Kind != ProviderKindLDAP ||
			validated.ProviderID() != providerID || validated.Version() != version+1 ||
			provider.Enabled != input.Enabled || provider.PlatformLoginEnabled != input.Enabled {
			return UpdateResult{}, authentication.ErrUnavailable
		}
		return validated, nil
	}
	result, err := repository.SetLDAPLoginState(ctx, SetLDAPLoginStateParams{
		SessionParams: sessionParams(session), ProviderID: providerID, ExpectedVersion: version,
		Enabled: input.Enabled, Reason: input.Reason, Event: input.Event,
		ValidateResult: validateResult,
	})
	if err != nil {
		return UpdateResult{}, mapRepositoryError(err)
	}
	return validateResult(result)
}

func ldapMatcherDomain(
	kind identityprovider.MappingMatcherType,
	caseSensitive bool,
) (identity.LDAPGroupMatcherKind, identity.LDAPGroupCaseMode, bool) {
	var mappedKind identity.LDAPGroupMatcherKind
	switch kind {
	case identityprovider.MappingMatcherExactDN:
		mappedKind = identity.LDAPGroupMatcherExactDN
	case identityprovider.MappingMatcherExactCN:
		mappedKind = identity.LDAPGroupMatcherExactCN
	case identityprovider.MappingMatcherRegex:
		mappedKind = identity.LDAPGroupMatcherRegex
	default:
		return 0, 0, false
	}
	if caseSensitive {
		return mappedKind, identity.LDAPGroupCaseSensitive, true
	}
	return mappedKind, identity.LDAPGroupCaseInsensitive, true
}

func (service *Service) Archive(
	ctx context.Context,
	session authentication.Session,
	providerID uuid.UUID,
	input ArchiveInput,
) (MutationReceipt, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityProviderManage); err != nil {
		return MutationReceipt{}, err
	}
	if !validSession(session) {
		return MutationReceipt{}, authentication.ErrUnavailable
	}
	if err := serviceContextError(ctx); err != nil {
		return MutationReceipt{}, err
	}
	normalized, expectedVersion, err := normalizeArchive(providerID, input)
	if err != nil {
		return MutationReceipt{}, err
	}
	receipt, err := service.repository.Archive(ctx, ArchiveParams{
		SessionParams: sessionParams(session), ProviderID: providerID, ExpectedVersion: expectedVersion,
		Reason: normalized.Reason, Event: normalized.Event,
	})
	if err != nil {
		return MutationReceipt{}, mapRepositoryError(err)
	}
	if validateMutationReceipt(receipt) != nil || receipt.ProviderID() != providerID ||
		receipt.Version() != expectedVersion+1 {
		return MutationReceipt{}, authentication.ErrUnavailable
	}
	return receipt, nil
}

func (service *Service) ReplaceOIDCClientSecret(
	ctx context.Context,
	session authentication.Session,
	providerID uuid.UUID,
	input ReplaceOIDCClientSecretInput,
) (SecretMutationReceipt, error) {
	defer clear(input.Secret)
	if err := service.require(session, authorization.PermissionPlatformIdentityProviderManage); err != nil {
		return SecretMutationReceipt{}, err
	}
	if !validSession(session) {
		return SecretMutationReceipt{}, authentication.ErrUnavailable
	}
	if err := serviceContextError(ctx); err != nil {
		return SecretMutationReceipt{}, err
	}
	normalized, expectedVersion, err := normalizeReplaceOIDCClientSecret(providerID, input)
	if err != nil {
		return SecretMutationReceipt{}, err
	}
	secretID, err := service.newID()
	if err != nil || !validUUIDv7(secretID) {
		return SecretMutationReceipt{}, authentication.ErrUnavailable
	}
	envelope, err := service.keyring.EncryptOIDCClientSecret(
		platformOIDCClientSecretContext(providerID, secretID), normalized.Secret,
	)
	if err != nil {
		return SecretMutationReceipt{}, authentication.ErrUnavailable
	}
	defer clear(envelope.Ciphertext)
	receipt, err := service.repository.ReplaceOIDCClientSecret(ctx, ReplaceOIDCClientSecretParams{
		SessionParams: sessionParams(session), ProviderID: providerID, ExpectedVersion: expectedVersion,
		Secret: EncryptedOIDCClientSecret{SecretID: secretID, Envelope: envelope},
		Reason: normalized.Reason, Event: normalized.Event,
	})
	if err != nil {
		return SecretMutationReceipt{}, mapRepositoryError(err)
	}
	if validateSecretMutationReceipt(receipt) != nil || receipt.ProviderID() != providerID ||
		receipt.Version() != expectedVersion+1 {
		return SecretMutationReceipt{}, authentication.ErrUnavailable
	}
	return receipt, nil
}

func (service *Service) Activate(
	ctx context.Context,
	session authentication.Session,
	providerID uuid.UUID,
	input ActivateInput,
) (UpdateResult, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityProviderManage); err != nil {
		return UpdateResult{}, err
	}
	if err := service.require(session, authorization.PermissionPlatformIdentityProviderRead); err != nil {
		return UpdateResult{}, err
	}
	if !validSession(session) {
		return UpdateResult{}, authentication.ErrUnavailable
	}
	if err := serviceContextError(ctx); err != nil {
		return UpdateResult{}, err
	}
	normalized, expectedVersion, err := normalizeActivate(providerID, input)
	if err != nil {
		return UpdateResult{}, err
	}
	validateResult := func(result UpdateResult) (UpdateResult, error) {
		validated, validationErr := validateUpdateResult(result, service.endpoints)
		provider := validated.Provider()
		if validationErr != nil || validated.ProviderID() != providerID ||
			validated.Version() != expectedVersion+1 ||
			!provider.Enabled || provider.ActivationAvailable ||
			provider.AccountMode != normalized.AccountMode || provider.ArchivedAt != nil {
			return UpdateResult{}, authentication.ErrUnavailable
		}
		return validated, nil
	}
	result, err := service.repository.Activate(ctx, ActivationParams{
		SessionParams: sessionParams(session), ProviderID: providerID,
		ExpectedVersion: expectedVersion, AccountMode: normalized.AccountMode,
		Reason: normalized.Reason, Event: normalized.Event, ValidateResult: validateResult,
	})
	if err != nil {
		return UpdateResult{}, mapRepositoryError(err)
	}
	return validateResult(result)
}

func (service *Service) Deactivate(
	ctx context.Context,
	session authentication.Session,
	providerID uuid.UUID,
	input DeactivateInput,
) (UpdateResult, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityProviderManage); err != nil {
		return UpdateResult{}, err
	}
	if err := service.require(session, authorization.PermissionPlatformIdentityProviderRead); err != nil {
		return UpdateResult{}, err
	}
	if !validSession(session) {
		return UpdateResult{}, authentication.ErrUnavailable
	}
	if err := serviceContextError(ctx); err != nil {
		return UpdateResult{}, err
	}
	normalized, expectedVersion, err := normalizeDeactivate(providerID, input)
	if err != nil {
		return UpdateResult{}, err
	}
	validateResult := func(result UpdateResult) (UpdateResult, error) {
		validated, validationErr := validateUpdateResult(result, service.endpoints)
		provider := validated.Provider()
		if validationErr != nil || validated.ProviderID() != providerID ||
			validated.Version() != expectedVersion+1 || provider.Enabled ||
			provider.AccountMode != AccountModeDisabled ||
			provider.ArchivedAt != nil {
			return UpdateResult{}, authentication.ErrUnavailable
		}
		return validated, nil
	}
	result, err := service.repository.Deactivate(ctx, DeactivationParams{
		SessionParams: sessionParams(session), ProviderID: providerID,
		ExpectedVersion: expectedVersion, Reason: normalized.Reason,
		Event: normalized.Event, ValidateResult: validateResult,
	})
	if err != nil {
		return UpdateResult{}, mapRepositoryError(err)
	}
	return validateResult(result)
}

func (service *Service) ActivateDirectLogin(
	ctx context.Context,
	session authentication.Session,
	providerID uuid.UUID,
	input DirectLoginInput,
) (UpdateResult, error) {
	return service.setDirectLogin(ctx, session, providerID, input, true)
}

func (service *Service) DeactivateDirectLogin(
	ctx context.Context,
	session authentication.Session,
	providerID uuid.UUID,
	input DirectLoginInput,
) (UpdateResult, error) {
	return service.setDirectLogin(ctx, session, providerID, input, false)
}

func (service *Service) setDirectLogin(
	ctx context.Context,
	session authentication.Session,
	providerID uuid.UUID,
	input DirectLoginInput,
	enabled bool,
) (UpdateResult, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityProviderManage); err != nil {
		return UpdateResult{}, err
	}
	if err := service.require(session, authorization.PermissionPlatformIdentityProviderRead); err != nil {
		return UpdateResult{}, err
	}
	if !validSession(session) {
		return UpdateResult{}, authentication.ErrUnavailable
	}
	if err := serviceContextError(ctx); err != nil {
		return UpdateResult{}, err
	}
	normalized, expectedVersion, err := normalizeDirectLogin(providerID, input)
	if err != nil {
		return UpdateResult{}, err
	}
	validateResult := func(result UpdateResult) (UpdateResult, error) {
		validated, validationErr := validateUpdateResult(result, service.endpoints)
		provider := validated.Provider()
		if validationErr != nil || validated.ProviderID() != providerID ||
			validated.Version() != expectedVersion+1 ||
			provider.PlatformLoginEnabled != enabled || provider.ArchivedAt != nil ||
			!provider.Enabled || !provider.Configured || !provider.SecretPresent {
			return UpdateResult{}, authentication.ErrUnavailable
		}
		return validated, nil
	}
	params := DirectLoginParams{
		SessionParams: sessionParams(session), ProviderID: providerID,
		ExpectedVersion: expectedVersion, Reason: normalized.Reason,
		Event: normalized.Event, ValidateResult: validateResult,
	}
	var result UpdateResult
	if enabled {
		result, err = service.repository.ActivateDirectLogin(ctx, params)
	} else {
		result, err = service.repository.DeactivateDirectLogin(ctx, params)
	}
	if err != nil {
		return UpdateResult{}, mapRepositoryError(err)
	}
	return validateResult(result)
}

func (service *Service) require(session authentication.Session, permission authorization.Permission) error {
	if service == nil || interfaceIsNil(service.repository) || service.newID == nil || !service.endpoints.valid() {
		return authentication.ErrUnavailable
	}
	if err := service.evaluator.Require(session.Permissions, permission); err != nil {
		return authentication.ErrForbidden
	}
	return nil
}

func sessionParams(session authentication.Session) SessionParams {
	return SessionParams{
		ActorID: session.User.ID, SessionID: session.ID, AuthenticationMethod: session.AuthenticationMethod,
	}
}

func platformOIDCClientSecretContext(providerID, secretID uuid.UUID) identity.OIDCClientSecretContext {
	return identity.OIDCClientSecretContext{
		Provider: identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: identity.EntityID(providerID),
		},
		BindingID: identity.EntityID{}, SecretID: identity.EntityID(secretID),
	}
}

func validateCreateReceipt(receipt CreateReceipt) error {
	restored, err := RestoreCreateReceipt(CreateReceiptInput{
		ProviderID: receipt.providerID, Version: receipt.version, Replayed: receipt.replayed,
	})
	if err != nil || restored != receipt {
		return authentication.ErrInvalidInput
	}
	return nil
}

func validateCreateResult(result CreateResult, endpoints canonicalEndpointPolicy) (CreateResult, error) {
	restored, err := RestoreCreateResult(CreateResultInput{
		ProviderID: result.receipt.providerID,
		Version:    result.receipt.version,
		Replayed:   result.receipt.replayed,
		Provider:   result.provider,
	})
	if err != nil || !validProvider(restored.provider, endpoints) {
		return CreateResult{}, authentication.ErrInvalidInput
	}
	return restored, nil
}

func validateMutationReceipt(receipt MutationReceipt) error {
	restored, err := RestoreMutationReceipt(MutationReceiptInput{
		ProviderID: receipt.providerID, Version: receipt.version,
	})
	if err != nil || restored != receipt {
		return authentication.ErrInvalidInput
	}
	return nil
}

func validateUpdateResult(result UpdateResult, endpoints canonicalEndpointPolicy) (UpdateResult, error) {
	restored, err := RestoreUpdateResult(UpdateResultInput{
		ProviderID: result.receipt.providerID,
		Version:    result.receipt.version,
		Provider:   result.provider,
	})
	if err != nil || !validProvider(restored.provider, endpoints) {
		return UpdateResult{}, authentication.ErrInvalidInput
	}
	return restored, nil
}

func validateSecretMutationReceipt(receipt SecretMutationReceipt) error {
	restored, err := RestoreSecretMutationReceipt(SecretMutationReceiptInput{
		ProviderID: receipt.providerID, Version: receipt.version, SecretRevision: receipt.secretRevision,
	})
	if err != nil || restored != receipt {
		return authentication.ErrInvalidInput
	}
	return nil
}

func mapRepositoryError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, authentication.ErrForbidden):
		return authentication.ErrForbidden
	case errors.Is(err, authentication.ErrNotFound):
		return authentication.ErrNotFound
	case errors.Is(err, authentication.ErrConflict):
		return authentication.ErrConflict
	case errors.Is(err, authentication.ErrInvalidInput):
		return authentication.ErrInvalidInput
	case errors.Is(err, ErrPreconditionFailed):
		return ErrPreconditionFailed
	default:
		return authentication.ErrUnavailable
	}
}

func serviceContextError(ctx context.Context) error {
	if interfaceIsNil(ctx) {
		return authentication.ErrUnavailable
	}
	return ctx.Err()
}

func interfaceIsNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func (service *Service) String() string {
	return "platformidentityprovider.Service{dependencies:[REDACTED]}"
}

func (service *Service) GoString() string { return service.String() }
