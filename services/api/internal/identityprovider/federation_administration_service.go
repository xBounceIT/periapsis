package identityprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

const federationRepositoryPageLimit = int32(101)

type FederationService struct {
	authority    FederationAuthorityRepository
	repository   FederationAdministrationRepository
	evaluator    authorization.Evaluator
	keyring      identity.Keyring
	publicOrigin string
	now          func() time.Time
	newID        func() (uuid.UUID, error)
	oidcTrust    FederationOIDCTrustDocumentFetcher
	saml         *federationSAMLAdministrationDependencies
}

func NewFederationServiceWithOIDCTrust(
	authority FederationAuthorityRepository,
	repository FederationAdministrationRepository,
	keyring identity.Keyring,
	publicOrigin string,
	oidcTrust FederationOIDCTrustDocumentFetcher,
) (*FederationService, error) {
	service, err := NewFederationService(authority, repository, keyring, publicOrigin)
	if err != nil || oidcTrust == nil {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("tenant OIDC trust document fetcher is required")
	}
	service.oidcTrust = oidcTrust
	return service, nil
}

func NewFederationService(
	authority FederationAuthorityRepository,
	repository FederationAdministrationRepository,
	keyring identity.Keyring,
	publicOrigin string,
) (*FederationService, error) {
	if authority == nil || keyring.ActiveVersion() < 1 || len(keyring.Versions()) == 0 ||
		!validCanonicalHTTPSURL(publicOrigin, false) {
		return nil, errors.New("tenant federation administration dependencies are required")
	}
	return &FederationService{
		authority: authority, repository: repository, evaluator: authorization.Evaluator{}, keyring: keyring,
		publicOrigin: publicOrigin, now: time.Now, newID: uuid.NewV7,
	}, nil
}

func (service *FederationService) List(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input FederationListInput,
) (FederationProviderPage, error) {
	normalized, err := normalizeFederationList(input)
	if err != nil {
		return FederationProviderPage{}, err
	}
	human, err := service.require(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderRead)
	if err != nil {
		return FederationProviderPage{}, err
	}
	if service.repository == nil {
		return FederationProviderPage{}, ErrUnavailable
	}
	rows, err := service.repository.ListFederatedProviders(ctx, FederationListParams{
		FederationHumanParams: human, After: normalized.After, Limit: int32(normalized.Limit + 1),
		IncludeArchived: normalized.IncludeArchived,
	})
	if err != nil {
		return FederationProviderPage{}, mapRepositoryError(err)
	}
	if len(rows) > normalized.Limit+1 || len(rows) > int(federationRepositoryPageLimit) {
		return FederationProviderPage{}, ErrUnavailable
	}
	for index := range rows {
		if !validFederationProviderSummary(rows[index], tenantID) ||
			!normalized.IncludeArchived && rows[index].ArchivedAt != nil ||
			normalized.After != nil && bytesCompareUUID(rows[index].ID, *normalized.After) <= 0 ||
			index > 0 && bytesCompareUUID(rows[index-1].ID, rows[index].ID) >= 0 {
			return FederationProviderPage{}, ErrUnavailable
		}
	}
	items := rows
	var next *uuid.UUID
	if len(rows) > normalized.Limit {
		items = rows[:normalized.Limit]
		cursor := items[len(items)-1].ID
		next = &cursor
	}
	items = slices.Clone(items)
	for index := range items {
		items[index] = cloneFederationProviderSummary(items[index])
	}
	return FederationProviderPage{Items: items, NextCursor: next}, nil
}

func (service *FederationService) Get(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, providerID uuid.UUID,
) (FederationProvider, error) {
	if !validUUIDv7(providerID) {
		return FederationProvider{}, ErrInvalidInput
	}
	human, err := service.require(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderRead)
	if err != nil {
		return FederationProvider{}, err
	}
	if service.repository == nil {
		return FederationProvider{}, ErrUnavailable
	}
	provider, err := service.repository.GetFederatedProvider(ctx, FederationGetParams{
		FederationHumanParams: human, ProviderID: providerID,
	})
	if err != nil {
		return FederationProvider{}, mapRepositoryError(err)
	}
	if provider.ID != providerID || !service.validFederationProvider(provider, tenantID) {
		return FederationProvider{}, ErrUnavailable
	}
	return cloneFederationProvider(provider), nil
}

func (service *FederationService) Create(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input FederationCreateInput,
) (FederationCreateResult, error) {
	normalized, err := normalizeFederationCreate(input)
	if err != nil || !service.validOIDCPostLogoutRedirect(normalized.OIDC) {
		if err != nil {
			return FederationCreateResult{}, err
		}
		return FederationCreateResult{}, ErrInvalidInput
	}
	human, err := service.require(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderManage)
	if err != nil {
		return FederationCreateResult{}, err
	}
	if service.repository == nil {
		return FederationCreateResult{}, ErrUnavailable
	}
	commandID, providerID, bindingID, err := service.threeDistinctIDs()
	if err != nil {
		return FederationCreateResult{}, err
	}
	now, err := service.currentTime()
	if err != nil {
		return FederationCreateResult{}, err
	}
	requestDigest, err := federationCreateRequestDigest(tenantID, normalized)
	if err != nil {
		return FederationCreateResult{}, err
	}
	defer clear(requestDigest[:])
	idempotencyDigest := sha256.Sum256([]byte(normalized.IdempotencyKey))
	defer clear(idempotencyDigest[:])
	result, err := service.repository.CreateFederatedProvider(ctx, FederationCreateParams{
		FederationHumanParams: human, Audit: normalized.Audit, OccurredAt: now,
		CommandID: commandID, ProviderID: providerID, BindingID: bindingID,
		IdempotencyKeyDigest: idempotencyDigest, RequestDigest: requestDigest, Input: normalized,
		OIDCRedirectURI: service.oidcRedirectURI(), SAMLACSURL: service.samlACSURL(),
		SAMLSPMetadataBaseURL: service.samlSPMetadataBaseURL(),
	})
	if err != nil {
		return FederationCreateResult{}, mapRepositoryError(err)
	}
	if !service.validFederationProvider(result.Provider, tenantID) || result.Provider.ID != providerID && !result.Replayed ||
		!result.Replayed && (result.Provider.Version != 1 || result.Provider.Binding.ID != bindingID ||
			result.Provider.Enabled || result.Provider.Binding.Enabled || result.Provider.Configured ||
			result.Provider.ArchivedAt != nil || !federationProviderMatchesIntendedState(
			result.Provider, federationIntendedState{
				Key: &normalized.Key, LoginKey: &normalized.LoginKey,
				DisplayName: normalized.DisplayName, Description: normalized.Description,
				Enabled: false, JITMode: normalized.JITMode, NoMatchPolicy: normalized.NoMatchPolicy,
				OIDC: normalized.OIDC, SAML: normalized.SAML,
			}, service.oidcRedirectURI(), service.samlACSURL(),
		)) {
		return FederationCreateResult{}, ErrUnavailable
	}
	result.Provider = cloneFederationProvider(result.Provider)
	return result, nil
}

type federationIntendedState struct {
	Key           *string
	LoginKey      *string
	DisplayName   string
	Description   string
	Enabled       bool
	JITMode       JITMode
	NoMatchPolicy NoMatchPolicy
	OIDC          *FederationOIDCCreateConfiguration
	SAML          *FederationSAMLCreateConfiguration
}

// federationProviderMatchesIntendedState attests the safe post-write
// projection against the normalized business request. Protected-material
// presence and revisions are deliberately outside this comparison.
func federationProviderMatchesIntendedState(
	provider FederationProvider,
	desired federationIntendedState,
	oidcRedirectURI, samlACSURL string,
) bool {
	if provider.DisplayName != desired.DisplayName || provider.Description != desired.Description ||
		provider.Enabled != desired.Enabled || provider.Binding.Enabled != desired.Enabled ||
		provider.JITMode != desired.JITMode || provider.NoMatchPolicy != desired.NoMatchPolicy ||
		(desired.Key != nil && provider.Key != *desired.Key) ||
		(desired.LoginKey != nil && provider.Binding.LoginKey != *desired.LoginKey) ||
		(provider.OIDC == nil) != (desired.OIDC == nil) || (provider.SAML == nil) != (desired.SAML == nil) {
		return false
	}
	if desired.OIDC != nil {
		actual := provider.OIDC
		return provider.Kind == FederationProviderOIDC && actual != nil &&
			actual.Issuer == desired.OIDC.Issuer && actual.ClientID == desired.OIDC.ClientID &&
			actual.RedirectURI == oidcRedirectURI &&
			actual.PostLogoutRedirectURI == desired.OIDC.PostLogoutRedirectURI &&
			slices.Equal(actual.ExtraScopes, desired.OIDC.ExtraScopes) &&
			actual.AllowRefreshToken == desired.OIDC.AllowRefreshToken &&
			actual.UseUserInfo == desired.OIDC.UseUserInfo
	}
	actual := provider.SAML
	return desired.SAML != nil && provider.Kind == FederationProviderSAML && actual != nil &&
		actual.ExpectedEntityID == desired.SAML.ExpectedEntityID && actual.ACSURL == samlACSURL &&
		actual.RedirectSignatureAlgorithm == desired.SAML.RedirectSignatureAlgorithm &&
		actual.SignaturePolicy == desired.SAML.SignaturePolicy &&
		actual.EncryptionPolicy == desired.SAML.EncryptionPolicy &&
		slices.Equal(actual.RequestedAuthnContexts, desired.SAML.RequestedAuthnContexts) &&
		actual.SubjectSource == desired.SAML.SubjectSource &&
		federationOptionalStringEqual(actual.SubjectAttributeName, desired.SAML.SubjectAttributeName) &&
		federationOptionalStringEqual(actual.SubjectAttributeNameFormat, desired.SAML.SubjectAttributeNameFormat) &&
		actual.ClockSkew == desired.SAML.ClockSkew &&
		actual.MaximumAuthenticationAge == desired.SAML.MaximumAuthenticationAge
}

func federationOptionalStringEqual(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

// federationCreateRequestDigest binds an idempotency key to the requested
// business state. Request-scoped audit metadata and the idempotency key itself
// are deliberately excluded so a legitimate retry remains replayable.
func federationCreateRequestDigest(tenantID uuid.UUID, input FederationCreateInput) ([32]byte, error) {
	type semanticInput struct {
		Kind          FederationProviderKind             `json:"kind"`
		Key           string                             `json:"key"`
		LoginKey      string                             `json:"loginKey"`
		DisplayName   string                             `json:"displayName"`
		Description   string                             `json:"description"`
		JITMode       JITMode                            `json:"jitMode"`
		NoMatchPolicy NoMatchPolicy                      `json:"noMatchPolicy"`
		OIDC          *FederationOIDCCreateConfiguration `json:"oidc,omitempty"`
		SAML          *FederationSAMLCreateConfiguration `json:"saml,omitempty"`
		Reason        string                             `json:"reason"`
	}
	return federationRequestDigest(struct {
		Schema   string        `json:"schema"`
		TenantID uuid.UUID     `json:"tenantId"`
		Input    semanticInput `json:"input"`
	}{
		Schema:   "periapsis/tenant-federation-provider-create/v1",
		TenantID: tenantID,
		Input: semanticInput{
			Kind: input.Kind, Key: input.Key, LoginKey: input.LoginKey,
			DisplayName: input.DisplayName, Description: input.Description,
			JITMode: input.JITMode, NoMatchPolicy: input.NoMatchPolicy,
			OIDC: input.OIDC, SAML: input.SAML, Reason: input.Reason,
		},
	})
}

func (service *FederationService) Update(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, providerID uuid.UUID,
	input FederationUpdateInput,
) (FederationProvider, error) {
	normalized, version, err := normalizeFederationUpdate(providerID, input)
	if err != nil || !service.validOIDCPostLogoutRedirect(normalized.OIDC) {
		if err != nil {
			return FederationProvider{}, err
		}
		return FederationProvider{}, ErrInvalidInput
	}
	human, err := service.require(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderManage)
	if err != nil {
		return FederationProvider{}, err
	}
	if service.repository == nil {
		return FederationProvider{}, ErrUnavailable
	}
	now, err := service.currentTime()
	if err != nil {
		return FederationProvider{}, err
	}
	provider, err := service.repository.UpdateFederatedProvider(ctx, FederationUpdateParams{
		FederationHumanParams: human, Audit: normalized.Audit, OccurredAt: now,
		ProviderID: providerID, ExpectedVersion: version, Input: normalized,
		OIDCRedirectURI: service.oidcRedirectURI(), SAMLACSURL: service.samlACSURL(),
		SAMLSPMetadataBaseURL: service.samlSPMetadataBaseURL(),
	})
	if err != nil {
		return FederationProvider{}, mapRepositoryError(err)
	}
	if provider.ID != providerID || provider.Version != version+1 ||
		!service.validFederationProvider(provider, tenantID) || provider.Enabled != normalized.Enabled ||
		(provider.OIDC == nil) != (normalized.OIDC == nil) ||
		!federationProviderMatchesIntendedState(provider, federationIntendedState{
			DisplayName: normalized.DisplayName, Description: normalized.Description,
			Enabled: normalized.Enabled, JITMode: normalized.JITMode, NoMatchPolicy: normalized.NoMatchPolicy,
			OIDC: normalized.OIDC, SAML: normalized.SAML,
		}, service.oidcRedirectURI(), service.samlACSURL()) {
		return FederationProvider{}, ErrUnavailable
	}
	return cloneFederationProvider(provider), nil
}

func (service *FederationService) Archive(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, providerID uuid.UUID,
	input FederationArchiveInput,
) (int64, error) {
	version, err := validateIncrementableFederationVersion(providerID, input.ExpectedEntityTag, input.Audit)
	input.Reason = strings.TrimSpace(input.Reason)
	if err != nil || !validFederationAuditReason(input.Reason) {
		if err != nil {
			return 0, err
		}
		return 0, ErrInvalidInput
	}
	human, err := service.require(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderManage)
	if err != nil {
		return 0, err
	}
	if service.repository == nil {
		return 0, ErrUnavailable
	}
	now, err := service.currentTime()
	if err != nil {
		return 0, err
	}
	next, err := service.repository.ArchiveFederatedProvider(ctx, FederationArchiveParams{
		FederationHumanParams: human, Audit: input.Audit, OccurredAt: now,
		ProviderID: providerID, ExpectedVersion: version, Reason: input.Reason,
	})
	if err != nil {
		return 0, mapRepositoryError(err)
	}
	if next != version+1 {
		return 0, ErrUnavailable
	}
	return next, nil
}

func (service *FederationService) ReplaceOIDCClientSecret(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, providerID uuid.UUID,
	input FederationReplaceOIDCSecretInput,
) (FederationSecretMutationReceipt, error) {
	defer clear(input.Secret)
	version, err := validateIncrementableFederationVersion(providerID, input.ExpectedEntityTag, input.Audit)
	input.Reason = strings.TrimSpace(input.Reason)
	if err != nil || len(input.Secret) < 1 || len(input.Secret) > maximumFederationClientSecretBytes ||
		!validFederationAuditReason(input.Reason) {
		if err != nil {
			return FederationSecretMutationReceipt{}, err
		}
		return FederationSecretMutationReceipt{}, ErrInvalidInput
	}
	human, err := service.require(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderManage)
	if err != nil {
		return FederationSecretMutationReceipt{}, err
	}
	if service.repository == nil {
		return FederationSecretMutationReceipt{}, ErrUnavailable
	}
	preparation, err := service.repository.PrepareOIDCClientSecretReplacement(ctx, FederationPrepareOIDCSecretParams{
		FederationHumanParams: human, ProviderID: providerID, ExpectedVersion: version,
	})
	if err != nil {
		return FederationSecretMutationReceipt{}, mapRepositoryError(err)
	}
	if !validFederationSecretPreparation(preparation, tenantID, providerID) {
		return FederationSecretMutationReceipt{}, ErrUnavailable
	}
	secretID := preparation.CurrentSecretID
	if secretID == nil {
		generated, generateErr := service.nextID()
		if generateErr != nil {
			return FederationSecretMutationReceipt{}, generateErr
		}
		secretID = &generated
	}
	envelope, err := service.keyring.EncryptOIDCClientSecret(identity.OIDCClientSecretContext{
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: identity.EntityID(tenantID),
			ProviderID: identity.EntityID(providerID),
		},
		BindingID: identity.EntityID(preparation.BindingID), SecretID: identity.EntityID(*secretID),
	}, input.Secret)
	if err != nil {
		return FederationSecretMutationReceipt{}, ErrUnavailable
	}
	defer clear(envelope.Nonce[:])
	defer clear(envelope.Ciphertext)
	now, err := service.currentTime()
	if err != nil {
		return FederationSecretMutationReceipt{}, err
	}
	receipt, err := service.repository.ReplaceOIDCClientSecret(ctx, FederationReplaceOIDCSecretParams{
		FederationHumanParams: human, Audit: input.Audit, OccurredAt: now,
		ProviderID: providerID, BindingID: preparation.BindingID, ExpectedVersion: version,
		ExpectedRevision: preparation.NextSecretRevision,
		Secret:           FederationEncryptedOIDCSecret{SecretID: *secretID, Envelope: envelope}, Reason: input.Reason,
	})
	if err != nil {
		return FederationSecretMutationReceipt{}, mapRepositoryError(err)
	}
	if receipt.ProviderID != providerID || receipt.ProviderVersion != version+1 ||
		receipt.SecretRevision != preparation.NextSecretRevision {
		return FederationSecretMutationReceipt{}, ErrUnavailable
	}
	return receipt, nil
}

func (service *FederationService) ClearOIDCClientSecret(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, providerID uuid.UUID,
	input FederationClearOIDCSecretInput,
) (FederationSecretMutationReceipt, error) {
	version, err := validateIncrementableFederationVersion(providerID, input.ExpectedEntityTag, input.Audit)
	input.Reason = strings.TrimSpace(input.Reason)
	if err != nil || !validFederationAuditReason(input.Reason) {
		if err != nil {
			return FederationSecretMutationReceipt{}, err
		}
		return FederationSecretMutationReceipt{}, ErrInvalidInput
	}
	human, err := service.require(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderManage)
	if err != nil {
		return FederationSecretMutationReceipt{}, err
	}
	if service.repository == nil {
		return FederationSecretMutationReceipt{}, ErrUnavailable
	}
	preparation, err := service.repository.PrepareOIDCClientSecretReplacement(ctx, FederationPrepareOIDCSecretParams{
		FederationHumanParams: human, ProviderID: providerID, ExpectedVersion: version,
	})
	if err != nil {
		return FederationSecretMutationReceipt{}, mapRepositoryError(err)
	}
	if !validFederationSecretPreparation(preparation, tenantID, providerID) {
		return FederationSecretMutationReceipt{}, ErrUnavailable
	}
	if preparation.CurrentSecretID == nil {
		return FederationSecretMutationReceipt{}, ErrConflict
	}
	now, err := service.currentTime()
	if err != nil {
		return FederationSecretMutationReceipt{}, err
	}
	receipt, err := service.repository.ClearOIDCClientSecret(ctx, FederationClearOIDCSecretParams{
		FederationHumanParams: human, Audit: input.Audit, OccurredAt: now,
		ProviderID: providerID, ExpectedVersion: version,
		ExpectedRevision: preparation.NextSecretRevision, Reason: input.Reason,
	})
	if err != nil {
		return FederationSecretMutationReceipt{}, mapRepositoryError(err)
	}
	if receipt.ProviderID != providerID || receipt.ProviderVersion != version+1 ||
		receipt.SecretRevision != preparation.NextSecretRevision {
		return FederationSecretMutationReceipt{}, ErrUnavailable
	}
	return receipt, nil
}

func (service *FederationService) ReplaceMappingPolicy(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, providerID uuid.UUID,
	input FederationReplaceMappingPolicyInput,
) (FederationPolicyMutationReceipt, error) {
	normalized, version, err := normalizeFederationMappingPolicy(providerID, input)
	if err != nil {
		return FederationPolicyMutationReceipt{}, err
	}
	authority, human, err := service.resolveHumanAuthority(ctx, actor, tenantID)
	if err != nil {
		return FederationPolicyMutationReceipt{}, err
	}
	resource := authorization.ResourceContext{TenantID: tenantID}
	if service.evaluator.RequireTenant(authority, authorization.TenantPermissionIdentityMappingManage, resource) != nil ||
		service.evaluator.RequireTenant(authority, authorization.TenantPermissionRoleGrant, resource) != nil {
		return FederationPolicyMutationReceipt{}, ErrForbidden
	}
	for _, rule := range normalized.Rules {
		if rule.OperatorTeamID == nil {
			continue
		}
		relationship := authorization.OperatorTeamRelationship{
			OperatorTeamID:    *rule.OperatorTeamID,
			AssignmentEpochID: *rule.OperatorTeamAssignmentEpochID,
		}
		resource.OperatorTeamRelationship = &relationship
		if service.evaluator.RequireTenant(
			authority, authorization.TenantPermissionOperatorTeamRosterManage, resource,
		) != nil {
			return FederationPolicyMutationReceipt{}, ErrForbidden
		}
	}
	if service.repository == nil {
		return FederationPolicyMutationReceipt{}, ErrUnavailable
	}
	now, err := service.currentTime()
	if err != nil {
		return FederationPolicyMutationReceipt{}, err
	}
	receipt, err := service.repository.ReplaceFederatedMappingPolicy(ctx, FederationReplaceMappingPolicyParams{
		FederationHumanParams: human, Audit: normalized.Audit, OccurredAt: now,
		ProviderID: providerID, ExpectedVersion: version, Input: normalized,
	})
	if err != nil {
		return FederationPolicyMutationReceipt{}, mapRepositoryError(err)
	}
	if receipt.ProviderID != providerID || receipt.ProviderVersion != version+1 ||
		receipt.MappingRevision < 2 || receipt.AssurancePolicyRevision != 0 {
		return FederationPolicyMutationReceipt{}, ErrUnavailable
	}
	return receipt, nil
}

func (service *FederationService) GetMappingPolicy(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, providerID uuid.UUID,
) (FederationMappingPolicy, error) {
	if !validUUIDv7(providerID) {
		return FederationMappingPolicy{}, ErrInvalidInput
	}
	human, err := service.require(ctx, actor, tenantID, authorization.TenantPermissionIdentityMappingRead)
	if err != nil {
		return FederationMappingPolicy{}, err
	}
	if service.repository == nil {
		return FederationMappingPolicy{}, ErrUnavailable
	}
	policy, err := service.repository.GetFederatedMappingPolicy(ctx, FederationGetParams{
		FederationHumanParams: human, ProviderID: providerID,
	})
	if err != nil {
		return FederationMappingPolicy{}, mapRepositoryError(err)
	}
	policy = cloneFederationMappingPolicy(policy)
	if !normalizeFederationMappingPolicyProjection(&policy, tenantID, providerID) {
		return FederationMappingPolicy{}, ErrUnavailable
	}
	return policy, nil
}

func (service *FederationService) ReplaceAssurancePolicy(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, providerID uuid.UUID,
	input FederationReplaceAssurancePolicyInput,
) (FederationPolicyMutationReceipt, error) {
	normalized, version, err := normalizeFederationAssurancePolicy(providerID, input)
	if err != nil {
		return FederationPolicyMutationReceipt{}, err
	}
	human, err := service.require(ctx, actor, tenantID, authorization.TenantPermissionIdentityPolicyManage)
	if err != nil {
		return FederationPolicyMutationReceipt{}, err
	}
	if service.repository == nil {
		return FederationPolicyMutationReceipt{}, ErrUnavailable
	}
	now, err := service.currentTime()
	if err != nil {
		return FederationPolicyMutationReceipt{}, err
	}
	receipt, err := service.repository.ReplaceFederatedAssurancePolicy(ctx, FederationReplaceAssurancePolicyParams{
		FederationHumanParams: human, Audit: normalized.Audit, OccurredAt: now,
		ProviderID: providerID, ExpectedVersion: version, Input: normalized,
	})
	if err != nil {
		return FederationPolicyMutationReceipt{}, mapRepositoryError(err)
	}
	if receipt.ProviderID != providerID || receipt.ProviderVersion != version+1 ||
		receipt.AssurancePolicyRevision < 2 || receipt.MappingRevision != 0 {
		return FederationPolicyMutationReceipt{}, ErrUnavailable
	}
	return receipt, nil
}

func (service *FederationService) GetAssurancePolicy(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, providerID uuid.UUID,
) (FederationAssurancePolicy, error) {
	if !validUUIDv7(providerID) {
		return FederationAssurancePolicy{}, ErrInvalidInput
	}
	human, err := service.require(ctx, actor, tenantID, authorization.TenantPermissionIdentityPolicyRead)
	if err != nil {
		return FederationAssurancePolicy{}, err
	}
	if service.repository == nil {
		return FederationAssurancePolicy{}, ErrUnavailable
	}
	policy, err := service.repository.GetFederatedAssurancePolicy(ctx, FederationGetParams{
		FederationHumanParams: human, ProviderID: providerID,
	})
	if err != nil {
		return FederationAssurancePolicy{}, mapRepositoryError(err)
	}
	policy = cloneFederationAssurancePolicy(policy)
	if !normalizeFederationAssurancePolicyProjection(&policy, tenantID, providerID) {
		return FederationAssurancePolicy{}, ErrUnavailable
	}
	return policy, nil
}

func (service *FederationService) RefreshOIDCTrustDocuments(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, providerID uuid.UUID,
	input FederationOIDCTrustDocumentsInput,
) (FederationOIDCTrustDocumentsReceipt, error) {
	normalized, version, err := normalizeFederationOIDCTrustDocuments(providerID, input)
	if err != nil {
		return FederationOIDCTrustDocumentsReceipt{}, err
	}
	human, err := service.require(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderManage)
	if err != nil {
		return FederationOIDCTrustDocumentsReceipt{}, err
	}
	if service.repository == nil || service.oidcTrust == nil {
		return FederationOIDCTrustDocumentsReceipt{}, ErrUnavailable
	}
	preparation, err := service.repository.PrepareOIDCTrustDocuments(ctx, FederationPrepareOIDCTrustParams{
		FederationHumanParams: human, ProviderID: providerID, ExpectedVersion: version,
	})
	if err != nil {
		return FederationOIDCTrustDocumentsReceipt{}, mapRepositoryError(err)
	}
	if preparation.TenantID != tenantID || preparation.ProviderID != providerID ||
		!validCanonicalHTTPSURL(preparation.Issuer, true) ||
		preparation.NextDiscoveryRevision < 2 || preparation.NextJWKSRevision < 2 ||
		preparation.NextDiscoveryRevision > maximumFederationRevision ||
		preparation.NextJWKSRevision > maximumFederationRevision {
		return FederationOIDCTrustDocumentsReceipt{}, ErrUnavailable
	}
	discoveryRequest := federatedoidc.DiscoveryRequest{
		Issuer: preparation.Issuer, Revision: uint64(preparation.NextDiscoveryRevision),
		Policy: federatedoidc.TrustPolicy{
			ClientAuthentication: normalized.ClientAuthentication,
			SigningAlgorithms:    slices.Clone(normalized.SigningAlgorithms),
		},
	}
	documents, err := service.oidcTrust.FetchTrustDocuments(
		ctx, discoveryRequest, uint64(preparation.NextJWKSRevision),
	)
	if err != nil {
		return FederationOIDCTrustDocumentsReceipt{}, ErrUnavailable
	}
	defer clear(documents.Discovery.Document)
	defer clear(documents.JWKS.Document)
	defer clear(documents.Discovery.Digest[:])
	defer clear(documents.JWKS.Digest[:])
	keyCount, err := service.oidcTrust.ValidateTrustDocumentRecords(
		documents, discoveryRequest, uint64(preparation.NextJWKSRevision),
	)
	if err != nil {
		return FederationOIDCTrustDocumentsReceipt{}, ErrUnavailable
	}
	documents.KeyCount = keyCount
	now, err := service.currentTime()
	if err != nil {
		return FederationOIDCTrustDocumentsReceipt{}, err
	}
	receipt, err := service.repository.CommitOIDCTrustDocuments(ctx, FederationCommitOIDCTrustParams{
		FederationHumanParams: human, Audit: normalized.Audit, OccurredAt: now,
		ProviderID: providerID, ExpectedVersion: version, Preparation: preparation,
		Documents: documents, Reason: normalized.Reason,
	})
	if err != nil {
		return FederationOIDCTrustDocumentsReceipt{}, mapRepositoryError(err)
	}
	if receipt.ProviderID != providerID || receipt.ProviderVersion != version+1 ||
		receipt.DiscoveryRevision != preparation.NextDiscoveryRevision ||
		receipt.JWKSRevision != preparation.NextJWKSRevision || receipt.KeyCount != documents.KeyCount {
		return FederationOIDCTrustDocumentsReceipt{}, ErrUnavailable
	}
	return receipt, nil
}

func (service *FederationService) require(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	permission authorization.TenantPermission,
) (FederationHumanParams, error) {
	authority, human, err := service.resolveHumanAuthority(ctx, actor, tenantID)
	if err != nil {
		return FederationHumanParams{}, err
	}
	if err := service.evaluator.RequireTenant(authority, permission, authorization.ResourceContext{TenantID: tenantID}); err != nil {
		return FederationHumanParams{}, ErrForbidden
	}
	return human, nil
}

func (service *FederationService) resolveHumanAuthority(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
) (authorization.TenantAuthority, FederationHumanParams, error) {
	if service == nil || service.authority == nil || ctx == nil || ctx.Err() != nil || !validUUIDv7(tenantID) {
		return authorization.TenantAuthority{}, FederationHumanParams{}, ErrInvalidInput
	}
	if !validUUIDv7(actor.UserID) || !validUUIDv7(actor.SessionID) || actor.ActiveTenantID != tenantID ||
		!validText(actor.AuthenticationMethod, 1, 64) {
		return authorization.TenantAuthority{}, FederationHumanParams{}, ErrForbidden
	}
	authority, err := service.authority.ResolveHumanAuthority(ctx, authorization.ResolveAuthorityParams{
		Actor: actor, TenantID: tenantID,
	})
	if err != nil {
		return authorization.TenantAuthority{}, FederationHumanParams{}, mapRepositoryError(err)
	}
	if authority.TenantID != tenantID || authority.Principal.ID != actor.UserID ||
		authority.Principal.Kind != authorization.PrincipalKindHuman || !validUUIDv7(authority.MembershipID) {
		return authorization.TenantAuthority{}, FederationHumanParams{}, ErrUnavailable
	}
	return authority, FederationHumanParams{
		Actor: actor, MembershipID: authority.MembershipID, TenantID: tenantID,
	}, nil
}

func (service *FederationService) currentTime() (time.Time, error) {
	if service == nil || service.now == nil {
		return time.Time{}, ErrUnavailable
	}
	value := service.now().UTC().Truncate(time.Microsecond)
	if !validInstant(value) {
		return time.Time{}, ErrUnavailable
	}
	return value, nil
}

func (service *FederationService) nextID() (uuid.UUID, error) {
	if service == nil || service.newID == nil {
		return uuid.Nil, ErrUnavailable
	}
	value, err := service.newID()
	if err != nil || !validUUIDv7(value) {
		return uuid.Nil, ErrUnavailable
	}
	return value, nil
}

func (service *FederationService) threeDistinctIDs() (uuid.UUID, uuid.UUID, uuid.UUID, error) {
	values := [3]uuid.UUID{}
	for index := range values {
		value, err := service.nextID()
		if err != nil {
			return uuid.Nil, uuid.Nil, uuid.Nil, err
		}
		for prior := range index {
			if value == values[prior] {
				return uuid.Nil, uuid.Nil, uuid.Nil, ErrUnavailable
			}
		}
		values[index] = value
	}
	return values[0], values[1], values[2], nil
}

func (service *FederationService) oidcRedirectURI() string {
	return service.publicOrigin + "/api/v1/auth/federated/oidc/callback"
}

func (service *FederationService) oidcPostLogoutRedirectURI() string {
	return service.publicOrigin + "/signed-out"
}

func (service *FederationService) validOIDCPostLogoutRedirect(configuration *FederationOIDCCreateConfiguration) bool {
	return service != nil && (configuration == nil ||
		configuration.PostLogoutRedirectURI == service.oidcPostLogoutRedirectURI())
}

func (service *FederationService) validFederationProvider(provider FederationProvider, tenantID uuid.UUID) bool {
	return service != nil && validFederationProvider(provider, tenantID) && (provider.OIDC == nil ||
		provider.OIDC.RedirectURI == service.oidcRedirectURI() &&
			provider.OIDC.PostLogoutRedirectURI == service.oidcPostLogoutRedirectURI())
}

func (service *FederationService) samlACSURL() string {
	return service.publicOrigin + "/api/v1/auth/federated/saml/acs"
}

func (service *FederationService) samlSPMetadataBaseURL() string {
	return service.publicOrigin + "/api/v1/auth/federated/saml"
}

func bytesCompareUUID(left, right uuid.UUID) int {
	return bytes.Compare(left[:], right[:])
}
