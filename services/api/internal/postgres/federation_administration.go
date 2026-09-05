package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

const maximumFederationAdministrationDocumentBytes = 4 << 20

var federationAdministrationFunctions = []string{
	"app.list_tenant_federated_auth_providers_v1",
	"app.get_tenant_federated_auth_provider_v1",
	"app.create_tenant_federated_auth_provider_v1",
	"app.update_tenant_federated_auth_provider_v1",
	"app.archive_tenant_federated_auth_provider_v1",
	"app.prepare_tenant_oidc_client_secret_v1",
	"app.replace_tenant_oidc_client_secret_v1",
	"app.clear_tenant_oidc_client_secret_v1",
	"app.get_tenant_federated_mapping_policy_v1",
	"app.replace_tenant_federated_mapping_policy_v1",
	"app.get_tenant_federated_assurance_policy_v1",
	"app.replace_tenant_federated_assurance_policy_v1",
	"app.prepare_tenant_oidc_trust_documents_v1",
	"app.commit_tenant_oidc_trust_documents_v1",
	"app.prepare_tenant_saml_metadata_v1",
	"app.replace_tenant_saml_metadata_v1",
	"app.prepare_tenant_saml_sp_credential_v1",
	"app.replace_tenant_saml_sp_credential_v1",
	"app.clear_tenant_saml_sp_credential_v1",
}

var _ identityprovider.FederationAdministrationRepository = (*IdentityProviderRepository)(nil)

type federationBindingWire struct {
	ID        uuid.UUID `json:"id"`
	LoginKey  string    `json:"loginKey"`
	Enabled   bool      `json:"enabled"`
	Version   int64     `json:"version"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type federationOIDCWire struct {
	Issuer                string   `json:"issuer"`
	ClientID              string   `json:"clientId"`
	RedirectURI           string   `json:"redirectUri"`
	PostLogoutRedirectURI string   `json:"postLogoutRedirectUri"`
	ExtraScopes           []string `json:"extraScopes"`
	AllowRefreshToken     bool     `json:"allowRefreshToken"`
	UseUserInfo           bool     `json:"useUserInfo"`
	ClientSecretPresent   bool     `json:"clientSecretPresent"`
	ClientSecretRevision  int64    `json:"clientSecretRevision"`
	DiscoveryRevision     int64    `json:"discoveryRevision"`
	JWKSRevision          int64    `json:"jwksRevision"`
}

type federationSAMLWire struct {
	ExpectedEntityID                string   `json:"expectedEntityId"`
	SPEntityID                      string   `json:"spEntityId"`
	ACSURL                          string   `json:"acsUrl"`
	SPKeyPresent                    bool     `json:"spKeyPresent"`
	SPKeyRevision                   int64    `json:"spKeyRevision"`
	MetadataRevision                int64    `json:"metadataRevision"`
	RedirectSignatureAlgorithm      string   `json:"redirectSignatureAlgorithm"`
	SignaturePolicy                 string   `json:"signaturePolicy"`
	EncryptionPolicy                string   `json:"encryptionPolicy"`
	RequestedAuthnContexts          []string `json:"requestedAuthnContexts"`
	SubjectSource                   string   `json:"subjectSource"`
	SubjectAttributeName            *string  `json:"subjectAttributeName"`
	SubjectAttributeNameFormat      *string  `json:"subjectAttributeNameFormat"`
	ClockSkewSeconds                int64    `json:"clockSkewSeconds"`
	MaximumAuthenticationAgeSeconds int64    `json:"maxAuthenticationAgeSeconds"`
	SingleLogoutConfigured          bool     `json:"singleLogoutConfigured"`
}

type federationProviderWire struct {
	ID                      uuid.UUID             `json:"id"`
	TenantID                uuid.UUID             `json:"tenantId"`
	Key                     string                `json:"key"`
	DisplayName             string                `json:"displayName"`
	Description             string                `json:"description"`
	Kind                    string                `json:"kind"`
	Enabled                 bool                  `json:"enabled"`
	Configured              bool                  `json:"configured"`
	Binding                 federationBindingWire `json:"binding"`
	ArchivedAt              *time.Time            `json:"archivedAt"`
	Version                 int64                 `json:"version"`
	CreatedAt               time.Time             `json:"createdAt"`
	UpdatedAt               time.Time             `json:"updatedAt"`
	ConfigurationRevision   int64                 `json:"configurationRevision"`
	SecurityRevision        int64                 `json:"securityRevision"`
	PlanRevision            int64                 `json:"planRevision"`
	AssurancePolicyRevision int64                 `json:"assurancePolicyRevision"`
	JITMode                 string                `json:"jitMode"`
	NoMatchPolicy           string                `json:"noMatchPolicy"`
	OIDC                    *federationOIDCWire   `json:"oidc"`
	SAML                    *federationSAMLWire   `json:"saml"`
}

type federationCreateResultWire struct {
	Provider federationProviderWire `json:"provider"`
	Replayed bool                   `json:"replayed"`
}

type federationSecretPreparationWire struct {
	TenantID           uuid.UUID  `json:"tenantId"`
	ProviderID         uuid.UUID  `json:"providerId"`
	BindingID          uuid.UUID  `json:"bindingId"`
	CurrentSecretID    *uuid.UUID `json:"currentSecretId"`
	NextSecretRevision int64      `json:"nextSecretRevision"`
}

type federationSecretReceiptWire struct {
	ProviderID      uuid.UUID `json:"providerId"`
	ProviderVersion int64     `json:"providerVersion"`
	SecretRevision  int64     `json:"secretRevision"`
}

type federationPolicyReceiptWire struct {
	ProviderID              uuid.UUID `json:"providerId"`
	ProviderVersion         int64     `json:"providerVersion"`
	MappingRevision         int64     `json:"mappingRevision,omitempty"`
	AssurancePolicyRevision int64     `json:"assurancePolicyRevision,omitempty"`
}

type federationClaimRuleWire struct {
	Source       string  `json:"source"`
	Kind         string  `json:"kind"`
	ClaimName    string  `json:"claimName"`
	ProfileField *string `json:"profileField"`
	Required     bool    `json:"required"`
}

type federationAttributeRuleWire struct {
	Kind                string  `json:"kind"`
	AttributeName       string  `json:"attributeName"`
	AttributeNameFormat string  `json:"attributeNameFormat"`
	ProfileField        *string `json:"profileField"`
	Required            bool    `json:"required"`
}

type federationMappingRuleWire struct {
	RuleID                        uuid.UUID   `json:"ruleId"`
	Priority                      int         `json:"priority"`
	MatcherKind                   string      `json:"matcherKind"`
	ClaimName                     *string     `json:"claimName"`
	MatcherValue                  string      `json:"matcherValue"`
	ReconciliationMode            string      `json:"reconciliationMode"`
	TenantSecurityGroupID         uuid.UUID   `json:"tenantSecurityGroupId"`
	RoleIDs                       []uuid.UUID `json:"roleIds"`
	OperatorTeamID                *uuid.UUID  `json:"operatorTeamId"`
	OperatorTeamAssignmentEpochID *uuid.UUID  `json:"operatorTeamAssignmentEpochId"`
	Enabled                       bool        `json:"enabled"`
}

type federationMappingPolicyWire struct {
	TenantID           uuid.UUID                     `json:"tenantId"`
	ProviderID         uuid.UUID                     `json:"providerId"`
	Kind               string                        `json:"kind"`
	ProviderVersion    int64                         `json:"providerVersion"`
	MappingRevision    int64                         `json:"mappingRevision"`
	OIDCClaimRules     []federationClaimRuleWire     `json:"oidcClaimRules"`
	SAMLAttributeRules []federationAttributeRuleWire `json:"samlAttributeRules"`
	Rules              []federationMappingRuleWire   `json:"rules"`
}

type federationAssuranceRuleWire struct {
	RuleID                          uuid.UUID `json:"ruleId"`
	Enabled                         bool      `json:"enabled"`
	Level                           string    `json:"level"`
	ExactValue                      *string   `json:"exactValue"`
	RequiredValues                  []string  `json:"requiredValues"`
	MaximumAuthenticationAgeSeconds int       `json:"maximumAuthenticationAgeSeconds"`
}

type federationAssurancePolicyWire struct {
	TenantID                uuid.UUID                     `json:"tenantId"`
	ProviderID              uuid.UUID                     `json:"providerId"`
	Kind                    string                        `json:"kind"`
	ProviderVersion         int64                         `json:"providerVersion"`
	AssurancePolicyRevision int64                         `json:"assurancePolicyRevision"`
	Rules                   []federationAssuranceRuleWire `json:"rules"`
}

type federationOIDCTrustPreparationWire struct {
	TenantID              uuid.UUID `json:"tenantId"`
	ProviderID            uuid.UUID `json:"providerId"`
	Issuer                string    `json:"issuer"`
	NextDiscoveryRevision int64     `json:"nextDiscoveryRevision"`
	NextJWKSRevision      int64     `json:"nextJwksRevision"`
}

type federationOIDCTrustReceiptWire struct {
	ProviderID        uuid.UUID `json:"providerId"`
	ProviderVersion   int64     `json:"providerVersion"`
	DiscoveryRevision int64     `json:"discoveryRevision"`
	JWKSRevision      int64     `json:"jwksRevision"`
	KeyCount          int       `json:"keyCount"`
}

type federationAuditWire struct {
	RequestID            uuid.UUID `json:"requestId"`
	CorrelationID        uuid.UUID `json:"correlationId"`
	RemoteAddress        *string   `json:"remoteAddress"`
	UserAgent            string    `json:"userAgent"`
	AuthenticationMethod string    `json:"authenticationMethod"`
}

type federationOIDCInputWire struct {
	Issuer                string   `json:"issuer"`
	ClientID              string   `json:"clientId"`
	PostLogoutRedirectURI string   `json:"postLogoutRedirectUri"`
	ExtraScopes           []string `json:"extraScopes"`
	AllowRefreshToken     bool     `json:"allowRefreshToken"`
	UseUserInfo           bool     `json:"useUserInfo"`
}

type federationSAMLInputWire struct {
	ExpectedEntityID                string   `json:"expectedEntityId"`
	RedirectSignatureAlgorithm      string   `json:"redirectSignatureAlgorithm"`
	SignaturePolicy                 string   `json:"signaturePolicy"`
	EncryptionPolicy                string   `json:"encryptionPolicy"`
	RequestedAuthnContexts          []string `json:"requestedAuthnContexts"`
	SubjectSource                   string   `json:"subjectSource"`
	SubjectAttributeName            *string  `json:"subjectAttributeName"`
	SubjectAttributeNameFormat      *string  `json:"subjectAttributeNameFormat"`
	ClockSkewSeconds                int64    `json:"clockSkewSeconds"`
	MaximumAuthenticationAgeSeconds int64    `json:"maxAuthenticationAgeSeconds"`
}

func (r *IdentityProviderRepository) ListFederatedProviders(
	ctx context.Context,
	params identityprovider.FederationListParams,
) ([]identityprovider.FederationProviderSummary, error) {
	if !validFederationHuman(params.FederationHumanParams) || params.Limit < 1 || params.Limit > 101 ||
		params.After != nil && !identityProviderUUIDv7(*params.After) {
		return nil, identityprovider.ErrInvalidInput
	}
	document, err := r.callFederationAdministrationFunction(ctx, params.FederationHumanParams,
		"app.list_tenant_federated_auth_providers_v1", struct {
			After           *uuid.UUID `json:"after"`
			Limit           int32      `json:"limit"`
			IncludeArchived bool       `json:"includeArchived"`
		}{params.After, params.Limit, params.IncludeArchived})
	if err != nil {
		return nil, err
	}
	var rows []federationProviderWire
	if err := decodeFederationAdministrationDocument(document, &rows); err != nil {
		return nil, err
	}
	result := make([]identityprovider.FederationProviderSummary, 0, len(rows))
	for _, row := range rows {
		result = append(result, federationProviderFromWire(row).FederationProviderSummary)
	}
	return result, nil
}

func (r *IdentityProviderRepository) GetFederatedProvider(
	ctx context.Context,
	params identityprovider.FederationGetParams,
) (identityprovider.FederationProvider, error) {
	if !validFederationHuman(params.FederationHumanParams) || !identityProviderUUIDv7(params.ProviderID) {
		return identityprovider.FederationProvider{}, identityprovider.ErrInvalidInput
	}
	document, err := r.callFederationAdministrationFunction(ctx, params.FederationHumanParams,
		"app.get_tenant_federated_auth_provider_v1", struct {
			ProviderID uuid.UUID `json:"providerId"`
		}{params.ProviderID})
	if err != nil {
		return identityprovider.FederationProvider{}, err
	}
	var wire federationProviderWire
	if err := decodeFederationAdministrationDocument(document, &wire); err != nil {
		return identityprovider.FederationProvider{}, err
	}
	return federationProviderFromWire(wire), nil
}

func (r *IdentityProviderRepository) CreateFederatedProvider(
	ctx context.Context,
	params identityprovider.FederationCreateParams,
) (identityprovider.FederationCreateResult, error) {
	if !validFederationHuman(params.FederationHumanParams) || !identityProviderUUIDv7(params.CommandID) ||
		!identityProviderUUIDv7(params.ProviderID) || !identityProviderUUIDv7(params.BindingID) {
		return identityprovider.FederationCreateResult{}, identityprovider.ErrInvalidInput
	}
	request := struct {
		MembershipID          uuid.UUID                `json:"membershipId"`
		CommandID             uuid.UUID                `json:"commandId"`
		ProviderID            uuid.UUID                `json:"providerId"`
		BindingID             uuid.UUID                `json:"bindingId"`
		IdempotencyDigest     []byte                   `json:"idempotencyDigest"`
		RequestDigest         []byte                   `json:"requestDigest"`
		Kind                  string                   `json:"kind"`
		Key                   string                   `json:"key"`
		LoginKey              string                   `json:"loginKey"`
		DisplayName           string                   `json:"displayName"`
		Description           string                   `json:"description"`
		JITMode               string                   `json:"jitMode"`
		NoMatchPolicy         string                   `json:"noMatchPolicy"`
		OIDC                  *federationOIDCInputWire `json:"oidc"`
		SAML                  *federationSAMLInputWire `json:"saml"`
		OIDCRedirectURI       string                   `json:"oidcRedirectUri"`
		SAMLACSURL            string                   `json:"samlAcsUrl"`
		SAMLSPMetadataBaseURL string                   `json:"samlSpMetadataBaseUrl"`
		Reason                string                   `json:"reason"`
		OccurredAt            time.Time                `json:"occurredAt"`
		Audit                 federationAuditWire      `json:"audit"`
	}{
		MembershipID: params.MembershipID, CommandID: params.CommandID, ProviderID: params.ProviderID,
		BindingID: params.BindingID, IdempotencyDigest: params.IdempotencyKeyDigest[:],
		RequestDigest: params.RequestDigest[:], Kind: string(params.Input.Kind), Key: params.Input.Key,
		LoginKey: params.Input.LoginKey, DisplayName: params.Input.DisplayName, Description: params.Input.Description,
		JITMode: string(params.Input.JITMode), NoMatchPolicy: string(params.Input.NoMatchPolicy),
		OIDC: federationOIDCInput(params.Input.OIDC), SAML: federationSAMLInput(params.Input.SAML),
		OIDCRedirectURI: params.OIDCRedirectURI, SAMLACSURL: params.SAMLACSURL, SAMLSPMetadataBaseURL: params.SAMLSPMetadataBaseURL,
		Reason: params.Input.Reason, OccurredAt: params.OccurredAt, Audit: federationAudit(params.Audit, params.Actor.AuthenticationMethod),
	}
	document, err := r.callFederationAdministrationFunction(ctx, params.FederationHumanParams,
		"app.create_tenant_federated_auth_provider_v1", request)
	if err != nil {
		return identityprovider.FederationCreateResult{}, err
	}
	var wire federationCreateResultWire
	if err := decodeFederationAdministrationDocument(document, &wire); err != nil {
		return identityprovider.FederationCreateResult{}, err
	}
	return identityprovider.FederationCreateResult{Provider: federationProviderFromWire(wire.Provider), Replayed: wire.Replayed}, nil
}

func (r *IdentityProviderRepository) UpdateFederatedProvider(
	ctx context.Context,
	params identityprovider.FederationUpdateParams,
) (identityprovider.FederationProvider, error) {
	request := struct {
		MembershipID          uuid.UUID                `json:"membershipId"`
		ProviderID            uuid.UUID                `json:"providerId"`
		ExpectedVersion       int64                    `json:"expectedVersion"`
		DisplayName           string                   `json:"displayName"`
		Description           string                   `json:"description"`
		Enabled               bool                     `json:"enabled"`
		JITMode               string                   `json:"jitMode"`
		NoMatchPolicy         string                   `json:"noMatchPolicy"`
		OIDC                  *federationOIDCInputWire `json:"oidc"`
		SAML                  *federationSAMLInputWire `json:"saml"`
		OIDCRedirectURI       string                   `json:"oidcRedirectUri"`
		SAMLACSURL            string                   `json:"samlAcsUrl"`
		SAMLSPMetadataBaseURL string                   `json:"samlSpMetadataBaseUrl"`
		Reason                string                   `json:"reason"`
		OccurredAt            time.Time                `json:"occurredAt"`
		Audit                 federationAuditWire      `json:"audit"`
	}{params.MembershipID, params.ProviderID, params.ExpectedVersion, params.Input.DisplayName,
		params.Input.Description, params.Input.Enabled, string(params.Input.JITMode), string(params.Input.NoMatchPolicy),
		federationOIDCInput(params.Input.OIDC), federationSAMLInput(params.Input.SAML), params.OIDCRedirectURI,
		params.SAMLACSURL, params.SAMLSPMetadataBaseURL, params.Input.Reason, params.OccurredAt,
		federationAudit(params.Audit, params.Actor.AuthenticationMethod)}
	document, err := r.callFederationAdministrationFunction(ctx, params.FederationHumanParams,
		"app.update_tenant_federated_auth_provider_v1", request)
	if err != nil {
		return identityprovider.FederationProvider{}, err
	}
	var wire federationProviderWire
	if err := decodeFederationAdministrationDocument(document, &wire); err != nil {
		return identityprovider.FederationProvider{}, err
	}
	return federationProviderFromWire(wire), nil
}

func (r *IdentityProviderRepository) ArchiveFederatedProvider(
	ctx context.Context,
	params identityprovider.FederationArchiveParams,
) (int64, error) {
	document, err := r.callFederationAdministrationFunction(ctx, params.FederationHumanParams,
		"app.archive_tenant_federated_auth_provider_v1", struct {
			MembershipID    uuid.UUID           `json:"membershipId"`
			ProviderID      uuid.UUID           `json:"providerId"`
			ExpectedVersion int64               `json:"expectedVersion"`
			Reason          string              `json:"reason"`
			OccurredAt      time.Time           `json:"occurredAt"`
			Audit           federationAuditWire `json:"audit"`
		}{params.MembershipID, params.ProviderID, params.ExpectedVersion, params.Reason, params.OccurredAt,
			federationAudit(params.Audit, params.Actor.AuthenticationMethod)})
	if err != nil {
		return 0, err
	}
	var result struct {
		Version int64 `json:"version"`
	}
	if err := decodeFederationAdministrationDocument(document, &result); err != nil {
		return 0, err
	}
	return result.Version, nil
}

func (r *IdentityProviderRepository) PrepareOIDCClientSecretReplacement(
	ctx context.Context,
	params identityprovider.FederationPrepareOIDCSecretParams,
) (identityprovider.FederationSecretPreparation, error) {
	document, err := r.callFederationAdministrationFunction(ctx, params.FederationHumanParams,
		"app.prepare_tenant_oidc_client_secret_v1", struct {
			MembershipID    uuid.UUID `json:"membershipId"`
			ProviderID      uuid.UUID `json:"providerId"`
			ExpectedVersion int64     `json:"expectedVersion"`
		}{params.MembershipID, params.ProviderID, params.ExpectedVersion})
	if err != nil {
		return identityprovider.FederationSecretPreparation{}, err
	}
	var wire federationSecretPreparationWire
	if err := decodeFederationAdministrationDocument(document, &wire); err != nil {
		return identityprovider.FederationSecretPreparation{}, err
	}
	return identityprovider.FederationSecretPreparation{
		TenantID: wire.TenantID, ProviderID: wire.ProviderID, BindingID: wire.BindingID,
		CurrentSecretID: wire.CurrentSecretID, NextSecretRevision: wire.NextSecretRevision,
	}, nil
}

func (r *IdentityProviderRepository) ReplaceOIDCClientSecret(
	ctx context.Context,
	params identityprovider.FederationReplaceOIDCSecretParams,
) (identityprovider.FederationSecretMutationReceipt, error) {
	nonce := slices.Clone(params.Secret.Envelope.Nonce[:])
	ciphertext := slices.Clone(params.Secret.Envelope.Ciphertext)
	defer clear(nonce)
	defer clear(ciphertext)
	document, err := r.callFederationAdministrationFunction(ctx, params.FederationHumanParams,
		"app.replace_tenant_oidc_client_secret_v1", struct {
			MembershipID     uuid.UUID           `json:"membershipId"`
			ProviderID       uuid.UUID           `json:"providerId"`
			BindingID        uuid.UUID           `json:"bindingId"`
			ExpectedVersion  int64               `json:"expectedVersion"`
			ExpectedRevision int64               `json:"expectedRevision"`
			SecretID         uuid.UUID           `json:"secretId"`
			KeyVersion       int16               `json:"keyVersion"`
			Nonce            []byte              `json:"nonce"`
			Ciphertext       []byte              `json:"ciphertext"`
			Reason           string              `json:"reason"`
			OccurredAt       time.Time           `json:"occurredAt"`
			Audit            federationAuditWire `json:"audit"`
		}{params.MembershipID, params.ProviderID, params.BindingID, params.ExpectedVersion,
			params.ExpectedRevision, params.Secret.SecretID, params.Secret.Envelope.KeyVersion, nonce, ciphertext,
			params.Reason, params.OccurredAt, federationAudit(params.Audit, params.Actor.AuthenticationMethod)})
	if err != nil {
		return identityprovider.FederationSecretMutationReceipt{}, err
	}
	return decodeFederationSecretReceipt(document)
}

func (r *IdentityProviderRepository) ClearOIDCClientSecret(
	ctx context.Context,
	params identityprovider.FederationClearOIDCSecretParams,
) (identityprovider.FederationSecretMutationReceipt, error) {
	document, err := r.callFederationAdministrationFunction(ctx, params.FederationHumanParams,
		"app.clear_tenant_oidc_client_secret_v1", struct {
			MembershipID     uuid.UUID           `json:"membershipId"`
			ProviderID       uuid.UUID           `json:"providerId"`
			ExpectedVersion  int64               `json:"expectedVersion"`
			ExpectedRevision int64               `json:"expectedRevision"`
			Reason           string              `json:"reason"`
			OccurredAt       time.Time           `json:"occurredAt"`
			Audit            federationAuditWire `json:"audit"`
		}{params.MembershipID, params.ProviderID, params.ExpectedVersion, params.ExpectedRevision,
			params.Reason, params.OccurredAt, federationAudit(params.Audit, params.Actor.AuthenticationMethod)})
	if err != nil {
		return identityprovider.FederationSecretMutationReceipt{}, err
	}
	return decodeFederationSecretReceipt(document)
}

func (r *IdentityProviderRepository) GetFederatedMappingPolicy(
	ctx context.Context,
	params identityprovider.FederationGetParams,
) (identityprovider.FederationMappingPolicy, error) {
	if !validFederationHuman(params.FederationHumanParams) || !identityProviderUUIDv7(params.ProviderID) {
		return identityprovider.FederationMappingPolicy{}, identityprovider.ErrInvalidInput
	}
	document, err := r.callFederationAdministrationFunction(ctx, params.FederationHumanParams,
		"app.get_tenant_federated_mapping_policy_v1", struct {
			ProviderID uuid.UUID `json:"providerId"`
		}{params.ProviderID})
	if err != nil {
		return identityprovider.FederationMappingPolicy{}, err
	}
	var wire federationMappingPolicyWire
	if err := decodeFederationAdministrationDocument(document, &wire); err != nil {
		return identityprovider.FederationMappingPolicy{}, err
	}
	claims := make([]identityprovider.FederationOIDCClaimRule, 0, len(wire.OIDCClaimRules))
	for _, claim := range wire.OIDCClaimRules {
		claims = append(claims, identityprovider.FederationOIDCClaimRule{
			Source: claim.Source, Kind: claim.Kind, ClaimName: claim.ClaimName,
			ProfileField: claim.ProfileField, Required: claim.Required,
		})
	}
	attributes := make([]identityprovider.FederationSAMLAttributeRule, 0, len(wire.SAMLAttributeRules))
	for _, attribute := range wire.SAMLAttributeRules {
		attributes = append(attributes, identityprovider.FederationSAMLAttributeRule{
			Kind: attribute.Kind, AttributeName: attribute.AttributeName,
			AttributeNameFormat: attribute.AttributeNameFormat,
			ProfileField:        attribute.ProfileField, Required: attribute.Required,
		})
	}
	rules := make([]identityprovider.FederationMappingRule, 0, len(wire.Rules))
	for _, rule := range wire.Rules {
		rules = append(rules, identityprovider.FederationMappingRule{
			RuleID: rule.RuleID, Priority: rule.Priority, MatcherKind: rule.MatcherKind,
			ClaimName: rule.ClaimName, MatcherValue: rule.MatcherValue,
			ReconciliationMode:    rule.ReconciliationMode,
			TenantSecurityGroupID: rule.TenantSecurityGroupID, RoleIDs: slices.Clone(rule.RoleIDs),
			OperatorTeamID:                rule.OperatorTeamID,
			OperatorTeamAssignmentEpochID: rule.OperatorTeamAssignmentEpochID, Enabled: rule.Enabled,
		})
	}
	return identityprovider.FederationMappingPolicy{
		TenantID: wire.TenantID, ProviderID: wire.ProviderID, Kind: identityprovider.FederationProviderKind(wire.Kind),
		ProviderVersion: wire.ProviderVersion, MappingRevision: wire.MappingRevision,
		OIDCClaimRules: claims, SAMLAttributeRules: attributes, Rules: rules,
	}, nil
}

func (r *IdentityProviderRepository) ReplaceFederatedMappingPolicy(
	ctx context.Context,
	params identityprovider.FederationReplaceMappingPolicyParams,
) (identityprovider.FederationPolicyMutationReceipt, error) {
	type claimWire struct {
		Source       string  `json:"source"`
		Kind         string  `json:"kind"`
		ClaimName    string  `json:"claimName"`
		ProfileField *string `json:"profileField,omitempty"`
		Required     bool    `json:"required"`
	}
	type attributeWire struct {
		Kind                string  `json:"kind"`
		AttributeName       string  `json:"attributeName"`
		AttributeNameFormat string  `json:"attributeNameFormat"`
		ProfileField        *string `json:"profileField,omitempty"`
		Required            bool    `json:"required"`
	}
	type ruleWire struct {
		RuleID                        uuid.UUID   `json:"ruleId"`
		Priority                      int         `json:"priority"`
		MatcherKind                   string      `json:"matcherKind"`
		ClaimName                     *string     `json:"claimName,omitempty"`
		MatcherValue                  string      `json:"matcherValue"`
		ReconciliationMode            string      `json:"reconciliationMode"`
		TenantSecurityGroupID         uuid.UUID   `json:"tenantSecurityGroupId"`
		RoleIDs                       []uuid.UUID `json:"roleIds"`
		OperatorTeamID                *uuid.UUID  `json:"operatorTeamId,omitempty"`
		OperatorTeamAssignmentEpochID *uuid.UUID  `json:"operatorTeamAssignmentEpochId,omitempty"`
		Enabled                       bool        `json:"enabled"`
	}
	claims := make([]claimWire, 0, len(params.Input.OIDCClaimRules))
	for _, claim := range params.Input.OIDCClaimRules {
		claims = append(claims, claimWire{claim.Source, claim.Kind, claim.ClaimName, claim.ProfileField, claim.Required})
	}
	attributes := make([]attributeWire, 0, len(params.Input.SAMLAttributeRules))
	for _, attribute := range params.Input.SAMLAttributeRules {
		attributes = append(attributes, attributeWire{
			attribute.Kind, attribute.AttributeName, attribute.AttributeNameFormat,
			attribute.ProfileField, attribute.Required,
		})
	}
	rules := make([]ruleWire, 0, len(params.Input.Rules))
	for _, rule := range params.Input.Rules {
		rules = append(rules, ruleWire{
			rule.RuleID, rule.Priority, rule.MatcherKind, rule.ClaimName, rule.MatcherValue,
			rule.ReconciliationMode, rule.TenantSecurityGroupID, slices.Clone(rule.RoleIDs),
			rule.OperatorTeamID, rule.OperatorTeamAssignmentEpochID, rule.Enabled,
		})
	}
	document, err := r.callFederationAdministrationFunction(ctx, params.FederationHumanParams,
		"app.replace_tenant_federated_mapping_policy_v1", struct {
			MembershipID       uuid.UUID           `json:"membershipId"`
			ProviderID         uuid.UUID           `json:"providerId"`
			ExpectedVersion    int64               `json:"expectedVersion"`
			Kind               string              `json:"kind"`
			OIDCClaimRules     []claimWire         `json:"oidcClaimRules"`
			SAMLAttributeRules []attributeWire     `json:"samlAttributeRules"`
			Rules              []ruleWire          `json:"rules"`
			Reason             string              `json:"reason"`
			OccurredAt         time.Time           `json:"occurredAt"`
			Audit              federationAuditWire `json:"audit"`
		}{params.MembershipID, params.ProviderID, params.ExpectedVersion, string(params.Input.Kind), claims, attributes, rules,
			params.Input.Reason, params.OccurredAt, federationAudit(params.Audit, params.Actor.AuthenticationMethod)})
	if err != nil {
		return identityprovider.FederationPolicyMutationReceipt{}, err
	}
	return decodeFederationPolicyReceipt(document)
}

func (r *IdentityProviderRepository) GetFederatedAssurancePolicy(
	ctx context.Context,
	params identityprovider.FederationGetParams,
) (identityprovider.FederationAssurancePolicy, error) {
	if !validFederationHuman(params.FederationHumanParams) || !identityProviderUUIDv7(params.ProviderID) {
		return identityprovider.FederationAssurancePolicy{}, identityprovider.ErrInvalidInput
	}
	document, err := r.callFederationAdministrationFunction(ctx, params.FederationHumanParams,
		"app.get_tenant_federated_assurance_policy_v1", struct {
			ProviderID uuid.UUID `json:"providerId"`
		}{params.ProviderID})
	if err != nil {
		return identityprovider.FederationAssurancePolicy{}, err
	}
	var wire federationAssurancePolicyWire
	if err := decodeFederationAdministrationDocument(document, &wire); err != nil {
		return identityprovider.FederationAssurancePolicy{}, err
	}
	rules := make([]identityprovider.FederationAssuranceRule, 0, len(wire.Rules))
	for _, rule := range wire.Rules {
		rules = append(rules, identityprovider.FederationAssuranceRule{
			RuleID: rule.RuleID, Enabled: rule.Enabled, Level: rule.Level,
			ExactValue: rule.ExactValue, RequiredValues: slices.Clone(rule.RequiredValues),
			MaximumAuthenticationAgeSeconds: rule.MaximumAuthenticationAgeSeconds,
		})
	}
	return identityprovider.FederationAssurancePolicy{
		TenantID: wire.TenantID, ProviderID: wire.ProviderID, Kind: identityprovider.FederationProviderKind(wire.Kind),
		ProviderVersion:         wire.ProviderVersion,
		AssurancePolicyRevision: wire.AssurancePolicyRevision, Rules: rules,
	}, nil
}

func (r *IdentityProviderRepository) ReplaceFederatedAssurancePolicy(
	ctx context.Context,
	params identityprovider.FederationReplaceAssurancePolicyParams,
) (identityprovider.FederationPolicyMutationReceipt, error) {
	type ruleWire struct {
		RuleID                          uuid.UUID `json:"ruleId"`
		Enabled                         bool      `json:"enabled"`
		Level                           string    `json:"level"`
		ExactValue                      *string   `json:"exactValue,omitempty"`
		RequiredValues                  []string  `json:"requiredValues"`
		MaximumAuthenticationAgeSeconds int       `json:"maximumAuthenticationAgeSeconds"`
	}
	rules := make([]ruleWire, 0, len(params.Input.Rules))
	for _, rule := range params.Input.Rules {
		rules = append(rules, ruleWire{rule.RuleID, rule.Enabled, rule.Level, rule.ExactValue,
			slices.Clone(rule.RequiredValues), rule.MaximumAuthenticationAgeSeconds})
	}
	document, err := r.callFederationAdministrationFunction(ctx, params.FederationHumanParams,
		"app.replace_tenant_federated_assurance_policy_v1", struct {
			MembershipID    uuid.UUID           `json:"membershipId"`
			ProviderID      uuid.UUID           `json:"providerId"`
			ExpectedVersion int64               `json:"expectedVersion"`
			Kind            string              `json:"kind"`
			Rules           []ruleWire          `json:"rules"`
			Reason          string              `json:"reason"`
			OccurredAt      time.Time           `json:"occurredAt"`
			Audit           federationAuditWire `json:"audit"`
		}{params.MembershipID, params.ProviderID, params.ExpectedVersion, string(params.Input.Kind), rules,
			params.Input.Reason, params.OccurredAt, federationAudit(params.Audit, params.Actor.AuthenticationMethod)})
	if err != nil {
		return identityprovider.FederationPolicyMutationReceipt{}, err
	}
	return decodeFederationPolicyReceipt(document)
}

func (r *IdentityProviderRepository) PrepareOIDCTrustDocuments(
	ctx context.Context,
	params identityprovider.FederationPrepareOIDCTrustParams,
) (identityprovider.FederationOIDCTrustPreparation, error) {
	document, err := r.callFederationAdministrationFunction(ctx, params.FederationHumanParams,
		"app.prepare_tenant_oidc_trust_documents_v1", struct {
			MembershipID    uuid.UUID `json:"membershipId"`
			ProviderID      uuid.UUID `json:"providerId"`
			ExpectedVersion int64     `json:"expectedVersion"`
		}{params.MembershipID, params.ProviderID, params.ExpectedVersion})
	if err != nil {
		return identityprovider.FederationOIDCTrustPreparation{}, err
	}
	var wire federationOIDCTrustPreparationWire
	if err := decodeFederationAdministrationDocument(document, &wire); err != nil {
		return identityprovider.FederationOIDCTrustPreparation{}, err
	}
	return identityprovider.FederationOIDCTrustPreparation{
		TenantID: wire.TenantID, ProviderID: wire.ProviderID, Issuer: wire.Issuer,
		NextDiscoveryRevision: wire.NextDiscoveryRevision, NextJWKSRevision: wire.NextJWKSRevision,
	}, nil
}

func (r *IdentityProviderRepository) CommitOIDCTrustDocuments(
	ctx context.Context,
	params identityprovider.FederationCommitOIDCTrustParams,
) (identityprovider.FederationOIDCTrustDocumentsReceipt, error) {
	discoveryDocument := slices.Clone(params.Documents.Discovery.Document)
	jwksDocument := slices.Clone(params.Documents.JWKS.Document)
	defer clear(discoveryDocument)
	defer clear(jwksDocument)
	algorithms := params.Documents.Discovery.Request.Policy.SigningAlgorithms
	if snapshotAlgorithms := params.Documents.JWKS.Discovery.SigningAlgorithms(); len(snapshotAlgorithms) > 0 {
		algorithms = snapshotAlgorithms
	}
	algorithmStrings := make([]string, len(algorithms))
	for index, algorithm := range algorithms {
		algorithmStrings[index] = string(algorithm)
	}
	type cacheWire struct {
		RetrievedAt    time.Time `json:"retrievedAt"`
		FreshUntil     time.Time `json:"freshUntil"`
		Cacheable      bool      `json:"cacheable"`
		MustRevalidate bool      `json:"mustRevalidate"`
	}
	document, err := r.callFederationAdministrationFunction(ctx, params.FederationHumanParams,
		"app.commit_tenant_oidc_trust_documents_v1", struct {
			MembershipID      uuid.UUID           `json:"membershipId"`
			ProviderID        uuid.UUID           `json:"providerId"`
			ExpectedVersion   int64               `json:"expectedVersion"`
			Issuer            string              `json:"issuer"`
			DiscoveryRevision int64               `json:"discoveryRevision"`
			JWKSRevision      int64               `json:"jwksRevision"`
			DiscoveryDocument []byte              `json:"discoveryDocument"`
			DiscoveryDigest   []byte              `json:"discoveryDigest"`
			DiscoveryCache    cacheWire           `json:"discoveryCache"`
			JWKSDocument      []byte              `json:"jwksDocument"`
			JWKSDigest        []byte              `json:"jwksDigest"`
			JWKSCache         cacheWire           `json:"jwksCache"`
			ClientAuth        string              `json:"clientAuthentication"`
			SigningAlgorithms []string            `json:"signingAlgorithms"`
			KeyCount          int                 `json:"keyCount"`
			Reason            string              `json:"reason"`
			OccurredAt        time.Time           `json:"occurredAt"`
			Audit             federationAuditWire `json:"audit"`
		}{
			params.MembershipID, params.ProviderID, params.ExpectedVersion, params.Preparation.Issuer,
			params.Preparation.NextDiscoveryRevision, params.Preparation.NextJWKSRevision,
			discoveryDocument, params.Documents.Discovery.Digest[:],
			cacheWire{params.Documents.Discovery.Cache.RetrievedAt, params.Documents.Discovery.Cache.FreshUntil,
				params.Documents.Discovery.Cache.Cacheable, params.Documents.Discovery.Cache.MustRevalidate},
			jwksDocument, params.Documents.JWKS.Digest[:],
			cacheWire{params.Documents.JWKS.Cache.RetrievedAt, params.Documents.JWKS.Cache.FreshUntil,
				params.Documents.JWKS.Cache.Cacheable, params.Documents.JWKS.Cache.MustRevalidate},
			string(params.Documents.Discovery.Request.Policy.ClientAuthentication), algorithmStrings,
			params.Documents.KeyCount, params.Reason, params.OccurredAt,
			federationAudit(params.Audit, params.Actor.AuthenticationMethod),
		})
	if err != nil {
		return identityprovider.FederationOIDCTrustDocumentsReceipt{}, err
	}
	var wire federationOIDCTrustReceiptWire
	if err := decodeFederationAdministrationDocument(document, &wire); err != nil {
		return identityprovider.FederationOIDCTrustDocumentsReceipt{}, err
	}
	return identityprovider.FederationOIDCTrustDocumentsReceipt{
		ProviderID: wire.ProviderID, ProviderVersion: wire.ProviderVersion,
		DiscoveryRevision: wire.DiscoveryRevision, JWKSRevision: wire.JWKSRevision, KeyCount: wire.KeyCount,
	}, nil
}

func (r *IdentityProviderRepository) callFederationAdministrationFunction(
	ctx context.Context,
	human identityprovider.FederationHumanParams,
	function string,
	request any,
) ([]byte, error) {
	if r == nil || r.begin == nil || r.queryFactory == nil || !slices.Contains(federationAdministrationFunctions, function) ||
		!validFederationHuman(human) {
		return nil, fmt.Errorf("%w: tenant federation repository dependencies are invalid", identityprovider.ErrUnavailable)
	}
	encoded, err := json.Marshal(request)
	if err != nil || len(encoded) < 2 || len(encoded) > maximumFederationAdministrationDocumentBytes {
		return nil, identityprovider.ErrInvalidInput
	}
	document, err := withinTransaction(ctx, r.begin, func(tx databaseTransaction) ([]byte, error) {
		queries := r.queryFactory(tx)
		if queries == nil {
			return nil, invalidIdentityProviderProjection("tenant federation context surface is unavailable")
		}
		installed, installErr := queries.SetTenantContext(ctx, dbsql.SetTenantContextParams{
			TenantID: toDatabaseUUID(human.TenantID), UserID: toDatabaseUUID(human.Actor.UserID),
		})
		if installErr != nil {
			return nil, installErr
		}
		if installed == nil || installed.TenantID != human.TenantID.String() || installed.UserID != human.Actor.UserID.String() {
			return nil, invalidIdentityProviderProjection("database installed an unexpected federation human context")
		}
		var result []byte
		if queryErr := tx.QueryRow(ctx, "SELECT "+function+"($1::jsonb)", encoded).Scan(&result); queryErr != nil {
			return nil, queryErr
		}
		if len(result) < 2 || len(result) > maximumFederationAdministrationDocumentBytes {
			return nil, invalidIdentityProviderProjection("database returned an invalid federation document size")
		}
		return result, nil
	})
	if err != nil {
		return nil, mapIdentityProviderDatabaseError(err)
	}
	return document, nil
}

func decodeFederationAdministrationDocument(document []byte, destination any) error {
	decoder := json.NewDecoder(strings.NewReader(string(document)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return invalidIdentityProviderProjection("malformed tenant federation database projection")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return invalidIdentityProviderProjection("tenant federation database projection has trailing data")
	}
	return nil
}

func federationProviderFromWire(wire federationProviderWire) identityprovider.FederationProvider {
	provider := identityprovider.FederationProvider{
		FederationProviderSummary: identityprovider.FederationProviderSummary{
			ID: wire.ID, TenantID: wire.TenantID, Key: wire.Key, DisplayName: wire.DisplayName,
			Description: wire.Description, Kind: identityprovider.FederationProviderKind(wire.Kind),
			Enabled: wire.Enabled, Configured: wire.Configured,
			Binding: identityprovider.FederationBinding{ID: wire.Binding.ID, LoginKey: wire.Binding.LoginKey,
				Enabled: wire.Binding.Enabled, Version: wire.Binding.Version, UpdatedAt: wire.Binding.UpdatedAt},
			ArchivedAt: wire.ArchivedAt, Version: wire.Version, CreatedAt: wire.CreatedAt, UpdatedAt: wire.UpdatedAt,
		},
		ConfigurationRevision: wire.ConfigurationRevision, SecurityRevision: wire.SecurityRevision,
		PlanRevision: wire.PlanRevision, AssurancePolicyRevision: wire.AssurancePolicyRevision,
		JITMode: identityprovider.JITMode(wire.JITMode), NoMatchPolicy: identityprovider.NoMatchPolicy(wire.NoMatchPolicy),
	}
	if wire.OIDC != nil {
		provider.OIDC = &identityprovider.FederationOIDCConfiguration{
			Issuer: wire.OIDC.Issuer, ClientID: wire.OIDC.ClientID, RedirectURI: wire.OIDC.RedirectURI,
			PostLogoutRedirectURI: wire.OIDC.PostLogoutRedirectURI,
			ExtraScopes:           slices.Clone(wire.OIDC.ExtraScopes), AllowRefreshToken: wire.OIDC.AllowRefreshToken,
			UseUserInfo: wire.OIDC.UseUserInfo, ClientSecretPresent: wire.OIDC.ClientSecretPresent,
			ClientSecretRevision: wire.OIDC.ClientSecretRevision, DiscoveryRevision: wire.OIDC.DiscoveryRevision,
			JWKSRevision: wire.OIDC.JWKSRevision,
		}
	}
	if wire.SAML != nil {
		provider.SAML = &identityprovider.FederationSAMLConfiguration{
			ExpectedEntityID: wire.SAML.ExpectedEntityID, SPEntityID: wire.SAML.SPEntityID, ACSURL: wire.SAML.ACSURL,
			SPKeyPresent: wire.SAML.SPKeyPresent, SPKeyRevision: wire.SAML.SPKeyRevision,
			MetadataRevision:           wire.SAML.MetadataRevision,
			RedirectSignatureAlgorithm: federatedsaml.RedirectSignatureAlgorithm(wire.SAML.RedirectSignatureAlgorithm),
			SignaturePolicy:            federatedsaml.SignaturePolicy(wire.SAML.SignaturePolicy),
			EncryptionPolicy:           federatedsaml.EncryptionPolicy(wire.SAML.EncryptionPolicy),
			RequestedAuthnContexts:     slices.Clone(wire.SAML.RequestedAuthnContexts),
			SubjectSource:              federatedsaml.SubjectSource(wire.SAML.SubjectSource),
			SubjectAttributeName:       wire.SAML.SubjectAttributeName,
			SubjectAttributeNameFormat: wire.SAML.SubjectAttributeNameFormat,
			ClockSkew:                  time.Duration(wire.SAML.ClockSkewSeconds) * time.Second,
			MaximumAuthenticationAge:   time.Duration(wire.SAML.MaximumAuthenticationAgeSeconds) * time.Second,
			SingleLogoutConfigured:     wire.SAML.SingleLogoutConfigured,
		}
	}
	return provider
}

func federationOIDCInput(input *identityprovider.FederationOIDCCreateConfiguration) *federationOIDCInputWire {
	if input == nil {
		return nil
	}
	return &federationOIDCInputWire{input.Issuer, input.ClientID, input.PostLogoutRedirectURI,
		slices.Clone(input.ExtraScopes), input.AllowRefreshToken, input.UseUserInfo}
}

func federationSAMLInput(input *identityprovider.FederationSAMLCreateConfiguration) *federationSAMLInputWire {
	if input == nil {
		return nil
	}
	return &federationSAMLInputWire{input.ExpectedEntityID, string(input.RedirectSignatureAlgorithm),
		string(input.SignaturePolicy), string(input.EncryptionPolicy), slices.Clone(input.RequestedAuthnContexts),
		string(input.SubjectSource), input.SubjectAttributeName, input.SubjectAttributeNameFormat,
		int64(input.ClockSkew / time.Second), int64(input.MaximumAuthenticationAge / time.Second)}
}

func federationAudit(audit authorization.AuditContext, authenticationMethod string) federationAuditWire {
	var remote *string
	if audit.RemoteAddress.IsValid() {
		value := audit.RemoteAddress.Unmap().String()
		remote = &value
	}
	return federationAuditWire{audit.RequestID, audit.CorrelationID, remote, audit.UserAgent, authenticationMethod}
}

func validFederationHuman(human identityprovider.FederationHumanParams) bool {
	return identityProviderUUIDv7(human.TenantID) && identityProviderUUIDv7(human.MembershipID) &&
		identityProviderUUIDv7(human.Actor.UserID) && identityProviderUUIDv7(human.Actor.SessionID) &&
		human.Actor.ActiveTenantID == human.TenantID && identityProviderText(human.Actor.AuthenticationMethod, 1, 64)
}

func decodeFederationSecretReceipt(document []byte) (identityprovider.FederationSecretMutationReceipt, error) {
	var wire federationSecretReceiptWire
	if err := decodeFederationAdministrationDocument(document, &wire); err != nil {
		return identityprovider.FederationSecretMutationReceipt{}, err
	}
	return identityprovider.FederationSecretMutationReceipt{
		ProviderID: wire.ProviderID, ProviderVersion: wire.ProviderVersion, SecretRevision: wire.SecretRevision,
	}, nil
}

func decodeFederationPolicyReceipt(document []byte) (identityprovider.FederationPolicyMutationReceipt, error) {
	var wire federationPolicyReceiptWire
	if err := decodeFederationAdministrationDocument(document, &wire); err != nil {
		return identityprovider.FederationPolicyMutationReceipt{}, err
	}
	return identityprovider.FederationPolicyMutationReceipt{
		ProviderID: wire.ProviderID, ProviderVersion: wire.ProviderVersion,
		MappingRevision: wire.MappingRevision, AssurancePolicyRevision: wire.AssurancePolicyRevision,
	}, nil
}
