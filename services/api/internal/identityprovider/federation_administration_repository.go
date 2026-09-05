package identityprovider

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

// FederationAuthorityRepository resolves live tenant authority before the
// application invokes the narrower protected federation writer functions.
type FederationAuthorityRepository interface {
	ResolveHumanAuthority(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error)
}

// FederationAdministrationRepository is the frozen application/DB ABI for
// tenant-owned OIDC/SAML administration. Implementations must reinstall the
// exact tenant, user, and membership context and recheck the named permission
// under forced RLS. No method may return raw trust or credential material.
// Create atomically installs the subtype and login binding disabled with its
// idempotency record and redacted audit event. Update may enable only a fully
// ready provider/binding. Update, archive, and secret retirement must advance
// the required security/configuration revisions and revoke every dependent
// local session in the same transaction; archive also requires disabled state.
// Secret replacement persists only the supplied envelope and exact AAD-bound
// identifiers, retiring the predecessor atomically without plaintext readback.
type FederationAdministrationRepository interface {
	ListFederatedProviders(context.Context, FederationListParams) ([]FederationProviderSummary, error)
	GetFederatedProvider(context.Context, FederationGetParams) (FederationProvider, error)
	CreateFederatedProvider(context.Context, FederationCreateParams) (FederationCreateResult, error)
	UpdateFederatedProvider(context.Context, FederationUpdateParams) (FederationProvider, error)
	ArchiveFederatedProvider(context.Context, FederationArchiveParams) (int64, error)
	PrepareOIDCClientSecretReplacement(context.Context, FederationPrepareOIDCSecretParams) (FederationSecretPreparation, error)
	ReplaceOIDCClientSecret(context.Context, FederationReplaceOIDCSecretParams) (FederationSecretMutationReceipt, error)
	ClearOIDCClientSecret(context.Context, FederationClearOIDCSecretParams) (FederationSecretMutationReceipt, error)
	GetFederatedMappingPolicy(context.Context, FederationGetParams) (FederationMappingPolicy, error)
	ReplaceFederatedMappingPolicy(context.Context, FederationReplaceMappingPolicyParams) (FederationPolicyMutationReceipt, error)
	GetFederatedAssurancePolicy(context.Context, FederationGetParams) (FederationAssurancePolicy, error)
	ReplaceFederatedAssurancePolicy(context.Context, FederationReplaceAssurancePolicyParams) (FederationPolicyMutationReceipt, error)
	PrepareOIDCTrustDocuments(context.Context, FederationPrepareOIDCTrustParams) (FederationOIDCTrustPreparation, error)
	CommitOIDCTrustDocuments(context.Context, FederationCommitOIDCTrustParams) (FederationOIDCTrustDocumentsReceipt, error)
}

type FederationHumanParams struct {
	Actor        authorization.Actor
	MembershipID uuid.UUID
	TenantID     uuid.UUID
}

type FederationListParams struct {
	FederationHumanParams
	After           *uuid.UUID
	Limit           int32
	IncludeArchived bool
}

type FederationGetParams struct {
	FederationHumanParams
	ProviderID uuid.UUID
}

type FederationCreateParams struct {
	FederationHumanParams
	Audit                 authorization.AuditContext
	OccurredAt            time.Time
	CommandID             uuid.UUID
	ProviderID            uuid.UUID
	BindingID             uuid.UUID
	IdempotencyKeyDigest  [sha256.Size]byte
	RequestDigest         [sha256.Size]byte
	Input                 FederationCreateInput
	OIDCRedirectURI       string
	SAMLACSURL            string
	SAMLSPMetadataBaseURL string
}

type FederationUpdateParams struct {
	FederationHumanParams
	Audit                 authorization.AuditContext
	OccurredAt            time.Time
	ProviderID            uuid.UUID
	ExpectedVersion       int64
	Input                 FederationUpdateInput
	OIDCRedirectURI       string
	SAMLACSURL            string
	SAMLSPMetadataBaseURL string
}

type FederationArchiveParams struct {
	FederationHumanParams
	Audit           authorization.AuditContext
	OccurredAt      time.Time
	ProviderID      uuid.UUID
	ExpectedVersion int64
	Reason          string
}

type FederationPrepareOIDCSecretParams struct {
	FederationHumanParams
	ProviderID      uuid.UUID
	ExpectedVersion int64
}

type FederationReplaceOIDCSecretParams struct {
	FederationHumanParams
	Audit            authorization.AuditContext
	OccurredAt       time.Time
	ProviderID       uuid.UUID
	BindingID        uuid.UUID
	ExpectedVersion  int64
	ExpectedRevision int64
	Secret           FederationEncryptedOIDCSecret
	Reason           string
}

type FederationClearOIDCSecretParams struct {
	FederationHumanParams
	Audit            authorization.AuditContext
	OccurredAt       time.Time
	ProviderID       uuid.UUID
	ExpectedVersion  int64
	ExpectedRevision int64
	Reason           string
}

type FederationReplaceMappingPolicyParams struct {
	FederationHumanParams
	Audit           authorization.AuditContext
	OccurredAt      time.Time
	ProviderID      uuid.UUID
	ExpectedVersion int64
	Input           FederationReplaceMappingPolicyInput
}

type FederationReplaceAssurancePolicyParams struct {
	FederationHumanParams
	Audit           authorization.AuditContext
	OccurredAt      time.Time
	ProviderID      uuid.UUID
	ExpectedVersion int64
	Input           FederationReplaceAssurancePolicyInput
}

type FederationPrepareOIDCTrustParams struct {
	FederationHumanParams
	ProviderID      uuid.UUID
	ExpectedVersion int64
}

type FederationCommitOIDCTrustParams struct {
	FederationHumanParams
	Audit           authorization.AuditContext
	OccurredAt      time.Time
	ProviderID      uuid.UUID
	ExpectedVersion int64
	Preparation     FederationOIDCTrustPreparation
	Documents       federatedoidc.TrustDocumentRecords
	Reason          string
}

type FederationOIDCTrustDocumentFetcher interface {
	FetchTrustDocuments(context.Context, federatedoidc.DiscoveryRequest, uint64) (federatedoidc.TrustDocumentRecords, error)
	ValidateTrustDocumentRecords(federatedoidc.TrustDocumentRecords, federatedoidc.DiscoveryRequest, uint64) (int, error)
}
