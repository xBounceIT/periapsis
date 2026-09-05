package identityprovider

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

// FederationProviderKind is deliberately narrower than the shared provider
// enum: LDAP remains owned by the established directory administration slice.
type FederationProviderKind string

const (
	FederationProviderOIDC FederationProviderKind = "oidc"
	FederationProviderSAML FederationProviderKind = "saml"
)

type FederationBinding struct {
	ID        uuid.UUID
	LoginKey  string
	Enabled   bool
	Version   int64
	UpdatedAt time.Time
}

// FederationOIDCConfiguration is the safe OIDC projection. Client-secret,
// discovery, JWKS, token, subject, and claim material are structurally absent.
type FederationOIDCConfiguration struct {
	Issuer                string
	ClientID              string
	RedirectURI           string
	PostLogoutRedirectURI string
	ExtraScopes           []string
	AllowRefreshToken     bool
	UseUserInfo           bool
	ClientSecretPresent   bool
	ClientSecretRevision  int64
	DiscoveryRevision     int64
	JWKSRevision          int64
}

// FederationSAMLConfiguration is a safe SAML projection. Raw metadata,
// certificates, private keys, assertions, subjects, and attributes are absent.
type FederationSAMLConfiguration struct {
	ExpectedEntityID           string
	SPEntityID                 string
	ACSURL                     string
	SPKeyPresent               bool
	SPKeyRevision              int64
	MetadataRevision           int64
	RedirectSignatureAlgorithm federatedsaml.RedirectSignatureAlgorithm
	SignaturePolicy            federatedsaml.SignaturePolicy
	EncryptionPolicy           federatedsaml.EncryptionPolicy
	RequestedAuthnContexts     []string
	SubjectSource              federatedsaml.SubjectSource
	SubjectAttributeName       *string
	SubjectAttributeNameFormat *string
	ClockSkew                  time.Duration
	MaximumAuthenticationAge   time.Duration
	SingleLogoutConfigured     bool
}

type FederationProviderSummary struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	Key         string
	DisplayName string
	Description string
	Kind        FederationProviderKind
	Enabled     bool
	Configured  bool
	Binding     FederationBinding
	ArchivedAt  *time.Time
	Version     int64
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type FederationProvider struct {
	FederationProviderSummary
	ConfigurationRevision   int64
	SecurityRevision        int64
	PlanRevision            int64
	AssurancePolicyRevision int64
	JITMode                 JITMode
	NoMatchPolicy           NoMatchPolicy
	OIDC                    *FederationOIDCConfiguration
	SAML                    *FederationSAMLConfiguration
}

type FederationProviderPage struct {
	Items      []FederationProviderSummary
	NextCursor *uuid.UUID
}

type FederationListInput struct {
	After           *uuid.UUID
	Limit           int
	IncludeArchived bool
}

type FederationOIDCCreateConfiguration struct {
	Issuer                string
	ClientID              string
	PostLogoutRedirectURI string
	ExtraScopes           []string
	AllowRefreshToken     bool
	UseUserInfo           bool
}

type FederationSAMLCreateConfiguration struct {
	ExpectedEntityID           string
	RedirectSignatureAlgorithm federatedsaml.RedirectSignatureAlgorithm
	SignaturePolicy            federatedsaml.SignaturePolicy
	EncryptionPolicy           federatedsaml.EncryptionPolicy
	RequestedAuthnContexts     []string
	SubjectSource              federatedsaml.SubjectSource
	SubjectAttributeName       *string
	SubjectAttributeNameFormat *string
	ClockSkew                  time.Duration
	MaximumAuthenticationAge   time.Duration
}

type FederationCreateInput struct {
	Kind           FederationProviderKind
	Key            string
	LoginKey       string
	DisplayName    string
	Description    string
	JITMode        JITMode
	NoMatchPolicy  NoMatchPolicy
	OIDC           *FederationOIDCCreateConfiguration
	SAML           *FederationSAMLCreateConfiguration
	Reason         string
	IdempotencyKey string
	Audit          authorization.AuditContext
}

type FederationUpdateInput struct {
	DisplayName       string
	Description       string
	Enabled           bool
	JITMode           JITMode
	NoMatchPolicy     NoMatchPolicy
	OIDC              *FederationOIDCCreateConfiguration
	SAML              *FederationSAMLCreateConfiguration
	Reason            string
	ExpectedEntityTag *string
	Audit             authorization.AuditContext
}

type FederationArchiveInput struct {
	Reason            string
	ExpectedEntityTag *string
	Audit             authorization.AuditContext
}

type FederationReplaceOIDCSecretInput struct {
	Secret            []byte `json:"-"`
	Reason            string
	ExpectedEntityTag *string
	Audit             authorization.AuditContext
}

func (input FederationReplaceOIDCSecretInput) String() string {
	return fmt.Sprintf(
		"identityprovider.FederationReplaceOIDCSecretInput{secret_bytes:%d,material:[REDACTED]}",
		len(input.Secret),
	)
}

func (input FederationReplaceOIDCSecretInput) GoString() string { return input.String() }

type FederationClearOIDCSecretInput struct {
	Reason            string
	ExpectedEntityTag *string
	Audit             authorization.AuditContext
}

type FederationCreateResult struct {
	Provider FederationProvider
	Replayed bool
}

type FederationSecretPreparation struct {
	TenantID           uuid.UUID
	ProviderID         uuid.UUID
	BindingID          uuid.UUID
	CurrentSecretID    *uuid.UUID
	NextSecretRevision int64
}

type FederationEncryptedOIDCSecret struct {
	SecretID uuid.UUID
	Envelope identity.OIDCClientSecretEnvelope
}

func (secret FederationEncryptedOIDCSecret) String() string {
	return fmt.Sprintf(
		"identityprovider.FederationEncryptedOIDCSecret{key_version:%d,ciphertext_bytes:%d,material:[REDACTED]}",
		secret.Envelope.KeyVersion,
		len(secret.Envelope.Ciphertext),
	)
}

func (secret FederationEncryptedOIDCSecret) GoString() string { return secret.String() }

type FederationSecretMutationReceipt struct {
	ProviderID      uuid.UUID
	ProviderVersion int64
	SecretRevision  int64
}

type FederationOIDCClaimRule struct {
	Source       string
	Kind         string
	ClaimName    string
	ProfileField *string
	Required     bool
}

type FederationSAMLAttributeRule struct {
	Kind                string
	AttributeName       string
	AttributeNameFormat string
	ProfileField        *string
	Required            bool
}

type FederationMappingRule struct {
	RuleID                        uuid.UUID
	Priority                      int
	MatcherKind                   string
	ClaimName                     *string
	MatcherValue                  string
	ReconciliationMode            string
	TenantSecurityGroupID         uuid.UUID
	RoleIDs                       []uuid.UUID
	OperatorTeamID                *uuid.UUID
	OperatorTeamAssignmentEpochID *uuid.UUID
	Enabled                       bool
}

type FederationReplaceMappingPolicyInput struct {
	Kind               FederationProviderKind
	OIDCClaimRules     []FederationOIDCClaimRule
	SAMLAttributeRules []FederationSAMLAttributeRule
	Rules              []FederationMappingRule
	Reason             string
	ExpectedEntityTag  *string
	Audit              authorization.AuditContext
}

type FederationMappingPolicy struct {
	TenantID           uuid.UUID
	ProviderID         uuid.UUID
	Kind               FederationProviderKind
	ProviderVersion    int64
	MappingRevision    int64
	OIDCClaimRules     []FederationOIDCClaimRule
	SAMLAttributeRules []FederationSAMLAttributeRule
	Rules              []FederationMappingRule
}

type FederationAssuranceRule struct {
	RuleID                          uuid.UUID
	Enabled                         bool
	Level                           string
	ExactValue                      *string
	RequiredValues                  []string
	MaximumAuthenticationAgeSeconds int
}

type FederationReplaceAssurancePolicyInput struct {
	Kind              FederationProviderKind
	Rules             []FederationAssuranceRule
	Reason            string
	ExpectedEntityTag *string
	Audit             authorization.AuditContext
}

type FederationAssurancePolicy struct {
	TenantID                uuid.UUID
	ProviderID              uuid.UUID
	Kind                    FederationProviderKind
	ProviderVersion         int64
	AssurancePolicyRevision int64
	Rules                   []FederationAssuranceRule
}

type FederationPolicyMutationReceipt struct {
	ProviderID              uuid.UUID
	ProviderVersion         int64
	MappingRevision         int64
	AssurancePolicyRevision int64
}

type FederationOIDCTrustDocumentsInput struct {
	ClientAuthentication federatedoidc.ClientAuthenticationMode
	SigningAlgorithms    []federatedoidc.SigningAlgorithm
	Reason               string
	ExpectedEntityTag    *string
	Audit                authorization.AuditContext
}

type FederationOIDCTrustPreparation struct {
	TenantID              uuid.UUID
	ProviderID            uuid.UUID
	Issuer                string
	NextDiscoveryRevision int64
	NextJWKSRevision      int64
}

type FederationOIDCTrustDocumentsReceipt struct {
	ProviderID        uuid.UUID
	ProviderVersion   int64
	DiscoveryRevision int64
	JWKSRevision      int64
	KeyCount          int
}
