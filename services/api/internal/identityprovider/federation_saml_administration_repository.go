package identityprovider

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

// FederationSAMLAdministrationRepository is the narrow protected writer ABI
// for tenant SAML trust and credential material. Implementations must install
// the exact tenant/user context, revalidate the live human manage permission,
// lock the provider, binding, configuration, and material coordinates, and
// commit every revision bump, session revocation, and redacted audit event in
// one transaction. Raw metadata may be returned only by the preparation call
// to this application service and must never cross the HTTP projection.
type FederationSAMLAdministrationRepository interface {
	PrepareSAMLMetadataReplacement(context.Context, FederationPrepareSAMLMetadataParams) (FederationSAMLMetadataPreparation, error)
	ReplaceSAMLMetadata(context.Context, FederationReplaceSAMLMetadataParams) (FederationSAMLMaterialMutationReceipt, error)
	PrepareSAMLSPCredentialMutation(context.Context, FederationPrepareSAMLSPCredentialParams) (FederationSAMLSPCredentialPreparation, error)
	ReplaceSAMLSPCredential(context.Context, FederationReplaceSAMLSPCredentialParams) (FederationSAMLMaterialMutationReceipt, error)
	ClearSAMLSPCredential(context.Context, FederationClearSAMLSPCredentialParams) (FederationSAMLMaterialMutationReceipt, error)
}

type FederationPrepareSAMLMetadataParams struct {
	FederationHumanParams
	ProviderID      uuid.UUID
	ExpectedVersion int64
}

type FederationReplaceSAMLMetadataParams struct {
	FederationHumanParams
	Audit             authorization.AuditContext
	OccurredAt        time.Time
	ProviderID        uuid.UUID
	BindingID         uuid.UUID
	ExpectedVersion   int64
	ExpectedRevision  int64
	Document          []byte `json:"-"`
	Digest            [sha256.Size]byte
	RetrievedAt       time.Time
	MaximumValidUntil time.Time
	ProtectedApproval bool
	Reason            string
}

func (params FederationReplaceSAMLMetadataParams) String() string {
	return "identityprovider.FederationReplaceSAMLMetadataParams{material:[REDACTED]}"
}

func (params FederationReplaceSAMLMetadataParams) GoString() string { return params.String() }

type FederationPrepareSAMLSPCredentialParams struct {
	FederationHumanParams
	ProviderID      uuid.UUID
	ExpectedVersion int64
}

type FederationReplaceSAMLSPCredentialParams struct {
	FederationHumanParams
	Audit            authorization.AuditContext
	OccurredAt       time.Time
	ProviderID       uuid.UUID
	BindingID        uuid.UUID
	ExpectedVersion  int64
	ExpectedRevision int64
	Credential       FederationEncryptedSAMLSPCredential
	Reason           string
}

func (params FederationReplaceSAMLSPCredentialParams) String() string {
	return "identityprovider.FederationReplaceSAMLSPCredentialParams{material:[REDACTED]}"
}

func (params FederationReplaceSAMLSPCredentialParams) GoString() string { return params.String() }

type FederationClearSAMLSPCredentialParams struct {
	FederationHumanParams
	Audit            authorization.AuditContext
	OccurredAt       time.Time
	ProviderID       uuid.UUID
	BindingID        uuid.UUID
	ExpectedVersion  int64
	ExpectedRevision int64
	Reason           string
}
