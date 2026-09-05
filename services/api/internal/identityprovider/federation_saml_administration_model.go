package identityprovider

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

const (
	maximumFederationSAMLMetadataBytes       = 512 * 1024
	maximumFederationSAMLSPKeyPlaintextBytes = 128*1024 - 12 - 16
	maximumFederationSAMLCertificateBytes    = 64 * 1024
	maximumFederationSAMLCertificates        = 8
	maximumFederationSAMLKeyRevision         = int64(2_147_483_647)
)

// ErrFederationSAMLTrustApprovalRequired is returned only when the next
// metadata document has no trusted certificate continuity with the current
// immutable snapshot. The caller must deliberately repeat against the same
// provider version with ApproveTrustReset set.
var ErrFederationSAMLTrustApprovalRequired = fmt.Errorf("tenant SAML trust replacement requires protected approval")

type FederationSAMLMetadataRetriever interface {
	// RetrieveTenantSAMLMetadata returns a fresh caller-owned document fetched
	// through the deployment SSRF-resistant client.
	RetrieveTenantSAMLMetadata(context.Context, string, int) ([]byte, time.Time, error)
}

type FederationSAMLSPCredentialValidator func([]byte, [][]byte, time.Time) error

type FederationSAMLSPCredentialGenerator func(
	FederationSAMLSPCredentialGenerationRequest,
) (FederationSAMLSPCredentialBundle, error)

type FederationSAMLAdministrationOptions struct {
	MetadataRetriever FederationSAMLMetadataRetriever
	GenerateSPKey     FederationSAMLSPCredentialGenerator
	ValidateSPKey     FederationSAMLSPCredentialValidator
}

type FederationReplaceSAMLMetadataInput struct {
	MetadataURL       *string
	MetadataXML       []byte `json:"-"`
	ApproveTrustReset bool
	Reason            string
	ExpectedEntityTag *string
	Audit             authorization.AuditContext
}

func (input FederationReplaceSAMLMetadataInput) String() string {
	return fmt.Sprintf(
		"identityprovider.FederationReplaceSAMLMetadataInput{url:%t,xml_bytes:%d,approval:%t,material:[REDACTED]}",
		input.MetadataURL != nil, len(input.MetadataXML), input.ApproveTrustReset,
	)
}

func (input FederationReplaceSAMLMetadataInput) GoString() string { return input.String() }

type FederationReplaceSAMLSPCredentialInput struct {
	Reason            string
	ExpectedEntityTag *string
	Audit             authorization.AuditContext
}

func (input FederationReplaceSAMLSPCredentialInput) String() string {
	return "identityprovider.FederationReplaceSAMLSPCredentialInput{server_generated:true,material:[REDACTED]}"
}

func (input FederationReplaceSAMLSPCredentialInput) GoString() string { return input.String() }

type FederationClearSAMLSPCredentialInput struct {
	Reason            string
	ExpectedEntityTag *string
	Audit             authorization.AuditContext
}

// FederationSAMLMetadataSnapshot is an internal-only immutable trust
// snapshot. It must never be mapped onto an HTTP or logging projection.
type FederationSAMLMetadataSnapshot struct {
	Revision          int64
	Document          []byte `json:"-"`
	Digest            [sha256.Size]byte
	RetrievedAt       time.Time
	MaximumValidUntil time.Time
}

func (snapshot *FederationSAMLMetadataSnapshot) Destroy() {
	if snapshot == nil {
		return
	}
	clear(snapshot.Document)
	clear(snapshot.Digest[:])
	*snapshot = FederationSAMLMetadataSnapshot{}
}

func (snapshot FederationSAMLMetadataSnapshot) String() string {
	return fmt.Sprintf(
		"identityprovider.FederationSAMLMetadataSnapshot{revision:%d,material:[REDACTED]}",
		snapshot.Revision,
	)
}

func (snapshot FederationSAMLMetadataSnapshot) GoString() string { return snapshot.String() }

type FederationSAMLMetadataPreparation struct {
	TenantID                uuid.UUID
	ProviderID              uuid.UUID
	BindingID               uuid.UUID
	ProviderVersion         int64
	ExpectedEntityID        string
	CurrentMetadataRevision int64
	Current                 *FederationSAMLMetadataSnapshot
}

func (preparation *FederationSAMLMetadataPreparation) Destroy() {
	if preparation == nil {
		return
	}
	preparation.Current.Destroy()
	*preparation = FederationSAMLMetadataPreparation{}
}

func (preparation FederationSAMLMetadataPreparation) String() string {
	return fmt.Sprintf(
		"identityprovider.FederationSAMLMetadataPreparation{provider_version:%d,metadata_revision:%d,current:%t,material:[REDACTED]}",
		preparation.ProviderVersion, preparation.CurrentMetadataRevision, preparation.Current != nil,
	)
}

func (preparation FederationSAMLMetadataPreparation) GoString() string { return preparation.String() }

type FederationSAMLSPCredentialPreparation struct {
	TenantID                   uuid.UUID
	ProviderID                 uuid.UUID
	BindingID                  uuid.UUID
	ProviderVersion            int64
	CurrentCredentialRevision  int64
	CredentialPresent          bool
	ProviderEnabled            bool
	BindingEnabled             bool
	SPEntityID                 string
	RedirectSignatureAlgorithm federatedsaml.RedirectSignatureAlgorithm
}

// FederationSAMLSPCredentialGenerationRequest is the complete non-secret
// input to the CSPRNG-backed SP credential generator. The generator binds the
// certificate URI SAN to the stored provider-specific SP entity ID.
type FederationSAMLSPCredentialGenerationRequest struct {
	RedirectSignatureAlgorithm federatedsaml.RedirectSignatureAlgorithm
	SPEntityID                 string
	GeneratedAt                time.Time
}

// FederationSAMLSPCredentialBundle is caller-owned ephemeral plaintext. It
// must be destroyed after validation and keyring encryption on every path.
type FederationSAMLSPCredentialBundle struct {
	PrivateKeyPKCS8 []byte   `json:"-"`
	CertificateDER  [][]byte `json:"-"`
}

func (bundle *FederationSAMLSPCredentialBundle) Destroy() {
	if bundle == nil {
		return
	}
	clear(bundle.PrivateKeyPKCS8)
	clearFederationSAMLByteSlices(bundle.CertificateDER)
	*bundle = FederationSAMLSPCredentialBundle{}
}

func (bundle FederationSAMLSPCredentialBundle) String() string {
	return fmt.Sprintf(
		"identityprovider.FederationSAMLSPCredentialBundle{key_bytes:%d,certificates:%d,material:[REDACTED]}",
		len(bundle.PrivateKeyPKCS8), len(bundle.CertificateDER),
	)
}

func (bundle FederationSAMLSPCredentialBundle) GoString() string { return bundle.String() }

type FederationEncryptedSAMLSPCredential struct {
	KeyID               uuid.UUID
	KeyRevision         int64
	Envelope            identity.SAMLSPKeyEnvelope `json:"-"`
	CertificateDER      [][]byte                   `json:"-"`
	CertificateValidity []FederationSAMLCertificateValidity
}

type FederationSAMLCertificateValidity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

func (credential FederationEncryptedSAMLSPCredential) String() string {
	return fmt.Sprintf(
		"identityprovider.FederationEncryptedSAMLSPCredential{key_revision:%d,key_version:%d,certificates:%d,material:[REDACTED]}",
		credential.KeyRevision, credential.Envelope.KeyVersion, len(credential.CertificateDER),
	)
}

func (credential FederationEncryptedSAMLSPCredential) GoString() string { return credential.String() }

type FederationSAMLMaterialMutationReceipt struct {
	ProviderID       uuid.UUID
	ProviderVersion  int64
	MaterialRevision int64
}
