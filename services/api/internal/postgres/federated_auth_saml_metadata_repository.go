package postgres

import (
	"context"
	"math"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamladapter"
)

const (
	loadTenantSAMLSPMetadataSQL        = `select app.get_tenant_saml_sp_metadata_v1($1::jsonb)`
	maximumTenantSAMLMetadataWireBytes = 1024 * 1024
)

var _ platformsamladapter.TenantSAMLMetadataSource = (*FederatedAuthRepository)(nil)

type tenantSAMLSPMetadataLookupWire struct {
	TenantSlug string `json:"tenantSlug"`
	LoginKey   string `json:"loginKey"`
}

type tenantSAMLSPMetadataResponseWire struct {
	Found      bool                                `json:"found"`
	Projection *tenantSAMLSPMetadataProjectionWire `json:"projection,omitempty"`
}

type tenantSAMLSPMetadataProjectionWire struct {
	TenantSlug                 string                                   `json:"tenantSlug"`
	LoginKey                   string                                   `json:"loginKey"`
	TenantID                   uuid.UUID                                `json:"tenantId"`
	ProviderID                 uuid.UUID                                `json:"providerId"`
	BindingID                  uuid.UUID                                `json:"bindingId"`
	ProviderVersion            uint64                                   `json:"providerVersion"`
	BindingVersion             uint64                                   `json:"bindingVersion"`
	ConfigurationRevision      uint64                                   `json:"configurationRevision"`
	SecurityRevision           uint64                                   `json:"securityRevision"`
	PlanRevision               uint64                                   `json:"planRevision"`
	AuthorizationRevision      uint64                                   `json:"authorizationRevision"`
	SPEntityID                 string                                   `json:"spEntityId"`
	ACSURL                     string                                   `json:"acsUrl"`
	SPKeyRevision              uint64                                   `json:"spKeyRevision"`
	RedirectSignatureAlgorithm federatedsaml.RedirectSignatureAlgorithm `json:"redirectSignatureAlgorithm"`
	SignaturePolicy            federatedsaml.SignaturePolicy            `json:"signaturePolicy"`
	EncryptionPolicy           federatedsaml.EncryptionPolicy           `json:"encryptionPolicy"`
	SubjectSource              federatedsaml.SubjectSource              `json:"subjectSource"`
	TenantActive               bool                                     `json:"tenantActive"`
	ProviderEnabled            bool                                     `json:"providerEnabled"`
	BindingEnabled             bool                                     `json:"bindingEnabled"`
	PolicyEnabled              bool                                     `json:"policyEnabled"`
	ProviderArchived           bool                                     `json:"providerArchived"`
	BindingArchived            bool                                     `json:"bindingArchived"`
	AccessEpochLive            bool                                     `json:"accessEpochLive"`
	Certificates               []tenantSAMLPublicCertificateWire        `json:"certificates"`
	ObservedAt                 time.Time                                `json:"observedAt"`
}

type tenantSAMLPublicCertificateWire struct {
	TenantID            uuid.UUID `json:"tenantId"`
	ProviderID          uuid.UUID `json:"providerId"`
	BindingID           uuid.UUID `json:"bindingId"`
	KeyID               uuid.UUID `json:"keyId"`
	KeyRevision         uint64    `json:"keyRevision"`
	CertificateSequence uint8     `json:"certificateSequence"`
	CertificateDER      []byte    `json:"certificateDer"`
}

func (repository *FederatedAuthRepository) LoadTenantSAMLMetadata(
	ctx context.Context,
	tenantSlug string,
	loginKey string,
) (platformsamladapter.TenantSAMLMetadataProjection, bool, error) {
	var response tenantSAMLSPMetadataResponseWire
	if err := repository.queryJSONWithResponseLimit(
		ctx, loadTenantSAMLSPMetadataSQL,
		tenantSAMLSPMetadataLookupWire{TenantSlug: tenantSlug, LoginKey: loginKey},
		&response, maximumTenantSAMLMetadataWireBytes,
	); err != nil {
		return platformsamladapter.TenantSAMLMetadataProjection{}, false, err
	}
	if !response.Found {
		if response.Projection != nil {
			clearTenantSAMLSPMetadataProjectionWire(response.Projection)
			return platformsamladapter.TenantSAMLMetadataProjection{}, false, errFederatedAuthPersistence
		}
		return platformsamladapter.TenantSAMLMetadataProjection{}, false, nil
	}
	if response.Projection == nil {
		return platformsamladapter.TenantSAMLMetadataProjection{}, false, errFederatedAuthPersistence
	}
	defer clearTenantSAMLSPMetadataProjectionWire(response.Projection)
	projection, err := tenantSAMLSPMetadataProjectionFromWire(*response.Projection)
	if err != nil || projection.TenantSlug != tenantSlug || projection.LoginKey != loginKey {
		return platformsamladapter.TenantSAMLMetadataProjection{}, false, errFederatedAuthPersistence
	}
	return projection, true, nil
}

func tenantSAMLSPMetadataProjectionFromWire(
	wire tenantSAMLSPMetadataProjectionWire,
) (platformsamladapter.TenantSAMLMetadataProjection, error) {
	if wire.ProviderVersion == 0 || wire.BindingVersion == 0 || wire.ConfigurationRevision == 0 ||
		wire.SecurityRevision == 0 || wire.PlanRevision == 0 || wire.AuthorizationRevision == 0 ||
		wire.SPKeyRevision == 0 || wire.SPKeyRevision > math.MaxUint32 || len(wire.Certificates) == 0 ||
		len(wire.Certificates) > maximumTenantSAMLCertificateCount {
		return platformsamladapter.TenantSAMLMetadataProjection{}, errFederatedAuthPersistence
	}
	projection := platformsamladapter.TenantSAMLMetadataProjection{
		TenantSlug: wire.TenantSlug, LoginKey: wire.LoginKey,
		TenantID: identity.EntityID(wire.TenantID), ProviderID: identity.EntityID(wire.ProviderID),
		BindingID: identity.EntityID(wire.BindingID), ProviderVersion: wire.ProviderVersion,
		BindingVersion: wire.BindingVersion, ConfigurationRevision: wire.ConfigurationRevision,
		SecurityRevision: wire.SecurityRevision, PlanRevision: wire.PlanRevision,
		AuthorizationRevision: wire.AuthorizationRevision, SPEntityID: wire.SPEntityID,
		ACSURL: wire.ACSURL, SPKeyRevision: wire.SPKeyRevision,
		RedirectSignatureAlgorithm: wire.RedirectSignatureAlgorithm,
		SignaturePolicy:            wire.SignaturePolicy, EncryptionPolicy: wire.EncryptionPolicy,
		SubjectSource: wire.SubjectSource, TenantActive: wire.TenantActive,
		ProviderEnabled: wire.ProviderEnabled, BindingEnabled: wire.BindingEnabled,
		PolicyEnabled: wire.PolicyEnabled, ProviderArchived: wire.ProviderArchived,
		BindingArchived: wire.BindingArchived, AccessEpochLive: wire.AccessEpochLive,
		ObservedAt:   wire.ObservedAt,
		Certificates: make([]platformsamladapter.TenantSAMLPublicCertificate, len(wire.Certificates)),
	}
	for index, certificate := range wire.Certificates {
		if certificate.KeyRevision == 0 || certificate.KeyRevision > math.MaxUint32 ||
			len(certificate.CertificateDER) == 0 || len(certificate.CertificateDER) > maximumTenantSAMLCertificateBytes {
			clearTenantSAMLMetadataProjection(&projection)
			return platformsamladapter.TenantSAMLMetadataProjection{}, errFederatedAuthPersistence
		}
		projection.Certificates[index] = platformsamladapter.TenantSAMLPublicCertificate{
			Context: identity.SAMLSPKeyContext{
				Provider: identity.ProviderContext{
					Scope: identity.TenantProviderScope, TenantID: identity.EntityID(certificate.TenantID),
					ProviderID: identity.EntityID(certificate.ProviderID),
				},
				BindingID: identity.EntityID(certificate.BindingID), KeyID: identity.EntityID(certificate.KeyID),
				KeyRevision: uint32(certificate.KeyRevision),
			},
			CertificateSequence: certificate.CertificateSequence,
			CertificateDER:      append([]byte(nil), certificate.CertificateDER...),
		}
	}
	return projection, nil
}

func clearTenantSAMLSPMetadataProjectionWire(wire *tenantSAMLSPMetadataProjectionWire) {
	if wire == nil {
		return
	}
	for index := range wire.Certificates {
		clear(wire.Certificates[index].CertificateDER)
	}
	*wire = tenantSAMLSPMetadataProjectionWire{}
}

func clearTenantSAMLMetadataProjection(projection *platformsamladapter.TenantSAMLMetadataProjection) {
	if projection == nil {
		return
	}
	for index := range projection.Certificates {
		clear(projection.Certificates[index].CertificateDER)
	}
	*projection = platformsamladapter.TenantSAMLMetadataProjection{}
}
