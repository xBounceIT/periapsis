package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

const (
	maximumTenantSAMLMetadataBytes     = 512 * 1024
	maximumTenantSAMLSPEnvelopeBytes   = 128 * 1024
	maximumTenantSAMLCertificateBytes  = 64 * 1024
	maximumTenantSAMLCertificateCount  = 8
	maximumTenantSAMLMaterialRevision  = int64(2_147_483_647)
	tenantSAMLAdministrationNonceBytes = 12
	minimumTenantSAMLCiphertextBytes   = 17
)

var _ identityprovider.FederationSAMLAdministrationRepository = (*IdentityProviderRepository)(nil)

type federationSAMLMetadataSnapshotWire struct {
	Revision          int64     `json:"revision"`
	Document          []byte    `json:"document"`
	Digest            []byte    `json:"digest"`
	RetrievedAt       time.Time `json:"retrievedAt"`
	MaximumValidUntil time.Time `json:"maximumValidUntil"`
}

type federationSAMLMetadataPreparationWire struct {
	TenantID                uuid.UUID                           `json:"tenantId"`
	ProviderID              uuid.UUID                           `json:"providerId"`
	BindingID               uuid.UUID                           `json:"bindingId"`
	ProviderVersion         int64                               `json:"providerVersion"`
	ExpectedEntityID        string                              `json:"expectedEntityId"`
	CurrentMetadataRevision int64                               `json:"currentMetadataRevision"`
	Current                 *federationSAMLMetadataSnapshotWire `json:"current"`
}

type federationSAMLSPCredentialPreparationWire struct {
	TenantID                   uuid.UUID                                `json:"tenantId"`
	ProviderID                 uuid.UUID                                `json:"providerId"`
	BindingID                  uuid.UUID                                `json:"bindingId"`
	ProviderVersion            int64                                    `json:"providerVersion"`
	CurrentCredentialRevision  int64                                    `json:"currentCredentialRevision"`
	CredentialPresent          bool                                     `json:"credentialPresent"`
	ProviderEnabled            bool                                     `json:"providerEnabled"`
	BindingEnabled             bool                                     `json:"bindingEnabled"`
	SPEntityID                 string                                   `json:"spEntityId"`
	RedirectSignatureAlgorithm federatedsaml.RedirectSignatureAlgorithm `json:"redirectSignatureAlgorithm"`
}

type federationSAMLMaterialReceiptWire struct {
	ProviderID       uuid.UUID `json:"providerId"`
	ProviderVersion  int64     `json:"providerVersion"`
	MaterialRevision int64     `json:"materialRevision"`
}

func (repository *IdentityProviderRepository) PrepareSAMLMetadataReplacement(
	ctx context.Context,
	params identityprovider.FederationPrepareSAMLMetadataParams,
) (identityprovider.FederationSAMLMetadataPreparation, error) {
	if !validFederationHuman(params.FederationHumanParams) || !identityProviderUUIDv7(params.ProviderID) ||
		params.ExpectedVersion < 1 || params.ExpectedVersion > 2_147_483_646 {
		return identityprovider.FederationSAMLMetadataPreparation{}, identityprovider.ErrInvalidInput
	}
	document, err := repository.callFederationAdministrationFunction(ctx, params.FederationHumanParams,
		"app.prepare_tenant_saml_metadata_v1", struct {
			MembershipID    uuid.UUID `json:"membershipId"`
			ProviderID      uuid.UUID `json:"providerId"`
			ExpectedVersion int64     `json:"expectedVersion"`
		}{params.MembershipID, params.ProviderID, params.ExpectedVersion})
	if err != nil {
		return identityprovider.FederationSAMLMetadataPreparation{}, err
	}
	var wire federationSAMLMetadataPreparationWire
	if err := decodeFederationAdministrationDocument(document, &wire); err != nil {
		return identityprovider.FederationSAMLMetadataPreparation{}, err
	}
	result := identityprovider.FederationSAMLMetadataPreparation{
		TenantID: wire.TenantID, ProviderID: wire.ProviderID, BindingID: wire.BindingID,
		ProviderVersion: wire.ProviderVersion, ExpectedEntityID: wire.ExpectedEntityID,
		CurrentMetadataRevision: wire.CurrentMetadataRevision,
	}
	if wire.Current != nil {
		if len(wire.Current.Digest) != sha256.Size {
			clear(wire.Current.Document)
			clear(wire.Current.Digest)
			return identityprovider.FederationSAMLMetadataPreparation{}, invalidIdentityProviderProjection(
				"tenant SAML metadata preparation returned an invalid digest",
			)
		}
		var digest [sha256.Size]byte
		copy(digest[:], wire.Current.Digest)
		clear(wire.Current.Digest)
		result.Current = &identityprovider.FederationSAMLMetadataSnapshot{
			Revision: wire.Current.Revision, Document: wire.Current.Document, Digest: digest,
			RetrievedAt: wire.Current.RetrievedAt, MaximumValidUntil: wire.Current.MaximumValidUntil,
		}
	}
	return result, nil
}

func (repository *IdentityProviderRepository) ReplaceSAMLMetadata(
	ctx context.Context,
	params identityprovider.FederationReplaceSAMLMetadataParams,
) (identityprovider.FederationSAMLMaterialMutationReceipt, error) {
	if !validFederationHuman(params.FederationHumanParams) || !identityProviderUUIDv7(params.ProviderID) ||
		!identityProviderUUIDv7(params.BindingID) || params.ExpectedVersion < 1 || params.ExpectedVersion > 2_147_483_646 ||
		params.ExpectedRevision < 2 || params.ExpectedRevision > maximumTenantSAMLMaterialRevision ||
		len(params.Document) < 1 || len(params.Document) > maximumTenantSAMLMetadataBytes ||
		params.Digest == ([sha256.Size]byte{}) || sha256.Sum256(params.Document) != params.Digest ||
		!validTenantSAMLAdministrationInstant(params.RetrievedAt) ||
		!validTenantSAMLAdministrationInstant(params.MaximumValidUntil) ||
		!params.MaximumValidUntil.After(params.RetrievedAt) ||
		params.MaximumValidUntil.Sub(params.RetrievedAt) > 31*24*time.Hour {
		return identityprovider.FederationSAMLMaterialMutationReceipt{}, identityprovider.ErrInvalidInput
	}
	document := slices.Clone(params.Document)
	digest := slices.Clone(params.Digest[:])
	defer clear(document)
	defer clear(digest)
	response, err := repository.callFederationAdministrationFunction(ctx, params.FederationHumanParams,
		"app.replace_tenant_saml_metadata_v1", struct {
			MembershipID      uuid.UUID           `json:"membershipId"`
			ProviderID        uuid.UUID           `json:"providerId"`
			BindingID         uuid.UUID           `json:"bindingId"`
			ExpectedVersion   int64               `json:"expectedVersion"`
			ExpectedRevision  int64               `json:"expectedRevision"`
			Document          []byte              `json:"document"`
			Digest            []byte              `json:"digest"`
			RetrievedAt       time.Time           `json:"retrievedAt"`
			MaximumValidUntil time.Time           `json:"maximumValidUntil"`
			ProtectedApproval bool                `json:"protectedApproval"`
			Reason            string              `json:"reason"`
			OccurredAt        time.Time           `json:"occurredAt"`
			Audit             federationAuditWire `json:"audit"`
		}{params.MembershipID, params.ProviderID, params.BindingID, params.ExpectedVersion,
			params.ExpectedRevision, document, digest, params.RetrievedAt, params.MaximumValidUntil,
			params.ProtectedApproval, params.Reason, params.OccurredAt,
			federationAudit(params.Audit, params.Actor.AuthenticationMethod)})
	if err != nil {
		return identityprovider.FederationSAMLMaterialMutationReceipt{}, err
	}
	return decodeFederationSAMLMaterialReceipt(response)
}

func (repository *IdentityProviderRepository) PrepareSAMLSPCredentialMutation(
	ctx context.Context,
	params identityprovider.FederationPrepareSAMLSPCredentialParams,
) (identityprovider.FederationSAMLSPCredentialPreparation, error) {
	if !validFederationHuman(params.FederationHumanParams) || !identityProviderUUIDv7(params.ProviderID) ||
		params.ExpectedVersion < 1 || params.ExpectedVersion > 2_147_483_646 {
		return identityprovider.FederationSAMLSPCredentialPreparation{}, identityprovider.ErrInvalidInput
	}
	document, err := repository.callFederationAdministrationFunction(ctx, params.FederationHumanParams,
		"app.prepare_tenant_saml_sp_credential_v1", struct {
			MembershipID    uuid.UUID `json:"membershipId"`
			ProviderID      uuid.UUID `json:"providerId"`
			ExpectedVersion int64     `json:"expectedVersion"`
		}{params.MembershipID, params.ProviderID, params.ExpectedVersion})
	if err != nil {
		return identityprovider.FederationSAMLSPCredentialPreparation{}, err
	}
	var wire federationSAMLSPCredentialPreparationWire
	if err := decodeFederationAdministrationDocument(document, &wire); err != nil {
		return identityprovider.FederationSAMLSPCredentialPreparation{}, err
	}
	return identityprovider.FederationSAMLSPCredentialPreparation{
		TenantID: wire.TenantID, ProviderID: wire.ProviderID, BindingID: wire.BindingID,
		ProviderVersion: wire.ProviderVersion, CurrentCredentialRevision: wire.CurrentCredentialRevision,
		CredentialPresent: wire.CredentialPresent, ProviderEnabled: wire.ProviderEnabled,
		BindingEnabled: wire.BindingEnabled, SPEntityID: wire.SPEntityID,
		RedirectSignatureAlgorithm: wire.RedirectSignatureAlgorithm,
	}, nil
}

func (repository *IdentityProviderRepository) ReplaceSAMLSPCredential(
	ctx context.Context,
	params identityprovider.FederationReplaceSAMLSPCredentialParams,
) (identityprovider.FederationSAMLMaterialMutationReceipt, error) {
	credential := params.Credential
	if !validFederationHuman(params.FederationHumanParams) || !identityProviderUUIDv7(params.ProviderID) ||
		!identityProviderUUIDv7(params.BindingID) || params.ExpectedVersion < 1 || params.ExpectedVersion > 2_147_483_646 ||
		params.ExpectedRevision < 2 || params.ExpectedRevision > maximumTenantSAMLMaterialRevision ||
		!identityProviderUUIDv7(credential.KeyID) || credential.KeyRevision != params.ExpectedRevision ||
		credential.Envelope.KeyVersion < 1 || len(credential.Envelope.Ciphertext) < minimumTenantSAMLCiphertextBytes ||
		len(credential.Envelope.Ciphertext)+tenantSAMLAdministrationNonceBytes > maximumTenantSAMLSPEnvelopeBytes ||
		!validTenantSAMLCertificates(credential.CertificateDER) ||
		!validTenantSAMLCertificateValidity(credential.CertificateDER, credential.CertificateValidity) {
		return identityprovider.FederationSAMLMaterialMutationReceipt{}, identityprovider.ErrInvalidInput
	}
	envelope := make([]byte, 0, tenantSAMLAdministrationNonceBytes+len(credential.Envelope.Ciphertext))
	envelope = append(envelope, credential.Envelope.Nonce[:]...)
	envelope = append(envelope, credential.Envelope.Ciphertext...)
	certificates := cloneFederatedBytes2D(credential.CertificateDER)
	defer clear(envelope)
	defer clearTenantSAMLByteSlices(certificates)
	response, err := repository.callFederationAdministrationFunction(ctx, params.FederationHumanParams,
		"app.replace_tenant_saml_sp_credential_v1", struct {
			MembershipID        uuid.UUID                                            `json:"membershipId"`
			ProviderID          uuid.UUID                                            `json:"providerId"`
			BindingID           uuid.UUID                                            `json:"bindingId"`
			ExpectedVersion     int64                                                `json:"expectedVersion"`
			ExpectedRevision    int64                                                `json:"expectedRevision"`
			KeyID               uuid.UUID                                            `json:"keyId"`
			KeyVersion          int16                                                `json:"keyVersion"`
			EnvelopeCiphertext  []byte                                               `json:"envelopeCiphertext"`
			CertificateDER      [][]byte                                             `json:"certificateDer"`
			CertificateValidity []identityprovider.FederationSAMLCertificateValidity `json:"certificateValidity"`
			Reason              string                                               `json:"reason"`
			OccurredAt          time.Time                                            `json:"occurredAt"`
			Audit               federationAuditWire                                  `json:"audit"`
		}{params.MembershipID, params.ProviderID, params.BindingID, params.ExpectedVersion,
			params.ExpectedRevision, credential.KeyID, credential.Envelope.KeyVersion, envelope,
			certificates, credential.CertificateValidity, params.Reason, params.OccurredAt,
			federationAudit(params.Audit, params.Actor.AuthenticationMethod)})
	if err != nil {
		return identityprovider.FederationSAMLMaterialMutationReceipt{}, err
	}
	return decodeFederationSAMLMaterialReceipt(response)
}

func validTenantSAMLCertificateValidity(
	certificateDER [][]byte,
	validity []identityprovider.FederationSAMLCertificateValidity,
) bool {
	if len(certificateDER) != len(validity) || len(validity) == 0 {
		return false
	}
	for index, der := range certificateDER {
		certificate, err := x509.ParseCertificate(der)
		if err != nil || !bytes.Equal(certificate.Raw, der) ||
			!certificate.NotBefore.Equal(validity[index].NotBefore) ||
			!certificate.NotAfter.Equal(validity[index].NotAfter) ||
			!validTenantSAMLAdministrationInstant(validity[index].NotBefore) ||
			!validTenantSAMLAdministrationInstant(validity[index].NotAfter) ||
			!validity[index].NotAfter.After(validity[index].NotBefore) {
			return false
		}
	}
	return true
}

func (repository *IdentityProviderRepository) ClearSAMLSPCredential(
	ctx context.Context,
	params identityprovider.FederationClearSAMLSPCredentialParams,
) (identityprovider.FederationSAMLMaterialMutationReceipt, error) {
	if !validFederationHuman(params.FederationHumanParams) || !identityProviderUUIDv7(params.ProviderID) ||
		!identityProviderUUIDv7(params.BindingID) || params.ExpectedVersion < 1 || params.ExpectedVersion > 2_147_483_646 ||
		params.ExpectedRevision < 2 || params.ExpectedRevision > maximumTenantSAMLMaterialRevision {
		return identityprovider.FederationSAMLMaterialMutationReceipt{}, identityprovider.ErrInvalidInput
	}
	response, err := repository.callFederationAdministrationFunction(ctx, params.FederationHumanParams,
		"app.clear_tenant_saml_sp_credential_v1", struct {
			MembershipID     uuid.UUID           `json:"membershipId"`
			ProviderID       uuid.UUID           `json:"providerId"`
			BindingID        uuid.UUID           `json:"bindingId"`
			ExpectedVersion  int64               `json:"expectedVersion"`
			ExpectedRevision int64               `json:"expectedRevision"`
			Reason           string              `json:"reason"`
			OccurredAt       time.Time           `json:"occurredAt"`
			Audit            federationAuditWire `json:"audit"`
		}{params.MembershipID, params.ProviderID, params.BindingID, params.ExpectedVersion,
			params.ExpectedRevision, params.Reason, params.OccurredAt,
			federationAudit(params.Audit, params.Actor.AuthenticationMethod)})
	if err != nil {
		return identityprovider.FederationSAMLMaterialMutationReceipt{}, err
	}
	return decodeFederationSAMLMaterialReceipt(response)
}

func decodeFederationSAMLMaterialReceipt(document []byte) (identityprovider.FederationSAMLMaterialMutationReceipt, error) {
	var wire federationSAMLMaterialReceiptWire
	if err := decodeFederationAdministrationDocument(document, &wire); err != nil {
		return identityprovider.FederationSAMLMaterialMutationReceipt{}, err
	}
	return identityprovider.FederationSAMLMaterialMutationReceipt{
		ProviderID: wire.ProviderID, ProviderVersion: wire.ProviderVersion,
		MaterialRevision: wire.MaterialRevision,
	}, nil
}

func validTenantSAMLCertificates(certificates [][]byte) bool {
	if len(certificates) < 1 || len(certificates) > maximumTenantSAMLCertificateCount {
		return false
	}
	seen := make(map[[sha256.Size]byte]struct{}, len(certificates))
	for _, certificate := range certificates {
		if len(certificate) < 1 || len(certificate) > maximumTenantSAMLCertificateBytes {
			return false
		}
		digest := sha256.Sum256(certificate)
		if _, duplicate := seen[digest]; duplicate {
			return false
		}
		seen[digest] = struct{}{}
	}
	return true
}

func validTenantSAMLAdministrationInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%int(time.Microsecond) == 0
}

func clearTenantSAMLByteSlices(values [][]byte) {
	for index := range values {
		clear(values[index])
	}
}
