package identityprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type federationSAMLAdministrationDependencies struct {
	repository        FederationSAMLAdministrationRepository
	metadataRetriever FederationSAMLMetadataRetriever
	generateSPKey     FederationSAMLSPCredentialGenerator
	validateSPKey     FederationSAMLSPCredentialValidator
}

// ConfigureFederationSAMLAdministration attaches the optional tenant SAML
// material boundary during single-threaded process startup. It is deliberately
// separate from the core federation constructor so rolling deployments can
// keep the existing OIDC/provider surface available while this ABI is absent.
func (service *FederationService) ConfigureFederationSAMLAdministration(
	repository FederationSAMLAdministrationRepository,
	options FederationSAMLAdministrationOptions,
) error {
	if service == nil || repository == nil || options.MetadataRetriever == nil ||
		options.GenerateSPKey == nil || options.ValidateSPKey == nil {
		return errors.New("tenant SAML administration dependencies are required")
	}
	if service.saml != nil {
		return errors.New("tenant SAML administration is already configured")
	}
	service.saml = &federationSAMLAdministrationDependencies{
		repository: repository, metadataRetriever: options.MetadataRetriever,
		generateSPKey: options.GenerateSPKey, validateSPKey: options.ValidateSPKey,
	}
	return nil
}

func (service *FederationService) ReplaceSAMLMetadata(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, providerID uuid.UUID,
	input FederationReplaceSAMLMetadataInput,
) (FederationSAMLMaterialMutationReceipt, error) {
	defer clear(input.MetadataXML)
	version, err := validateIncrementableFederationVersion(providerID, input.ExpectedEntityTag, input.Audit)
	input.Reason = strings.TrimSpace(input.Reason)
	if input.MetadataURL != nil {
		location := strings.TrimSpace(*input.MetadataURL)
		input.MetadataURL = &location
	}
	if err != nil || !validFederationAuditReason(input.Reason) || !validFederationSAMLMetadataChoice(input) {
		if err != nil {
			return FederationSAMLMaterialMutationReceipt{}, err
		}
		return FederationSAMLMaterialMutationReceipt{}, ErrInvalidInput
	}
	human, err := service.require(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderManage)
	if err != nil {
		return FederationSAMLMaterialMutationReceipt{}, err
	}
	if service.saml == nil || service.saml.repository == nil || service.saml.metadataRetriever == nil {
		return FederationSAMLMaterialMutationReceipt{}, ErrUnavailable
	}
	preparation, err := service.saml.repository.PrepareSAMLMetadataReplacement(ctx, FederationPrepareSAMLMetadataParams{
		FederationHumanParams: human, ProviderID: providerID, ExpectedVersion: version,
	})
	defer preparation.Destroy()
	if err != nil {
		return FederationSAMLMaterialMutationReceipt{}, mapRepositoryError(err)
	}
	if !validFederationSAMLMetadataPreparation(preparation, tenantID, providerID, version) {
		return FederationSAMLMaterialMutationReceipt{}, ErrUnavailable
	}
	nextRevision := preparation.CurrentMetadataRevision + 1
	document, retrievedAt, err := service.resolveFederationSAMLMetadata(ctx, input)
	defer clear(document)
	if err != nil {
		return FederationSAMLMaterialMutationReceipt{}, err
	}
	maximumValidUntil := retrievedAt.Add(31 * 24 * time.Hour)
	next, err := federatedsaml.CompileMetadata(federatedsaml.MetadataCompilationRequest{
		Document: document, ExpectedEntityID: preparation.ExpectedEntityID,
		Revision: uint64(nextRevision), RetrievedAt: retrievedAt, MaximumValidUntil: maximumValidUntil,
	}, federatedsaml.DefaultLimits())
	if err != nil {
		return FederationSAMLMaterialMutationReceipt{}, ErrInvalidInput
	}
	protectedApproval := false
	if preparation.Current != nil {
		prior, compileErr := federatedsaml.CompileMetadata(federatedsaml.MetadataCompilationRequest{
			Document: preparation.Current.Document, ExpectedEntityID: preparation.ExpectedEntityID,
			Revision: uint64(preparation.Current.Revision), RetrievedAt: preparation.Current.RetrievedAt,
			MaximumValidUntil: preparation.Current.MaximumValidUntil,
		}, federatedsaml.DefaultLimits())
		if compileErr != nil || prior.Digest() != preparation.Current.Digest {
			return FederationSAMLMaterialMutationReceipt{}, ErrUnavailable
		}
		assessment, assessmentErr := federatedsaml.AssessMetadataRollover(prior, next)
		if assessmentErr != nil {
			return FederationSAMLMaterialMutationReceipt{}, ErrInvalidInput
		}
		protectedApproval = assessment.Decision == federatedsaml.RolloverProtectedApproval
		if protectedApproval && !input.ApproveTrustReset {
			return FederationSAMLMaterialMutationReceipt{}, ErrFederationSAMLTrustApprovalRequired
		}
	}
	digest := next.Digest()
	defer clear(digest[:])
	occurredAt, err := service.currentTime()
	if err != nil {
		return FederationSAMLMaterialMutationReceipt{}, err
	}
	receipt, err := service.saml.repository.ReplaceSAMLMetadata(ctx, FederationReplaceSAMLMetadataParams{
		FederationHumanParams: human, Audit: input.Audit, ProviderID: providerID,
		BindingID: preparation.BindingID, ExpectedVersion: version, ExpectedRevision: nextRevision,
		Document: document, Digest: digest, RetrievedAt: retrievedAt, MaximumValidUntil: next.ValidUntil(),
		ProtectedApproval: protectedApproval, Reason: input.Reason, OccurredAt: occurredAt,
	})
	if err != nil {
		return FederationSAMLMaterialMutationReceipt{}, mapRepositoryError(err)
	}
	if !validFederationSAMLMaterialReceipt(receipt, providerID, version+1, nextRevision) {
		return FederationSAMLMaterialMutationReceipt{}, ErrUnavailable
	}
	return receipt, nil
}

func (service *FederationService) ReplaceSAMLSPCredential(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, providerID uuid.UUID,
	input FederationReplaceSAMLSPCredentialInput,
) (FederationSAMLMaterialMutationReceipt, error) {
	version, err := validateIncrementableFederationVersion(providerID, input.ExpectedEntityTag, input.Audit)
	input.Reason = strings.TrimSpace(input.Reason)
	if err != nil || !validFederationAuditReason(input.Reason) {
		if err != nil {
			return FederationSAMLMaterialMutationReceipt{}, err
		}
		return FederationSAMLMaterialMutationReceipt{}, ErrInvalidInput
	}
	human, err := service.require(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderManage)
	if err != nil {
		return FederationSAMLMaterialMutationReceipt{}, err
	}
	if service.saml == nil || service.saml.repository == nil || service.saml.generateSPKey == nil ||
		service.saml.validateSPKey == nil {
		return FederationSAMLMaterialMutationReceipt{}, ErrUnavailable
	}
	preparation, err := service.saml.repository.PrepareSAMLSPCredentialMutation(ctx, FederationPrepareSAMLSPCredentialParams{
		FederationHumanParams: human, ProviderID: providerID, ExpectedVersion: version,
	})
	if err != nil {
		return FederationSAMLMaterialMutationReceipt{}, mapRepositoryError(err)
	}
	if !validFederationSAMLSPCredentialPreparation(preparation, tenantID, providerID, version) {
		return FederationSAMLMaterialMutationReceipt{}, ErrUnavailable
	}
	// V1 intentionally has no live overlap ceremony. Replacing a key while the
	// provider or binding can start transactions would invalidate their exact
	// SP-key pin, so rotation fails closed until both boundaries are disabled.
	if preparation.ProviderEnabled || preparation.BindingEnabled {
		return FederationSAMLMaterialMutationReceipt{}, ErrConflict
	}
	now, err := service.currentTime()
	if err != nil {
		return FederationSAMLMaterialMutationReceipt{}, err
	}
	generationRequest := FederationSAMLSPCredentialGenerationRequest{
		RedirectSignatureAlgorithm: preparation.RedirectSignatureAlgorithm,
		SPEntityID:                 preparation.SPEntityID,
		GeneratedAt:                now,
	}
	bundle, err := service.saml.generateSPKey(generationRequest)
	defer bundle.Destroy()
	if err != nil || !validGeneratedFederationSAMLSPCredential(bundle, generationRequest) ||
		service.saml.validateSPKey(bundle.PrivateKeyPKCS8, bundle.CertificateDER, now) != nil {
		return FederationSAMLMaterialMutationReceipt{}, ErrUnavailable
	}
	certificateValidity, valid := federationSAMLCertificateValidity(bundle.CertificateDER, now)
	if !valid {
		return FederationSAMLMaterialMutationReceipt{}, ErrUnavailable
	}
	nextRevision := preparation.CurrentCredentialRevision + 1
	keyID, err := service.nextID()
	if err != nil {
		return FederationSAMLMaterialMutationReceipt{}, err
	}
	envelope, err := service.keyring.EncryptSAMLSPKey(identity.SAMLSPKeyContext{
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: identity.EntityID(tenantID),
			ProviderID: identity.EntityID(providerID),
		},
		BindingID: identity.EntityID(preparation.BindingID), KeyID: identity.EntityID(keyID),
		KeyRevision: uint32(nextRevision),
	}, bundle.PrivateKeyPKCS8)
	if err != nil {
		return FederationSAMLMaterialMutationReceipt{}, ErrUnavailable
	}
	defer clear(envelope.Nonce[:])
	defer clear(envelope.Ciphertext)
	certificates := cloneFederationSAMLByteSlices(bundle.CertificateDER)
	defer clearFederationSAMLByteSlices(certificates)
	receipt, err := service.saml.repository.ReplaceSAMLSPCredential(ctx, FederationReplaceSAMLSPCredentialParams{
		FederationHumanParams: human, Audit: input.Audit, OccurredAt: now,
		ProviderID: providerID, BindingID: preparation.BindingID, ExpectedVersion: version,
		ExpectedRevision: nextRevision, Credential: FederationEncryptedSAMLSPCredential{
			KeyID: keyID, KeyRevision: nextRevision, Envelope: envelope, CertificateDER: certificates,
			CertificateValidity: certificateValidity,
		}, Reason: input.Reason,
	})
	if err != nil {
		return FederationSAMLMaterialMutationReceipt{}, mapRepositoryError(err)
	}
	if !validFederationSAMLMaterialReceipt(receipt, providerID, version+1, nextRevision) {
		return FederationSAMLMaterialMutationReceipt{}, ErrUnavailable
	}
	return receipt, nil
}

func federationSAMLCertificateValidity(
	certificates [][]byte,
	observedAt time.Time,
) ([]FederationSAMLCertificateValidity, bool) {
	if !validFederationSAMLAdministrationInstant(observedAt) {
		return nil, false
	}
	result := make([]FederationSAMLCertificateValidity, len(certificates))
	for index, der := range certificates {
		certificate, err := x509.ParseCertificate(der)
		if err != nil || !bytes.Equal(certificate.Raw, der) {
			return nil, false
		}
		notBefore := certificate.NotBefore.UTC().Truncate(time.Microsecond)
		notAfter := certificate.NotAfter.UTC().Truncate(time.Microsecond)
		if !certificate.NotBefore.Equal(notBefore) || !certificate.NotAfter.Equal(notAfter) ||
			notBefore.After(observedAt) || !notAfter.After(observedAt) {
			return nil, false
		}
		result[index] = FederationSAMLCertificateValidity{NotBefore: notBefore, NotAfter: notAfter}
	}
	return result, len(result) != 0
}

func (service *FederationService) ClearSAMLSPCredential(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, providerID uuid.UUID,
	input FederationClearSAMLSPCredentialInput,
) (FederationSAMLMaterialMutationReceipt, error) {
	version, err := validateIncrementableFederationVersion(providerID, input.ExpectedEntityTag, input.Audit)
	input.Reason = strings.TrimSpace(input.Reason)
	if err != nil || !validFederationAuditReason(input.Reason) {
		if err != nil {
			return FederationSAMLMaterialMutationReceipt{}, err
		}
		return FederationSAMLMaterialMutationReceipt{}, ErrInvalidInput
	}
	human, err := service.require(ctx, actor, tenantID, authorization.TenantPermissionIdentityProviderManage)
	if err != nil {
		return FederationSAMLMaterialMutationReceipt{}, err
	}
	if service.saml == nil || service.saml.repository == nil {
		return FederationSAMLMaterialMutationReceipt{}, ErrUnavailable
	}
	preparation, err := service.saml.repository.PrepareSAMLSPCredentialMutation(ctx, FederationPrepareSAMLSPCredentialParams{
		FederationHumanParams: human, ProviderID: providerID, ExpectedVersion: version,
	})
	if err != nil {
		return FederationSAMLMaterialMutationReceipt{}, mapRepositoryError(err)
	}
	if !validFederationSAMLSPCredentialPreparation(preparation, tenantID, providerID, version) {
		return FederationSAMLMaterialMutationReceipt{}, ErrUnavailable
	}
	if !preparation.CredentialPresent || preparation.ProviderEnabled || preparation.BindingEnabled {
		return FederationSAMLMaterialMutationReceipt{}, ErrConflict
	}
	now, err := service.currentTime()
	if err != nil {
		return FederationSAMLMaterialMutationReceipt{}, err
	}
	nextRevision := preparation.CurrentCredentialRevision + 1
	receipt, err := service.saml.repository.ClearSAMLSPCredential(ctx, FederationClearSAMLSPCredentialParams{
		FederationHumanParams: human, Audit: input.Audit, OccurredAt: now,
		ProviderID: providerID, BindingID: preparation.BindingID, ExpectedVersion: version,
		ExpectedRevision: nextRevision, Reason: input.Reason,
	})
	if err != nil {
		return FederationSAMLMaterialMutationReceipt{}, mapRepositoryError(err)
	}
	if !validFederationSAMLMaterialReceipt(receipt, providerID, version+1, nextRevision) {
		return FederationSAMLMaterialMutationReceipt{}, ErrUnavailable
	}
	return receipt, nil
}

func (service *FederationService) resolveFederationSAMLMetadata(
	ctx context.Context,
	input FederationReplaceSAMLMetadataInput,
) ([]byte, time.Time, error) {
	if input.MetadataURL != nil {
		document, retrievedAt, err := service.saml.metadataRetriever.RetrieveTenantSAMLMetadata(
			ctx, *input.MetadataURL, maximumFederationSAMLMetadataBytes,
		)
		if err != nil || !validFederationSAMLMetadataDocument(document, retrievedAt) {
			clear(document)
			return nil, time.Time{}, ErrUnavailable
		}
		return document, retrievedAt, nil
	}
	now, err := service.currentTime()
	if err != nil {
		return nil, time.Time{}, err
	}
	return slices.Clone(input.MetadataXML), now, nil
}

func validFederationSAMLMetadataChoice(input FederationReplaceSAMLMetadataInput) bool {
	urlPresent := input.MetadataURL != nil
	xmlPresent := len(input.MetadataXML) != 0
	if urlPresent == xmlPresent || len(input.MetadataXML) > maximumFederationSAMLMetadataBytes {
		return false
	}
	if urlPresent {
		return validCanonicalHTTPSFetchURL(*input.MetadataURL)
	}
	return true
}

func validCanonicalHTTPSFetchURL(value string) bool {
	if !validCanonicalHTTPSURL(value, false) {
		return false
	}
	parsed, err := url.Parse(value)
	return err == nil && parsed.RawQuery == "" && !parsed.ForceQuery
}

func validFederationSAMLMetadataPreparation(
	value FederationSAMLMetadataPreparation,
	tenantID, providerID uuid.UUID,
	providerVersion int64,
) bool {
	if value.TenantID != tenantID || value.ProviderID != providerID || !validUUIDv7(value.BindingID) ||
		value.ProviderVersion != providerVersion || !validCanonicalAbsoluteURI(value.ExpectedEntityID) ||
		value.CurrentMetadataRevision < 1 || value.CurrentMetadataRevision >= maximumFederationSAMLKeyRevision {
		return false
	}
	if value.CurrentMetadataRevision == 1 {
		return value.Current == nil
	}
	return validFederationSAMLMetadataSnapshot(value.Current, value.CurrentMetadataRevision)
}

func validFederationSAMLMetadataSnapshot(value *FederationSAMLMetadataSnapshot, revision int64) bool {
	return value != nil && value.Revision == revision && len(value.Document) > 0 &&
		len(value.Document) <= maximumFederationSAMLMetadataBytes && value.Digest == sha256.Sum256(value.Document) &&
		validFederationSAMLAdministrationInstant(value.RetrievedAt) &&
		validFederationSAMLAdministrationInstant(value.MaximumValidUntil) &&
		value.MaximumValidUntil.After(value.RetrievedAt) &&
		value.MaximumValidUntil.Sub(value.RetrievedAt) <= 31*24*time.Hour
}

func validFederationSAMLSPCredentialPreparation(
	value FederationSAMLSPCredentialPreparation,
	tenantID, providerID uuid.UUID,
	providerVersion int64,
) bool {
	return value.TenantID == tenantID && value.ProviderID == providerID && validUUIDv7(value.BindingID) &&
		value.ProviderVersion == providerVersion && value.CurrentCredentialRevision >= 1 &&
		value.CurrentCredentialRevision < maximumFederationSAMLKeyRevision &&
		(!value.CredentialPresent || value.CurrentCredentialRevision >= 2) &&
		validCanonicalAbsoluteURI(value.SPEntityID) && validFederationRedirectAlgorithm(value.RedirectSignatureAlgorithm)
}

func validFederationSAMLSPCredentialSize(privateKey []byte, certificates [][]byte) bool {
	if len(privateKey) < 1 || len(privateKey) > maximumFederationSAMLSPKeyPlaintextBytes ||
		len(certificates) < 1 || len(certificates) > maximumFederationSAMLCertificates {
		return false
	}
	seen := make(map[[sha256.Size]byte]struct{}, len(certificates))
	for _, certificate := range certificates {
		if len(certificate) < 1 || len(certificate) > maximumFederationSAMLCertificateBytes {
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

func validFederationSAMLMaterialReceipt(
	receipt FederationSAMLMaterialMutationReceipt,
	providerID uuid.UUID,
	providerVersion, materialRevision int64,
) bool {
	return receipt.ProviderID == providerID && receipt.ProviderVersion == providerVersion &&
		receipt.MaterialRevision == materialRevision && validFederationResourceVersion(receipt.ProviderVersion) &&
		receipt.MaterialRevision >= 2 && receipt.MaterialRevision <= maximumFederationSAMLKeyRevision
}

func validFederationSAMLMetadataDocument(document []byte, retrievedAt time.Time) bool {
	return len(document) > 0 && len(document) <= maximumFederationSAMLMetadataBytes &&
		validFederationSAMLAdministrationInstant(retrievedAt)
}

func validFederationSAMLAdministrationInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%int(time.Microsecond) == 0
}

func cloneFederationSAMLByteSlices(values [][]byte) [][]byte {
	cloned := make([][]byte, len(values))
	for index := range values {
		cloned[index] = slices.Clone(values[index])
	}
	return cloned
}

func clearFederationSAMLByteSlices(values [][]byte) {
	for index := range values {
		clear(values[index])
	}
}
