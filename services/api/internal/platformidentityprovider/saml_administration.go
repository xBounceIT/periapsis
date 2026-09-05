package platformidentityprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

const maximumSAMLMetadataBytes = 512 * 1024

var ErrSAMLTrustApprovalRequired = errors.New("platform SAML trust replacement requires protected approval")

type SAMLMetadataDocument struct {
	Document    []byte `json:"-"`
	RetrievedAt time.Time
}

func (document SAMLMetadataDocument) String() string {
	return fmt.Sprintf(
		"platformidentityprovider.SAMLMetadataDocument{bytes:%d,retrieved:%t,material:[REDACTED]}",
		len(document.Document), !document.RetrievedAt.IsZero(),
	)
}

func (document SAMLMetadataDocument) GoString() string { return document.String() }

func (document *SAMLMetadataDocument) Destroy() {
	if document == nil {
		return
	}
	clear(document.Document)
	*document = SAMLMetadataDocument{}
}

type SAMLMetadataRetriever interface {
	RetrieveSAMLMetadata(context.Context, string, int) (SAMLMetadataDocument, error)
}

type SAMLSPKeyBundleValidator func([]byte, [][]byte, time.Time) error

type SAMLAdministrationOptions struct {
	MetadataRetriever SAMLMetadataRetriever
	ValidateSPKey     SAMLSPKeyBundleValidator
	Now               func() time.Time
}

func validSAMLAdministrationOptions(options SAMLAdministrationOptions) bool {
	return !interfaceIsNil(options.MetadataRetriever) && options.ValidateSPKey != nil && options.Now != nil
}

type ReplaceSAMLMetadataInput struct {
	MetadataURL       *string
	MetadataXML       []byte `json:"-"`
	ApproveTrustReset bool
	Reason            string
	ExpectedEntityTag *string
	Event             authentication.EventContext
}

func (input ReplaceSAMLMetadataInput) String() string {
	return fmt.Sprintf(
		"platformidentityprovider.ReplaceSAMLMetadataInput{url:%t,xml_bytes:%d,approval:%t,material:[REDACTED]}",
		input.MetadataURL != nil, len(input.MetadataXML), input.ApproveTrustReset,
	)
}

func (input ReplaceSAMLMetadataInput) GoString() string { return input.String() }

type ReplaceSAMLSPKeyInput struct {
	PrivateKeyPKCS8   []byte   `json:"-"`
	CertificateDER    [][]byte `json:"-"`
	Reason            string
	ExpectedEntityTag *string
	Event             authentication.EventContext
}

func (input ReplaceSAMLSPKeyInput) String() string {
	return fmt.Sprintf(
		"platformidentityprovider.ReplaceSAMLSPKeyInput{key_bytes:%d,certificates:%d,material:[REDACTED]}",
		len(input.PrivateKeyPKCS8), len(input.CertificateDER),
	)
}

func (input ReplaceSAMLSPKeyInput) GoString() string { return input.String() }

type ClearSAMLSPKeyInput struct {
	Reason            string
	ExpectedEntityTag *string
	Event             authentication.EventContext
}

type SAMLMetadataAdminSnapshot struct {
	ProviderID        uuid.UUID
	ProviderVersion   int64
	MetadataRevision  int64
	Document          []byte `json:"-"`
	Digest            [sha256.Size]byte
	RetrievedAt       time.Time
	MaximumValidUntil time.Time
}

func (snapshot *SAMLMetadataAdminSnapshot) Destroy() {
	if snapshot == nil {
		return
	}
	clear(snapshot.Document)
	clear(snapshot.Digest[:])
	*snapshot = SAMLMetadataAdminSnapshot{}
}

func (snapshot SAMLMetadataAdminSnapshot) String() string {
	return fmt.Sprintf(
		"platformidentityprovider.SAMLMetadataAdminSnapshot{provider_version:%d,metadata_revision:%d,material:[REDACTED]}",
		snapshot.ProviderVersion, snapshot.MetadataRevision,
	)
}

func (snapshot SAMLMetadataAdminSnapshot) GoString() string { return snapshot.String() }

type LoadSAMLMetadataAdminParams struct {
	SessionParams
	ProviderID uuid.UUID
}

type ReplaceSAMLMetadataParams struct {
	SessionParams
	ProviderID        uuid.UUID
	ExpectedVersion   int64
	Document          []byte `json:"-"`
	Digest            [sha256.Size]byte
	RetrievedAt       time.Time
	MaximumValidUntil time.Time
	ProtectedApproval bool
	Reason            string
	Event             authentication.EventContext
}

func (params ReplaceSAMLMetadataParams) String() string {
	return fmt.Sprintf(
		"platformidentityprovider.ReplaceSAMLMetadataParams{expected_version:%d,approval:%t,material:[REDACTED]}",
		params.ExpectedVersion, params.ProtectedApproval,
	)
}

func (params ReplaceSAMLMetadataParams) GoString() string { return params.String() }

type EncryptedSAMLSPKey struct {
	KeyID               uuid.UUID
	KeyRevision         int64
	Envelope            identity.SAMLSPKeyEnvelope `json:"-"`
	CertificateDER      [][]byte                   `json:"-"`
	CertificateValidity []SAMLCertificateValidity
}

type SAMLCertificateValidity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

func (key EncryptedSAMLSPKey) String() string {
	return fmt.Sprintf(
		"platformidentityprovider.EncryptedSAMLSPKey{key_revision:%d,key_version:%d,certificates:%d,material:[REDACTED]}",
		key.KeyRevision, key.Envelope.KeyVersion, len(key.CertificateDER),
	)
}

func (key EncryptedSAMLSPKey) GoString() string { return key.String() }

type ReplaceSAMLSPKeyParams struct {
	SessionParams
	ProviderID      uuid.UUID
	ExpectedVersion int64
	Key             EncryptedSAMLSPKey
	Reason          string
	Event           authentication.EventContext
}

func (params ReplaceSAMLSPKeyParams) String() string {
	return fmt.Sprintf(
		"platformidentityprovider.ReplaceSAMLSPKeyParams{expected_version:%d,key:%q,material:[REDACTED]}",
		params.ExpectedVersion, params.Key.String(),
	)
}

func (params ReplaceSAMLSPKeyParams) GoString() string { return params.String() }

type ClearSAMLSPKeyParams struct {
	SessionParams
	ProviderID      uuid.UUID
	ExpectedVersion int64
	Reason          string
	Event           authentication.EventContext
}

type SAMLAdministrationRepository interface {
	LoadSAMLMetadataAdmin(context.Context, LoadSAMLMetadataAdminParams) (SAMLMetadataAdminSnapshot, error)
	ReplaceSAMLMetadata(context.Context, ReplaceSAMLMetadataParams) (SAMLMaterialMutationReceipt, error)
	ReplaceSAMLSPKey(context.Context, ReplaceSAMLSPKeyParams) (SAMLMaterialMutationReceipt, error)
	ClearSAMLSPKey(context.Context, ClearSAMLSPKeyParams) (SAMLMaterialMutationReceipt, error)
}

type SAMLMaterialMutationReceiptInput struct {
	ProviderID       uuid.UUID
	Version          int64
	MaterialRevision int64
}

type SAMLMaterialMutationReceipt struct {
	providerID       uuid.UUID
	version          int64
	materialRevision int64
}

func RestoreSAMLMaterialMutationReceipt(input SAMLMaterialMutationReceiptInput) (SAMLMaterialMutationReceipt, error) {
	if !validUUIDv7(input.ProviderID) || !validResourceVersion(input.Version) || input.Version < 2 ||
		!validProviderRevision(input.MaterialRevision) || input.MaterialRevision < 2 {
		return SAMLMaterialMutationReceipt{}, authentication.ErrInvalidInput
	}
	return SAMLMaterialMutationReceipt{
		providerID: input.ProviderID, version: input.Version, materialRevision: input.MaterialRevision,
	}, nil
}

func (receipt SAMLMaterialMutationReceipt) ProviderID() uuid.UUID { return receipt.providerID }
func (receipt SAMLMaterialMutationReceipt) Version() int64        { return receipt.version }
func (receipt SAMLMaterialMutationReceipt) MaterialRevision() int64 {
	return receipt.materialRevision
}

func (receipt SAMLMaterialMutationReceipt) String() string {
	return fmt.Sprintf(
		"platformidentityprovider.SAMLMaterialMutationReceipt{version:%d,material_revision:%d,metadata:[REDACTED]}",
		receipt.version, receipt.materialRevision,
	)
}

func (receipt SAMLMaterialMutationReceipt) GoString() string { return receipt.String() }

func (service *Service) ReplaceSAMLMetadata(
	ctx context.Context,
	session authentication.Session,
	providerID uuid.UUID,
	input ReplaceSAMLMetadataInput,
) (SAMLMaterialMutationReceipt, error) {
	defer clear(input.MetadataXML)
	expectedVersion, err := service.prepareSAMLAdministration(ctx, session, providerID, input.ExpectedEntityTag, input.Event)
	if err != nil {
		return SAMLMaterialMutationReceipt{}, err
	}
	input.Reason = normalizeSAMLAdministrationReason(input.Reason)
	if input.MetadataURL != nil {
		location := strings.TrimSpace(*input.MetadataURL)
		input.MetadataURL = &location
	}
	if !validReason(input.Reason) || !validSAMLMetadataChoice(input) {
		return SAMLMaterialMutationReceipt{}, authentication.ErrInvalidInput
	}
	provider, err := service.loadSAMLAdministrationProvider(ctx, session, providerID, expectedVersion)
	if err != nil {
		return SAMLMaterialMutationReceipt{}, err
	}
	currentRevision := provider.SAML.MetadataRevision
	if !validProviderRevision(currentRevision) || currentRevision >= maximumProviderRevision {
		return SAMLMaterialMutationReceipt{}, authentication.ErrUnavailable
	}
	nextRevision := currentRevision + 1

	var previous SAMLMetadataAdminSnapshot
	if currentRevision > 1 {
		previous, err = service.samlRepository.LoadSAMLMetadataAdmin(ctx, LoadSAMLMetadataAdminParams{
			SessionParams: sessionParams(session), ProviderID: providerID,
		})
		if err != nil {
			return SAMLMaterialMutationReceipt{}, mapRepositoryError(err)
		}
		defer previous.Destroy()
		if err := validateSAMLMetadataAdminSnapshot(previous, providerID, expectedVersion, currentRevision); err != nil {
			return SAMLMaterialMutationReceipt{}, authentication.ErrUnavailable
		}
	}

	document, err := service.resolveSAMLMetadata(ctx, input)
	if err != nil {
		return SAMLMaterialMutationReceipt{}, err
	}
	defer document.Destroy()
	maximumValidUntil := document.RetrievedAt.Add(31 * 24 * time.Hour)
	next, err := federatedsaml.CompileMetadata(federatedsaml.MetadataCompilationRequest{
		Document: document.Document, ExpectedEntityID: provider.SAML.ExpectedEntityID,
		Revision: uint64(nextRevision), RetrievedAt: document.RetrievedAt,
		MaximumValidUntil: maximumValidUntil,
	}, federatedsaml.DefaultLimits())
	if err != nil {
		return SAMLMaterialMutationReceipt{}, authentication.ErrInvalidInput
	}
	protectedApproval := false
	if currentRevision > 1 {
		prior, compileErr := federatedsaml.CompileMetadata(federatedsaml.MetadataCompilationRequest{
			Document: previous.Document, ExpectedEntityID: provider.SAML.ExpectedEntityID,
			Revision: uint64(previous.MetadataRevision), RetrievedAt: previous.RetrievedAt,
			MaximumValidUntil: previous.MaximumValidUntil,
		}, federatedsaml.DefaultLimits())
		if compileErr != nil || prior.Digest() != previous.Digest {
			return SAMLMaterialMutationReceipt{}, authentication.ErrUnavailable
		}
		assessment, assessmentErr := federatedsaml.AssessMetadataRollover(prior, next)
		if assessmentErr != nil {
			return SAMLMaterialMutationReceipt{}, authentication.ErrInvalidInput
		}
		protectedApproval = assessment.Decision == federatedsaml.RolloverProtectedApproval
		if protectedApproval && !input.ApproveTrustReset {
			return SAMLMaterialMutationReceipt{}, ErrSAMLTrustApprovalRequired
		}
	}
	digest := next.Digest()
	receipt, err := service.samlRepository.ReplaceSAMLMetadata(ctx, ReplaceSAMLMetadataParams{
		SessionParams: sessionParams(session), ProviderID: providerID, ExpectedVersion: expectedVersion,
		Document: document.Document, Digest: digest, RetrievedAt: document.RetrievedAt,
		MaximumValidUntil: maximumValidUntil, ProtectedApproval: protectedApproval,
		Reason: input.Reason, Event: input.Event,
	})
	clear(digest[:])
	if err != nil {
		return SAMLMaterialMutationReceipt{}, mapRepositoryError(err)
	}
	if !validSAMLMaterialMutationReceipt(receipt, providerID, expectedVersion+1, nextRevision) {
		return SAMLMaterialMutationReceipt{}, authentication.ErrUnavailable
	}
	return receipt, nil
}

func (service *Service) ReplaceSAMLSPKey(
	ctx context.Context,
	session authentication.Session,
	providerID uuid.UUID,
	input ReplaceSAMLSPKeyInput,
) (SAMLMaterialMutationReceipt, error) {
	defer clear(input.PrivateKeyPKCS8)
	defer clearSAMLByteSlices(input.CertificateDER)
	expectedVersion, err := service.prepareSAMLAdministration(ctx, session, providerID, input.ExpectedEntityTag, input.Event)
	if err != nil {
		return SAMLMaterialMutationReceipt{}, err
	}
	input.Reason = normalizeSAMLAdministrationReason(input.Reason)
	if !validReason(input.Reason) {
		return SAMLMaterialMutationReceipt{}, authentication.ErrInvalidInput
	}
	provider, err := service.loadSAMLAdministrationProvider(ctx, session, providerID, expectedVersion)
	if err != nil {
		return SAMLMaterialMutationReceipt{}, err
	}
	now, ok := canonicalSAMLAdministrationNow(service.saml.Now)
	if !ok {
		return SAMLMaterialMutationReceipt{}, authentication.ErrUnavailable
	}
	if service.saml.ValidateSPKey(input.PrivateKeyPKCS8, input.CertificateDER, now) != nil {
		return SAMLMaterialMutationReceipt{}, authentication.ErrInvalidInput
	}
	certificateValidity, valid := platformSAMLCertificateValidity(input.CertificateDER, now)
	if !valid {
		return SAMLMaterialMutationReceipt{}, authentication.ErrInvalidInput
	}
	if !validProviderRevision(provider.SAML.SPKeyRevision) || provider.SAML.SPKeyRevision >= maximumProviderRevision {
		return SAMLMaterialMutationReceipt{}, authentication.ErrUnavailable
	}
	nextRevision := provider.SAML.SPKeyRevision + 1
	keyID, err := service.newID()
	if err != nil || !validUUIDv7(keyID) {
		return SAMLMaterialMutationReceipt{}, authentication.ErrUnavailable
	}
	keyContext := identity.DirectPlatformSAMLSPKeyContext{
		Provider: identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: identity.EntityID(providerID),
		},
		KeyID: identity.EntityID(keyID), KeyRevision: uint64(nextRevision),
	}
	envelope, err := service.keyring.EncryptDirectPlatformSAMLSPKey(keyContext, input.PrivateKeyPKCS8)
	if err != nil {
		return SAMLMaterialMutationReceipt{}, authentication.ErrUnavailable
	}
	defer clear(envelope.Nonce[:])
	defer clear(envelope.Ciphertext)
	certificates := cloneSAMLByteSlices(input.CertificateDER)
	defer clearSAMLByteSlices(certificates)
	receipt, err := service.samlRepository.ReplaceSAMLSPKey(ctx, ReplaceSAMLSPKeyParams{
		SessionParams: sessionParams(session), ProviderID: providerID, ExpectedVersion: expectedVersion,
		Key: EncryptedSAMLSPKey{
			KeyID: keyID, KeyRevision: nextRevision, Envelope: envelope, CertificateDER: certificates,
			CertificateValidity: certificateValidity,
		},
		Reason: input.Reason, Event: input.Event,
	})
	if err != nil {
		return SAMLMaterialMutationReceipt{}, mapRepositoryError(err)
	}
	if !validSAMLMaterialMutationReceipt(receipt, providerID, expectedVersion+1, nextRevision) {
		return SAMLMaterialMutationReceipt{}, authentication.ErrUnavailable
	}
	return receipt, nil
}

func platformSAMLCertificateValidity(
	certificates [][]byte,
	observedAt time.Time,
) ([]SAMLCertificateValidity, bool) {
	if !validSAMLAdministrationInstant(observedAt) {
		return nil, false
	}
	result := make([]SAMLCertificateValidity, len(certificates))
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
		result[index] = SAMLCertificateValidity{NotBefore: notBefore, NotAfter: notAfter}
	}
	return result, len(result) != 0
}

func (service *Service) ClearSAMLSPKey(
	ctx context.Context,
	session authentication.Session,
	providerID uuid.UUID,
	input ClearSAMLSPKeyInput,
) (SAMLMaterialMutationReceipt, error) {
	expectedVersion, err := service.prepareSAMLAdministration(ctx, session, providerID, input.ExpectedEntityTag, input.Event)
	if err != nil {
		return SAMLMaterialMutationReceipt{}, err
	}
	input.Reason = normalizeSAMLAdministrationReason(input.Reason)
	if !validReason(input.Reason) {
		return SAMLMaterialMutationReceipt{}, authentication.ErrInvalidInput
	}
	provider, err := service.loadSAMLAdministrationProvider(ctx, session, providerID, expectedVersion)
	if err != nil {
		return SAMLMaterialMutationReceipt{}, err
	}
	if !provider.SAML.SPKeyPresent {
		return SAMLMaterialMutationReceipt{}, authentication.ErrConflict
	}
	if !validProviderRevision(provider.SAML.SPKeyRevision) || provider.SAML.SPKeyRevision >= maximumProviderRevision {
		return SAMLMaterialMutationReceipt{}, authentication.ErrUnavailable
	}
	nextRevision := provider.SAML.SPKeyRevision + 1
	receipt, err := service.samlRepository.ClearSAMLSPKey(ctx, ClearSAMLSPKeyParams{
		SessionParams: sessionParams(session), ProviderID: providerID, ExpectedVersion: expectedVersion,
		Reason: input.Reason, Event: input.Event,
	})
	if err != nil {
		return SAMLMaterialMutationReceipt{}, mapRepositoryError(err)
	}
	if !validSAMLMaterialMutationReceipt(receipt, providerID, expectedVersion+1, nextRevision) {
		return SAMLMaterialMutationReceipt{}, authentication.ErrUnavailable
	}
	return receipt, nil
}

func (service *Service) prepareSAMLAdministration(
	ctx context.Context,
	session authentication.Session,
	providerID uuid.UUID,
	entityTag *string,
	event authentication.EventContext,
) (int64, error) {
	if err := service.require(session, authorization.PermissionPlatformIdentityProviderManage); err != nil {
		return 0, err
	}
	if err := service.require(session, authorization.PermissionPlatformIdentityProviderRead); err != nil {
		return 0, err
	}
	if service == nil || interfaceIsNil(service.samlRepository) || !validSAMLAdministrationOptions(service.saml) {
		return 0, authentication.ErrUnavailable
	}
	if !validSession(session) {
		return 0, authentication.ErrUnavailable
	}
	if err := serviceContextError(ctx); err != nil {
		return 0, err
	}
	return normalizeVersioned(providerID, entityTag, event)
}

func (service *Service) loadSAMLAdministrationProvider(
	ctx context.Context,
	session authentication.Session,
	providerID uuid.UUID,
	expectedVersion int64,
) (Provider, error) {
	provider, err := service.repository.Get(ctx, GetParams{
		SessionParams: sessionParams(session), ProviderID: providerID,
	})
	if err != nil {
		return Provider{}, mapRepositoryError(err)
	}
	if provider.ID != providerID || !validProvider(provider, service.endpoints) {
		return Provider{}, authentication.ErrUnavailable
	}
	if provider.Version != expectedVersion {
		return Provider{}, ErrPreconditionFailed
	}
	if provider.Kind != ProviderKindSAML || provider.SAML == nil || provider.OIDC != nil || provider.ArchivedAt != nil {
		return Provider{}, authentication.ErrConflict
	}
	return provider, nil
}

func (service *Service) resolveSAMLMetadata(
	ctx context.Context,
	input ReplaceSAMLMetadataInput,
) (SAMLMetadataDocument, error) {
	if input.MetadataURL != nil {
		document, err := service.saml.MetadataRetriever.RetrieveSAMLMetadata(ctx, *input.MetadataURL, maximumSAMLMetadataBytes)
		if err != nil {
			return SAMLMetadataDocument{}, authentication.ErrUnavailable
		}
		if !validSAMLMetadataDocument(document) {
			document.Destroy()
			return SAMLMetadataDocument{}, authentication.ErrUnavailable
		}
		return document, nil
	}
	now, ok := canonicalSAMLAdministrationNow(service.saml.Now)
	if !ok {
		return SAMLMetadataDocument{}, authentication.ErrUnavailable
	}
	return SAMLMetadataDocument{Document: append([]byte(nil), input.MetadataXML...), RetrievedAt: now}, nil
}

func validSAMLMetadataChoice(input ReplaceSAMLMetadataInput) bool {
	urlPresent := input.MetadataURL != nil
	xmlPresent := len(input.MetadataXML) != 0
	if urlPresent == xmlPresent || len(input.MetadataXML) > maximumSAMLMetadataBytes {
		return false
	}
	if urlPresent {
		return *input.MetadataURL != "" && len(*input.MetadataURL) <= maximumFederationEndpointURIBytes
	}
	return true
}

func validateSAMLMetadataAdminSnapshot(
	snapshot SAMLMetadataAdminSnapshot,
	providerID uuid.UUID,
	providerVersion int64,
	metadataRevision int64,
) error {
	if snapshot.ProviderID != providerID || snapshot.ProviderVersion != providerVersion ||
		snapshot.MetadataRevision != metadataRevision || len(snapshot.Document) == 0 ||
		len(snapshot.Document) > maximumSAMLMetadataBytes || snapshot.Digest != sha256.Sum256(snapshot.Document) ||
		!validSAMLAdministrationInstant(snapshot.RetrievedAt) ||
		!validSAMLAdministrationInstant(snapshot.MaximumValidUntil) ||
		!snapshot.MaximumValidUntil.After(snapshot.RetrievedAt) ||
		snapshot.MaximumValidUntil.Sub(snapshot.RetrievedAt) > 31*24*time.Hour {
		return authentication.ErrInvalidInput
	}
	return nil
}

func validSAMLMetadataDocument(document SAMLMetadataDocument) bool {
	return len(document.Document) > 0 && len(document.Document) <= maximumSAMLMetadataBytes &&
		validSAMLAdministrationInstant(document.RetrievedAt)
}

func validSAMLMaterialMutationReceipt(
	receipt SAMLMaterialMutationReceipt,
	providerID uuid.UUID,
	version int64,
	materialRevision int64,
) bool {
	restored, err := RestoreSAMLMaterialMutationReceipt(SAMLMaterialMutationReceiptInput{
		ProviderID: receipt.providerID, Version: receipt.version, MaterialRevision: receipt.materialRevision,
	})
	return err == nil && restored == receipt && receipt.ProviderID() == providerID &&
		receipt.Version() == version && receipt.MaterialRevision() == materialRevision
}

func canonicalSAMLAdministrationNow(now func() time.Time) (time.Time, bool) {
	if now == nil {
		return time.Time{}, false
	}
	value := now().UTC().Truncate(time.Microsecond)
	return value, validSAMLAdministrationInstant(value)
}

func validSAMLAdministrationInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%1_000 == 0
}

func normalizeSAMLAdministrationReason(value string) string {
	return strings.TrimSpace(value)
}

func cloneSAMLByteSlices(values [][]byte) [][]byte {
	cloned := make([][]byte, len(values))
	for index := range values {
		cloned[index] = append([]byte(nil), values[index]...)
	}
	return cloned
}

func clearSAMLByteSlices(values [][]byte) {
	for index := range values {
		clear(values[index])
	}
}
