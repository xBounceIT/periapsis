package platformidentityprovider

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
)

type samlAdministrationRepositoryStub struct {
	*repositoryStub
	loadMetadata    func(context.Context, LoadSAMLMetadataAdminParams) (SAMLMetadataAdminSnapshot, error)
	replaceMetadata func(context.Context, ReplaceSAMLMetadataParams) (SAMLMaterialMutationReceipt, error)
	replaceKey      func(context.Context, ReplaceSAMLSPKeyParams) (SAMLMaterialMutationReceipt, error)
	clearKey        func(context.Context, ClearSAMLSPKeyParams) (SAMLMaterialMutationReceipt, error)
	metadataLoads   int
	metadataWrites  int
	keyWrites       int
	keyClears       int
}

func (repository *samlAdministrationRepositoryStub) LoadSAMLMetadataAdmin(
	ctx context.Context,
	params LoadSAMLMetadataAdminParams,
) (SAMLMetadataAdminSnapshot, error) {
	repository.metadataLoads++
	if repository.loadMetadata != nil {
		return repository.loadMetadata(ctx, params)
	}
	return SAMLMetadataAdminSnapshot{}, nil
}

func (repository *samlAdministrationRepositoryStub) ReplaceSAMLMetadata(
	ctx context.Context,
	params ReplaceSAMLMetadataParams,
) (SAMLMaterialMutationReceipt, error) {
	repository.metadataWrites++
	if repository.replaceMetadata != nil {
		return repository.replaceMetadata(ctx, params)
	}
	return SAMLMaterialMutationReceipt{}, nil
}

func (repository *samlAdministrationRepositoryStub) ReplaceSAMLSPKey(
	ctx context.Context,
	params ReplaceSAMLSPKeyParams,
) (SAMLMaterialMutationReceipt, error) {
	repository.keyWrites++
	if repository.replaceKey != nil {
		return repository.replaceKey(ctx, params)
	}
	return SAMLMaterialMutationReceipt{}, nil
}

func (repository *samlAdministrationRepositoryStub) ClearSAMLSPKey(
	ctx context.Context,
	params ClearSAMLSPKeyParams,
) (SAMLMaterialMutationReceipt, error) {
	repository.keyClears++
	if repository.clearKey != nil {
		return repository.clearKey(ctx, params)
	}
	return SAMLMaterialMutationReceipt{}, nil
}

type samlMetadataRetrieverStub struct {
	document SAMLMetadataDocument
	err      error
	location string
	limit    int
	calls    int
}

func (retriever *samlMetadataRetrieverStub) RetrieveSAMLMetadata(
	_ context.Context,
	location string,
	maximumBytes int,
) (SAMLMetadataDocument, error) {
	retriever.calls++
	retriever.location = location
	retriever.limit = maximumBytes
	return SAMLMetadataDocument{
		Document: append([]byte(nil), retriever.document.Document...), RetrievedAt: retriever.document.RetrievedAt,
	}, retriever.err
}

func TestReplaceSAMLMetadataCompilesUploadedDocumentAndPersistsOnlyBoundedSnapshot(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 123_456_000, time.UTC)
	providerID := mustUUIDv7(t)
	provider := validSAMLProvider(t, providerID)
	provider.Version = 3
	provider.SAML.MetadataRevision = 1
	_, certificate := samlAdministrationKeyAndCertificate(t, now)
	document := samlAdministrationMetadata(t, now, certificate, provider.SAML.ExpectedEntityID, "https://id.example.test/sso")
	wantDocument := append([]byte(nil), document...)
	repository := &samlAdministrationRepositoryStub{repositoryStub: &repositoryStub{}}
	repository.get = func(_ context.Context, params GetParams) (Provider, error) {
		if params.ProviderID != providerID {
			t.Fatalf("Get() params = %#v", params)
		}
		return provider, nil
	}
	repository.replaceMetadata = func(_ context.Context, params ReplaceSAMLMetadataParams) (SAMLMaterialMutationReceipt, error) {
		if params.ProviderID != providerID || params.ExpectedVersion != 3 || params.Reason != "Approve first metadata" ||
			params.ProtectedApproval || params.RetrievedAt != now ||
			params.MaximumValidUntil != now.Add(31*24*time.Hour) || !bytes.Equal(params.Document, wantDocument) ||
			params.Digest != sha256.Sum256(wantDocument) || params.Event.RequestID == uuid.Nil {
			t.Fatalf("ReplaceSAMLMetadata() params = %#v", params)
		}
		return mustSAMLMaterialReceipt(t, providerID, 4, 2), nil
	}
	service := mustSAMLAdministrationService(t, repository, now, func([]byte, [][]byte, time.Time) error { return nil })
	tag := mustEntityTag(t, 3)
	receipt, err := service.ReplaceSAMLMetadata(context.Background(), manageSession(t), providerID, ReplaceSAMLMetadataInput{
		MetadataXML: document, Reason: " Approve first metadata ", ExpectedEntityTag: &tag, Event: testEvent(t),
	})
	if err != nil || receipt.ProviderID() != providerID || receipt.Version() != 4 || receipt.MaterialRevision() != 2 {
		t.Fatalf("ReplaceSAMLMetadata() = %#v, %v", receipt, err)
	}
	if !allZero(document) || repository.metadataLoads != 0 || repository.metadataWrites != 1 {
		t.Fatalf("ownership/calls = cleared:%t loads:%d writes:%d", allZero(document), repository.metadataLoads, repository.metadataWrites)
	}
}

func TestReplaceSAMLMetadataRequiresAndAuditsProtectedRolloverApproval(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 30, 0, 123_456_000, time.UTC)
	providerID := mustUUIDv7(t)
	provider := validSAMLProvider(t, providerID)
	provider.Version = 4
	provider.SAML.MetadataRevision = 2
	_, certificate := samlAdministrationKeyAndCertificate(t, now)
	previousDocument := samlAdministrationMetadata(t, now, certificate, provider.SAML.ExpectedEntityID, "https://id.example.test/sso")
	previousDigest := sha256.Sum256(previousDocument)
	nextDocument := samlAdministrationMetadata(t, now, certificate, provider.SAML.ExpectedEntityID, "https://id.example.test/new-sso")
	repository := &samlAdministrationRepositoryStub{repositoryStub: &repositoryStub{}}
	repository.get = func(context.Context, GetParams) (Provider, error) { return provider, nil }
	repository.loadMetadata = func(_ context.Context, params LoadSAMLMetadataAdminParams) (SAMLMetadataAdminSnapshot, error) {
		if params.ProviderID != providerID || params.SessionID == uuid.Nil {
			t.Fatalf("LoadSAMLMetadataAdmin() params = %#v", params)
		}
		return SAMLMetadataAdminSnapshot{
			ProviderID: providerID, ProviderVersion: 4, MetadataRevision: 2,
			Document: append([]byte(nil), previousDocument...), Digest: previousDigest,
			RetrievedAt: now, MaximumValidUntil: now.Add(31 * 24 * time.Hour),
		}, nil
	}
	repository.replaceMetadata = func(_ context.Context, params ReplaceSAMLMetadataParams) (SAMLMaterialMutationReceipt, error) {
		if !params.ProtectedApproval {
			t.Fatal("protected rollover approval was not persisted for the audit boundary")
		}
		return mustSAMLMaterialReceipt(t, providerID, 5, 3), nil
	}
	service := mustSAMLAdministrationService(t, repository, now, func([]byte, [][]byte, time.Time) error { return nil })
	tag := mustEntityTag(t, 4)
	withoutApproval := append([]byte(nil), nextDocument...)
	_, err := service.ReplaceSAMLMetadata(context.Background(), manageSession(t), providerID, ReplaceSAMLMetadataInput{
		MetadataXML: withoutApproval, Reason: "Rotate endpoint", ExpectedEntityTag: &tag, Event: testEvent(t),
	})
	if !errors.Is(err, ErrSAMLTrustApprovalRequired) || repository.metadataWrites != 0 || !allZero(withoutApproval) {
		t.Fatalf("unapproved replacement error/calls/clear = %v/%d/%t", err, repository.metadataWrites, allZero(withoutApproval))
	}
	approved := append([]byte(nil), nextDocument...)
	receipt, err := service.ReplaceSAMLMetadata(context.Background(), manageSession(t), providerID, ReplaceSAMLMetadataInput{
		MetadataXML: approved, ApproveTrustReset: true, Reason: "Rotate endpoint",
		ExpectedEntityTag: &tag, Event: testEvent(t),
	})
	if err != nil || receipt.MaterialRevision() != 3 || repository.metadataWrites != 1 || !allZero(approved) {
		t.Fatalf("approved replacement = %#v, %v, writes=%d, clear=%t", receipt, err, repository.metadataWrites, allZero(approved))
	}
}

func TestReplaceSAMLMetadataURLUsesOnlyInjectedHardenedRetriever(t *testing.T) {
	now := time.Date(2026, 8, 30, 13, 0, 0, 123_456_000, time.UTC)
	providerID := mustUUIDv7(t)
	provider := validSAMLProvider(t, providerID)
	provider.Version = 3
	_, certificate := samlAdministrationKeyAndCertificate(t, now)
	document := samlAdministrationMetadata(t, now, certificate, provider.SAML.ExpectedEntityID, "https://id.example.test/sso")
	retriever := &samlMetadataRetrieverStub{document: SAMLMetadataDocument{Document: document, RetrievedAt: now}}
	repository := &samlAdministrationRepositoryStub{repositoryStub: &repositoryStub{}}
	repository.get = func(context.Context, GetParams) (Provider, error) { return provider, nil }
	repository.replaceMetadata = func(context.Context, ReplaceSAMLMetadataParams) (SAMLMaterialMutationReceipt, error) {
		return mustSAMLMaterialReceipt(t, providerID, 4, 2), nil
	}
	service := mustSAMLAdministrationServiceWithRetriever(
		t, repository, retriever, now, func([]byte, [][]byte, time.Time) error { return nil },
	)
	tag := mustEntityTag(t, 3)
	location := " https://id.example.test/metadata.xml "
	if _, err := service.ReplaceSAMLMetadata(context.Background(), manageSession(t), providerID, ReplaceSAMLMetadataInput{
		MetadataURL: &location, Reason: "Refresh metadata", ExpectedEntityTag: &tag, Event: testEvent(t),
	}); err != nil {
		t.Fatalf("ReplaceSAMLMetadata() error = %v", err)
	}
	if retriever.calls != 1 || retriever.location != "https://id.example.test/metadata.xml" ||
		retriever.limit != maximumSAMLMetadataBytes {
		t.Fatalf("retriever calls/location/limit = %d/%q/%d", retriever.calls, retriever.location, retriever.limit)
	}
}

func TestReplaceSAMLSPKeyUsesPurposeSeparatedAADAndClearsAllCallerMaterial(t *testing.T) {
	now := time.Date(2026, 8, 30, 14, 0, 0, 123_456_000, time.UTC)
	providerID, keyID := mustUUIDv7(t), mustUUIDv7(t)
	provider := validSAMLProvider(t, providerID)
	provider.Version = 3
	provider.SAML.SPKeyRevision = 1
	privateKey, certificate := samlAdministrationKeyAndCertificate(t, now)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	wantPKCS8 := append([]byte(nil), pkcs8...)
	wantCertificate := append([]byte(nil), certificate...)
	repository := &samlAdministrationRepositoryStub{repositoryStub: &repositoryStub{}}
	repository.get = func(context.Context, GetParams) (Provider, error) { return provider, nil }
	var captured EncryptedSAMLSPKey
	repository.replaceKey = func(_ context.Context, params ReplaceSAMLSPKeyParams) (SAMLMaterialMutationReceipt, error) {
		captured = EncryptedSAMLSPKey{
			KeyID: params.Key.KeyID, KeyRevision: params.Key.KeyRevision,
			Envelope: identity.SAMLSPKeyEnvelope{
				KeyVersion: params.Key.Envelope.KeyVersion, Nonce: params.Key.Envelope.Nonce,
				Ciphertext: append([]byte(nil), params.Key.Envelope.Ciphertext...),
			},
			CertificateDER: cloneSAMLByteSlices(params.Key.CertificateDER),
		}
		if params.ExpectedVersion != 3 || params.Reason != "Rotate SP key" {
			t.Fatalf("ReplaceSAMLSPKey() params = %#v", params)
		}
		return mustSAMLMaterialReceipt(t, providerID, 4, 2), nil
	}
	validatorCalls := 0
	service := mustSAMLAdministrationService(t, repository, now, func(key []byte, certificates [][]byte, observedAt time.Time) error {
		validatorCalls++
		if !bytes.Equal(key, wantPKCS8) || len(certificates) != 1 || !bytes.Equal(certificates[0], wantCertificate) || observedAt != now {
			t.Fatal("validator did not receive the exact owned bundle")
		}
		return nil
	})
	service.newID = func() (uuid.UUID, error) { return keyID, nil }
	tag := mustEntityTag(t, 3)
	receipt, err := service.ReplaceSAMLSPKey(context.Background(), manageSession(t), providerID, ReplaceSAMLSPKeyInput{
		PrivateKeyPKCS8: pkcs8, CertificateDER: [][]byte{certificate},
		Reason: " Rotate SP key ", ExpectedEntityTag: &tag, Event: testEvent(t),
	})
	if err != nil || receipt.Version() != 4 || receipt.MaterialRevision() != 2 || validatorCalls != 1 {
		t.Fatalf("ReplaceSAMLSPKey() = %#v, %v, validator calls=%d", receipt, err, validatorCalls)
	}
	if !allZero(pkcs8) || !allZero(certificate) {
		t.Fatalf("caller key/certificate were not cleared: %t/%t", allZero(pkcs8), allZero(certificate))
	}
	context := identity.DirectPlatformSAMLSPKeyContext{
		Provider: identity.ProviderContext{
			Scope: identity.PlatformProviderScope, ProviderID: identity.EntityID(providerID),
		},
		KeyID: identity.EntityID(keyID), KeyRevision: 2,
	}
	plaintext, err := service.keyring.DecryptDirectPlatformSAMLSPKey(context, captured.Envelope)
	defer clear(plaintext)
	defer clear(captured.Envelope.Ciphertext)
	defer clearSAMLByteSlices(captured.CertificateDER)
	if err != nil || !bytes.Equal(plaintext, wantPKCS8) || captured.KeyRevision != 2 ||
		len(captured.CertificateDER) != 1 || !bytes.Equal(captured.CertificateDER[0], wantCertificate) {
		t.Fatalf("captured key = %q, decrypt error = %v", captured.String(), err)
	}
	wrongContext := context
	wrongContext.KeyRevision++
	wrong, wrongErr := service.keyring.DecryptDirectPlatformSAMLSPKey(wrongContext, captured.Envelope)
	clear(wrong)
	if wrongErr == nil {
		t.Fatal("SP key envelope opened under a substituted semantic revision")
	}
}

func TestClearSAMLSPKeyRequiresPresentMaterialAndAdvancesSemanticFence(t *testing.T) {
	now := time.Date(2026, 8, 30, 15, 0, 0, 123_456_000, time.UTC)
	providerID := mustUUIDv7(t)
	provider := validSAMLProvider(t, providerID)
	provider.Version = 4
	provider.SecretPresent = true
	provider.SAML.SPKeyPresent = true
	provider.SAML.SPKeyRevision = 2
	repository := &samlAdministrationRepositoryStub{repositoryStub: &repositoryStub{}}
	repository.get = func(context.Context, GetParams) (Provider, error) { return provider, nil }
	repository.clearKey = func(_ context.Context, params ClearSAMLSPKeyParams) (SAMLMaterialMutationReceipt, error) {
		if params.ProviderID != providerID || params.ExpectedVersion != 4 || params.Reason != "Retire compromised key" {
			t.Fatalf("ClearSAMLSPKey() params = %#v", params)
		}
		return mustSAMLMaterialReceipt(t, providerID, 5, 3), nil
	}
	service := mustSAMLAdministrationService(t, repository, now, func([]byte, [][]byte, time.Time) error { return nil })
	tag := mustEntityTag(t, 4)
	receipt, err := service.ClearSAMLSPKey(context.Background(), manageSession(t), providerID, ClearSAMLSPKeyInput{
		Reason: " Retire compromised key ", ExpectedEntityTag: &tag, Event: testEvent(t),
	})
	if err != nil || receipt.Version() != 5 || receipt.MaterialRevision() != 3 || repository.keyClears != 1 {
		t.Fatalf("ClearSAMLSPKey() = %#v, %v, clears=%d", receipt, err, repository.keyClears)
	}

	provider.Version = 5
	provider.SecretPresent = false
	provider.SAML.SPKeyPresent = false
	provider.SAML.SPKeyRevision = 3
	tag = mustEntityTag(t, 5)
	_, err = service.ClearSAMLSPKey(context.Background(), manageSession(t), providerID, ClearSAMLSPKeyInput{
		Reason: "Clear again", ExpectedEntityTag: &tag, Event: testEvent(t),
	})
	if !errors.Is(err, authentication.ErrConflict) || repository.keyClears != 1 {
		t.Fatalf("second clear error/calls = %v/%d", err, repository.keyClears)
	}
}

func TestSAMLAdministrationDeniesBeforeMaterialValidationAndRedactsDiagnostics(t *testing.T) {
	now := time.Date(2026, 8, 30, 16, 0, 0, 123_456_000, time.UTC)
	repository := &samlAdministrationRepositoryStub{repositoryStub: &repositoryStub{}}
	service := mustSAMLAdministrationService(t, repository, now, func([]byte, [][]byte, time.Time) error {
		t.Fatal("validator called before authorization")
		return nil
	})
	session := manageSession(t)
	session.Permissions = nil
	key := []byte("private-key-material")
	certificate := []byte("certificate-material")
	input := ReplaceSAMLSPKeyInput{PrivateKeyPKCS8: key, CertificateDER: [][]byte{certificate}}
	if _, err := service.ReplaceSAMLSPKey(nil, session, uuid.Nil, input); !errors.Is(err, authentication.ErrForbidden) {
		t.Fatalf("ReplaceSAMLSPKey() error = %v", err)
	}
	if !allZero(key) || !allZero(certificate) || repository.calls != 0 || repository.keyWrites != 0 {
		t.Fatalf("denied ownership/calls = %t/%t/%d/%d", allZero(key), allZero(certificate), repository.calls, repository.keyWrites)
	}
	secretText := "private-key-material"
	metadata := ReplaceSAMLMetadataInput{MetadataXML: []byte("<sensitive-metadata/>")}
	params := ReplaceSAMLMetadataParams{Document: []byte("<sensitive-metadata/>")}
	for _, diagnostic := range []string{
		input.String(), input.GoString(), fmt.Sprintf("%#v", input),
		metadata.String(), metadata.GoString(), fmt.Sprintf("%#v", metadata),
		params.String(), params.GoString(), fmt.Sprintf("%#v", params),
	} {
		if strings.Contains(diagnostic, secretText) || strings.Contains(diagnostic, "sensitive-metadata") ||
			!strings.Contains(diagnostic, "[REDACTED]") {
			t.Fatalf("diagnostic was not redacted: %s", diagnostic)
		}
	}
}

func mustSAMLAdministrationService(
	t testing.TB,
	repository *samlAdministrationRepositoryStub,
	now time.Time,
	validator SAMLSPKeyBundleValidator,
) *Service {
	t.Helper()
	return mustSAMLAdministrationServiceWithRetriever(t, repository, &samlMetadataRetrieverStub{}, now, validator)
}

func mustSAMLAdministrationServiceWithRetriever(
	t testing.TB,
	repository *samlAdministrationRepositoryStub,
	retriever SAMLMetadataRetriever,
	now time.Time,
	validator SAMLSPKeyBundleValidator,
) *Service {
	t.Helper()
	service, err := NewService(repository, testKeyring(t), testPublicOrigin, SAMLAdministrationOptions{
		MetadataRetriever: retriever, ValidateSPKey: validator, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service
}

func mustSAMLMaterialReceipt(
	t testing.TB,
	providerID uuid.UUID,
	version int64,
	materialRevision int64,
) SAMLMaterialMutationReceipt {
	t.Helper()
	receipt, err := RestoreSAMLMaterialMutationReceipt(SAMLMaterialMutationReceiptInput{
		ProviderID: providerID, Version: version, MaterialRevision: materialRevision,
	})
	if err != nil {
		t.Fatalf("RestoreSAMLMaterialMutationReceipt() error = %v", err)
	}
	return receipt
}

func samlAdministrationKeyAndCertificate(t testing.TB, now time.Time) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.Unix()), Subject: pkix.Name{CommonName: "platform-saml-admin-test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(7 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return key, certificate
}

func samlAdministrationMetadata(
	t testing.TB,
	now time.Time,
	certificate []byte,
	entityID string,
	ssoURL string,
) []byte {
	t.Helper()
	return []byte(fmt.Sprintf(
		`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="%s" validUntil="%s"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="true"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s"/></md:IDPSSODescriptor></md:EntityDescriptor>`,
		entityID, now.Add(24*time.Hour).Format(time.RFC3339Nano), base64.StdEncoding.EncodeToString(certificate), ssoURL,
	))
}
