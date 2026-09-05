package identityprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

func TestFederationSAMLMetadataReplacementUsesExactSnapshotAndProtectedRollover(t *testing.T) {
	entityID := "https://idp.example.test/entity"
	spEntityID := "https://soc.example.com/api/v1/auth/federated/saml/acme/corporate_saml/metadata"
	bundle := mustFederationSAMLGeneratedBundle(t, federatedsaml.RedirectECDSASHA256, spEntityID)
	defer bundle.Destroy()
	currentDocument := federationSAMLMetadataDocument(
		testNow, bundle.CertificateDER[0], entityID, "https://idp.example.test/sso",
	)
	nextDocument := federationSAMLMetadataDocument(
		testNow, bundle.CertificateDER[0], entityID, "https://idp.example.test/new-sso",
	)
	repository := &federationSAMLAdministrationRepositoryStub{}
	repository.prepareMetadata = func(context.Context, FederationPrepareSAMLMetadataParams) (FederationSAMLMetadataPreparation, error) {
		return FederationSAMLMetadataPreparation{
			TenantID: testTenantID, ProviderID: testProviderID, BindingID: testFederationBindingID,
			ProviderVersion: 4, ExpectedEntityID: entityID, CurrentMetadataRevision: 2,
			Current: &FederationSAMLMetadataSnapshot{
				Revision: 2, Document: append([]byte(nil), currentDocument...),
				Digest: sha256.Sum256(currentDocument), RetrievedAt: testNow,
				MaximumValidUntil: testNow.Add(31 * 24 * time.Hour),
			},
		}, nil
	}
	repository.replaceMetadata = func(_ context.Context, params FederationReplaceSAMLMetadataParams) (FederationSAMLMaterialMutationReceipt, error) {
		if params.ProviderID != testProviderID || params.BindingID != testFederationBindingID ||
			params.ExpectedVersion != 4 || params.ExpectedRevision != 3 || !params.ProtectedApproval ||
			!bytes.Equal(params.Document, nextDocument) || params.Digest != sha256.Sum256(nextDocument) ||
			params.Reason != "Approve trust reset" || params.OccurredAt != testNow {
			t.Fatalf("ReplaceSAMLMetadata() params = %s", params.String())
		}
		return FederationSAMLMaterialMutationReceipt{
			ProviderID: testProviderID, ProviderVersion: 5, MaterialRevision: 3,
		}, nil
	}
	service := testFederationSAMLService(t, repository, nil, GenerateFederationSAMLSPCredential, func([]byte, [][]byte, time.Time) error { return nil })
	tag := `"v4"`
	unapproved := append([]byte(nil), nextDocument...)
	_, err := service.ReplaceSAMLMetadata(context.Background(), testActor(), testTenantID, testProviderID, FederationReplaceSAMLMetadataInput{
		MetadataXML: unapproved, Reason: "Approve trust reset", ExpectedEntityTag: &tag, Audit: testAudit(),
	})
	if !errors.Is(err, ErrFederationSAMLTrustApprovalRequired) || repository.metadataWrites != 0 ||
		!federationSAMLAllZero(unapproved) {
		t.Fatalf("unapproved replacement = %v, writes=%d, cleared=%t", err, repository.metadataWrites, federationSAMLAllZero(unapproved))
	}
	approved := append([]byte(nil), nextDocument...)
	receipt, err := service.ReplaceSAMLMetadata(context.Background(), testActor(), testTenantID, testProviderID, FederationReplaceSAMLMetadataInput{
		MetadataXML: approved, ApproveTrustReset: true, Reason: " Approve trust reset ",
		ExpectedEntityTag: &tag, Audit: testAudit(),
	})
	if err != nil || receipt.ProviderVersion != 5 || receipt.MaterialRevision != 3 ||
		repository.metadataWrites != 1 || !federationSAMLAllZero(approved) {
		t.Fatalf("approved replacement = %#v, %v, writes=%d, cleared=%t", receipt, err, repository.metadataWrites, federationSAMLAllZero(approved))
	}
}

func TestFederationSAMLMetadataReplacementPersistsXMLValidUntilInsteadOfCompilationCap(t *testing.T) {
	entityID := "https://idp.example.test/entity"
	spEntityID := "https://soc.example.com/api/v1/auth/federated/saml/acme/corporate_saml/metadata"
	bundle := mustFederationSAMLGeneratedBundle(t, federatedsaml.RedirectECDSASHA256, spEntityID)
	defer bundle.Destroy()
	validUntil := testNow.Add(90 * time.Minute)
	expiredAt := validUntil.Add(time.Microsecond)
	compilationCap := testNow.Add(31 * 24 * time.Hour)
	document := federationSAMLMetadataDocumentWithValidUntil(
		validUntil, bundle.CertificateDER[0], entityID, "https://idp.example.test/sso",
	)
	repository := &federationSAMLAdministrationRepositoryStub{}
	repository.prepareMetadata = func(context.Context, FederationPrepareSAMLMetadataParams) (FederationSAMLMetadataPreparation, error) {
		return FederationSAMLMetadataPreparation{
			TenantID: testTenantID, ProviderID: testProviderID, BindingID: testFederationBindingID,
			ProviderVersion: 3, ExpectedEntityID: entityID, CurrentMetadataRevision: 1,
		}, nil
	}
	repository.replaceMetadata = func(_ context.Context, params FederationReplaceSAMLMetadataParams) (FederationSAMLMaterialMutationReceipt, error) {
		if params.RetrievedAt != testNow || params.MaximumValidUntil != validUntil ||
			!params.MaximumValidUntil.Before(expiredAt) || !expiredAt.Before(compilationCap) {
			t.Fatalf("metadata validity = retrieved %s, persisted %s; XML expiry %s, cap %s",
				params.RetrievedAt, params.MaximumValidUntil, expiredAt, compilationCap)
		}
		return FederationSAMLMaterialMutationReceipt{
			ProviderID: testProviderID, ProviderVersion: 4, MaterialRevision: 2,
		}, nil
	}
	service := testFederationSAMLService(t, repository, nil, GenerateFederationSAMLSPCredential, func([]byte, [][]byte, time.Time) error { return nil })
	tag := `"v3"`
	receipt, err := service.ReplaceSAMLMetadata(context.Background(), testActor(), testTenantID, testProviderID, FederationReplaceSAMLMetadataInput{
		MetadataXML: append([]byte(nil), document...), Reason: "Refresh metadata",
		ExpectedEntityTag: &tag, Audit: testAudit(),
	})
	if err != nil || receipt.ProviderVersion != 4 || receipt.MaterialRevision != 2 || repository.metadataWrites != 1 {
		t.Fatalf("replacement = %#v, %v, writes=%d", receipt, err, repository.metadataWrites)
	}
}

func TestFederationSAMLMetadataURLUsesOnlyHardenedRetrieverAndRejectsInvalidDocument(t *testing.T) {
	entityID := "https://idp.example.test/entity"
	spEntityID := "https://soc.example.com/api/v1/auth/federated/saml/acme/corporate_saml/metadata"
	bundle := mustFederationSAMLGeneratedBundle(t, federatedsaml.RedirectECDSASHA256, spEntityID)
	defer bundle.Destroy()
	document := federationSAMLMetadataDocument(testNow, bundle.CertificateDER[0], entityID, "https://idp.example.test/sso")
	retriever := &federationSAMLMetadataRetrieverStub{document: document, retrievedAt: testNow}
	repository := &federationSAMLAdministrationRepositoryStub{}
	repository.prepareMetadata = func(context.Context, FederationPrepareSAMLMetadataParams) (FederationSAMLMetadataPreparation, error) {
		return FederationSAMLMetadataPreparation{
			TenantID: testTenantID, ProviderID: testProviderID, BindingID: testFederationBindingID,
			ProviderVersion: 3, ExpectedEntityID: entityID, CurrentMetadataRevision: 1,
		}, nil
	}
	repository.replaceMetadata = func(context.Context, FederationReplaceSAMLMetadataParams) (FederationSAMLMaterialMutationReceipt, error) {
		return FederationSAMLMaterialMutationReceipt{ProviderID: testProviderID, ProviderVersion: 4, MaterialRevision: 2}, nil
	}
	service := testFederationSAMLService(t, repository, retriever, GenerateFederationSAMLSPCredential, func([]byte, [][]byte, time.Time) error { return nil })
	tag := `"v3"`
	location := " https://idp.example.test/metadata.xml "
	_, err := service.ReplaceSAMLMetadata(context.Background(), testActor(), testTenantID, testProviderID, FederationReplaceSAMLMetadataInput{
		MetadataURL: &location, Reason: "Refresh metadata", ExpectedEntityTag: &tag, Audit: testAudit(),
	})
	if err != nil || retriever.calls != 1 || retriever.location != "https://idp.example.test/metadata.xml" ||
		retriever.maximumBytes != maximumFederationSAMLMetadataBytes {
		t.Fatalf("metadata URL replacement = %v, retriever=%#v", err, retriever)
	}
	location = "https://idp.example.test/metadata.xml?tenant=acme"
	_, err = service.ReplaceSAMLMetadata(context.Background(), testActor(), testTenantID, testProviderID, FederationReplaceSAMLMetadataInput{
		MetadataURL: &location, Reason: "Refresh metadata", ExpectedEntityTag: &tag, Audit: testAudit(),
	})
	if !errors.Is(err, ErrInvalidInput) || retriever.calls != 1 {
		t.Fatalf("metadata URL query error/calls = %v/%d", err, retriever.calls)
	}

	location = "https://idp.example.test/metadata.xml"
	retriever.document = []byte("<sensitive-invalid-metadata/>")
	_, err = service.ReplaceSAMLMetadata(context.Background(), testActor(), testTenantID, testProviderID, FederationReplaceSAMLMetadataInput{
		MetadataURL: &location, Reason: "Refresh metadata", ExpectedEntityTag: &tag, Audit: testAudit(),
	})
	if !errors.Is(err, ErrInvalidInput) || repository.metadataWrites != 1 {
		t.Fatalf("invalid metadata error/writes = %v/%d", err, repository.metadataWrites)
	}
}

func TestFederationSAMLSPCredentialIsServerGeneratedTenantBoundAndDestroyed(t *testing.T) {
	spEntityID := "https://soc.example.com/api/v1/auth/federated/saml/acme/corporate_saml/metadata"
	repository := &federationSAMLAdministrationRepositoryStub{}
	repository.prepareCredential = func(_ context.Context, params FederationPrepareSAMLSPCredentialParams) (FederationSAMLSPCredentialPreparation, error) {
		if params.ProviderID != testProviderID || params.ExpectedVersion != 3 {
			t.Fatalf("prepare params = %#v", params)
		}
		return FederationSAMLSPCredentialPreparation{
			TenantID: testTenantID, ProviderID: testProviderID, BindingID: testFederationBindingID,
			ProviderVersion: 3, CurrentCredentialRevision: 1, SPEntityID: spEntityID,
			RedirectSignatureAlgorithm: federatedsaml.RedirectECDSASHA256,
		}, nil
	}
	keyring := testIdentityKeyring(t)
	var keyAlias, certificateAlias []byte
	generatorCalls := 0
	generator := func(request FederationSAMLSPCredentialGenerationRequest) (FederationSAMLSPCredentialBundle, error) {
		generatorCalls++
		if request.RedirectSignatureAlgorithm != federatedsaml.RedirectECDSASHA256 ||
			request.SPEntityID != spEntityID || request.GeneratedAt != testNow {
			t.Fatalf("generation request = %#v", request)
		}
		generated, err := GenerateFederationSAMLSPCredential(request)
		if err == nil {
			keyAlias = generated.PrivateKeyPKCS8
			certificateAlias = generated.CertificateDER[0]
		}
		return generated, err
	}
	validatorCalls := 0
	validator := func(key []byte, certificates [][]byte, observedAt time.Time) error {
		validatorCalls++
		if observedAt != testNow || len(key) == 0 || len(certificates) != 1 {
			t.Fatal("validator did not receive the generated bundle")
		}
		return nil
	}
	repository.replaceCredential = func(_ context.Context, params FederationReplaceSAMLSPCredentialParams) (FederationSAMLMaterialMutationReceipt, error) {
		if params.ExpectedVersion != 3 || params.ExpectedRevision != 2 || params.Credential.KeyID != testSecretID ||
			params.Credential.KeyRevision != 2 || params.Reason != "Rotate SP credential" {
			t.Fatalf("replace params = %s", params.String())
		}
		keyContext := identity.SAMLSPKeyContext{
			Provider: identity.ProviderContext{
				Scope: identity.TenantProviderScope, TenantID: identity.EntityID(testTenantID),
				ProviderID: identity.EntityID(testProviderID),
			},
			BindingID: identity.EntityID(testFederationBindingID), KeyID: identity.EntityID(testSecretID), KeyRevision: 2,
		}
		plaintext, decryptErr := keyring.DecryptSAMLSPKey(keyContext, params.Credential.Envelope)
		if decryptErr != nil || !bytes.Equal(plaintext, keyAlias) {
			clear(plaintext)
			t.Fatalf("decrypt generated credential = %v", decryptErr)
		}
		clear(plaintext)
		wrongContext := keyContext
		wrongContext.Provider.TenantID = identity.EntityID(testFederationOtherTenantID)
		wrong, wrongErr := keyring.DecryptSAMLSPKey(wrongContext, params.Credential.Envelope)
		clear(wrong)
		if wrongErr == nil {
			t.Fatal("tenant SAML credential opened under a substituted tenant AAD")
		}
		return FederationSAMLMaterialMutationReceipt{ProviderID: testProviderID, ProviderVersion: 4, MaterialRevision: 2}, nil
	}
	service := testFederationSAMLServiceWithKeyring(t, repository, nil, generator, validator, keyring)
	service.newID = func() (uuid.UUID, error) { return testSecretID, nil }
	tag := `"v3"`
	receipt, err := service.ReplaceSAMLSPCredential(context.Background(), testActor(), testTenantID, testProviderID, FederationReplaceSAMLSPCredentialInput{
		Reason: " Rotate SP credential ", ExpectedEntityTag: &tag, Audit: testAudit(),
	})
	if err != nil || receipt.ProviderVersion != 4 || receipt.MaterialRevision != 2 ||
		generatorCalls != 1 || validatorCalls != 1 || !federationSAMLAllZero(keyAlias) ||
		!federationSAMLAllZero(certificateAlias) {
		t.Fatalf("replace = %#v, %v calls=%d/%d destroyed=%t/%t", receipt, err, generatorCalls, validatorCalls,
			federationSAMLAllZero(keyAlias), federationSAMLAllZero(certificateAlias))
	}
}

func TestFederationSAMLSPCredentialRotationFailsClosedBeforeGeneration(t *testing.T) {
	tests := []struct {
		name        string
		tenantID    uuid.UUID
		permission  authorization.TenantPermission
		preparation FederationSAMLSPCredentialPreparation
		prepareErr  error
		want        error
	}{
		{
			name: "wrong active tenant", tenantID: testFederationOtherTenantID,
			permission: authorization.TenantPermissionIdentityProviderManage, want: ErrForbidden,
		},
		{
			name: "deny by default", tenantID: testTenantID,
			permission: authorization.TenantPermissionIdentityProviderRead, want: ErrForbidden,
		},
		{
			name: "stale CAS", tenantID: testTenantID,
			permission: authorization.TenantPermissionIdentityProviderManage,
			prepareErr: authorization.ErrPreconditionFailed, want: ErrPreconditionFailed,
		},
		{
			name: "enabled provider", tenantID: testTenantID,
			permission:  authorization.TenantPermissionIdentityProviderManage,
			preparation: validFederationSAMLSPCredentialPreparationForTest(true, false), want: ErrConflict,
		},
		{
			name: "enabled binding", tenantID: testTenantID,
			permission:  authorization.TenantPermissionIdentityProviderManage,
			preparation: validFederationSAMLSPCredentialPreparationForTest(false, true), want: ErrConflict,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			authority := &federationAdministrationRepositoryStub{}
			authority.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
				return testIdentityProviderAuthority(test.permission), nil
			}
			repository := &federationSAMLAdministrationRepositoryStub{}
			repository.prepareCredential = func(context.Context, FederationPrepareSAMLSPCredentialParams) (FederationSAMLSPCredentialPreparation, error) {
				return test.preparation, test.prepareErr
			}
			generatorCalls := 0
			service := testFederationService(t, authority, nil)
			if err := service.ConfigureFederationSAMLAdministration(repository, FederationSAMLAdministrationOptions{
				MetadataRetriever: &federationSAMLMetadataRetrieverStub{},
				GenerateSPKey: func(FederationSAMLSPCredentialGenerationRequest) (FederationSAMLSPCredentialBundle, error) {
					generatorCalls++
					return FederationSAMLSPCredentialBundle{}, errors.New("unexpected generator call")
				},
				ValidateSPKey: func([]byte, [][]byte, time.Time) error { return nil },
			}); err != nil {
				t.Fatal(err)
			}
			tag := `"v3"`
			_, err := service.ReplaceSAMLSPCredential(context.Background(), testActor(), test.tenantID, testProviderID, FederationReplaceSAMLSPCredentialInput{
				Reason: "Rotate SP credential", ExpectedEntityTag: &tag, Audit: testAudit(),
			})
			if !errors.Is(err, test.want) || generatorCalls != 0 || repository.credentialWrites != 0 {
				t.Fatalf("error/generator/writes = %v/%d/%d", err, generatorCalls, repository.credentialWrites)
			}
		})
	}
}

func TestFederationSAMLAdministrationDiagnosticsNeverExposeMaterial(t *testing.T) {
	bundle := FederationSAMLSPCredentialBundle{
		PrivateKeyPKCS8: []byte("private-key-material"), CertificateDER: [][]byte{[]byte("certificate-material")},
	}
	metadata := FederationReplaceSAMLMetadataInput{MetadataXML: []byte("<secret-metadata/>")}
	params := FederationReplaceSAMLMetadataParams{Document: []byte("<secret-metadata/>")}
	for _, diagnostic := range []string{
		bundle.String(), bundle.GoString(), fmt.Sprintf("%#v", bundle),
		metadata.String(), metadata.GoString(), fmt.Sprintf("%#v", metadata),
		params.String(), params.GoString(), fmt.Sprintf("%#v", params),
	} {
		if strings.Contains(diagnostic, "private-key-material") || strings.Contains(diagnostic, "certificate-material") ||
			strings.Contains(diagnostic, "secret-metadata") || !strings.Contains(diagnostic, "[REDACTED]") {
			t.Fatalf("diagnostic was not redacted: %s", diagnostic)
		}
	}
	bundle.Destroy()
}

func TestGenerateFederationSAMLSPCredentialMatchesConfiguredAlgorithmAndCertificateProfile(t *testing.T) {
	for _, algorithm := range []federatedsaml.RedirectSignatureAlgorithm{
		federatedsaml.RedirectRSASHA256,
		federatedsaml.RedirectECDSASHA256,
	} {
		algorithm := algorithm
		t.Run(string(algorithm), func(t *testing.T) {
			request := FederationSAMLSPCredentialGenerationRequest{
				RedirectSignatureAlgorithm: algorithm,
				SPEntityID:                 "https://soc.example.com/api/v1/auth/federated/saml/acme/corporate_saml/metadata",
				GeneratedAt:                testNow,
			}
			bundle, err := GenerateFederationSAMLSPCredential(request)
			if err != nil || !validGeneratedFederationSAMLSPCredential(bundle, request) {
				bundle.Destroy()
				t.Fatalf("generated bundle error/valid = %v/%t", err, validGeneratedFederationSAMLSPCredential(bundle, request))
			}
			parsed, parseErr := x509.ParsePKCS8PrivateKey(bundle.PrivateKeyPKCS8)
			if parseErr != nil || !federationSAMLPrivateKeyMatchesAlgorithm(parsed, algorithm) {
				bundle.Destroy()
				t.Fatalf("generated key type = %T, %v", parsed, parseErr)
			}
			keyAlias := bundle.PrivateKeyPKCS8
			certificateAlias := bundle.CertificateDER[0]
			bundle.Destroy()
			if !federationSAMLAllZero(keyAlias) || !federationSAMLAllZero(certificateAlias) {
				t.Fatal("generated plaintext was not destroyed")
			}
		})
	}
}

type federationSAMLAdministrationRepositoryStub struct {
	prepareMetadata   func(context.Context, FederationPrepareSAMLMetadataParams) (FederationSAMLMetadataPreparation, error)
	replaceMetadata   func(context.Context, FederationReplaceSAMLMetadataParams) (FederationSAMLMaterialMutationReceipt, error)
	prepareCredential func(context.Context, FederationPrepareSAMLSPCredentialParams) (FederationSAMLSPCredentialPreparation, error)
	replaceCredential func(context.Context, FederationReplaceSAMLSPCredentialParams) (FederationSAMLMaterialMutationReceipt, error)
	clearCredential   func(context.Context, FederationClearSAMLSPCredentialParams) (FederationSAMLMaterialMutationReceipt, error)
	metadataWrites    int
	credentialWrites  int
	credentialClears  int
}

func (stub *federationSAMLAdministrationRepositoryStub) PrepareSAMLMetadataReplacement(ctx context.Context, params FederationPrepareSAMLMetadataParams) (FederationSAMLMetadataPreparation, error) {
	return stub.prepareMetadata(ctx, params)
}

func (stub *federationSAMLAdministrationRepositoryStub) ReplaceSAMLMetadata(ctx context.Context, params FederationReplaceSAMLMetadataParams) (FederationSAMLMaterialMutationReceipt, error) {
	stub.metadataWrites++
	return stub.replaceMetadata(ctx, params)
}

func (stub *federationSAMLAdministrationRepositoryStub) PrepareSAMLSPCredentialMutation(ctx context.Context, params FederationPrepareSAMLSPCredentialParams) (FederationSAMLSPCredentialPreparation, error) {
	return stub.prepareCredential(ctx, params)
}

func (stub *federationSAMLAdministrationRepositoryStub) ReplaceSAMLSPCredential(ctx context.Context, params FederationReplaceSAMLSPCredentialParams) (FederationSAMLMaterialMutationReceipt, error) {
	stub.credentialWrites++
	return stub.replaceCredential(ctx, params)
}

func (stub *federationSAMLAdministrationRepositoryStub) ClearSAMLSPCredential(ctx context.Context, params FederationClearSAMLSPCredentialParams) (FederationSAMLMaterialMutationReceipt, error) {
	stub.credentialClears++
	return stub.clearCredential(ctx, params)
}

type federationSAMLMetadataRetrieverStub struct {
	document     []byte
	retrievedAt  time.Time
	err          error
	location     string
	maximumBytes int
	calls        int
}

func (stub *federationSAMLMetadataRetrieverStub) RetrieveTenantSAMLMetadata(_ context.Context, location string, maximumBytes int) ([]byte, time.Time, error) {
	stub.calls++
	stub.location = location
	stub.maximumBytes = maximumBytes
	return append([]byte(nil), stub.document...), stub.retrievedAt, stub.err
}

func testFederationSAMLService(
	t *testing.T,
	repository FederationSAMLAdministrationRepository,
	retriever FederationSAMLMetadataRetriever,
	generator FederationSAMLSPCredentialGenerator,
	validator FederationSAMLSPCredentialValidator,
) *FederationService {
	t.Helper()
	return testFederationSAMLServiceWithKeyring(t, repository, retriever, generator, validator, testIdentityKeyring(t))
}

func testFederationSAMLServiceWithKeyring(
	t *testing.T,
	repository FederationSAMLAdministrationRepository,
	retriever FederationSAMLMetadataRetriever,
	generator FederationSAMLSPCredentialGenerator,
	validator FederationSAMLSPCredentialValidator,
	keyring identity.Keyring,
) *FederationService {
	t.Helper()
	authority := &federationAdministrationRepositoryStub{}
	authority.resolve = func(context.Context, authorization.ResolveAuthorityParams) (authorization.TenantAuthority, error) {
		return testIdentityProviderAuthority(authorization.TenantPermissionIdentityProviderManage), nil
	}
	service := testFederationServiceWithKeyring(t, authority, nil, keyring)
	if retriever == nil {
		retriever = &federationSAMLMetadataRetrieverStub{}
	}
	if err := service.ConfigureFederationSAMLAdministration(repository, FederationSAMLAdministrationOptions{
		MetadataRetriever: retriever, GenerateSPKey: generator, ValidateSPKey: validator,
	}); err != nil {
		t.Fatalf("ConfigureFederationSAMLAdministration() error = %v", err)
	}
	return service
}

func validFederationSAMLSPCredentialPreparationForTest(providerEnabled, bindingEnabled bool) FederationSAMLSPCredentialPreparation {
	return FederationSAMLSPCredentialPreparation{
		TenantID: testTenantID, ProviderID: testProviderID, BindingID: testFederationBindingID,
		ProviderVersion: 3, CurrentCredentialRevision: 1,
		ProviderEnabled: providerEnabled, BindingEnabled: bindingEnabled,
		SPEntityID:                 "https://soc.example.com/api/v1/auth/federated/saml/acme/corporate_saml/metadata",
		RedirectSignatureAlgorithm: federatedsaml.RedirectECDSASHA256,
	}
}

func mustFederationSAMLGeneratedBundle(
	t *testing.T,
	algorithm federatedsaml.RedirectSignatureAlgorithm,
	spEntityID string,
) FederationSAMLSPCredentialBundle {
	t.Helper()
	bundle, err := GenerateFederationSAMLSPCredential(FederationSAMLSPCredentialGenerationRequest{
		RedirectSignatureAlgorithm: algorithm, SPEntityID: spEntityID, GeneratedAt: testNow,
	})
	if err != nil {
		t.Fatalf("GenerateFederationSAMLSPCredential() error = %v", err)
	}
	return bundle
}

func federationSAMLMetadataDocument(now time.Time, certificate []byte, entityID, ssoURL string) []byte {
	return federationSAMLMetadataDocumentWithValidUntil(now.Add(24*time.Hour), certificate, entityID, ssoURL)
}

func federationSAMLMetadataDocumentWithValidUntil(validUntil time.Time, certificate []byte, entityID, ssoURL string) []byte {
	return []byte(fmt.Sprintf(
		`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="%s" validUntil="%s"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="true"><md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s"/></md:IDPSSODescriptor></md:EntityDescriptor>`,
		entityID, validUntil.Format(time.RFC3339), base64.StdEncoding.EncodeToString(certificate), ssoURL,
	))
}

func federationSAMLAllZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
