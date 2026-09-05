package platformsamladapter

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

func TestBuildTenantSAMLMetadataIsExactProviderQualifiedAndCertificateOnly(t *testing.T) {
	projection := tenantSAMLMetadataProjectionFixture(t)
	first, err := BuildTenantSAMLMetadata(projection)
	if err != nil {
		t.Fatalf("BuildTenantSAMLMetadata() error = %v", err)
	}
	second, err := BuildTenantSAMLMetadata(projection)
	if err != nil || !bytes.Equal(first.Document, second.Document) || first.Digest != second.Digest {
		t.Fatalf("metadata is not deterministic: %v", err)
	}
	document := string(first.Document)
	if first.ContentType != SAMLMetadataContentType ||
		!strings.Contains(document, `entityID="https://soc.example.com/api/v1/auth/federated/saml/acme/corporate_saml/metadata"`) ||
		!strings.Contains(document, `Location="https://soc.example.com/api/v1/auth/federated/saml/acs"`) ||
		!strings.Contains(document, `<md:KeyDescriptor use="signing">`) ||
		strings.Contains(document, `<md:KeyDescriptor use="encryption">`) ||
		strings.Contains(document, "PRIVATE KEY") || strings.Contains(document, "ciphertext") {
		t.Fatalf("unsafe or incomplete metadata = %s", document)
	}
}

func TestBuildTenantSAMLMetadataRejectsLocatorLifecycleAndCertificateSubstitution(t *testing.T) {
	base := tenantSAMLMetadataProjectionFixture(t)
	tests := []struct {
		name   string
		mutate func(*TenantSAMLMetadataProjection)
	}{
		{"tenant locator", func(value *TenantSAMLMetadataProjection) { value.TenantSlug = "other" }},
		{"login locator", func(value *TenantSAMLMetadataProjection) { value.LoginKey = "other_saml" }},
		{"disabled provider", func(value *TenantSAMLMetadataProjection) { value.ProviderEnabled = false }},
		{"disabled binding", func(value *TenantSAMLMetadataProjection) { value.BindingEnabled = false }},
		{"disabled policy", func(value *TenantSAMLMetadataProjection) { value.PolicyEnabled = false }},
		{"inactive tenant", func(value *TenantSAMLMetadataProjection) { value.TenantActive = false }},
		{"archived provider", func(value *TenantSAMLMetadataProjection) { value.ProviderArchived = true }},
		{"archived binding", func(value *TenantSAMLMetadataProjection) { value.BindingArchived = true }},
		{"closed epoch", func(value *TenantSAMLMetadataProjection) { value.AccessEpochLive = false }},
		{"wrong tenant certificate", func(value *TenantSAMLMetadataProjection) {
			value.Certificates[0].Context.Provider.TenantID = testEntity(91)
		}},
		{"wrong key revision", func(value *TenantSAMLMetadataProjection) {
			value.Certificates[0].Context.KeyRevision++
		}},
		{"sequence gap", func(value *TenantSAMLMetadataProjection) {
			value.Certificates[0].CertificateSequence = 1
		}},
		{"expired certificate", func(value *TenantSAMLMetadataProjection) {
			value.ObservedAt = value.ObservedAt.Add(48 * time.Hour)
		}},
		{"duplicate certificate digest", func(value *TenantSAMLMetadataProjection) {
			duplicate := value.Certificates[0]
			duplicate.CertificateSequence = 1
			duplicate.CertificateDER = append([]byte(nil), duplicate.CertificateDER...)
			value.Certificates = append(value.Certificates, duplicate)
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			projection := base
			projection.Certificates = append([]TenantSAMLPublicCertificate(nil), base.Certificates...)
			test.mutate(&projection)
			if _, err := BuildTenantSAMLMetadata(projection); err == nil {
				t.Fatal("substituted tenant metadata projection was accepted")
			}
		})
	}
}

func tenantSAMLMetadataProjectionFixture(t *testing.T) TenantSAMLMetadataProjection {
	t.Helper()
	now := testInstant()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(93), Subject: pkix.Name{CommonName: "tenant-saml-metadata"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}, &x509.Certificate{
		SerialNumber: big.NewInt(93), Subject: pkix.Name{CommonName: "tenant-saml-metadata"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	tenantID, providerID, bindingID, keyID := testEntity(81), testEntity(82), testEntity(83), testEntity(84)
	return TenantSAMLMetadataProjection{
		TenantSlug: "acme", LoginKey: "corporate_saml", PublicOrigin: "https://soc.example.com",
		TenantID: tenantID, ProviderID: providerID, BindingID: bindingID,
		ProviderVersion: 4, BindingVersion: 5, ConfigurationRevision: 6,
		SecurityRevision: 7, PlanRevision: 8, AuthorizationRevision: 9,
		SPEntityID: "https://soc.example.com/api/v1/auth/federated/saml/acme/corporate_saml/metadata",
		ACSURL:     "https://soc.example.com/api/v1/auth/federated/saml/acs", SPKeyRevision: 2,
		RedirectSignatureAlgorithm: federatedsaml.RedirectECDSASHA256,
		SignaturePolicy:            federatedsaml.SignedBoth, EncryptionPolicy: federatedsaml.EncryptionDisabled,
		SubjectSource: federatedsaml.SubjectPersistentNameID,
		TenantActive:  true, ProviderEnabled: true, BindingEnabled: true, PolicyEnabled: true,
		AccessEpochLive: true, ObservedAt: now,
		Certificates: []TenantSAMLPublicCertificate{{
			Context: identity.SAMLSPKeyContext{
				Provider:  identity.ProviderContext{Scope: identity.TenantProviderScope, TenantID: tenantID, ProviderID: providerID},
				BindingID: bindingID, KeyID: keyID, KeyRevision: 2,
			},
			CertificateDER: certificate,
		}},
	}
}
