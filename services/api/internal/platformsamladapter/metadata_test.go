package platformsamladapter

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

func testMetadataProjection(
	t *testing.T,
	encryption federatedsaml.EncryptionPolicy,
	decryption []uint64,
) DirectSAMLMetadataProjection {
	t.Helper()
	configuration := testDirectConfiguration(t, encryption, decryption)
	pins := testDirectPins(t, configuration)
	_, certificate := testRSAKeyAndCertificate(t)
	revisions := map[uint64]struct{}{pins.Protocol.SPKeyRevision: {}}
	for _, revision := range decryption {
		revisions[revision] = struct{}{}
	}
	certificates := make([]DirectSAMLPublicCertificate, 0, len(revisions))
	seed := byte(100)
	for revision := range revisions {
		_, encrypt := sliceContainsRevision(decryption, revision)
		certificates = append(certificates, DirectSAMLPublicCertificate{
			Context: identity.DirectPlatformSAMLSPKeyContext{
				Provider: pins.Protocol.Provider, KeyID: testEntity(seed), KeyRevision: revision,
			},
			PlatformLoginRevision: pins.Protocol.PlatformLoginRevision,
			Signing:               revision == pins.Protocol.SPKeyRevision, Encryption: encrypt,
			CertificateDER: append([]byte(nil), certificate...),
		})
		seed++
	}
	return DirectSAMLMetadataProjection{
		ProviderKey: "primary", PublicOrigin: "https://sp.example.test",
		Configuration: platformsamlauth.ConfigurationSnapshot{
			Pins: pins, ProviderKind: platformsamlauth.ProviderKindSAML, Authentication: configuration,
		},
		Certificates: certificates, ObservedAt: testInstant(),
	}
}

func sliceContainsRevision(values []uint64, target uint64) (int, bool) {
	for index, value := range values {
		if value == target {
			return index, true
		}
	}
	return -1, false
}

func TestBuildDirectSAMLMetadataIsDeterministicProviderSpecificAndPublicOnly(t *testing.T) {
	projection := testMetadataProjection(t, federatedsaml.EncryptionDisabled, nil)
	first, err := BuildDirectSAMLMetadata(projection)
	if err != nil {
		t.Fatalf("BuildDirectSAMLMetadata() error = %v", err)
	}
	second, err := BuildDirectSAMLMetadata(projection)
	if err != nil || !bytes.Equal(first.Document, second.Document) || first.Digest != second.Digest ||
		first.Digest != sha256.Sum256(first.Document) {
		t.Fatalf("metadata was not deterministic: error=%v", err)
	}
	document := string(first.Document)
	for _, expected := range []string{
		`entityID="https://sp.example.test/api/v1/auth/platform/saml/primary/metadata"`,
		`Location="https://sp.example.test/api/v1/auth/platform/saml/acs"`,
		`<md:KeyDescriptor use="signing">`, federatedsaml.PersistentNameIDFormat,
	} {
		if !strings.Contains(document, expected) {
			t.Fatalf("metadata does not contain %q", expected)
		}
	}
	if strings.Contains(document, `<md:KeyDescriptor use="encryption">`) ||
		strings.Contains(document, "PRIVATE KEY") || strings.Contains(document, "Ciphertext") ||
		len(first.Document) > maximumDirectSAMLMetadataBytes {
		t.Fatalf("metadata exposes unexpected material or exceeds bound: %d bytes", len(first.Document))
	}
}

func TestBuildDirectSAMLMetadataSupportsOneRevisionForSigningAndEncryption(t *testing.T) {
	projection := testMetadataProjection(t, federatedsaml.EncryptionRequired, []uint64{8})
	if len(projection.Certificates) != 1 || !projection.Certificates[0].Signing || !projection.Certificates[0].Encryption {
		t.Fatalf("combined semantic certificate shape = %#v", projection.Certificates)
	}
	document, err := BuildDirectSAMLMetadata(projection)
	if err != nil {
		t.Fatalf("BuildDirectSAMLMetadata() error = %v", err)
	}
	text := string(document.Document)
	if strings.Count(text, `<md:KeyDescriptor use="signing">`) != 1 ||
		strings.Count(text, `<md:KeyDescriptor use="encryption">`) != 1 ||
		strings.Count(text, `<ds:X509Certificate>`) != 2 {
		t.Fatalf("combined key usage metadata is ambiguous: %s", text)
	}
}

func TestBuildDirectSAMLMetadataPreservesOrderedCertificateBundlePerKey(t *testing.T) {
	projection := testMetadataProjection(t, federatedsaml.EncryptionDisabled, nil)
	key, _ := testRSAKeyAndCertificate(t)
	secondDER := testMetadataCertificateForKey(t, key, 78)
	first := projection.Certificates[0]
	second := first
	second.CertificateSequence = 1
	second.CertificateDER = secondDER

	canonical := projection
	canonical.Certificates = []DirectSAMLPublicCertificate{first, second}
	want, err := BuildDirectSAMLMetadata(canonical)
	if err != nil {
		t.Fatalf("BuildDirectSAMLMetadata(canonical bundle) error = %v", err)
	}
	reordered := projection
	reordered.Certificates = []DirectSAMLPublicCertificate{second, first}
	got, err := BuildDirectSAMLMetadata(reordered)
	if err != nil || !bytes.Equal(got.Document, want.Document) || got.Digest != want.Digest {
		t.Fatalf("ordered certificate bundle was not deterministic: error=%v", err)
	}
	document := string(got.Document)
	firstEncoded := base64.StdEncoding.EncodeToString(first.CertificateDER)
	secondEncoded := base64.StdEncoding.EncodeToString(second.CertificateDER)
	if strings.Count(document, `<md:KeyDescriptor use="signing">`) != 1 ||
		strings.Count(document, `<ds:X509Certificate>`) != 2 ||
		strings.Index(document, firstEncoded) >= strings.Index(document, secondEncoded) {
		t.Fatalf("certificate bundle was not emitted once in sequence order: %s", document)
	}
}

func TestBuildDirectSAMLMetadataRejectsConfigurationAndCertificateSubstitution(t *testing.T) {
	tests := map[string]func(*DirectSAMLMetadataProjection){
		"provider kind": func(value *DirectSAMLMetadataProjection) {
			value.Configuration.ProviderKind = "oidc"
		},
		"configuration encryption policy": func(value *DirectSAMLMetadataProjection) {
			value.Configuration.Authentication.EncryptionPolicy = federatedsaml.EncryptionRequired
			value.Configuration.Authentication.DirectPlatformDecryptionKeyRevisions = []uint64{8}
		},
		"decryption revisions": func(value *DirectSAMLMetadataProjection) {
			value.Configuration.Authentication.DirectPlatformDecryptionKeyRevisions = []uint64{8}
		},
		"entity id": func(value *DirectSAMLMetadataProjection) {
			value.Configuration.Authentication.SPEntityID = "https://sp.example.test/api/v1/auth/platform/saml/other/metadata"
		},
		"acs": func(value *DirectSAMLMetadataProjection) {
			value.Configuration.Authentication.ACSURL = "https://sp.example.test/api/v1/auth/federated/saml/acs"
		},
		"tenant scope": func(value *DirectSAMLMetadataProjection) {
			value.Configuration.Authentication.Provider.Scope = identity.TenantProviderScope
		},
		"semantic revision": func(value *DirectSAMLMetadataProjection) {
			value.Certificates[0].Context.KeyRevision++
		},
		"platform login revision": func(value *DirectSAMLMetadataProjection) {
			value.Certificates[0].PlatformLoginRevision++
		},
		"key id": func(value *DirectSAMLMetadataProjection) {
			value.Certificates[0].Context.KeyID = identity.EntityID{}
		},
		"usage": func(value *DirectSAMLMetadataProjection) {
			value.Certificates[0].Encryption = true
		},
		"unrelated certificate": func(value *DirectSAMLMetadataProjection) {
			value.Certificates = append(value.Certificates, value.Certificates[0])
			value.Certificates[1].Context.KeyRevision = 88
			value.Certificates[1].Context.KeyID = testEntity(111)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			projection := testMetadataProjection(t, federatedsaml.EncryptionDisabled, nil)
			mutate(&projection)
			if _, err := BuildDirectSAMLMetadata(projection); !errorsIsProtocolRejected(err) {
				t.Fatalf("BuildDirectSAMLMetadata() error = %v", err)
			}
		})
	}
}

func errorsIsProtocolRejected(err error) bool { return err == ErrProtocolRejected }

func TestCanonicalPublicOriginRejectsBrowserEquivalentNonCanonicalForms(t *testing.T) {
	for _, valid := range []string{
		"https://sp.example.test",
		"https://sp.example.test:8443",
		"https://192.0.2.1",
		"https://[2001:db8::1]",
		"https://[2001:db8::1]:8443",
	} {
		if canonical, ok := canonicalPublicOrigin(valid); !ok || canonical != valid {
			t.Errorf("canonicalPublicOrigin(%q) = %q, %t", valid, canonical, ok)
		}
	}
	for _, invalid := range []string{
		"http://sp.example.test",
		"https://SP.example.test",
		"https://sp.example.test:443",
		"https://sp.example.test:",
		"https://sp.example.test/",
		"https://sp.example.test.",
		"https://user@sp.example.test",
		"https://127.1",
		"https://192.168.001.001",
		"https://[2001:0db8:0:0:0:0:0:1]",
		"https://[fe80::1%25eth0]",
		"https://sp.example.test:08443",
	} {
		if canonical, ok := canonicalPublicOrigin(invalid); ok {
			t.Errorf("canonicalPublicOrigin(%q) accepted as %q", invalid, canonical)
		}
	}
}

func TestBuildDirectSAMLMetadataRejectsUnboundedOrAmbiguousCertificateSets(t *testing.T) {
	projection := testMetadataProjection(t, federatedsaml.EncryptionDisabled, nil)
	key, _ := testRSAKeyAndCertificate(t)
	for sequence := 1; sequence <= maximumCertificatesPerKey; sequence++ {
		additional := projection.Certificates[0]
		additional.CertificateSequence = uint8(sequence)
		additional.CertificateDER = testMetadataCertificateForKey(t, key, int64(100+sequence))
		projection.Certificates = append(projection.Certificates, additional)
	}
	if _, err := BuildDirectSAMLMetadata(projection); !errorsIsProtocolRejected(err) {
		t.Fatalf("overlong certificate bundle error = %v", err)
	}

	combined := testMetadataProjection(t, federatedsaml.EncryptionRequired, []uint64{8})
	duplicate := combined.Certificates[0]
	duplicate.CertificateSequence = 1
	combined.Certificates = append(combined.Certificates, duplicate)
	if _, err := BuildDirectSAMLMetadata(combined); !errorsIsProtocolRejected(err) {
		t.Fatalf("duplicate certificate in semantic key error = %v", err)
	}

	gap := testMetadataProjection(t, federatedsaml.EncryptionDisabled, nil)
	additional := gap.Certificates[0]
	additional.CertificateSequence = 2
	additional.CertificateDER = testMetadataCertificateForKey(t, key, 200)
	gap.Certificates = append(gap.Certificates, additional)
	if _, err := BuildDirectSAMLMetadata(gap); !errorsIsProtocolRejected(err) {
		t.Fatalf("certificate sequence gap error = %v", err)
	}

	foreignKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate foreign test key: %v", err)
	}
	foreign := testMetadataProjection(t, federatedsaml.EncryptionDisabled, nil)
	additional = foreign.Certificates[0]
	additional.CertificateSequence = 1
	additional.CertificateDER = testMetadataCertificateForKey(t, foreignKey, 201)
	foreign.Certificates = append(foreign.Certificates, additional)
	if _, err := BuildDirectSAMLMetadata(foreign); !errorsIsProtocolRejected(err) {
		t.Fatalf("mixed-public-key certificate bundle error = %v", err)
	}
}

func testMetadataCertificateForKey(t *testing.T, key *rsa.PrivateKey, serial int64) []byte {
	t.Helper()
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "platform-saml-metadata-test"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create metadata test certificate: %v", err)
	}
	return encoded
}
