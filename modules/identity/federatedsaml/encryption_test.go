package federatedsaml

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestEncryptedAssertionUsesPinnedModernAlgorithms(t *testing.T) {
	fixture := newTestFixture(t)
	fixture.config.EncryptionPolicy = EncryptionRequired
	fixture.config.DecryptionKeyVersions = []uint32{11}
	restartFixture(t, &fixture)
	fixture.decrypter.assertion = validAssertionDocument(fixture, true)
	document := responseDocument(fixture, true, encryptedAssertionEnvelope(aes128GCM, rsaOAEP11, digestSHA256, mgf1SHA256))
	validated, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, document))
	if err != nil {
		t.Fatalf("ValidateCallback() error = %v", err)
	}
	if fixture.decrypter.calls != 1 || validated.JIT().SubjectValue() != "subject-secret-value" {
		t.Fatalf("decrypter calls=%d JIT=%v", fixture.decrypter.calls, validated.JIT())
	}
}

func TestEncryptedAssertionRejectsLegacyOrUnboundAlgorithms(t *testing.T) {
	externalReference := strings.Replace(string(encryptedAssertionEnvelope(aes128GCM, rsaOAEP11, digestSHA256, mgf1SHA256)),
		`<xenc:CipherValue>`+base64.StdEncoding.EncodeToString([]byte("encrypted-assertion-material"))+`</xenc:CipherValue>`,
		`<xenc:CipherReference URI="https://attacker.test/SECRET"/>`, 1)
	tests := map[string][]byte{
		"CBC content":               encryptedAssertionEnvelope("http://www.w3.org/2001/04/xmlenc#aes256-cbc", rsaOAEP11, digestSHA256, mgf1SHA256),
		"unproved AES-256 GCM":      encryptedAssertionEnvelope(aes256GCM, rsaOAEP11, digestSHA256, mgf1SHA256),
		"RSA v1.5":                  encryptedAssertionEnvelope(aes128GCM, "http://www.w3.org/2001/04/xmlenc#rsa-1_5", digestSHA256, mgf1SHA256),
		"SHA-1":                     encryptedAssertionEnvelope(aes128GCM, rsaOAEP11, "http://www.w3.org/2000/09/xmldsig#sha1", mgf1SHA256),
		"mismatched MGF":            encryptedAssertionEnvelope(aes128GCM, rsaOAEP11, digestSHA256, mgf1SHA512),
		"external cipher reference": []byte(externalReference),
	}
	for name, envelope := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newTestFixture(t)
			fixture.config.EncryptionPolicy = EncryptionRequired
			fixture.config.DecryptionKeyVersions = []uint32{11}
			restartFixture(t, &fixture)
			fixture.decrypter.assertion = validAssertionDocument(fixture, true)
			document := responseDocument(fixture, true, envelope)
			if _, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, document)); err == nil {
				t.Fatal("ValidateCallback() unexpectedly succeeded")
			}
			if fixture.decrypter.calls != 0 {
				t.Fatalf("legacy envelope reached private-key port: calls=%d", fixture.decrypter.calls)
			}
		})
	}

	fixture := newTestFixture(t)
	fixture.config.EncryptionPolicy = EncryptionRequired
	fixture.config.DecryptionKeyVersions = []uint32{11}
	restartFixture(t, &fixture)
	fixture.decrypter.assertion = validAssertionDocument(fixture, true)
	fixture.decrypter.mutate = func(result *DecryptionResult) { result.EncryptedObjectID = "_other" }
	document := responseDocument(fixture, true, encryptedAssertionEnvelope(aes128GCM, rsaOAEP11, digestSHA256, mgf1SHA256))
	if _, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, document)); !errors.Is(err, ErrEncryptionRejected) {
		t.Fatalf("unbound decryption proof error = %v", err)
	}

	fixture = newTestFixture(t)
	fixture.config.EncryptionPolicy = EncryptionRequired
	fixture.config.DecryptionKeyVersions = []uint32{11}
	restartFixture(t, &fixture)
	fixture.decrypter.assertion = []byte(strings.Replace(string(validAssertionDocument(fixture, true)), `_assertion`, `_response`, 1))
	document = responseDocument(fixture, true, encryptedAssertionEnvelope(aes128GCM, rsaOAEP11, digestSHA256, mgf1SHA256))
	if _, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, document)); !errors.Is(err, ErrAssertionRejected) {
		t.Fatalf("cross-document duplicate ID error = %v", err)
	}
}

func TestSignedResponseIsVerifiedBeforeDecryption(t *testing.T) {
	fixture := newTestFixture(t)
	fixture.config.EncryptionPolicy = EncryptionRequired
	fixture.config.DecryptionKeyVersions = []uint32{11}
	restartFixture(t, &fixture)
	fixture.decrypter.assertion = validAssertionDocument(fixture, true)
	fixture.verifier.mutate = func(proof *SignatureVerificationResult) { proof.ReferenceURI = "#_attacker" }
	document := responseDocument(fixture, true, encryptedAssertionEnvelope(aes128GCM, rsaOAEP11, digestSHA256, mgf1SHA256))
	if _, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, document)); !errors.Is(err, ErrSignatureRejected) {
		t.Fatalf("ValidateCallback() error = %v", err)
	}
	if fixture.decrypter.calls != 0 {
		t.Fatalf("decryption happened before response signature verification: %d", fixture.decrypter.calls)
	}
}

func TestEncryptionPolicyIsExact(t *testing.T) {
	fixture := newTestFixture(t)
	fixture.config.EncryptionPolicy = EncryptionRequired
	fixture.config.DecryptionKeyVersions = []uint32{11}
	restartFixture(t, &fixture)
	if _, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, validResponseDocument(fixture))); !errors.Is(err, ErrEncryptionRejected) {
		t.Fatalf("required/plaintext error = %v", err)
	}

	fixture = newTestFixture(t)
	document := responseDocument(fixture, true, encryptedAssertionEnvelope(aes128GCM, rsaOAEP11, digestSHA256, mgf1SHA256))
	if _, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, document)); !errors.Is(err, ErrEncryptionRejected) {
		t.Fatalf("disabled/encrypted error = %v", err)
	}

	fixture = newTestFixture(t)
	fixture.config.EncryptionPolicy = EncryptionOptional
	fixture.config.DecryptionKeyVersions = []uint32{11}
	restartFixture(t, &fixture)
	if _, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, validResponseDocument(fixture))); err != nil {
		t.Fatalf("optional/plaintext error = %v", err)
	}
	fixture.decrypter.assertion = validAssertionDocument(fixture, true)
	document = responseDocument(fixture, true, encryptedAssertionEnvelope(aes128GCM, rsaOAEP11, digestSHA256, mgf1SHA256))
	if _, err := fixture.kernel.ValidateCallback(context.Background(), callbackRequest(fixture, document)); err != nil {
		t.Fatalf("optional/encrypted error = %v", err)
	}
}

func encryptedAssertionEnvelope(content, transport, digest, mgf string) []byte {
	keyCipher := base64.StdEncoding.EncodeToString([]byte("encrypted-key-material"))
	dataCipher := base64.StdEncoding.EncodeToString([]byte("encrypted-assertion-material"))
	return []byte(fmt.Sprintf(`<saml:EncryptedAssertion xmlns:xenc="%s" xmlns:xenc11="%s"><xenc:EncryptedData Id="_encrypted-data" Type="%sElement"><xenc:EncryptionMethod Algorithm="%s"/><ds:KeyInfo><xenc:EncryptedKey Id="_encrypted-key"><xenc:EncryptionMethod Algorithm="%s"><ds:DigestMethod Algorithm="%s"/><xenc11:MGF Algorithm="%s"/></xenc:EncryptionMethod><xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>%s</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>`,
		xmlEncryptionNamespace, xmlEncryption11NS, xmlEncryptionNamespace, content, transport, digest, mgf, keyCipher, dataCipher))
}

func restartFixture(t *testing.T, fixture *testFixture) {
	t.Helper()
	start, err := fixture.kernel.StartAuthentication(context.Background(), StartRequest{Begin: testAuthenticationBegin(2), Configuration: fixture.config, ReturnPath: "/incidents?view=mine"})
	if err != nil {
		t.Fatalf("restart authentication: %v", err)
	}
	parsed, err := url.Parse(start.RedirectURL())
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	fixture.start = start
	fixture.relay = parsed.Query().Get("RelayState")
	if strings.TrimSpace(fixture.relay) == "" {
		t.Fatal("restart redirect has no relay state")
	}
}
