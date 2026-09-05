package identity

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestExternalSubjectRoundTripAcrossRetainedKeyVersions(t *testing.T) {
	rootOne := bytes.Repeat([]byte{0x31}, sourceKeyBytes)
	rootTwo := bytes.Repeat([]byte{0x32}, sourceKeyBytes)
	writer := mustKeyring(t, 1, map[int16][]byte{1: rootOne})
	writer.random = bytes.NewReader(bytes.Repeat([]byte{0x41}, externalSubjectNonceBytes))
	context := testExternalSubjectContext(0x51)
	subject, _ := CanonicalUTF8CaseFold([]byte("Straße"))

	envelope, err := writer.EncryptExternalSubject(context, subject)
	if err != nil {
		t.Fatalf("EncryptExternalSubject() error = %v", err)
	}
	if envelope.KeyVersion != 1 || envelope.Format != UTF8CaseFoldSubject ||
		len(envelope.Ciphertext) != len("strasse")+externalSubjectTagBytes {
		t.Fatalf("envelope = %#v", envelope)
	}
	reader := mustKeyring(t, 2, map[int16][]byte{1: rootOne, 2: rootTwo})
	decrypted, err := reader.DecryptExternalSubject(context, envelope)
	if err != nil || decrypted.Format() != UTF8CaseFoldSubject || !bytes.Equal(decrypted.value, subject.value) {
		t.Fatalf("DecryptExternalSubject() = %#v, %v", decrypted, err)
	}
	clear(decrypted.value)
	clear(envelope.Ciphertext)
}

func TestExternalSubjectEncryptionBindsEveryContextAndEnvelopeField(t *testing.T) {
	root := bytes.Repeat([]byte{0x61}, sourceKeyBytes)
	keyring := mustKeyring(t, 1, map[int16][]byte{1: root})
	keyring.random = bytes.NewReader(bytes.Repeat([]byte{0x62}, externalSubjectNonceBytes))
	context := testExternalSubjectContext(0x63)
	subject, _ := CanonicalUTF8Exact([]byte("private-subject"))
	envelope, err := keyring.EncryptExternalSubject(context, subject)
	if err != nil {
		t.Fatalf("EncryptExternalSubject() error = %v", err)
	}

	changedTenant := context
	changedTenant.Provider.TenantID = testID(0x64)
	changedProvider := context
	changedProvider.Provider.ProviderID = testID(0x65)
	changedRow := context
	changedRow.ExternalIdentityID = testID(0x66)
	for name, candidate := range map[string]ExternalSubjectContext{
		"tenant": changedTenant, "provider": changedProvider, "row": changedRow,
	} {
		if _, err := keyring.DecryptExternalSubject(candidate, envelope); !errors.Is(err, ErrInvalidEncryptedExternalSubject) {
			t.Fatalf("changed %s error = %v", name, err)
		}
	}

	wrongFormat := cloneExternalSubjectEnvelope(envelope)
	wrongFormat.Format = UTF8CaseFoldSubject
	wrongVersion := cloneExternalSubjectEnvelope(envelope)
	wrongVersion.KeyVersion = 2
	wrongNonce := cloneExternalSubjectEnvelope(envelope)
	wrongNonce.Nonce[0] ^= 1
	wrongCiphertext := cloneExternalSubjectEnvelope(envelope)
	wrongCiphertext.Ciphertext[0] ^= 1
	for name, candidate := range map[string]ExternalSubjectEnvelope{
		"format": wrongFormat, "version": wrongVersion, "nonce": wrongNonce, "ciphertext": wrongCiphertext,
	} {
		if _, err := keyring.DecryptExternalSubject(context, candidate); !errors.Is(err, ErrInvalidEncryptedExternalSubject) {
			t.Fatalf("changed %s error = %v", name, err)
		}
		clear(candidate.Ciphertext)
	}
	clear(envelope.Ciphertext)
}

func TestExternalSubjectRejectsInvalidInputsAndRandomFailure(t *testing.T) {
	root := bytes.Repeat([]byte{0x71}, sourceKeyBytes)
	keyring := mustKeyring(t, 1, map[int16][]byte{1: root})
	context := testExternalSubjectContext(0x72)
	subject, _ := CanonicalEntryUUID("550e8400-e29b-41d4-a716-446655440000")
	for _, test := range []struct {
		context ExternalSubjectContext
		subject Subject
	}{
		{subject: subject},
		{context: context},
	} {
		if _, err := keyring.EncryptExternalSubject(test.context, test.subject); err == nil {
			t.Fatal("EncryptExternalSubject() accepted an invalid input")
		}
	}
	failing := keyring
	failing.random = failingReader{}
	if _, err := failing.EncryptExternalSubject(context, subject); err == nil {
		t.Fatal("EncryptExternalSubject() accepted nonce generation failure")
	}
	if _, err := (Keyring{}).DecryptExternalSubject(context, ExternalSubjectEnvelope{}); !errors.Is(err, ErrInvalidEncryptedExternalSubject) {
		t.Fatalf("zero envelope error = %v", err)
	}
}

func TestExternalSubjectFormattingDoesNotExposePlaintext(t *testing.T) {
	subject, _ := CanonicalUTF8Exact([]byte("private-directory-identifier"))
	formatted := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x", subject, subject, subject, subject, subject, subject)
	if strings.Contains(formatted, "private-directory-identifier") {
		t.Fatalf("formatted subject exposed plaintext: %s", formatted)
	}
}

func testExternalSubjectContext(seed byte) ExternalSubjectContext {
	return ExternalSubjectContext{
		Provider: ProviderContext{
			Scope: TenantProviderScope, TenantID: testID(seed), ProviderID: testID(seed + 1),
		},
		ExternalIdentityID: testID(seed + 2),
	}
}

func cloneExternalSubjectEnvelope(value ExternalSubjectEnvelope) ExternalSubjectEnvelope {
	value.Ciphertext = append([]byte(nil), value.Ciphertext...)
	return value
}
