package notification

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestNotificationSecretKeyringRoundTripAndContextBinding(t *testing.T) {
	root := make([]byte, notificationRootKeyBytes)
	for index := range root {
		root[index] = byte(index)
	}
	keyring, err := newKeyring(7, map[int16][]byte{7: root}, bytes.NewReader(bytes.Repeat([]byte{0x42}, notificationNonceBytes)))
	if err != nil {
		t.Fatalf("newKeyring() error = %v", err)
	}
	tenantID := uuid.MustParse("019c9878-1111-7222-8333-444455556666")
	context := SecretContext{
		TenantID: &tenantID, SecretID: uuid.MustParse("019c9878-7777-7888-8999-aaaabbbbcccc"),
		SecretVersion: 3, Kind: SecretKindSMTPPassword,
	}
	plaintext := []byte("cross-runtime-secret")
	envelope, err := keyring.Protect(context, plaintext)
	if err != nil {
		t.Fatalf("Protect() error = %v", err)
	}
	if envelope.KeyVersion != 7 || hex.EncodeToString(envelope.Nonce) != "424242424242424242424242" {
		t.Fatalf("unexpected envelope metadata: %#v", envelope)
	}
	const expectedCiphertext = "e2207ed000a94fd98bbdf8e678c2478a4689fb0ab9325a373220405d1f9a70d7a2fef0ce"
	if encoded := hex.EncodeToString(envelope.Ciphertext); encoded != expectedCiphertext {
		t.Fatalf("ciphertext = %s", encoded)
	}
	if bytes.Contains(envelope.Ciphertext, plaintext) {
		t.Fatal("ciphertext contains plaintext")
	}
	decrypted, err := keyring.Unprotect(context, envelope)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Unprotect() = %q, %v", decrypted, err)
	}
	clear(decrypted)

	wrongTenant := uuid.MustParse("019c9878-1111-7222-8333-444455556667")
	mutations := []SecretContext{
		{TenantID: &wrongTenant, SecretID: context.SecretID, SecretVersion: 3, Kind: context.Kind},
		{TenantID: context.TenantID, SecretID: uuid.MustParse("019c9878-7777-7888-8999-aaaabbbbcccd"), SecretVersion: 3, Kind: context.Kind},
		{TenantID: context.TenantID, SecretID: context.SecretID, SecretVersion: 4, Kind: context.Kind},
		{TenantID: context.TenantID, SecretID: context.SecretID, SecretVersion: 3, Kind: SecretKindWebhookSigningKey},
		{TenantID: nil, SecretID: context.SecretID, SecretVersion: 3, Kind: context.Kind},
	}
	for _, candidate := range mutations {
		if value, decryptErr := keyring.Unprotect(candidate, envelope); !errors.Is(decryptErr, ErrInvalidSecret) {
			clear(value)
			t.Fatalf("context substitution accepted: %#v", candidate)
		}
	}

	tampered := cloneSecretEnvelope(envelope)
	tampered.Ciphertext[0] ^= 1
	if value, decryptErr := keyring.Unprotect(context, tampered); !errors.Is(decryptErr, ErrInvalidSecret) {
		clear(value)
		t.Fatal("tampered ciphertext accepted")
	}
	clear(envelope.Ciphertext)
	clear(tampered.Ciphertext)
}

func TestParseNotificationKeyringDocumentIsClosedAndRedacted(t *testing.T) {
	root := bytes.Repeat([]byte{0x7a}, notificationRootKeyBytes)
	document := []byte(fmt.Sprintf(
		`{"activeVersion":2,"keys":[{"version":2,"key":%q}]}`,
		base64.RawURLEncoding.EncodeToString(root),
	))
	keyring, err := ParseKeyringDocument(document)
	if err != nil {
		t.Fatalf("ParseKeyringDocument() error = %v", err)
	}
	if keyring.ActiveVersion() != 2 || !slices.Equal(keyring.Versions(), []int16{2}) {
		t.Fatalf("unexpected keyring metadata: %s", keyring)
	}
	formatted := fmt.Sprintf("%v %#v", keyring, keyring)
	if strings.Contains(formatted, base64.RawURLEncoding.EncodeToString(root)) || strings.Contains(formatted, "7a7a") {
		t.Fatalf("keyring formatting exposed material: %s", formatted)
	}

	for _, invalid := range []string{
		`{}`,
		`{"activeVersion":2,"keys":[]}`,
		`{"activeVersion":2,"keys":[{"version":2,"key":"bad"}]}`,
		fmt.Sprintf(`{"activeVersion":2,"keys":[{"version":2,"key":%q},{"version":2,"key":%q}]}`, base64.RawURLEncoding.EncodeToString(root), base64.RawURLEncoding.EncodeToString(root)),
		string(document) + `{}`,
		fmt.Sprintf(`{"activeVersion":2,"keys":[{"version":2,"key":%q}],"extra":true}`, base64.RawURLEncoding.EncodeToString(root)),
		fmt.Sprintf(`{"activeVersion":1,"activeVersion":2,"keys":[{"version":2,"key":%q}]}`, base64.RawURLEncoding.EncodeToString(root)),
		fmt.Sprintf(`{"activeVersion":2,"keys":[{"version":1,"version":2,"key":%q}]}`, base64.RawURLEncoding.EncodeToString(root)),
	} {
		if _, parseErr := ParseKeyringDocument([]byte(invalid)); !errors.Is(parseErr, ErrInvalidKeyring) {
			t.Fatalf("invalid document accepted: %s", invalid)
		}
	}
}

func TestNotificationKeyringCloseInvalidatesEveryCopy(t *testing.T) {
	keyring, err := NewKeyring(1, map[int16][]byte{1: bytes.Repeat([]byte{1}, notificationRootKeyBytes)})
	if err != nil {
		t.Fatal(err)
	}
	copyOfKeyring := keyring
	keyring.Close()
	keyring.Close()
	if keyring.ActiveVersion() != 0 || len(keyring.Versions()) != 0 || len(copyOfKeyring.Versions()) != 0 {
		t.Fatalf("closed keyring retained metadata: original=%s copy=%s", keyring, copyOfKeyring)
	}
	context := SecretContext{SecretID: uuid.Must(uuid.NewV7()), SecretVersion: 1, Kind: SecretKindWebhookSigningKey}
	if _, err := copyOfKeyring.Protect(context, []byte("value")); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("copied keyring remained usable after close: %v", err)
	}
}

func TestNotificationSecretBoundsFailClosed(t *testing.T) {
	keyring, err := NewKeyring(1, map[int16][]byte{1: bytes.Repeat([]byte{1}, notificationRootKeyBytes)})
	if err != nil {
		t.Fatal(err)
	}
	context := SecretContext{SecretID: uuid.Must(uuid.NewV7()), SecretVersion: 1, Kind: SecretKindWebhookSigningKey}
	for _, plaintext := range [][]byte{nil, make([]byte, maximumNotificationSecret+1)} {
		if _, protectErr := keyring.Protect(context, plaintext); !errors.Is(protectErr, ErrInvalidSecret) {
			t.Fatal("invalid secret length accepted")
		}
	}
	if _, err := keyring.Protect(SecretContext{}, []byte("value")); !errors.Is(err, ErrInvalidSecret) {
		t.Fatal("invalid context accepted")
	}
}

func cloneSecretEnvelope(value SecretEnvelope) SecretEnvelope {
	return SecretEnvelope{
		KeyVersion: value.KeyVersion,
		Nonce:      append([]byte(nil), value.Nonce...), Ciphertext: append([]byte(nil), value.Ciphertext...),
	}
}
