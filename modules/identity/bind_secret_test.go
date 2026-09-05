package identity

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestBindSecretRoundTripAndHistoricalDecryption(t *testing.T) {
	t.Parallel()

	roots := map[int16][]byte{
		1: bytes.Repeat([]byte{0x51}, sourceKeyBytes),
		2: bytes.Repeat([]byte{0x52}, sourceKeyBytes),
	}
	nonce := bytes.Repeat([]byte{0xA5}, bindSecretNonceBytes)
	oldKeyring, err := newKeyring(1, roots, bytes.NewReader(nonce))
	if err != nil {
		t.Fatalf("newKeyring() error = %v", err)
	}
	context := tenantBindSecretContext(1)
	secret := []byte("correct horse battery staple")
	envelope, err := oldKeyring.EncryptBindSecret(context, secret)
	if err != nil {
		t.Fatalf("EncryptBindSecret() error = %v", err)
	}
	if envelope.KeyVersion != 1 || !bytes.Equal(envelope.Nonce[:], nonce) {
		t.Fatalf("envelope = version %d nonce %x", envelope.KeyVersion, envelope.Nonce)
	}
	if bytes.Contains(envelope.Ciphertext, secret) || len(envelope.Ciphertext) != len(secret)+bindSecretTagBytes {
		t.Fatalf("ciphertext shape is invalid: %d bytes", len(envelope.Ciphertext))
	}
	if got := hex.EncodeToString(envelope.Ciphertext); got != "105668df94dad4187d1893810164eae5425e5a8265411732eeb0fd5bbcbebb3a5d29ad46b3b703067e8f72ae" {
		t.Fatalf("bind-secret ciphertext vector = %s", got)
	}

	newKeyring := mustKeyring(t, 2, roots)
	plaintext, err := newKeyring.DecryptBindSecret(context, envelope)
	if err != nil {
		t.Fatalf("DecryptBindSecret() error = %v", err)
	}
	if !bytes.Equal(plaintext, secret) {
		t.Fatalf("plaintext = %q", plaintext)
	}
	clear(plaintext)
	plaintextAgain, err := newKeyring.DecryptBindSecret(context, envelope)
	if err != nil || !bytes.Equal(plaintextAgain, secret) {
		t.Fatalf("second decryption = %q, %v", plaintextAgain, err)
	}
	clear(plaintextAgain)
}

func TestBindSecretRejectsTamperingAndCrossContextSwaps(t *testing.T) {
	t.Parallel()

	roots := map[int16][]byte{
		1: bytes.Repeat([]byte{0x61}, sourceKeyBytes),
		2: bytes.Repeat([]byte{0x62}, sourceKeyBytes),
	}
	keyring, err := newKeyring(1, roots, bytes.NewReader(bytes.Repeat([]byte{0xB5}, bindSecretNonceBytes)))
	if err != nil {
		t.Fatalf("newKeyring() error = %v", err)
	}
	context := tenantBindSecretContext(10)
	envelope, err := keyring.EncryptBindSecret(context, []byte("bind-password"))
	if err != nil {
		t.Fatalf("EncryptBindSecret() error = %v", err)
	}

	changedTenant := context
	changedTenant.Provider.TenantID = testID(11)
	changedProvider := context
	changedProvider.Provider.ProviderID = testID(12)
	changedRow := context
	changedRow.SecretID = testID(13)
	platformContext := context
	platformContext.Provider.Scope = PlatformProviderScope
	platformContext.Provider.TenantID = EntityID{}

	for _, test := range []struct {
		name     string
		context  BindSecretContext
		envelope BindSecretEnvelope
	}{
		{name: "tenant", context: changedTenant, envelope: cloneEnvelope(envelope)},
		{name: "provider", context: changedProvider, envelope: cloneEnvelope(envelope)},
		{name: "row", context: changedRow, envelope: cloneEnvelope(envelope)},
		{name: "scope", context: platformContext, envelope: cloneEnvelope(envelope)},
		{name: "invalid context", context: BindSecretContext{}, envelope: cloneEnvelope(envelope)},
		{name: "key version", context: context, envelope: mutateEnvelope(envelope, func(value *BindSecretEnvelope) { value.KeyVersion = 2 })},
		{name: "unknown key version", context: context, envelope: mutateEnvelope(envelope, func(value *BindSecretEnvelope) { value.KeyVersion = 99 })},
		{name: "nonce", context: context, envelope: mutateEnvelope(envelope, func(value *BindSecretEnvelope) { value.Nonce[0] ^= 1 })},
		{name: "ciphertext", context: context, envelope: mutateEnvelope(envelope, func(value *BindSecretEnvelope) { value.Ciphertext[0] ^= 1 })},
		{name: "tag", context: context, envelope: mutateEnvelope(envelope, func(value *BindSecretEnvelope) { value.Ciphertext[len(value.Ciphertext)-1] ^= 1 })},
		{name: "empty ciphertext", context: context, envelope: BindSecretEnvelope{KeyVersion: 1}},
		{name: "tag-only ciphertext", context: context, envelope: BindSecretEnvelope{KeyVersion: 1, Ciphertext: make([]byte, 16)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			plaintext, decryptErr := keyring.DecryptBindSecret(test.context, test.envelope)
			clear(plaintext)
			if !errors.Is(decryptErr, ErrInvalidEncryptedBindSecret) {
				t.Fatalf("DecryptBindSecret() error = %v", decryptErr)
			}
		})
	}
}

func TestEncryptBindSecretValidatesInputsAndRandomSource(t *testing.T) {
	t.Parallel()

	root := map[int16][]byte{1: bytes.Repeat([]byte{0x71}, sourceKeyBytes)}
	keyring := mustKeyring(t, 1, root)
	validContext := tenantBindSecretContext(20)
	for _, test := range []struct {
		name    string
		context BindSecretContext
		secret  []byte
	}{
		{name: "missing context", secret: []byte("secret")},
		{name: "missing secret", context: validContext},
		{name: "oversized secret", context: validContext, secret: make([]byte, maximumBindSecretBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := keyring.EncryptBindSecret(test.context, test.secret); err == nil {
				t.Fatal("EncryptBindSecret() unexpectedly succeeded")
			}
		})
	}
	failingKeyring, err := newKeyring(1, root, failingReader{})
	if err != nil {
		t.Fatalf("newKeyring() error = %v", err)
	}
	if _, err := failingKeyring.EncryptBindSecret(validContext, []byte("secret")); err == nil {
		t.Fatal("EncryptBindSecret() accepted a failing random source")
	}
	if _, err := (Keyring{}).EncryptBindSecret(validContext, []byte("secret")); !errors.Is(err, ErrInvalidKeyring) {
		t.Fatalf("zero keyring encryption error = %v", err)
	}
	maximumEnvelope, err := keyring.EncryptBindSecret(validContext, make([]byte, maximumBindSecretBytes))
	if err != nil {
		t.Fatalf("maximum-size EncryptBindSecret() error = %v", err)
	}
	if len(maximumEnvelope.Ciphertext) != maximumBindSecretCiphertextBytes {
		t.Fatalf("maximum ciphertext length = %d", len(maximumEnvelope.Ciphertext))
	}
	minimumEnvelope, err := keyring.EncryptBindSecret(validContext, []byte{1})
	if err != nil {
		t.Fatalf("minimum-size EncryptBindSecret() error = %v", err)
	}
	if len(minimumEnvelope.Ciphertext) != bindSecretTagBytes+1 {
		t.Fatalf("minimum ciphertext length = %d", len(minimumEnvelope.Ciphertext))
	}
}

func tenantBindSecretContext(seed byte) BindSecretContext {
	return BindSecretContext{
		Provider: ProviderContext{
			Scope:      TenantProviderScope,
			TenantID:   testID(seed),
			ProviderID: testID(seed + 1),
		},
		SecretID: testID(seed + 2),
	}
}

func testID(seed byte) EntityID {
	var id EntityID
	for index := range id {
		id[index] = seed + byte(index)
	}
	return id
}

func cloneEnvelope(source BindSecretEnvelope) BindSecretEnvelope {
	copy := source
	copy.Ciphertext = append([]byte(nil), source.Ciphertext...)
	return copy
}

func mutateEnvelope(source BindSecretEnvelope, mutate func(*BindSecretEnvelope)) BindSecretEnvelope {
	copy := cloneEnvelope(source)
	mutate(&copy)
	return copy
}
