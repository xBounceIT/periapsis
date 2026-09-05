package identity

import (
	"bytes"
	"errors"
	"testing"
)

func TestSAMLSPKeyRoundTripAndHistoricalDecryption(t *testing.T) {
	t.Parallel()
	roots := map[int16][]byte{
		1: bytes.Repeat([]byte{0x91}, sourceKeyBytes),
		2: bytes.Repeat([]byte{0x92}, sourceKeyBytes),
	}
	nonce := bytes.Repeat([]byte{0xA7}, samlSecretNonceBytes)
	oldKeyring, err := newKeyring(1, roots, bytes.NewReader(nonce))
	if err != nil {
		t.Fatalf("newKeyring() error = %v", err)
	}
	context := testSAMLSPKeyContext()
	plaintext := []byte("pkcs8-private-key-material")
	envelope, err := oldKeyring.EncryptSAMLSPKey(context, plaintext)
	if err != nil {
		t.Fatalf("EncryptSAMLSPKey() error = %v", err)
	}
	if envelope.KeyVersion != 1 || !bytes.Equal(envelope.Nonce[:], nonce) ||
		bytes.Contains(envelope.Ciphertext, plaintext) {
		t.Fatalf("unexpected protected envelope: %s", envelope)
	}

	newKeyring, err := newKeyring(2, roots, bytes.NewReader(bytes.Repeat([]byte{0xB8}, samlSecretNonceBytes)))
	if err != nil {
		t.Fatalf("newKeyring() error = %v", err)
	}
	opened, err := newKeyring.DecryptSAMLSPKey(context, envelope)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("DecryptSAMLSPKey() = %q, %v", opened, err)
	}
	clear(opened)
}

func TestSAMLSPKeyEncryptionBindsEveryContextAndEnvelopeField(t *testing.T) {
	t.Parallel()
	keyring, err := newKeyring(
		1,
		map[int16][]byte{1: bytes.Repeat([]byte{0x82}, sourceKeyBytes)},
		bytes.NewReader(bytes.Repeat([]byte{0x39}, samlSecretNonceBytes)),
	)
	if err != nil {
		t.Fatalf("newKeyring() error = %v", err)
	}
	context := testSAMLSPKeyContext()
	envelope, err := keyring.EncryptSAMLSPKey(context, []byte("secret"))
	if err != nil {
		t.Fatalf("EncryptSAMLSPKey() error = %v", err)
	}

	contexts := []SAMLSPKeyContext{
		{Provider: context.Provider, BindingID: context.BindingID, KeyID: context.KeyID, KeyRevision: context.KeyRevision + 1},
		{Provider: context.Provider, BindingID: context.BindingID, KeyID: EntityID{9}, KeyRevision: context.KeyRevision},
		{Provider: context.Provider, BindingID: EntityID{8}, KeyID: context.KeyID, KeyRevision: context.KeyRevision},
		{Provider: ProviderContext{Scope: TenantProviderScope, TenantID: EntityID{7}, ProviderID: context.Provider.ProviderID}, BindingID: context.BindingID, KeyID: context.KeyID, KeyRevision: context.KeyRevision},
		{Provider: ProviderContext{Scope: TenantProviderScope, TenantID: context.Provider.TenantID, ProviderID: EntityID{6}}, BindingID: context.BindingID, KeyID: context.KeyID, KeyRevision: context.KeyRevision},
	}
	for index, candidate := range contexts {
		if plaintext, decryptErr := keyring.DecryptSAMLSPKey(candidate, envelope); !errors.Is(decryptErr, ErrInvalidEncryptedSAMLSPKey) {
			clear(plaintext)
			t.Fatalf("context mutation %d accepted: %v", index, decryptErr)
		}
	}

	tampered := envelope
	tampered.Nonce[0] ^= 1
	if plaintext, decryptErr := keyring.DecryptSAMLSPKey(context, tampered); !errors.Is(decryptErr, ErrInvalidEncryptedSAMLSPKey) {
		clear(plaintext)
		t.Fatalf("tampered nonce accepted: %v", decryptErr)
	}
	tampered = envelope
	tampered.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
	tampered.Ciphertext[0] ^= 1
	if plaintext, decryptErr := keyring.DecryptSAMLSPKey(context, tampered); !errors.Is(decryptErr, ErrInvalidEncryptedSAMLSPKey) {
		clear(plaintext)
		t.Fatalf("tampered ciphertext accepted: %v", decryptErr)
	}
}

func TestSAMLSPKeyEncryptionRejectsInvalidInputs(t *testing.T) {
	t.Parallel()
	context := testSAMLSPKeyContext()
	keyring, err := newKeyring(
		1,
		map[int16][]byte{1: bytes.Repeat([]byte{0x63}, sourceKeyBytes)},
		bytes.NewReader(bytes.Repeat([]byte{0x44}, samlSecretNonceBytes)),
	)
	if err != nil {
		t.Fatalf("newKeyring() error = %v", err)
	}
	if _, err := keyring.EncryptSAMLSPKey(context, nil); !errors.Is(err, ErrInvalidEncryptedSAMLSPKey) {
		t.Fatalf("empty plaintext error = %v", err)
	}
	invalid := context
	invalid.KeyRevision = 0
	if _, err := keyring.EncryptSAMLSPKey(invalid, []byte("secret")); !errors.Is(err, ErrInvalidEncryptedSAMLSPKey) {
		t.Fatalf("invalid context error = %v", err)
	}
	failing, err := newKeyring(
		1,
		map[int16][]byte{1: bytes.Repeat([]byte{0x64}, sourceKeyBytes)},
		failingReader{},
	)
	if err != nil {
		t.Fatalf("newKeyring() error = %v", err)
	}
	if _, err := failing.EncryptSAMLSPKey(context, []byte("secret")); err == nil {
		t.Fatal("nonce generation failure was accepted")
	}
	if _, err := (Keyring{}).DecryptSAMLSPKey(context, SAMLSPKeyEnvelope{}); !errors.Is(err, ErrInvalidEncryptedSAMLSPKey) {
		t.Fatalf("empty keyring error = %v", err)
	}
}

func TestDirectPlatformSAMLSPKeyIsRevisionBoundAndNotTenantPortable(t *testing.T) {
	t.Parallel()
	keyring, err := newKeyring(
		1,
		map[int16][]byte{1: bytes.Repeat([]byte{0xD1}, sourceKeyBytes)},
		bytes.NewReader(bytes.Repeat([]byte{0x52}, samlSecretNonceBytes*2)),
	)
	if err != nil {
		t.Fatalf("newKeyring() error = %v", err)
	}
	context := testDirectPlatformSAMLSPKeyContext()
	plaintext := []byte("direct-platform-pkcs8-private-key")
	directEnvelope, err := keyring.EncryptDirectPlatformSAMLSPKey(context, plaintext)
	if err != nil {
		t.Fatalf("EncryptDirectPlatformSAMLSPKey() error = %v", err)
	}
	opened, err := keyring.DecryptDirectPlatformSAMLSPKey(context, directEnvelope)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("DecryptDirectPlatformSAMLSPKey() = %q, %v", opened, err)
	}
	clear(opened)

	for name, mutate := range map[string]func(*DirectPlatformSAMLSPKeyContext){
		"provider": func(value *DirectPlatformSAMLSPKeyContext) {
			value.Provider.ProviderID = testID(81)
		},
		"key row": func(value *DirectPlatformSAMLSPKeyContext) { value.KeyID = testID(82) },
		"key revision": func(value *DirectPlatformSAMLSPKeyContext) {
			value.KeyRevision++
		},
	} {
		t.Run(name+" substitution", func(t *testing.T) {
			changed := context
			mutate(&changed)
			candidate, decryptErr := keyring.DecryptDirectPlatformSAMLSPKey(changed, directEnvelope)
			clear(candidate)
			if !errors.Is(decryptErr, ErrInvalidEncryptedSAMLSPKey) {
				t.Fatalf("DecryptDirectPlatformSAMLSPKey() error = %v", decryptErr)
			}
		})
	}

	tenantContext := SAMLSPKeyContext{
		Provider: ProviderContext{
			Scope: TenantProviderScope, TenantID: testID(83), ProviderID: context.Provider.ProviderID,
		},
		BindingID: testID(84), KeyID: context.KeyID, KeyRevision: uint32(context.KeyRevision),
	}
	tenantEnvelope, err := keyring.EncryptSAMLSPKey(tenantContext, plaintext)
	if err != nil {
		t.Fatalf("EncryptSAMLSPKey() error = %v", err)
	}
	opened, decryptErr := keyring.DecryptSAMLSPKey(tenantContext, directEnvelope)
	clear(opened)
	if !errors.Is(decryptErr, ErrInvalidEncryptedSAMLSPKey) {
		t.Fatalf("direct ciphertext opened in tenant context: %v", decryptErr)
	}
	opened, decryptErr = keyring.DecryptDirectPlatformSAMLSPKey(context, tenantEnvelope)
	clear(opened)
	if !errors.Is(decryptErr, ErrInvalidEncryptedSAMLSPKey) {
		t.Fatalf("tenant ciphertext opened in direct context: %v", decryptErr)
	}
}

func TestDirectPlatformSAMLSPKeyRejectsSyntheticAuthorityAndRevisionBounds(t *testing.T) {
	t.Parallel()
	keyring := mustKeyring(t, 1, map[int16][]byte{1: bytes.Repeat([]byte{0xD2}, sourceKeyBytes)})
	plaintext := []byte("direct-platform-key")
	maximum := testDirectPlatformSAMLSPKeyContext()
	maximum.KeyRevision = maximumContextRevision
	if _, err := keyring.EncryptDirectPlatformSAMLSPKey(maximum, plaintext); err != nil {
		t.Fatalf("maximum key revision rejected: %v", err)
	}

	for name, mutate := range map[string]func(*DirectPlatformSAMLSPKeyContext){
		"zero provider": func(value *DirectPlatformSAMLSPKeyContext) {
			value.Provider.ProviderID = EntityID{}
		},
		"tenant provider": func(value *DirectPlatformSAMLSPKeyContext) {
			value.Provider.Scope = TenantProviderScope
			value.Provider.TenantID = testID(91)
		},
		"fake tenant": func(value *DirectPlatformSAMLSPKeyContext) {
			value.Provider.TenantID = testID(92)
		},
		"zero key row":  func(value *DirectPlatformSAMLSPKeyContext) { value.KeyID = EntityID{} },
		"zero revision": func(value *DirectPlatformSAMLSPKeyContext) { value.KeyRevision = 0 },
		"revision overflow": func(value *DirectPlatformSAMLSPKeyContext) {
			value.KeyRevision = maximumContextRevision + 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			context := testDirectPlatformSAMLSPKeyContext()
			mutate(&context)
			if _, err := keyring.EncryptDirectPlatformSAMLSPKey(context, plaintext); !errors.Is(err, ErrInvalidEncryptedSAMLSPKey) {
				t.Fatalf("EncryptDirectPlatformSAMLSPKey() error = %v", err)
			}
		})
	}
}

func testSAMLSPKeyContext() SAMLSPKeyContext {
	return SAMLSPKeyContext{
		Provider:  ProviderContext{Scope: TenantProviderScope, TenantID: EntityID{1}, ProviderID: EntityID{2}},
		BindingID: EntityID{3}, KeyID: EntityID{4}, KeyRevision: 5,
	}
}

func testDirectPlatformSAMLSPKeyContext() DirectPlatformSAMLSPKeyContext {
	return DirectPlatformSAMLSPKeyContext{
		Provider: ProviderContext{Scope: PlatformProviderScope, ProviderID: testID(74)},
		KeyID:    testID(75), KeyRevision: 76,
	}
}
