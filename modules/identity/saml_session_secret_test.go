package identity

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSAMLSessionMaterialRoundTripAcrossRotationAndPurposeSeparation(t *testing.T) {
	t.Parallel()
	roots := map[int16][]byte{
		1: bytes.Repeat([]byte{0xA1}, sourceKeyBytes),
		2: bytes.Repeat([]byte{0xA2}, sourceKeyBytes),
	}
	nonce := bytes.Repeat([]byte{0x57}, samlSessionMaterialNonceBytes)
	oldKeyring, err := newKeyring(1, roots, bytes.NewReader(append(append([]byte(nil), nonce...), nonce...)))
	if err != nil {
		t.Fatalf("newKeyring() error = %v", err)
	}
	materialContext := testSAMLSessionMaterialContext()
	plaintext := []byte("canonical-nameid-format-session-index-document")
	envelope, err := oldKeyring.EncryptSAMLSessionMaterial(materialContext, plaintext)
	if err != nil {
		t.Fatalf("EncryptSAMLSessionMaterial() error = %v", err)
	}
	if envelope.KeyVersion != 1 || !bytes.Equal(envelope.Nonce[:], nonce) ||
		bytes.Contains(envelope.Ciphertext, plaintext) {
		t.Fatalf("unexpected protected envelope: %s", envelope)
	}

	// Reusing the same root, nonce, and plaintext with the SP-key purpose must
	// still produce different ciphertext.
	spEnvelope, err := oldKeyring.EncryptSAMLSPKey(testSAMLSPKeyContext(), plaintext)
	if err != nil {
		t.Fatalf("EncryptSAMLSPKey() error = %v", err)
	}
	if bytes.Equal(envelope.Ciphertext, spEnvelope.Ciphertext) {
		t.Fatal("SAML session and SP-key purposes produced the same ciphertext")
	}

	reader := mustKeyring(t, 2, roots)
	opened, err := reader.DecryptSAMLSessionMaterial(materialContext, envelope)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("DecryptSAMLSessionMaterial() = %q, %v", opened, err)
	}
	clear(opened)
}

func TestSAMLSessionMaterialBindsImmutableRowAndEveryEnvelopeField(t *testing.T) {
	t.Parallel()
	keyring, err := newKeyring(
		1,
		map[int16][]byte{1: bytes.Repeat([]byte{0xB1}, sourceKeyBytes)},
		bytes.NewReader(bytes.Repeat([]byte{0x43}, samlSessionMaterialNonceBytes)),
	)
	if err != nil {
		t.Fatalf("newKeyring() error = %v", err)
	}
	context := testSAMLSessionMaterialContext()
	envelope, err := keyring.EncryptSAMLSessionMaterial(context, []byte("logout-provenance"))
	if err != nil {
		t.Fatalf("EncryptSAMLSessionMaterial() error = %v", err)
	}

	contexts := []SAMLSessionMaterialContext{
		{Provider: context.Provider, BindingID: context.BindingID, MaterialID: testID(90)},
		{Provider: context.Provider, BindingID: testID(91), MaterialID: context.MaterialID},
		{Provider: ProviderContext{Scope: TenantProviderScope, TenantID: testID(92), ProviderID: context.Provider.ProviderID}, BindingID: context.BindingID, MaterialID: context.MaterialID},
		{Provider: ProviderContext{Scope: TenantProviderScope, TenantID: context.Provider.TenantID, ProviderID: testID(93)}, BindingID: context.BindingID, MaterialID: context.MaterialID},
	}
	for index, candidate := range contexts {
		plaintext, decryptErr := keyring.DecryptSAMLSessionMaterial(candidate, envelope)
		clear(plaintext)
		if !errors.Is(decryptErr, ErrInvalidEncryptedSAMLSessionMaterial) {
			t.Fatalf("context mutation %d accepted: %v", index, decryptErr)
		}
	}

	tamperedNonce := envelope
	tamperedNonce.Nonce[0] ^= 1
	plaintext, decryptErr := keyring.DecryptSAMLSessionMaterial(context, tamperedNonce)
	clear(plaintext)
	if !errors.Is(decryptErr, ErrInvalidEncryptedSAMLSessionMaterial) {
		t.Fatalf("tampered nonce accepted: %v", decryptErr)
	}
	tamperedCiphertext := envelope
	tamperedCiphertext.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
	tamperedCiphertext.Ciphertext[0] ^= 1
	plaintext, decryptErr = keyring.DecryptSAMLSessionMaterial(context, tamperedCiphertext)
	clear(plaintext)
	if !errors.Is(decryptErr, ErrInvalidEncryptedSAMLSessionMaterial) {
		t.Fatalf("tampered ciphertext accepted: %v", decryptErr)
	}
	unknownVersion := envelope
	unknownVersion.KeyVersion = 2
	plaintext, decryptErr = keyring.DecryptSAMLSessionMaterial(context, unknownVersion)
	clear(plaintext)
	if !errors.Is(decryptErr, ErrInvalidEncryptedSAMLSessionMaterial) {
		t.Fatalf("unknown version accepted: %v", decryptErr)
	}
}

func TestSAMLSessionMaterialRejectsInvalidInputsAndFormatsRedacted(t *testing.T) {
	t.Parallel()
	context := testSAMLSessionMaterialContext()
	keyring, err := newKeyring(
		1,
		map[int16][]byte{1: bytes.Repeat([]byte{0xC1}, sourceKeyBytes)},
		bytes.NewReader(bytes.Repeat([]byte{0x31}, samlSessionMaterialNonceBytes*2)),
	)
	if err != nil {
		t.Fatalf("newKeyring() error = %v", err)
	}
	for name, plaintext := range map[string][]byte{
		"empty":     nil,
		"oversized": make([]byte, maximumSAMLSessionMaterialBytes+1),
	} {
		if _, encryptErr := keyring.EncryptSAMLSessionMaterial(context, plaintext); !errors.Is(encryptErr, ErrInvalidEncryptedSAMLSessionMaterial) {
			t.Fatalf("%s plaintext error = %v", name, encryptErr)
		}
	}
	invalidContexts := []SAMLSessionMaterialContext{
		{},
		{Provider: context.Provider, BindingID: context.BindingID},
		{Provider: context.Provider, MaterialID: context.MaterialID},
		{Provider: ProviderContext{Scope: PlatformProviderScope, ProviderID: context.Provider.ProviderID}, BindingID: context.BindingID, MaterialID: context.MaterialID},
	}
	for index, candidate := range invalidContexts {
		if _, encryptErr := keyring.EncryptSAMLSessionMaterial(candidate, []byte("secret")); !errors.Is(encryptErr, ErrInvalidEncryptedSAMLSessionMaterial) {
			t.Fatalf("invalid context %d error = %v", index, encryptErr)
		}
	}
	failing, err := newKeyring(
		1,
		map[int16][]byte{1: bytes.Repeat([]byte{0xC2}, sourceKeyBytes)},
		failingReader{},
	)
	if err != nil {
		t.Fatalf("newKeyring() error = %v", err)
	}
	if _, encryptErr := failing.EncryptSAMLSessionMaterial(context, []byte("secret")); encryptErr == nil {
		t.Fatal("nonce generation failure was accepted")
	}
	if plaintext, decryptErr := (Keyring{}).DecryptSAMLSessionMaterial(context, SAMLSessionMaterialEnvelope{}); !errors.Is(decryptErr, ErrInvalidEncryptedSAMLSessionMaterial) {
		clear(plaintext)
		t.Fatalf("empty keyring error = %v", decryptErr)
	}

	const canary = "saml-session-material-canary"
	envelope := SAMLSessionMaterialEnvelope{Ciphertext: []byte(canary)}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		if output := fmt.Sprintf(format, envelope); strings.Contains(output, canary) {
			t.Fatalf("envelope leaked with %s: %s", format, output)
		}
	}
}

func TestDirectPlatformSAMLSessionMaterialIsAuthorityBoundAndNotTenantPortable(t *testing.T) {
	t.Parallel()
	keyring, err := newKeyring(
		1,
		map[int16][]byte{1: bytes.Repeat([]byte{0xD3}, sourceKeyBytes)},
		bytes.NewReader(bytes.Repeat([]byte{0x63}, samlSessionMaterialNonceBytes*2)),
	)
	if err != nil {
		t.Fatalf("newKeyring() error = %v", err)
	}
	context := testDirectPlatformSAMLSessionMaterialContext()
	plaintext := []byte("direct-platform-nameid-session-index")
	directEnvelope, err := keyring.EncryptDirectPlatformSAMLSessionMaterial(context, plaintext)
	if err != nil {
		t.Fatalf("EncryptDirectPlatformSAMLSessionMaterial() error = %v", err)
	}
	opened, err := keyring.DecryptDirectPlatformSAMLSessionMaterial(context, directEnvelope)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("DecryptDirectPlatformSAMLSessionMaterial() = %q, %v", opened, err)
	}
	clear(opened)

	for name, mutate := range map[string]func(*DirectPlatformSAMLSessionMaterialContext){
		"provider": func(value *DirectPlatformSAMLSessionMaterialContext) {
			value.Provider.ProviderID = testID(101)
		},
		"material row": func(value *DirectPlatformSAMLSessionMaterialContext) {
			value.MaterialID = testID(102)
		},
		"platform login revision": func(value *DirectPlatformSAMLSessionMaterialContext) {
			value.PlatformLoginRevision++
		},
	} {
		t.Run(name+" substitution", func(t *testing.T) {
			changed := context
			mutate(&changed)
			candidate, decryptErr := keyring.DecryptDirectPlatformSAMLSessionMaterial(changed, directEnvelope)
			clear(candidate)
			if !errors.Is(decryptErr, ErrInvalidEncryptedSAMLSessionMaterial) {
				t.Fatalf("DecryptDirectPlatformSAMLSessionMaterial() error = %v", decryptErr)
			}
		})
	}

	tenantContext := SAMLSessionMaterialContext{
		Provider: ProviderContext{
			Scope: TenantProviderScope, TenantID: testID(103), ProviderID: context.Provider.ProviderID,
		},
		BindingID: testID(104), MaterialID: context.MaterialID,
	}
	tenantEnvelope, err := keyring.EncryptSAMLSessionMaterial(tenantContext, plaintext)
	if err != nil {
		t.Fatalf("EncryptSAMLSessionMaterial() error = %v", err)
	}
	opened, decryptErr := keyring.DecryptSAMLSessionMaterial(tenantContext, directEnvelope)
	clear(opened)
	if !errors.Is(decryptErr, ErrInvalidEncryptedSAMLSessionMaterial) {
		t.Fatalf("direct ciphertext opened in tenant context: %v", decryptErr)
	}
	opened, decryptErr = keyring.DecryptDirectPlatformSAMLSessionMaterial(context, tenantEnvelope)
	clear(opened)
	if !errors.Is(decryptErr, ErrInvalidEncryptedSAMLSessionMaterial) {
		t.Fatalf("tenant ciphertext opened in direct context: %v", decryptErr)
	}
}

func TestDirectPlatformSAMLSessionMaterialRejectsSyntheticAuthorityAndRevisionBounds(t *testing.T) {
	t.Parallel()
	keyring := mustKeyring(t, 1, map[int16][]byte{1: bytes.Repeat([]byte{0xD4}, sourceKeyBytes)})
	plaintext := []byte("direct-platform-session-material")
	maximum := testDirectPlatformSAMLSessionMaterialContext()
	maximum.PlatformLoginRevision = maximumContextRevision
	if _, err := keyring.EncryptDirectPlatformSAMLSessionMaterial(maximum, plaintext); err != nil {
		t.Fatalf("maximum platform-login revision rejected: %v", err)
	}

	for name, mutate := range map[string]func(*DirectPlatformSAMLSessionMaterialContext){
		"zero provider": func(value *DirectPlatformSAMLSessionMaterialContext) {
			value.Provider.ProviderID = EntityID{}
		},
		"tenant provider": func(value *DirectPlatformSAMLSessionMaterialContext) {
			value.Provider.Scope = TenantProviderScope
			value.Provider.TenantID = testID(111)
		},
		"fake tenant": func(value *DirectPlatformSAMLSessionMaterialContext) {
			value.Provider.TenantID = testID(112)
		},
		"zero material row": func(value *DirectPlatformSAMLSessionMaterialContext) {
			value.MaterialID = EntityID{}
		},
		"zero revision": func(value *DirectPlatformSAMLSessionMaterialContext) {
			value.PlatformLoginRevision = 0
		},
		"revision overflow": func(value *DirectPlatformSAMLSessionMaterialContext) {
			value.PlatformLoginRevision = maximumContextRevision + 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			context := testDirectPlatformSAMLSessionMaterialContext()
			mutate(&context)
			if _, err := keyring.EncryptDirectPlatformSAMLSessionMaterial(context, plaintext); !errors.Is(err, ErrInvalidEncryptedSAMLSessionMaterial) {
				t.Fatalf("EncryptDirectPlatformSAMLSessionMaterial() error = %v", err)
			}
		})
	}
}

func TestDirectPlatformSAMLSecretPurposesAreNotSubstitutable(t *testing.T) {
	t.Parallel()
	keyring, err := newKeyring(
		1,
		map[int16][]byte{1: bytes.Repeat([]byte{0xD5}, sourceKeyBytes)},
		bytes.NewReader(bytes.Repeat([]byte{0x71}, samlSecretNonceBytes*2)),
	)
	if err != nil {
		t.Fatalf("newKeyring() error = %v", err)
	}
	spContext := testDirectPlatformSAMLSPKeyContext()
	sessionContext := DirectPlatformSAMLSessionMaterialContext{
		Provider: spContext.Provider, MaterialID: spContext.KeyID,
		PlatformLoginRevision: spContext.KeyRevision,
	}
	plaintext := []byte("same-direct-platform-secret-material")
	spEnvelope, err := keyring.EncryptDirectPlatformSAMLSPKey(spContext, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	sessionEnvelope, err := keyring.EncryptDirectPlatformSAMLSessionMaterial(sessionContext, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(spEnvelope.Ciphertext, sessionEnvelope.Ciphertext) {
		t.Fatal("direct SP-key and session-material purposes produced equal ciphertext")
	}

	openedSession, sessionErr := keyring.DecryptDirectPlatformSAMLSessionMaterial(
		sessionContext,
		SAMLSessionMaterialEnvelope{
			KeyVersion: spEnvelope.KeyVersion, Nonce: spEnvelope.Nonce, Ciphertext: spEnvelope.Ciphertext,
		},
	)
	clear(openedSession)
	if !errors.Is(sessionErr, ErrInvalidEncryptedSAMLSessionMaterial) {
		t.Fatalf("SP-key ciphertext opened as session material: %v", sessionErr)
	}
	openedKey, keyErr := keyring.DecryptDirectPlatformSAMLSPKey(
		spContext,
		SAMLSPKeyEnvelope{
			KeyVersion: sessionEnvelope.KeyVersion, Nonce: sessionEnvelope.Nonce, Ciphertext: sessionEnvelope.Ciphertext,
		},
	)
	clear(openedKey)
	if !errors.Is(keyErr, ErrInvalidEncryptedSAMLSPKey) {
		t.Fatalf("session-material ciphertext opened as SP key: %v", keyErr)
	}

	spAAD := directPlatformSAMLSPKeyAAD(spContext, 1)
	defer clear(spAAD)
	sessionAAD := directPlatformSAMLSessionMaterialAAD(sessionContext, 1)
	defer clear(sessionAAD)
	if !bytes.Contains(spAAD, []byte(directPlatformSAMLSPKeyPurpose)) ||
		!bytes.Contains(sessionAAD, []byte(directPlatformSAMLSessionPurpose)) || bytes.Equal(spAAD, sessionAAD) {
		t.Fatal("direct-platform SAML AAD lost its exact purpose separation")
	}
}

func testSAMLSessionMaterialContext() SAMLSessionMaterialContext {
	return SAMLSessionMaterialContext{
		Provider: ProviderContext{
			Scope: TenantProviderScope, TenantID: testID(70), ProviderID: testID(71),
		},
		BindingID: testID(72), MaterialID: testID(73),
	}
}

func testDirectPlatformSAMLSessionMaterialContext() DirectPlatformSAMLSessionMaterialContext {
	return DirectPlatformSAMLSessionMaterialContext{
		Provider:              ProviderContext{Scope: PlatformProviderScope, ProviderID: testID(105)},
		MaterialID:            testID(106),
		PlatformLoginRevision: 107,
	}
}
