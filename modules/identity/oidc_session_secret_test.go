package identity

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestOIDCSessionTokensRoundTripAcrossRotationAndArePurposeSeparated(t *testing.T) {
	t.Parallel()
	roots := map[int16][]byte{
		1: bytes.Repeat([]byte{0x91}, sourceKeyBytes),
		2: bytes.Repeat([]byte{0x92}, sourceKeyBytes),
	}
	nonce := bytes.Repeat([]byte{0x51}, oidcSessionTokenNonceBytes)
	writer, err := newKeyring(1, roots, bytes.NewReader(append(append([]byte(nil), nonce...), nonce...)))
	if err != nil {
		t.Fatal(err)
	}
	context := testOIDCSessionMaterialContext()
	plaintext := []byte("eyJhbGciOiJFUzI1NiJ9.same-material.signature")
	idEnvelope, err := writer.EncryptOIDCIDToken(context, plaintext)
	if err != nil {
		t.Fatalf("EncryptOIDCIDToken() error = %v", err)
	}
	refreshEnvelope, err := writer.EncryptOIDCRefreshToken(context, plaintext)
	if err != nil {
		t.Fatalf("EncryptOIDCRefreshToken() error = %v", err)
	}
	if bytes.Equal(idEnvelope.Ciphertext, refreshEnvelope.Ciphertext) ||
		bytes.Contains(idEnvelope.Ciphertext, plaintext) || bytes.Contains(refreshEnvelope.Ciphertext, plaintext) {
		t.Fatal("OIDC token purposes were not cryptographically separated")
	}

	reader := mustKeyring(t, 2, roots)
	openedID, err := reader.DecryptOIDCIDToken(context, idEnvelope)
	if err != nil || !bytes.Equal(openedID, plaintext) {
		t.Fatalf("DecryptOIDCIDToken() = %q, %v", openedID, err)
	}
	clear(openedID)
	openedRefresh, err := reader.DecryptOIDCRefreshToken(context, refreshEnvelope)
	if err != nil || !bytes.Equal(openedRefresh, plaintext) {
		t.Fatalf("DecryptOIDCRefreshToken() = %q, %v", openedRefresh, err)
	}
	clear(openedRefresh)

	openedID, err = reader.DecryptOIDCIDToken(context, refreshEnvelope)
	clear(openedID)
	if !errors.Is(err, ErrInvalidEncryptedOIDCSessionToken) {
		t.Fatalf("refresh token opened as ID token: %v", err)
	}
	openedRefresh, err = reader.DecryptOIDCRefreshToken(context, idEnvelope)
	clear(openedRefresh)
	if !errors.Is(err, ErrInvalidEncryptedOIDCSessionToken) {
		t.Fatalf("ID token opened as refresh token: %v", err)
	}
}

func TestOIDCSessionTokensBindTenantProviderBindingAndMaterialRow(t *testing.T) {
	t.Parallel()
	keyring, err := newKeyring(
		1,
		map[int16][]byte{1: bytes.Repeat([]byte{0x93}, sourceKeyBytes)},
		bytes.NewReader(bytes.Repeat([]byte{0x53}, oidcSessionTokenNonceBytes)),
	)
	if err != nil {
		t.Fatal(err)
	}
	context := testOIDCSessionMaterialContext()
	envelope, err := keyring.EncryptOIDCIDToken(context, []byte("id-token"))
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*OIDCSessionMaterialContext){
		"tenant":   func(value *OIDCSessionMaterialContext) { value.TenantID = testID(121) },
		"provider": func(value *OIDCSessionMaterialContext) { value.Provider.ProviderID = testID(122) },
		"binding":  func(value *OIDCSessionMaterialContext) { value.BindingID = testID(123) },
		"row":      func(value *OIDCSessionMaterialContext) { value.MaterialID = testID(124) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := context
			mutate(&candidate)
			plaintext, decryptErr := keyring.DecryptOIDCIDToken(candidate, envelope)
			clear(plaintext)
			if !errors.Is(decryptErr, ErrInvalidEncryptedOIDCSessionToken) {
				t.Fatalf("substituted context accepted: %v", decryptErr)
			}
		})
	}
	tampered := envelope
	tampered.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
	tampered.Ciphertext[0] ^= 1
	plaintext, err := keyring.DecryptOIDCIDToken(context, tampered)
	clear(plaintext)
	if !errors.Is(err, ErrInvalidEncryptedOIDCSessionToken) {
		t.Fatalf("tampered ciphertext accepted: %v", err)
	}
}

func TestOIDCSessionTokensRejectInvalidInputsAndFormatRedacted(t *testing.T) {
	t.Parallel()
	context := testOIDCSessionMaterialContext()
	keyring, err := newKeyring(
		1,
		map[int16][]byte{1: bytes.Repeat([]byte{0x94}, sourceKeyBytes)},
		bytes.NewReader(bytes.Repeat([]byte{0x54}, oidcSessionTokenNonceBytes*2)),
	)
	if err != nil {
		t.Fatal(err)
	}
	for name, plaintext := range map[string][]byte{
		"empty": nil, "oversized": make([]byte, maximumOIDCSessionTokenBytes+1),
	} {
		if _, encryptErr := keyring.EncryptOIDCIDToken(context, plaintext); !errors.Is(encryptErr, ErrInvalidEncryptedOIDCSessionToken) {
			t.Fatalf("%s plaintext error = %v", name, encryptErr)
		}
	}
	for index, candidate := range []OIDCSessionMaterialContext{
		{},
		{Provider: context.Provider, BindingID: context.BindingID},
		{Provider: context.Provider, MaterialID: context.MaterialID},
		{Provider: ProviderContext{Scope: PlatformProviderScope, ProviderID: context.Provider.ProviderID}, TenantID: context.TenantID, MaterialID: context.MaterialID},
	} {
		if _, encryptErr := keyring.EncryptOIDCRefreshToken(candidate, []byte("refresh")); !errors.Is(encryptErr, ErrInvalidEncryptedOIDCSessionToken) {
			t.Fatalf("invalid context %d error = %v", index, encryptErr)
		}
	}

	const canary = "oidc-session-token-canary"
	envelope := OIDCSessionTokenEnvelope{Ciphertext: []byte(canary)}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		if output := fmt.Sprintf(format, envelope); strings.Contains(output, canary) {
			t.Fatalf("envelope leaked with %s: %s", format, output)
		}
	}
}

func testOIDCSessionMaterialContext() OIDCSessionMaterialContext {
	return OIDCSessionMaterialContext{
		Provider: ProviderContext{
			Scope: TenantProviderScope, TenantID: testID(117), ProviderID: testID(118),
		},
		TenantID: testID(117), BindingID: testID(119), MaterialID: testID(120),
	}
}
