package identity

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestOIDCSecretsRoundTripAcrossRotationAndRemainPurposeSeparated(t *testing.T) {
	t.Parallel()
	roots := map[int16][]byte{
		1: bytes.Repeat([]byte{0x81}, sourceKeyBytes),
		2: bytes.Repeat([]byte{0x82}, sourceKeyBytes),
	}
	nonces := bytes.Repeat([]byte{0xA1}, oidcSecretNonceBytes*2)
	oldKeyring, err := newKeyring(1, roots, bytes.NewReader(nonces))
	if err != nil {
		t.Fatal(err)
	}
	clientContext := tenantOIDCClientSecretContext(10)
	pkceContext := tenantOIDCPKCEContext(10)
	secret := []byte(strings.Repeat("s", minimumOIDCPKCEVerifierBytes))
	clientEnvelope, err := oldKeyring.EncryptOIDCClientSecret(clientContext, secret)
	if err != nil {
		t.Fatalf("EncryptOIDCClientSecret() error = %v", err)
	}
	pkceEnvelope, err := oldKeyring.EncryptOIDCPKCEVerifier(pkceContext, secret)
	if err != nil {
		t.Fatalf("EncryptOIDCPKCEVerifier() error = %v", err)
	}
	if bytes.Equal(clientEnvelope.Ciphertext, pkceEnvelope.Ciphertext) ||
		bytes.Contains(clientEnvelope.Ciphertext, secret) || bytes.Contains(pkceEnvelope.Ciphertext, secret) {
		t.Fatal("OIDC secret purposes were not cryptographically separated")
	}
	reader := mustKeyring(t, 2, roots)
	clientPlaintext, err := reader.DecryptOIDCClientSecret(clientContext, clientEnvelope)
	if err != nil || !bytes.Equal(clientPlaintext, secret) {
		t.Fatalf("DecryptOIDCClientSecret() = %q, %v", clientPlaintext, err)
	}
	clear(clientPlaintext)
	pkcePlaintext, err := reader.DecryptOIDCPKCEVerifier(pkceContext, pkceEnvelope)
	if err != nil || !bytes.Equal(pkcePlaintext, secret) {
		t.Fatalf("DecryptOIDCPKCEVerifier() = %q, %v", pkcePlaintext, err)
	}
	clear(pkcePlaintext)
}

func TestOIDCSecretsRejectTamperingAndCrossContextSwaps(t *testing.T) {
	t.Parallel()
	root := map[int16][]byte{1: bytes.Repeat([]byte{0x83}, sourceKeyBytes)}
	keyring := mustKeyring(t, 1, root)
	clientContext := tenantOIDCClientSecretContext(20)
	clientEnvelope, err := keyring.EncryptOIDCClientSecret(clientContext, []byte("client-secret"))
	if err != nil {
		t.Fatal(err)
	}
	changedClient := clientContext
	changedClient.SecretID = testID(99)
	clientEnvelope.Ciphertext[0] ^= 1
	for name, context := range map[string]OIDCClientSecretContext{
		"tamper":  clientContext,
		"context": changedClient,
	} {
		t.Run("client "+name, func(t *testing.T) {
			envelope := clientEnvelope
			if name == "context" {
				envelope, _ = keyring.EncryptOIDCClientSecret(clientContext, []byte("client-secret"))
			}
			plaintext, decryptErr := keyring.DecryptOIDCClientSecret(context, envelope)
			clear(plaintext)
			if !errors.Is(decryptErr, ErrInvalidEncryptedOIDCClientSecret) {
				t.Fatalf("DecryptOIDCClientSecret() error = %v", decryptErr)
			}
		})
	}

	pkceContext := tenantOIDCPKCEContext(30)
	pkceEnvelope, err := keyring.EncryptOIDCPKCEVerifier(pkceContext, []byte(strings.Repeat("v", 64)))
	if err != nil {
		t.Fatal(err)
	}
	changedPKCE := pkceContext
	changedPKCE.TransactionID[0] ^= 0xff
	if plaintext, decryptErr := keyring.DecryptOIDCPKCEVerifier(changedPKCE, pkceEnvelope); !errors.Is(decryptErr, ErrInvalidEncryptedOIDCPKCEVerifier) {
		clear(plaintext)
		t.Fatalf("cross-transaction DecryptOIDCPKCEVerifier() error = %v", decryptErr)
	}
}

func TestPlatformOIDCPKCEVerifierBindsExactTenantAdmission(t *testing.T) {
	t.Parallel()
	keyring := mustKeyring(t, 1, map[int16][]byte{1: bytes.Repeat([]byte{0x85}, sourceKeyBytes)})
	context := platformOIDCPKCEContext(50)
	verifier := []byte(strings.Repeat("p", 64))
	envelope, err := keyring.EncryptPlatformOIDCPKCEVerifier(context, verifier)
	if err != nil {
		t.Fatalf("EncryptPlatformOIDCPKCEVerifier() error = %v", err)
	}
	plaintext, err := keyring.DecryptPlatformOIDCPKCEVerifier(context, envelope)
	if err != nil || !bytes.Equal(plaintext, verifier) {
		t.Fatalf("DecryptPlatformOIDCPKCEVerifier() = %q, %v", plaintext, err)
	}
	clear(plaintext)

	mutations := map[string]func(*PlatformOIDCPKCEVerifierContext){
		"transaction": func(value *PlatformOIDCPKCEVerifierContext) { value.TransactionID[0] ^= 0xff },
		"provider":    func(value *PlatformOIDCPKCEVerifierContext) { value.Provider.ProviderID = testID(90) },
		"tenant":      func(value *PlatformOIDCPKCEVerifierContext) { value.Admission.TenantID = testID(91) },
		"binding":     func(value *PlatformOIDCPKCEVerifierContext) { value.Admission.BindingID = testID(92) },
	}
	for name, mutate := range mutations {
		t.Run(name+" substitution", func(t *testing.T) {
			changed := context
			mutate(&changed)
			opened, decryptErr := keyring.DecryptPlatformOIDCPKCEVerifier(changed, envelope)
			clear(opened)
			if !errors.Is(decryptErr, ErrInvalidEncryptedOIDCPKCEVerifier) {
				t.Fatalf("DecryptPlatformOIDCPKCEVerifier() error = %v", decryptErr)
			}
		})
	}

	legacy := tenantOIDCPKCEContext(50)
	legacy.TransactionID = context.TransactionID
	legacy.Provider.ProviderID = context.Provider.ProviderID
	legacy.BindingID = context.Admission.BindingID
	opened, decryptErr := keyring.DecryptOIDCPKCEVerifier(legacy, envelope)
	clear(opened)
	if !errors.Is(decryptErr, ErrInvalidEncryptedOIDCPKCEVerifier) {
		t.Fatalf("platform ciphertext opened with legacy AAD: %v", decryptErr)
	}
}

func TestDirectPlatformOIDCPKCEVerifierUsesDisjointRevisionBoundAAD(t *testing.T) {
	t.Parallel()
	keyring := mustKeyring(t, 1, map[int16][]byte{1: bytes.Repeat([]byte{0x86}, sourceKeyBytes)})
	direct := directPlatformOIDCPKCEContext(60)
	verifier := []byte(strings.Repeat("d", 64))
	directEnvelope, err := keyring.EncryptDirectPlatformOIDCPKCEVerifier(direct, verifier)
	if err != nil {
		t.Fatalf("EncryptDirectPlatformOIDCPKCEVerifier() error = %v", err)
	}
	plaintext, err := keyring.DecryptDirectPlatformOIDCPKCEVerifier(direct, directEnvelope)
	if err != nil || !bytes.Equal(plaintext, verifier) {
		t.Fatalf("DecryptDirectPlatformOIDCPKCEVerifier() = %q, %v", plaintext, err)
	}
	clear(plaintext)

	for name, mutate := range map[string]func(*DirectPlatformOIDCPKCEVerifierContext){
		"transaction": func(value *DirectPlatformOIDCPKCEVerifierContext) { value.TransactionID[0] ^= 0xff },
		"provider": func(value *DirectPlatformOIDCPKCEVerifierContext) {
			value.Provider.ProviderID = testID(90)
		},
		"platform login revision": func(value *DirectPlatformOIDCPKCEVerifierContext) {
			value.PlatformLoginRevision++
		},
	} {
		t.Run(name+" substitution", func(t *testing.T) {
			changed := direct
			mutate(&changed)
			opened, decryptErr := keyring.DecryptDirectPlatformOIDCPKCEVerifier(changed, directEnvelope)
			clear(opened)
			if !errors.Is(decryptErr, ErrInvalidEncryptedOIDCPKCEVerifier) {
				t.Fatalf("DecryptDirectPlatformOIDCPKCEVerifier() error = %v", decryptErr)
			}
		})
	}

	tenantPlatform := platformOIDCPKCEContext(60)
	tenantPlatform.TransactionID = direct.TransactionID
	tenantPlatform.Provider = direct.Provider
	tenantEnvelope, err := keyring.EncryptPlatformOIDCPKCEVerifier(tenantPlatform, verifier)
	if err != nil {
		t.Fatalf("EncryptPlatformOIDCPKCEVerifier() error = %v", err)
	}
	opened, decryptErr := keyring.DecryptPlatformOIDCPKCEVerifier(tenantPlatform, directEnvelope)
	clear(opened)
	if !errors.Is(decryptErr, ErrInvalidEncryptedOIDCPKCEVerifier) {
		t.Fatalf("direct ciphertext opened as tenant-admitted platform ciphertext: %v", decryptErr)
	}
	opened, decryptErr = keyring.DecryptDirectPlatformOIDCPKCEVerifier(direct, tenantEnvelope)
	clear(opened)
	if !errors.Is(decryptErr, ErrInvalidEncryptedOIDCPKCEVerifier) {
		t.Fatalf("tenant-admitted platform ciphertext opened as direct ciphertext: %v", decryptErr)
	}
}

func TestDirectPlatformOIDCPKCEVerifierRejectsTenantAuthorityAndRevisionBounds(t *testing.T) {
	t.Parallel()
	keyring := mustKeyring(t, 1, map[int16][]byte{1: bytes.Repeat([]byte{0x87}, sourceKeyBytes)})
	verifier := []byte(strings.Repeat("d", 64))
	maximum := directPlatformOIDCPKCEContext(69)
	maximum.PlatformLoginRevision = maximumContextRevision
	if _, err := keyring.EncryptDirectPlatformOIDCPKCEVerifier(maximum, verifier); err != nil {
		t.Fatalf("maximum platform-login revision rejected: %v", err)
	}
	for name, mutate := range map[string]func(*DirectPlatformOIDCPKCEVerifierContext){
		"zero transaction": func(value *DirectPlatformOIDCPKCEVerifierContext) {
			value.TransactionID = OIDCTransactionID{}
		},
		"tenant provider": func(value *DirectPlatformOIDCPKCEVerifierContext) {
			value.Provider.Scope = TenantProviderScope
			value.Provider.TenantID = testID(91)
		},
		"fake tenant on platform provider": func(value *DirectPlatformOIDCPKCEVerifierContext) {
			value.Provider.TenantID = testID(92)
		},
		"zero platform login revision": func(value *DirectPlatformOIDCPKCEVerifierContext) {
			value.PlatformLoginRevision = 0
		},
		"platform login revision overflow": func(value *DirectPlatformOIDCPKCEVerifierContext) {
			value.PlatformLoginRevision = maximumContextRevision + 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			context := directPlatformOIDCPKCEContext(70)
			mutate(&context)
			if _, err := keyring.EncryptDirectPlatformOIDCPKCEVerifier(context, verifier); !errors.Is(err, ErrInvalidEncryptedOIDCPKCEVerifier) {
				t.Fatalf("EncryptDirectPlatformOIDCPKCEVerifier() error = %v", err)
			}
		})
	}
}

func TestOIDCSecretInputsAreBoundedAndFormattingIsRedacted(t *testing.T) {
	t.Parallel()
	keyring := mustKeyring(t, 1, map[int16][]byte{1: bytes.Repeat([]byte{0x84}, sourceKeyBytes)})
	clientContext := tenantOIDCClientSecretContext(40)
	pkceContext := tenantOIDCPKCEContext(40)
	if _, err := keyring.EncryptOIDCClientSecret(clientContext, nil); !errors.Is(err, ErrInvalidEncryptedOIDCClientSecret) {
		t.Fatalf("empty client secret error = %v", err)
	}
	if _, err := keyring.EncryptOIDCClientSecret(clientContext, make([]byte, maximumOIDCClientSecretBytes+1)); !errors.Is(err, ErrInvalidEncryptedOIDCClientSecret) {
		t.Fatalf("oversized client secret error = %v", err)
	}
	if _, err := keyring.EncryptOIDCPKCEVerifier(pkceContext, make([]byte, minimumOIDCPKCEVerifierBytes-1)); !errors.Is(err, ErrInvalidEncryptedOIDCPKCEVerifier) {
		t.Fatalf("short PKCE verifier error = %v", err)
	}
	failingKeyring, err := newKeyring(1, map[int16][]byte{1: bytes.Repeat([]byte{0x84}, sourceKeyBytes)}, failingReader{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failingKeyring.EncryptOIDCPKCEVerifier(pkceContext, []byte(strings.Repeat("v", 64))); err == nil {
		t.Fatal("failing random source was accepted")
	}
	const canary = "oidc-secret-canary"
	for _, value := range []any{
		OIDCClientSecretEnvelope{Ciphertext: []byte(canary)},
		OIDCPKCEVerifierEnvelope{Ciphertext: []byte(canary)},
	} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if output := fmt.Sprintf(format, value); strings.Contains(output, canary) {
				t.Fatalf("%T leaked with %s: %s", value, format, output)
			}
		}
	}
}

func tenantOIDCClientSecretContext(seed byte) OIDCClientSecretContext {
	return OIDCClientSecretContext{
		Provider: ProviderContext{
			Scope: TenantProviderScope, TenantID: testID(seed), ProviderID: testID(seed + 1),
		},
		BindingID: testID(seed + 2), SecretID: testID(seed + 3),
	}
}

func tenantOIDCPKCEContext(seed byte) OIDCPKCEVerifierContext {
	var transactionID OIDCTransactionID
	for index := range transactionID {
		transactionID[index] = seed + byte(index)
	}
	return OIDCPKCEVerifierContext{
		TransactionID: transactionID,
		Provider: ProviderContext{
			Scope: TenantProviderScope, TenantID: testID(seed), ProviderID: testID(seed + 1),
		},
		BindingID: testID(seed + 2),
	}
}

func platformOIDCPKCEContext(seed byte) PlatformOIDCPKCEVerifierContext {
	var transactionID OIDCTransactionID
	for index := range transactionID {
		transactionID[index] = seed + byte(index)
	}
	return PlatformOIDCPKCEVerifierContext{
		TransactionID: transactionID,
		Provider: ProviderContext{
			Scope: PlatformProviderScope, ProviderID: testID(seed + 1),
		},
		Admission: TenantAdmissionContext{TenantID: testID(seed + 2), BindingID: testID(seed + 3)},
	}
}

func directPlatformOIDCPKCEContext(seed byte) DirectPlatformOIDCPKCEVerifierContext {
	var transactionID OIDCTransactionID
	for index := range transactionID {
		transactionID[index] = seed + byte(index)
	}
	return DirectPlatformOIDCPKCEVerifierContext{
		TransactionID: transactionID,
		Provider: ProviderContext{
			Scope: PlatformProviderScope, ProviderID: testID(seed + 1),
		},
		PlatformLoginRevision: 23,
	}
}
