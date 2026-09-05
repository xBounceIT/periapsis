package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	oidcSecretNonceBytes                     = 12
	oidcSecretTagBytes                       = 16
	maximumOIDCClientSecretBytes             = 8 * 1024
	maximumOIDCClientSecretCiphertextBytes   = maximumOIDCClientSecretBytes + oidcSecretTagBytes
	minimumOIDCPKCEVerifierBytes             = 43
	maximumOIDCPKCEVerifierBytes             = 128
	maximumOIDCPKCECiphertextBytes           = maximumOIDCPKCEVerifierBytes + oidcSecretTagBytes
	oidcSecretAADSchema                      = "periapsis/identity/aad/v1"
	oidcClientSecretAADPurpose               = "oidc-client-secret"
	oidcPKCEVerifierAADPurpose               = "oidc-pkce-verifier"
	platformOIDCPKCEVerifierAADPurpose       = "oidc-platform-tenant-pkce-verifier"
	directPlatformOIDCPKCEVerifierAADPurpose = "oidc-platform-direct-pkce-verifier"
	oidcSecretEncryptionProfile              = "aes-256-gcm"
)

var (
	ErrInvalidEncryptedOIDCClientSecret = errors.New("invalid encrypted OIDC client secret")
	ErrInvalidEncryptedOIDCPKCEVerifier = errors.New("invalid encrypted OIDC PKCE verifier")
)

type OIDCClientSecretEnvelope struct {
	KeyVersion int16
	Nonce      [oidcSecretNonceBytes]byte
	Ciphertext []byte
}

func (envelope OIDCClientSecretEnvelope) String() string {
	return fmt.Sprintf(
		"identity.OIDCClientSecretEnvelope{keyVersion:%d,ciphertextBytes:%d,nonce:[REDACTED],ciphertext:[REDACTED]}",
		envelope.KeyVersion, len(envelope.Ciphertext),
	)
}
func (envelope OIDCClientSecretEnvelope) GoString() string { return envelope.String() }

type OIDCPKCEVerifierEnvelope struct {
	KeyVersion int16
	Nonce      [oidcSecretNonceBytes]byte
	Ciphertext []byte
}

func (envelope OIDCPKCEVerifierEnvelope) String() string {
	return fmt.Sprintf(
		"identity.OIDCPKCEVerifierEnvelope{keyVersion:%d,ciphertextBytes:%d,nonce:[REDACTED],ciphertext:[REDACTED]}",
		envelope.KeyVersion, len(envelope.Ciphertext),
	)
}
func (envelope OIDCPKCEVerifierEnvelope) GoString() string { return envelope.String() }

func (k Keyring) EncryptOIDCClientSecret(
	context OIDCClientSecretContext,
	plaintext []byte,
) (OIDCClientSecretEnvelope, error) {
	if validateOIDCClientSecretContext(context) != nil || len(plaintext) < 1 ||
		len(plaintext) > maximumOIDCClientSecretBytes {
		return OIDCClientSecretEnvelope{}, ErrInvalidEncryptedOIDCClientSecret
	}
	keysForVersion, exists := k.keys[k.activeVersion]
	if !exists || k.random == nil {
		return OIDCClientSecretEnvelope{}, ErrInvalidKeyring
	}
	defer clearVersionKey(&keysForVersion)
	aead, err := newOIDCSecretAEAD(keysForVersion.oidcClientSecret)
	if err != nil {
		return OIDCClientSecretEnvelope{}, ErrInvalidKeyring
	}
	nonce, err := oidcSecretNonce(k.random)
	if err != nil {
		return OIDCClientSecretEnvelope{}, err
	}
	aad := oidcClientSecretAAD(context, k.activeVersion)
	ciphertext := aead.Seal(nil, nonce[:], plaintext, aad)
	clear(aad)
	return OIDCClientSecretEnvelope{KeyVersion: k.activeVersion, Nonce: nonce, Ciphertext: ciphertext}, nil
}

func (k Keyring) DecryptOIDCClientSecret(
	context OIDCClientSecretContext,
	envelope OIDCClientSecretEnvelope,
) ([]byte, error) {
	if validateOIDCClientSecretContext(context) != nil {
		return nil, ErrInvalidEncryptedOIDCClientSecret
	}
	keysForVersion, exists := k.keys[envelope.KeyVersion]
	if !exists || len(envelope.Ciphertext) <= oidcSecretTagBytes ||
		len(envelope.Ciphertext) > maximumOIDCClientSecretCiphertextBytes {
		return nil, ErrInvalidEncryptedOIDCClientSecret
	}
	defer clearVersionKey(&keysForVersion)
	aead, err := newOIDCSecretAEAD(keysForVersion.oidcClientSecret)
	if err != nil {
		return nil, ErrInvalidEncryptedOIDCClientSecret
	}
	aad := oidcClientSecretAAD(context, envelope.KeyVersion)
	plaintext, err := aead.Open(nil, envelope.Nonce[:], envelope.Ciphertext, aad)
	clear(aad)
	if err != nil || len(plaintext) < 1 || len(plaintext) > maximumOIDCClientSecretBytes {
		clear(plaintext)
		return nil, ErrInvalidEncryptedOIDCClientSecret
	}
	return plaintext, nil
}

func (k Keyring) EncryptOIDCPKCEVerifier(
	context OIDCPKCEVerifierContext,
	plaintext []byte,
) (OIDCPKCEVerifierEnvelope, error) {
	if validateOIDCPKCEVerifierContext(context) != nil || len(plaintext) < minimumOIDCPKCEVerifierBytes ||
		len(plaintext) > maximumOIDCPKCEVerifierBytes {
		return OIDCPKCEVerifierEnvelope{}, ErrInvalidEncryptedOIDCPKCEVerifier
	}
	keysForVersion, exists := k.keys[k.activeVersion]
	if !exists || k.random == nil {
		return OIDCPKCEVerifierEnvelope{}, ErrInvalidKeyring
	}
	defer clearVersionKey(&keysForVersion)
	aead, err := newOIDCSecretAEAD(keysForVersion.oidcPKCEVerifier)
	if err != nil {
		return OIDCPKCEVerifierEnvelope{}, ErrInvalidKeyring
	}
	nonce, err := oidcSecretNonce(k.random)
	if err != nil {
		return OIDCPKCEVerifierEnvelope{}, err
	}
	aad := oidcPKCEVerifierAAD(context, k.activeVersion)
	ciphertext := aead.Seal(nil, nonce[:], plaintext, aad)
	clear(aad)
	return OIDCPKCEVerifierEnvelope{KeyVersion: k.activeVersion, Nonce: nonce, Ciphertext: ciphertext}, nil
}

func (k Keyring) DecryptOIDCPKCEVerifier(
	context OIDCPKCEVerifierContext,
	envelope OIDCPKCEVerifierEnvelope,
) ([]byte, error) {
	if validateOIDCPKCEVerifierContext(context) != nil {
		return nil, ErrInvalidEncryptedOIDCPKCEVerifier
	}
	keysForVersion, exists := k.keys[envelope.KeyVersion]
	if !exists || len(envelope.Ciphertext) < minimumOIDCPKCEVerifierBytes+oidcSecretTagBytes ||
		len(envelope.Ciphertext) > maximumOIDCPKCECiphertextBytes {
		return nil, ErrInvalidEncryptedOIDCPKCEVerifier
	}
	defer clearVersionKey(&keysForVersion)
	aead, err := newOIDCSecretAEAD(keysForVersion.oidcPKCEVerifier)
	if err != nil {
		return nil, ErrInvalidEncryptedOIDCPKCEVerifier
	}
	aad := oidcPKCEVerifierAAD(context, envelope.KeyVersion)
	plaintext, err := aead.Open(nil, envelope.Nonce[:], envelope.Ciphertext, aad)
	clear(aad)
	if err != nil || len(plaintext) < minimumOIDCPKCEVerifierBytes || len(plaintext) > maximumOIDCPKCEVerifierBytes {
		clear(plaintext)
		return nil, ErrInvalidEncryptedOIDCPKCEVerifier
	}
	return plaintext, nil
}

// EncryptPlatformOIDCPKCEVerifier protects a verifier for a platform provider
// admitted into one tenant. Its AAD purpose is distinct from the legacy
// tenant-provider format, so neither ciphertext form can be opened as the
// other even when all UUID bytes happen to match.
func (k Keyring) EncryptPlatformOIDCPKCEVerifier(
	context PlatformOIDCPKCEVerifierContext,
	plaintext []byte,
) (OIDCPKCEVerifierEnvelope, error) {
	if validatePlatformOIDCPKCEVerifierContext(context) != nil ||
		len(plaintext) < minimumOIDCPKCEVerifierBytes || len(plaintext) > maximumOIDCPKCEVerifierBytes {
		return OIDCPKCEVerifierEnvelope{}, ErrInvalidEncryptedOIDCPKCEVerifier
	}
	keysForVersion, exists := k.keys[k.activeVersion]
	if !exists || k.random == nil {
		return OIDCPKCEVerifierEnvelope{}, ErrInvalidKeyring
	}
	defer clearVersionKey(&keysForVersion)
	aead, err := newOIDCSecretAEAD(keysForVersion.oidcPKCEVerifier)
	if err != nil {
		return OIDCPKCEVerifierEnvelope{}, ErrInvalidKeyring
	}
	nonce, err := oidcSecretNonce(k.random)
	if err != nil {
		return OIDCPKCEVerifierEnvelope{}, err
	}
	aad := platformOIDCPKCEVerifierAAD(context, k.activeVersion)
	ciphertext := aead.Seal(nil, nonce[:], plaintext, aad)
	clear(aad)
	return OIDCPKCEVerifierEnvelope{KeyVersion: k.activeVersion, Nonce: nonce, Ciphertext: ciphertext}, nil
}

func (k Keyring) DecryptPlatformOIDCPKCEVerifier(
	context PlatformOIDCPKCEVerifierContext,
	envelope OIDCPKCEVerifierEnvelope,
) ([]byte, error) {
	if validatePlatformOIDCPKCEVerifierContext(context) != nil {
		return nil, ErrInvalidEncryptedOIDCPKCEVerifier
	}
	keysForVersion, exists := k.keys[envelope.KeyVersion]
	if !exists || len(envelope.Ciphertext) < minimumOIDCPKCEVerifierBytes+oidcSecretTagBytes ||
		len(envelope.Ciphertext) > maximumOIDCPKCECiphertextBytes {
		return nil, ErrInvalidEncryptedOIDCPKCEVerifier
	}
	defer clearVersionKey(&keysForVersion)
	aead, err := newOIDCSecretAEAD(keysForVersion.oidcPKCEVerifier)
	if err != nil {
		return nil, ErrInvalidEncryptedOIDCPKCEVerifier
	}
	aad := platformOIDCPKCEVerifierAAD(context, envelope.KeyVersion)
	plaintext, err := aead.Open(nil, envelope.Nonce[:], envelope.Ciphertext, aad)
	clear(aad)
	if err != nil || len(plaintext) < minimumOIDCPKCEVerifierBytes || len(plaintext) > maximumOIDCPKCEVerifierBytes {
		clear(plaintext)
		return nil, ErrInvalidEncryptedOIDCPKCEVerifier
	}
	return plaintext, nil
}

// EncryptDirectPlatformOIDCPKCEVerifier protects a verifier for direct
// platform authentication. Its AAD purpose and shape are disjoint from both
// tenant-owned-provider and tenant-admitted-platform-provider ceremonies.
func (k Keyring) EncryptDirectPlatformOIDCPKCEVerifier(
	context DirectPlatformOIDCPKCEVerifierContext,
	plaintext []byte,
) (OIDCPKCEVerifierEnvelope, error) {
	if validateDirectPlatformOIDCPKCEVerifierContext(context) != nil ||
		len(plaintext) < minimumOIDCPKCEVerifierBytes || len(plaintext) > maximumOIDCPKCEVerifierBytes {
		return OIDCPKCEVerifierEnvelope{}, ErrInvalidEncryptedOIDCPKCEVerifier
	}
	keysForVersion, exists := k.keys[k.activeVersion]
	if !exists || k.random == nil {
		return OIDCPKCEVerifierEnvelope{}, ErrInvalidKeyring
	}
	defer clearVersionKey(&keysForVersion)
	aead, err := newOIDCSecretAEAD(keysForVersion.oidcPKCEVerifier)
	if err != nil {
		return OIDCPKCEVerifierEnvelope{}, ErrInvalidKeyring
	}
	nonce, err := oidcSecretNonce(k.random)
	if err != nil {
		return OIDCPKCEVerifierEnvelope{}, err
	}
	aad := directPlatformOIDCPKCEVerifierAAD(context, k.activeVersion)
	ciphertext := aead.Seal(nil, nonce[:], plaintext, aad)
	clear(aad)
	return OIDCPKCEVerifierEnvelope{KeyVersion: k.activeVersion, Nonce: nonce, Ciphertext: ciphertext}, nil
}

func (k Keyring) DecryptDirectPlatformOIDCPKCEVerifier(
	context DirectPlatformOIDCPKCEVerifierContext,
	envelope OIDCPKCEVerifierEnvelope,
) ([]byte, error) {
	if validateDirectPlatformOIDCPKCEVerifierContext(context) != nil {
		return nil, ErrInvalidEncryptedOIDCPKCEVerifier
	}
	keysForVersion, exists := k.keys[envelope.KeyVersion]
	if !exists || len(envelope.Ciphertext) < minimumOIDCPKCEVerifierBytes+oidcSecretTagBytes ||
		len(envelope.Ciphertext) > maximumOIDCPKCECiphertextBytes {
		return nil, ErrInvalidEncryptedOIDCPKCEVerifier
	}
	defer clearVersionKey(&keysForVersion)
	aead, err := newOIDCSecretAEAD(keysForVersion.oidcPKCEVerifier)
	if err != nil {
		return nil, ErrInvalidEncryptedOIDCPKCEVerifier
	}
	aad := directPlatformOIDCPKCEVerifierAAD(context, envelope.KeyVersion)
	plaintext, err := aead.Open(nil, envelope.Nonce[:], envelope.Ciphertext, aad)
	clear(aad)
	if err != nil || len(plaintext) < minimumOIDCPKCEVerifierBytes || len(plaintext) > maximumOIDCPKCEVerifierBytes {
		clear(plaintext)
		return nil, ErrInvalidEncryptedOIDCPKCEVerifier
	}
	return plaintext, nil
}

func newOIDCSecretAEAD(key [derivedKeyBytes]byte) (cipher.AEAD, error) {
	defer clear(key[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || aead.NonceSize() != oidcSecretNonceBytes {
		return nil, errors.New("initialize OIDC secret encryption")
	}
	return aead, nil
}

func oidcSecretNonce(random io.Reader) ([oidcSecretNonceBytes]byte, error) {
	var nonce [oidcSecretNonceBytes]byte
	if _, err := io.ReadFull(random, nonce[:]); err != nil {
		clear(nonce[:])
		return nonce, errors.New("generate OIDC secret nonce")
	}
	return nonce, nil
}

func oidcClientSecretAAD(context OIDCClientSecretContext, version int16) []byte {
	aad := oidcSecretAADPrefix(oidcClientSecretAADPurpose, context.Provider, context.BindingID)
	aad = appendTypedField(aad, fieldRowID, context.SecretID[:])
	return appendOIDCSecretAADSuffix(aad, version)
}

func oidcPKCEVerifierAAD(context OIDCPKCEVerifierContext, version int16) []byte {
	aad := oidcSecretAADPrefix(oidcPKCEVerifierAADPurpose, context.Provider, context.BindingID)
	aad = appendTypedField(aad, fieldTransactionID, context.TransactionID[:])
	return appendOIDCSecretAADSuffix(aad, version)
}

func platformOIDCPKCEVerifierAAD(context PlatformOIDCPKCEVerifierContext, version int16) []byte {
	aad := make([]byte, 0, 256)
	aad = appendTypedField(aad, fieldSchema, []byte(oidcSecretAADSchema))
	aad = appendTypedField(aad, fieldPurpose, []byte(platformOIDCPKCEVerifierAADPurpose))
	aad = appendProviderContext(aad, context.Provider)
	aad = appendTypedField(aad, fieldTenantID, context.Admission.TenantID[:])
	aad = appendTypedField(aad, fieldBindingID, context.Admission.BindingID[:])
	aad = appendTypedField(aad, fieldTransactionID, context.TransactionID[:])
	return appendOIDCSecretAADSuffix(aad, version)
}

func directPlatformOIDCPKCEVerifierAAD(
	context DirectPlatformOIDCPKCEVerifierContext,
	version int16,
) []byte {
	aad := make([]byte, 0, 256)
	aad = appendTypedField(aad, fieldSchema, []byte(oidcSecretAADSchema))
	aad = appendTypedField(aad, fieldPurpose, []byte(directPlatformOIDCPKCEVerifierAADPurpose))
	aad = appendProviderContext(aad, context.Provider)
	revision := [8]byte{}
	binary.BigEndian.PutUint64(revision[:], context.PlatformLoginRevision)
	aad = appendTypedField(aad, fieldRevision, revision[:])
	aad = appendTypedField(aad, fieldTransactionID, context.TransactionID[:])
	return appendOIDCSecretAADSuffix(aad, version)
}

func oidcSecretAADPrefix(purpose string, provider ProviderContext, bindingID EntityID) []byte {
	aad := make([]byte, 0, 256)
	aad = appendTypedField(aad, fieldSchema, []byte(oidcSecretAADSchema))
	aad = appendTypedField(aad, fieldPurpose, []byte(purpose))
	aad = appendProviderContext(aad, provider)
	return appendTypedField(aad, fieldBindingID, bindingID[:])
}

func appendOIDCSecretAADSuffix(aad []byte, version int16) []byte {
	aad = appendTypedField(aad, fieldFormat, []byte(oidcSecretEncryptionProfile))
	versionBytes := [2]byte{}
	binary.BigEndian.PutUint16(versionBytes[:], uint16(version))
	return appendTypedField(aad, fieldKeyVersion, versionBytes[:])
}
