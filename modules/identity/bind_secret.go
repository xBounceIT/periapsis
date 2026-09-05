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
	bindSecretNonceBytes             = 12
	bindSecretTagBytes               = 16
	maximumBindSecretCiphertextBytes = 8 * 1024
	maximumBindSecretBytes           = maximumBindSecretCiphertextBytes - bindSecretTagBytes
	bindSecretAADSchema              = "periapsis/identity/aad/v1"
	bindSecretAADPurpose             = "ldap-bind-secret"
	bindSecretEncryptionProfile      = "aes-256-gcm"
)

// ErrInvalidEncryptedBindSecret deliberately combines malformed envelopes,
// unknown versions, authentication failures, and context mismatches.
var ErrInvalidEncryptedBindSecret = errors.New("invalid encrypted LDAP bind secret")

// BindSecretEnvelope is the authenticated value persisted for an LDAP bind
// secret. Associated data is reconstructed from the typed context and is not
// stored as caller-controlled bytes.
type BindSecretEnvelope struct {
	KeyVersion int16
	Nonce      [bindSecretNonceBytes]byte
	Ciphertext []byte
}

func (envelope BindSecretEnvelope) String() string {
	return fmt.Sprintf(
		"identity.BindSecretEnvelope{keyVersion:%d,ciphertextBytes:%d,nonce:[REDACTED],ciphertext:[REDACTED]}",
		envelope.KeyVersion, len(envelope.Ciphertext),
	)
}
func (envelope BindSecretEnvelope) GoString() string { return envelope.String() }

// EncryptBindSecret encrypts one non-empty LDAP bind secret with the active
// key and a fresh 96-bit CSPRNG nonce.
func (k Keyring) EncryptBindSecret(context BindSecretContext, plaintext []byte) (BindSecretEnvelope, error) {
	if err := validateBindSecretContext(context); err != nil {
		return BindSecretEnvelope{}, errors.New("valid LDAP bind-secret context is required")
	}
	if len(plaintext) < 1 || len(plaintext) > maximumBindSecretBytes {
		return BindSecretEnvelope{}, errors.New("LDAP bind secret has an invalid length")
	}
	keysForVersion, exists := k.keys[k.activeVersion]
	if !exists || k.random == nil {
		return BindSecretEnvelope{}, ErrInvalidKeyring
	}
	defer clearVersionKey(&keysForVersion)
	aead, err := newBindSecretAEAD(keysForVersion.bindSecret)
	if err != nil {
		return BindSecretEnvelope{}, ErrInvalidKeyring
	}

	var nonce [bindSecretNonceBytes]byte
	if _, err := io.ReadFull(k.random, nonce[:]); err != nil {
		clear(nonce[:])
		return BindSecretEnvelope{}, errors.New("generate LDAP bind-secret nonce")
	}
	aad := bindSecretAAD(context, k.activeVersion)
	ciphertext := aead.Seal(nil, nonce[:], plaintext, aad)
	clear(aad)
	return BindSecretEnvelope{KeyVersion: k.activeVersion, Nonce: nonce, Ciphertext: ciphertext}, nil
}

// DecryptBindSecret authenticates every envelope field against the supplied
// typed context. Tampering, an unknown key version, and a cross-context swap
// intentionally return the same public error.
func (k Keyring) DecryptBindSecret(context BindSecretContext, envelope BindSecretEnvelope) ([]byte, error) {
	if err := validateBindSecretContext(context); err != nil {
		return nil, ErrInvalidEncryptedBindSecret
	}
	keysForVersion, exists := k.keys[envelope.KeyVersion]
	if !exists || len(envelope.Ciphertext) <= bindSecretTagBytes || len(envelope.Ciphertext) > maximumBindSecretCiphertextBytes {
		return nil, ErrInvalidEncryptedBindSecret
	}
	defer clearVersionKey(&keysForVersion)
	aead, err := newBindSecretAEAD(keysForVersion.bindSecret)
	if err != nil || aead.Overhead() != bindSecretTagBytes {
		return nil, ErrInvalidEncryptedBindSecret
	}
	aad := bindSecretAAD(context, envelope.KeyVersion)
	plaintext, err := aead.Open(nil, envelope.Nonce[:], envelope.Ciphertext, aad)
	clear(aad)
	if err != nil || len(plaintext) < 1 || len(plaintext) > maximumBindSecretBytes {
		clear(plaintext)
		return nil, ErrInvalidEncryptedBindSecret
	}
	return plaintext, nil
}

func newBindSecretAEAD(key [derivedKeyBytes]byte) (cipher.AEAD, error) {
	defer clear(key[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || aead.NonceSize() != bindSecretNonceBytes {
		return nil, errors.New("initialize LDAP bind-secret encryption")
	}
	return aead, nil
}

func bindSecretAAD(context BindSecretContext, version int16) []byte {
	aad := make([]byte, 0, 192)
	aad = appendTypedField(aad, fieldSchema, []byte(bindSecretAADSchema))
	aad = appendTypedField(aad, fieldPurpose, []byte(bindSecretAADPurpose))
	aad = appendProviderContext(aad, context.Provider)
	aad = appendTypedField(aad, fieldRowID, context.SecretID[:])
	aad = appendTypedField(aad, fieldFormat, []byte(bindSecretEncryptionProfile))
	versionBytes := [2]byte{}
	binary.BigEndian.PutUint16(versionBytes[:], uint16(version))
	return appendTypedField(aad, fieldKeyVersion, versionBytes[:])
}
