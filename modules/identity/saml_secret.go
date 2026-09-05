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
	samlSecretNonceBytes            = 12
	samlSecretTagBytes              = 16
	maximumSAMLSPKeyPlaintextBytes  = 128*1024 - samlSecretNonceBytes - samlSecretTagBytes
	maximumSAMLSPKeyCiphertextBytes = maximumSAMLSPKeyPlaintextBytes + samlSecretTagBytes
	samlSecretAADSchema             = "periapsis/identity/aad/v1"
	samlSPKeyAADPurpose             = "saml-sp-key"
	directPlatformSAMLSPKeyPurpose  = "saml-platform-direct-sp-key"
	samlSecretEncryptionProfile     = "aes-256-gcm"
)

// ErrInvalidEncryptedSAMLSPKey intentionally combines malformed envelopes,
// unknown versions, authentication failures, and invalid contexts.
var ErrInvalidEncryptedSAMLSPKey = errors.New("invalid encrypted SAML SP key")

// SAMLSPKeyEnvelope contains one nonce and authenticated ciphertext. The
// persistence adapter serializes nonce || ciphertext into its opaque column.
type SAMLSPKeyEnvelope struct {
	KeyVersion int16
	Nonce      [samlSecretNonceBytes]byte
	Ciphertext []byte
}

func (envelope SAMLSPKeyEnvelope) String() string {
	return fmt.Sprintf(
		"identity.SAMLSPKeyEnvelope{keyVersion:%d,ciphertextBytes:%d,nonce:[REDACTED],ciphertext:[REDACTED]}",
		envelope.KeyVersion, len(envelope.Ciphertext),
	)
}
func (envelope SAMLSPKeyEnvelope) GoString() string { return envelope.String() }

// EncryptSAMLSPKey protects one PKCS#8 DER document with the active,
// purpose-separated identity key. Parsing and certificate matching remain at
// the federated-authentication adapter boundary.
func (k Keyring) EncryptSAMLSPKey(
	context SAMLSPKeyContext,
	plaintext []byte,
) (SAMLSPKeyEnvelope, error) {
	if validateSAMLSPKeyContext(context) != nil || len(plaintext) < 1 ||
		len(plaintext) > maximumSAMLSPKeyPlaintextBytes {
		return SAMLSPKeyEnvelope{}, ErrInvalidEncryptedSAMLSPKey
	}
	keysForVersion, exists := k.keys[k.activeVersion]
	if !exists || k.random == nil {
		return SAMLSPKeyEnvelope{}, ErrInvalidKeyring
	}
	defer clearVersionKey(&keysForVersion)
	aead, err := newSAMLSecretAEAD(keysForVersion.samlSPKey)
	if err != nil {
		return SAMLSPKeyEnvelope{}, ErrInvalidKeyring
	}
	nonce, err := samlSecretNonce(k.random)
	if err != nil {
		return SAMLSPKeyEnvelope{}, err
	}
	aad := samlSPKeyAAD(context, k.activeVersion)
	ciphertext := aead.Seal(nil, nonce[:], plaintext, aad)
	clear(aad)
	return SAMLSPKeyEnvelope{KeyVersion: k.activeVersion, Nonce: nonce, Ciphertext: ciphertext}, nil
}

// DecryptSAMLSPKey authenticates every context and envelope field and returns
// a fresh plaintext slice owned by the caller.
func (k Keyring) DecryptSAMLSPKey(
	context SAMLSPKeyContext,
	envelope SAMLSPKeyEnvelope,
) ([]byte, error) {
	if validateSAMLSPKeyContext(context) != nil {
		return nil, ErrInvalidEncryptedSAMLSPKey
	}
	keysForVersion, exists := k.keys[envelope.KeyVersion]
	if !exists || len(envelope.Ciphertext) <= samlSecretTagBytes ||
		len(envelope.Ciphertext) > maximumSAMLSPKeyCiphertextBytes {
		return nil, ErrInvalidEncryptedSAMLSPKey
	}
	defer clearVersionKey(&keysForVersion)
	aead, err := newSAMLSecretAEAD(keysForVersion.samlSPKey)
	if err != nil {
		return nil, ErrInvalidEncryptedSAMLSPKey
	}
	aad := samlSPKeyAAD(context, envelope.KeyVersion)
	plaintext, err := aead.Open(nil, envelope.Nonce[:], envelope.Ciphertext, aad)
	clear(aad)
	if err != nil || len(plaintext) < 1 || len(plaintext) > maximumSAMLSPKeyPlaintextBytes {
		clear(plaintext)
		return nil, ErrInvalidEncryptedSAMLSPKey
	}
	return plaintext, nil
}

// EncryptDirectPlatformSAMLSPKey protects a platform-owned PKCS#8 document.
// Its AAD purpose and shape are disjoint from tenant-owned SP keys and carry
// no synthetic tenant or binding identifiers.
func (k Keyring) EncryptDirectPlatformSAMLSPKey(
	context DirectPlatformSAMLSPKeyContext,
	plaintext []byte,
) (SAMLSPKeyEnvelope, error) {
	if validateDirectPlatformSAMLSPKeyContext(context) != nil || len(plaintext) < 1 ||
		len(plaintext) > maximumSAMLSPKeyPlaintextBytes {
		return SAMLSPKeyEnvelope{}, ErrInvalidEncryptedSAMLSPKey
	}
	keysForVersion, exists := k.keys[k.activeVersion]
	if !exists || k.random == nil {
		return SAMLSPKeyEnvelope{}, ErrInvalidKeyring
	}
	defer clearVersionKey(&keysForVersion)
	aead, err := newSAMLSecretAEAD(keysForVersion.samlSPKey)
	if err != nil {
		return SAMLSPKeyEnvelope{}, ErrInvalidKeyring
	}
	nonce, err := samlSecretNonce(k.random)
	if err != nil {
		return SAMLSPKeyEnvelope{}, err
	}
	aad := directPlatformSAMLSPKeyAAD(context, k.activeVersion)
	ciphertext := aead.Seal(nil, nonce[:], plaintext, aad)
	clear(aad)
	return SAMLSPKeyEnvelope{KeyVersion: k.activeVersion, Nonce: nonce, Ciphertext: ciphertext}, nil
}

// DecryptDirectPlatformSAMLSPKey authenticates the exact platform provider,
// immutable key row, key revision, and direct-platform purpose.
func (k Keyring) DecryptDirectPlatformSAMLSPKey(
	context DirectPlatformSAMLSPKeyContext,
	envelope SAMLSPKeyEnvelope,
) ([]byte, error) {
	if validateDirectPlatformSAMLSPKeyContext(context) != nil {
		return nil, ErrInvalidEncryptedSAMLSPKey
	}
	keysForVersion, exists := k.keys[envelope.KeyVersion]
	if !exists || len(envelope.Ciphertext) <= samlSecretTagBytes ||
		len(envelope.Ciphertext) > maximumSAMLSPKeyCiphertextBytes {
		return nil, ErrInvalidEncryptedSAMLSPKey
	}
	defer clearVersionKey(&keysForVersion)
	aead, err := newSAMLSecretAEAD(keysForVersion.samlSPKey)
	if err != nil {
		return nil, ErrInvalidEncryptedSAMLSPKey
	}
	aad := directPlatformSAMLSPKeyAAD(context, envelope.KeyVersion)
	plaintext, err := aead.Open(nil, envelope.Nonce[:], envelope.Ciphertext, aad)
	clear(aad)
	if err != nil || len(plaintext) < 1 || len(plaintext) > maximumSAMLSPKeyPlaintextBytes {
		clear(plaintext)
		return nil, ErrInvalidEncryptedSAMLSPKey
	}
	return plaintext, nil
}

func newSAMLSecretAEAD(key [derivedKeyBytes]byte) (cipher.AEAD, error) {
	defer clear(key[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || aead.NonceSize() != samlSecretNonceBytes {
		return nil, errors.New("initialize SAML secret encryption")
	}
	return aead, nil
}

func samlSecretNonce(random io.Reader) ([samlSecretNonceBytes]byte, error) {
	var nonce [samlSecretNonceBytes]byte
	if _, err := io.ReadFull(random, nonce[:]); err != nil {
		clear(nonce[:])
		return nonce, errors.New("generate SAML secret nonce")
	}
	return nonce, nil
}

func samlSPKeyAAD(context SAMLSPKeyContext, version int16) []byte {
	aad := make([]byte, 0, 256)
	aad = appendTypedField(aad, fieldSchema, []byte(samlSecretAADSchema))
	aad = appendTypedField(aad, fieldPurpose, []byte(samlSPKeyAADPurpose))
	aad = appendProviderContext(aad, context.Provider)
	aad = appendTypedField(aad, fieldBindingID, context.BindingID[:])
	aad = appendTypedField(aad, fieldRowID, context.KeyID[:])
	revision := [4]byte{}
	binary.BigEndian.PutUint32(revision[:], context.KeyRevision)
	aad = appendTypedField(aad, fieldRevision, revision[:])
	aad = appendTypedField(aad, fieldFormat, []byte(samlSecretEncryptionProfile))
	keyVersion := [2]byte{}
	binary.BigEndian.PutUint16(keyVersion[:], uint16(version))
	return appendTypedField(aad, fieldKeyVersion, keyVersion[:])
}

func directPlatformSAMLSPKeyAAD(context DirectPlatformSAMLSPKeyContext, version int16) []byte {
	aad := make([]byte, 0, 256)
	aad = appendTypedField(aad, fieldSchema, []byte(samlSecretAADSchema))
	aad = appendTypedField(aad, fieldPurpose, []byte(directPlatformSAMLSPKeyPurpose))
	aad = appendProviderContext(aad, context.Provider)
	aad = appendTypedField(aad, fieldRowID, context.KeyID[:])
	revision := [8]byte{}
	binary.BigEndian.PutUint64(revision[:], context.KeyRevision)
	aad = appendTypedField(aad, fieldRevision, revision[:])
	aad = appendTypedField(aad, fieldFormat, []byte(samlSecretEncryptionProfile))
	keyVersion := [2]byte{}
	binary.BigEndian.PutUint16(keyVersion[:], uint16(version))
	return appendTypedField(aad, fieldKeyVersion, keyVersion[:])
}
