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
	samlSessionMaterialNonceBytes     = 12
	samlSessionMaterialTagBytes       = 16
	maximumSAMLSessionMaterialBytes   = 16*1024 - samlSessionMaterialNonceBytes - samlSessionMaterialTagBytes
	maximumSAMLSessionCiphertextBytes = maximumSAMLSessionMaterialBytes + samlSessionMaterialTagBytes
	samlSessionMaterialAADSchema      = "periapsis/identity/aad/v1"
	samlSessionMaterialAADPurpose     = "saml-session-material"
	directPlatformSAMLSessionPurpose  = "saml-platform-direct-session-material"
	samlSessionMaterialProfile        = "aes-256-gcm"
)

// ErrInvalidEncryptedSAMLSessionMaterial deliberately combines malformed
// material, an invalid anchor, an unknown key version, and authentication
// failure so callers cannot use this boundary as an oracle.
var ErrInvalidEncryptedSAMLSessionMaterial = errors.New("invalid encrypted SAML session material")

// SAMLSessionMaterialEnvelope is stored as nonce || ciphertext by the
// persistence adapter. The plaintext is an adapter-owned canonical encoding
// of NameID, NameID format, and SessionIndex.
type SAMLSessionMaterialEnvelope struct {
	KeyVersion int16
	Nonce      [samlSessionMaterialNonceBytes]byte
	Ciphertext []byte
}

func (envelope SAMLSessionMaterialEnvelope) String() string {
	return fmt.Sprintf(
		"identity.SAMLSessionMaterialEnvelope{keyVersion:%d,ciphertextBytes:%d,nonce:[REDACTED],ciphertext:[REDACTED]}",
		envelope.KeyVersion, len(envelope.Ciphertext),
	)
}

func (envelope SAMLSessionMaterialEnvelope) GoString() string { return envelope.String() }

// EncryptSAMLSessionMaterial protects one bounded canonical material document
// with the active, purpose-separated identity key.
func (k Keyring) EncryptSAMLSessionMaterial(
	context SAMLSessionMaterialContext,
	plaintext []byte,
) (SAMLSessionMaterialEnvelope, error) {
	if validateSAMLSessionMaterialContext(context) != nil || len(plaintext) < 1 ||
		len(plaintext) > maximumSAMLSessionMaterialBytes {
		return SAMLSessionMaterialEnvelope{}, ErrInvalidEncryptedSAMLSessionMaterial
	}
	keysForVersion, exists := k.keys[k.activeVersion]
	if !exists || k.random == nil {
		return SAMLSessionMaterialEnvelope{}, ErrInvalidKeyring
	}
	defer clearVersionKey(&keysForVersion)
	aead, err := newSAMLSessionMaterialAEAD(keysForVersion.samlSession)
	if err != nil {
		return SAMLSessionMaterialEnvelope{}, ErrInvalidKeyring
	}
	nonce, err := samlSessionMaterialNonce(k.random)
	if err != nil {
		return SAMLSessionMaterialEnvelope{}, err
	}
	aad := samlSessionMaterialAAD(context, k.activeVersion)
	ciphertext := aead.Seal(nil, nonce[:], plaintext, aad)
	clear(aad)
	return SAMLSessionMaterialEnvelope{
		KeyVersion: k.activeVersion,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}

// DecryptSAMLSessionMaterial authenticates the immutable material-row anchor
// and returns a fresh plaintext slice owned by the caller.
func (k Keyring) DecryptSAMLSessionMaterial(
	context SAMLSessionMaterialContext,
	envelope SAMLSessionMaterialEnvelope,
) ([]byte, error) {
	if validateSAMLSessionMaterialContext(context) != nil {
		return nil, ErrInvalidEncryptedSAMLSessionMaterial
	}
	keysForVersion, exists := k.keys[envelope.KeyVersion]
	if !exists || len(envelope.Ciphertext) <= samlSessionMaterialTagBytes ||
		len(envelope.Ciphertext) > maximumSAMLSessionCiphertextBytes {
		return nil, ErrInvalidEncryptedSAMLSessionMaterial
	}
	defer clearVersionKey(&keysForVersion)
	aead, err := newSAMLSessionMaterialAEAD(keysForVersion.samlSession)
	if err != nil {
		return nil, ErrInvalidEncryptedSAMLSessionMaterial
	}
	aad := samlSessionMaterialAAD(context, envelope.KeyVersion)
	plaintext, err := aead.Open(nil, envelope.Nonce[:], envelope.Ciphertext, aad)
	clear(aad)
	if err != nil || len(plaintext) < 1 || len(plaintext) > maximumSAMLSessionMaterialBytes {
		clear(plaintext)
		return nil, ErrInvalidEncryptedSAMLSessionMaterial
	}
	return plaintext, nil
}

// EncryptDirectPlatformSAMLSessionMaterial protects direct-platform logout
// provenance without inventing a tenant admission. The exact platform-login
// authority revision is authenticated alongside the immutable material row.
func (k Keyring) EncryptDirectPlatformSAMLSessionMaterial(
	context DirectPlatformSAMLSessionMaterialContext,
	plaintext []byte,
) (SAMLSessionMaterialEnvelope, error) {
	if validateDirectPlatformSAMLSessionMaterialContext(context) != nil || len(plaintext) < 1 ||
		len(plaintext) > maximumSAMLSessionMaterialBytes {
		return SAMLSessionMaterialEnvelope{}, ErrInvalidEncryptedSAMLSessionMaterial
	}
	keysForVersion, exists := k.keys[k.activeVersion]
	if !exists || k.random == nil {
		return SAMLSessionMaterialEnvelope{}, ErrInvalidKeyring
	}
	defer clearVersionKey(&keysForVersion)
	aead, err := newSAMLSessionMaterialAEAD(keysForVersion.samlSession)
	if err != nil {
		return SAMLSessionMaterialEnvelope{}, ErrInvalidKeyring
	}
	nonce, err := samlSessionMaterialNonce(k.random)
	if err != nil {
		return SAMLSessionMaterialEnvelope{}, err
	}
	aad := directPlatformSAMLSessionMaterialAAD(context, k.activeVersion)
	ciphertext := aead.Seal(nil, nonce[:], plaintext, aad)
	clear(aad)
	return SAMLSessionMaterialEnvelope{
		KeyVersion: k.activeVersion,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}

// DecryptDirectPlatformSAMLSessionMaterial authenticates the exact platform
// provider, immutable material row, authority revision, and direct purpose.
func (k Keyring) DecryptDirectPlatformSAMLSessionMaterial(
	context DirectPlatformSAMLSessionMaterialContext,
	envelope SAMLSessionMaterialEnvelope,
) ([]byte, error) {
	if validateDirectPlatformSAMLSessionMaterialContext(context) != nil {
		return nil, ErrInvalidEncryptedSAMLSessionMaterial
	}
	keysForVersion, exists := k.keys[envelope.KeyVersion]
	if !exists || len(envelope.Ciphertext) <= samlSessionMaterialTagBytes ||
		len(envelope.Ciphertext) > maximumSAMLSessionCiphertextBytes {
		return nil, ErrInvalidEncryptedSAMLSessionMaterial
	}
	defer clearVersionKey(&keysForVersion)
	aead, err := newSAMLSessionMaterialAEAD(keysForVersion.samlSession)
	if err != nil {
		return nil, ErrInvalidEncryptedSAMLSessionMaterial
	}
	aad := directPlatformSAMLSessionMaterialAAD(context, envelope.KeyVersion)
	plaintext, err := aead.Open(nil, envelope.Nonce[:], envelope.Ciphertext, aad)
	clear(aad)
	if err != nil || len(plaintext) < 1 || len(plaintext) > maximumSAMLSessionMaterialBytes {
		clear(plaintext)
		return nil, ErrInvalidEncryptedSAMLSessionMaterial
	}
	return plaintext, nil
}

func newSAMLSessionMaterialAEAD(key [derivedKeyBytes]byte) (cipher.AEAD, error) {
	defer clear(key[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || aead.NonceSize() != samlSessionMaterialNonceBytes {
		return nil, errors.New("initialize SAML session material encryption")
	}
	return aead, nil
}

func samlSessionMaterialNonce(random io.Reader) ([samlSessionMaterialNonceBytes]byte, error) {
	var nonce [samlSessionMaterialNonceBytes]byte
	if _, err := io.ReadFull(random, nonce[:]); err != nil {
		clear(nonce[:])
		return nonce, errors.New("generate SAML session material nonce")
	}
	return nonce, nil
}

func samlSessionMaterialAAD(context SAMLSessionMaterialContext, version int16) []byte {
	aad := make([]byte, 0, 256)
	aad = appendTypedField(aad, fieldSchema, []byte(samlSessionMaterialAADSchema))
	aad = appendTypedField(aad, fieldPurpose, []byte(samlSessionMaterialAADPurpose))
	aad = appendProviderContext(aad, context.Provider)
	aad = appendTypedField(aad, fieldBindingID, context.BindingID[:])
	aad = appendTypedField(aad, fieldRowID, context.MaterialID[:])
	aad = appendTypedField(aad, fieldFormat, []byte(samlSessionMaterialProfile))
	keyVersion := [2]byte{}
	binary.BigEndian.PutUint16(keyVersion[:], uint16(version))
	return appendTypedField(aad, fieldKeyVersion, keyVersion[:])
}

func directPlatformSAMLSessionMaterialAAD(
	context DirectPlatformSAMLSessionMaterialContext,
	version int16,
) []byte {
	aad := make([]byte, 0, 256)
	aad = appendTypedField(aad, fieldSchema, []byte(samlSessionMaterialAADSchema))
	aad = appendTypedField(aad, fieldPurpose, []byte(directPlatformSAMLSessionPurpose))
	aad = appendProviderContext(aad, context.Provider)
	aad = appendTypedField(aad, fieldRowID, context.MaterialID[:])
	revision := [8]byte{}
	binary.BigEndian.PutUint64(revision[:], context.PlatformLoginRevision)
	aad = appendTypedField(aad, fieldRevision, revision[:])
	aad = appendTypedField(aad, fieldFormat, []byte(samlSessionMaterialProfile))
	keyVersion := [2]byte{}
	binary.BigEndian.PutUint16(keyVersion[:], uint16(version))
	return appendTypedField(aad, fieldKeyVersion, keyVersion[:])
}
