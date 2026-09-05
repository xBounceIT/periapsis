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
	oidcSessionTokenNonceBytes    = 12
	oidcSessionTokenTagBytes      = 16
	maximumOIDCSessionTokenBytes  = 256 * 1024
	maximumOIDCSessionCipherBytes = maximumOIDCSessionTokenBytes + oidcSessionTokenTagBytes
	oidcSessionTokenAADSchema     = "periapsis/identity/aad/v1"
	oidcIDTokenAADPurpose         = "oidc-id-token"
	oidcRefreshTokenAADPurpose    = "oidc-refresh-token"
	oidcSessionTokenCipherProfile = "aes-256-gcm"
)

// ErrInvalidEncryptedOIDCSessionToken deliberately combines malformed
// material, invalid authenticated context, unknown key versions, and
// authentication failures so callers cannot use this boundary as an oracle.
var ErrInvalidEncryptedOIDCSessionToken = errors.New("invalid encrypted OIDC session token")

// OIDCSessionTokenEnvelope is persisted as nonce plus ciphertext. It never
// exposes plaintext through formatting and is safe to carry across repository
// boundaries.
type OIDCSessionTokenEnvelope struct {
	KeyVersion int16
	Nonce      [oidcSessionTokenNonceBytes]byte
	Ciphertext []byte
}

func (envelope OIDCSessionTokenEnvelope) String() string {
	return fmt.Sprintf(
		"identity.OIDCSessionTokenEnvelope{keyVersion:%d,ciphertextBytes:%d,nonce:[REDACTED],ciphertext:[REDACTED]}",
		envelope.KeyVersion, len(envelope.Ciphertext),
	)
}

func (envelope OIDCSessionTokenEnvelope) GoString() string { return envelope.String() }

// EncryptOIDCIDToken protects the verified ID token used only as an
// RP-initiated logout hint. Its key and AAD purpose cannot be substituted for
// refresh-token material.
func (k Keyring) EncryptOIDCIDToken(
	context OIDCSessionMaterialContext,
	plaintext []byte,
) (OIDCSessionTokenEnvelope, error) {
	return k.encryptOIDCSessionToken(
		context, plaintext, oidcIDTokenAADPurpose,
		func(keys versionKeys) [derivedKeyBytes]byte { return keys.oidcIDToken },
	)
}

func (k Keyring) DecryptOIDCIDToken(
	context OIDCSessionMaterialContext,
	envelope OIDCSessionTokenEnvelope,
) ([]byte, error) {
	return k.decryptOIDCSessionToken(
		context, envelope, oidcIDTokenAADPurpose,
		func(keys versionKeys) [derivedKeyBytes]byte { return keys.oidcIDToken },
	)
}

// EncryptOIDCRefreshToken protects optional rotation material under an
// independent derived key and authenticated purpose.
func (k Keyring) EncryptOIDCRefreshToken(
	context OIDCSessionMaterialContext,
	plaintext []byte,
) (OIDCSessionTokenEnvelope, error) {
	return k.encryptOIDCSessionToken(
		context, plaintext, oidcRefreshTokenAADPurpose,
		func(keys versionKeys) [derivedKeyBytes]byte { return keys.oidcRefreshToken },
	)
}

func (k Keyring) DecryptOIDCRefreshToken(
	context OIDCSessionMaterialContext,
	envelope OIDCSessionTokenEnvelope,
) ([]byte, error) {
	return k.decryptOIDCSessionToken(
		context, envelope, oidcRefreshTokenAADPurpose,
		func(keys versionKeys) [derivedKeyBytes]byte { return keys.oidcRefreshToken },
	)
}

func (k Keyring) encryptOIDCSessionToken(
	context OIDCSessionMaterialContext,
	plaintext []byte,
	purpose string,
	selectKey func(versionKeys) [derivedKeyBytes]byte,
) (OIDCSessionTokenEnvelope, error) {
	if validateOIDCSessionMaterialContext(context) != nil || len(plaintext) < 1 ||
		len(plaintext) > maximumOIDCSessionTokenBytes || selectKey == nil {
		return OIDCSessionTokenEnvelope{}, ErrInvalidEncryptedOIDCSessionToken
	}
	keysForVersion, exists := k.keys[k.activeVersion]
	if !exists || k.random == nil {
		return OIDCSessionTokenEnvelope{}, ErrInvalidKeyring
	}
	defer clearVersionKey(&keysForVersion)
	key := selectKey(keysForVersion)
	aead, err := newOIDCSessionTokenAEAD(key)
	if err != nil {
		return OIDCSessionTokenEnvelope{}, ErrInvalidKeyring
	}
	nonce, err := oidcSessionTokenNonce(k.random)
	if err != nil {
		return OIDCSessionTokenEnvelope{}, err
	}
	aad := oidcSessionTokenAAD(context, purpose, k.activeVersion)
	ciphertext := aead.Seal(nil, nonce[:], plaintext, aad)
	clear(aad)
	return OIDCSessionTokenEnvelope{
		KeyVersion: k.activeVersion,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}

func (k Keyring) decryptOIDCSessionToken(
	context OIDCSessionMaterialContext,
	envelope OIDCSessionTokenEnvelope,
	purpose string,
	selectKey func(versionKeys) [derivedKeyBytes]byte,
) ([]byte, error) {
	if validateOIDCSessionMaterialContext(context) != nil || selectKey == nil {
		return nil, ErrInvalidEncryptedOIDCSessionToken
	}
	keysForVersion, exists := k.keys[envelope.KeyVersion]
	if !exists || len(envelope.Ciphertext) <= oidcSessionTokenTagBytes ||
		len(envelope.Ciphertext) > maximumOIDCSessionCipherBytes {
		return nil, ErrInvalidEncryptedOIDCSessionToken
	}
	defer clearVersionKey(&keysForVersion)
	key := selectKey(keysForVersion)
	aead, err := newOIDCSessionTokenAEAD(key)
	if err != nil {
		return nil, ErrInvalidEncryptedOIDCSessionToken
	}
	aad := oidcSessionTokenAAD(context, purpose, envelope.KeyVersion)
	plaintext, err := aead.Open(nil, envelope.Nonce[:], envelope.Ciphertext, aad)
	clear(aad)
	if err != nil || len(plaintext) < 1 || len(plaintext) > maximumOIDCSessionTokenBytes {
		clear(plaintext)
		return nil, ErrInvalidEncryptedOIDCSessionToken
	}
	return plaintext, nil
}

func newOIDCSessionTokenAEAD(key [derivedKeyBytes]byte) (cipher.AEAD, error) {
	defer clear(key[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || aead.NonceSize() != oidcSessionTokenNonceBytes {
		return nil, errors.New("initialize OIDC session token encryption")
	}
	return aead, nil
}

func oidcSessionTokenNonce(random io.Reader) ([oidcSessionTokenNonceBytes]byte, error) {
	var nonce [oidcSessionTokenNonceBytes]byte
	if _, err := io.ReadFull(random, nonce[:]); err != nil {
		clear(nonce[:])
		return nonce, errors.New("generate OIDC session token nonce")
	}
	return nonce, nil
}

func oidcSessionTokenAAD(
	context OIDCSessionMaterialContext,
	purpose string,
	version int16,
) []byte {
	aad := make([]byte, 0, 256)
	aad = appendTypedField(aad, fieldSchema, []byte(oidcSessionTokenAADSchema))
	aad = appendTypedField(aad, fieldPurpose, []byte(purpose))
	aad = appendProviderContext(aad, context.Provider)
	aad = appendTypedField(aad, fieldTenantID, context.TenantID[:])
	aad = appendTypedField(aad, fieldBindingID, context.BindingID[:])
	aad = appendTypedField(aad, fieldRowID, context.MaterialID[:])
	aad = appendTypedField(aad, fieldFormat, []byte(oidcSessionTokenCipherProfile))
	keyVersion := [2]byte{}
	binary.BigEndian.PutUint16(keyVersion[:], uint16(version))
	return appendTypedField(aad, fieldKeyVersion, keyVersion[:])
}
