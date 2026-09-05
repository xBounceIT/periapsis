package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	mfaSecretNonceBytes           = 12
	mfaSecretTagBytes             = 16
	maximumMFATOTPSecretBytes     = 256
	maximumMFATOTPCiphertextBytes = maximumMFATOTPSecretBytes + mfaSecretTagBytes
	mfaAADSchema                  = "periapsis/identity/aad/v1"
	mfaTOTPSecretAADPurpose       = "mfa-totp-secret"
	mfaRecoveryDigestPurpose      = "mfa-recovery-code"
	mfaSecretEncryptionProfile    = "aes-256-gcm"
)

var (
	ErrInvalidEncryptedMFATOTPSecret = errors.New("invalid encrypted MFA TOTP secret")
	ErrInvalidMFARecoveryCode        = errors.New("invalid MFA recovery code")
)

// MFATOTPContext pins a TOTP ciphertext to one tenant-scoped factor row.
type MFATOTPContext struct {
	TenantID EntityID
	UserID   EntityID
	FactorID EntityID
}

// MFARecoveryCodeContext pins a recovery digest to one immutable recovery set.
type MFARecoveryCodeContext struct {
	TenantID EntityID
	UserID   EntityID
	SetID    EntityID
}

type MFATOTPEnvelope struct {
	KeyVersion int16
	Nonce      [mfaSecretNonceBytes]byte
	Ciphertext []byte
}

func (envelope MFATOTPEnvelope) String() string {
	return fmt.Sprintf("identity.MFATOTPEnvelope{keyVersion:%d,ciphertextBytes:%d,material:[REDACTED]}",
		envelope.KeyVersion, len(envelope.Ciphertext))
}

func (envelope MFATOTPEnvelope) GoString() string { return envelope.String() }

func (k Keyring) EncryptMFATOTPSecret(context MFATOTPContext, plaintext []byte) (MFATOTPEnvelope, error) {
	if !validMFATOTPContext(context) || len(plaintext) < 1 || len(plaintext) > maximumMFATOTPSecretBytes {
		return MFATOTPEnvelope{}, ErrInvalidEncryptedMFATOTPSecret
	}
	keysForVersion, exists := k.keys[k.activeVersion]
	if !exists || k.random == nil {
		return MFATOTPEnvelope{}, ErrInvalidKeyring
	}
	defer clearVersionKey(&keysForVersion)
	aead, err := newMFASecretAEAD(keysForVersion.mfaTOTPSecret)
	if err != nil {
		return MFATOTPEnvelope{}, ErrInvalidKeyring
	}
	var nonce [mfaSecretNonceBytes]byte
	if _, err := io.ReadFull(k.random, nonce[:]); err != nil {
		clear(nonce[:])
		return MFATOTPEnvelope{}, errors.New("generate MFA TOTP nonce")
	}
	aad := mfaTOTPSecretAAD(context, k.activeVersion)
	ciphertext := aead.Seal(nil, nonce[:], plaintext, aad)
	clear(aad)
	return MFATOTPEnvelope{KeyVersion: k.activeVersion, Nonce: nonce, Ciphertext: ciphertext}, nil
}

func (k Keyring) DecryptMFATOTPSecret(context MFATOTPContext, envelope MFATOTPEnvelope) ([]byte, error) {
	if !validMFATOTPContext(context) {
		return nil, ErrInvalidEncryptedMFATOTPSecret
	}
	keysForVersion, exists := k.keys[envelope.KeyVersion]
	if !exists || len(envelope.Ciphertext) <= mfaSecretTagBytes ||
		len(envelope.Ciphertext) > maximumMFATOTPCiphertextBytes {
		return nil, ErrInvalidEncryptedMFATOTPSecret
	}
	defer clearVersionKey(&keysForVersion)
	aead, err := newMFASecretAEAD(keysForVersion.mfaTOTPSecret)
	if err != nil {
		return nil, ErrInvalidEncryptedMFATOTPSecret
	}
	aad := mfaTOTPSecretAAD(context, envelope.KeyVersion)
	plaintext, err := aead.Open(nil, envelope.Nonce[:], envelope.Ciphertext, aad)
	clear(aad)
	if err != nil || len(plaintext) < 1 || len(plaintext) > maximumMFATOTPSecretBytes {
		clear(plaintext)
		return nil, ErrInvalidEncryptedMFATOTPSecret
	}
	return plaintext, nil
}

// DigestMFARecoveryCode produces a context-bound one-way digest under an exact
// retained key version. Callers canonicalize and clear code bytes.
func (k Keyring) DigestMFARecoveryCode(
	context MFARecoveryCodeContext,
	keyVersion int16,
	canonicalCode []byte,
) ([sha256.Size]byte, error) {
	if !validMFARecoveryContext(context) || !validCanonicalRecoveryCode(canonicalCode) {
		return [sha256.Size]byte{}, ErrInvalidMFARecoveryCode
	}
	keysForVersion, exists := k.keys[keyVersion]
	if !exists {
		return [sha256.Size]byte{}, ErrInvalidMFARecoveryCode
	}
	defer clearVersionKey(&keysForVersion)
	message := mfaRecoveryDigestPrefix(context, keyVersion)
	message = appendTypedField(message, fieldSubjectValue, canonicalCode)
	mac := hmac.New(sha256.New, keysForVersion.mfaRecoveryCode[:])
	_, _ = mac.Write(message)
	clear(message)
	value := mac.Sum(nil)
	defer clear(value)
	var result [sha256.Size]byte
	copy(result[:], value)
	return result, nil
}

func validCanonicalRecoveryCode(value []byte) bool {
	if len(value) != 52 {
		return false
	}
	for _, character := range value {
		if character >= 'A' && character <= 'Z' || character >= '2' && character <= '7' {
			continue
		}
		return false
	}
	return true
}

func newMFASecretAEAD(key [derivedKeyBytes]byte) (cipher.AEAD, error) {
	defer clear(key[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func mfaTOTPSecretAAD(context MFATOTPContext, version int16) []byte {
	aad := make([]byte, 0, 192)
	aad = appendTypedField(aad, fieldSchema, []byte(mfaAADSchema))
	aad = appendTypedField(aad, fieldPurpose, []byte(mfaTOTPSecretAADPurpose))
	aad = appendTypedField(aad, fieldTenantID, context.TenantID[:])
	aad = appendTypedField(aad, fieldUserID, context.UserID[:])
	aad = appendTypedField(aad, fieldFactorID, context.FactorID[:])
	aad = appendTypedField(aad, fieldFormat, []byte(mfaSecretEncryptionProfile))
	versionBytes := [2]byte{}
	binary.BigEndian.PutUint16(versionBytes[:], uint16(version))
	return appendTypedField(aad, fieldKeyVersion, versionBytes[:])
}

func mfaRecoveryDigestPrefix(context MFARecoveryCodeContext, version int16) []byte {
	message := make([]byte, 0, 192)
	message = appendTypedField(message, fieldSchema, []byte(mfaAADSchema))
	message = appendTypedField(message, fieldPurpose, []byte(mfaRecoveryDigestPurpose))
	message = appendTypedField(message, fieldTenantID, context.TenantID[:])
	message = appendTypedField(message, fieldUserID, context.UserID[:])
	message = appendTypedField(message, fieldSetID, context.SetID[:])
	versionBytes := [2]byte{}
	binary.BigEndian.PutUint16(versionBytes[:], uint16(version))
	return appendTypedField(message, fieldKeyVersion, versionBytes[:])
}

func validMFATOTPContext(context MFATOTPContext) bool {
	return context.TenantID != (EntityID{}) && context.UserID != (EntityID{}) &&
		context.FactorID != (EntityID{}) && context.TenantID != context.UserID &&
		context.TenantID != context.FactorID && context.UserID != context.FactorID
}

func validMFARecoveryContext(context MFARecoveryCodeContext) bool {
	return context.TenantID != (EntityID{}) && context.UserID != (EntityID{}) &&
		context.SetID != (EntityID{}) && context.TenantID != context.UserID &&
		context.TenantID != context.SetID && context.UserID != context.SetID
}
