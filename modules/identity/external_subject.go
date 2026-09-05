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
	externalSubjectNonceBytes             = 12
	externalSubjectTagBytes               = 16
	maximumExternalSubjectCiphertextBytes = maximumCanonicalSubjectBytes + externalSubjectTagBytes
	externalSubjectAADSchema              = "periapsis/identity/aad/v1"
	externalSubjectAADPurpose             = "external-subject"
	externalSubjectEncryptionProfile      = "aes-256-gcm"
)

// ErrInvalidEncryptedExternalSubject combines malformed envelopes, unknown
// keys, context/format mismatches, and authentication failures.
var ErrInvalidEncryptedExternalSubject = errors.New("invalid encrypted external subject")

// ExternalSubjectEnvelope is the authenticated form persisted beside an
// external identity. Format is authenticated in AAD and cannot be changed to
// reinterpret the same plaintext bytes.
type ExternalSubjectEnvelope struct {
	KeyVersion int16
	Format     SubjectFormat
	Nonce      [externalSubjectNonceBytes]byte
	Ciphertext []byte
}

func (envelope ExternalSubjectEnvelope) String() string {
	return fmt.Sprintf(
		"identity.ExternalSubjectEnvelope{keyVersion:%d,format:%d,ciphertextBytes:%d,nonce:[REDACTED],ciphertext:[REDACTED]}",
		envelope.KeyVersion, envelope.Format, len(envelope.Ciphertext),
	)
}
func (envelope ExternalSubjectEnvelope) GoString() string { return envelope.String() }

// EncryptExternalSubject encrypts canonical immutable-subject bytes with the
// active write key and an operation-specific derivative.
func (k Keyring) EncryptExternalSubject(
	context ExternalSubjectContext,
	subject Subject,
) (ExternalSubjectEnvelope, error) {
	if validateExternalSubjectContext(context) != nil || !validCanonicalSubject(subject) {
		return ExternalSubjectEnvelope{}, ErrInvalidSubject
	}
	keysForVersion, exists := k.keys[k.activeVersion]
	if !exists || k.random == nil {
		return ExternalSubjectEnvelope{}, ErrInvalidKeyring
	}
	defer clearVersionKey(&keysForVersion)
	aead, err := newExternalSubjectAEAD(keysForVersion.externalSubject)
	if err != nil {
		return ExternalSubjectEnvelope{}, ErrInvalidKeyring
	}
	var nonce [externalSubjectNonceBytes]byte
	if _, err := io.ReadFull(k.random, nonce[:]); err != nil {
		clear(nonce[:])
		return ExternalSubjectEnvelope{}, errors.New("generate external-subject nonce")
	}
	aad := externalSubjectAAD(context, subject.format, k.activeVersion)
	ciphertext := aead.Seal(nil, nonce[:], subject.value, aad)
	clear(aad)
	return ExternalSubjectEnvelope{
		KeyVersion: k.activeVersion, Format: subject.format,
		Nonce: nonce, Ciphertext: ciphertext,
	}, nil
}

// DecryptExternalSubject authenticates and reconstructs one canonical Subject.
// The returned Subject retains private bytes and preserves redacted formatting.
func (k Keyring) DecryptExternalSubject(
	context ExternalSubjectContext,
	envelope ExternalSubjectEnvelope,
) (Subject, error) {
	if validateExternalSubjectContext(context) != nil || !knownSubjectFormat(envelope.Format) {
		return Subject{}, ErrInvalidEncryptedExternalSubject
	}
	keysForVersion, exists := k.keys[envelope.KeyVersion]
	if !exists || len(envelope.Ciphertext) <= externalSubjectTagBytes ||
		len(envelope.Ciphertext) > maximumExternalSubjectCiphertextBytes {
		return Subject{}, ErrInvalidEncryptedExternalSubject
	}
	defer clearVersionKey(&keysForVersion)
	aead, err := newExternalSubjectAEAD(keysForVersion.externalSubject)
	if err != nil || aead.Overhead() != externalSubjectTagBytes {
		return Subject{}, ErrInvalidEncryptedExternalSubject
	}
	aad := externalSubjectAAD(context, envelope.Format, envelope.KeyVersion)
	plaintext, err := aead.Open(nil, envelope.Nonce[:], envelope.Ciphertext, aad)
	clear(aad)
	if err != nil {
		clear(plaintext)
		return Subject{}, ErrInvalidEncryptedExternalSubject
	}
	subject := Subject{format: envelope.Format, value: plaintext}
	if !validCanonicalSubject(subject) {
		clear(plaintext)
		return Subject{}, ErrInvalidEncryptedExternalSubject
	}
	return subject, nil
}

func knownSubjectFormat(value SubjectFormat) bool {
	switch value {
	case ADObjectGUIDSubject, EntryUUIDSubject, UTF8ExactSubject, UTF8CaseFoldSubject:
		return true
	default:
		return false
	}
}

func newExternalSubjectAEAD(key [derivedKeyBytes]byte) (cipher.AEAD, error) {
	defer clear(key[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || aead.NonceSize() != externalSubjectNonceBytes {
		return nil, errors.New("initialize external-subject encryption")
	}
	return aead, nil
}

func externalSubjectAAD(
	context ExternalSubjectContext,
	format SubjectFormat,
	version int16,
) []byte {
	aad := make([]byte, 0, 192)
	aad = appendTypedField(aad, fieldSchema, []byte(externalSubjectAADSchema))
	aad = appendTypedField(aad, fieldPurpose, []byte(externalSubjectAADPurpose))
	aad = appendProviderContext(aad, context.Provider)
	aad = appendTypedField(aad, fieldRowID, context.ExternalIdentityID[:])
	aad = appendTypedField(aad, fieldSubjectFormat, []byte{byte(format)})
	aad = appendTypedField(aad, fieldFormat, []byte(externalSubjectEncryptionProfile))
	versionBytes := [2]byte{}
	binary.BigEndian.PutUint16(versionBytes[:], uint16(version))
	return appendTypedField(aad, fieldKeyVersion, versionBytes[:])
}
