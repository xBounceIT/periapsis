// Package serviceaccount implements tenant machine-principal domain boundaries.
package serviceaccount

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
)

const (
	credentialFormatPrefix            = "periapsis_api_v1"
	credentialFormatVersion     byte  = 1
	credentialLocatorBytes            = 16
	credentialSecretBytes             = 32
	credentialDigestBytes             = sha256.Size
	credentialSourceKeyBytes          = 32
	minimumCredentialTokenBytes       = len(credentialFormatPrefix) + 3 + 1 + 22 + 43
	maximumCredentialTokenBytes       = len(credentialFormatPrefix) + 3 + 5 + 22 + 43
	maximumKeyVersion           int16 = 32_767
)

var (
	// ErrInvalidCredential intentionally does not distinguish malformed tokens,
	// unknown key versions, or failed authentication.
	ErrInvalidCredential = errors.New("invalid API credential")
	credentialEncoding   = base64.RawURLEncoding.Strict()
)

// PresentedCredential contains only the bounded lookup and verification
// material needed by a bearer database entry point. Secret bytes are never
// exposed by this type.
type PresentedCredential struct {
	Locator    [credentialLocatorBytes]byte
	KeyVersion int16
	Digest     [credentialDigestBytes]byte
}

// IssuedCredential is returned exactly once by issue or rotation. Callers must
// keep Token out of caches, logs, telemetry, URLs, and persistent UI state.
type IssuedCredential struct {
	PresentedCredential
	Token string
}

// CredentialKeyring contains one active issuance key and every key retained for
// verification. Values are domain-separated HKDF outputs, not source keys.
type CredentialKeyring struct {
	activeVersion int16
	keys          map[int16][credentialDigestBytes]byte
	random        io.Reader
}

// NewCredentialKeyring validates and copies a versioned set of 256-bit source
// keys. The active version must be present.
func NewCredentialKeyring(activeVersion int16, sourceKeys map[int16][]byte) (CredentialKeyring, error) {
	return newCredentialKeyring(activeVersion, sourceKeys, rand.Reader)
}

func newCredentialKeyring(activeVersion int16, sourceKeys map[int16][]byte, random io.Reader) (CredentialKeyring, error) {
	if activeVersion < 1 || activeVersion > maximumKeyVersion {
		return CredentialKeyring{}, errors.New("active credential key version must be positive")
	}
	if len(sourceKeys) == 0 || len(sourceKeys) > 16 {
		return CredentialKeyring{}, errors.New("credential keyring must contain between 1 and 16 keys")
	}
	if random == nil {
		return CredentialKeyring{}, errors.New("credential random source is required")
	}
	keys := make(map[int16][credentialDigestBytes]byte, len(sourceKeys))
	for version, source := range sourceKeys {
		if version < 1 || version > maximumKeyVersion {
			clearCredentialVerificationKeys(keys)
			return CredentialKeyring{}, errors.New("credential key version must be positive")
		}
		if len(source) != credentialSourceKeyBytes {
			clearCredentialVerificationKeys(keys)
			return CredentialKeyring{}, errors.New("credential source keys must contain exactly 32 bytes")
		}
		sourceCopy := append([]byte(nil), source...)
		derived, err := hkdf.Key(
			sha256.New,
			sourceCopy,
			[]byte("periapsis/api-credential/hkdf-sha256/v1"),
			"periapsis/api-credential/hmac-sha256/v1/key/"+strconv.Itoa(int(version)),
			credentialDigestBytes,
		)
		clear(sourceCopy)
		if err != nil {
			clearCredentialVerificationKeys(keys)
			return CredentialKeyring{}, errors.New("derive credential verification key")
		}
		var key [credentialDigestBytes]byte
		copy(key[:], derived)
		clear(derived)
		keys[version] = key
		clear(key[:])
	}
	if _, exists := keys[activeVersion]; !exists {
		clearCredentialVerificationKeys(keys)
		return CredentialKeyring{}, errors.New("active credential key version is absent")
	}
	return CredentialKeyring{activeVersion: activeVersion, keys: keys, random: random}, nil
}

func clearCredentialVerificationKeys(keys map[int16][credentialDigestBytes]byte) {
	for version := range keys {
		keys[version] = [credentialDigestBytes]byte{}
	}
}

// ActiveVersion returns the only key version used for new credentials.
func (k CredentialKeyring) ActiveVersion() int16 {
	return k.activeVersion
}

// VerificationVersions returns a stable copy suitable for readiness reporting.
func (k CredentialKeyring) VerificationVersions() []int16 {
	versions := make([]int16, 0, len(k.keys))
	for version := range k.keys {
		versions = append(versions, version)
	}
	slices.Sort(versions)
	return versions
}

// MissingVersions reports the distinct live database versions that this
// replica cannot verify. Invalid versions are treated as missing.
func (k CredentialKeyring) MissingVersions(liveVersions []int16) []int16 {
	missingSet := make(map[int16]struct{})
	for _, version := range liveVersions {
		if _, exists := k.keys[version]; !exists {
			missingSet[version] = struct{}{}
		}
	}
	missing := make([]int16, 0, len(missingSet))
	for version := range missingSet {
		missing = append(missing, version)
	}
	slices.Sort(missing)
	return missing
}

// Issue generates one random 128-bit locator and one independent 256-bit
// secret, then returns their canonical textual envelope exactly once.
func (k CredentialKeyring) Issue() (IssuedCredential, error) {
	var locator [credentialLocatorBytes]byte
	if _, err := io.ReadFull(k.random, locator[:]); err != nil {
		return IssuedCredential{}, errors.New("generate API credential locator")
	}
	var secret [credentialSecretBytes]byte
	defer clear(secret[:])
	if _, err := io.ReadFull(k.random, secret[:]); err != nil {
		return IssuedCredential{}, errors.New("generate API credential secret")
	}
	token := encodeCredentialToken(k.activeVersion, &locator, &secret)
	digest, err := k.digest(k.activeVersion, locator, &secret)
	if err != nil {
		return IssuedCredential{}, err
	}
	return IssuedCredential{
		PresentedCredential: PresentedCredential{
			Locator: locator, KeyVersion: k.activeVersion, Digest: digest,
		},
		Token: token,
	}, nil
}

// ParseAndDigest validates the exact envelope and computes the digest used by
// the bounded database authenticator. Every rejection uses one public error.
func (k CredentialKeyring) ParseAndDigest(token string) (PresentedCredential, error) {
	if len(token) < minimumCredentialTokenBytes || len(token) > maximumCredentialTokenBytes {
		return PresentedCredential{}, ErrInvalidCredential
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != credentialFormatPrefix {
		return PresentedCredential{}, ErrInvalidCredential
	}
	version64, err := strconv.ParseInt(parts[1], 10, 16)
	if err != nil || version64 < 1 || strconv.FormatInt(version64, 10) != parts[1] {
		return PresentedCredential{}, ErrInvalidCredential
	}
	version := int16(version64)
	locatorBytes, err := credentialEncoding.DecodeString(parts[2])
	if err != nil || len(locatorBytes) != credentialLocatorBytes {
		return PresentedCredential{}, ErrInvalidCredential
	}
	secretBytes, err := credentialEncoding.DecodeString(parts[3])
	if err != nil || len(secretBytes) != credentialSecretBytes {
		clear(locatorBytes)
		clear(secretBytes)
		return PresentedCredential{}, ErrInvalidCredential
	}
	defer clear(locatorBytes)
	defer clear(secretBytes)
	var locator [credentialLocatorBytes]byte
	copy(locator[:], locatorBytes)
	var secret [credentialSecretBytes]byte
	copy(secret[:], secretBytes)
	digest, err := k.digest(version, locator, &secret)
	clear(secret[:])
	if err != nil {
		return PresentedCredential{}, ErrInvalidCredential
	}
	return PresentedCredential{Locator: locator, KeyVersion: version, Digest: digest}, nil
}

func encodeCredentialToken(
	version int16,
	locator *[credentialLocatorBytes]byte,
	secret *[credentialSecretBytes]byte,
) string {
	tokenBytes := make([]byte, 0, maximumCredentialTokenBytes)
	tokenBytes = append(tokenBytes, credentialFormatPrefix...)
	tokenBytes = append(tokenBytes, '.')
	tokenBytes = strconv.AppendInt(tokenBytes, int64(version), 10)
	tokenBytes = append(tokenBytes, '.')
	tokenBytes = credentialEncoding.AppendEncode(tokenBytes, locator[:])
	tokenBytes = append(tokenBytes, '.')
	tokenBytes = credentialEncoding.AppendEncode(tokenBytes, secret[:])
	token := string(tokenBytes)
	clear(tokenBytes)
	return token
}

func (k CredentialKeyring) digest(version int16, locator [credentialLocatorBytes]byte, secret *[credentialSecretBytes]byte) ([credentialDigestBytes]byte, error) {
	key, exists := k.keys[version]
	if !exists {
		return [credentialDigestBytes]byte{}, ErrInvalidCredential
	}
	defer clear(key[:])
	message := make([]byte, 0, len(credentialFormatPrefix)+1+2+len(locator)+len(secret))
	message = append(message, credentialFormatPrefix...)
	message = append(message, credentialFormatVersion)
	versionBytes := [2]byte{}
	binary.BigEndian.PutUint16(versionBytes[:], uint16(version))
	message = append(message, versionBytes[:]...)
	message = append(message, locator[:]...)
	message = append(message, secret[:]...)
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(message)
	clear(message)
	result := mac.Sum(nil)
	if len(result) != credentialDigestBytes {
		return [credentialDigestBytes]byte{}, fmt.Errorf("unexpected credential digest length %d", len(result))
	}
	var digest [credentialDigestBytes]byte
	copy(digest[:], result)
	clear(result)
	return digest, nil
}
