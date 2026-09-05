// Package identity owns the cryptographic identity-provider boundary shared by
// the API and worker processes.
package identity

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"strconv"
)

const (
	sourceKeyBytes    = 32
	derivedKeyBytes   = sha256.Size
	maximumKeyVersion = int16(32_767)
	maximumKeyCount   = 16

	hkdfSalt = "periapsis/identity/hkdf-sha256/v1"

	bindSecretKeyPurpose    = "periapsis/identity/ldap-bind-secret/aes-256-gcm/key/v1"
	oidcClientSecretPurpose = "periapsis/identity/oidc-client-secret/aes-256-gcm/key/v1"
	oidcPKCEVerifierPurpose = "periapsis/identity/oidc-pkce-verifier/aes-256-gcm/key/v1"
	oidcIDTokenPurpose      = "periapsis/identity/oidc-id-token/aes-256-gcm/key/v1"
	oidcRefreshTokenPurpose = "periapsis/identity/oidc-refresh-token/aes-256-gcm/key/v1"
	samlSPKeyPurpose        = "periapsis/identity/saml-sp-key/aes-256-gcm/key/v1"
	samlSessionPurpose      = "periapsis/identity/saml-session-material/aes-256-gcm/key/v1"
	externalSubjectPurpose  = "periapsis/identity/external-subject/aes-256-gcm/key/v1"
	subjectAliasKeyPurpose  = "periapsis/identity/external-subject/hmac-sha256/key/v1"
	mfaTOTPSecretPurpose    = "periapsis/identity/mfa-totp-secret/aes-256-gcm/key/v1"
	mfaRecoveryCodePurpose  = "periapsis/identity/mfa-recovery-code/hmac-sha256/key/v1"
	readinessKeyPurpose     = "periapsis/identity/database-readiness/hmac-sha256/key/v1"
	readinessChallenge      = "periapsis/identity/database-readiness/challenge/v1"
	readinessTranscript     = "periapsis/identity/database-readiness/transcript/v1"
)

// ErrInvalidKeyring intentionally does not reveal which keyring constraint or
// derived operation failed.
var ErrInvalidKeyring = errors.New("invalid identity keyring")

type versionKeys struct {
	bindSecret       [derivedKeyBytes]byte
	oidcClientSecret [derivedKeyBytes]byte
	oidcPKCEVerifier [derivedKeyBytes]byte
	oidcIDToken      [derivedKeyBytes]byte
	oidcRefreshToken [derivedKeyBytes]byte
	samlSPKey        [derivedKeyBytes]byte
	samlSession      [derivedKeyBytes]byte
	externalSubject  [derivedKeyBytes]byte
	subjectAlias     [derivedKeyBytes]byte
	mfaTOTPSecret    [derivedKeyBytes]byte
	mfaRecoveryCode  [derivedKeyBytes]byte
	readiness        [derivedKeyBytes]byte
}

// Keyring contains one active write key and every retained read key. It is
// immutable after construction. Only domain-separated derivatives are kept;
// root keys and derived keys are never returned by its API.
type Keyring struct {
	activeVersion int16
	keys          map[int16]versionKeys
	random        io.Reader
}

// NewKeyring validates and derives an immutable keyring from versioned,
// independent 256-bit roots. The caller retains ownership of sourceKeys.
func NewKeyring(activeVersion int16, sourceKeys map[int16][]byte) (Keyring, error) {
	return newKeyring(activeVersion, sourceKeys, rand.Reader)
}

func newKeyring(activeVersion int16, sourceKeys map[int16][]byte, random io.Reader) (Keyring, error) {
	if activeVersion < 1 || activeVersion > maximumKeyVersion || random == nil {
		return Keyring{}, ErrInvalidKeyring
	}
	if len(sourceKeys) < 1 || len(sourceKeys) > maximumKeyCount {
		return Keyring{}, ErrInvalidKeyring
	}

	keys := make(map[int16]versionKeys, len(sourceKeys))
	for version, source := range sourceKeys {
		if version < 1 || version > maximumKeyVersion || len(source) != sourceKeyBytes {
			clearVersionKeys(keys)
			return Keyring{}, ErrInvalidKeyring
		}
		derived, err := deriveVersionKeys(version, source)
		if err != nil {
			clearVersionKeys(keys)
			return Keyring{}, ErrInvalidKeyring
		}
		keys[version] = derived
		clearVersionKey(&derived)
	}
	if _, exists := keys[activeVersion]; !exists {
		clearVersionKeys(keys)
		return Keyring{}, ErrInvalidKeyring
	}
	return Keyring{activeVersion: activeVersion, keys: keys, random: random}, nil
}

func deriveVersionKeys(version int16, source []byte) (versionKeys, error) {
	root := append([]byte(nil), source...)
	defer clear(root)

	bindSecret, err := derivePurposeKey(root, version, bindSecretKeyPurpose)
	if err != nil {
		return versionKeys{}, err
	}
	oidcClientSecret, err := derivePurposeKey(root, version, oidcClientSecretPurpose)
	if err != nil {
		clear(bindSecret[:])
		return versionKeys{}, err
	}
	oidcPKCEVerifier, err := derivePurposeKey(root, version, oidcPKCEVerifierPurpose)
	if err != nil {
		clear(bindSecret[:])
		clear(oidcClientSecret[:])
		return versionKeys{}, err
	}
	oidcIDToken, err := derivePurposeKey(root, version, oidcIDTokenPurpose)
	if err != nil {
		clear(bindSecret[:])
		clear(oidcClientSecret[:])
		clear(oidcPKCEVerifier[:])
		return versionKeys{}, err
	}
	oidcRefreshToken, err := derivePurposeKey(root, version, oidcRefreshTokenPurpose)
	if err != nil {
		clear(bindSecret[:])
		clear(oidcClientSecret[:])
		clear(oidcPKCEVerifier[:])
		clear(oidcIDToken[:])
		return versionKeys{}, err
	}
	samlSPKey, err := derivePurposeKey(root, version, samlSPKeyPurpose)
	if err != nil {
		clear(bindSecret[:])
		clear(oidcClientSecret[:])
		clear(oidcPKCEVerifier[:])
		clear(oidcIDToken[:])
		clear(oidcRefreshToken[:])
		return versionKeys{}, err
	}
	samlSession, err := derivePurposeKey(root, version, samlSessionPurpose)
	if err != nil {
		clear(bindSecret[:])
		clear(oidcClientSecret[:])
		clear(oidcPKCEVerifier[:])
		clear(oidcIDToken[:])
		clear(oidcRefreshToken[:])
		clear(samlSPKey[:])
		return versionKeys{}, err
	}
	externalSubject, err := derivePurposeKey(root, version, externalSubjectPurpose)
	if err != nil {
		clear(bindSecret[:])
		clear(oidcClientSecret[:])
		clear(oidcPKCEVerifier[:])
		clear(oidcIDToken[:])
		clear(oidcRefreshToken[:])
		clear(samlSPKey[:])
		clear(samlSession[:])
		return versionKeys{}, err
	}
	subjectAlias, err := derivePurposeKey(root, version, subjectAliasKeyPurpose)
	if err != nil {
		clear(bindSecret[:])
		clear(oidcClientSecret[:])
		clear(oidcPKCEVerifier[:])
		clear(oidcIDToken[:])
		clear(oidcRefreshToken[:])
		clear(samlSPKey[:])
		clear(samlSession[:])
		clear(externalSubject[:])
		return versionKeys{}, err
	}
	mfaTOTPSecret, err := derivePurposeKey(root, version, mfaTOTPSecretPurpose)
	if err != nil {
		clear(bindSecret[:])
		clear(oidcClientSecret[:])
		clear(oidcPKCEVerifier[:])
		clear(oidcIDToken[:])
		clear(oidcRefreshToken[:])
		clear(samlSPKey[:])
		clear(samlSession[:])
		clear(externalSubject[:])
		clear(subjectAlias[:])
		return versionKeys{}, err
	}
	mfaRecoveryCode, err := derivePurposeKey(root, version, mfaRecoveryCodePurpose)
	if err != nil {
		clear(bindSecret[:])
		clear(oidcClientSecret[:])
		clear(oidcPKCEVerifier[:])
		clear(oidcIDToken[:])
		clear(oidcRefreshToken[:])
		clear(samlSPKey[:])
		clear(samlSession[:])
		clear(externalSubject[:])
		clear(subjectAlias[:])
		clear(mfaTOTPSecret[:])
		return versionKeys{}, err
	}
	readiness, err := derivePurposeKey(root, version, readinessKeyPurpose)
	if err != nil {
		clear(bindSecret[:])
		clear(oidcClientSecret[:])
		clear(oidcPKCEVerifier[:])
		clear(oidcIDToken[:])
		clear(oidcRefreshToken[:])
		clear(samlSPKey[:])
		clear(samlSession[:])
		clear(externalSubject[:])
		clear(subjectAlias[:])
		clear(mfaTOTPSecret[:])
		clear(mfaRecoveryCode[:])
		return versionKeys{}, err
	}
	return versionKeys{
		bindSecret: bindSecret, oidcClientSecret: oidcClientSecret, oidcPKCEVerifier: oidcPKCEVerifier,
		oidcIDToken: oidcIDToken, oidcRefreshToken: oidcRefreshToken,
		samlSPKey:       samlSPKey,
		samlSession:     samlSession,
		externalSubject: externalSubject,
		subjectAlias:    subjectAlias, mfaTOTPSecret: mfaTOTPSecret,
		mfaRecoveryCode: mfaRecoveryCode, readiness: readiness,
	}, nil
}

func derivePurposeKey(source []byte, version int16, purpose string) ([derivedKeyBytes]byte, error) {
	info := purpose + "/version/" + strconv.Itoa(int(version))
	derived, err := hkdf.Key(sha256.New, source, []byte(hkdfSalt), info, derivedKeyBytes)
	if err != nil {
		return [derivedKeyBytes]byte{}, err
	}
	defer clear(derived)
	var key [derivedKeyBytes]byte
	copy(key[:], derived)
	return key, nil
}

func clearVersionKeys(keys map[int16]versionKeys) {
	for version, keysForVersion := range keys {
		clearVersionKey(&keysForVersion)
		keys[version] = versionKeys{}
	}
}

func clearVersionKey(keys *versionKeys) {
	clear(keys.bindSecret[:])
	clear(keys.oidcClientSecret[:])
	clear(keys.oidcPKCEVerifier[:])
	clear(keys.oidcIDToken[:])
	clear(keys.oidcRefreshToken[:])
	clear(keys.samlSPKey[:])
	clear(keys.samlSession[:])
	clear(keys.externalSubject[:])
	clear(keys.subjectAlias[:])
	clear(keys.mfaTOTPSecret[:])
	clear(keys.mfaRecoveryCode[:])
	clear(keys.readiness[:])
}

// ActiveVersion returns the only version used for new encrypted values and
// subject aliases.
func (k Keyring) ActiveVersion() int16 {
	return k.activeVersion
}

// String returns only non-secret keyring metadata. It prevents ordinary
// formatting and structured-log fallbacks from traversing derived key fields.
func (k Keyring) String() string {
	return "identity.Keyring{activeVersion:" + strconv.Itoa(int(k.activeVersion)) +
		",retainedKeys:" + strconv.Itoa(len(k.keys)) + "}"
}

// GoString provides the same redaction for %#v formatting.
func (k Keyring) GoString() string {
	return k.String()
}

// Versions returns every retained version in strictly ascending order.
func (k Keyring) Versions() []int16 {
	versions := make([]int16, 0, len(k.keys))
	for version := range k.keys {
		versions = append(versions, version)
	}
	slices.Sort(versions)
	return versions
}

// MissingVersions returns the distinct requested versions not retained by the
// keyring. Invalid versions are missing and the result is sorted.
func (k Keyring) MissingVersions(required []int16) []int16 {
	missingSet := make(map[int16]struct{})
	for _, version := range required {
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

// VersionVerifier irreversibly binds one key version to its exact root
// material. Verifier is evidence for database readiness, not a cryptographic
// key usable by another operation.
type VersionVerifier struct {
	KeyVersion int16
	Verifier   [sha256.Size]byte
}

// ReadinessEvidence is the bounded process evidence submitted to the database.
// Versions always contains between one and sixteen entries in strictly
// ascending key-version order.
type ReadinessEvidence struct {
	ActiveVersion int16
	Versions      []VersionVerifier
}

// ReadinessEvidence returns independently comparable evidence for every
// retained root plus the active write version. Per-version evidence remains
// stable while other versions are added or removed, enabling safe rolling key
// rotation without permitting a version number to be rebound to another root.
func (k Keyring) ReadinessEvidence() (ReadinessEvidence, error) {
	versions := k.Versions()
	if k.activeVersion < 1 || len(versions) < 1 || len(versions) > maximumKeyCount {
		return ReadinessEvidence{}, ErrInvalidKeyring
	}
	if _, exists := k.keys[k.activeVersion]; !exists {
		return ReadinessEvidence{}, ErrInvalidKeyring
	}

	evidence := ReadinessEvidence{
		ActiveVersion: k.activeVersion,
		Versions:      make([]VersionVerifier, 0, len(versions)),
	}
	for _, version := range versions {
		keysForVersion, exists := k.keys[version]
		if !exists {
			return ReadinessEvidence{}, ErrInvalidKeyring
		}
		readinessKey := keysForVersion.readiness
		mac := hmac.New(sha256.New, readinessKey[:])
		_, _ = mac.Write([]byte(readinessChallenge))
		verifierBytes := mac.Sum(nil)
		clear(readinessKey[:])
		clearVersionKey(&keysForVersion)

		var verifier [sha256.Size]byte
		copy(verifier[:], verifierBytes)
		clear(verifierBytes)
		evidence.Versions = append(evidence.Versions, VersionVerifier{
			KeyVersion: version,
			Verifier:   verifier,
		})
		clear(verifier[:])
	}
	return evidence, nil
}

// ReadinessVerifier returns a stable, non-reversible verifier for the exact
// active version, retained version inventory, and root material in this
// keyring. It is a convenience fingerprint, not a key. Database rolling
// readiness should use ReadinessEvidence so each version remains independently
// bound while the retained set changes.
func (k Keyring) ReadinessVerifier() ([sha256.Size]byte, error) {
	evidence, err := k.ReadinessEvidence()
	if err != nil {
		return [sha256.Size]byte{}, ErrInvalidKeyring
	}

	transcript := make([]byte, 0, 128+len(evidence.Versions)*(2+sha256.Size))
	transcript = appendTypedField(transcript, fieldSchema, []byte(readinessTranscript))
	active := [2]byte{}
	binary.BigEndian.PutUint16(active[:], uint16(evidence.ActiveVersion))
	transcript = appendTypedField(transcript, fieldKeyVersion, active[:])
	count := [2]byte{}
	binary.BigEndian.PutUint16(count[:], uint16(len(evidence.Versions)))
	transcript = appendTypedField(transcript, fieldKeyCount, count[:])

	for _, versionEvidence := range evidence.Versions {
		versionBytes := [2]byte{}
		binary.BigEndian.PutUint16(versionBytes[:], uint16(versionEvidence.KeyVersion))
		transcript = appendTypedField(transcript, fieldKeyVersion, versionBytes[:])
		transcript = appendTypedField(transcript, fieldVerifier, versionEvidence.Verifier[:])
	}
	result := sha256.Sum256(transcript)
	clear(transcript)
	return result, nil
}
