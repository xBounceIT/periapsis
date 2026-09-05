package notification

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"slices"
	"strconv"

	"github.com/google/uuid"
)

const (
	notificationRootKeyBytes      = 32
	notificationNonceBytes        = 12
	notificationTagBytes          = 16
	maximumNotificationSecret     = 64 * 1024
	maximumNotificationKeyCount   = 16
	maximumNotificationKeyVersion = int16(32_767)

	notificationHKDFSalt         = "periapsis/notification/hkdf-sha256/v1"
	notificationKeyPurpose       = "periapsis/notification/config-secret/aes-256-gcm/key/v1"
	notificationAADSchema        = "periapsis/notification/config-secret/aes-256-gcm/aad/v1"
	notificationCursorKeyPurpose = "periapsis/notification/admin-cursor/hmac-sha256/key/v1"
)

// SecretKind is part of the authenticated encryption context. Ciphertext for
// one provider field cannot be substituted for another provider field.
type SecretKind string

const (
	SecretKindSMTPPassword       SecretKind = "smtp_password"
	SecretKindSMTPDKIMPrivateKey SecretKind = "smtp_dkim_private_key"
	SecretKindWebhookSigningKey  SecretKind = "webhook_signing_key"
)

// SecretContext binds an immutable encrypted secret version to its ownership
// scope and identifier. TenantID nil denotes the platform-global scope.
type SecretContext struct {
	TenantID      *uuid.UUID
	SecretID      uuid.UUID
	SecretVersion int64
	Kind          SecretKind
}

// SecretEnvelope is safe to persist but never safe to log: ciphertext length
// can still reveal bounded metadata. Nonce and ciphertext are caller-owned.
type SecretEnvelope struct {
	KeyVersion int16
	Nonce      []byte
	Ciphertext []byte
}

type notificationVersionKey [sha256.Size]byte
type notificationCursorKey [sha256.Size]byte

// Keyring retains only domain-separated AES keys. Root keys are copied during
// construction, derived, and immediately cleared.
type Keyring struct {
	activeVersion int16
	keys          map[int16]notificationVersionKey
	cursorKeys    map[int16]notificationCursorKey
	random        io.Reader
}

type keyringDocument struct {
	ActiveVersion int16                  `json:"activeVersion"`
	Keys          []keyringDocumentEntry `json:"keys"`
}

type keyringDocumentEntry struct {
	Version int16  `json:"version"`
	Key     string `json:"key"`
}

func ParseKeyringDocument(document []byte) (Keyring, error) {
	if len(document) == 0 || len(document) > 64*1024 {
		return Keyring{}, ErrInvalidKeyring
	}
	if err := rejectDuplicateJSONNames(document); err != nil {
		return Keyring{}, ErrInvalidKeyring
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var value keyringDocument
	if err := decoder.Decode(&value); err != nil {
		return Keyring{}, ErrInvalidKeyring
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return Keyring{}, ErrInvalidKeyring
	}
	keys := make(map[int16][]byte, len(value.Keys))
	defer func() {
		for _, key := range keys {
			clear(key)
		}
	}()
	for _, entry := range value.Keys {
		if _, exists := keys[entry.Version]; exists {
			return Keyring{}, ErrInvalidKeyring
		}
		decoded, err := base64.RawURLEncoding.DecodeString(entry.Key)
		if err != nil {
			return Keyring{}, ErrInvalidKeyring
		}
		keys[entry.Version] = decoded
	}
	return NewKeyring(value.ActiveVersion, keys)
}

func NewKeyring(activeVersion int16, roots map[int16][]byte) (Keyring, error) {
	return newKeyring(activeVersion, roots, rand.Reader)
}

func newKeyring(activeVersion int16, roots map[int16][]byte, random io.Reader) (Keyring, error) {
	if activeVersion < 1 || activeVersion > maximumNotificationKeyVersion || random == nil ||
		len(roots) < 1 || len(roots) > maximumNotificationKeyCount {
		return Keyring{}, ErrInvalidKeyring
	}
	keys := make(map[int16]notificationVersionKey, len(roots))
	cursorKeys := make(map[int16]notificationCursorKey, len(roots))
	for version, source := range roots {
		if version < 1 || version > maximumNotificationKeyVersion || len(source) != notificationRootKeyBytes {
			clearNotificationKeys(keys)
			clearNotificationCursorKeys(cursorKeys)
			return Keyring{}, ErrInvalidKeyring
		}
		root := append([]byte(nil), source...)
		derived, err := hkdf.Key(
			sha256.New,
			root,
			[]byte(notificationHKDFSalt),
			notificationKeyPurpose+"/version/"+strconv.Itoa(int(version)),
			sha256.Size,
		)
		if err != nil {
			clear(root)
			clearNotificationKeys(keys)
			clearNotificationCursorKeys(cursorKeys)
			return Keyring{}, ErrInvalidKeyring
		}
		cursorDerived, err := hkdf.Key(
			sha256.New,
			root,
			[]byte(notificationHKDFSalt),
			notificationCursorKeyPurpose+"/version/"+strconv.Itoa(int(version)),
			sha256.Size,
		)
		clear(root)
		if err != nil {
			clear(derived)
			clearNotificationKeys(keys)
			clearNotificationCursorKeys(cursorKeys)
			return Keyring{}, ErrInvalidKeyring
		}
		var key notificationVersionKey
		copy(key[:], derived)
		clear(derived)
		keys[version] = key
		clear(key[:])
		var cursorKey notificationCursorKey
		copy(cursorKey[:], cursorDerived)
		clear(cursorDerived)
		cursorKeys[version] = cursorKey
		clear(cursorKey[:])
	}
	if _, exists := keys[activeVersion]; !exists {
		clearNotificationKeys(keys)
		clearNotificationCursorKeys(cursorKeys)
		return Keyring{}, ErrInvalidKeyring
	}
	return Keyring{activeVersion: activeVersion, keys: keys, cursorKeys: cursorKeys, random: random}, nil
}

func (k Keyring) ActiveVersion() int16 { return k.activeVersion }

func (k Keyring) Versions() []int16 {
	versions := make([]int16, 0, len(k.keys))
	for version := range k.keys {
		versions = append(versions, version)
	}
	slices.Sort(versions)
	return versions
}

func (k Keyring) String() string {
	return "notification.Keyring{activeVersion:" + strconv.Itoa(int(k.activeVersion)) +
		",retainedKeys:" + strconv.Itoa(len(k.keys)) + "}"
}

func (k Keyring) GoString() string { return k.String() }

// Close destroys all retained derived keys. Keyring copies share their maps,
// so deleting entries also makes every service copy fail closed after shutdown.
func (k *Keyring) Close() {
	if k == nil {
		return
	}
	clearNotificationKeys(k.keys)
	clearNotificationCursorKeys(k.cursorKeys)
	k.activeVersion = 0
	k.keys = nil
	k.cursorKeys = nil
	k.random = nil
}

func (k Keyring) Protect(context SecretContext, plaintext []byte) (SecretEnvelope, error) {
	aad, err := notificationSecretAAD(context)
	if err != nil || len(plaintext) < 1 || len(plaintext) > maximumNotificationSecret {
		return SecretEnvelope{}, ErrInvalidSecret
	}
	key, exists := k.keys[k.activeVersion]
	if !exists || k.random == nil {
		return SecretEnvelope{}, ErrInvalidKeyring
	}
	aead, err := notificationAEAD(key)
	clear(key[:])
	if err != nil {
		return SecretEnvelope{}, ErrInvalidKeyring
	}
	nonce := make([]byte, notificationNonceBytes)
	if _, err := io.ReadFull(k.random, nonce); err != nil {
		clear(nonce)
		return SecretEnvelope{}, ErrInvalidKeyring
	}
	secret := append([]byte(nil), plaintext...)
	ciphertext := aead.Seal(nil, nonce, secret, aad)
	clear(secret)
	return SecretEnvelope{KeyVersion: k.activeVersion, Nonce: nonce, Ciphertext: ciphertext}, nil
}

func (k Keyring) Unprotect(context SecretContext, envelope SecretEnvelope) ([]byte, error) {
	aad, err := notificationSecretAAD(context)
	if err != nil || len(envelope.Nonce) != notificationNonceBytes ||
		len(envelope.Ciphertext) <= notificationTagBytes ||
		len(envelope.Ciphertext) > maximumNotificationSecret+notificationTagBytes {
		return nil, ErrInvalidSecret
	}
	key, exists := k.keys[envelope.KeyVersion]
	if !exists {
		return nil, ErrInvalidSecret
	}
	aead, err := notificationAEAD(key)
	clear(key[:])
	if err != nil {
		return nil, ErrInvalidSecret
	}
	plaintext, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, aad)
	if err != nil {
		return nil, ErrInvalidSecret
	}
	return plaintext, nil
}

func notificationAEAD(key notificationVersionKey) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func notificationSecretAAD(context SecretContext) ([]byte, error) {
	if context.SecretID.Version() != 7 || context.SecretVersion < 1 || context.SecretVersion > 2_147_483_647 ||
		!validSecretKind(context.Kind) || context.TenantID != nil && context.TenantID.Version() != 7 {
		return nil, ErrInvalidSecret
	}
	value := make([]byte, 0, 160)
	value = appendLengthPrefixed(value, []byte(notificationAADSchema))
	if context.TenantID == nil {
		value = appendLengthPrefixed(value, []byte("platform"))
		value = appendLengthPrefixed(value, nil)
	} else {
		value = appendLengthPrefixed(value, []byte("tenant"))
		value = appendLengthPrefixed(value, context.TenantID[:])
	}
	value = appendLengthPrefixed(value, context.SecretID[:])
	var version [8]byte
	binary.BigEndian.PutUint64(version[:], uint64(context.SecretVersion))
	value = appendLengthPrefixed(value, version[:])
	value = appendLengthPrefixed(value, []byte(context.Kind))
	return value, nil
}

func appendLengthPrefixed(destination, value []byte) []byte {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	destination = append(destination, length[:]...)
	return append(destination, value...)
}

func validSecretKind(kind SecretKind) bool {
	return kind == SecretKindSMTPPassword || kind == SecretKindSMTPDKIMPrivateKey ||
		kind == SecretKindWebhookSigningKey
}

func clearNotificationKeys(keys map[int16]notificationVersionKey) {
	for version, key := range keys {
		clear(key[:])
		keys[version] = notificationVersionKey{}
		delete(keys, version)
	}
}

func clearNotificationCursorKeys(keys map[int16]notificationCursorKey) {
	for version, key := range keys {
		clear(key[:])
		keys[version] = notificationCursorKey{}
		delete(keys, version)
	}
}

func rejectDuplicateJSONNames(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	if err := walkUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalidKeyring
	}
	return nil
}

func walkUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return ErrInvalidKeyring
			}
			if _, duplicate := seen[name]; duplicate {
				return ErrInvalidKeyring
			}
			seen[name] = struct{}{}
			if err := walkUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrInvalidKeyring
		}
	case '[':
		for decoder.More() {
			if err := walkUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrInvalidKeyring
		}
	default:
		return ErrInvalidKeyring
	}
	return nil
}
