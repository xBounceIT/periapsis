// Package authentication implements local break-glass authentication and server-side sessions.
package authentication

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/argon2"
)

const (
	tokenBytes         = 32
	recoveryCodeBytes  = 32
	totpPeriod         = uint64(30)
	sha256DigestLength = sha256.Size
)

var passwordParams = &argon2id.Params{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   32,
}

// PasswordManager hashes and verifies human-selected passwords with the fixed Argon2id profile.
type PasswordManager struct{}

func (PasswordManager) Hash(password string) (string, error) {
	return argon2id.CreateHash(password, passwordParams)
}

func (PasswordManager) Verify(password, encodedHash string) bool {
	params, _, _, err := argon2id.DecodeHash(encodedHash)
	if err != nil || !boundedArgonParams(params) {
		return false
	}
	match, _, err := argon2id.CheckHash(password, encodedHash)
	return err == nil && match
}

func boundedArgonParams(params *argon2id.Params) bool {
	return argon2.Version == 0x13 && params != nil &&
		params.Memory >= 19*1024 && params.Memory <= 256*1024 &&
		params.Iterations >= 1 && params.Iterations <= 10 &&
		params.Parallelism >= 1 && params.Parallelism <= 4 &&
		params.SaltLength >= 16 && params.SaltLength <= 64 &&
		params.KeyLength >= 16 && params.KeyLength <= 64
}

// TokenGenerator creates opaque high-entropy credentials and one-use recovery codes.
type TokenGenerator struct {
	random io.Reader
}

func NewTokenGenerator() TokenGenerator {
	return TokenGenerator{random: rand.Reader}
}

func newTokenGenerator(random io.Reader) TokenGenerator {
	return TokenGenerator{random: random}
}

func (g TokenGenerator) Opaque() (string, error) {
	value := make([]byte, tokenBytes)
	defer clear(value)
	if _, err := io.ReadFull(g.random, value); err != nil {
		return "", errors.New("generate opaque credential")
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func (g TokenGenerator) RecoveryCode() (string, []byte, error) {
	value := make([]byte, recoveryCodeBytes)
	defer clear(value)
	if _, err := io.ReadFull(g.random, value); err != nil {
		return "", nil, errors.New("generate recovery code")
	}
	canonical := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(value)
	groups := make([]string, 0, len(canonical)/4)
	for start := 0; start < len(canonical); start += 4 {
		groups = append(groups, canonical[start:start+4])
	}
	return strings.Join(groups, "-"), digest(canonical), nil
}

func digest(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return append([]byte(nil), sum[:]...)
}

func recoveryCodeDigest(value string) ([]byte, bool) {
	canonical := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(value), "-", ""))
	if len(canonical) != 52 {
		return nil, false
	}
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(canonical); err != nil {
		return nil, false
	}
	return digest(canonical), true
}

// EncryptedSecret is the authenticated ciphertext persisted for a TOTP secret.
type EncryptedSecret struct {
	Ciphertext []byte
	Nonce      []byte
	AAD        []byte
	KeyVersion int16
}

func (EncryptedSecret) String() string          { return "authentication.EncryptedSecret{material:[REDACTED]}" }
func (secret EncryptedSecret) GoString() string { return secret.String() }

// SecretCipher encrypts recoverable MFA secrets with AES-256-GCM.
type SecretCipher struct {
	aead cipher.AEAD
}

func (SecretCipher) String() string          { return "authentication.SecretCipher{key:[REDACTED]}" }
func (secret SecretCipher) GoString() string { return secret.String() }

func NewSecretCipher(key []byte) (SecretCipher, error) {
	var combined byte
	for _, item := range key {
		combined |= item
	}
	if len(key) != 32 || combined == 0 {
		return SecretCipher{}, errors.New("master key must be a non-zero 32-byte value")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return SecretCipher{}, errors.New("initialize secret cipher")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return SecretCipher{}, errors.New("initialize authenticated encryption")
	}
	return SecretCipher{aead: aead}, nil
}

func (c SecretCipher) EncryptTOTP(aadContext, secret string) (EncryptedSecret, error) {
	if aadContext == "" || secret == "" {
		return EncryptedSecret{}, errors.New("TOTP encryption context and secret are required")
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return EncryptedSecret{}, errors.New("generate encryption nonce")
	}
	aad := []byte(aadContext)
	ciphertext := c.aead.Seal(nil, nonce, []byte(secret), aad)
	return EncryptedSecret{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		AAD:        aad,
		KeyVersion: 1,
	}, nil
}

func (c SecretCipher) DecryptTOTP(aadContext string, encrypted EncryptedSecret) (string, error) {
	if encrypted.KeyVersion != 1 || string(encrypted.AAD) != aadContext {
		return "", errors.New("unsupported encrypted secret context")
	}
	plaintext, err := c.aead.Open(nil, encrypted.Nonce, encrypted.Ciphertext, encrypted.AAD)
	if err != nil {
		return "", errors.New("decrypt TOTP secret")
	}
	secret := string(plaintext)
	clear(plaintext)
	return secret, nil
}

func bootstrapTOTPContext(enrollmentID uuid.UUID, email string) string {
	return "bootstrap_enrollment:" + enrollmentID.String() + ":email:" + email
}

func credentialTOTPContext(credentialID, userID uuid.UUID) string {
	return "totp_credential:" + credentialID.String() + ":user:" + userID.String()
}

// CredentialTOTPContextAtRevision binds administrative TOTP enrollment to the
// immutable owner, identifier, and security revision. The original context
// remains readable and is required by the sealed, unversioned bootstrap ABI.
func CredentialTOTPContextAtRevision(
	credentialID uuid.UUID,
	userID uuid.UUID,
	revision uint64,
) (string, error) {
	if credentialID == uuid.Nil || credentialID.Version() != 7 ||
		credentialID.Variant() != uuid.RFC4122 || userID == uuid.Nil || userID.Version() != 7 ||
		userID.Variant() != uuid.RFC4122 || credentialID == userID ||
		revision == 0 || revision > 9_007_199_254_740_991 {
		return "", errors.New("invalid TOTP credential context")
	}
	return "totp_credential:v2:factor:" + credentialID.String() +
		":user:" + userID.String() + ":revision:" + strconv.FormatUint(revision, 10), nil
}

func credentialTOTPDecryptionContext(
	credentialID uuid.UUID,
	userID uuid.UUID,
	aad []byte,
) (string, uint64, bool) {
	if _, err := CredentialTOTPContextAtRevision(credentialID, userID, 1); err != nil {
		return "", 0, false
	}
	legacy := credentialTOTPContext(credentialID, userID)
	if string(aad) == legacy {
		return legacy, 0, true
	}
	prefix := "totp_credential:v2:factor:" + credentialID.String() +
		":user:" + userID.String() + ":revision:"
	value := string(aad)
	if !strings.HasPrefix(value, prefix) {
		return "", 0, false
	}
	revisionText := strings.TrimPrefix(value, prefix)
	revision, err := strconv.ParseUint(revisionText, 10, 64)
	canonical, canonicalErr := CredentialTOTPContextAtRevision(credentialID, userID, revision)
	if err != nil || canonicalErr != nil || canonical != value {
		return "", 0, false
	}
	return canonical, revision, true
}

func validDirectTOTPSecret(secret string) bool {
	if len(secret) < 16 || len(secret) > 256 || strings.ContainsRune(secret, '=') ||
		secret != strings.ToUpper(secret) {
		return false
	}
	decoded := make([]byte, base32.StdEncoding.WithPadding(base32.NoPadding).DecodedLen(len(secret)))
	written, err := base32.StdEncoding.WithPadding(base32.NoPadding).Decode(decoded, []byte(secret))
	canonical := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(decoded[:written])
	var combined byte
	for _, item := range decoded[:written] {
		combined |= item
	}
	clear(decoded)
	return err == nil && written >= 10 && combined != 0 && canonical == secret
}

// TOTPManager delegates RFC 6238 generation and HOTP verification to pquerna/otp.
type TOTPManager struct {
	random io.Reader
}

func NewTOTPManager() TOTPManager {
	return TOTPManager{random: rand.Reader}
}

func (m TOTPManager) Generate(email string) (secret string, provisioningURI string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Periapsis",
		AccountName: email,
		Period:      uint(totpPeriod),
		SecretSize:  32,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
		Rand:        m.random,
	})
	if err != nil {
		return "", "", errors.New("generate TOTP enrollment")
	}
	secret = key.Secret()
	if !validDirectTOTPSecret(secret) {
		return "", "", errors.New("generate TOTP enrollment")
	}
	return secret, key.URL(), nil
}

// Validate returns the accepted time-step, rejecting an already accepted or out-of-window code.
func (TOTPManager) Validate(secret, code string, now time.Time, lastAcceptedCounter int64) (int64, error) {
	if len(code) != 6 || now.Unix() < 0 {
		return 0, ErrInvalidAuthentication
	}
	current := now.Unix() / int64(totpPeriod)
	accepted := int64(-1)
	for counter := current - 1; counter <= current+1; counter++ {
		if counter < 0 {
			continue
		}
		valid, err := hotp.ValidateCustom(code, uint64(counter), secret, hotp.ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			return 0, fmt.Errorf("validate TOTP code: %w", err)
		}
		if valid && counter > accepted {
			accepted = counter
		}
	}
	if accepted < 0 || accepted <= lastAcceptedCounter {
		return 0, ErrInvalidAuthentication
	}
	return accepted, nil
}
