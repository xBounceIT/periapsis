package mfaauth

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
)

const (
	admissionKeyInfo        = "periapsis/mfa/admission/hmac-sha256/key/v1"
	admissionNetworkScope   = "periapsis/mfa/admission/network/v1"
	admissionPrincipalScope = "periapsis/mfa/admission/principal/v1"
	admissionResourceScope  = "periapsis/mfa/admission/resource/v1"
	serializedNonceBytes    = 12
	recoveryCanonicalBytes  = 52
)

type opaqueMaterialSource interface {
	Opaque() (string, error)
	RecoveryCode() (string, []byte, error)
}

type totpMaterialEngine interface {
	Generate(string) (string, string, error)
	Validate(string, string, time.Time, int64) (int64, error)
}

type RuntimeCryptographyOptions struct {
	Keyring          identity.Keyring
	AdmissionRootKey []byte
	Tokens           opaqueMaterialSource
	TOTP             totpMaterialEngine
	NewID            func() (uuid.UUID, error)
}

// RuntimeCryptography owns the purpose-separated cryptographic adapters used
// by local MFA. It never returns key material and its formatting is redacted.
type RuntimeCryptography struct {
	keyring      identity.Keyring
	admissionKey [sha256.Size]byte
	tokens       opaqueMaterialSource
	totp         totpMaterialEngine
	newID        func() (uuid.UUID, error)
}

var (
	_ TOTPEnrollmentMaterialSource = (*RuntimeCryptography)(nil)
	_ RecoveryCodeGenerator        = (*RuntimeCryptography)(nil)
	_ mfa.TOTPVerifier             = (*RuntimeCryptography)(nil)
	_ mfa.RecoveryDigester         = (*RuntimeCryptography)(nil)
)

func NewRuntimeCryptography(options RuntimeCryptographyOptions) (*RuntimeCryptography, error) {
	if options.Keyring.ActiveVersion() < 1 || len(options.AdmissionRootKey) < sha256.Size ||
		options.Tokens == nil || options.TOTP == nil {
		return nil, ErrInvalidInput
	}
	if options.NewID == nil {
		options.NewID = uuid.NewV7
	}
	derived, err := hkdf.Key(sha256.New, options.AdmissionRootKey, nil, admissionKeyInfo, sha256.Size)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(derived)
	var key [sha256.Size]byte
	copy(key[:], derived)
	return &RuntimeCryptography{
		keyring: options.Keyring, admissionKey: key,
		tokens: options.Tokens, totp: options.TOTP, newID: options.NewID,
	}, nil
}

func (runtime *RuntimeCryptography) String() string {
	return "mfaauth.RuntimeCryptography{material:[REDACTED]}"
}
func (runtime *RuntimeCryptography) GoString() string { return runtime.String() }

func (runtime *RuntimeCryptography) Admission(
	network netip.Addr,
	principal identity.EntityID,
	resource string,
) (AdmissionContext, error) {
	if runtime == nil || runtime.newID == nil || !network.IsValid() || network.Zone() != "" ||
		principal == (identity.EntityID{}) || !validPublicText(resource, 256) {
		return AdmissionContext{}, ErrInvalidInput
	}
	operationID, err := runtime.newID()
	if err != nil || operationID == uuid.Nil || operationID.Version() != 7 {
		return AdmissionContext{}, ErrUnavailable
	}
	value := AdmissionContext{
		OperationID:     identity.EntityID(operationID),
		NetworkDigest:   runtime.admissionDigest(admissionNetworkScope, []byte(network.Unmap().String())),
		PrincipalDigest: runtime.admissionDigest(admissionPrincipalScope, principal[:]),
		ResourceDigest:  runtime.admissionDigest(admissionResourceScope, []byte(resource)),
	}
	if !validAdmission(value) {
		return AdmissionContext{}, ErrUnavailable
	}
	return value, nil
}

func (runtime *RuntimeCryptography) admissionDigest(scope string, value []byte) AdmissionDigest {
	mac := hmac.New(sha256.New, runtime.admissionKey[:])
	_, _ = mac.Write([]byte(scope))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(value)
	sum := mac.Sum(nil)
	defer clear(sum)
	var digest AdmissionDigest
	copy(digest[:], sum)
	return digest
}

func (runtime *RuntimeCryptography) NewTOTPEnrollmentMaterial(
	_ context.Context,
	tenantID identity.EntityID,
	userID identity.EntityID,
) (TOTPEnrollmentMaterial, error) {
	if runtime == nil || runtime.tokens == nil || runtime.totp == nil || runtime.newID == nil ||
		!validRuntimeID(tenantID) || !validRuntimeID(userID) || tenantID == userID {
		return TOTPEnrollmentMaterial{}, ErrInvalidInput
	}
	enrollmentID, err := runtime.newID()
	if err != nil {
		return TOTPEnrollmentMaterial{}, ErrUnavailable
	}
	factorID, err := runtime.newID()
	if err != nil || enrollmentID == factorID || enrollmentID.Version() != 7 || factorID.Version() != 7 {
		return TOTPEnrollmentMaterial{}, ErrUnavailable
	}
	browserHandle, err := runtime.tokens.Opaque()
	if err != nil || !validOpaque([]byte(browserHandle)) {
		return TOTPEnrollmentMaterial{}, ErrUnavailable
	}
	secret, provisioningURI, err := runtime.totp.Generate(uuid.UUID(userID).String())
	if err != nil {
		return TOTPEnrollmentMaterial{}, ErrUnavailable
	}
	secretBytes := []byte(secret)
	defer clear(secretBytes)
	envelope, err := runtime.keyring.EncryptMFATOTPSecret(identity.MFATOTPContext{
		TenantID: tenantID, UserID: userID, FactorID: identity.EntityID(factorID),
	}, secretBytes)
	if err != nil {
		return TOTPEnrollmentMaterial{}, ErrUnavailable
	}
	ciphertext := make([]byte, 0, serializedNonceBytes+len(envelope.Ciphertext))
	ciphertext = append(ciphertext, envelope.Nonce[:]...)
	ciphertext = append(ciphertext, envelope.Ciphertext...)
	return TOTPEnrollmentMaterial{
		EnrollmentID: identity.EntityID(enrollmentID), FactorID: identity.EntityID(factorID),
		BrowserHandle: []byte(browserHandle), BrowserDigest: sha256.Sum256([]byte(browserHandle)),
		ProtectedSecret: mfa.ProtectedTOTPSecret{
			KeyVersion: uint32(envelope.KeyVersion), Ciphertext: ciphertext,
		},
		DisplaySecret: []byte(secret), ProvisioningURI: []byte(provisioningURI),
	}, nil
}

func (runtime *RuntimeCryptography) VerifyTOTP(
	_ context.Context,
	request mfa.TOTPVerificationRequest,
) (mfa.TOTPProof, error) {
	if runtime == nil || runtime.totp == nil || !validRuntimeID(request.TenantID) ||
		!validRuntimeID(request.UserID) || !validRuntimeID(request.FactorID) ||
		request.Secret.KeyVersion < 1 || request.Secret.KeyVersion > 32_767 ||
		len(request.Secret.Ciphertext) <= serializedNonceBytes || len(request.Code) != 6 || !validInstant(request.At) {
		return mfa.TOTPProof{}, ErrAuthentication
	}
	var nonce [serializedNonceBytes]byte
	copy(nonce[:], request.Secret.Ciphertext[:serializedNonceBytes])
	ciphertext := append([]byte(nil), request.Secret.Ciphertext[serializedNonceBytes:]...)
	defer clear(ciphertext)
	secret, err := runtime.keyring.DecryptMFATOTPSecret(identity.MFATOTPContext{
		TenantID: request.TenantID, UserID: request.UserID, FactorID: request.FactorID,
	}, identity.MFATOTPEnvelope{
		KeyVersion: int16(request.Secret.KeyVersion), Nonce: nonce, Ciphertext: ciphertext,
	})
	if err != nil {
		return mfa.TOTPProof{}, ErrAuthentication
	}
	defer clear(secret)
	counter, err := runtime.totp.Validate(string(secret), string(request.Code), request.At, -1)
	if err != nil || counter < 0 {
		return mfa.TOTPProof{}, ErrAuthentication
	}
	return mfa.TOTPProof{Counter: counter}, nil
}

func (runtime *RuntimeCryptography) GenerateRecoveryCodes(
	_ context.Context,
	request RecoveryCodeGenerationRequest,
) (RecoveryCodeBatch, error) {
	if runtime == nil || runtime.tokens == nil || runtime.newID == nil || !validRuntimeID(request.TenantID) ||
		!validRuntimeID(request.UserID) || request.Count < minimumRecoveryCodes || request.Count > maximumRecoveryCodes {
		return RecoveryCodeBatch{}, ErrInvalidInput
	}
	setID, err := runtime.newID()
	if err != nil || setID == uuid.Nil || setID.Version() != 7 {
		return RecoveryCodeBatch{}, ErrUnavailable
	}
	version := runtime.keyring.ActiveVersion()
	if version < 1 {
		return RecoveryCodeBatch{}, ErrUnavailable
	}
	batch := RecoveryCodeBatch{
		SetID: identity.EntityID(setID), DigestKeyVersion: uint32(version),
		Codes: make([]RecoveryCodeMaterial, 0, request.Count),
	}
	for range request.Count {
		code, legacyDigest, generateErr := runtime.tokens.RecoveryCode()
		clear(legacyDigest)
		canonical, canonicalErr := canonicalRecoveryCode([]byte(code))
		if generateErr != nil || canonicalErr != nil {
			destroyRecoveryBatch(&batch)
			return RecoveryCodeBatch{}, ErrUnavailable
		}
		digest, digestErr := runtime.keyring.DigestMFARecoveryCode(identity.MFARecoveryCodeContext{
			TenantID: request.TenantID, UserID: request.UserID, SetID: identity.EntityID(setID),
		}, version, canonical)
		clear(canonical)
		if digestErr != nil {
			destroyRecoveryBatch(&batch)
			return RecoveryCodeBatch{}, ErrUnavailable
		}
		batch.Codes = append(batch.Codes, RecoveryCodeMaterial{Code: []byte(code), Digest: RecoveryCodeDigest(digest)})
	}
	return batch, nil
}

func (runtime *RuntimeCryptography) DigestRecoveryCode(
	_ context.Context,
	request mfa.RecoveryDigestRequest,
) ([sha256.Size]byte, error) {
	if runtime == nil || !validRuntimeID(request.TenantID) || !validRuntimeID(request.UserID) ||
		!validRuntimeID(request.SetID) || request.KeyVersion < 1 || request.KeyVersion > 32_767 {
		return [sha256.Size]byte{}, ErrAuthentication
	}
	canonical, err := canonicalRecoveryCode(request.Code)
	if err != nil {
		return [sha256.Size]byte{}, ErrAuthentication
	}
	defer clear(canonical)
	digest, err := runtime.keyring.DigestMFARecoveryCode(identity.MFARecoveryCodeContext{
		TenantID: request.TenantID, UserID: request.UserID, SetID: request.SetID,
	}, int16(request.KeyVersion), canonical)
	if err != nil {
		return [sha256.Size]byte{}, ErrAuthentication
	}
	return digest, nil
}

func canonicalRecoveryCode(value []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(value))
	if trimmed != string(value) {
		return nil, errors.New("recovery code is not canonical")
	}
	canonical := strings.ToUpper(strings.ReplaceAll(trimmed, "-", ""))
	if len(canonical) != recoveryCanonicalBytes {
		return nil, errors.New("recovery code is invalid")
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(canonical)
	if err != nil || base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(decoded) != canonical {
		clear(decoded)
		return nil, errors.New("recovery code is invalid")
	}
	clear(decoded)
	return []byte(canonical), nil
}

func validRuntimeID(value identity.EntityID) bool {
	id := uuid.UUID(value)
	return id != uuid.Nil && id.Version() == 7
}

// NewDefaultRuntimeCryptography uses the maintained local authentication
// primitives while keeping them behind the narrow MFA ports.
func NewDefaultRuntimeCryptography(
	keyring identity.Keyring,
	admissionRootKey []byte,
) (*RuntimeCryptography, error) {
	return NewRuntimeCryptography(RuntimeCryptographyOptions{
		Keyring: keyring, AdmissionRootKey: admissionRootKey,
		Tokens: authentication.NewTokenGenerator(), TOTP: authentication.NewTOTPManager(),
	})
}
