package mfaauth

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

type runtimeTokenSource struct{ recovery int }

func (*runtimeTokenSource) Opaque() (string, error) {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, 32)), nil
}
func (source *runtimeTokenSource) RecoveryCode() (string, []byte, error) {
	raw := bytes.Repeat([]byte{byte(source.recovery + 1)}, 32)
	code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	clear(raw)
	source.recovery++
	return code, bytes.Repeat([]byte{0x99}, 32), nil
}

type runtimeTOTPEngine struct{}

func (runtimeTOTPEngine) Generate(account string) (string, string, error) {
	secret := "JBSWY3DPEHPK3PXP"
	return secret, "otpauth://totp/Periapsis:" + account + "?secret=" + secret + "&issuer=Periapsis", nil
}
func (runtimeTOTPEngine) Validate(secret, code string, _ time.Time, counter int64) (int64, error) {
	if secret != "JBSWY3DPEHPK3PXP" || code != "123456" || counter != -1 {
		return 0, errors.New("invalid proof")
	}
	return 42, nil
}

func TestRuntimeCryptographyProducesTypedAdmissionAndMFAArtifacts(t *testing.T) {
	keyring, err := identity.NewKeyring(2, map[int16][]byte{
		1: bytes.Repeat([]byte{0x11}, 32), 2: bytes.Repeat([]byte{0x22}, 32),
	})
	if err != nil {
		t.Fatalf("NewKeyring() error = %v", err)
	}
	runtime, err := NewRuntimeCryptography(RuntimeCryptographyOptions{
		Keyring: keyring, AdmissionRootKey: bytes.Repeat([]byte{0x31}, 32),
		Tokens: &runtimeTokenSource{}, TOTP: runtimeTOTPEngine{}, NewID: uuid.NewV7,
	})
	if err != nil {
		t.Fatalf("NewRuntimeCryptography() error = %v", err)
	}
	tenantID, userID := runtimeEntityID(t), runtimeEntityID(t)
	admission, err := runtime.Admission(netip.MustParseAddr("198.51.100.7"), userID, "mfa.device.enroll")
	if err != nil || !validAdmission(admission) {
		t.Fatalf("Admission() = %#v, %v", admission, err)
	}
	if got := runtime.String(); got != "mfaauth.RuntimeCryptography{material:[REDACTED]}" {
		t.Fatalf("String() = %q", got)
	}

	material, err := runtime.NewTOTPEnrollmentMaterial(context.Background(), tenantID, userID)
	if err != nil || !validTOTPEnrollmentMaterial(material) {
		t.Fatalf("NewTOTPEnrollmentMaterial() = %#v, %v", material, err)
	}
	proof, err := runtime.VerifyTOTP(context.Background(), mfa.TOTPVerificationRequest{
		TenantID: tenantID, UserID: userID, FactorID: material.FactorID,
		Secret: material.ProtectedSecret, Code: []byte("123456"),
		At: time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC),
	})
	if err != nil || proof.Counter != 42 {
		t.Fatalf("VerifyTOTP() = %#v, %v", proof, err)
	}
	wrongFactor := runtimeEntityID(t)
	if _, err := runtime.VerifyTOTP(context.Background(), mfa.TOTPVerificationRequest{
		TenantID: tenantID, UserID: userID, FactorID: wrongFactor,
		Secret: material.ProtectedSecret, Code: []byte("123456"),
		At: time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC),
	}); err == nil {
		t.Fatal("VerifyTOTP accepted ciphertext under another factor")
	}

	batch, err := runtime.GenerateRecoveryCodes(context.Background(), RecoveryCodeGenerationRequest{
		TenantID: tenantID, UserID: userID, Count: 10,
	})
	if err != nil || !validRecoveryBatch(batch, 10) {
		t.Fatalf("GenerateRecoveryCodes() = %#v, %v", batch, err)
	}
	digest, err := runtime.DigestRecoveryCode(context.Background(), mfa.RecoveryDigestRequest{
		SetID: batch.SetID, TenantID: tenantID, UserID: userID,
		KeyVersion: batch.DigestKeyVersion, Code: batch.Codes[0].Code,
	})
	if err != nil || RecoveryCodeDigest(digest) != batch.Codes[0].Digest {
		t.Fatalf("DigestRecoveryCode() did not reproduce the stored digest: %v", err)
	}
	if _, err := runtime.DigestRecoveryCode(context.Background(), mfa.RecoveryDigestRequest{
		SetID: runtimeEntityID(t), TenantID: tenantID, UserID: userID,
		KeyVersion: batch.DigestKeyVersion, Code: batch.Codes[0].Code,
	}); err != nil {
		// A different set is valid input but must produce a different digest.
		t.Fatalf("DigestRecoveryCode(other set) error = %v", err)
	}
	other, _ := runtime.DigestRecoveryCode(context.Background(), mfa.RecoveryDigestRequest{
		SetID: runtimeEntityID(t), TenantID: tenantID, UserID: userID,
		KeyVersion: batch.DigestKeyVersion, Code: batch.Codes[0].Code,
	})
	if other == digest {
		t.Fatal("recovery digest was not bound to its set")
	}
	destroyRecoveryBatch(&batch)
	material.destroy()
}

func TestRuntimeCryptographyFailsClosedOnInvalidConfigurationAndInputs(t *testing.T) {
	if _, err := NewRuntimeCryptography(RuntimeCryptographyOptions{}); err == nil {
		t.Fatal("NewRuntimeCryptography accepted empty dependencies")
	}
	keyring, _ := identity.NewKeyring(1, map[int16][]byte{1: bytes.Repeat([]byte{0x11}, 32)})
	runtime, err := NewRuntimeCryptography(RuntimeCryptographyOptions{
		Keyring: keyring, AdmissionRootKey: bytes.Repeat([]byte{0x31}, 32),
		Tokens: &runtimeTokenSource{}, TOTP: runtimeTOTPEngine{}, NewID: uuid.NewV7,
	})
	if err != nil {
		t.Fatalf("NewRuntimeCryptography() error = %v", err)
	}
	if _, err := runtime.Admission(netip.Addr{}, runtimeEntityID(t), "mfa.device.enroll"); err == nil {
		t.Fatal("Admission accepted an invalid network")
	}
	if _, err := runtime.DigestRecoveryCode(context.Background(), mfa.RecoveryDigestRequest{
		SetID: runtimeEntityID(t), TenantID: runtimeEntityID(t), UserID: runtimeEntityID(t),
		KeyVersion: 1, Code: []byte(" lower "),
	}); err == nil {
		t.Fatal("DigestRecoveryCode accepted a non-canonical code")
	}
}

func runtimeEntityID(t *testing.T) identity.EntityID {
	t.Helper()
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("uuid.NewV7() error = %v", err)
	}
	return identity.EntityID(id)
}
