package identity

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestMFASecretKeyringBindsCiphertextAndRecoveryDigestsToTypedContext(t *testing.T) {
	keyring, err := newKeyring(2, map[int16][]byte{
		1: bytes.Repeat([]byte{0x11}, 32),
		2: bytes.Repeat([]byte{0x22}, 32),
	}, bytes.NewReader(bytes.Repeat([]byte{0xA5}, 128)))
	if err != nil {
		t.Fatalf("newKeyring() error = %v", err)
	}
	totpContext := MFATOTPContext{TenantID: mfaSecretTestID(1), UserID: mfaSecretTestID(2), FactorID: mfaSecretTestID(3)}
	secret := []byte("JBSWY3DPEHPK3PXP")
	envelope, err := keyring.EncryptMFATOTPSecret(totpContext, secret)
	if err != nil {
		t.Fatalf("EncryptMFATOTPSecret() error = %v", err)
	}
	plaintext, err := keyring.DecryptMFATOTPSecret(totpContext, envelope)
	if err != nil || !bytes.Equal(plaintext, secret) {
		t.Fatalf("DecryptMFATOTPSecret() = %q, %v", plaintext, err)
	}
	clear(plaintext)

	wrongContext := totpContext
	wrongContext.FactorID = mfaSecretTestID(4)
	if plaintext, err = keyring.DecryptMFATOTPSecret(wrongContext, envelope); err == nil || plaintext != nil {
		t.Fatal("DecryptMFATOTPSecret accepted a cross-factor envelope")
	}
	tampered := envelope
	tampered.Ciphertext = append([]byte(nil), envelope.Ciphertext...)
	tampered.Ciphertext[0] ^= 0xff
	if plaintext, err = keyring.DecryptMFATOTPSecret(totpContext, tampered); err == nil || plaintext != nil {
		t.Fatal("DecryptMFATOTPSecret accepted tampered ciphertext")
	}
	if got := fmt.Sprintf("%#v", envelope); bytes.Contains([]byte(got), secret) ||
		!bytes.Contains([]byte(got), []byte("[REDACTED]")) {
		t.Fatalf("envelope formatting leaked material: %q", got)
	}

	recoveryContext := MFARecoveryCodeContext{
		TenantID: mfaSecretTestID(1), UserID: mfaSecretTestID(2), SetID: mfaSecretTestID(5),
	}
	code := bytes.Repeat([]byte{'A'}, 52)
	first, err := keyring.DigestMFARecoveryCode(recoveryContext, 2, code)
	if err != nil || first == ([sha256.Size]byte{}) {
		t.Fatalf("DigestMFARecoveryCode() = %x, %v", first, err)
	}
	second, err := keyring.DigestMFARecoveryCode(recoveryContext, 2, code)
	if err != nil || first != second {
		t.Fatal("recovery digest is not deterministic")
	}
	otherSet := recoveryContext
	otherSet.SetID = mfaSecretTestID(6)
	third, err := keyring.DigestMFARecoveryCode(otherSet, 2, code)
	if err != nil || third == first {
		t.Fatal("recovery digest was not set-bound")
	}
	if _, err := keyring.DigestMFARecoveryCode(recoveryContext, 3, code); err == nil {
		t.Fatal("recovery digest accepted an unknown key version")
	}
	invalid := append([]byte(nil), code...)
	invalid[0] = '-'
	if _, err := keyring.DigestMFARecoveryCode(recoveryContext, 2, invalid); err == nil {
		t.Fatal("recovery digest accepted a non-canonical code")
	}
}

func mfaSecretTestID(value byte) EntityID {
	var id EntityID
	id[len(id)-1] = value
	return id
}
