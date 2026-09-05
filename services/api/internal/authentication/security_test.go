package authentication

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
)

func TestPasswordManagerUsesBoundedArgon2idProfile(t *testing.T) {
	manager := PasswordManager{}
	hash, err := manager.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if !strings.Contains(hash, "$argon2id$v=19$m=65536,t=3,p=1$") {
		t.Fatalf("hash does not encode the required profile: %q", hash)
	}
	if !manager.Verify("correct horse battery staple", hash) {
		t.Fatal("Verify() rejected the correct password")
	}
	if manager.Verify("wrong", hash) {
		t.Fatal("Verify() accepted the wrong password")
	}
	if manager.Verify("password", "$argon2id$v=19$m=1048576,t=20,p=8$c2FsdHNhbHQ$aGFzaA") {
		t.Fatal("Verify() accepted an abusive encoded profile")
	}
}

func TestOpaqueTokensAndRecoveryCodesUseIndependentEntropy(t *testing.T) {
	random := bytes.NewReader(bytes.Repeat([]byte{0x5a}, tokenBytes+recoveryCodeBytes))
	generator := newTokenGenerator(random)
	token, err := generator.Opaque()
	if err != nil {
		t.Fatalf("Opaque() error = %v", err)
	}
	if len(token) != 43 {
		t.Fatalf("opaque token length = %d, want 43", len(token))
	}
	code, codeDigest, err := generator.RecoveryCode()
	if err != nil {
		t.Fatalf("RecoveryCode() error = %v", err)
	}
	if len(codeDigest) != sha256DigestLength || strings.Count(code, "-") != 12 || len(code) != 64 {
		t.Fatalf("unexpected recovery code output: %q", code)
	}
	wantDigest, ok := recoveryCodeDigest(strings.ToLower(code))
	if !ok || !bytes.Equal(codeDigest, wantDigest) {
		t.Fatal("display recovery code does not round-trip to its digest")
	}
}

func TestSecretCipherBindsTOTPToContext(t *testing.T) {
	if _, err := NewSecretCipher(make([]byte, 32)); err == nil {
		t.Fatal("NewSecretCipher() accepted an all-zero master key")
	}
	cipher, err := NewSecretCipher(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatalf("NewSecretCipher() error = %v", err)
	}
	contextID := uuid.Must(uuid.NewV7())
	aadContext := bootstrapTOTPContext(contextID, "admin@example.invalid")
	encrypted, err := cipher.EncryptTOTP(aadContext, "JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("EncryptTOTP() error = %v", err)
	}
	plaintext, err := cipher.DecryptTOTP(aadContext, encrypted)
	if err != nil || plaintext != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("DecryptTOTP() = %q, %v", plaintext, err)
	}
	if _, err := cipher.DecryptTOTP(bootstrapTOTPContext(uuid.Must(uuid.NewV7()), "admin@example.invalid"), encrypted); err == nil {
		t.Fatal("DecryptTOTP() accepted a different credential context")
	}
	encrypted.Ciphertext[0] ^= 0xff
	if _, err := cipher.DecryptTOTP(aadContext, encrypted); err == nil {
		t.Fatal("DecryptTOTP() accepted tampered ciphertext")
	}
}

func TestTOTPManagerRejectsZeroEntropy(t *testing.T) {
	manager := TOTPManager{random: bytes.NewReader(make([]byte, 32))}
	secret, provisioningURI, err := manager.Generate("01900000-0000-7000-8000-000000000001")
	if err == nil || secret != "" || provisioningURI != "" {
		t.Fatalf("Generate() = %q, %q, %v", secret, provisioningURI, err)
	}
}

func TestTOTPSecretAndCipherFormattingRemainRedacted(t *testing.T) {
	canary := []byte("totp-secret-material-canary")
	encrypted := EncryptedSecret{
		Ciphertext: canary, Nonce: canary, AAD: canary, KeyVersion: 1,
	}
	if strings.Contains(fmt.Sprintf("%#v", encrypted), string(canary)) {
		t.Fatal("encrypted TOTP formatting leaked material")
	}
	cipher, err := NewSecretCipher(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%#v", cipher), "42424242") {
		t.Fatal("secret cipher formatting leaked key material")
	}
}

func TestTOTPManagerRejectsTimeStepReplay(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	now := time.Unix(1_800_000_000, 0).UTC()
	code, err := totp.GenerateCodeCustom(secret, now, totp.ValidateOpts{
		Period:    uint(totpPeriod),
		Skew:      0,
		Digits:    6,
		Algorithm: 0,
	})
	if err != nil {
		t.Fatalf("GenerateCodeCustom() error = %v", err)
	}
	counter, err := (TOTPManager{}).Validate(secret, code, now, -1)
	if err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if _, err := (TOTPManager{}).Validate(secret, code, now, counter); err == nil {
		t.Fatal("Validate() accepted the same TOTP time-step twice")
	}
}

func TestCredentialTOTPContextAcceptsOnlyExactLegacyOrCanonicalV2(t *testing.T) {
	t.Parallel()
	factorID := uuid.MustParse("01900000-0000-7000-8000-000000000001")
	userID := uuid.MustParse("01900000-0000-7000-8000-000000000002")
	legacy := credentialTOTPContext(factorID, userID)
	if context, revision, ok := credentialTOTPDecryptionContext(factorID, userID, []byte(legacy)); !ok || context != legacy || revision != 0 {
		t.Fatalf("legacy context = %q, %d, %t", context, revision, ok)
	}
	v2, err := CredentialTOTPContextAtRevision(factorID, userID, 7)
	if err != nil {
		t.Fatal(err)
	}
	if context, revision, ok := credentialTOTPDecryptionContext(factorID, userID, []byte(v2)); !ok || context != v2 || revision != 7 {
		t.Fatalf("v2 context = %q, %d, %t", context, revision, ok)
	}

	prefix := "totp_credential:v2:factor:" + factorID.String() + ":user:" + userID.String() + ":revision:"
	for _, malformed := range []string{
		prefix, prefix + "0", prefix + "01", prefix + "+1", prefix + "1 ", prefix + "1:trailing",
		prefix + "9007199254740992",
		strings.Replace(v2, factorID.String(), "01900000-0000-7000-8000-000000000003", 1),
		strings.Replace(v2, userID.String(), "01900000-0000-7000-8000-000000000004", 1),
		legacy + ":revision:7",
	} {
		if context, revision, ok := credentialTOTPDecryptionContext(factorID, userID, []byte(malformed)); ok || context != "" || revision != 0 {
			t.Fatalf("accepted malformed context %q as %q/%d", malformed, context, revision)
		}
	}

	invalidVariant := uuid.MustParse("01900000-0000-7000-0000-000000000005")
	if _, err := CredentialTOTPContextAtRevision(invalidVariant, userID, 1); err == nil {
		t.Fatal("accepted a non-RFC4122 UUIDv7 factor")
	}
	if _, err := CredentialTOTPContextAtRevision(factorID, factorID, 1); err == nil {
		t.Fatal("accepted identical factor and user IDs")
	}
}
