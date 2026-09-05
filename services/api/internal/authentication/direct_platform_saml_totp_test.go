package authentication

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

func TestVerifyDirectSAMLTOTPUsesExactPlatformFactorAndClearsOwnedEnvelope(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 18, 30, 0, 0, time.UTC)
	userID := uuid.Must(uuid.NewV7())
	factorID := uuid.Must(uuid.NewV7())
	lastCounter := int64(40)
	var capturedCiphertext, capturedNonce, capturedAAD []byte
	cryptor := directPlatformSAMLTOTPSecretCryptorFunc(func(context string, secret EncryptedSecret) (string, error) {
		if context != credentialTOTPContext(factorID, userID) {
			t.Fatalf("decrypt context = %q", context)
		}
		capturedCiphertext, capturedNonce, capturedAAD = secret.Ciphertext, secret.Nonce, secret.AAD
		return "JBSWY3DPEHPK3PXP", nil
	})
	service := &Service{cipher: cryptor, totp: totpEngineStub{counter: 41}}
	request := directPlatformSAMLTOTPVerificationRequest(now, userID, factorID, &lastCounter)
	proof, err := service.VerifyDirectSAMLTOTP(context.Background(), request)
	if err != nil || proof.Counter != 41 {
		t.Fatalf("VerifyDirectSAMLTOTP() = %#v, %v", proof, err)
	}
	for name, value := range map[string][]byte{
		"ciphertext": capturedCiphertext, "nonce": capturedNonce, "aad": capturedAAD,
	} {
		for _, item := range value {
			if item != 0 {
				t.Fatalf("owned %s was not cleared: %x", name, value)
			}
		}
	}
	request.Secret.AAD = []byte(credentialTOTPContext(uuid.Must(uuid.NewV7()), userID))
	if proof, err = service.VerifyDirectSAMLTOTP(context.Background(), request); !errors.Is(err, ErrUnavailable) ||
		proof != (platformsamlauth.DirectSAMLTOTPProof{}) {
		t.Fatalf("cross-factor VerifyDirectSAMLTOTP() = %#v, %v", proof, err)
	}
	v2Context, contextErr := CredentialTOTPContextAtRevision(factorID, userID, request.FactorRevision)
	if contextErr != nil {
		t.Fatal(contextErr)
	}
	request = directPlatformSAMLTOTPVerificationRequest(now, userID, factorID, &lastCounter)
	request.Secret.AAD = []byte(v2Context)
	v2Service := &Service{cipher: secretCryptorStub{}, totp: totpEngineStub{counter: 41}}
	if proof, err = v2Service.VerifyDirectSAMLTOTP(context.Background(), request); err != nil || proof.Counter != 41 {
		t.Fatalf("v2 VerifyDirectSAMLTOTP() = %#v, %v", proof, err)
	}
	request.FactorRevision++
	if proof, err = v2Service.VerifyDirectSAMLTOTP(context.Background(), request); !errors.Is(err, ErrUnavailable) ||
		proof != (platformsamlauth.DirectSAMLTOTPProof{}) {
		t.Fatalf("stale v2 revision VerifyDirectSAMLTOTP() = %#v, %v", proof, err)
	}
}

func TestVerifyDirectSAMLTOTPDistinguishesUserProofFromRuntimeFailure(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 18, 31, 0, 0, time.UTC)
	userID := uuid.Must(uuid.NewV7())
	factorID := uuid.Must(uuid.NewV7())
	request := directPlatformSAMLTOTPVerificationRequest(now, userID, factorID, nil)

	invalid := &Service{cipher: secretCryptorStub{}, totp: totpEngineStub{validateError: ErrInvalidAuthentication}}
	if proof, err := invalid.VerifyDirectSAMLTOTP(context.Background(), request); !errors.Is(err, platformsamlauth.ErrDirectSAMLTOTPInvalidProof) ||
		proof != (platformsamlauth.DirectSAMLTOTPProof{}) {
		t.Fatalf("invalid proof = %#v, %v", proof, err)
	}
	request.Code = []byte("12345")
	if proof, err := invalid.VerifyDirectSAMLTOTP(context.Background(), request); !errors.Is(err, platformsamlauth.ErrDirectSAMLTOTPInvalidProof) ||
		proof != (platformsamlauth.DirectSAMLTOTPProof{}) {
		t.Fatalf("invalid length = %#v, %v", proof, err)
	}
	request = directPlatformSAMLTOTPVerificationRequest(now, userID, factorID, nil)
	broken := &Service{
		cipher: directPlatformSAMLTOTPSecretCryptorFunc(func(string, EncryptedSecret) (string, error) {
			return "", errors.New("key unavailable")
		}),
		totp: totpEngineStub{counter: 41},
	}
	if proof, err := broken.VerifyDirectSAMLTOTP(context.Background(), request); !errors.Is(err, ErrUnavailable) ||
		errors.Is(err, platformsamlauth.ErrDirectSAMLTOTPInvalidProof) ||
		proof != (platformsamlauth.DirectSAMLTOTPProof{}) {
		t.Fatalf("runtime failure = %#v, %v", proof, err)
	}
	request = directPlatformSAMLTOTPVerificationRequest(
		time.Date(1960, 1, 1, 0, 0, 0, 0, time.UTC), userID, factorID, nil,
	)
	if proof, err := invalid.VerifyDirectSAMLTOTP(context.Background(), request); !errors.Is(err, ErrUnavailable) ||
		errors.Is(err, platformsamlauth.ErrDirectSAMLTOTPInvalidProof) ||
		proof != (platformsamlauth.DirectSAMLTOTPProof{}) {
		t.Fatalf("invalid clock = %#v, %v", proof, err)
	}
}

type directPlatformSAMLTOTPSecretCryptorFunc func(string, EncryptedSecret) (string, error)

func (function directPlatformSAMLTOTPSecretCryptorFunc) EncryptTOTP(string, string) (EncryptedSecret, error) {
	return EncryptedSecret{}, errors.New("unused")
}

func (function directPlatformSAMLTOTPSecretCryptorFunc) DecryptTOTP(context string, secret EncryptedSecret) (string, error) {
	return function(context, secret)
}

func directPlatformSAMLTOTPVerificationRequest(
	now time.Time,
	userID uuid.UUID,
	factorID uuid.UUID,
	lastCounter *int64,
) platformsamlauth.DirectSAMLTOTPVerificationRequest {
	aad := credentialTOTPContext(factorID, userID)
	return platformsamlauth.DirectSAMLTOTPVerificationRequest{
		UserID: identity.EntityID(userID), FactorID: identity.EntityID(factorID),
		FactorRevision: 7, UserAuthenticationRevision: 8,
		Secret: platformsamlauth.DirectSAMLProtectedTOTPSecret{
			Ciphertext: []byte("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"),
			Nonce:      []byte("123456789012"), AAD: []byte(aad), KeyVersion: 1,
			EncryptionAlgorithm: "aes-256-gcm", OTPAlgorithm: "SHA1", Digits: 6, PeriodSeconds: 30,
		},
		Code: []byte("123456"), At: now, LastAcceptedCounter: lastCounter,
	}
}
