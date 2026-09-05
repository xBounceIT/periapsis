package authentication

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

func TestVerifyDirectTOTPUsesExactPlatformFactorContext(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 14, 0, 0, 0, time.UTC)
	userID := uuid.Must(uuid.NewV7())
	factorID := uuid.Must(uuid.NewV7())
	lastCounter := int64(40)
	service := &Service{cipher: secretCryptorStub{}, totp: totpEngineStub{counter: 41}}
	request := directPlatformTOTPVerificationRequest(now, userID, factorID, &lastCounter)
	proof, err := service.VerifyDirectTOTP(context.Background(), request)
	if err != nil || proof.Counter != 41 {
		t.Fatalf("VerifyDirectTOTP() = %#v, %v", proof, err)
	}
	request.Secret.AAD = []byte(credentialTOTPContext(uuid.Must(uuid.NewV7()), userID))
	if proof, err = service.VerifyDirectTOTP(context.Background(), request); !errors.Is(err, ErrUnavailable) || proof != (platformoidcauth.DirectTOTPProof{}) {
		t.Fatalf("cross-factor VerifyDirectTOTP() = %#v, %v", proof, err)
	}
	v2Context, contextErr := CredentialTOTPContextAtRevision(factorID, userID, 7)
	if contextErr != nil {
		t.Fatal(contextErr)
	}
	request = directPlatformTOTPVerificationRequest(now, userID, factorID, &lastCounter)
	request.FactorRevision = 7
	request.Secret.AAD = []byte(v2Context)
	if proof, err = service.VerifyDirectTOTP(context.Background(), request); err != nil || proof.Counter != 41 {
		t.Fatalf("v2 VerifyDirectTOTP() = %#v, %v", proof, err)
	}
	request.FactorRevision = 8
	if proof, err = service.VerifyDirectTOTP(context.Background(), request); !errors.Is(err, ErrUnavailable) ||
		proof != (platformoidcauth.DirectTOTPProof{}) {
		t.Fatalf("stale v2 revision VerifyDirectTOTP() = %#v, %v", proof, err)
	}
}

func TestVerifyDirectTOTPDistinguishesInvalidProofFromRuntimeFailure(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 30, 14, 0, 0, 0, time.UTC)
	userID := uuid.Must(uuid.NewV7())
	factorID := uuid.Must(uuid.NewV7())
	request := directPlatformTOTPVerificationRequest(now, userID, factorID, nil)
	invalid := &Service{
		cipher: secretCryptorStub{},
		totp:   totpEngineStub{validateError: ErrInvalidAuthentication},
	}
	if proof, err := invalid.VerifyDirectTOTP(context.Background(), request); !errors.Is(err, platformoidcauth.ErrDirectTOTPInvalidProof) ||
		proof != (platformoidcauth.DirectTOTPProof{}) {
		t.Fatalf("invalid proof = %#v, %v", proof, err)
	}
	broken := &Service{
		cipher: directPlatformTOTPSecretCryptorFunc(func(string, EncryptedSecret) (string, error) {
			return "", errors.New("key unavailable")
		}),
		totp: totpEngineStub{counter: 41},
	}
	if proof, err := broken.VerifyDirectTOTP(context.Background(), request); !errors.Is(err, ErrUnavailable) || errors.Is(err, platformoidcauth.ErrDirectTOTPInvalidProof) ||
		proof != (platformoidcauth.DirectTOTPProof{}) {
		t.Fatalf("runtime failure = %#v, %v", proof, err)
	}
	zeroSecret := &Service{
		cipher: directPlatformTOTPSecretCryptorFunc(func(string, EncryptedSecret) (string, error) {
			return "AAAAAAAAAAAAAAAA", nil
		}),
		totp: totpEngineStub{counter: 41},
	}
	if proof, err := zeroSecret.VerifyDirectTOTP(context.Background(), request); !errors.Is(err, ErrUnavailable) ||
		errors.Is(err, platformoidcauth.ErrDirectTOTPInvalidProof) || proof != (platformoidcauth.DirectTOTPProof{}) {
		t.Fatalf("zero secret = %#v, %v", proof, err)
	}
	malformedSecret := &Service{
		cipher: directPlatformTOTPSecretCryptorFunc(func(string, EncryptedSecret) (string, error) {
			return "not-a-canonical-base32-secret", nil
		}),
		totp: totpEngineStub{counter: 41},
	}
	if proof, err := malformedSecret.VerifyDirectTOTP(context.Background(), request); !errors.Is(err, ErrUnavailable) ||
		errors.Is(err, platformoidcauth.ErrDirectTOTPInvalidProof) || proof != (platformoidcauth.DirectTOTPProof{}) {
		t.Fatalf("malformed secret = %#v, %v", proof, err)
	}
	request = directPlatformTOTPVerificationRequest(
		time.Date(1960, 1, 1, 0, 0, 0, 0, time.UTC), userID, factorID, nil,
	)
	if proof, err := invalid.VerifyDirectTOTP(context.Background(), request); !errors.Is(err, ErrUnavailable) ||
		errors.Is(err, platformoidcauth.ErrDirectTOTPInvalidProof) || proof != (platformoidcauth.DirectTOTPProof{}) {
		t.Fatalf("invalid clock = %#v, %v", proof, err)
	}
}

type directPlatformTOTPSecretCryptorFunc func(string, EncryptedSecret) (string, error)

func (function directPlatformTOTPSecretCryptorFunc) EncryptTOTP(string, string) (EncryptedSecret, error) {
	return EncryptedSecret{}, errors.New("unused")
}

func (function directPlatformTOTPSecretCryptorFunc) DecryptTOTP(
	context string,
	secret EncryptedSecret,
) (string, error) {
	return function(context, secret)
}

func directPlatformTOTPVerificationRequest(
	now time.Time,
	userID uuid.UUID,
	factorID uuid.UUID,
	lastCounter *int64,
) platformoidcauth.DirectTOTPVerificationRequest {
	aad := credentialTOTPContext(factorID, userID)
	return platformoidcauth.DirectTOTPVerificationRequest{
		UserID: identity.EntityID(userID), FactorID: identity.EntityID(factorID),
		FactorRevision: 1,
		Secret: platformoidcauth.DirectProtectedTOTPSecret{
			Ciphertext: []byte("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"),
			Nonce:      []byte("123456789012"), AAD: []byte(aad), KeyVersion: 1,
			EncryptionAlgorithm: "aes-256-gcm", OTPAlgorithm: "SHA1", Digits: 6, PeriodSeconds: 30,
		},
		Code: []byte("123456"), At: now, LastAcceptedCounter: lastCounter,
	}
}
