package authentication

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

const maximumDirectPlatformSAMLTOTPRevision = uint64(9_007_199_254_740_991)

var _ platformsamlauth.DirectSAMLTOTPVerifier = (*Service)(nil)

// VerifyDirectSAMLTOTP opens one platform-owned TOTP factor without a tenant
// context. User proof failures are the only failures allowed to consume an
// attempt; keyring, ciphertext, clock, and runtime failures remain distinct.
func (s *Service) VerifyDirectSAMLTOTP(
	ctx context.Context,
	request platformsamlauth.DirectSAMLTOTPVerificationRequest,
) (platformsamlauth.DirectSAMLTOTPProof, error) {
	if s == nil || s.cipher == nil || s.totp == nil || ctx == nil || ctx.Err() != nil ||
		!validFederatedSessionUUID(uuid.UUID(request.UserID)) ||
		!validFederatedSessionUUID(uuid.UUID(request.FactorID)) || request.UserID == request.FactorID ||
		request.FactorRevision == 0 || request.FactorRevision > maximumDirectPlatformSAMLTOTPRevision ||
		request.UserAuthenticationRevision == 0 ||
		request.UserAuthenticationRevision > maximumDirectPlatformSAMLTOTPRevision ||
		request.At.IsZero() || request.At.Location() != time.UTC || request.At.Unix() < 0 ||
		request.At.Nanosecond()%int(time.Microsecond) != 0 ||
		request.Secret.KeyVersion != 1 || request.Secret.EncryptionAlgorithm != "aes-256-gcm" ||
		request.Secret.OTPAlgorithm != "SHA1" || request.Secret.Digits != 6 ||
		request.Secret.PeriodSeconds != 30 || len(request.Secret.Ciphertext) <= 16 ||
		len(request.Secret.Ciphertext) > 8*1024 || len(request.Secret.Nonce) != 12 ||
		len(request.Secret.AAD) == 0 || len(request.Secret.AAD) > 1024 ||
		request.LastAcceptedCounter != nil && *request.LastAcceptedCounter < 0 {
		return platformsamlauth.DirectSAMLTOTPProof{}, ErrUnavailable
	}
	expectedAAD, aadRevision, validAAD := credentialTOTPDecryptionContext(
		uuid.UUID(request.FactorID), uuid.UUID(request.UserID), request.Secret.AAD,
	)
	if !validAAD || aadRevision != 0 && aadRevision != request.FactorRevision {
		return platformsamlauth.DirectSAMLTOTPProof{}, ErrUnavailable
	}
	if len(request.Code) != int(request.Secret.Digits) {
		return platformsamlauth.DirectSAMLTOTPProof{}, platformsamlauth.ErrDirectSAMLTOTPInvalidProof
	}
	for _, character := range request.Code {
		if character < '0' || character > '9' {
			return platformsamlauth.DirectSAMLTOTPProof{}, platformsamlauth.ErrDirectSAMLTOTPInvalidProof
		}
	}
	encrypted := EncryptedSecret{
		Ciphertext: append([]byte(nil), request.Secret.Ciphertext...),
		Nonce:      append([]byte(nil), request.Secret.Nonce...),
		AAD:        append([]byte(nil), request.Secret.AAD...),
		KeyVersion: request.Secret.KeyVersion,
	}
	defer clear(encrypted.Ciphertext)
	defer clear(encrypted.Nonce)
	defer clear(encrypted.AAD)
	secret, err := s.cipher.DecryptTOTP(expectedAAD, encrypted)
	if err != nil || !validDirectTOTPSecret(secret) || ctx.Err() != nil {
		return platformsamlauth.DirectSAMLTOTPProof{}, ErrUnavailable
	}
	lastAcceptedCounter := int64(-1)
	if request.LastAcceptedCounter != nil {
		lastAcceptedCounter = *request.LastAcceptedCounter
	}
	counter, err := s.totp.Validate(secret, string(request.Code), request.At, lastAcceptedCounter)
	if errors.Is(err, ErrInvalidAuthentication) {
		return platformsamlauth.DirectSAMLTOTPProof{}, platformsamlauth.ErrDirectSAMLTOTPInvalidProof
	}
	if err != nil || counter < 0 || counter <= lastAcceptedCounter || ctx.Err() != nil {
		return platformsamlauth.DirectSAMLTOTPProof{}, ErrUnavailable
	}
	return platformsamlauth.DirectSAMLTOTPProof{Counter: counter}, nil
}
