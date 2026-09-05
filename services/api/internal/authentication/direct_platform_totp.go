package authentication

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

var _ platformoidcauth.DirectTOTPVerifier = (*Service)(nil)

// VerifyDirectTOTP opens one platform-owned account factor without inventing
// a tenant context. Invalid user input is distinguished from keyring or
// ciphertext failures so infrastructure outages never consume an MFA attempt.
func (s *Service) VerifyDirectTOTP(
	ctx context.Context,
	request platformoidcauth.DirectTOTPVerificationRequest,
) (platformoidcauth.DirectTOTPProof, error) {
	if s == nil || s.cipher == nil || s.totp == nil || ctx == nil || ctx.Err() != nil ||
		!validFederatedSessionUUID(uuid.UUID(request.UserID)) ||
		!validFederatedSessionUUID(uuid.UUID(request.FactorID)) || request.UserID == request.FactorID ||
		request.FactorRevision == 0 || request.FactorRevision > maximumDirectPlatformSAMLTOTPRevision ||
		request.At.IsZero() || request.At.Location() != time.UTC || request.At.Unix() < 0 ||
		request.At.Nanosecond()%int(time.Microsecond) != 0 ||
		request.Secret.KeyVersion != 1 || request.Secret.EncryptionAlgorithm != "aes-256-gcm" ||
		request.Secret.OTPAlgorithm != "SHA1" || request.Secret.Digits != 6 ||
		request.Secret.PeriodSeconds != 30 || len(request.Secret.Ciphertext) <= 16 ||
		len(request.Secret.Ciphertext) > 8*1024 || len(request.Secret.Nonce) != 12 ||
		len(request.Secret.AAD) == 0 || len(request.Secret.AAD) > 1024 ||
		len(request.Code) != int(request.Secret.Digits) ||
		request.LastAcceptedCounter != nil && *request.LastAcceptedCounter < 0 {
		return platformoidcauth.DirectTOTPProof{}, ErrUnavailable
	}
	expectedAAD, aadRevision, validAAD := credentialTOTPDecryptionContext(
		uuid.UUID(request.FactorID), uuid.UUID(request.UserID), request.Secret.AAD,
	)
	if !validAAD || aadRevision != 0 && aadRevision != request.FactorRevision {
		return platformoidcauth.DirectTOTPProof{}, ErrUnavailable
	}
	for _, character := range request.Code {
		if character < '0' || character > '9' {
			return platformoidcauth.DirectTOTPProof{}, platformoidcauth.ErrDirectTOTPInvalidProof
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
		return platformoidcauth.DirectTOTPProof{}, ErrUnavailable
	}
	lastAcceptedCounter := int64(-1)
	if request.LastAcceptedCounter != nil {
		lastAcceptedCounter = *request.LastAcceptedCounter
	}
	counter, err := s.totp.Validate(secret, string(request.Code), request.At, lastAcceptedCounter)
	if errors.Is(err, ErrInvalidAuthentication) {
		return platformoidcauth.DirectTOTPProof{}, platformoidcauth.ErrDirectTOTPInvalidProof
	}
	if err != nil || counter < 0 || counter <= lastAcceptedCounter || ctx.Err() != nil {
		return platformoidcauth.DirectTOTPProof{}, ErrUnavailable
	}
	return platformoidcauth.DirectTOTPProof{Counter: counter}, nil
}
