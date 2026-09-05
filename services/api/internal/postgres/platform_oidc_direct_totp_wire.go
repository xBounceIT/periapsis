package postgres

import (
	"crypto/sha256"
	"net/netip"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

const (
	maximumPlatformOIDCDirectTOTPWireBytes = 64 * 1024
	maximumPlatformOIDCDirectRevision      = uint64(maximumMFAJSONSafeInteger)
	maximumPlatformOIDCDirectTOTPFailures  = uint32(5)
	maximumPlatformOIDCAuditUserAgentBytes = 512
	maximumPlatformOIDCDirectSessionAge    = 30 * 24 * time.Hour
)

type platformOIDCDirectAuditWire struct {
	EventID              string `json:"eventId"`
	RequestID            string `json:"requestId"`
	CorrelationID        string `json:"correlationId"`
	IPAddress            string `json:"ipAddress"`
	UserAgent            string `json:"userAgent"`
	AuthenticationMethod string `json:"authenticationMethod"`
}

type platformOIDCDirectTOTPChallengeInputWire struct {
	ID            []byte    `json:"id"`
	BrowserDigest []byte    `json:"browserDigest"`
	CreatedAt     time.Time `json:"createdAt"`
	ExpiresAt     time.Time `json:"expiresAt"`
}

type platformOIDCDirectTOTPBeginWire struct {
	ContinuationID  string                                   `json:"continuationId"`
	ReceiptDigest   []byte                                   `json:"receiptDigest"`
	ExpectedVersion uint64                                   `json:"expectedVersion"`
	Challenge       platformOIDCDirectTOTPChallengeInputWire `json:"challenge"`
	ObservedAt      time.Time                                `json:"observedAt"`
	Audit           platformOIDCDirectAuditWire              `json:"audit"`
}

type platformOIDCDirectTOTPLookupWire struct {
	ChallengeID    []byte    `json:"challengeId"`
	BrowserDigest  []byte    `json:"browserDigest"`
	ContinuationID string    `json:"continuationId"`
	ReceiptDigest  []byte    `json:"receiptDigest"`
	ObservedAt     time.Time `json:"observedAt"`
}

type platformOIDCDirectTOTPFailureWire struct {
	ChallengeID     []byte                      `json:"challengeId"`
	BrowserDigest   []byte                      `json:"browserDigest"`
	ContinuationID  string                      `json:"continuationId"`
	ReceiptDigest   []byte                      `json:"receiptDigest"`
	ExpectedVersion uint64                      `json:"expectedVersion"`
	ObservedAt      time.Time                   `json:"observedAt"`
	Audit           platformOIDCDirectAuditWire `json:"audit"`
}

type platformOIDCDirectSessionWire struct {
	ID                string    `json:"id"`
	RotationFamilyID  string    `json:"rotationFamilyId"`
	TokenDigest       []byte    `json:"tokenDigest"`
	CSRFSecretDigest  []byte    `json:"csrfSecretDigest"`
	Audience          string    `json:"audience"`
	IdleExpiresAt     time.Time `json:"idleExpiresAt"`
	AbsoluteExpiresAt time.Time `json:"absoluteExpiresAt"`
	SessionVersion    uint64    `json:"sessionVersion"`
}

type platformOIDCDirectTOTPApplyWire struct {
	ChallengeID             []byte                        `json:"challengeId"`
	BrowserDigest           []byte                        `json:"browserDigest"`
	ContinuationID          string                        `json:"continuationId"`
	ReceiptDigest           []byte                        `json:"receiptDigest"`
	ExpectedVersion         uint64                        `json:"expectedVersion"`
	AcceptedCounter         int64                         `json:"acceptedCounter"`
	CompletionRequestDigest []byte                        `json:"completionRequestDigest"`
	Session                 platformOIDCDirectSessionWire `json:"session"`
	ObservedAt              time.Time                     `json:"observedAt"`
	Audit                   platformOIDCDirectAuditWire   `json:"audit"`
}

type platformOIDCDirectTOTPAbandonWire struct {
	ChallengeID     []byte                      `json:"challengeId"`
	BrowserDigest   []byte                      `json:"browserDigest"`
	ContinuationID  string                      `json:"continuationId"`
	ReceiptDigest   []byte                      `json:"receiptDigest"`
	ExpectedVersion uint64                      `json:"expectedVersion"`
	ObservedAt      time.Time                   `json:"observedAt"`
	Reason          string                      `json:"reason"`
	Audit           platformOIDCDirectAuditWire `json:"audit"`
}

type platformOIDCDirectTOTPChallengeWire struct {
	ChallengeID                []byte    `json:"challengeId"`
	ContinuationID             string    `json:"continuationId"`
	UserID                     string    `json:"userId"`
	TOTPCredentialID           string    `json:"totpCredentialId"`
	UserAuthenticationRevision uint64    `json:"userAuthenticationRevision"`
	TOTPSecurityRevision       uint64    `json:"totpSecurityRevision"`
	FailureCount               uint32    `json:"failureCount"`
	State                      string    `json:"state"`
	Version                    uint64    `json:"version"`
	ExpiresAt                  time.Time `json:"expiresAt"`
}

type platformOIDCDirectTOTPVerificationWire struct {
	Authority                  string    `json:"authority"`
	ChallengeID                []byte    `json:"challengeId"`
	ContinuationID             string    `json:"continuationId"`
	UserID                     string    `json:"userId"`
	ReceiptDigest              []byte    `json:"receiptDigest"`
	TOTPCredentialID           string    `json:"totpCredentialId"`
	SecretCiphertext           []byte    `json:"secretCiphertext"`
	SecretNonce                []byte    `json:"secretNonce"`
	SecretAAD                  []byte    `json:"secretAad"`
	KeyVersion                 int16     `json:"keyVersion"`
	EncryptionAlgorithm        string    `json:"encryptionAlgorithm"`
	OTPAlgorithm               string    `json:"otpAlgorithm"`
	Digits                     uint8     `json:"digits"`
	PeriodSeconds              uint16    `json:"periodSeconds"`
	LastAcceptedCounter        *int64    `json:"lastAcceptedCounter,omitempty"`
	UserAuthenticationRevision uint64    `json:"userAuthenticationRevision"`
	TOTPSecurityRevision       uint64    `json:"totpSecurityRevision"`
	ExpiresAt                  time.Time `json:"expiresAt"`
	Version                    uint64    `json:"version"`
}

type platformOIDCDirectTOTPApplyResultWire struct {
	Applied              bool    `json:"applied"`
	Category             string  `json:"category"`
	SessionID            *string `json:"sessionId,omitempty"`
	UserID               *string `json:"userId,omitempty"`
	ExternalIdentityID   *string `json:"externalIdentityId,omitempty"`
	AcceptedCounter      *int64  `json:"acceptedCounter,omitempty"`
	TOTPCredentialID     *string `json:"totpCredentialId,omitempty"`
	TOTPSecurityRevision *uint64 `json:"totpSecurityRevision,omitempty"`
}

func platformOIDCDirectAuditToWire(
	value platformoidcauth.DirectAuditContext,
	eventID uuid.UUID,
) (platformOIDCDirectAuditWire, error) {
	requestID, requestErr := requiredFederatedEntityIDWire(value.RequestID)
	correlationID, correlationErr := requiredFederatedEntityIDWire(value.CorrelationID)
	if requestErr != nil || correlationErr != nil || !platformOIDCDirectUUIDv7(eventID) ||
		!validPlatformOIDCDirectAuditAddress(value.RemoteAddress) || value.UserAgent == "" ||
		len(value.UserAgent) > maximumPlatformOIDCAuditUserAgentBytes || !utf8.ValidString(value.UserAgent) {
		return platformOIDCDirectAuditWire{}, errFederatedAuthPersistence
	}
	for _, character := range value.UserAgent {
		if unicode.IsControl(character) || platformOIDCDirectionalControl(character) {
			return platformOIDCDirectAuditWire{}, errFederatedAuthPersistence
		}
	}
	return platformOIDCDirectAuditWire{
		EventID: eventID.String(), RequestID: requestID, CorrelationID: correlationID,
		IPAddress: value.RemoteAddress.String(), UserAgent: value.UserAgent,
		AuthenticationMethod: "oidc",
	}, nil
}

func platformOIDCDirectTOTPBeginToWire(
	value platformoidcauth.DirectTOTPBeginRequest,
	eventID uuid.UUID,
) (platformOIDCDirectTOTPBeginWire, error) {
	continuationID, idErr := requiredFederatedEntityIDWire(value.ContinuationID)
	audit, auditErr := platformOIDCDirectAuditToWire(value.Audit, eventID)
	if idErr != nil || auditErr != nil || !validPlatformOIDCDigest(value.ReceiptDigest[:]) ||
		value.ExpectedContinuationVersion != 1 || !validPlatformOIDCDigest(value.ChallengeID[:]) ||
		!validPlatformOIDCDigest(value.BrowserDigest[:]) || !validFederatedDatabaseTime(value.CreatedAt) ||
		!validFederatedDatabaseTime(value.ExpiresAt) || !value.ExpiresAt.After(value.CreatedAt) ||
		value.ExpiresAt.Before(value.CreatedAt.Add(time.Minute)) ||
		value.ExpiresAt.After(value.CreatedAt.Add(10*time.Minute)) {
		return platformOIDCDirectTOTPBeginWire{}, errFederatedAuthPersistence
	}
	return platformOIDCDirectTOTPBeginWire{
		ContinuationID: continuationID, ReceiptDigest: append([]byte(nil), value.ReceiptDigest[:]...),
		ExpectedVersion: value.ExpectedContinuationVersion,
		Challenge: platformOIDCDirectTOTPChallengeInputWire{
			ID:            append([]byte(nil), value.ChallengeID[:]...),
			BrowserDigest: append([]byte(nil), value.BrowserDigest[:]...),
			CreatedAt:     value.CreatedAt, ExpiresAt: value.ExpiresAt,
		},
		ObservedAt: value.CreatedAt, Audit: audit,
	}, nil
}

func platformOIDCDirectTOTPLookupToWire(
	value platformoidcauth.DirectTOTPLookup,
) (platformOIDCDirectTOTPLookupWire, error) {
	continuationID, idErr := requiredFederatedEntityIDWire(value.ContinuationID)
	if idErr != nil || value.Authority != federatedauth.ContinuationAuthorityDirectPlatformOIDC ||
		!validPlatformOIDCDigest(value.ChallengeID[:]) || !validPlatformOIDCDigest(value.BrowserDigest[:]) ||
		!validPlatformOIDCDigest(value.ReceiptDigest[:]) || !validFederatedDatabaseTime(value.ObservedAt) {
		return platformOIDCDirectTOTPLookupWire{}, errFederatedAuthPersistence
	}
	return platformOIDCDirectTOTPLookupWire{
		ChallengeID:    append([]byte(nil), value.ChallengeID[:]...),
		BrowserDigest:  append([]byte(nil), value.BrowserDigest[:]...),
		ContinuationID: continuationID, ReceiptDigest: append([]byte(nil), value.ReceiptDigest[:]...),
		ObservedAt: value.ObservedAt,
	}, nil
}

func platformOIDCDirectTOTPFailureToWire(
	value platformoidcauth.DirectTOTPFailureRequest,
	eventID uuid.UUID,
) (platformOIDCDirectTOTPFailureWire, error) {
	lookup, lookupErr := platformOIDCDirectTOTPLookupToWire(platformoidcauth.DirectTOTPLookup{
		ChallengeID: value.ChallengeID, ContinuationID: value.ContinuationID,
		Authority: value.Authority, ReceiptDigest: value.ReceiptDigest,
		BrowserDigest: value.BrowserDigest, ObservedAt: value.ObservedAt,
	})
	audit, auditErr := platformOIDCDirectAuditToWire(value.Audit, eventID)
	if lookupErr != nil || auditErr != nil || !validPlatformOIDCDirectRevision(value.ExpectedVersion) ||
		value.ExpectedVersion > uint64(maximumPlatformOIDCDirectTOTPFailures) {
		clearPlatformOIDCDirectTOTPLookupWire(&lookup)
		return platformOIDCDirectTOTPFailureWire{}, errFederatedAuthPersistence
	}
	return platformOIDCDirectTOTPFailureWire{
		ChallengeID: lookup.ChallengeID, BrowserDigest: lookup.BrowserDigest,
		ContinuationID: lookup.ContinuationID, ReceiptDigest: lookup.ReceiptDigest,
		ExpectedVersion: value.ExpectedVersion, ObservedAt: lookup.ObservedAt, Audit: audit,
	}, nil
}

func platformOIDCDirectTOTPApplyToWire(
	value platformoidcauth.DirectTOTPApplyRequest,
	eventID uuid.UUID,
) (platformOIDCDirectTOTPApplyWire, error) {
	lookup, lookupErr := platformOIDCDirectTOTPLookupToWire(platformoidcauth.DirectTOTPLookup{
		ChallengeID: value.ChallengeID, ContinuationID: value.ContinuationID,
		Authority: value.Authority, ReceiptDigest: value.ReceiptDigest,
		BrowserDigest: value.BrowserDigest, ObservedAt: value.ObservedAt,
	})
	audit, auditErr := platformOIDCDirectAuditToWire(value.Audit, eventID)
	session, sessionErr := platformOIDCDirectSessionToWire(value.Session, value.ObservedAt)
	if lookupErr != nil || auditErr != nil || sessionErr != nil ||
		!validPlatformOIDCDirectRevision(value.ExpectedVersion) ||
		value.ExpectedVersion > uint64(maximumPlatformOIDCDirectTOTPFailures) || value.AcceptedCounter < 0 ||
		!validPlatformOIDCDigest(value.CompletionRequestDigest[:]) {
		clearPlatformOIDCDirectTOTPLookupWire(&lookup)
		clearPlatformOIDCDirectSessionWire(&session)
		return platformOIDCDirectTOTPApplyWire{}, errFederatedAuthPersistence
	}
	return platformOIDCDirectTOTPApplyWire{
		ChallengeID: lookup.ChallengeID, BrowserDigest: lookup.BrowserDigest,
		ContinuationID: lookup.ContinuationID, ReceiptDigest: lookup.ReceiptDigest,
		ExpectedVersion: value.ExpectedVersion, AcceptedCounter: value.AcceptedCounter,
		CompletionRequestDigest: append([]byte(nil), value.CompletionRequestDigest[:]...),
		Session:                 session, ObservedAt: lookup.ObservedAt, Audit: audit,
	}, nil
}

func platformOIDCDirectTOTPAbandonToWire(
	value platformoidcauth.DirectTOTPAbandonRequest,
	eventID uuid.UUID,
) (platformOIDCDirectTOTPAbandonWire, error) {
	lookup, lookupErr := platformOIDCDirectTOTPLookupToWire(platformoidcauth.DirectTOTPLookup{
		ChallengeID: value.ChallengeID, ContinuationID: value.ContinuationID,
		Authority: value.Authority, ReceiptDigest: value.ReceiptDigest,
		BrowserDigest: value.BrowserDigest, ObservedAt: value.ObservedAt,
	})
	audit, auditErr := platformOIDCDirectAuditToWire(value.Audit, eventID)
	if lookupErr != nil || auditErr != nil || !validPlatformOIDCDirectRevision(value.ExpectedVersion) ||
		value.ExpectedVersion > uint64(maximumPlatformOIDCDirectTOTPFailures) ||
		!validPlatformOIDCDirectTOTPAbandonReason(value.Reason) {
		clearPlatformOIDCDirectTOTPLookupWire(&lookup)
		return platformOIDCDirectTOTPAbandonWire{}, errFederatedAuthPersistence
	}
	return platformOIDCDirectTOTPAbandonWire{
		ChallengeID: lookup.ChallengeID, BrowserDigest: lookup.BrowserDigest,
		ContinuationID: lookup.ContinuationID, ReceiptDigest: lookup.ReceiptDigest,
		ExpectedVersion: value.ExpectedVersion, ObservedAt: lookup.ObservedAt,
		Reason: string(value.Reason), Audit: audit,
	}, nil
}

func platformOIDCDirectSessionToWire(
	value mfa.SessionReservation,
	issuedAt time.Time,
) (platformOIDCDirectSessionWire, error) {
	sessionID, sessionErr := requiredFederatedEntityIDWire(value.SessionID())
	familyID, familyErr := requiredFederatedEntityIDWire(value.FamilyID())
	tokenDigest := value.TokenDigest()
	csrfDigest := value.CSRFDigest()
	if sessionErr != nil || familyErr != nil || sessionID == familyID ||
		value.AuthenticationMethod() != mfa.SessionAuthenticationOIDC || !value.ValidAt(issuedAt) ||
		!validPlatformOIDCDigest(tokenDigest[:]) || !validPlatformOIDCDigest(csrfDigest[:]) ||
		tokenDigest == csrfDigest || !value.AbsoluteExpiresAt().After(value.IdleExpiresAt()) ||
		value.AbsoluteExpiresAt().After(issuedAt.Add(maximumPlatformOIDCDirectSessionAge)) {
		return platformOIDCDirectSessionWire{}, errFederatedAuthPersistence
	}
	return platformOIDCDirectSessionWire{
		ID: sessionID, RotationFamilyID: familyID,
		TokenDigest:      append([]byte(nil), tokenDigest[:]...),
		CSRFSecretDigest: append([]byte(nil), csrfDigest[:]...),
		Audience:         "api", IdleExpiresAt: value.IdleExpiresAt(),
		AbsoluteExpiresAt: value.AbsoluteExpiresAt(), SessionVersion: 1,
	}, nil
}

func platformOIDCDirectTOTPChallengeFromWire(
	value platformOIDCDirectTOTPChallengeWire,
) (platformoidcauth.DirectTOTPChallenge, error) {
	challengeID, challengeErr := platformOIDCDirectChallengeIDFromWire(value.ChallengeID)
	continuationID, continuationErr := parseFederatedEntityIDWire(value.ContinuationID, false)
	userID, userErr := parseFederatedEntityIDWire(value.UserID, false)
	factorID, factorErr := parseFederatedEntityIDWire(value.TOTPCredentialID, false)
	expiresAt, validExpiresAt := canonicalFederatedDatabaseTimeFromWire(value.ExpiresAt)
	state := platformoidcauth.DirectTOTPChallengeState(value.State)
	if challengeErr != nil || continuationErr != nil || userErr != nil || factorErr != nil ||
		continuationID == userID || continuationID == factorID || userID == factorID ||
		!validPlatformOIDCDirectRevision(value.UserAuthenticationRevision) ||
		!validPlatformOIDCDirectRevision(value.TOTPSecurityRevision) || !validExpiresAt ||
		!validPlatformOIDCDirectTOTPChallengeState(state, value.FailureCount, value.Version) {
		return platformoidcauth.DirectTOTPChallenge{}, errFederatedAuthPersistence
	}
	return platformoidcauth.DirectTOTPChallenge{
		ChallengeID: challengeID, ContinuationID: continuationID, UserID: userID, FactorID: factorID,
		UserAuthenticationRevision: value.UserAuthenticationRevision,
		TOTPSecurityRevision:       value.TOTPSecurityRevision, FailureCount: value.FailureCount,
		State: state, Version: value.Version, ExpiresAt: expiresAt,
	}, nil
}

func platformOIDCDirectTOTPVerificationFromWire(
	value platformOIDCDirectTOTPVerificationWire,
) (platformoidcauth.DirectTOTPVerificationSnapshot, error) {
	challengeID, challengeErr := platformOIDCDirectChallengeIDFromWire(value.ChallengeID)
	continuationID, continuationErr := parseFederatedEntityIDWire(value.ContinuationID, false)
	userID, userErr := parseFederatedEntityIDWire(value.UserID, false)
	factorID, factorErr := parseFederatedEntityIDWire(value.TOTPCredentialID, false)
	expiresAt, validExpiresAt := canonicalFederatedDatabaseTimeFromWire(value.ExpiresAt)
	if challengeErr != nil || continuationErr != nil || userErr != nil || factorErr != nil ||
		continuationID == userID || continuationID == factorID || userID == factorID ||
		value.Authority != string(federatedauth.ContinuationAuthorityDirectPlatformOIDC) ||
		!validPlatformOIDCDigest(value.ReceiptDigest) ||
		!validPlatformOIDCDirectProtectedTOTPSecret(value) ||
		value.LastAcceptedCounter != nil && *value.LastAcceptedCounter < 0 ||
		!validPlatformOIDCDirectRevision(value.UserAuthenticationRevision) ||
		!validPlatformOIDCDirectRevision(value.TOTPSecurityRevision) || !validExpiresAt ||
		value.Version < 1 || value.Version > uint64(maximumPlatformOIDCDirectTOTPFailures) {
		return platformoidcauth.DirectTOTPVerificationSnapshot{}, errFederatedAuthPersistence
	}
	var receipt [sha256.Size]byte
	copy(receipt[:], value.ReceiptDigest)
	return platformoidcauth.DirectTOTPVerificationSnapshot{
		ChallengeID: challengeID, ContinuationID: continuationID,
		Authority: federatedauth.ContinuationAuthorityDirectPlatformOIDC, ReceiptDigest: receipt,
		UserID: userID, FactorID: factorID,
		Secret: platformoidcauth.DirectProtectedTOTPSecret{
			Ciphertext: append([]byte(nil), value.SecretCiphertext...),
			Nonce:      append([]byte(nil), value.SecretNonce...), AAD: append([]byte(nil), value.SecretAAD...),
			KeyVersion: value.KeyVersion, EncryptionAlgorithm: value.EncryptionAlgorithm,
			OTPAlgorithm: value.OTPAlgorithm, Digits: value.Digits, PeriodSeconds: value.PeriodSeconds,
		},
		LastAcceptedCounter:        clonePlatformOIDCDirectCounter(value.LastAcceptedCounter),
		UserAuthenticationRevision: value.UserAuthenticationRevision,
		TOTPSecurityRevision:       value.TOTPSecurityRevision,
		ExpiresAt:                  expiresAt, Version: value.Version,
	}, nil
}

func platformOIDCDirectTOTPApplyResultFromWire(
	value platformOIDCDirectTOTPApplyResultWire,
) (platformoidcauth.DirectTOTPApplyResult, error) {
	category := platformoidcauth.DirectTOTPApplyCategory(value.Category)
	if !value.Applied {
		if category != platformoidcauth.DirectTOTPApplyStale && category != platformoidcauth.DirectTOTPApplyReplay ||
			value.SessionID != nil || value.UserID != nil || value.ExternalIdentityID != nil ||
			value.AcceptedCounter != nil || value.TOTPCredentialID != nil || value.TOTPSecurityRevision != nil {
			return platformoidcauth.DirectTOTPApplyResult{}, errFederatedAuthPersistence
		}
		return platformoidcauth.DirectTOTPApplyResult{Category: category}, nil
	}
	if category != platformoidcauth.DirectTOTPApplySuccess || value.SessionID == nil || value.UserID == nil ||
		value.ExternalIdentityID == nil || value.AcceptedCounter == nil || value.TOTPCredentialID == nil ||
		value.TOTPSecurityRevision == nil || *value.AcceptedCounter < 0 ||
		!validPlatformOIDCDirectRevision(*value.TOTPSecurityRevision) {
		return platformoidcauth.DirectTOTPApplyResult{}, errFederatedAuthPersistence
	}
	sessionID, sessionErr := parseFederatedEntityIDWire(*value.SessionID, false)
	userID, userErr := parseFederatedEntityIDWire(*value.UserID, false)
	externalIdentityID, identityErr := parseFederatedEntityIDWire(*value.ExternalIdentityID, false)
	factorID, factorErr := parseFederatedEntityIDWire(*value.TOTPCredentialID, false)
	if sessionErr != nil || userErr != nil || identityErr != nil || factorErr != nil ||
		sessionID == userID || sessionID == externalIdentityID || sessionID == factorID ||
		userID == externalIdentityID || userID == factorID || externalIdentityID == factorID {
		return platformoidcauth.DirectTOTPApplyResult{}, errFederatedAuthPersistence
	}
	return platformoidcauth.DirectTOTPApplyResult{
		Category: category, SessionID: sessionID, UserID: userID, FactorID: factorID,
		TOTPSecurityRevision: *value.TOTPSecurityRevision, AcceptedCounter: *value.AcceptedCounter,
	}, nil
}

func platformOIDCDirectChallengeIDFromWire(
	value []byte,
) (platformoidcauth.DirectTOTPChallengeID, error) {
	if !validPlatformOIDCDigest(value) {
		return platformoidcauth.DirectTOTPChallengeID{}, errFederatedAuthPersistence
	}
	var result platformoidcauth.DirectTOTPChallengeID
	copy(result[:], value)
	return result, nil
}

func validPlatformOIDCDirectTOTPChallengeState(
	state platformoidcauth.DirectTOTPChallengeState,
	failureCount uint32,
	version uint64,
) bool {
	switch state {
	case platformoidcauth.DirectTOTPChallengePending:
		return failureCount < maximumPlatformOIDCDirectTOTPFailures && version == uint64(failureCount)+1
	case platformoidcauth.DirectTOTPChallengeFailed:
		return failureCount == maximumPlatformOIDCDirectTOTPFailures && version == uint64(failureCount)+1
	case platformoidcauth.DirectTOTPChallengeAbandoned, platformoidcauth.DirectTOTPChallengeExpired:
		return failureCount < maximumPlatformOIDCDirectTOTPFailures && version == uint64(failureCount)+2
	default:
		return false
	}
}

func validPlatformOIDCDirectProtectedTOTPSecret(value platformOIDCDirectTOTPVerificationWire) bool {
	return value.KeyVersion > 0 && len(value.SecretCiphertext) > 16 && len(value.SecretCiphertext) <= 8*1024 &&
		len(value.SecretNonce) >= 12 && len(value.SecretNonce) <= 24 &&
		len(value.SecretAAD) > 0 && len(value.SecretAAD) <= 1024 &&
		(value.EncryptionAlgorithm == "aes-256-gcm" || value.EncryptionAlgorithm == "xchacha20-poly1305") &&
		(value.OTPAlgorithm == "SHA1" || value.OTPAlgorithm == "SHA256" || value.OTPAlgorithm == "SHA512") &&
		(value.Digits == 6 || value.Digits == 8) && value.PeriodSeconds >= 15 && value.PeriodSeconds <= 120
}

func validPlatformOIDCDirectTOTPAbandonReason(value platformoidcauth.DirectTOTPAbandonReason) bool {
	return value == platformoidcauth.DirectTOTPAbandonCancelled ||
		value == platformoidcauth.DirectTOTPAbandonExpired ||
		value == platformoidcauth.DirectTOTPAbandonSuperseded
}

func validPlatformOIDCDirectRevision(value uint64) bool {
	return value > 0 && value <= maximumPlatformOIDCDirectRevision
}

func validPlatformOIDCDigest(value []byte) bool {
	return len(value) == sha256.Size && !allZeroFederatedBytes(value)
}

func validPlatformOIDCDirectAuditAddress(value netip.Addr) bool {
	return value.IsValid() && value.Zone() == "" && value == value.Unmap()
}

func platformOIDCDirectionalControl(character rune) bool {
	return character == '\u200e' || character == '\u200f' ||
		character >= '\u202a' && character <= '\u202e' ||
		character >= '\u2066' && character <= '\u2069'
}

func platformOIDCDirectUUIDv7(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func clonePlatformOIDCDirectCounter(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func clearPlatformOIDCDirectTOTPBeginWire(value *platformOIDCDirectTOTPBeginWire) {
	if value == nil {
		return
	}
	clear(value.ReceiptDigest)
	clear(value.Challenge.ID)
	clear(value.Challenge.BrowserDigest)
	*value = platformOIDCDirectTOTPBeginWire{}
}

func clearPlatformOIDCDirectTOTPLookupWire(value *platformOIDCDirectTOTPLookupWire) {
	if value == nil {
		return
	}
	clear(value.ChallengeID)
	clear(value.BrowserDigest)
	clear(value.ReceiptDigest)
	*value = platformOIDCDirectTOTPLookupWire{}
}

func clearPlatformOIDCDirectTOTPFailureWire(value *platformOIDCDirectTOTPFailureWire) {
	if value == nil {
		return
	}
	clear(value.ChallengeID)
	clear(value.BrowserDigest)
	clear(value.ReceiptDigest)
	*value = platformOIDCDirectTOTPFailureWire{}
}

func clearPlatformOIDCDirectSessionWire(value *platformOIDCDirectSessionWire) {
	if value == nil {
		return
	}
	clear(value.TokenDigest)
	clear(value.CSRFSecretDigest)
	*value = platformOIDCDirectSessionWire{}
}

func clearPlatformOIDCDirectTOTPApplyWire(value *platformOIDCDirectTOTPApplyWire) {
	if value == nil {
		return
	}
	clear(value.ChallengeID)
	clear(value.BrowserDigest)
	clear(value.ReceiptDigest)
	clear(value.CompletionRequestDigest)
	clearPlatformOIDCDirectSessionWire(&value.Session)
	*value = platformOIDCDirectTOTPApplyWire{}
}

func clearPlatformOIDCDirectTOTPAbandonWire(value *platformOIDCDirectTOTPAbandonWire) {
	if value == nil {
		return
	}
	clear(value.ChallengeID)
	clear(value.BrowserDigest)
	clear(value.ReceiptDigest)
	*value = platformOIDCDirectTOTPAbandonWire{}
}

func clearPlatformOIDCDirectTOTPVerificationWire(value *platformOIDCDirectTOTPVerificationWire) {
	if value == nil {
		return
	}
	clear(value.ChallengeID)
	clear(value.ReceiptDigest)
	clear(value.SecretCiphertext)
	clear(value.SecretNonce)
	clear(value.SecretAAD)
	if value.LastAcceptedCounter != nil {
		*value.LastAcceptedCounter = 0
	}
	*value = platformOIDCDirectTOTPVerificationWire{}
}
