package postgres

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

const currentSessionLogoutReason = "user_logout"

// AuthenticationRepository implements authentication's persistence boundary
// with the narrow SECURITY DEFINER functions exposed to the API runtime role.
type AuthenticationRepository struct {
	pool    *pgxpool.Pool
	queries *dbsql.Queries
	begin   transactionBeginner
	newID   func() (uuid.UUID, error)
}

func NewAuthenticationRepository(pool *pgxpool.Pool) *AuthenticationRepository {
	return &AuthenticationRepository{
		pool: pool, queries: dbsql.New(pool), begin: poolTransactionBeginner(pool), newID: uuid.NewV7,
	}
}

func (r *AuthenticationRepository) VerifyProtectedConfiguration(
	ctx context.Context,
	authorityDigest []byte,
	masterKeyVerifier []byte,
) (bool, error) {
	if len(authorityDigest) != sha256DigestBytes || len(masterKeyVerifier) != sha256DigestBytes {
		return false, authentication.ErrInvalidInput
	}
	available, err := r.queries.VerifyProtectedConfiguration(ctx, dbsql.VerifyProtectedConfigurationParams{
		AuthorityDigest: authorityDigest, MasterKeyVerifier: masterKeyVerifier,
	})
	if postgresCode(err) == "42501" {
		return false, authentication.ErrInvalidAuthentication
	}
	return available, mapCommonDatabaseError(err)
}

func (r *AuthenticationRepository) ReserveBootstrap(
	ctx context.Context,
	params authentication.ReserveBootstrapParams,
) error {
	event, err := eventArguments(params.Event)
	if err != nil || params.Enrollment.ID == uuid.Nil || params.CanonicalEmail == "" ||
		len(params.AuthorityDigest) != sha256DigestBytes ||
		len(params.EnrollmentDigest) != sha256DigestBytes ||
		len(params.EnrollmentRateKey) != sha256DigestBytes ||
		params.MaxAttempts < 1 || params.Enrollment.ExpiresAt.IsZero() {
		return authentication.ErrInvalidInput
	}
	secret := params.Enrollment.EncryptedTOTP
	if err := validateEncryptedSecret(secret); err != nil {
		return authentication.ErrInvalidInput
	}
	createdID, err := r.queries.ReserveBootstrap(ctx, dbsql.ReserveBootstrapParams{
		EnrollmentID:            toDatabaseUUID(params.Enrollment.ID),
		AuthorityDigest:         params.AuthorityDigest,
		EnrollmentDigest:        params.EnrollmentDigest,
		EnrollmentRateKeyDigest: params.EnrollmentRateKey,
		CanonicalEmail:          params.CanonicalEmail,
		TotpCiphertext:          secret.Ciphertext,
		TotpNonce:               secret.Nonce,
		TotpAad:                 secret.AAD,
		TotpKeyVersion:          int32(secret.KeyVersion),
		ExpiresAt:               databaseTime(params.Enrollment.ExpiresAt),
		MaxAttempts:             params.MaxAttempts,
		RequestID:               event.requestID,
		CorrelationID:           event.correlationID,
		IpAddress:               params.Event.RemoteAddress,
		UserAgent:               params.Event.UserAgent,
	})
	if err != nil {
		if postgresCode(err) == "42501" {
			return authentication.ErrInvalidAuthentication
		}
		return mapCommonDatabaseError(err)
	}
	identifier, err := domainUUID(createdID)
	if err != nil || identifier != params.Enrollment.ID {
		return errors.New("database returned an unexpected bootstrap enrollment")
	}
	return nil
}

func (r *AuthenticationRepository) GetBootstrapEnrollment(
	ctx context.Context,
	authorityDigest []byte,
	enrollmentDigest []byte,
	_ time.Time,
) (authentication.StoredBootstrapEnrollment, error) {
	if len(authorityDigest) != sha256DigestBytes || len(enrollmentDigest) != sha256DigestBytes {
		return authentication.StoredBootstrapEnrollment{}, authentication.ErrInvalidAuthentication
	}
	row, err := r.queries.GetBootstrapEnrollment(ctx, dbsql.GetBootstrapEnrollmentParams{
		AuthorityDigest: authorityDigest, EnrollmentDigest: enrollmentDigest,
	})
	if err != nil {
		switch postgresCode(err) {
		case "42501":
			return authentication.StoredBootstrapEnrollment{}, authentication.ErrInvalidAuthentication
		case "55000":
			return authentication.StoredBootstrapEnrollment{}, authentication.ErrConflict
		default:
			return authentication.StoredBootstrapEnrollment{}, mapCommonDatabaseError(err)
		}
	}
	identifier, err := domainUUID(row.EnrollmentID)
	if err != nil {
		return authentication.StoredBootstrapEnrollment{}, err
	}
	expiresAt, err := domainTime(row.ExpiresAt)
	if err != nil {
		return authentication.StoredBootstrapEnrollment{}, err
	}
	return authentication.StoredBootstrapEnrollment{
		ID: identifier, CanonicalEmail: row.CanonicalEmail,
		EncryptedTOTP: authentication.EncryptedSecret{
			Ciphertext: append([]byte(nil), row.TotpSecretCiphertext...),
			Nonce:      append([]byte(nil), row.TotpSecretNonce...),
			AAD:        append([]byte(nil), row.TotpSecretAad...),
			KeyVersion: int16(row.TotpKeyVersion),
		},
		ExpiresAt: expiresAt,
	}, nil
}

func (r *AuthenticationRepository) ConfirmBootstrap(
	ctx context.Context,
	params authentication.ConfirmBootstrapParams,
) (authentication.Session, error) {
	event, err := eventArguments(params.Event)
	if err != nil || params.EnrollmentID == uuid.Nil || params.UserID == uuid.Nil ||
		params.LocalCredentialID == uuid.Nil || params.TOTPCredentialID == uuid.Nil ||
		params.PlatformRoleGrantID == uuid.Nil || params.AuditID == uuid.Nil ||
		len(params.AuthorityDigest) != sha256DigestBytes ||
		len(params.EnrollmentDigest) != sha256DigestBytes ||
		len(params.RecoveryCodes) == 0 || params.AcceptedTOTPCounter < 0 {
		return authentication.Session{}, authentication.ErrInvalidInput
	}
	if err := validateSessionMaterial(params.Session); err != nil {
		return authentication.Session{}, authentication.ErrInvalidInput
	}
	if err := validateEncryptedSecret(params.TOTP); err != nil {
		return authentication.Session{}, authentication.ErrInvalidInput
	}
	recoveryIDs := make([]pgtype.UUID, len(params.RecoveryCodes))
	recoveryDigests := make([][]byte, len(params.RecoveryCodes))
	for index, recovery := range params.RecoveryCodes {
		if recovery.ID == uuid.Nil || len(recovery.Digest) != sha256DigestBytes {
			return authentication.Session{}, authentication.ErrInvalidInput
		}
		recoveryIDs[index] = toDatabaseUUID(recovery.ID)
		recoveryDigests[index] = append([]byte(nil), recovery.Digest...)
	}

	return withinTransaction(ctx, r.begin, func(tx databaseTransaction) (authentication.Session, error) {
		queries := dbsql.New(tx)
		sessionID, queryErr := queries.ConfirmBootstrap(ctx, dbsql.ConfirmBootstrapParams{
			AuthorityDigest:     params.AuthorityDigest,
			EnrollmentDigest:    params.EnrollmentDigest,
			UserID:              toDatabaseUUID(params.UserID),
			LocalCredentialID:   toDatabaseUUID(params.LocalCredentialID),
			TotpCredentialID:    toDatabaseUUID(params.TOTPCredentialID),
			TotpCiphertext:      params.TOTP.Ciphertext,
			TotpNonce:           params.TOTP.Nonce,
			TotpAad:             params.TOTP.AAD,
			TotpKeyVersion:      int32(params.TOTP.KeyVersion),
			PlatformRoleGrantID: toDatabaseUUID(params.PlatformRoleGrantID),
			CanonicalEmail:      params.CanonicalEmail,
			DisplayName:         params.DisplayName,
			PasswordPhc:         params.PasswordHash,
			InitialTotpCounter:  params.AcceptedTOTPCounter,
			RecoveryCodeIds:     recoveryIDs,
			RecoveryCodeDigests: recoveryDigests,
			SessionID:           toDatabaseUUID(params.Session.ID),
			RotationFamilyID:    toDatabaseUUID(params.Session.FamilyID),
			SessionTokenDigest:  params.Session.TokenDigest,
			CsrfDigest:          params.Session.CSRFDigest,
			IdleExpiresAt:       databaseTime(params.Session.IdleExpiresAt),
			AbsoluteExpiresAt:   databaseTime(params.Session.AbsoluteExpiresAt),
			AuditID:             toDatabaseUUID(params.AuditID),
			RequestID:           event.requestID,
			CorrelationID:       event.correlationID,
			IpAddress:           params.Event.RemoteAddress,
			UserAgent:           params.Event.UserAgent,
		})
		if queryErr != nil {
			switch postgresCode(queryErr) {
			case "42501", "23514":
				return authentication.Session{}, authentication.ErrInvalidAuthentication
			case "55000", "23505":
				return authentication.Session{}, authentication.ErrConflict
			default:
				return authentication.Session{}, mapCommonDatabaseError(queryErr)
			}
		}
		returnedID, queryErr := domainUUID(sessionID)
		if queryErr != nil || returnedID != params.Session.ID {
			return authentication.Session{}, errors.New("database returned an unexpected bootstrap session")
		}
		return resolveSession(ctx, queries, params.Session.TokenDigest)
	})
}

func (r *AuthenticationRepository) AdmitRateLimits(
	ctx context.Context,
	params authentication.AdmitRateLimitsParams,
) (time.Time, error) {
	rules, err := mapRateRules(params.Rules)
	if err != nil || params.OccurredAt.IsZero() {
		return time.Time{}, authentication.ErrInvalidInput
	}
	row, err := r.queries.AdmitAuthAttempts(ctx, dbsql.AdmitAuthAttemptsParams{
		Scopes: rules.scopes, KeyDigests: rules.keyDigests,
		WindowSeconds: rules.windowSeconds, MaxAttempts: rules.maxAttempts,
		BlockSeconds: rules.blockSeconds,
	})
	if err != nil {
		return time.Time{}, mapCommonDatabaseError(err)
	}
	if row.Admitted || !row.BlockedUntil.Valid {
		return time.Time{}, nil
	}
	return row.BlockedUntil.Time.UTC(), nil
}

func (r *AuthenticationRepository) CheckRateLimit(
	ctx context.Context,
	keys []authentication.RateLimitKey,
	_ time.Time,
) (time.Time, error) {
	if len(keys) == 0 || len(keys) > maximumRateRules {
		return time.Time{}, authentication.ErrInvalidInput
	}
	var blockedUntil time.Time
	for _, key := range keys {
		scope, err := databaseScope(key.Scope)
		if err != nil || len(key.Digest) != sha256DigestBytes {
			return time.Time{}, authentication.ErrInvalidInput
		}
		row, err := r.queries.GetAuthRateLimit(ctx, dbsql.GetAuthRateLimitParams{
			Scope: scope, KeyDigest: key.Digest,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return time.Time{}, mapCommonDatabaseError(err)
		}
		if row.BlockedUntil.Valid && row.BlockedUntil.Time.After(blockedUntil) {
			blockedUntil = row.BlockedUntil.Time.UTC()
		}
	}
	return blockedUntil, nil
}

func (r *AuthenticationRepository) RecordAuthFailure(
	ctx context.Context,
	params authentication.RecordAuthFailureParams,
) (time.Time, error) {
	event, err := eventArguments(params.Event)
	if err != nil || params.OccurredAt.IsZero() {
		return time.Time{}, authentication.ErrInvalidInput
	}
	rules, err := mapUniformRateRules(params.Keys, params.Policy)
	if err != nil {
		return time.Time{}, authentication.ErrInvalidInput
	}
	reason, method, err := failureAttribution(params.Action)
	if err != nil {
		return time.Time{}, authentication.ErrInvalidInput
	}
	auditID, err := r.newID()
	if err != nil {
		return time.Time{}, err
	}
	row, err := r.queries.RecordAuthRateLimitFailure(ctx, dbsql.RecordAuthRateLimitFailureParams{
		Scopes: rules.scopes, KeyDigests: rules.keyDigests,
		WindowSeconds: rules.windowSeconds, MaxAttempts: rules.maxAttempts,
		BlockSeconds: rules.blockSeconds, AuditID: toDatabaseUUID(auditID),
		Reason: reason, RequestID: event.requestID, CorrelationID: event.correlationID,
		IpAddress: params.Event.RemoteAddress, UserAgent: params.Event.UserAgent,
		AuthenticationMethod: method,
	})
	if err != nil {
		return time.Time{}, mapCommonDatabaseError(err)
	}
	if row.BlockedUntil.Valid {
		return row.BlockedUntil.Time.UTC(), nil
	}
	return time.Time{}, nil
}

func (r *AuthenticationRepository) RecordPasswordFailure(
	ctx context.Context,
	params authentication.RecordPasswordFailureParams,
) error {
	event, err := eventArguments(params.Event)
	if err != nil || params.OccurredAt.IsZero() ||
		params.MeteredAccountKey.Scope != string(dbsql.AuthRateLimitScopeLocalLogin) ||
		len(params.MeteredAccountKey.Digest) != sha256DigestBytes {
		return authentication.ErrInvalidInput
	}
	auditID, err := r.newID()
	if err != nil {
		return err
	}
	recorded, err := r.queries.RecordAuthenticationFailure(ctx, dbsql.RecordAuthenticationFailureParams{
		MeteredKeyDigest: params.MeteredAccountKey.Digest,
		UserID:           optionalDatabaseUUID(params.UserID),
		AuditID:          toDatabaseUUID(auditID),
		RequestID:        event.requestID,
		CorrelationID:    event.correlationID,
		IpAddress:        params.Event.RemoteAddress,
		UserAgent:        params.Event.UserAgent,
	})
	if err != nil {
		return mapCommonDatabaseError(err)
	}
	if !recorded {
		return errors.New("database did not record authentication failure")
	}
	return nil
}

func (r *AuthenticationRepository) RecordBootstrapFailure(
	ctx context.Context,
	params authentication.RecordBootstrapFailureParams,
) (time.Time, error) {
	event, err := eventArguments(params.Event)
	if err != nil || params.EnrollmentID == uuid.Nil || params.OccurredAt.IsZero() ||
		len(params.AuthorityDigest) != sha256DigestBytes ||
		len(params.EnrollmentDigest) != sha256DigestBytes {
		return time.Time{}, authentication.ErrInvalidInput
	}
	rules, err := mapUniformRateRules(params.Keys, params.Policy)
	if err != nil {
		return time.Time{}, authentication.ErrInvalidInput
	}
	auditID, err := r.newID()
	if err != nil {
		return time.Time{}, err
	}
	row, err := r.queries.RecordBootstrapFailure(ctx, dbsql.RecordBootstrapFailureParams{
		AuthorityDigest: params.AuthorityDigest, EnrollmentDigest: params.EnrollmentDigest,
		Scopes: rules.scopes, KeyDigests: rules.keyDigests,
		WindowSeconds: rules.windowSeconds, MaxAttempts: rules.maxAttempts,
		BlockSeconds: rules.blockSeconds, AuditID: toDatabaseUUID(auditID),
		RequestID: event.requestID, CorrelationID: event.correlationID,
		IpAddress: params.Event.RemoteAddress, UserAgent: params.Event.UserAgent,
	})
	if err != nil {
		if postgresCode(err) == "42501" {
			return time.Time{}, authentication.ErrInvalidAuthentication
		}
		return time.Time{}, mapCommonDatabaseError(err)
	}
	if row.BlockedUntil.Valid {
		return row.BlockedUntil.Time.UTC(), nil
	}
	return time.Time{}, nil
}

func (r *AuthenticationRepository) RecordMFAFailure(
	ctx context.Context,
	params authentication.RecordMFAFailureParams,
) (time.Time, error) {
	event, err := eventArguments(params.Event)
	if err != nil || params.ChallengeID == uuid.Nil || params.UserID == uuid.Nil ||
		params.OccurredAt.IsZero() || len(params.ChallengeDigest) != sha256DigestBytes {
		return time.Time{}, authentication.ErrInvalidInput
	}
	rules, err := mapUniformRateRules(params.Keys, params.Policy)
	if err != nil {
		return time.Time{}, authentication.ErrInvalidInput
	}
	auditID, err := r.newID()
	if err != nil {
		return time.Time{}, err
	}
	row, err := r.queries.RecordMFAFailure(ctx, dbsql.RecordMFAFailureParams{
		ChallengeDigest: params.ChallengeDigest,
		Scopes:          rules.scopes, KeyDigests: rules.keyDigests,
		WindowSeconds: rules.windowSeconds, MaxAttempts: rules.maxAttempts,
		BlockSeconds: rules.blockSeconds, AuditID: toDatabaseUUID(auditID),
		RequestID: event.requestID, CorrelationID: event.correlationID,
		IpAddress: params.Event.RemoteAddress, UserAgent: params.Event.UserAgent,
		AuthenticationMethod: "mfa",
	})
	if err != nil {
		return time.Time{}, mapCommonDatabaseError(err)
	}
	if row.BlockedUntil.Valid {
		return row.BlockedUntil.Time.UTC(), nil
	}
	return time.Time{}, nil
}

func (r *AuthenticationRepository) FindLocalCredential(
	ctx context.Context,
	canonicalEmail string,
) (authentication.LocalCredential, error) {
	if canonicalEmail == "" {
		return authentication.LocalCredential{}, authentication.ErrInvalidInput
	}
	row, err := r.queries.GetLocalCredential(ctx, dbsql.GetLocalCredentialParams{
		CanonicalEmail: canonicalEmail,
	})
	if err != nil {
		return authentication.LocalCredential{}, mapCommonDatabaseError(err)
	}
	userID, err := domainUUID(row.UserID)
	if err != nil {
		return authentication.LocalCredential{}, err
	}
	return authentication.LocalCredential{
		User:         authentication.User{ID: userID, Email: &canonicalEmail},
		PasswordHash: row.PasswordPhc,
		Enabled:      true,
	}, nil
}

func (r *AuthenticationRepository) CreateMFAChallenge(
	ctx context.Context,
	params authentication.CreateMFAChallengeParams,
) error {
	event, err := eventArguments(params.Event)
	if err != nil || params.ID == uuid.Nil || params.UserID == uuid.Nil ||
		len(params.TokenDigest) != sha256DigestBytes ||
		len(params.ChallengeRateKey) != sha256DigestBytes ||
		len(params.UserRateKey) != sha256DigestBytes ||
		len(params.LoginAccountRateKey) != sha256DigestBytes ||
		params.MaxAttempts < 1 || params.ExpiresAt.IsZero() {
		return authentication.ErrInvalidInput
	}
	auditID, err := r.newID()
	if err != nil {
		return err
	}
	createdID, err := r.queries.CreateMFAChallenge(ctx, dbsql.CreateMFAChallengeParams{
		ChallengeID: toDatabaseUUID(params.ID), UserID: toDatabaseUUID(params.UserID),
		ChallengeRateKeyDigest:    params.ChallengeRateKey,
		MfaRateKeyDigest:          params.UserRateKey,
		LoginAccountRateKeyDigest: params.LoginAccountRateKey,
		TokenDigest:               params.TokenDigest, ExpiresAt: databaseTime(params.ExpiresAt),
		MaxAttempts: params.MaxAttempts, AuditID: toDatabaseUUID(auditID),
		RequestID: event.requestID, CorrelationID: event.correlationID,
		IpAddress: params.Event.RemoteAddress, UserAgent: params.Event.UserAgent,
	})
	if err != nil {
		if postgresCode(err) == "53300" {
			return r.mfaChallengeRateLimit(ctx, params.UserRateKey, params.OccurredAt)
		}
		if postgresCode(err) == "42501" {
			return authentication.ErrInvalidAuthentication
		}
		return mapCommonDatabaseError(err)
	}
	identifier, err := domainUUID(createdID)
	if err != nil || identifier != params.ID {
		return errors.New("database returned an unexpected MFA challenge")
	}
	return nil
}

func (r *AuthenticationRepository) mfaChallengeRateLimit(
	ctx context.Context,
	userRateKey []byte,
	now time.Time,
) error {
	row, err := r.queries.GetAuthRateLimit(ctx, dbsql.GetAuthRateLimitParams{
		Scope: dbsql.AuthRateLimitScopeMfaChallenge, KeyDigest: userRateKey,
	})
	if err != nil {
		return mapCommonDatabaseError(err)
	}
	if rateLimit := retryAfter(row.BlockedUntil, now); rateLimit != nil {
		return rateLimit
	}
	return errors.New("database reported an MFA challenge rate limit without blocking state")
}

func (r *AuthenticationRepository) GetMFAChallenge(
	ctx context.Context,
	challengeDigest []byte,
	_ time.Time,
) (authentication.StoredMFAChallenge, error) {
	if len(challengeDigest) != sha256DigestBytes {
		return authentication.StoredMFAChallenge{}, authentication.ErrNotFound
	}
	row, err := r.queries.GetMFAChallenge(ctx, dbsql.GetMFAChallengeParams{
		ChallengeDigest: challengeDigest,
	})
	if err != nil {
		return authentication.StoredMFAChallenge{}, mapCommonDatabaseError(err)
	}
	challengeID, err := domainUUID(row.ChallengeID)
	if err != nil {
		return authentication.StoredMFAChallenge{}, err
	}
	userID, err := domainUUID(row.UserID)
	if err != nil {
		return authentication.StoredMFAChallenge{}, err
	}
	credentialID, err := domainUUID(row.CredentialID)
	if err != nil {
		return authentication.StoredMFAChallenge{}, err
	}
	expiresAt, err := domainTime(row.ExpiresAt)
	if err != nil {
		return authentication.StoredMFAChallenge{}, err
	}
	return authentication.StoredMFAChallenge{
		ID: challengeID, User: authentication.User{ID: userID},
		EncryptedTOTP: authentication.EncryptedSecret{
			Ciphertext: append([]byte(nil), row.SecretCiphertext...),
			Nonce:      append([]byte(nil), row.SecretNonce...), AAD: append([]byte(nil), row.SecretAad...),
			KeyVersion: int16(row.KeyVersion),
		},
		TOTPContextID: credentialID, LastAcceptedCounter: row.LastAcceptedCounter,
		ExpiresAt: expiresAt, Attempts: row.Attempts, MaxAttempts: row.MaxAttempts,
	}, nil
}

func (r *AuthenticationRepository) CompleteTOTPChallenge(
	ctx context.Context,
	params authentication.CompleteTOTPParams,
) (authentication.Session, error) {
	counter := params.AcceptedCounter
	return r.completeMFA(ctx, completeMFAParams{
		challengeDigest: params.ChallengeDigest, challengeID: params.ChallengeID,
		userID: params.UserID, method: "totp", counter: &counter,
		auditID: params.AuditID, session: params.Session, clearKeys: params.ClearKeys,
		failureKeys: params.FailureKeys, failurePolicy: params.FailurePolicy, event: params.Event,
	})
}

func (r *AuthenticationRepository) CompleteRecoveryChallenge(
	ctx context.Context,
	params authentication.CompleteRecoveryParams,
) (authentication.Session, error) {
	return r.completeMFA(ctx, completeMFAParams{
		challengeDigest: params.ChallengeDigest, challengeID: params.ChallengeID,
		userID: params.UserID, method: "recovery_code", recoveryDigest: params.RecoveryDigest,
		auditID: params.AuditID, session: params.Session, clearKeys: params.ClearKeys,
		failureKeys: params.FailureKeys, failurePolicy: params.FailurePolicy, event: params.Event,
	})
}

type completeMFAParams struct {
	challengeDigest []byte
	challengeID     uuid.UUID
	userID          uuid.UUID
	method          string
	counter         *int64
	recoveryDigest  []byte
	auditID         uuid.UUID
	session         authentication.SessionMaterial
	clearKeys       []authentication.RateLimitKey
	failureKeys     []authentication.RateLimitKey
	failurePolicy   authentication.RateLimitPolicy
	event           authentication.EventContext
}

type completeMFAOutcome struct {
	session   authentication.Session
	publicErr error
}

func (r *AuthenticationRepository) completeMFA(
	ctx context.Context,
	params completeMFAParams,
) (authentication.Session, error) {
	event, err := eventArguments(params.event)
	if err != nil || params.challengeID == uuid.Nil || params.userID == uuid.Nil ||
		params.auditID == uuid.Nil || len(params.challengeDigest) != sha256DigestBytes {
		return authentication.Session{}, authentication.ErrInvalidInput
	}
	if params.method == "totp" {
		if params.counter == nil || *params.counter < 0 || len(params.recoveryDigest) != 0 {
			return authentication.Session{}, authentication.ErrInvalidInput
		}
	} else if params.method == "recovery_code" {
		if params.counter != nil || len(params.recoveryDigest) != sha256DigestBytes {
			return authentication.Session{}, authentication.ErrInvalidInput
		}
	} else {
		return authentication.Session{}, authentication.ErrInvalidInput
	}
	if err := validateSessionMaterial(params.session); err != nil {
		return authentication.Session{}, authentication.ErrInvalidInput
	}
	failureRules, err := mapUniformRateRules(params.failureKeys, params.failurePolicy)
	if err != nil {
		return authentication.Session{}, authentication.ErrInvalidInput
	}
	clearScopes, clearDigests, err := mapRateKeys(params.clearKeys)
	if err != nil {
		return authentication.Session{}, authentication.ErrInvalidInput
	}
	outcome, err := withinTransaction(ctx, r.begin, func(tx databaseTransaction) (completeMFAOutcome, error) {
		queries := dbsql.New(tx)
		row, queryErr := queries.CompleteMFALogin(ctx, dbsql.CompleteMFALoginParams{
			ChallengeDigest: params.challengeDigest, AuthenticationMethod: params.method,
			TotpCounter: params.counter, RecoveryCodeDigest: params.recoveryDigest,
			SessionID:          toDatabaseUUID(params.session.ID),
			RotationFamilyID:   toDatabaseUUID(params.session.FamilyID),
			SessionTokenDigest: params.session.TokenDigest, CsrfDigest: params.session.CSRFDigest,
			IdleExpiresAt:     databaseTime(params.session.IdleExpiresAt),
			AbsoluteExpiresAt: databaseTime(params.session.AbsoluteExpiresAt),
			FailureScopes:     failureRules.scopes, FailureKeyDigests: failureRules.keyDigests,
			FailureWindowSeconds: failureRules.windowSeconds,
			FailureMaxAttempts:   failureRules.maxAttempts,
			FailureBlockSeconds:  failureRules.blockSeconds,
			ClearScopes:          clearScopes, ClearKeyDigests: clearDigests,
			AuditID: toDatabaseUUID(params.auditID), RequestID: event.requestID,
			CorrelationID: event.correlationID, IpAddress: params.event.RemoteAddress,
			UserAgent: params.event.UserAgent,
		})
		if queryErr != nil {
			if postgresCode(queryErr) == "42501" {
				return completeMFAOutcome{}, authentication.ErrInvalidAuthentication
			}
			return completeMFAOutcome{}, mapCommonDatabaseError(queryErr)
		}
		if row.FailureRecorded {
			if rateLimit := retryAfter(row.BlockedUntil, params.session.CreatedAt); rateLimit != nil {
				return completeMFAOutcome{publicErr: rateLimit}, nil
			}
			return completeMFAOutcome{publicErr: authentication.ErrInvalidAuthentication}, nil
		}
		if !row.SessionID.Valid {
			return completeMFAOutcome{}, authentication.ErrInvalidAuthentication
		}
		returnedID, queryErr := domainUUID(row.SessionID)
		if queryErr != nil || returnedID != params.session.ID {
			return completeMFAOutcome{}, errors.New("database returned an unexpected MFA session")
		}
		session, queryErr := resolveSession(ctx, queries, params.session.TokenDigest)
		if queryErr != nil {
			return completeMFAOutcome{}, queryErr
		}
		return completeMFAOutcome{session: session}, nil
	})
	if err != nil {
		return authentication.Session{}, err
	}
	if outcome.publicErr != nil {
		return authentication.Session{}, outcome.publicErr
	}
	return outcome.session, nil
}

func (r *AuthenticationRepository) ResolveSession(
	ctx context.Context,
	tokenDigest []byte,
	_ time.Time,
) (authentication.Session, error) {
	if len(tokenDigest) != sha256DigestBytes {
		return authentication.Session{}, authentication.ErrNotFound
	}
	return resolveSession(ctx, r.queries, tokenDigest)
}

func resolveSession(
	ctx context.Context,
	queries *dbsql.Queries,
	tokenDigest []byte,
) (authentication.Session, error) {
	row, err := queries.ResolveSession(ctx, dbsql.ResolveSessionParams{TokenDigest: tokenDigest})
	if err != nil {
		return authentication.Session{}, mapCommonDatabaseError(err)
	}
	sessionID, err := domainUUID(row.SessionID)
	if err != nil {
		return authentication.Session{}, err
	}
	userID, err := domainUUID(row.UserID)
	if err != nil {
		return authentication.Session{}, err
	}
	familyID, err := domainUUID(row.RotationFamilyID)
	if err != nil {
		return authentication.Session{}, err
	}
	permissions, err := mapPermissions(row.PlatformPermissions)
	if err != nil {
		return authentication.Session{}, err
	}
	createdAt, err := domainTime(row.CreatedAt)
	if err != nil {
		return authentication.Session{}, err
	}
	lastSeenAt, err := domainTime(row.LastSeenAt)
	if err != nil {
		return authentication.Session{}, err
	}
	idleExpiresAt, err := domainTime(row.IdleExpiresAt)
	if err != nil {
		return authentication.Session{}, err
	}
	absoluteExpiresAt, err := domainTime(row.AbsoluteExpiresAt)
	if err != nil {
		return authentication.Session{}, err
	}
	var activeTenantID *uuid.UUID
	if row.ActiveTenantID.Valid {
		identifier, identifierErr := domainUUID(row.ActiveTenantID)
		if identifierErr != nil {
			return authentication.Session{}, identifierErr
		}
		activeTenantID = &identifier
	}
	if len(row.CsrfSecretDigest) != sha256DigestBytes || row.AuthenticationMethod == "" {
		return authentication.Session{}, errors.New("database returned invalid session security material")
	}
	var email *string
	if row.Email != "" {
		value := row.Email
		email = &value
	}
	return authentication.Session{
		ID: sessionID, RotationFamilyID: familyID,
		User:       authentication.User{ID: userID, Email: email, DisplayName: row.DisplayName},
		CSRFDigest: append([]byte(nil), row.CsrfSecretDigest...), Permissions: permissions,
		ActiveTenantID: activeTenantID, CreatedAt: createdAt, LastSeenAt: lastSeenAt,
		IdleExpiresAt: idleExpiresAt, AbsoluteExpiresAt: absoluteExpiresAt,
		AuthenticationMethod: row.AuthenticationMethod,
	}, nil
}

func (r *AuthenticationRepository) RotateSession(
	ctx context.Context,
	params authentication.RotateSessionParams,
) (authentication.Session, error) {
	event, err := eventArguments(params.Event)
	if err != nil || params.NewSessionID == uuid.Nil ||
		len(params.CurrentTokenDigest) != sha256DigestBytes ||
		len(params.NewTokenDigest) != sha256DigestBytes || len(params.NewCSRFDigest) != sha256DigestBytes {
		return authentication.Session{}, authentication.ErrInvalidInput
	}
	auditID, err := r.newID()
	if err != nil {
		return authentication.Session{}, err
	}
	return withinTransaction(ctx, r.begin, func(tx databaseTransaction) (authentication.Session, error) {
		queries := dbsql.New(tx)
		identifier, queryErr := queries.RotateSession(ctx, dbsql.RotateSessionParams{
			CurrentTokenDigest: params.CurrentTokenDigest,
			NewSessionID:       toDatabaseUUID(params.NewSessionID), NewTokenDigest: params.NewTokenDigest,
			NewCsrfDigest: params.NewCSRFDigest, IdleExpiresAt: databaseTime(params.IdleExpiresAt),
			AbsoluteExpiresAt: databaseTime(params.AbsoluteExpiresAt), AuditID: toDatabaseUUID(auditID),
			RequestID: event.requestID, CorrelationID: event.correlationID,
			IpAddress: params.Event.RemoteAddress, UserAgent: params.Event.UserAgent,
		})
		if queryErr != nil {
			if postgresCode(queryErr) == "42501" {
				return authentication.Session{}, authentication.ErrForbidden
			}
			return authentication.Session{}, mapCommonDatabaseError(queryErr)
		}
		returnedID, queryErr := domainUUID(identifier)
		if queryErr != nil || returnedID != params.NewSessionID {
			return authentication.Session{}, authentication.ErrNotFound
		}
		return resolveSession(ctx, queries, params.NewTokenDigest)
	})
}

func (r *AuthenticationRepository) TouchSession(
	ctx context.Context,
	tokenDigest []byte,
	_ time.Time,
	idleExpiresAt time.Time,
) error {
	if len(tokenDigest) != sha256DigestBytes || idleExpiresAt.IsZero() {
		return authentication.ErrInvalidInput
	}
	touched, err := r.queries.TouchSession(ctx, dbsql.TouchSessionParams{
		TokenDigest: tokenDigest, IdleExpiresAt: databaseTime(idleExpiresAt),
	})
	if err != nil {
		return mapCommonDatabaseError(err)
	}
	if !touched {
		return authentication.ErrNotFound
	}
	return nil
}

func (r *AuthenticationRepository) RevokeCurrentSession(
	ctx context.Context,
	actorID uuid.UUID,
	sessionID uuid.UUID,
	event authentication.EventContext,
) error {
	return r.revokeSession(ctx, actorID, sessionID, currentSessionLogoutReason, event)
}

func (r *AuthenticationRepository) RevokeSession(
	ctx context.Context,
	actorID uuid.UUID,
	sessionID uuid.UUID,
	event authentication.EventContext,
) error {
	return r.revokeSession(ctx, actorID, sessionID, "user_revoked", event)
}

func (r *AuthenticationRepository) revokeSession(
	ctx context.Context,
	actorID uuid.UUID,
	sessionID uuid.UUID,
	reason string,
	eventContext authentication.EventContext,
) error {
	event, err := eventArguments(eventContext)
	if err != nil || actorID == uuid.Nil || sessionID == uuid.Nil {
		return authentication.ErrInvalidInput
	}
	auditID, err := r.newID()
	if err != nil {
		return err
	}
	_, err = withinTransaction(ctx, r.begin, func(tx databaseTransaction) (struct{}, error) {
		queries := dbsql.New(tx)
		if setErr := setUserContext(ctx, queries, actorID); setErr != nil {
			return struct{}{}, setErr
		}
		revoked, queryErr := queries.RevokeUserSession(ctx, dbsql.RevokeUserSessionParams{
			SessionID: toDatabaseUUID(sessionID), Reason: reason, AuditID: toDatabaseUUID(auditID),
			RequestID: event.requestID, CorrelationID: event.correlationID,
			IpAddress: eventContext.RemoteAddress, UserAgent: eventContext.UserAgent,
		})
		if queryErr != nil {
			if postgresCode(queryErr) == "42501" {
				return struct{}{}, authentication.ErrForbidden
			}
			return struct{}{}, mapCommonDatabaseError(queryErr)
		}
		if !revoked {
			return struct{}{}, authentication.ErrNotFound
		}
		return struct{}{}, nil
	})
	return err
}

func (r *AuthenticationRepository) ListSessions(
	ctx context.Context,
	params authentication.ListSessionsParams,
) ([]authentication.SessionSummary, error) {
	if params.ActorID == uuid.Nil || params.CurrentSessionID == uuid.Nil ||
		params.Limit < 1 || params.Limit > 101 || params.After != nil && *params.After == uuid.Nil {
		return nil, authentication.ErrInvalidInput
	}
	return withinTransaction(ctx, r.begin, func(tx databaseTransaction) ([]authentication.SessionSummary, error) {
		queries := dbsql.New(tx)
		if err := setUserContext(ctx, queries, params.ActorID); err != nil {
			return nil, err
		}
		rows, err := queries.ListUserSessions(ctx, dbsql.ListUserSessionsParams{
			CurrentSessionID: toDatabaseUUID(params.CurrentSessionID),
			AfterSessionID:   optionalDatabaseUUID(params.After),
			PageSize:         params.Limit,
		})
		if err != nil {
			if postgresCode(err) == "42501" {
				return nil, authentication.ErrInvalidAuthentication
			}
			return nil, mapCommonDatabaseError(err)
		}
		items := make([]authentication.SessionSummary, 0, len(rows))
		for _, row := range rows {
			item, mapErr := mapSessionSummary(row)
			if mapErr != nil {
				return nil, mapErr
			}
			items = append(items, item)
		}
		return items, nil
	})
}

func (r *AuthenticationRepository) ListTenantMemberships(
	ctx context.Context,
	params authentication.ListTenantMembershipsParams,
) ([]authentication.TenantMembership, error) {
	if params.ActorID == uuid.Nil || params.Limit < 1 || params.Limit > 101 ||
		params.After != nil && *params.After == uuid.Nil {
		return nil, authentication.ErrInvalidInput
	}
	return withinTransaction(ctx, r.begin, func(tx databaseTransaction) ([]authentication.TenantMembership, error) {
		queries := dbsql.New(tx)
		if err := setUserContext(ctx, queries, params.ActorID); err != nil {
			return nil, err
		}
		rows, err := queries.ListUserTenantMemberships(ctx, dbsql.ListUserTenantMembershipsParams{
			AfterMembershipID: optionalDatabaseUUID(params.After), PageSize: params.Limit,
		})
		if err != nil {
			if postgresCode(err) == "42501" {
				return nil, authentication.ErrInvalidAuthentication
			}
			return nil, mapCommonDatabaseError(err)
		}
		items := make([]authentication.TenantMembership, 0, len(rows))
		for _, row := range rows {
			item, mapErr := mapTenantMembership(row)
			if mapErr != nil {
				return nil, mapErr
			}
			items = append(items, item)
		}
		return items, nil
	})
}

type switchTenantOutcome struct {
	session   authentication.Session
	publicErr error
}

func (r *AuthenticationRepository) SwitchActiveTenant(
	ctx context.Context,
	params authentication.SwitchTenantParams,
) (authentication.Session, error) {
	event, err := eventArguments(params.Event)
	if err != nil || params.UserID == uuid.Nil || params.TenantID == uuid.Nil ||
		params.NewSessionID == uuid.Nil || len(params.CurrentTokenDigest) != sha256DigestBytes ||
		len(params.NewTokenDigest) != sha256DigestBytes || len(params.NewCSRFDigest) != sha256DigestBytes {
		return authentication.Session{}, authentication.ErrInvalidInput
	}
	rules, err := mapRateRules(params.AdmissionRules)
	if err != nil {
		return authentication.Session{}, authentication.ErrInvalidInput
	}
	auditID, err := r.newID()
	if err != nil {
		return authentication.Session{}, err
	}
	outcome, err := withinTransaction(ctx, r.begin, func(tx databaseTransaction) (switchTenantOutcome, error) {
		queries := dbsql.New(tx)
		if setErr := setUserContext(ctx, queries, params.UserID); setErr != nil {
			return switchTenantOutcome{}, setErr
		}
		admission, queryErr := queries.AdmitAuthAttempts(ctx, dbsql.AdmitAuthAttemptsParams{
			Scopes: rules.scopes, KeyDigests: rules.keyDigests,
			WindowSeconds: rules.windowSeconds, MaxAttempts: rules.maxAttempts,
			BlockSeconds: rules.blockSeconds,
		})
		if queryErr != nil {
			return switchTenantOutcome{}, mapCommonDatabaseError(queryErr)
		}
		if !admission.Admitted {
			if rateLimit := retryAfter(admission.BlockedUntil, params.Now); rateLimit != nil {
				return switchTenantOutcome{publicErr: rateLimit}, nil
			}
			return switchTenantOutcome{}, errors.New("tenant switch admission denied without blocking state")
		}
		identifier, queryErr := queries.RotateSessionTenant(ctx, dbsql.RotateSessionTenantParams{
			CurrentTokenDigest: params.CurrentTokenDigest,
			NewSessionID:       toDatabaseUUID(params.NewSessionID), NewTokenDigest: params.NewTokenDigest,
			NewCsrfDigest: params.NewCSRFDigest, TenantID: toDatabaseUUID(params.TenantID),
			IdleExpiresAt:     databaseTime(params.IdleExpiresAt),
			AbsoluteExpiresAt: databaseTime(params.AbsoluteExpiresAt),
			AuditID:           toDatabaseUUID(auditID), RequestID: event.requestID,
			CorrelationID: event.correlationID, IpAddress: params.Event.RemoteAddress,
			UserAgent: params.Event.UserAgent,
		})
		if queryErr != nil {
			if postgresCode(queryErr) == "42501" {
				return switchTenantOutcome{}, authentication.ErrForbidden
			}
			return switchTenantOutcome{}, mapCommonDatabaseError(queryErr)
		}
		returnedID, queryErr := domainUUID(identifier)
		if queryErr != nil || returnedID != params.NewSessionID {
			return switchTenantOutcome{}, authentication.ErrNotFound
		}
		session, queryErr := resolveSession(ctx, queries, params.NewTokenDigest)
		if queryErr != nil {
			return switchTenantOutcome{}, queryErr
		}
		return switchTenantOutcome{session: session}, nil
	})
	if err != nil {
		return authentication.Session{}, err
	}
	if outcome.publicErr != nil {
		return authentication.Session{}, outcome.publicErr
	}
	return outcome.session, nil
}

func setUserContext(ctx context.Context, queries *dbsql.Queries, actorID uuid.UUID) error {
	value, err := queries.SetUserContext(ctx, dbsql.SetUserContextParams{UserID: toDatabaseUUID(actorID)})
	if err != nil {
		return mapCommonDatabaseError(err)
	}
	if value != actorID.String() {
		return errors.New("database did not install the requested user context")
	}
	return nil
}

func mapSessionSummary(row *dbsql.ListUserSessionsRow) (authentication.SessionSummary, error) {
	identifier, err := domainUUID(row.SessionID)
	if err != nil {
		return authentication.SessionSummary{}, err
	}
	createdAt, err := domainTime(row.CreatedAt)
	if err != nil {
		return authentication.SessionSummary{}, err
	}
	lastSeenAt, err := domainTime(row.LastSeenAt)
	if err != nil {
		return authentication.SessionSummary{}, err
	}
	idleExpiresAt, err := domainTime(row.IdleExpiresAt)
	if err != nil {
		return authentication.SessionSummary{}, err
	}
	absoluteExpiresAt, err := domainTime(row.AbsoluteExpiresAt)
	if err != nil {
		return authentication.SessionSummary{}, err
	}
	return authentication.SessionSummary{
		ID: identifier, Current: row.Current, CreatedAt: createdAt, LastSeenAt: lastSeenAt,
		IdleExpiresAt: idleExpiresAt, AbsoluteExpiresAt: absoluteExpiresAt,
		RevokedAt: optionalDomainTime(row.RevokedAt), AuthenticationMethod: row.AuthenticationMethod,
	}, nil
}

func mapTenantMembership(row *dbsql.ListUserTenantMembershipsRow) (authentication.TenantMembership, error) {
	membershipID, err := domainUUID(row.MembershipID)
	if err != nil {
		return authentication.TenantMembership{}, err
	}
	tenantID, err := domainUUID(row.TenantID)
	if err != nil {
		return authentication.TenantMembership{}, err
	}
	createdAt, err := domainTime(row.CreatedAt)
	if err != nil {
		return authentication.TenantMembership{}, err
	}
	updatedAt, err := domainTime(row.UpdatedAt)
	if err != nil {
		return authentication.TenantMembership{}, err
	}
	return authentication.TenantMembership{
		ID: membershipID,
		Tenant: authentication.Tenant{
			ID: tenantID, Slug: row.TenantSlug, Name: row.TenantName,
			Status: row.TenantStatus, Timezone: row.Timezone, Locale: row.Locale,
			CreatedAt: createdAt, UpdatedAt: updatedAt,
		},
		Role: row.MembershipRole,
	}, nil
}

func validateEncryptedSecret(secret authentication.EncryptedSecret) error {
	if len(secret.Ciphertext) == 0 || len(secret.Nonce) == 0 || len(secret.AAD) == 0 || secret.KeyVersion != 1 {
		return errors.New("encrypted secret material is invalid")
	}
	return nil
}

func validateSessionMaterial(session authentication.SessionMaterial) error {
	if session.ID == uuid.Nil || session.FamilyID == uuid.Nil ||
		len(session.TokenDigest) != sha256DigestBytes || len(session.CSRFDigest) != sha256DigestBytes ||
		session.CreatedAt.IsZero() || session.IdleExpiresAt.IsZero() ||
		session.AbsoluteExpiresAt.IsZero() || !session.CreatedAt.Before(session.IdleExpiresAt) ||
		!session.IdleExpiresAt.After(session.CreatedAt) ||
		!session.AbsoluteExpiresAt.After(session.CreatedAt) || session.AuthenticationMethod == "" ||
		bytes.Equal(session.TokenDigest, session.CSRFDigest) {
		return errors.New("session material is invalid")
	}
	return nil
}

func failureAttribution(action string) (reason string, method string, err error) {
	switch action {
	case "authentication.bootstrap_authority_failed":
		return "bootstrap_authority_failed", "bootstrap_token", nil
	case "authentication.bootstrap_proof_failed":
		return "bootstrap_proof_failed", "bootstrap_token", nil
	case "authentication.mfa_failed":
		return "mfa_failed", "mfa", nil
	default:
		return "", "", fmt.Errorf("unsupported authentication failure action %q", action)
	}
}
