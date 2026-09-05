package authentication

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Repository is the transactional persistence boundary for authentication use cases.
type Repository interface {
	VerifyProtectedConfiguration(context.Context, []byte, []byte) (bool, error)
	ReserveBootstrap(context.Context, ReserveBootstrapParams) error
	GetBootstrapEnrollment(context.Context, []byte, []byte, time.Time) (StoredBootstrapEnrollment, error)
	ConfirmBootstrap(context.Context, ConfirmBootstrapParams) (Session, error)

	AdmitRateLimits(context.Context, AdmitRateLimitsParams) (time.Time, error)
	CheckRateLimit(context.Context, []RateLimitKey, time.Time) (time.Time, error)
	RecordAuthFailure(context.Context, RecordAuthFailureParams) (time.Time, error)
	RecordPasswordFailure(context.Context, RecordPasswordFailureParams) error
	RecordBootstrapFailure(context.Context, RecordBootstrapFailureParams) (time.Time, error)
	RecordMFAFailure(context.Context, RecordMFAFailureParams) (time.Time, error)
	FindLocalCredential(context.Context, string) (LocalCredential, error)
	CreateMFAChallenge(context.Context, CreateMFAChallengeParams) error
	GetMFAChallenge(context.Context, []byte, time.Time) (StoredMFAChallenge, error)
	CompleteTOTPChallenge(context.Context, CompleteTOTPParams) (Session, error)
	CompleteRecoveryChallenge(context.Context, CompleteRecoveryParams) (Session, error)

	ResolveSession(context.Context, []byte, time.Time) (Session, error)
	RotateSession(context.Context, RotateSessionParams) (Session, error)
	TouchSession(context.Context, []byte, time.Time, time.Time) error
	RevokeCurrentSession(context.Context, uuid.UUID, uuid.UUID, EventContext) error
	ListSessions(context.Context, ListSessionsParams) ([]SessionSummary, error)
	RevokeSession(context.Context, uuid.UUID, uuid.UUID, EventContext) error
	ListTenantMemberships(context.Context, ListTenantMembershipsParams) ([]TenantMembership, error)
	SwitchActiveTenant(context.Context, SwitchTenantParams) (Session, error)
}

type ReserveBootstrapParams struct {
	AuthorityDigest   []byte
	EnrollmentDigest  []byte
	EnrollmentRateKey []byte
	CanonicalEmail    string
	Enrollment        StoredBootstrapEnrollment
	MaxAttempts       int32
	Event             EventContext
}

type ConfirmBootstrapParams struct {
	AuthorityDigest     []byte
	EnrollmentDigest    []byte
	EnrollmentID        uuid.UUID
	CanonicalEmail      string
	DisplayName         string
	PasswordHash        string
	TOTP                EncryptedSecret
	AcceptedTOTPCounter int64
	UserID              uuid.UUID
	LocalCredentialID   uuid.UUID
	TOTPCredentialID    uuid.UUID
	PlatformRoleGrantID uuid.UUID
	AuditID             uuid.UUID
	RecoveryCodes       []RecoveryCodeMaterial
	Session             SessionMaterial
	Event               EventContext
}

type RecordAuthFailureParams struct {
	Keys       []RateLimitKey
	Policy     RateLimitPolicy
	OccurredAt time.Time
	Action     string
	UserID     *uuid.UUID
	Event      EventContext
}

type RateLimitRule struct {
	Key    RateLimitKey
	Policy RateLimitPolicy
}

type AdmitRateLimitsParams struct {
	Rules      []RateLimitRule
	OccurredAt time.Time
}

type RecordPasswordFailureParams struct {
	OccurredAt        time.Time
	UserID            *uuid.UUID
	MeteredAccountKey RateLimitKey
	Event             EventContext
}

// RecordMFAFailure atomically advances the challenge attempt counter and shared
// rate-limit rows. Implementations must make an exhausted challenge unusable in
// the same transaction that returns the updated blocking state.
type RecordMFAFailureParams struct {
	ChallengeDigest []byte
	ChallengeID     uuid.UUID
	UserID          uuid.UUID
	Keys            []RateLimitKey
	Policy          RateLimitPolicy
	OccurredAt      time.Time
	Event           EventContext
}

// RecordBootstrapFailure atomically advances the reserved enrollment attempt
// counter and shared rate-limit rows, exhausting the enrollment at the limit.
type RecordBootstrapFailureParams struct {
	AuthorityDigest  []byte
	EnrollmentDigest []byte
	EnrollmentID     uuid.UUID
	Keys             []RateLimitKey
	Policy           RateLimitPolicy
	OccurredAt       time.Time
	Event            EventContext
}

type CreateMFAChallengeParams struct {
	ID                  uuid.UUID
	TokenDigest         []byte
	UserID              uuid.UUID
	ChallengeRateKey    []byte
	UserRateKey         []byte
	LoginAccountRateKey []byte
	ExpiresAt           time.Time
	MaxAttempts         int32
	OccurredAt          time.Time
	ClearKeys           []RateLimitKey
	Event               EventContext
}

type CompleteTOTPParams struct {
	ChallengeDigest []byte
	ChallengeID     uuid.UUID
	UserID          uuid.UUID
	AcceptedCounter int64
	AuditID         uuid.UUID
	Session         SessionMaterial
	ClearKeys       []RateLimitKey
	FailureKeys     []RateLimitKey
	FailurePolicy   RateLimitPolicy
	Event           EventContext
}

type CompleteRecoveryParams struct {
	ChallengeDigest []byte
	ChallengeID     uuid.UUID
	UserID          uuid.UUID
	RecoveryDigest  []byte
	AuditID         uuid.UUID
	Session         SessionMaterial
	ClearKeys       []RateLimitKey
	FailureKeys     []RateLimitKey
	FailurePolicy   RateLimitPolicy
	Event           EventContext
}

type RotateSessionParams struct {
	CurrentTokenDigest []byte
	NewSessionID       uuid.UUID
	NewTokenDigest     []byte
	NewCSRFDigest      []byte
	Now                time.Time
	IdleExpiresAt      time.Time
	AbsoluteExpiresAt  time.Time
	Event              EventContext
}

type SwitchTenantParams struct {
	CurrentTokenDigest []byte
	NewSessionID       uuid.UUID
	NewTokenDigest     []byte
	NewCSRFDigest      []byte
	UserID             uuid.UUID
	TenantID           uuid.UUID
	Now                time.Time
	IdleExpiresAt      time.Time
	AbsoluteExpiresAt  time.Time
	Event              EventContext
	AdmissionRules     []RateLimitRule
}

type ListSessionsParams struct {
	ActorID          uuid.UUID
	CurrentSessionID uuid.UUID
	After            *uuid.UUID
	Limit            int32
	Now              time.Time
}

type ListTenantMembershipsParams struct {
	ActorID uuid.UUID
	After   *uuid.UUID
	Limit   int32
}
