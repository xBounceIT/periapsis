// Package oidcmaintenance runs bounded access-expiry and retention phases,
// then executes already-claimed OIDC refresh, logout retry, and secret-scrub
// work through the worker-only PostgreSQL ABI.
package oidcmaintenance

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
)

const (
	MaximumBatchSize       = 90
	MinimumOperation       = 100 * time.Millisecond
	MaximumOperation       = 2 * time.Minute
	MinimumDatabaseTimeout = time.Second
	MaximumDatabaseTimeout = 25 * time.Second
	MinimumLeaseSafety     = time.Second
	MaximumLeaseSafety     = time.Minute
	NominalLeaseDuration   = 2 * time.Minute
	// MinimumLeaseSchedulingMargin remains available after a successful,
	// bounded claim read, the complete upstream operation, and lease safety.
	MinimumLeaseSchedulingMargin = time.Second
	MaximumPersistentCount       = uint64(9_000_000_000_000_000)
)

var (
	ErrInvalidConfiguration = errors.New("invalid OIDC maintenance configuration")
	ErrInvalidInput         = errors.New("invalid OIDC maintenance input")
	ErrInvalidProjection    = errors.New("invalid OIDC maintenance projection")
	ErrUnavailable          = errors.New("OIDC maintenance dependency unavailable")
	ErrInterrupted          = errors.New("OIDC maintenance interrupted")
	ErrOutcomeUnknown       = errors.New("OIDC maintenance transition outcome unknown")
	errTraceRetryScheduled  = errors.New("OIDC maintenance operation scheduled for retry")
	errTraceRejected        = errors.New("OIDC maintenance operation rejected")
)

// Kind is both the dispatcher selector and returned work discriminator. The
// worker rotates this closed set so continuously busy classes cannot starve.
type Kind string

const (
	KindLogoutRetry Kind = "logout_retry"
	KindRefresh     Kind = "refresh"
	KindScrub       Kind = "scrub"
)

var orderedKinds = [...]Kind{KindLogoutRetry, KindRefresh, KindScrub}

type ProtectedToken struct {
	KeyVersion uint32
	Ciphertext []byte
}

func (value ProtectedToken) String() string {
	return fmt.Sprintf("oidcmaintenance.ProtectedToken{keyVersion:%d,material:[REDACTED]}", value.KeyVersion)
}
func (value ProtectedToken) GoString() string { return value.String() }

type RefreshClaim struct {
	TenantID              identity.EntityID
	EffectiveTenantID     identity.EntityID
	MaterialID            identity.EntityID
	SessionFamilyID       identity.EntityID
	Generation            uint64
	Version               uint64
	LeaseExpiresAt        time.Time
	Provider              identity.ProviderContext
	Admission             identity.TenantAdmissionContext
	BindingID             identity.EntityID
	ClientSecretRevision  uint64
	Endpoint              string
	ClientAuthentication  federatedoidc.ClientAuthenticationMode
	ClientID              string
	Token                 ProtectedToken
	TokenDigest           [sha256.Size]byte
	MaterialExpiresAt     time.Time
	AbsoluteSessionExpiry time.Time
}

func (value RefreshClaim) String() string {
	return fmt.Sprintf("oidcmaintenance.RefreshClaim{generation:%d,material:[REDACTED]}", value.Generation)
}
func (value RefreshClaim) GoString() string { return value.String() }

type LogoutRetryClaim struct {
	JobID                identity.EntityID
	TenantID             identity.EntityID
	MaterialID           identity.EntityID
	SessionFamilyID      identity.EntityID
	Attempt              int
	MaximumAttempts      int
	ClaimVersion         uint64
	LeaseExpiresAt       time.Time
	NotBefore            time.Time
	Provider             identity.ProviderContext
	Admission            identity.TenantAdmissionContext
	BindingID            identity.EntityID
	ClientSecretRevision uint64
	ClientAuthentication federatedoidc.ClientAuthenticationMode
	ClientID             string
	Endpoint             string
	RefreshGeneration    uint64
	TokenDigest          [sha256.Size]byte
	MaterialExpiresAt    time.Time
	OpaqueReference      ProtectedToken
}

func (value LogoutRetryClaim) String() string {
	return fmt.Sprintf("oidcmaintenance.LogoutRetryClaim{attempt:%d,material:[REDACTED]}", value.Attempt)
}
func (value LogoutRetryClaim) GoString() string { return value.String() }

type ScrubReceipt struct {
	MaterialID     identity.EntityID
	OperationRunID identity.EntityID
	CompletedAt    time.Time
}

type QueueCategorySnapshot struct {
	DueCount         uint64
	ReclaimableCount uint64
	DeadLetterCount  uint64
	OldestDueAt      time.Time
}

type QueueSnapshot struct {
	ObservedAt  time.Time
	LogoutRetry QueueCategorySnapshot
	Refresh     QueueCategorySnapshot
	Scrub       QueueCategorySnapshot
}

// Work contains exactly one category-specific payload.
type Work struct {
	ObservedAt  time.Time
	Kind        Kind
	Refresh     *RefreshClaim
	LogoutRetry *LogoutRetryClaim
	Scrub       *ScrubReceipt
}

func (value Work) String() string {
	return fmt.Sprintf("oidcmaintenance.Work{kind:%s,material:[REDACTED]}", value.Kind)
}
func (value Work) GoString() string { return value.String() }

type ClientSecretLookup struct {
	Provider          identity.ProviderContext
	Admission         identity.TenantAdmissionContext
	BindingID         identity.EntityID
	Revision          uint64
	Kind              Kind
	MaterialID        identity.EntityID
	SessionFamilyID   identity.EntityID
	ClaimVersion      uint64
	RefreshGeneration uint64
	JobID             identity.EntityID
	Attempt           int
}

type ClientSecretSnapshot struct {
	Lookup   ClientSecretLookup
	SecretID identity.EntityID
	Envelope identity.OIDCClientSecretEnvelope
}

func (value ClientSecretSnapshot) String() string {
	return fmt.Sprintf(
		"oidcmaintenance.ClientSecretSnapshot{revision:%t,secret:%t,envelope:%q,material:[REDACTED]}",
		value.Lookup.Revision != 0, value.SecretID != (identity.EntityID{}), value.Envelope.String(),
	)
}
func (value ClientSecretSnapshot) GoString() string { return value.String() }

type RefreshOutcome string

const (
	RefreshRotated          RefreshOutcome = "rotated"
	RefreshSafeToRetry      RefreshOutcome = "safe_to_retry"
	RefreshLocalUnavailable RefreshOutcome = "local_dependency_unavailable"
	RefreshAmbiguous        RefreshOutcome = "ambiguous"
	RefreshRejected         RefreshOutcome = "rejected"
)

type RefreshCompletion struct {
	TenantID            identity.EntityID
	EffectiveTenantID   identity.EntityID
	MaterialID          identity.EntityID
	SessionFamilyID     identity.EntityID
	ExpectedVersion     uint64
	ExpectedGeneration  uint64
	Outcome             RefreshOutcome
	SuccessorGeneration uint64
	SuccessorDigest     [sha256.Size]byte
	SuccessorToken      ProtectedToken
	AccessExpiresAt     time.Time
	CompletedAt         time.Time
}

func (value RefreshCompletion) String() string {
	return "oidcmaintenance.RefreshCompletion{material:[REDACTED]}"
}
func (value RefreshCompletion) GoString() string { return value.String() }

type LogoutOutcome string

const (
	LogoutSucceeded        LogoutOutcome = "succeeded"
	LogoutSafeToRetry      LogoutOutcome = "safe_to_retry"
	LogoutLocalUnavailable LogoutOutcome = "local_dependency_unavailable"
	LogoutAmbiguous        LogoutOutcome = "ambiguous"
	LogoutRejected         LogoutOutcome = "rejected"
)

type LogoutCompletion struct {
	JobID           identity.EntityID
	Attempt         int
	ExpectedVersion uint64
	Outcome         LogoutOutcome
	CompletedAt     time.Time
	NextTryAt       time.Time
}

// Repository exposes only the worker role's purpose-bound functions. A false
// completion means its version fence was lost and is a benign stale result.
type Repository interface {
	Ready(context.Context) error
	QueueSnapshot(context.Context) (QueueSnapshot, error)
	ExpireAccessLease(context.Context, time.Time) error
	CleanupFederatedRetention(context.Context, time.Time) error
	ClaimDue(context.Context, Kind, time.Time) (*Work, error)
	LoadClientSecret(context.Context, ClientSecretLookup) (ClientSecretSnapshot, error)
	CompleteRefresh(context.Context, RefreshCompletion) (bool, error)
	CompleteLogout(context.Context, LogoutCompletion) (bool, error)
}

// RefreshResult is the deliberately narrow value returned by the worker's
// pinned upstream adapter. Access and ID tokens never cross this boundary.
type RefreshResult struct {
	RefreshToken    []byte
	AccessExpiresAt time.Time
}

func (value RefreshResult) String() string {
	return "oidcmaintenance.RefreshResult{material:[REDACTED]}"
}
func (value RefreshResult) GoString() string { return value.String() }

func (value *RefreshResult) Destroy() {
	if value == nil {
		return
	}
	clear(value.RefreshToken)
	*value = RefreshResult{}
}

type Upstream interface {
	Refresh(context.Context, federatedoidc.StoredRefreshExchangeRequest, time.Time) (RefreshResult, error)
	Revoke(context.Context, federatedoidc.StoredRevocationMaterial) error
}

type Observer interface {
	SetOIDCMaintenanceReady(bool)
	SetOIDCMaintenanceQueueObservation(QueueSnapshot) bool
	ClearOIDCMaintenanceQueueObservation()
	ObserveOIDCMaintenanceRun(Summary, error) bool
}

type OperationTracer interface {
	StartOperation(context.Context, string) (context.Context, func(error))
}

type Options struct {
	Repository       Repository
	Keyring          identity.Keyring
	Upstream         Upstream
	BatchSize        int
	DatabaseTimeout  time.Duration
	OperationTimeout time.Duration
	LeaseSafety      time.Duration
	PollInterval     time.Duration
	Clock            func() time.Time
	Logger           *slog.Logger
	Observer         Observer
	Tracer           OperationTracer
}

type Summary struct {
	Dispatches     int
	Claimed        int
	RefreshRotated int
	LogoutComplete int
	RetryScheduled int
	LocalDeferred  int
	DeadLettered   int
	Scrubbed       int
	FenceLost      int
}

func (summary Summary) DidWork() bool { return summary.Claimed != 0 }
