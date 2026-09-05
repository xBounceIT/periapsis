// Package mfaauth coordinates local assurance ceremonies without owning HTTP
// parsing, cryptographic verification, or persistence adapters.
package mfaauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

const (
	minimumOperationTimeout = 100 * time.Millisecond
	maximumOperationTimeout = time.Minute
	maximumAdmissionRetry   = 24 * time.Hour
)

var (
	ErrInvalidInput   = errors.New("invalid MFA authentication input")
	ErrDenied         = errors.New("MFA authentication denied")
	ErrAuthentication = errors.New("MFA authentication rejected")
	ErrNotFound       = errors.New("MFA resource not found")
	ErrConflict       = errors.New("MFA resource conflict")
	ErrPrecondition   = errors.New("MFA resource precondition failed")
	ErrUnavailable    = errors.New("MFA authentication unavailable")
)

type AdmissionDigest [32]byte

// AdmissionContext contains only purpose-separated keyed digests. The HTTP
// adapter derives them; raw addresses, account identifiers, and proofs never
// enter this package or its formatting.
type AdmissionContext struct {
	OperationID     identity.EntityID
	NetworkDigest   AdmissionDigest
	PrincipalDigest AdmissionDigest
	ResourceDigest  AdmissionDigest
}

func (value AdmissionContext) String() string {
	return "mfaauth.AdmissionContext{digests:[REDACTED]}"
}
func (value AdmissionContext) GoString() string { return value.String() }

type AdmissionOutcome uint8

const (
	AdmissionAllowed AdmissionOutcome = iota + 1
	AdmissionRateLimited
	AdmissionLocked
)

type AdmissionDecision struct {
	Outcome AdmissionOutcome
	RetryAt time.Time
}

// AdmissionGate must atomically meter the supplied purpose-separated keys in
// shared storage. A locked/rate-limited decision is authoritative across API
// replicas and is checked before any identity or factor lookup.
type AdmissionGate interface {
	Admit(context.Context, AdmissionContext, time.Time) (AdmissionDecision, error)
}

type RateLimitError struct {
	retryAfter time.Duration
	locked     bool
}

func (err *RateLimitError) Error() string { return "MFA authentication temporarily unavailable" }
func (err *RateLimitError) RetryAfter() time.Duration {
	if err == nil {
		return 0
	}
	return err.retryAfter
}
func (err *RateLimitError) Locked() bool { return err != nil && err.locked }
func (err *RateLimitError) String() string {
	return fmt.Sprintf("mfaauth.RateLimitError{locked:%t,retry_after:%s}", err.Locked(), err.RetryAfter())
}
func (err *RateLimitError) GoString() string { return err.String() }

func admit(ctx context.Context, gate AdmissionGate, value AdmissionContext, now time.Time) error {
	if gate == nil || !validAdmission(value) || !validInstant(now) {
		return ErrInvalidInput
	}
	decision, err := gate.Admit(ctx, value, now)
	if err != nil {
		return ErrUnavailable
	}
	switch decision.Outcome {
	case AdmissionAllowed:
		if !decision.RetryAt.IsZero() {
			return ErrUnavailable
		}
		return nil
	case AdmissionRateLimited, AdmissionLocked:
		if !validDeadline(decision.RetryAt) || !decision.RetryAt.After(now) ||
			decision.RetryAt.Sub(now) > maximumAdmissionRetry {
			return ErrUnavailable
		}
		return &RateLimitError{
			retryAfter: decision.RetryAt.Sub(now), locked: decision.Outcome == AdmissionLocked,
		}
	default:
		return ErrUnavailable
	}
}

func validAdmission(value AdmissionContext) bool {
	zero := AdmissionDigest{}
	return value.OperationID != (identity.EntityID{}) && value.NetworkDigest != zero &&
		value.PrincipalDigest != zero && value.ResourceDigest != zero &&
		value.NetworkDigest != value.PrincipalDigest && value.NetworkDigest != value.ResourceDigest &&
		value.PrincipalDigest != value.ResourceDigest
}

func operation(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc, error) {
	if ctx == nil || ctx.Err() != nil || timeout < minimumOperationTimeout || timeout > maximumOperationTimeout ||
		timeout%time.Microsecond != 0 {
		return nil, nil, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	return bounded, cancel, nil
}

func validInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%int(time.Microsecond) == 0
}

func validDeadline(value time.Time) bool {
	return validInstant(value) && value.Nanosecond()%int(time.Millisecond) == 0
}
