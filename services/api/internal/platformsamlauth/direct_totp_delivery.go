package platformsamlauth

import (
	"context"
	"sync"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

type directSAMLTOTPDeliveryState uint8

const (
	directSAMLTOTPDeliveryPending directSAMLTOTPDeliveryState = iota + 1
	directSAMLTOTPDeliveryCompensating
	directSAMLTOTPDeliveryConfirmed
	directSAMLTOTPDeliveryCompensated
)

// DirectSAMLTOTPDeliveryFinalizer is an unforgeable, copy-safe post-commit
// capability. Copies share one authority cell, so confirmation and
// compensation are mutually exclusive across all wrappers.
type DirectSAMLTOTPDeliveryFinalizer struct {
	authority *directSAMLTOTPDeliveryAuthority
}

type directSAMLTOTPDeliveryAuthority struct {
	guard sync.Mutex
	state directSAMLTOTPDeliveryState

	store           DirectSAMLTOTPStore
	now             func() time.Time
	recoveryTimeout time.Duration
	request         DirectSAMLTOTPCleanupRequest
}

func newDirectSAMLTOTPDeliveryFinalizer(
	store DirectSAMLTOTPStore,
	now func() time.Time,
	recoveryTimeout time.Duration,
	apply DirectSAMLTOTPApplyRequest,
	result DirectSAMLTOTPApplyResult,
	audit AuditContext,
) *DirectSAMLTOTPDeliveryFinalizer {
	cleanup := DirectSAMLTOTPCleanupRequest{
		Request: apply, Result: result, Reason: CleanupDeliveryFailed,
		CleanedUpAt: result.CompletedAt, Audit: audit,
	}
	if store == nil || now == nil || recoveryTimeout < minimumRecoveryTimeout ||
		recoveryTimeout > maximumRecoveryTimeout || recoveryTimeout%time.Microsecond != 0 ||
		!validDirectSAMLTOTPCleanupRequest(cleanup) {
		return nil
	}
	return &DirectSAMLTOTPDeliveryFinalizer{authority: &directSAMLTOTPDeliveryAuthority{
		state: directSAMLTOTPDeliveryPending, store: store, now: now,
		recoveryTimeout: recoveryTimeout, request: cleanup,
	}}
}

func (finalizer *DirectSAMLTOTPDeliveryFinalizer) String() string {
	return "platformsamlauth.DirectSAMLTOTPDeliveryFinalizer{authority:direct_platform_saml,material:[REDACTED]}"
}

func (finalizer *DirectSAMLTOTPDeliveryFinalizer) GoString() string { return finalizer.String() }

func (finalizer *DirectSAMLTOTPDeliveryFinalizer) ConfirmBrowserDelivery() error {
	if finalizer == nil || finalizer.authority == nil {
		return ErrBrowserDeliveryRejected
	}
	authority := finalizer.authority
	authority.guard.Lock()
	defer authority.guard.Unlock()
	if authority.state != directSAMLTOTPDeliveryPending || !validDirectSAMLTOTPCleanupRequest(authority.request) {
		return ErrBrowserDeliveryRejected
	}
	authority.state = directSAMLTOTPDeliveryConfirmed
	authority.clearProofLocked()
	return nil
}

func (finalizer *DirectSAMLTOTPDeliveryFinalizer) CompensateBrowserDelivery(ctx context.Context) error {
	if finalizer == nil || finalizer.authority == nil {
		return ErrBrowserDeliveryRejected
	}
	authority := finalizer.authority
	authority.guard.Lock()
	defer authority.guard.Unlock()
	switch authority.state {
	case directSAMLTOTPDeliveryConfirmed:
		return ErrBrowserDeliveryRejected
	case directSAMLTOTPDeliveryCompensated:
		return nil
	case directSAMLTOTPDeliveryPending:
		authority.state = directSAMLTOTPDeliveryCompensating
		cleanedUpAt := authority.now().UTC().Truncate(time.Microsecond)
		if !validInstant(cleanedUpAt) || cleanedUpAt.Before(authority.request.Result.CompletedAt) {
			cleanedUpAt = authority.request.Result.CompletedAt
		}
		authority.request.CleanedUpAt = cleanedUpAt
	case directSAMLTOTPDeliveryCompensating:
	default:
		return ErrBrowserDeliveryRejected
	}
	request := authority.request
	if !validDirectSAMLTOTPCleanupRequest(request) {
		return ErrBrowserDeliveryRejected
	}
	for range 2 {
		bounded, cancel := context.WithTimeout(detachedContext(ctx), authority.recoveryTimeout)
		err := authority.store.CleanupDirectSAMLTOTPApply(bounded, request)
		cancel()
		if err == nil {
			authority.state = directSAMLTOTPDeliveryCompensated
			authority.clearProofLocked()
			return nil
		}
	}
	return ErrBrowserDeliveryUnavailable
}

func (authority *directSAMLTOTPDeliveryAuthority) clearProofLocked() {
	authority.store = nil
	authority.now = nil
	authority.recoveryTimeout = 0
	authority.request = DirectSAMLTOTPCleanupRequest{}
}

func validDirectSAMLTOTPCleanupRequest(request DirectSAMLTOTPCleanupRequest) bool {
	apply := request.Request
	result := request.Result
	return validDirectSAMLTOTPApplyProof(apply) &&
		(result.Category == DirectSAMLTOTPApplySuccess || result.Category == DirectSAMLTOTPApplyAlreadyApplied) &&
		result.SessionID == apply.Session.SessionID() && validUUIDv7(result.SessionID) &&
		validUUIDv7(result.UserID) && validUUIDv7(result.FactorID) &&
		result.SessionID != result.UserID && result.SessionID != result.FactorID && result.UserID != result.FactorID &&
		result.FactorRevision == apply.ExpectedFactorRevision &&
		result.UserAuthenticationRevision == apply.ExpectedUserAuthenticationRevision &&
		result.AcceptedCounter == apply.AcceptedCounter && result.CompletedAt.Equal(apply.ObservedAt) &&
		request.Reason == CleanupDeliveryFailed && validInstant(request.CleanedUpAt) &&
		!request.CleanedUpAt.Before(result.CompletedAt) && request.Audit == apply.Audit &&
		validAuditContext(request.Audit)
}

func validDirectSAMLTOTPApplyProof(request DirectSAMLTOTPApplyRequest) bool {
	return request.ChallengeID != (mfa.ChallengeID{}) &&
		validDirectSAMLTOTPContinuation(request.ContinuationID, request.ReceiptDigest) &&
		request.BrowserDigest != (DirectSAMLTOTPBrowserDigest{}) &&
		validRevision(request.ExpectedContinuationVersion) &&
		validRevision(request.ExpectedFactorRevision) &&
		validRevision(request.ExpectedUserAuthenticationRevision) &&
		validRevision(request.ExpectedChallengeVersion) && request.AcceptedCounter >= 0 &&
		request.CompletionRequestDigest != (DirectSAMLTOTPCompletionDigest{}) &&
		validDirectSAMLTOTPSession(request.Session, request.ObservedAt) && validAuditContext(request.Audit)
}

func validDirectSAMLTOTPSession(session mfa.SessionReservation, issuedAt time.Time) bool {
	if session.IsZero() || session.AuthenticationMethod() != mfa.SessionAuthenticationSAML ||
		!session.ValidAt(issuedAt.Truncate(time.Millisecond)) ||
		session.SessionID() == session.FamilyID() || !validUUIDv7(session.SessionID()) ||
		!validUUIDv7(session.FamilyID()) {
		return false
	}
	tokenDigest, csrfDigest := session.TokenDigest(), session.CSRFDigest()
	return tokenDigest != ([32]byte{}) && csrfDigest != ([32]byte{}) && tokenDigest != csrfDigest &&
		session.IdleExpiresAt().After(issuedAt) && session.AbsoluteExpiresAt().After(session.IdleExpiresAt())
}

var _ interface {
	ConfirmBrowserDelivery() error
	CompensateBrowserDelivery(context.Context) error
} = (*DirectSAMLTOTPDeliveryFinalizer)(nil)
