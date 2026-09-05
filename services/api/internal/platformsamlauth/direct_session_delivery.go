package platformsamlauth

import (
	"context"
	"sync"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

type directSAMLSessionDeliveryState uint8

const (
	directSAMLSessionDeliveryPending directSAMLSessionDeliveryState = iota + 1
	directSAMLSessionDeliveryCompensating
	directSAMLSessionDeliveryConfirmed
	directSAMLSessionDeliveryCompensated
)

// DirectSAMLSessionDeliveryFinalizer is an unforgeable, copy-safe post-commit
// capability. Its private authority cell owns the exact command/result proof
// until browser delivery is confirmed or the successor is compensated.
type DirectSAMLSessionDeliveryFinalizer struct {
	authority *directSAMLSessionDeliveryAuthority
}

type directSAMLSessionDeliveryAuthority struct {
	guard           sync.Mutex
	state           directSAMLSessionDeliveryState
	store           DirectSAMLSessionRevalidationStore
	now             func() time.Time
	recoveryTimeout time.Duration
	cleanup         DirectSAMLSessionRevalidationCleanup
}

func newDirectSAMLSessionDeliveryFinalizer(
	store DirectSAMLSessionRevalidationStore,
	now func() time.Time,
	recoveryTimeout time.Duration,
	command DirectSAMLSessionRevalidationCommand,
	result DirectSAMLSessionRevalidationResult,
) *DirectSAMLSessionDeliveryFinalizer {
	cleanup := DirectSAMLSessionRevalidationCleanup{
		Command: command, Result: result, Reason: CleanupDeliveryFailed,
		CleanedUpAt: result.AppliedAt, Audit: command.Audit,
	}
	return &DirectSAMLSessionDeliveryFinalizer{authority: &directSAMLSessionDeliveryAuthority{
		state: directSAMLSessionDeliveryPending, store: store, now: now,
		recoveryTimeout: recoveryTimeout, cleanup: cleanup,
	}}
}

func (finalizer *DirectSAMLSessionDeliveryFinalizer) String() string {
	return "platformsamlauth.DirectSAMLSessionDeliveryFinalizer{authority:direct_platform_saml,material:[REDACTED]}"
}

func (finalizer *DirectSAMLSessionDeliveryFinalizer) GoString() string { return finalizer.String() }

func (finalizer *DirectSAMLSessionDeliveryFinalizer) ConfirmBrowserDelivery() error {
	if finalizer == nil || finalizer.authority == nil {
		return ErrBrowserDeliveryRejected
	}
	authority := finalizer.authority
	authority.guard.Lock()
	defer authority.guard.Unlock()
	if authority.state != directSAMLSessionDeliveryPending ||
		!authority.validProofLocked() {
		return ErrBrowserDeliveryRejected
	}
	authority.state = directSAMLSessionDeliveryConfirmed
	authority.clearProofLocked()
	return nil
}

func (finalizer *DirectSAMLSessionDeliveryFinalizer) CompensateBrowserDelivery(ctx context.Context) error {
	if finalizer == nil || finalizer.authority == nil {
		return ErrBrowserDeliveryRejected
	}
	authority := finalizer.authority
	authority.guard.Lock()
	defer authority.guard.Unlock()
	switch authority.state {
	case directSAMLSessionDeliveryConfirmed:
		return ErrBrowserDeliveryRejected
	case directSAMLSessionDeliveryCompensated:
		return nil
	case directSAMLSessionDeliveryPending:
		if !authority.validProofLocked() {
			return ErrBrowserDeliveryRejected
		}
		authority.state = directSAMLSessionDeliveryCompensating
		cleanedUpAt := authority.now().UTC().Truncate(time.Microsecond)
		if !validInstant(cleanedUpAt) || cleanedUpAt.Before(authority.cleanup.Result.AppliedAt) {
			cleanedUpAt = authority.cleanup.Result.AppliedAt
		}
		authority.cleanup.CleanedUpAt = cleanedUpAt
	case directSAMLSessionDeliveryCompensating:
	default:
		return ErrBrowserDeliveryRejected
	}
	cleanup := authority.cleanup
	if !authority.validProofLocked() || !validDirectSAMLSessionCleanup(cleanup) {
		return ErrBrowserDeliveryRejected
	}
	for range 2 {
		bounded, cancel := context.WithTimeout(detachedContext(ctx), authority.recoveryTimeout)
		err := authority.store.CleanupDirectSAMLSessionRevalidationDelivery(bounded, cleanup)
		cancel()
		if err == nil {
			authority.state = directSAMLSessionDeliveryCompensated
			authority.clearProofLocked()
			return nil
		}
	}
	return ErrBrowserDeliveryUnavailable
}

func (authority *directSAMLSessionDeliveryAuthority) validProofLocked() bool {
	return authority != nil && !directSAMLSessionNil(authority.store) && authority.now != nil &&
		authority.recoveryTimeout >= minimumRecoveryTimeout &&
		authority.recoveryTimeout <= maximumRecoveryTimeout &&
		authority.recoveryTimeout%time.Microsecond == 0 &&
		validDirectSAMLSessionCleanup(authority.cleanup)
}

func (authority *directSAMLSessionDeliveryAuthority) clearProofLocked() {
	authority.store = nil
	authority.now = nil
	authority.recoveryTimeout = 0
	authority.cleanup = DirectSAMLSessionRevalidationCleanup{}
}

func validDirectSAMLSessionCleanup(cleanup DirectSAMLSessionRevalidationCleanup) bool {
	command := cleanup.Command
	result := cleanup.Result
	if !validDirectSAMLSessionCommand(command) ||
		(command.Decision != mfa.SessionRotate && command.Decision != mfa.SessionStepUp) ||
		!validDirectSAMLSessionResult(result, command, result.UserID) ||
		cleanup.Reason != CleanupDeliveryFailed || cleanup.Audit != command.Audit ||
		!validInstant(cleanup.CleanedUpAt) || cleanup.CleanedUpAt.Before(result.AppliedAt) {
		return false
	}
	return true
}

var _ interface {
	ConfirmBrowserDelivery() error
	CompensateBrowserDelivery(context.Context) error
} = (*DirectSAMLSessionDeliveryFinalizer)(nil)
