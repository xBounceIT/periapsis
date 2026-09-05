package platformsamlauth

import (
	"context"
	"errors"
	"sync"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

var (
	// ErrBrowserDeliveryRejected is deliberately generic: it covers a stale,
	// copied, mutated, or already-finalized browser delivery capability.
	ErrBrowserDeliveryRejected = errors.New("direct platform SAML browser delivery rejected")
	// ErrBrowserDeliveryUnavailable reports only that exact compensation could
	// not be concluded within its bounded retry budget.
	ErrBrowserDeliveryUnavailable = errors.New("direct platform SAML browser delivery unavailable")
)

type browserDeliveryState uint8

const (
	browserDeliveryPending browserDeliveryState = iota + 1
	browserDeliveryConfirmed
	browserDeliveryCompensated
)

type browserDeliverySnapshot struct {
	disposition    Disposition
	userID         identity.EntityID
	sessionID      identity.EntityID
	continuationID identity.EntityID
	returnPath     string
	credential     *BrowserCredential
}

type browserDeliveryAuthority struct {
	guard sync.Mutex

	state           browserDeliveryState
	snapshot        browserDeliverySnapshot
	apply           AtomicApplyPort
	now             func() time.Time
	recoveryTimeout time.Duration
	result          ApplyResult
	audit           AuditContext
}

func newBrowserDeliveryAuthority(
	apply AtomicApplyPort,
	now func() time.Time,
	recoveryTimeout time.Duration,
	result ApplyResult,
	audit AuditContext,
	outcome Outcome,
) *browserDeliveryAuthority {
	cleanupProof := CleanupRequest{
		Result: result, Reason: CleanupDeliveryFailed, CleanedUpAt: result.AppliedAt, Audit: audit,
	}
	if apply == nil || now == nil || recoveryTimeout < minimumRecoveryTimeout ||
		recoveryTimeout > maximumRecoveryTimeout || recoveryTimeout%time.Microsecond != 0 ||
		!validCleanupRequest(cleanupProof) ||
		result.Category != ApplySuccess && result.Category != ApplyAlreadyApplied ||
		result.UserID != outcome.UserID || result.SessionID != outcome.SessionID ||
		result.ContinuationID != outcome.ContinuationID || result.ReturnPath != outcome.ReturnPath ||
		outcome.Credential == nil || !validReturnPath(outcome.ReturnPath) || !validUUIDv7(outcome.UserID) ||
		outcome.Disposition == ImmediateSession && (!validUUIDv7(outcome.SessionID) || outcome.ContinuationID != (identity.EntityID{})) ||
		outcome.Disposition == TOTPContinuation && (outcome.SessionID != (identity.EntityID{}) || !validUUIDv7(outcome.ContinuationID)) ||
		outcome.Disposition != ImmediateSession && outcome.Disposition != TOTPContinuation {
		return nil
	}
	return &browserDeliveryAuthority{
		state: browserDeliveryPending,
		snapshot: browserDeliverySnapshot{
			disposition: outcome.Disposition, userID: outcome.UserID, sessionID: outcome.SessionID,
			continuationID: outcome.ContinuationID, returnPath: outcome.ReturnPath, credential: outcome.Credential,
		},
		apply: apply, now: now, recoveryTimeout: recoveryTimeout, result: result, audit: audit,
	}
}

func (authority *browserDeliveryAuthority) matches(outcome Outcome) bool {
	if authority == nil {
		return false
	}
	authority.guard.Lock()
	defer authority.guard.Unlock()
	return authority.matchesLocked(outcome)
}

func (authority *browserDeliveryAuthority) matchesLocked(outcome Outcome) bool {
	return outcome.delivery == authority && outcome.Disposition == authority.snapshot.disposition &&
		outcome.UserID == authority.snapshot.userID && outcome.SessionID == authority.snapshot.sessionID &&
		outcome.ContinuationID == authority.snapshot.continuationID && outcome.ReturnPath == authority.snapshot.returnPath &&
		outcome.Credential == authority.snapshot.credential
}

// ConfirmBrowserDelivery irreversibly records successful synchronous browser
// delivery. Copies share one authority and cannot confirm twice.
func (outcome *Outcome) ConfirmBrowserDelivery() error {
	if outcome == nil || outcome.delivery == nil {
		return ErrBrowserDeliveryRejected
	}
	authority := outcome.delivery
	authority.guard.Lock()
	defer authority.guard.Unlock()
	if !authority.matchesLocked(*outcome) || authority.state != browserDeliveryPending {
		return ErrBrowserDeliveryRejected
	}
	authority.state = browserDeliveryConfirmed
	authority.clearProofLocked()
	return nil
}

// CompensateBrowserDelivery revokes the exact committed session or consumes
// the exact continuation after delivery failure. It never accepts caller
// timestamps, audit data, identifiers, or proof material.
func (outcome *Outcome) CompensateBrowserDelivery(ctx context.Context) error {
	if outcome == nil || outcome.delivery == nil {
		return ErrBrowserDeliveryRejected
	}
	authority := outcome.delivery
	authority.guard.Lock()
	defer authority.guard.Unlock()
	if !authority.matchesLocked(*outcome) {
		return ErrBrowserDeliveryRejected
	}
	switch authority.state {
	case browserDeliveryConfirmed:
		return ErrBrowserDeliveryRejected
	case browserDeliveryCompensated:
		return nil
	case browserDeliveryPending:
	default:
		return ErrBrowserDeliveryRejected
	}
	cleanedUpAt := authority.now().UTC().Truncate(time.Microsecond)
	if !validInstant(cleanedUpAt) || cleanedUpAt.Before(authority.result.AppliedAt) {
		cleanedUpAt = authority.result.AppliedAt
	}
	request := CleanupRequest{
		Result: authority.result, Reason: CleanupDeliveryFailed, CleanedUpAt: cleanedUpAt, Audit: authority.audit,
	}
	if !validCleanupRequest(request) {
		return ErrBrowserDeliveryRejected
	}
	for range 2 {
		bounded, cancel := context.WithTimeout(detachedContext(ctx), authority.recoveryTimeout)
		err := authority.apply.CleanupDirectSAML(bounded, request)
		cancel()
		if err == nil {
			authority.state = browserDeliveryCompensated
			authority.clearProofLocked()
			return nil
		}
	}
	return ErrBrowserDeliveryUnavailable
}

func (authority *browserDeliveryAuthority) clearProofLocked() {
	authority.result = ApplyResult{}
	authority.audit = AuditContext{}
	authority.apply = nil
	authority.now = nil
	authority.recoveryTimeout = 0
}
