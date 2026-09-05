package platformlocalaccount

import "errors"

var (
	// ErrPreconditionFailed reports a stale strong validator without disclosing
	// whether a differently scoped account exists.
	ErrPreconditionFailed = errors.New("platform local account precondition failed")
	// ErrTransitionConflict reports a lifecycle or recovery-floor conflict.
	ErrTransitionConflict = errors.New("platform local account transition conflict")
	// ErrPasswordReused reports that the proposed password matches retained
	// credential history. It deliberately carries no history detail.
	ErrPasswordReused = errors.New("platform local account password was previously used")
	// ErrEnrollmentProofRejected is the only callback failure that may consume
	// a bounded ceremony attempt. It never distinguishes token, TOTP, or state.
	ErrEnrollmentProofRejected = errors.New("platform local account enrollment proof rejected")
)
