package mfapolicy

import "errors"

var (
	ErrInvalidInput         = errors.New("invalid MFA policy input")
	ErrForbidden            = errors.New("MFA policy access forbidden")
	ErrNotFound             = errors.New("MFA policy not found")
	ErrConflict             = errors.New("MFA policy conflict")
	ErrRecoveryUnsafe       = errors.New("MFA policy recovery safety invariant failed")
	ErrPreconditionRequired = errors.New("MFA policy precondition required")
	ErrPreconditionFailed   = errors.New("MFA policy precondition failed")
	ErrUnavailable          = errors.New("MFA policy service unavailable")
)
