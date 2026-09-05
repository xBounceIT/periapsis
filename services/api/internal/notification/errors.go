package notification

import "errors"

var (
	ErrInvalidInput         = errors.New("invalid notification input")
	ErrForbidden            = errors.New("notification administration forbidden")
	ErrNotFound             = errors.New("notification resource not found")
	ErrConflict             = errors.New("notification state conflict")
	ErrPreconditionRequired = errors.New("notification precondition required")
	ErrPreconditionFailed   = errors.New("notification precondition failed")
	ErrRateLimited          = errors.New("notification operation rate limited")
	ErrUnavailable          = errors.New("notification administration unavailable")
	ErrInvalidKeyring       = errors.New("invalid notification keyring")
	ErrInvalidSecret        = errors.New("invalid protected notification secret")
	ErrInvalidCursor        = errors.New("invalid notification cursor")
)
