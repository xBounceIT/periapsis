package authorization

import "errors"

var (
	ErrInvalidInput         = errors.New("invalid authorization input")
	ErrForbidden            = errors.New("authorization forbidden")
	ErrNotFound             = errors.New("authorization resource not found")
	ErrConflict             = errors.New("authorization state conflict")
	ErrPreconditionRequired = errors.New("authorization precondition required")
	ErrPreconditionFailed   = errors.New("authorization precondition failed")
	ErrUnavailable          = errors.New("authorization unavailable")
)
