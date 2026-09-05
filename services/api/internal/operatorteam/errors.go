package operatorteam

import "errors"

var (
	ErrInvalidInput         = errors.New("invalid operator team input")
	ErrForbidden            = errors.New("operator team forbidden")
	ErrNotFound             = errors.New("operator team resource not found")
	ErrConflict             = errors.New("operator team state conflict")
	ErrPreconditionRequired = errors.New("operator team precondition required")
	ErrPreconditionFailed   = errors.New("operator team precondition failed")
	ErrUnavailable          = errors.New("operator team unavailable")
)
