package alert

import "errors"

var (
	ErrInvalidInput    = errors.New("invalid Alert input")
	ErrUnauthenticated = errors.New("Alert authentication failed")
	ErrForbidden       = errors.New("Alert operation forbidden")
	ErrConflict        = errors.New("Alert state conflict")
	ErrUnavailable     = errors.New("Alert service unavailable")
)
