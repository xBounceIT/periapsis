package auditoperations

import "errors"

var (
	ErrInvalidInput = errors.New("audit operation input is invalid")
	ErrForbidden    = errors.New("audit operation authorization denied")
	ErrNotFound     = errors.New("audit operation resource was not found")
	ErrConflict     = errors.New("audit operation conflicts with current state")
	ErrPrecondition = errors.New("audit operation precondition failed")
	ErrUnavailable  = errors.New("audit operation service is unavailable")
)
