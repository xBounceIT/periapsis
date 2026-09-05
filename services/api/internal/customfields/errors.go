// Package customfields implements the deny-by-default application boundary for
// tenant custom-field definitions and values.
package customfields

import "errors"

var (
	ErrInvalidInput       = errors.New("invalid custom-field input")
	ErrForbidden          = errors.New("custom-field action forbidden")
	ErrNotFound           = errors.New("custom-field resource not found")
	ErrConflict           = errors.New("custom-field state conflict")
	ErrPreconditionFailed = errors.New("custom-field precondition failed")
	ErrUnavailable        = errors.New("custom-field dependency unavailable")
)

// Repository errors are intentionally separate from public application errors.
// Adapters may wrap these sentinels without leaking PostgreSQL details.
var (
	ErrRepositoryNotFound     = errors.New("custom-field repository not found")
	ErrRepositoryConflict     = errors.New("custom-field repository conflict")
	ErrRepositoryPrecondition = errors.New("custom-field repository precondition")
	ErrRepositoryForbidden    = errors.New("custom-field repository forbidden")
)
