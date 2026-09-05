// Package contacts implements the application boundary for customer contacts,
// recipient groups, portal relationships, and customer-safe author snapshots.
package contacts

import "errors"

var (
	ErrInvalidInput       = errors.New("invalid contacts input")
	ErrForbidden          = errors.New("contacts action forbidden")
	ErrNotFound           = errors.New("contacts resource not found")
	ErrConflict           = errors.New("contacts state conflict")
	ErrPreconditionFailed = errors.New("contacts precondition failed")
	ErrUnavailable        = errors.New("contacts dependency unavailable")

	ErrRepositoryForbidden    = errors.New("contacts repository forbidden")
	ErrRepositoryNotFound     = errors.New("contacts repository not found")
	ErrRepositoryConflict     = errors.New("contacts repository conflict")
	ErrRepositoryPrecondition = errors.New("contacts repository precondition failed")
)
