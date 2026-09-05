// Package ticketnumbering defines the tenant-scoped application boundary for
// immutable ticket-numbering policies. Number allocation itself remains a
// transaction-local ticket persistence concern and uses the pure ticketing
// kernel plans.
package ticketnumbering

import "errors"

var (
	ErrInvalidInput = errors.New("invalid ticket numbering input")
	ErrForbidden    = errors.New("ticket numbering action forbidden")
	ErrNotFound     = errors.New("ticket numbering policy not found")
	ErrConflict     = errors.New("ticket numbering policy conflict")
	ErrPrecondition = errors.New("ticket numbering policy precondition failed")
	ErrNoChange     = errors.New("ticket numbering policy has no change")
	ErrUnavailable  = errors.New("ticket numbering dependency unavailable")

	ErrRepositoryInvalidInput = errors.New("ticket numbering repository invalid input")
	ErrRepositoryForbidden    = errors.New("ticket numbering repository forbidden")
	ErrRepositoryNotFound     = errors.New("ticket numbering repository not found")
	ErrRepositoryConflict     = errors.New("ticket numbering repository conflict")
	ErrRepositoryPrecondition = errors.New("ticket numbering repository precondition failed")
)
