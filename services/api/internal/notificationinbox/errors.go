// Package notificationinbox defines the application boundary for the personal,
// tenant-scoped notification inbox.
package notificationinbox

import "errors"

var (
	ErrInvalidInput       = errors.New("invalid notification inbox input")
	ErrForbidden          = errors.New("notification inbox action forbidden")
	ErrNotFound           = errors.New("notification inbox item not found")
	ErrConflict           = errors.New("notification inbox state conflict")
	ErrPreconditionFailed = errors.New("notification inbox precondition failed")
	ErrUnavailable        = errors.New("notification inbox dependency unavailable")

	// Repository sentinels let future adapters report storage outcomes without
	// leaking driver errors or database details across the application boundary.
	ErrRepositoryInvalidInput = errors.New("notification inbox repository invalid input")
	ErrRepositoryForbidden    = errors.New("notification inbox repository forbidden")
	ErrRepositoryNotFound     = errors.New("notification inbox repository not found")
	ErrRepositoryConflict     = errors.New("notification inbox repository conflict")
	ErrRepositoryPrecondition = errors.New("notification inbox repository precondition failed")
)
