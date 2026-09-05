// Package ticketing implements the application boundary around the shared,
// deterministic ticketing kernel.
package ticketing

import "errors"

var (
	ErrInvalidInput       = errors.New("invalid ticketing input")
	ErrForbidden          = errors.New("ticketing action forbidden")
	ErrNotFound           = errors.New("ticketing resource not found")
	ErrConflict           = errors.New("ticketing state conflict")
	ErrExportLimit        = errors.New("customer portal export exceeds the synchronous limit")
	ErrPreconditionFailed = errors.New("ticketing precondition failed")
	ErrUnavailable        = errors.New("ticketing dependency unavailable")
)
