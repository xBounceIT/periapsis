package platformoperations

import "errors"

var (
	ErrInvalidInput = errors.New("platform operations input is invalid")
	ErrForbidden    = errors.New("platform operations authorization denied")
	ErrNotFound     = errors.New("platform operations resource was not found")
	ErrConflict     = errors.New("platform operations resource changed concurrently")
	ErrUnavailable  = errors.New("platform operations are unavailable")
)
