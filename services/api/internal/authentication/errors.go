package authentication

import (
	"errors"
	"time"
)

var (
	ErrConflict              = errors.New("authentication state conflict")
	ErrForbidden             = errors.New("action forbidden")
	ErrInvalidAuthentication = errors.New("authentication failed")
	ErrInvalidInput          = errors.New("invalid input")
	ErrNotFound              = errors.New("record not found")
	ErrUnavailable           = errors.New("authentication unavailable")
)

// RateLimitError exposes only the retry interval required by the HTTP contract.
type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return "authentication temporarily throttled"
}
