package serviceaccount

import (
	"errors"

	"github.com/google/uuid"
)

var (
	ErrInvalidInput               = errors.New("invalid service-account input")
	ErrForbidden                  = errors.New("service-account operation forbidden")
	ErrNotFound                   = errors.New("service-account resource not found")
	ErrConflict                   = errors.New("service-account state conflict")
	ErrPreconditionRequired       = errors.New("service-account precondition required")
	ErrPreconditionFailed         = errors.New("service-account precondition failed")
	ErrOneTimeSecretAlreadyIssued = errors.New("one-time API credential secret already issued")
	ErrUnavailable                = errors.New("service-account service unavailable")
)

// OneTimeSecretAlreadyIssuedError identifies only the redacted result of an
// exact issue or rotation replay. It never contains the original or replacement
// bearer token.
type OneTimeSecretAlreadyIssuedError struct {
	ServiceAccountID uuid.UUID
	CredentialID     uuid.UUID
	Version          int64
}

func (e *OneTimeSecretAlreadyIssuedError) Error() string {
	return ErrOneTimeSecretAlreadyIssued.Error()
}

func (e *OneTimeSecretAlreadyIssuedError) Unwrap() error {
	return ErrOneTimeSecretAlreadyIssued
}
