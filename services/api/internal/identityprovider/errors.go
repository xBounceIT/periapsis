package identityprovider

import "errors"

var (
	ErrInvalidInput         = errors.New("invalid identity-provider input")
	ErrForbidden            = errors.New("identity-provider operation forbidden")
	ErrNotFound             = errors.New("identity provider not found")
	ErrConflict             = errors.New("identity-provider conflict")
	ErrPreconditionRequired = errors.New("identity-provider precondition required")
	ErrPreconditionFailed   = errors.New("identity-provider precondition failed")
	ErrRateLimited          = errors.New("identity-provider operation rate limited")
	ErrUnavailable          = errors.New("identity-provider service unavailable")
)
