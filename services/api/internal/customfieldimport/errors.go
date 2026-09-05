// Package customfieldimport is the isolated application boundary for bounded,
// asynchronous Alert and Case custom-field imports.
package customfieldimport

import "errors"

var (
	ErrInvalidInput       = errors.New("invalid custom-field import input")
	ErrForbidden          = errors.New("custom-field import forbidden")
	ErrNotFound           = errors.New("custom-field import not found")
	ErrConflict           = errors.New("custom-field import conflict")
	ErrPreconditionFailed = errors.New("custom-field import precondition failed")
	ErrUnavailable        = errors.New("custom-field import dependency unavailable")
)

// Persistence adapters wrap only these stable sentinels. Raw PostgreSQL,
// authorization, validation, ticket, and tenant data must never cross this ABI.
var (
	ErrRepositoryNotFound             = errors.New("custom-field import repository not found")
	ErrRepositoryConflict             = errors.New("custom-field import repository conflict")
	ErrRepositoryPrecondition         = errors.New("custom-field import repository precondition")
	ErrRepositoryForbidden            = errors.New("custom-field import repository forbidden")
	ErrRepositoryAuthorizationRevoked = errors.New("custom-field import repository authorization revoked")
)
