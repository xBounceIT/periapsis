// Package dfir implements the deny-by-default application and storage
// orchestration boundary for tenant forensic resources.
package dfir

import "errors"

var (
	ErrInvalidInput       = errors.New("invalid DFIR input")
	ErrForbidden          = errors.New("DFIR action forbidden")
	ErrNotFound           = errors.New("DFIR resource not found")
	ErrConflict           = errors.New("DFIR state conflict")
	ErrPreconditionFailed = errors.New("DFIR precondition failed")
	ErrUnavailable        = errors.New("DFIR dependency unavailable")
)

var (
	ErrRepositoryNotFound     = errors.New("DFIR repository not found")
	ErrRepositoryForbidden    = errors.New("DFIR repository forbidden")
	ErrRepositoryConflict     = errors.New("DFIR repository conflict")
	ErrRepositoryPrecondition = errors.New("DFIR repository precondition")
)
