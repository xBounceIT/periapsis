package sla

import "errors"

var (
	ErrForbidden          = errors.New("SLA operation forbidden")
	ErrInvalidInput       = errors.New("invalid SLA request")
	ErrNotFound           = errors.New("SLA resource not found")
	ErrConflict           = errors.New("SLA operation conflict")
	ErrPreconditionFailed = errors.New("SLA precondition failed")
	ErrUnavailable        = errors.New("SLA service unavailable")

	ErrRepositoryForbidden    = errors.New("SLA repository forbidden")
	ErrRepositoryNotFound     = errors.New("SLA repository not found")
	ErrRepositoryConflict     = errors.New("SLA repository conflict")
	ErrRepositoryPrecondition = errors.New("SLA repository precondition failed")
)
