// Package webhookurlpolicy defines the tenant-scoped kernel and application
// boundary for immutable webhook URL egress policies.
package webhookurlpolicy

import "errors"

var (
	ErrInvalidInput = errors.New("invalid webhook URL policy input")
	ErrForbidden    = errors.New("webhook URL policy action forbidden")
	ErrNotFound     = errors.New("webhook URL policy not found")
	ErrConflict     = errors.New("webhook URL policy conflict")
	ErrNoChange     = errors.New("webhook URL policy has no change")
	ErrUnavailable  = errors.New("webhook URL policy dependency unavailable")

	ErrRepositoryInvalidInput = errors.New("webhook URL policy repository invalid input")
	ErrRepositoryForbidden    = errors.New("webhook URL policy repository forbidden")
	ErrRepositoryNotFound     = errors.New("webhook URL policy repository not found")
	ErrRepositoryConflict     = errors.New("webhook URL policy repository conflict")
)
