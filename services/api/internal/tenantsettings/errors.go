package tenantsettings

import "errors"

var (
	ErrInvalidInput = errors.New("tenant settings input is invalid")
	ErrForbidden    = errors.New("tenant settings authorization denied")
	ErrNotFound     = errors.New("tenant settings were not found")
	ErrConflict     = errors.New("tenant settings changed concurrently")
	ErrUnavailable  = errors.New("tenant settings are unavailable")
)
