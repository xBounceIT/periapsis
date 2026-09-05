package platformidentitybinding

import "errors"

// ErrPreconditionFailed represents an exact optimistic-version mismatch. All
// other lifecycle and idempotency conflicts use authentication.ErrConflict.
var ErrPreconditionFailed = errors.New("platform identity binding precondition failed")
