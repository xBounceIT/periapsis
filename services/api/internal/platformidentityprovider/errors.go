package platformidentityprovider

import "errors"

// ErrPreconditionFailed is the only repository outcome kept distinct from the
// authentication error family. It represents an exact optimistic-version
// mismatch and is mapped by HTTP to status 412. Lifecycle and idempotency
// conflicts remain authentication.ErrConflict (409).
var ErrPreconditionFailed = errors.New("platform identity provider precondition failed")
