package platformidentityaccount

import "errors"

// ErrPreconditionFailed represents an exact account or embedded-user
// representation-version mismatch. Subject collisions, idempotency mismatches,
// and attempts to recreate a retired link remain authentication.ErrConflict.
var ErrPreconditionFailed = errors.New("platform identity account precondition failed")
