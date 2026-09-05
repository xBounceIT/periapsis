package postgres

import (
	"context"
	"errors"
)

const pruneExpiredAuthStateQuery = `
SELECT
  authentication.rate_limits_deleted,
  authentication.challenges_deleted,
  authentication.sessions_deleted,
  authorization_cleanup.platform_commands_deleted,
  authorization_cleanup.tenant_commands_deleted,
  membership_cleanup.tenant_membership_lifecycle_commands_deleted,
  dfir_cleanup.results_deleted,
  dfir_cleanup.commands_deleted
FROM app.prune_expired_auth_state($1) AS authentication
CROSS JOIN app.prune_expired_authorization_commands($1) AS authorization_cleanup
CROSS JOIN app.prune_expired_tenant_membership_lifecycle_commands_v1($1) AS membership_cleanup
CROSS JOIN app.prune_expired_dfir_mutation_commands_v1($1) AS dfir_cleanup
`

// AuthStateCleanupCounts reports one atomic, bounded authentication,
// authorization, membership-lifecycle, and DFIR-receipt retention pass.
type AuthStateCleanupCounts struct {
	RateLimits                        int
	Challenges                        int
	Sessions                          int
	PlatformCommands                  int
	TenantCommands                    int
	TenantMembershipLifecycleCommands int
	DFIRMutationCommandResults        int
	DFIRMutationCommands              int
}

// AuthStateCleaner invokes the worker-only retention functions.
type AuthStateCleaner struct {
	pool SchemaQuerier
}

// NewAuthStateCleaner returns a PostgreSQL-backed authentication state cleaner.
func NewAuthStateCleaner(pool SchemaQuerier) AuthStateCleaner {
	return AuthStateCleaner{pool: pool}
}

// Prune performs a bounded pass with an independent limit for every state class.
func (c AuthStateCleaner) Prune(ctx context.Context, perClassBatchSize int) (AuthStateCleanupCounts, error) {
	if perClassBatchSize < 1 || perClassBatchSize > 1000 {
		return AuthStateCleanupCounts{}, errors.New("retention cleanup batch is outside the database contract")
	}

	var counts AuthStateCleanupCounts
	err := c.pool.QueryRow(ctx, pruneExpiredAuthStateQuery, perClassBatchSize).Scan(
		&counts.RateLimits,
		&counts.Challenges,
		&counts.Sessions,
		&counts.PlatformCommands,
		&counts.TenantCommands,
		&counts.TenantMembershipLifecycleCommands,
		&counts.DFIRMutationCommandResults,
		&counts.DFIRMutationCommands,
	)
	if err != nil {
		return AuthStateCleanupCounts{}, errors.New("prune expired retained state")
	}
	return counts, nil
}
