package postgres

import (
	"context"
	"errors"

	"github.com/periapsis-im/periapsis/services/api/internal/apiratelimit"
)

const admitAPIRequestQuery = `
SELECT admission.admitted,
       admission.retry_after_seconds
FROM app.admit_api_request_v1(
  $1::text[]::auth_rate_limit_scope[],
  $2::bytea[],
  $3::integer[]
) AS admission
`

// APIRateLimitRepository uses the API wrapper around the existing locked,
// multi-key PostgreSQL admission ABI. The wrapper bounds stale API-meter churn;
// runtime callers never receive table privileges or raw identity material.
type APIRateLimitRepository struct {
	pool SchemaQuerier
}

// NewAPIRateLimitRepository returns shared API admission persistence.
func NewAPIRateLimitRepository(pool SchemaQuerier) APIRateLimitRepository {
	return APIRateLimitRepository{pool: pool}
}

// Admit updates all API dimensions atomically and returns database-clock retry
// guidance suitable for an integer Retry-After header.
func (r APIRateLimitRepository) Admit(
	ctx context.Context,
	rules []apiratelimit.Rule,
) (apiratelimit.Decision, error) {
	if r.pool == nil || ctx == nil || len(rules) < 1 || len(rules) > 3 {
		return apiratelimit.Decision{}, errors.New("invalid API rate-limit admission")
	}
	if err := ctx.Err(); err != nil {
		return apiratelimit.Decision{}, err
	}

	scopes := make([]string, len(rules))
	digests := make([][]byte, len(rules))
	limits := make([]int32, len(rules))
	defer func() {
		for index := range digests {
			clear(digests[index])
		}
	}()
	seen := make(map[string]struct{}, len(rules))
	for index, rule := range rules {
		if !validAPIRateLimitScope(rule.Scope) || len(rule.Digest) != 32 ||
			rule.Limit < 1 || rule.Limit > apiratelimit.MaximumRequestsPerSecond {
			return apiratelimit.Decision{}, errors.New("invalid API rate-limit rule")
		}
		identity := rule.Scope + ":" + string(rule.Digest)
		if _, duplicate := seen[identity]; duplicate {
			return apiratelimit.Decision{}, errors.New("duplicate API rate-limit rule")
		}
		seen[identity] = struct{}{}
		scopes[index] = rule.Scope
		digests[index] = append([]byte(nil), rule.Digest...)
		limits[index] = rule.Limit
	}

	var decision apiratelimit.Decision
	err := r.pool.QueryRow(
		ctx, admitAPIRequestQuery, scopes, digests, limits,
	).Scan(&decision.Admitted, &decision.RetryAfterSeconds)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return apiratelimit.Decision{}, contextErr
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return apiratelimit.Decision{}, err
		}
		return apiratelimit.Decision{}, errors.New("admit API request")
	}
	if !decision.Valid() {
		return apiratelimit.Decision{}, errors.New("database returned an invalid API rate-limit decision")
	}
	return decision, nil
}

func validAPIRateLimitScope(scope string) bool {
	switch scope {
	case apiratelimit.ScopeNetwork, apiratelimit.ScopeCredential, apiratelimit.ScopeTenantSubject:
		return true
	default:
		return false
	}
}
