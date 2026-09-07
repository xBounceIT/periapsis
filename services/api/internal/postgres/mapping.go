package postgres

import (
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

const (
	sha256DigestBytes = 32
	maximumRateRules  = 8
	maximumRetryAfter = 24 * time.Hour
)

type auditArguments struct {
	requestID     pgtype.UUID
	correlationID pgtype.UUID
}

func eventArguments(event authentication.EventContext) (auditArguments, error) {
	if err := validateEventContext(event); err != nil {
		return auditArguments{}, err
	}
	return auditArguments{
		requestID:     toDatabaseUUID(event.RequestID),
		correlationID: toDatabaseUUID(event.CorrelationID),
	}, nil
}

func toDatabaseUUID(value uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: [16]byte(value), Valid: value != uuid.Nil}
}

func optionalDatabaseUUID(value *uuid.UUID) pgtype.UUID {
	if value == nil {
		return pgtype.UUID{}
	}
	return toDatabaseUUID(*value)
}

func domainUUID(value pgtype.UUID) (uuid.UUID, error) {
	if !value.Valid {
		return uuid.Nil, errors.New("database UUID is null")
	}
	identifier := uuid.UUID(value.Bytes)
	if identifier == uuid.Nil {
		return uuid.Nil, errors.New("database UUID is zero")
	}
	return identifier, nil
}

func databaseTime(value time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: value.UTC(), Valid: !value.IsZero()}
}

func domainTime(value pgtype.Timestamptz) (time.Time, error) {
	if !value.Valid || value.Time.IsZero() {
		return time.Time{}, errors.New("database timestamp is null")
	}
	return value.Time.UTC(), nil
}

func optionalDomainTime(value pgtype.Timestamptz) *time.Time {
	if !value.Valid || value.Time.IsZero() {
		return nil
	}
	timestamp := value.Time.UTC()
	return &timestamp
}

func databaseScope(scope string) (dbsql.AuthRateLimitScope, error) {
	switch scope {
	case string(dbsql.AuthRateLimitScopeBootstrapTotp):
		return dbsql.AuthRateLimitScopeBootstrapTotp, nil
	case string(dbsql.AuthRateLimitScopeLocalLogin):
		return dbsql.AuthRateLimitScopeLocalLogin, nil
	case string(dbsql.AuthRateLimitScopeMfaChallenge):
		return dbsql.AuthRateLimitScopeMfaChallenge, nil
	case string(dbsql.AuthRateLimitScopeRecoveryCode):
		return dbsql.AuthRateLimitScopeRecoveryCode, nil
	case string(dbsql.AuthRateLimitScopeTenantSwitch):
		return dbsql.AuthRateLimitScopeTenantSwitch, nil
	default:
		return "", fmt.Errorf("unknown authentication rate-limit scope %q", scope)
	}
}

type databaseRateRules struct {
	scopes        []string
	keyDigests    [][]byte
	windowSeconds []int32
	maxAttempts   []int32
	blockSeconds  []int32
}

func mapRateRules(rules []authentication.RateLimitRule) (databaseRateRules, error) {
	if len(rules) == 0 || len(rules) > maximumRateRules {
		return databaseRateRules{}, errors.New("authentication rate-limit rule count is invalid")
	}
	mapped := databaseRateRules{
		scopes:        make([]string, 0, len(rules)),
		keyDigests:    make([][]byte, 0, len(rules)),
		windowSeconds: make([]int32, 0, len(rules)),
		maxAttempts:   make([]int32, 0, len(rules)),
		blockSeconds:  make([]int32, 0, len(rules)),
	}
	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		scope, err := databaseScope(rule.Key.Scope)
		if err != nil {
			return databaseRateRules{}, err
		}
		if len(rule.Key.Digest) != sha256DigestBytes || rule.Policy.Limit < 1 {
			return databaseRateRules{}, errors.New("authentication rate-limit rule is invalid")
		}
		windowSeconds, err := durationSeconds(rule.Policy.Window)
		if err != nil {
			return databaseRateRules{}, fmt.Errorf("authentication rate-limit window: %w", err)
		}
		blockSeconds, err := durationSeconds(rule.Policy.BlockFor)
		if err != nil {
			return databaseRateRules{}, fmt.Errorf("authentication rate-limit block: %w", err)
		}
		identity := string(scope) + ":" + string(rule.Key.Digest)
		if _, duplicate := seen[identity]; duplicate {
			return databaseRateRules{}, errors.New("duplicate authentication rate-limit rule")
		}
		seen[identity] = struct{}{}
		mapped.scopes = append(mapped.scopes, string(scope))
		mapped.keyDigests = append(mapped.keyDigests, append([]byte(nil), rule.Key.Digest...))
		mapped.windowSeconds = append(mapped.windowSeconds, windowSeconds)
		mapped.maxAttempts = append(mapped.maxAttempts, rule.Policy.Limit)
		mapped.blockSeconds = append(mapped.blockSeconds, blockSeconds)
	}
	return mapped, nil
}

func mapUniformRateRules(
	keys []authentication.RateLimitKey,
	policy authentication.RateLimitPolicy,
) (databaseRateRules, error) {
	rules := make([]authentication.RateLimitRule, len(keys))
	for index, key := range keys {
		rules[index] = authentication.RateLimitRule{Key: key, Policy: policy}
	}
	return mapRateRules(rules)
}

func mapRateKeys(keys []authentication.RateLimitKey) ([]string, [][]byte, error) {
	if len(keys) == 0 || len(keys) > maximumRateRules {
		return nil, nil, errors.New("authentication rate-limit key count is invalid")
	}
	scopes := make([]string, 0, len(keys))
	digests := make([][]byte, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		scope, err := databaseScope(key.Scope)
		if err != nil || len(key.Digest) != sha256DigestBytes {
			return nil, nil, errors.New("authentication rate-limit key is invalid")
		}
		identity := string(scope) + ":" + string(key.Digest)
		if _, duplicate := seen[identity]; duplicate {
			return nil, nil, errors.New("duplicate authentication rate-limit key")
		}
		seen[identity] = struct{}{}
		scopes = append(scopes, string(scope))
		digests = append(digests, append([]byte(nil), key.Digest...))
	}
	return scopes, digests, nil
}

func durationSeconds(value time.Duration) (int32, error) {
	if value < time.Second || value%time.Second != 0 {
		return 0, errors.New("duration must be a positive whole number of seconds")
	}
	seconds := value / time.Second
	if seconds > math.MaxInt32 {
		return 0, errors.New("duration exceeds database range")
	}
	return int32(seconds), nil
}

func retryAfter(blockedUntil pgtype.Timestamptz, now time.Time) *authentication.RateLimitError {
	if !blockedUntil.Valid || !blockedUntil.Time.After(now) {
		return nil
	}
	duration := blockedUntil.Time.Sub(now)
	if duration < time.Second {
		duration = time.Second
	}
	if duration > maximumRetryAfter {
		duration = maximumRetryAfter
	}
	return &authentication.RateLimitError{RetryAfter: duration}
}

func mapPermissions(values []string) ([]authorization.Permission, error) {
	permissions := make([]authorization.Permission, 0, len(values))
	seen := make(map[authorization.Permission]struct{}, len(values))
	for _, value := range values {
		permission := authorization.Permission(value)
		// Validate database grants against the same closed catalog used by
		// authorization, so new catalog entries cannot break session hydration.
		if err := (authorization.Evaluator{}).Require([]authorization.Permission{permission}, permission); err != nil {
			return nil, fmt.Errorf("database returned unknown permission %q", value)
		}
		if _, duplicate := seen[permission]; duplicate {
			continue
		}
		seen[permission] = struct{}{}
		permissions = append(permissions, permission)
	}
	return permissions, nil
}

func postgresCode(err error) string {
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		return databaseError.Code
	}
	return ""
}

func mapCommonDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return authentication.ErrNotFound
	}
	switch postgresCode(err) {
	case "22023":
		return authentication.ErrInvalidInput
	case "23505", "55000":
		return authentication.ErrConflict
	default:
		return err
	}
}
