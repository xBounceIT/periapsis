package postgres

import (
	"context"
	"errors"
	"math"
)

const liveAPIKeyVersionsQuery = `
select coalesce(
  array_agg(version.key_version order by version.key_version),
  '{}'::integer[]
)
from app.list_live_api_credential_key_versions_v1($1) as version
`

// APIKeyVersionInventory is the least-privileged readiness adapter for the
// bounded key-version function. It never queries credential identifiers,
// locators, digests, or other bearer metadata.
type APIKeyVersionInventory struct {
	pool SchemaQuerier
}

func NewAPIKeyVersionInventory(pool SchemaQuerier) APIKeyVersionInventory {
	return APIKeyVersionInventory{pool: pool}
}

func (i APIKeyVersionInventory) ListLiveAPIKeyVersions(ctx context.Context, limit int32) ([]int16, error) {
	if i.pool == nil || limit < 1 || limit > 17 {
		return nil, errors.New("invalid live API key-version inventory request")
	}
	var raw []int32
	if err := i.pool.QueryRow(ctx, liveAPIKeyVersionsQuery, limit).Scan(&raw); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("query live API key-version inventory")
	}
	if len(raw) > int(limit) {
		return nil, errors.New("invalid live API key-version inventory")
	}
	versions := make([]int16, len(raw))
	for index, version := range raw {
		if version < 1 || version > math.MaxInt16 || index > 0 && raw[index-1] >= version {
			return nil, errors.New("invalid live API key-version inventory")
		}
		versions[index] = int16(version)
	}
	return versions, nil
}
