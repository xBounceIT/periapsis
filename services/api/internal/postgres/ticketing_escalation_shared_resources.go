package postgres

import (
	"context"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

// Lock the full selected resource set before the escalation ABI locks ticket
// roots. Shared-resource mutation/link writers use that same resource-first
// order. These locks do not grant permission: the SQL ABI must still validate
// the selection and all current linked-root authority in this transaction.
func lockEscalationSharedResources(ctx context.Context, tx databaseTransaction, tenantID uuid.UUID, sources []escalationSourceJSON) error {
	if !authorizationUUIDv7(tenantID) {
		return application.ErrForbidden
	}
	for _, resource := range []struct{ field, table string }{
		{"assetIds", "public.dfir_assets"}, {"iocIds", "public.dfir_iocs"},
	} {
		unique := make(map[uuid.UUID]struct{})
		for _, source := range sources {
			for _, id := range source.ItemIDs[resource.field] {
				if !authorizationUUIDv7(id) {
					return application.ErrInvalidInput
				}
				unique[id] = struct{}{}
			}
		}
		if len(unique) == 0 {
			continue
		}
		ids := make([]uuid.UUID, 0, len(unique))
		for id := range unique {
			ids = append(ids, id)
		}
		slices.SortFunc(ids, func(left, right uuid.UUID) int { return slices.Compare(left[:], right[:]) })
		rows, err := tx.Query(ctx, `SELECT id FROM `+resource.table+`
			WHERE tenant_id = $1 AND id = ANY($2::uuid[]) AND archived_at IS NULL
			ORDER BY id FOR UPDATE`, tenantID, ids)
		if err != nil {
			return err
		}
		locked, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			return err
		}
		if !slices.Equal(locked, ids) {
			return application.ErrNotFound
		}
	}
	return nil
}
