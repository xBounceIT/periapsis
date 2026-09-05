package postgres

import (
	"context"
	"slices"

	"github.com/google/uuid"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

// An attachment on a shared IOC/asset appears through all its active roots.
// Preparing or replaying that upload therefore requires attachment.manage on
// every root, even when the actor may read the resource through the path alone.
func authorizeDFIRSharedAttachment(
	ctx context.Context,
	tx databaseTransaction,
	authority authorization.TenantAuthority,
	write application.StorageWrite,
) ([]dfirSharedRoot, error) {
	subject := write.Attachment.Subject()
	if subject.Kind() != kernel.EntityIOC && subject.Kind() != kernel.EntityAsset {
		return nil, nil
	}
	if err := validateDFIRAuthority(authority, write.Actor); err != nil {
		return nil, err
	}
	if write.Actor.Kind != application.PrincipalHuman ||
		uuid.UUID(subject.TenantID().Bytes()) != write.Actor.TenantID {
		return nil, authorization.ErrForbidden
	}
	root := dfirSharedRoot{kind: kernel.EntityCase, id: uuid.UUID(write.CaseID.Bytes())}
	if write.AlertID != (kernel.EntityID{}) {
		if write.CaseID != (kernel.EntityID{}) {
			return nil, authorization.ErrForbidden
		}
		root = dfirSharedRoot{kind: kernel.EntityAlert, id: uuid.UUID(write.AlertID.Bytes())}
	}
	if !authorizationUUIDv7(root.id) {
		return nil, authorization.ErrForbidden
	}
	roots, err := loadDFIRSharedRoots(ctx, tx, write.Actor.TenantID, subject.Kind(), uuid.UUID(subject.ID().Bytes()), true)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(roots, root) {
		return nil, authorization.ErrForbidden
	}
	if err := lockDFIRSharedAttachmentRoots(ctx, tx, write.Actor.TenantID, roots); err != nil {
		return nil, err
	}
	if err := authorizeDFIRSharedRoots(ctx, tx, authority, write.Actor, application.CapabilityAttachmentManage, roots, root); err != nil {
		return nil, err
	}
	return roots, nil
}

func lockDFIRSharedAttachmentRoots(ctx context.Context, tx databaseTransaction, tenantID uuid.UUID, roots []dfirSharedRoot) error {
	ordered := slices.Clone(roots)
	slices.SortFunc(ordered, compareDFIRSharedRoots)
	for _, root := range ordered {
		query := `SELECT id FROM public.cases WHERE tenant_id = $1 AND id = $2 FOR UPDATE`
		if root.kind == kernel.EntityAlert {
			query = `SELECT id FROM public.alerts WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL FOR UPDATE`
		} else if root.kind != kernel.EntityCase {
			return authorization.ErrForbidden
		}
		var lockedID uuid.UUID
		if err := tx.QueryRow(ctx, query, tenantID, root.id).Scan(&lockedID); err != nil {
			return err
		}
		if lockedID != root.id {
			return unexpectedDFIRProjection("shared attachment root identifier mismatch")
		}
	}
	return nil
}

func (repository *DFIRRepository) appendSharedAttachmentActivities(
	ctx context.Context,
	tx databaseTransaction,
	commandID uuid.UUID,
	roots []dfirSharedRoot,
) error {
	if len(roots) < 2 {
		return nil
	}
	ids, err := phase4NewIDs(repository.newID, len(roots)-1)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `SELECT app.append_shared_dfir_activities_v1($1, $2::uuid[])`, commandID, ids)
	return err
}
