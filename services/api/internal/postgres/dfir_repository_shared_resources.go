package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

const maximumDFIRSharedRoots = 64

type dfirSharedRoot struct {
	kind kernel.EntityKind
	id   uuid.UUID
}

// All writers of a shared resource lock its row before inspecting associations.
// Together with the serializable transaction, this keeps the authorization set
// tied to the resource version even when another root changes its links.
func loadDFIRSharedRoots(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	resourceKind kernel.EntityKind,
	resourceID uuid.UUID,
	lock bool,
) ([]dfirSharedRoot, error) {
	var resourceQuery, linksQuery string
	switch resourceKind {
	case kernel.EntityIOC:
		resourceQuery = `SELECT id FROM public.dfir_iocs
			WHERE tenant_id = $1 AND id = $2 AND archived_at IS NULL`
		linksQuery = `SELECT CASE WHEN case_id IS NOT NULL THEN 'case' ELSE 'alert' END AS root_kind,
			coalesce(case_id, alert_id) AS root_id
			FROM public.dfir_ioc_links WHERE tenant_id = $1 AND ioc_id = $2
			ORDER BY root_kind, root_id LIMIT 65`
	case kernel.EntityAsset:
		resourceQuery = `SELECT id FROM public.dfir_assets
			WHERE tenant_id = $1 AND id = $2 AND archived_at IS NULL`
		linksQuery = `SELECT CASE WHEN case_id IS NOT NULL THEN 'case' ELSE 'alert' END AS root_kind,
			coalesce(case_id, alert_id) AS root_id
			FROM public.dfir_asset_links WHERE tenant_id = $1 AND asset_id = $2
			ORDER BY root_kind, root_id LIMIT 65`
	default:
		return nil, application.ErrRepositoryForbidden
	}
	if !authorizationUUIDv7(tenantID) || !authorizationUUIDv7(resourceID) {
		return nil, application.ErrRepositoryForbidden
	}
	if lock {
		resourceQuery += " FOR UPDATE"
	}
	var lockedID uuid.UUID
	if err := tx.QueryRow(ctx, resourceQuery, tenantID, resourceID).Scan(&lockedID); err != nil {
		return nil, err
	}
	if lockedID != resourceID {
		return nil, unexpectedDFIRProjection("shared resource identifier mismatch")
	}
	rows, err := tx.Query(ctx, linksQuery, tenantID, resourceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	roots := make([]dfirSharedRoot, 0)
	seen := make(map[dfirSharedRoot]struct{})
	for rows.Next() {
		var kind string
		var id uuid.UUID
		if err := rows.Scan(&kind, &id); err != nil {
			return nil, err
		}
		root := dfirSharedRoot{kind: kernel.EntityKind(kind), id: id}
		if (root.kind != kernel.EntityCase && root.kind != kernel.EntityAlert) || !authorizationUUIDv7(root.id) {
			return nil, unexpectedDFIRProjection("invalid shared resource root")
		}
		if _, duplicate := seen[root]; duplicate {
			return nil, unexpectedDFIRProjection("duplicate shared resource root")
		}
		seen[root] = struct{}{}
		roots = append(roots, root)
		if len(roots) > maximumDFIRSharedRoots {
			return nil, application.ErrRepositoryConflict
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(roots) == 0 {
		return nil, application.ErrRepositoryForbidden
	}
	return roots, nil
}

func authorizeDFIRSharedRoots(
	ctx context.Context,
	tx databaseTransaction,
	authority authorization.TenantAuthority,
	actor application.Actor,
	capability application.Capability,
	roots []dfirSharedRoot,
	requiredRoot dfirSharedRoot,
) error {
	if actor.Kind != application.PrincipalHuman ||
		(capability != application.CapabilityIOCManage && capability != application.CapabilityAssetManage &&
			capability != application.CapabilityAttachmentManage) ||
		len(roots) == 0 || len(roots) > maximumDFIRSharedRoots {
		return authorization.ErrForbidden
	}
	if err := validateDFIRAuthority(authority, actor); err != nil {
		return err
	}
	found := false
	for _, root := range roots {
		if _, err := dfirSharedRootAccess(ctx, tx, authority, actor, capability, root); err != nil {
			return err
		}
		found = found || root == requiredRoot
	}
	if !found {
		return authorization.ErrForbidden
	}
	return nil
}

func authorizeDFIRSharedMutation(
	ctx context.Context,
	tx databaseTransaction,
	actor application.Actor,
	tenantID uuid.UUID,
	resourceKind kernel.EntityKind,
	resourceID uuid.UUID,
	requiredRoot dfirSharedRoot,
) ([]dfirSharedRoot, error) {
	capability := application.CapabilityIOCManage
	if resourceKind == kernel.EntityAsset {
		capability = application.CapabilityAssetManage
	} else if resourceKind != kernel.EntityIOC {
		return nil, authorization.ErrForbidden
	}
	authority, err := phase4Authority(ctx, tx, dfirAuthorizationActor(actor), tenantID)
	if err != nil {
		return nil, err
	}
	if err := validateDFIRAuthority(authority, actor); err != nil {
		return nil, err
	}
	roots, err := loadDFIRSharedRoots(ctx, tx, tenantID, resourceKind, resourceID, true)
	if err != nil {
		return nil, err
	}
	if err := authorizeDFIRSharedRoots(ctx, tx, authority, actor, capability, roots, requiredRoot); err != nil {
		return nil, err
	}
	return roots, nil
}

func dfirSharedRootAccess(
	ctx context.Context,
	tx databaseTransaction,
	authority authorization.TenantAuthority,
	actor application.Actor,
	capability application.Capability,
	root dfirSharedRoot,
) (application.Access, error) {
	switch root.kind {
	case kernel.EntityCase:
		return dfirAccessForCase(ctx, tx, authority, actor, capability, root.id)
	case kernel.EntityAlert:
		return dfirAccessForAlert(ctx, tx, authority, actor, capability, root.id)
	default:
		return application.Access{}, authorization.ErrForbidden
	}
}

// Read projections omit roots the current actor cannot see. Unexpected database
// errors still abort the request rather than looking like a permission denial.
func visibleDFIRSharedRoots(
	ctx context.Context,
	tx databaseTransaction,
	authority authorization.TenantAuthority,
	actor application.Actor,
	capability application.Capability,
	roots []dfirSharedRoot,
) ([]dfirSharedRoot, error) {
	if capability != application.CapabilityIOCRead && capability != application.CapabilityAssetRead {
		return nil, authorization.ErrForbidden
	}
	if err := validateDFIRAuthority(authority, actor); err != nil {
		return nil, err
	}
	visible := make([]dfirSharedRoot, 0, len(roots))
	for _, root := range roots {
		if _, err := dfirSharedRootAccess(ctx, tx, authority, actor, capability, root); err != nil {
			if errors.Is(err, authorization.ErrForbidden) || errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			return nil, err
		}
		visible = append(visible, root)
	}
	return visible, nil
}

func loadDFIRWorkspaceSharedResources(
	ctx context.Context,
	tx databaseTransaction,
	authority authorization.TenantAuthority,
	actor application.Actor,
	indicators []application.Versioned[kernel.Indicator],
	assets []application.Versioned[kernel.Asset],
) ([]application.SharedResource, error) {
	if err := validateDFIRAuthority(authority, actor); err != nil {
		return nil, err
	}
	result := make([]application.SharedResource, 0, len(indicators)+len(assets))
	type accessKey struct {
		capability application.Capability
		root       dfirSharedRoot
	}
	// Many resources share the same tickets. Cache only within this transaction
	// and include the capability so IOC access cannot grant asset visibility.
	readable := make(map[accessKey]bool)
	appendResource := func(kind kernel.EntityKind, id kernel.EntityID, capability application.Capability) error {
		roots, err := loadDFIRSharedRoots(ctx, tx, actor.TenantID, kind, uuid.UUID(id.Bytes()), false)
		if err != nil {
			return err
		}
		item := application.SharedResource{ResourceKind: kind, ResourceID: id, Roots: make([]application.RelatedRoot, 0, len(roots))}
		for _, root := range roots {
			key := accessKey{capability: capability, root: root}
			visible, cached := readable[key]
			if !cached {
				projection, err := visibleDFIRSharedRoots(ctx, tx, authority, actor, capability, []dfirSharedRoot{root})
				if err != nil {
					return err
				}
				visible = len(projection) == 1
				readable[key] = visible
			}
			if visible {
				item.Roots = append(item.Roots, application.RelatedRoot{Kind: root.kind, ID: entityID(root.id)})
			}
		}
		result = append(result, item)
		return nil
	}
	for _, item := range indicators {
		if err := appendResource(kernel.EntityIOC, item.Resource.ID(), application.CapabilityIOCRead); err != nil {
			return nil, err
		}
	}
	for _, item := range assets {
		if err := appendResource(kernel.EntityAsset, item.Resource.ID(), application.CapabilityAssetRead); err != nil {
			return nil, err
		}
	}
	return result, nil
}
