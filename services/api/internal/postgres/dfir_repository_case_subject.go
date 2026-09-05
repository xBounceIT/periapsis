package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

// Shared resources have no unique owning Case. Resolve only the association
// named by the request; an Alert-to-Case link does not implicitly copy its IOC
// or asset inventory into that Case.
func resolveDFIRCaseSubject(
	ctx context.Context,
	tx databaseTransaction,
	tenantID uuid.UUID,
	caseID uuid.UUID,
	subject kernel.EntityReference,
) (kernel.Visibility, error) {
	if !authorizationUUIDv7(caseID) || !authorizationUUIDv7(tenantID) ||
		uuid.UUID(subject.TenantID().Bytes()) != tenantID || subject.ID() == (kernel.EntityID{}) {
		return "", authorization.ErrForbidden
	}
	id := uuid.UUID(subject.ID().Bytes())
	visibility := kernel.VisibilityPrivate
	switch subject.Kind() {
	case kernel.EntityCase:
		if id != caseID {
			return "", authorization.ErrForbidden
		}
	case kernel.EntityEvidence:
		var classification string
		if err := tx.QueryRow(ctx, `SELECT classification::text FROM public.dfir_evidence
			WHERE tenant_id = $1 AND case_id = $2 AND id = $3`, tenantID, caseID, id).Scan(&classification); err != nil {
			return "", err
		}
		if classification == string(kernel.EvidencePublic) {
			visibility = kernel.VisibilityPublic
		}
		return visibility, nil
	case kernel.EntityTask:
		var storedID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM public.dfir_tasks
			WHERE tenant_id = $1 AND case_id = $2 AND id = $3`, tenantID, caseID, id).Scan(&storedID); err != nil {
			return "", err
		}
		if storedID != id {
			return "", unexpectedDFIRProjection("task subject identifier mismatch")
		}
		return visibility, nil
	case kernel.EntityIOC, kernel.EntityAsset:
		linkTable, resourceTable, column := "public.dfir_ioc_links", "public.dfir_iocs", "ioc_id"
		if subject.Kind() == kernel.EntityAsset {
			linkTable, resourceTable, column = "public.dfir_asset_links", "public.dfir_assets", "asset_id"
		}
		var linked bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM `+linkTable+` AS link
			JOIN `+resourceTable+` AS resource
			  ON resource.tenant_id = link.tenant_id AND resource.id = link.`+column+`
			WHERE link.tenant_id = $1 AND link.case_id = $2 AND link.`+column+` = $3
			  AND resource.archived_at IS NULL
		)`, tenantID, caseID, id).Scan(&linked); err != nil {
			return "", err
		}
		if !linked {
			return "", pgx.ErrNoRows
		}
		return visibility, nil
	case kernel.EntityAlert:
		var linked bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM public.alert_case_links AS link
			WHERE link.tenant_id = $1 AND link.case_id = $2 AND link.alert_id = $3
			  AND NOT EXISTS (
			    SELECT 1 FROM public.alert_case_link_retractions AS retraction
			    WHERE retraction.tenant_id = link.tenant_id AND retraction.link_id = link.id
			  )
		)`, tenantID, caseID, id).Scan(&linked); err != nil {
			return "", err
		}
		if !linked {
			return "", pgx.ErrNoRows
		}
		inherited, err := resolveDFIRAlertSubject(ctx, tx, tenantID, id, subject)
		if err != nil || inherited == kernel.VisibilityPrivate {
			return inherited, err
		}
	default:
		return "", authorization.ErrForbidden
	}
	record, err := loadDFIRCaseAccessRecord(ctx, tx, tenantID, caseID)
	if err != nil {
		return "", err
	}
	if record.customerVisible && record.customerState {
		visibility = kernel.VisibilityPublic
	}
	return visibility, nil
}
