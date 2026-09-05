package postgres

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func TestDFIRSharedMutationRequiresEveryCurrentRoot(t *testing.T) {
	t.Parallel()
	actor, authority := sharedDFIRTestAuthority()
	caseRoot := dfirSharedRoot{kind: kernel.EntityCase, id: alertTestUUID(151)}
	alertRoot := dfirSharedRoot{kind: kernel.EntityAlert, id: alertTestUUID(152)}
	secondCase := dfirSharedRoot{kind: kernel.EntityCase, id: alertTestUUID(153)}
	roots := []dfirSharedRoot{alertRoot, caseRoot, secondCase}
	allowed := map[uuid.UUID]bool{caseRoot.id: true, alertRoot.id: true}
	visited := make([]uuid.UUID, 0)
	tx := sharedDFIRAccessTransaction(actor, allowed, &visited)
	if err := authorizeDFIRSharedRoots(context.Background(), tx, authority, actor,
		application.CapabilityIOCManage, roots, caseRoot); !errors.Is(err, authorization.ErrForbidden) {
		t.Fatalf("write through one allowed Case exposed another Case: %v", err)
	}
	if !slices.Equal(visited, []uuid.UUID{alertRoot.id, caseRoot.id, secondCase.id}) {
		t.Fatalf("root checks = %v", visited)
	}
	allowed[secondCase.id] = true
	if err := authorizeDFIRSharedRoots(context.Background(), tx, authority, actor,
		application.CapabilityIOCManage, roots, caseRoot); err != nil {
		t.Fatalf("fully authorized shared write: %v", err)
	}
	for _, required := range []dfirSharedRoot{
		{kind: kernel.EntityCase, id: alertTestUUID(154)},
		{kind: kernel.EntityAlert, id: caseRoot.id},
	} {
		if err := authorizeDFIRSharedRoots(context.Background(), tx, authority, actor,
			application.CapabilityIOCManage, roots, required); !errors.Is(err, authorization.ErrForbidden) {
			t.Fatalf("unlinked or wrong-kind path accepted: %v", err)
		}
	}
	if err := authorizeDFIRSharedRoots(context.Background(), tx, authority, actor,
		application.CapabilityIOCRead, roots, caseRoot); !errors.Is(err, authorization.ErrForbidden) {
		t.Fatalf("read permission authorized a shared write: %v", err)
	}
	authority.TenantID = alertTestUUID(155)
	if err := authorizeDFIRSharedRoots(context.Background(), tx, authority, actor,
		application.CapabilityIOCManage, roots, caseRoot); !errors.Is(err, authorization.ErrForbidden) {
		t.Fatalf("cross-tenant authority accepted: %v", err)
	}
}

func TestDFIRRelatedRootsUseCurrentVisibilityAndFailOnDatabaseErrors(t *testing.T) {
	t.Parallel()
	actor, authority := sharedDFIRTestAuthority()
	visibleCase := dfirSharedRoot{kind: kernel.EntityCase, id: alertTestUUID(161)}
	hiddenCase := dfirSharedRoot{kind: kernel.EntityCase, id: alertTestUUID(162)}
	alert := dfirSharedRoot{kind: kernel.EntityAlert, id: alertTestUUID(163)}
	roots := []dfirSharedRoot{alert, visibleCase, hiddenCase}
	allowed := map[uuid.UUID]bool{visibleCase.id: true, alert.id: true}
	visited := make([]uuid.UUID, 0)
	tx := sharedDFIRAccessTransaction(actor, allowed, &visited)
	visible, err := visibleDFIRSharedRoots(context.Background(), tx, authority, actor, application.CapabilityIOCRead, roots)
	if err != nil || !slices.Equal(visible, []dfirSharedRoot{alert, visibleCase}) {
		t.Fatalf("operator related roots = %v, %v", visible, err)
	}
	actor.Kind = application.PrincipalCustomer
	visible, err = visibleDFIRSharedRoots(context.Background(), tx, authority, actor, application.CapabilityIOCRead, roots)
	if err != nil || !slices.Equal(visible, []dfirSharedRoot{visibleCase}) {
		t.Fatalf("customer received hidden Case or Alert identifiers: %v, %v", visible, err)
	}
	databaseFailure := errors.New("database unavailable")
	tx.row = func(string, []any, []any) error { return databaseFailure }
	if _, err := visibleDFIRSharedRoots(context.Background(), tx, authority, actor,
		application.CapabilityIOCRead, roots); !errors.Is(err, databaseFailure) {
		t.Fatalf("database error masked as visibility: %v", err)
	}
}

func TestDFIRSharedRootLookupIsLockedBoundedAndRejectsMalformedResults(t *testing.T) {
	t.Parallel()
	tenantID, resourceID, rootID := alertTestUUID(171), alertTestUUID(172), alertTestUUID(173)
	for _, resourceKind := range []kernel.EntityKind{kernel.EntityIOC, kernel.EntityAsset} {
		t.Run(string(resourceKind), func(t *testing.T) {
			locked := false
			values := [][]any{{"case", rootID}}
			tx := &dfirTransactionStub{
				row: func(query string, args []any, destinations []any) error {
					if !strings.Contains(query, "FOR UPDATE") || !strings.Contains(query, "archived_at IS NULL") ||
						len(args) != 2 || args[0] != tenantID || args[1] != resourceID {
						return errors.New("resource lookup must lock an exact live tenant resource")
					}
					locked = true
					*(destinations[0].(*uuid.UUID)) = resourceID
					return nil
				},
				query: func(query string, args []any) (pgx.Rows, error) {
					if !locked || !strings.Contains(query, "ORDER BY root_kind, root_id LIMIT 65") ||
						len(args) != 2 || args[0] != tenantID || args[1] != resourceID {
						return nil, errors.New("unlocked, unbounded or unscoped associations")
					}
					return &dfirRowsStub{rows: values}, nil
				},
			}
			roots, err := loadDFIRSharedRoots(context.Background(), tx, tenantID, resourceKind, resourceID, true)
			if err != nil || !slices.Equal(roots, []dfirSharedRoot{{kind: kernel.EntityCase, id: rootID}}) {
				t.Fatalf("roots = %v, %v", roots, err)
			}
			for _, bad := range [][][]any{
				{}, {{"case", uuid.Nil}}, {{"external", rootID}}, {{"case", rootID}, {"case", rootID}},
			} {
				values = bad
				if _, err := loadDFIRSharedRoots(context.Background(), tx, tenantID, resourceKind, resourceID, true); err == nil {
					t.Fatalf("malformed roots accepted: %v", bad)
				}
			}
			values = make([][]any, maximumDFIRSharedRoots+1)
			for i := range values {
				id := rootID
				id[15] = byte(i)
				values[i] = []any{"case", id}
			}
			if _, err := loadDFIRSharedRoots(context.Background(), tx, tenantID, resourceKind, resourceID, true); !errors.Is(err, application.ErrRepositoryConflict) {
				t.Fatalf("oversized association set accepted: %v", err)
			}
			tx.row = func(string, []any, []any) error { return pgx.ErrNoRows }
			if _, err := loadDFIRSharedRoots(context.Background(), tx, tenantID, resourceKind, resourceID, true); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("deleted/archived resource accepted: %v", err)
			}
		})
	}
}

func sharedDFIRTestAuthority() (application.Actor, authorization.TenantAuthority) {
	actor := application.Actor{
		TenantID: alertTestUUID(191), ActiveTenantID: alertTestUUID(191),
		UserID: alertTestUUID(192), MembershipID: alertTestUUID(193),
		SessionID: alertTestUUID(194), AuthenticationMethod: "oidc", Kind: application.PrincipalHuman,
	}
	return actor, authorization.TenantAuthority{
		TenantID: actor.TenantID, MembershipID: actor.MembershipID,
		MembershipStatus: authorization.MembershipStatusActive,
		Principal:        authorization.TenantPrincipal{ID: actor.UserID, Kind: authorization.PrincipalKindHuman},
		LegacyRole:       authorization.LegacyMembershipRoleAnalyst,
		Permissions: []authorization.ScopedPermission{
			{Permission: authorization.TenantPermissionDFIRIOCRead, Scope: authorization.ScopeAssigned},
			{Permission: authorization.TenantPermissionDFIRIOCManage, Scope: authorization.ScopeAssigned},
			{Permission: authorization.TenantPermissionDFIRAssetRead, Scope: authorization.ScopeAssigned},
			{Permission: authorization.TenantPermissionDFIRAssetManage, Scope: authorization.ScopeAssigned},
		},
	}
}

func sharedDFIRAccessTransaction(actor application.Actor, allowed map[uuid.UUID]bool, visited *[]uuid.UUID) *dfirTransactionStub {
	return &dfirTransactionStub{row: func(query string, args []any, destinations []any) error {
		if len(args) != 2 || args[0] != actor.TenantID {
			return errors.New("access lookup omitted tenant context")
		}
		id := args[1].(uuid.UUID)
		*visited = append(*visited, id)
		var assignee *uuid.UUID
		if allowed[id] {
			assignee = &actor.UserID
		}
		if strings.Contains(query, "FROM public.cases AS ticket") {
			visible := allowed[id]
			return dfirCaseAccessRow(&visible, assignee, nil, nil, nil, visible)(query, args, destinations)
		}
		if !strings.Contains(query, "FROM public.alerts AS alert") || len(destinations) != 4 {
			return errors.New("unexpected root authorization query")
		}
		*(destinations[0].(**uuid.UUID)) = assignee
		*(destinations[1].(**uuid.UUID)) = nil
		*(destinations[2].(**uuid.UUID)) = nil
		*(destinations[3].(**uuid.UUID)) = nil
		return nil
	}}
}
