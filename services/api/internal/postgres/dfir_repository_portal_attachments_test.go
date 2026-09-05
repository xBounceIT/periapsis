package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func TestDFIRPortalAttachmentAccessUsesOneCompoundAuthoritySnapshotAndExactLiveLink(t *testing.T) {
	t.Parallel()
	tenantID := portalTestUUID(1)
	userID := portalTestUUID(2)
	membershipID := portalTestUUID(3)
	contactID := portalTestUUID(4)
	rootID := portalTestUUID(5)
	actor := application.Actor{
		TenantID: tenantID, ActiveTenantID: tenantID, UserID: userID, MembershipID: membershipID,
		SessionID: portalTestUUID(6), AuthenticationMethod: "oidc", Kind: application.PrincipalCustomer,
	}
	root := application.PortalAttachmentRoot{Kind: application.PortalTicketAlert, ID: entityID(rootID)}
	claimed := application.PortalAttachmentAuthorization{
		TenantID: tenantID, Root: root, ContactID: contactID, TicketVersion: 7,
	}
	permissions := [][]any{
		{"portal.attachment.read", "own", false, pgtype.Timestamptz{}},
		{"portal.alert.read", "own", false, pgtype.Timestamptz{}},
	}
	linked := true
	customerVisible := true
	linkQueries := 0
	now := time.Now().UTC().Truncate(time.Microsecond)
	tx := &dfirTransactionStub{
		row: func(query string, arguments []any, destinations []any) error {
			switch {
			case strings.Contains(query, "set_config('app.tenant_id'"):
				if len(arguments) != 2 || len(destinations) != 2 {
					return errors.New("tenant context was not exact")
				}
				*(destinations[0].(*string)) = tenantID.String()
				*(destinations[1].(*string)) = userID.String()
				return nil
			case strings.Contains(query, "get_current_tenant_authorization_context"):
				if len(arguments) != 0 || len(destinations) != 6 {
					return errors.New("authority context query drifted")
				}
				*(destinations[0].(*pgtype.UUID)) = portalPGUUID(tenantID)
				*(destinations[1].(*pgtype.UUID)) = portalPGUUID(membershipID)
				*(destinations[2].(*int64)) = 11
				*(destinations[3].(*string)) = "active"
				*(destinations[4].(*string)) = "customer_user"
				*(destinations[5].(*pgtype.Timestamptz)) = pgtype.Timestamptz{Time: now, Valid: true}
				return nil
			case strings.Contains(query, "FROM public.customer_contacts AS contact"):
				linkQueries++
				if !strings.Contains(query, "ticket.deleted_at IS NULL") ||
					!strings.Contains(query, "contact.linked_membership_id = $3") ||
					!strings.Contains(query, "contact.linked_user_id = $4") || len(arguments) != 6 ||
					arguments[0] != tenantID || arguments[1] != contactID || arguments[2] != membershipID ||
					arguments[3] != userID || arguments[4] != rootID || arguments[5] != "alert" {
					return errors.New("portal link query was not exact and live")
				}
				*(destinations[0].(*uuid.UUID)) = contactID
				*(destinations[1].(*int64)) = 3
				*(destinations[2].(*int64)) = 7
				*(destinations[3].(*bool)) = customerVisible
				*(destinations[4].(*bool)) = true
				*(destinations[5].(*bool)) = linked
				return nil
			default:
				return errors.New("unexpected portal authorization row query")
			}
		},
		query: func(query string, _ []any) (pgx.Rows, error) {
			switch {
			case strings.Contains(query, "resolve_current_tenant_human_authority_v3"):
				return &dfirRowsStub{rows: permissions}, nil
			case strings.Contains(query, "resolve_current_tenant_operator_teams"):
				return &dfirRowsStub{}, nil
			case strings.Contains(query, "resolve_current_tenant_human_role_grant_paths"):
				return &dfirRowsStub{}, nil
			default:
				return nil, errors.New("unexpected portal authorization rows query")
			}
		},
	}
	if err := validateDFIRPortalAttachmentAccess(context.Background(), tx, actor, tenantID, claimed); err != nil || linkQueries != 1 {
		t.Fatalf("compound portal access = %v, link queries=%d", err, linkQueries)
	}

	permissions = permissions[:1]
	if err := validateDFIRPortalAttachmentAccess(context.Background(), tx, actor, tenantID, claimed); !errors.Is(err, authorization.ErrForbidden) || linkQueries != 1 {
		t.Fatalf("missing root permission = %v, link queries=%d", err, linkQueries)
	}
	permissions = append(permissions, []any{"portal.alert.read", "own", false, pgtype.Timestamptz{}})
	linked = false
	if err := validateDFIRPortalAttachmentAccess(context.Background(), tx, actor, tenantID, claimed); !errors.Is(err, authorization.ErrForbidden) || linkQueries != 2 {
		t.Fatalf("archived link = %v, link queries=%d", err, linkQueries)
	}
	linked = true
	customerVisible = false
	if err := validateDFIRPortalAttachmentAccess(context.Background(), tx, actor, tenantID, claimed); !errors.Is(err, authorization.ErrForbidden) || linkQueries != 3 {
		t.Fatalf("non-live customer ticket = %v, link queries=%d", err, linkQueries)
	}
}

func TestDFIRPortalAttachmentQueriesFilterBeforeBoundedStablePagination(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		kind application.PortalTicketKind
		want []string
	}{
		{kind: application.PortalTicketAlert, want: []string{"attachment.alert_id = $2", "link.alert_id = $2", "resource.archived_at IS NULL"}},
		{kind: application.PortalTicketCase, want: []string{"attachment.case_id = $2", "evidence.case_id = $2", "task.case_id = $2", "public.dfir_attachment_case_links", "link.attachment_id = attachment.id", "link.case_id = $2", "resource.id = link.ioc_id AND resource.archived_at IS NULL", "resource.id = link.asset_id AND resource.archived_at IS NULL"}},
	} {
		statement, err := portalAttachmentListStatement(test.kind)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range append(test.want,
			"attachment.visibility = 'public'", "attachment.scan_state = 'available'", "storage.state = attachment.scan_state",
			"storage.bucket = $5", "storage.object_key = $1::text || '/' || storage.id::text",
			"storage.original_filename = attachment.original_filename", "storage.created_by_membership_id = attachment.uploaded_by_membership_id",
			"storage.created_at = attachment.uploaded_at", "(attachment.uploaded_at, attachment.id) <",
			"ORDER BY attachment.uploaded_at DESC, attachment.id DESC", "LIMIT $6",
		) {
			if !strings.Contains(statement, fragment) {
				t.Fatalf("%s portal attachment query omits %q", test.kind, fragment)
			}
		}
		if test.kind == application.PortalTicketCase && strings.Contains(statement, "public.alert_case_links") {
			t.Fatal("Case portal attachment query must require the explicit attachment copy link")
		}
		visibility := strings.Index(statement, "attachment.visibility = 'public'")
		cursor := strings.Index(statement, "(attachment.uploaded_at, attachment.id) <")
		if visibility < 0 || cursor < 0 || visibility > cursor {
			t.Fatalf("%s query paginates before visibility filtering", test.kind)
		}
	}
	if _, err := portalAttachmentListStatement("future"); !errors.Is(err, application.ErrRepositoryForbidden) {
		t.Fatalf("unknown root query error = %v", err)
	}
}

func TestDFIRPortalAttachmentRepositoryInputRejectsCrossTenantUnboundedAndMalformedCursor(t *testing.T) {
	t.Parallel()
	tenantID := portalTestUUID(21)
	root := application.PortalAttachmentRoot{Kind: application.PortalTicketCase, ID: entityID(portalTestUUID(22))}
	actor := application.Actor{
		TenantID: tenantID, ActiveTenantID: tenantID, UserID: portalTestUUID(23), MembershipID: portalTestUUID(24),
		SessionID: portalTestUUID(25), AuthenticationMethod: "password", Kind: application.PrincipalCustomer,
	}
	claimed := application.PortalAttachmentAuthorization{TenantID: tenantID, Root: root, ContactID: portalTestUUID(26), TicketVersion: 1}
	query := application.PortalAttachmentListQuery{Root: root, Authorization: claimed, Bucket: "periapsis-evidence", Limit: 101}
	if !validDFIRPortalAttachmentQuery(actor, tenantID, query) {
		t.Fatal("maximum bounded portal query was rejected")
	}
	query.Limit = 102
	if validDFIRPortalAttachmentQuery(actor, tenantID, query) {
		t.Fatal("unbounded portal query was accepted")
	}
	query.Limit = 10
	actor.TenantID = portalTestUUID(27)
	if validDFIRPortalAttachmentQuery(actor, tenantID, query) {
		t.Fatal("cross-tenant portal query was accepted")
	}
	actor.TenantID = tenantID
	query.After = &application.PortalAttachmentPosition{UploadedAt: time.Time{}, ID: entityID(portalTestUUID(28))}
	if validDFIRPortalAttachmentQuery(actor, tenantID, query) {
		t.Fatal("malformed portal cursor position was accepted")
	}
}

func portalTestUUID(seed byte) uuid.UUID {
	return uuid.UUID{0x01, 0x9d, 0x03, 0, 0, seed, 0x70, seed, 0x80, seed, 0, 0, 0, 0, 0, seed}
}

func portalPGUUID(value uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: [16]byte(value), Valid: true}
}
