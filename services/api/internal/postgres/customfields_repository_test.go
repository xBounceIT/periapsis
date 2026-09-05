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

	kernel "github.com/periapsis-im/periapsis/modules/customfields"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/customfields"
)

func TestCustomDefinitionCursorRoundTripAndCanonicalValidation(t *testing.T) {
	t.Parallel()
	id := uuid.MustParse("00000000-0000-7000-8000-000000000123")
	encoded := encodeCustomDefinitionCursor("incident.category", id)
	key, decodedID, err := decodeCustomDefinitionCursor(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if key.String() != "incident.category" || decodedID != id {
		t.Fatalf("decoded cursor = (%q, %s)", key.String(), decodedID)
	}
	for _, malformed := range []string{encoded + "=", strings.ToUpper(encoded), "AQBh", "not+base64url"} {
		if _, _, err := decodeCustomDefinitionCursor(malformed); err == nil {
			t.Fatalf("malformed cursor %q was accepted", malformed)
		}
	}
}

func TestCustomAccessRequiresExactLiveMembershipRouteIntentAndScope(t *testing.T) {
	t.Parallel()
	tenantID := uuid.MustParse("00000000-0000-7000-8000-000000000201")
	userID := uuid.MustParse("00000000-0000-7000-8000-000000000202")
	membershipID := uuid.MustParse("00000000-0000-7000-8000-000000000203")
	actor := application.Actor{
		TenantID: tenantID, UserID: userID, MembershipID: membershipID,
		Kind: application.PrincipalHuman,
	}
	authority := authorization.TenantAuthority{
		TenantID:     tenantID,
		Principal:    authorization.TenantPrincipal{ID: userID, Kind: authorization.PrincipalKindHuman},
		MembershipID: membershipID, MembershipStatus: authorization.MembershipStatusActive,
		// Compatibility metadata cannot turn this explicit operator route into a
		// customer projection.
		LegacyRole: authorization.LegacyMembershipRoleReadOnly,
		Permissions: []authorization.ScopedPermission{{
			Permission: authorization.TenantPermissionCustomFieldManage,
			Scope:      authorization.ScopeTenant,
		}},
		EvaluatedAt: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC),
	}
	access, err := customAccess(authority, actor, application.CapabilityManage)
	if err != nil {
		t.Fatal(err)
	}
	if !access.Manage || access.Write || access.Audience != kernel.AudienceOperator || access.Scope != application.ScopeTenant {
		t.Fatalf("unexpected access: %#v", access)
	}
	authority.LegacyRole = authorization.LegacyMembershipRoleAnalyst
	authority.Permissions = []authorization.ScopedPermission{{
		Permission: authorization.TenantPermissionCustomFieldRead,
		Scope:      authorization.ScopeTenant,
	}}
	actor.Kind = application.PrincipalCustomer
	access, err = customAccess(authority, actor, application.CapabilityRead)
	if err != nil || access.Audience != kernel.AudienceCustomer || access.Manage {
		t.Fatalf("explicit customer route access = %#v, %v", access, err)
	}
	actor.Kind = application.PrincipalHuman
	authority.Permissions = []authorization.ScopedPermission{{
		Permission: authorization.TenantPermissionCustomFieldManage,
		Scope:      authorization.ScopeTenant,
	}}
	authority.MembershipID = uuid.MustParse("00000000-0000-7000-8000-000000000204")
	if _, err := customAccess(authority, actor, application.CapabilityManage); err == nil {
		t.Fatal("mismatched live membership was accepted")
	}
}

func TestCustomDefinitionInventoryAccessRequiresReadAndOnlyEnrichesFromSameManageSnapshot(t *testing.T) {
	t.Parallel()
	tenantID := uuid.MustParse("00000000-0000-7000-8000-000000000211")
	userID := uuid.MustParse("00000000-0000-7000-8000-000000000212")
	membershipID := uuid.MustParse("00000000-0000-7000-8000-000000000213")
	actor := application.Actor{
		TenantID: tenantID, UserID: userID, MembershipID: membershipID,
		Kind: application.PrincipalHuman,
	}
	authority := authorization.TenantAuthority{
		TenantID:     tenantID,
		Principal:    authorization.TenantPrincipal{ID: userID, Kind: authorization.PrincipalKindHuman},
		MembershipID: membershipID, MembershipStatus: authorization.MembershipStatusActive,
		Permissions: []authorization.ScopedPermission{
			{Permission: authorization.TenantPermissionCustomFieldRead, Scope: authorization.ScopeTenant},
			{Permission: authorization.TenantPermissionCustomFieldManage, Scope: authorization.ScopeTenant},
		},
		EvaluatedAt: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC),
	}
	ordinary, err := customAccess(authority, actor, application.CapabilityRead)
	if err != nil || ordinary.DefinitionInventory || ordinary.Manage {
		t.Fatalf("ordinary object read was changed by manage permission: (%#v, %v)", ordinary, err)
	}
	access, err := customDefinitionInventoryAccess(authority, actor)
	if err != nil || !access.DefinitionInventory || !access.Manage || access.Audience != kernel.AudienceOperator || access.Scope != application.ScopeTenant {
		t.Fatalf("read+manage definition inventory = (%#v, %v)", access, err)
	}

	authority.Permissions = authority.Permissions[:1]
	access, err = customDefinitionInventoryAccess(authority, actor)
	if err != nil || !access.DefinitionInventory || access.Manage || access.Audience != kernel.AudienceOperator {
		t.Fatalf("read-only definition inventory = (%#v, %v)", access, err)
	}

	authority.Permissions = []authorization.ScopedPermission{{
		Permission: authorization.TenantPermissionCustomFieldManage,
		Scope:      authorization.ScopeTenant,
	}}
	if _, err = customDefinitionInventoryAccess(authority, actor); !errors.Is(err, authorization.ErrForbidden) {
		t.Fatalf("manage-only definition inventory error = %v, want forbidden", err)
	}
}

func TestResolveCustomDefinitionInventoryAccessUsesOneLiveAuthoritySnapshot(t *testing.T) {
	t.Parallel()
	tenantID := uuid.MustParse("00000000-0000-7000-8000-000000000221")
	userID := uuid.MustParse("00000000-0000-7000-8000-000000000222")
	membershipID := uuid.MustParse("00000000-0000-7000-8000-000000000223")
	actor := application.Actor{
		TenantID: tenantID, ActiveTenantID: tenantID, UserID: userID,
		MembershipID: membershipID, SessionID: uuid.MustParse("00000000-0000-7000-8000-000000000224"),
		AuthenticationMethod: "oidc", Kind: application.PrincipalHuman,
	}
	permissions := [][]any{
		{"custom_field.read", "tenant", false, pgtype.Timestamptz{}},
		{"custom_field.manage", "tenant", false, pgtype.Timestamptz{}},
	}
	snapshots := 0
	tx := &dfirTransactionStub{
		row: func(query string, arguments []any, destinations []any) error {
			switch {
			case strings.Contains(query, "set_config('app.tenant_id'"):
				*(destinations[0].(*string)) = tenantID.String()
				*(destinations[1].(*string)) = userID.String()
				return nil
			case strings.Contains(query, "get_current_tenant_authorization_context"):
				snapshots++
				*(destinations[0].(*pgtype.UUID)) = portalPGUUID(tenantID)
				*(destinations[1].(*pgtype.UUID)) = portalPGUUID(membershipID)
				*(destinations[2].(*int64)) = 5
				*(destinations[3].(*string)) = "active"
				*(destinations[4].(*string)) = "tenant_admin"
				*(destinations[5].(*pgtype.Timestamptz)) = pgtype.Timestamptz{
					Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true,
				}
				return nil
			default:
				return errors.New("unexpected definition inventory authority row query")
			}
		},
		query: func(query string, _ []any) (pgx.Rows, error) {
			switch {
			case strings.Contains(query, "resolve_current_tenant_human_authority_v3"):
				return &dfirRowsStub{rows: permissions}, nil
			case strings.Contains(query, "resolve_current_tenant_operator_teams"),
				strings.Contains(query, "resolve_current_tenant_human_role_grant_paths"):
				return &dfirRowsStub{}, nil
			default:
				return nil, errors.New("unexpected definition inventory authority rows query")
			}
		},
	}
	access, err := resolveCustomDefinitionInventoryAccessInTransaction(context.Background(), tx, actor, tenantID)
	if err != nil || snapshots != 1 || !access.DefinitionInventory || !access.Manage {
		t.Fatalf("compound inventory access = (%#v, %v), snapshots=%d", access, err, snapshots)
	}
}

func TestAuthorizationMappingAcceptsEveryPhase4Permission(t *testing.T) {
	t.Parallel()
	values := []authorization.TenantPermission{
		authorization.TenantPermissionCustomFieldRead,
		authorization.TenantPermissionCustomFieldManage,
		authorization.TenantPermissionDFIRIOCRead,
		authorization.TenantPermissionDFIRIOCManage,
		authorization.TenantPermissionDFIRAssetRead,
		authorization.TenantPermissionDFIRAssetManage,
		authorization.TenantPermissionDFIREvidenceRead,
		authorization.TenantPermissionDFIREvidenceManage,
		authorization.TenantPermissionDFIRTimelineRead,
		authorization.TenantPermissionDFIRTimelineManage,
		authorization.TenantPermissionDFIRTaskRead,
		authorization.TenantPermissionDFIRTaskManage,
		authorization.TenantPermissionDFIRAttachmentRead,
		authorization.TenantPermissionDFIRAttachmentManage,
		authorization.TenantPermissionDFIRRelationshipRead,
		authorization.TenantPermissionDFIRRelationshipManage,
	}
	for _, value := range values {
		mapped, err := domainTenantPermission(string(value))
		if err != nil || mapped != value {
			t.Fatalf("domainTenantPermission(%q) = %q, %v", value, mapped, err)
		}
	}
}
