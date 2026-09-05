package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	kernel "github.com/periapsis-im/periapsis/modules/contacts"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	application "github.com/periapsis-im/periapsis/services/api/internal/contacts"
)

func TestContactPrincipalKindIsRouteIntentNotLegacyRole(t *testing.T) {
	tenantID := mustPostgresUUIDv7(t)
	userID := mustPostgresUUIDv7(t)
	membershipID := mustPostgresUUIDv7(t)
	authority := authorization.TenantAuthority{
		TenantID: tenantID,
		Principal: authorization.TenantPrincipal{
			ID: userID, Kind: authorization.PrincipalKindHuman,
		},
		MembershipID:     membershipID,
		MembershipStatus: authorization.MembershipStatusActive,
		LegacyRole:       authorization.LegacyMembershipRoleReadOnly,
	}
	actor := application.Actor{
		TenantID: tenantID, ActiveTenantID: tenantID, UserID: userID,
		MembershipID: membershipID, SessionID: mustPostgresUUIDv7(t),
		Kind: application.PrincipalOperator, AuthenticationMethod: "totp",
	}
	if !contactOperatorAuthority(authority, actor) {
		t.Fatal("read_only legacy membership was rejected despite operator route intent")
	}
	authority.LegacyRole = authorization.LegacyMembershipRoleAnalyst
	actor.Kind = application.PrincipalCustomer
	if !contactCustomerAuthority(authority, actor) {
		t.Fatal("custom-role/analyst membership was rejected despite customer route intent")
	}
}

func TestLoadContactLinkForArchiveAuthorizesClaimedTicketBeforeLinkLookup(t *testing.T) {
	tenantID := mustPostgresUUIDv7(t)
	userID := mustPostgresUUIDv7(t)
	membershipID := mustPostgresUUIDv7(t)
	linkID := mustPostgresUUIDv7(t)
	ticketID := mustPostgresUUIDv7(t)
	contactID := mustPostgresUUIDv7(t)
	actor := application.Actor{
		TenantID: tenantID, ActiveTenantID: tenantID, UserID: userID,
		MembershipID: membershipID, SessionID: mustPostgresUUIDv7(t),
		Kind: application.PrincipalOperator, AuthenticationMethod: "totp",
	}
	authority := authorization.TenantAuthority{
		TenantID: tenantID,
		Principal: authorization.TenantPrincipal{
			ID: userID, Kind: authorization.PrincipalKindHuman,
		},
		MembershipID: membershipID, MembershipStatus: authorization.MembershipStatusActive,
		LegacyRole: authorization.LegacyMembershipRoleAnalyst,
		Permissions: []authorization.ScopedPermission{{
			Permission: authorization.TenantPermissionContactRead,
			Scope:      authorization.ScopeTenant,
		}},
	}
	tx := &contactArchiveTransaction{
		linkID: linkID, tenantID: tenantID, ticketID: ticketID,
		contactID: contactID,
	}

	_, err := loadContactLinkForArchive(
		context.Background(), tx, authority, actor, tenantID, linkID,
		kernel.TicketAlert, ticketID,
	)
	if !errors.Is(err, application.ErrRepositoryNotFound) {
		t.Fatalf("loadContactLinkForArchive() error = %v, want not found", err)
	}
	if len(tx.queries) != 1 || !strings.Contains(tx.queries[0], "FROM public.alerts AS ticket") {
		t.Fatalf("unauthorized archive queried link existence before ticket authorization: %#v", tx.queries)
	}
}

func TestLoadContactLinkForArchiveRejectsLinkOutsideClaimedTicket(t *testing.T) {
	tenantID := mustPostgresUUIDv7(t)
	userID := mustPostgresUUIDv7(t)
	membershipID := mustPostgresUUIDv7(t)
	linkID := mustPostgresUUIDv7(t)
	claimedTicketID := mustPostgresUUIDv7(t)
	storedTicketID := mustPostgresUUIDv7(t)
	actor := application.Actor{
		TenantID: tenantID, ActiveTenantID: tenantID, UserID: userID,
		MembershipID: membershipID, SessionID: mustPostgresUUIDv7(t),
		Kind: application.PrincipalOperator, AuthenticationMethod: "totp",
	}
	authority := authorization.TenantAuthority{
		TenantID: tenantID,
		Principal: authorization.TenantPrincipal{
			ID: userID, Kind: authorization.PrincipalKindHuman,
		},
		MembershipID: membershipID, MembershipStatus: authorization.MembershipStatusActive,
		LegacyRole: authorization.LegacyMembershipRoleAnalyst,
		Permissions: []authorization.ScopedPermission{
			{Permission: authorization.TenantPermissionContactRead, Scope: authorization.ScopeTenant},
			{Permission: authorization.TenantPermissionAlertUpdate, Scope: authorization.ScopeTenant},
		},
	}
	tx := &contactArchiveTransaction{
		linkID: linkID, tenantID: tenantID, ticketID: storedTicketID,
		contactID: mustPostgresUUIDv7(t),
	}

	_, err := loadContactLinkForArchive(
		context.Background(), tx, authority, actor, tenantID, linkID,
		kernel.TicketAlert, claimedTicketID,
	)
	if !errors.Is(err, application.ErrRepositoryNotFound) {
		t.Fatalf("loadContactLinkForArchive() error = %v, want not found", err)
	}
	if len(tx.queries) != 2 || !strings.Contains(tx.queries[0], "FROM public.alerts AS ticket") ||
		!strings.Contains(tx.queries[1], "FROM public.ticket_customer_contacts") {
		t.Fatalf("archive authorization/query order drifted: %#v", tx.queries)
	}
}

type contactArchiveTransaction struct {
	recordingTransaction
	queries   []string
	linkID    uuid.UUID
	tenantID  uuid.UUID
	ticketID  uuid.UUID
	contactID uuid.UUID
}

func (tx *contactArchiveTransaction) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	tx.queries = append(tx.queries, query)
	if strings.Contains(query, "FROM public.alerts AS ticket") {
		return contactArchiveRow(func(destinations ...any) error {
			if len(destinations) != 5 {
				return errors.New("unexpected ticket authorization projection")
			}
			return nil
		})
	}
	if strings.Contains(query, "FROM public.ticket_customer_contacts") {
		return contactArchiveRow(func(destinations ...any) error {
			if len(destinations) != 12 {
				return errors.New("unexpected contact link projection")
			}
			*destinations[0].(*uuid.UUID) = tx.linkID
			*destinations[1].(*uuid.UUID) = tx.tenantID
			*destinations[2].(**uuid.UUID) = &tx.ticketID
			*destinations[3].(**uuid.UUID) = nil
			*destinations[4].(*uuid.UUID) = tx.contactID
			*destinations[5].(*string) = "primary"
			*destinations[6].(*string) = "manual"
			*destinations[7].(**uuid.UUID) = nil
			*destinations[8].(**int64) = nil
			*destinations[9].(*int64) = 1
			*destinations[10].(*time.Time) = time.Now().UTC()
			*destinations[11].(**time.Time) = nil
			return nil
		})
	}
	return contactArchiveRow(func(...any) error {
		return errors.New("unexpected contact archive query")
	})
}

type contactArchiveRow func(...any) error

func (row contactArchiveRow) Scan(destinations ...any) error {
	return row(destinations...)
}
