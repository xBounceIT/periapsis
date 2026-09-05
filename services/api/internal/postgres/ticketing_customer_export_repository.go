package postgres

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

const maximumCustomerPortalExportRows = 201

// ExportPortal executes one operation-shaped SELECT. The exact linked contact,
// active membership, current customer-visible state, and public-only comment
// predicate are evaluated together under tenant RLS. Private comments are
// removed inside the bounded subquery, before ordering, limiting or aggregation.
func (repository *TicketingRepository) ExportPortal(
	ctx context.Context,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	resourceID uuid.UUID,
	access application.LiveAccess,
	limit int,
) (application.CustomerPortalExport, error) {
	if access.Authority.Principal() != kernel.PrincipalCustomer || access.CustomerContactID == nil ||
		!slices.Contains(access.Scopes, application.ScopeOwn) ||
		limit < 1 || limit > maximumCustomerPortalExportRows {
		return application.CustomerPortalExport{}, application.ErrForbidden
	}
	query, err := customerPortalExportQuery(kind)
	if err != nil {
		return application.CustomerPortalExport{}, err
	}
	actorID := uuid.UUID(access.Authority.Actor().Bytes())
	contactID := uuid.UUID(access.CustomerContactID.Bytes())
	return withinTicketReadTransaction(ctx, repository, actorID, tenantID,
		func(tx databaseTransaction) (application.CustomerPortalExport, error) {
			return scanCustomerPortalExport(
				tx.QueryRow(ctx, query, kind.String(), resourceID, contactID, limit),
				tenantID, kind, resourceID,
			)
		},
	)
}

func customerPortalExportQuery(kind kernel.AggregateKind) (string, error) {
	switch kind {
	case kernel.AggregateAlert, kernel.AggregateCase:
		return `
SELECT result_reference, result_title, result_summary, result_description,
       result_state, result_severity, result_priority, result_category,
       result_occurred_at, result_updated_at, result_version,
       result_public_comments
FROM app.get_customer_portal_ticket_export_v2(
  $1::public.ticket_aggregate_kind,$2,$3,$4
)`, nil
	default:
		return "", application.ErrInvalidInput
	}
}

type storedCustomerPortalExportComment struct {
	ID           uuid.UUID `json:"id"`
	Visibility   string    `json:"visibility"`
	BodyMarkdown string    `json:"bodyMarkdown"`
	Author       string    `json:"author"`
	Audience     string    `json:"audience"`
	CreatedAt    time.Time `json:"createdAt"`
}

func scanCustomerPortalExport(
	row ticketRecordScanner,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	resourceID uuid.UUID,
) (application.CustomerPortalExport, error) {
	var result application.CustomerPortalExport
	var version int32
	var commentsJSON []byte
	if err := row.Scan(
		&result.Reference, &result.Title, &result.Summary, &result.Description,
		&result.State, &result.Severity, &result.Priority, &result.Category,
		&result.OccurredAt, &result.UpdatedAt, &version, &commentsJSON,
	); err != nil {
		return application.CustomerPortalExport{}, mapTicketDatabaseError(err)
	}
	if version < 1 || len(commentsJSON) == 0 || len(commentsJSON) > 16*1024*1024 {
		return application.CustomerPortalExport{}, application.ErrUnavailable
	}
	var stored []storedCustomerPortalExportComment
	if err := decodeStrictTicketCommentJSON(commentsJSON, &stored); err != nil || stored == nil {
		return application.CustomerPortalExport{}, application.ErrUnavailable
	}
	result.TenantID, result.ResourceID, result.Kind = tenantID, resourceID, kind
	result.Version = uint64(version)
	result.OccurredAt, result.UpdatedAt = ticketTime(result.OccurredAt), ticketTime(result.UpdatedAt)
	result.Comments = make([]application.CustomerPortalExportComment, len(stored))
	for index, comment := range stored {
		if comment.Visibility != "public" ||
			(comment.Audience != "operator" && comment.Audience != "customer") ||
			strings.TrimSpace(comment.Author) == "" {
			return application.CustomerPortalExport{}, application.ErrUnavailable
		}
		result.Comments[index] = application.CustomerPortalExportComment{
			ID: comment.ID, Visibility: kernel.CommentPublic,
			BodyMarkdown: comment.BodyMarkdown, Author: comment.Author,
			Audience: comment.Audience, CreatedAt: ticketTime(comment.CreatedAt),
		}
	}
	return result, nil
}

// customerPortalExportProjection returns only the SELECT list. Static security
// tests use it to ensure future query edits cannot smuggle operator fields into
// the customer export while hiding them elsewhere in the statement.
func customerPortalExportProjection(query string) string {
	parts := strings.SplitN(query, "FROM app.", 2)
	return parts[0]
}
