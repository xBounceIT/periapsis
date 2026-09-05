package ticketing

import (
	"bytes"
	"context"
	"encoding/csv"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

const (
	maximumCustomerPortalExportComments = 200
	maximumCustomerPortalExportBytes    = 2 * 1024 * 1024
)

// CustomerPortalExport is an operation-shaped projection. It intentionally
// omits tenant/contact identities, workflow topology, assignments, raw payload,
// operator custom fields, HTML, attachments, mentions, and private comments.
type CustomerPortalExport struct {
	TenantID    uuid.UUID
	ResourceID  uuid.UUID
	Kind        kernel.AggregateKind
	Reference   string
	Title       string
	Summary     string
	Description string
	State       string
	Severity    string
	Priority    string
	Category    string
	OccurredAt  time.Time
	UpdatedAt   time.Time
	Version     uint64
	Comments    []CustomerPortalExportComment
}

type CustomerPortalExportComment struct {
	ID           uuid.UUID
	Visibility   kernel.CommentVisibility
	BodyMarkdown string
	Author       string
	Audience     string
	CreatedAt    time.Time
}

// ExportPortal requires both the kind-specific ticket read permission and the
// public-comment permission. Both are resolved live before the repository runs
// its exact contact-link, customer-state and public-comment allowlist query.
func (service *Service) ExportPortal(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	resourceID uuid.UUID,
) (CustomerPortalExport, error) {
	access, err := service.access(ctx, actor, tenantID, portalExportCapability(kind))
	if err != nil {
		return CustomerPortalExport{}, err
	}
	if access.Authority.Principal() != kernel.PrincipalCustomer || access.CustomerContactID == nil ||
		!slices.Contains(access.Scopes, ScopeOwn) {
		return CustomerPortalExport{}, ErrForbidden
	}
	if _, err := entityID(resourceID); err != nil {
		return CustomerPortalExport{}, ErrInvalidInput
	}

	result, err := service.repository.ExportPortal(
		ctx, tenantID, kind, resourceID, access, maximumCustomerPortalExportComments+1,
	)
	if err != nil {
		return CustomerPortalExport{}, repositoryError(err)
	}
	if len(result.Comments) > maximumCustomerPortalExportComments {
		return CustomerPortalExport{}, ErrExportLimit
	}
	if !validCustomerPortalExport(result, tenantID, kind, resourceID) {
		return CustomerPortalExport{}, ErrUnavailable
	}
	result.Comments = append([]CustomerPortalExportComment(nil), result.Comments...)
	return result, nil
}

func validCustomerPortalExport(
	value CustomerPortalExport,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	resourceID uuid.UUID,
) bool {
	if value.TenantID != tenantID || value.ResourceID != resourceID || value.Kind != kind ||
		(kind != kernel.AggregateAlert && kind != kernel.AggregateCase) ||
		!validText(value.Reference, 64, true) || !validText(value.Title, 240, true) ||
		!validText(value.Summary, 2_000, false) ||
		!validText(value.Description, descriptionLimit(kind), false) ||
		!validText(value.State, 80, true) ||
		!validEnum(value.Severity, "informational", "low", "medium", "high", "critical") ||
		!validEnum(value.Priority, "low", "medium", "high", "urgent", "critical") ||
		!validText(value.Category, 120, true) || !validStoredInstant(value.OccurredAt) ||
		!validStoredInstant(value.UpdatedAt) || value.UpdatedAt.Before(value.OccurredAt) ||
		value.Version == 0 || value.Version > maxResourceVersion ||
		len(value.Comments) > maximumCustomerPortalExportComments {
		return false
	}
	if _, err := kernel.NewKey(value.State); err != nil {
		return false
	}
	seen := make(map[uuid.UUID]struct{}, len(value.Comments))
	for index, comment := range value.Comments {
		if _, err := entityID(comment.ID); err != nil ||
			comment.Visibility != kernel.CommentPublic ||
			!validCommentMarkdownSource(comment.BodyMarkdown) ||
			!validText(comment.Author, 200, true) ||
			!validEnum(comment.Audience, "operator", "customer") ||
			!validStoredInstant(comment.CreatedAt) {
			return false
		}
		if _, duplicate := seen[comment.ID]; duplicate {
			return false
		}
		seen[comment.ID] = struct{}{}
		if index > 0 {
			previous := value.Comments[index-1]
			if comment.CreatedAt.Before(previous.CreatedAt) ||
				comment.CreatedAt.Equal(previous.CreatedAt) && strings.Compare(comment.ID.String(), previous.ID.String()) <= 0 {
				return false
			}
		}
	}
	return true
}

// RenderCustomerPortalCSV serializes only the closed customer export shape.
// Every dynamic cell is neutralized before RFC 4180 quoting so spreadsheet
// programs cannot reinterpret customer/operator text as a formula.
func RenderCustomerPortalCSV(value CustomerPortalExport) ([]byte, error) {
	if len(value.Comments) > maximumCustomerPortalExportComments {
		return nil, ErrExportLimit
	}
	if !validCustomerPortalExport(value, value.TenantID, value.Kind, value.ResourceID) {
		return nil, ErrUnavailable
	}
	var output bytes.Buffer
	writer := csv.NewWriter(&output)
	writer.UseCRLF = true
	rows := [][]string{{
		"record_type", "reference", "title", "summary", "description", "status",
		"severity", "priority", "category", "author", "occurred_at", "updated_at",
	}, {
		"ticket", value.Reference, value.Title, value.Summary, value.Description, value.State,
		value.Severity, value.Priority, value.Category, "", exportInstant(value.OccurredAt), exportInstant(value.UpdatedAt),
	}}
	for _, comment := range value.Comments {
		rows = append(rows, []string{
			"comment", value.Reference, "", "", comment.BodyMarkdown, "", "", "", "",
			comment.Author, exportInstant(comment.CreatedAt), "",
		})
	}
	for _, row := range rows {
		for index := range row {
			row[index] = neutralizeSpreadsheetCell(row[index])
		}
		if err := writer.Write(row); err != nil {
			return nil, ErrUnavailable
		}
	}
	writer.Flush()
	if writer.Error() != nil {
		return nil, ErrUnavailable
	}
	if output.Len() > maximumCustomerPortalExportBytes {
		return nil, ErrExportLimit
	}
	return output.Bytes(), nil
}

func neutralizeSpreadsheetCell(value string) string {
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			continue
		}
		if strings.ContainsRune("=+-@", character) {
			return "'" + value
		}
		return value
	}
	return value
}

func exportInstant(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
