package ticketing

import (
	"context"
	"encoding/csv"
	"errors"
	"strings"
	"testing"
	"time"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

func TestCustomerPortalExportUsesCompoundLiveCapability(t *testing.T) {
	fixture := newServiceFixture(t)
	repository := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalCustomer, scopes: []Scope{ScopeOwn},
		export: validPortalExportFixture(t, fixture),
	}
	service := mustService(t, repository)

	result, err := service.ExportPortal(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert, fixture.ticketUUID,
	)
	if err != nil || result.ResourceID != fixture.ticketUUID || repository.exportCalls.Load() != 1 {
		t.Fatalf("ExportPortal() = (%+v, %v), calls=%d", result, err, repository.exportCalls.Load())
	}
	if len(repository.accessCalls) != 1 || repository.accessCalls[0] != CapabilityPortalAlertExport {
		t.Fatalf("live capability checks = %v", repository.accessCalls)
	}

	repository.accessErrors = map[Capability]error{CapabilityPortalAlertExport: ErrForbidden}
	repository.accessCalls = nil
	repository.exportCalls.Store(0)
	_, err = service.ExportPortal(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert, fixture.ticketUUID,
	)
	if !errors.Is(err, ErrForbidden) || repository.exportCalls.Load() != 0 {
		t.Fatalf("revoked public-comment capability error=%v exports=%d", err, repository.exportCalls.Load())
	}
}

func TestCustomerPortalExportFailsClosedOnRepositoryProjectionDrift(t *testing.T) {
	fixture := newServiceFixture(t)
	valid := validPortalExportFixture(t, fixture)
	tests := []struct {
		name   string
		mutate func(*CustomerPortalExport)
		want   error
	}{
		{
			name: "private comment",
			mutate: func(value *CustomerPortalExport) {
				value.Comments[0].Visibility = kernel.CommentPrivate
			},
			want: ErrUnavailable,
		},
		{
			name: "operator field sized comment corpus",
			mutate: func(value *CustomerPortalExport) {
				comment := value.Comments[0]
				value.Comments = make([]CustomerPortalExportComment, maximumCustomerPortalExportComments+1)
				for index := range value.Comments {
					copy := comment
					copy.ID = mustUUIDv7(t)
					copy.CreatedAt = copy.CreatedAt.Add(time.Duration(index) * time.Microsecond)
					value.Comments[index] = copy
				}
			},
			want: ErrExportLimit,
		},
		{
			name: "wrong tenant",
			mutate: func(value *CustomerPortalExport) {
				value.TenantID = mustUUIDv7(t)
			},
			want: ErrUnavailable,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			projection := valid

			projection.Comments = append([]CustomerPortalExportComment(nil), valid.Comments...)
			test.mutate(&projection)
			repository := &fakeRepository{
				fixture: fixture, principal: kernel.PrincipalCustomer, scopes: []Scope{ScopeOwn}, export: projection,
			}
			service := mustService(t, repository)
			_, err := service.ExportPortal(
				context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert, fixture.ticketUUID,
			)
			if !errors.Is(err, test.want) {
				t.Fatalf("ExportPortal() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestCustomerPortalCSVNeutralizesSpreadsheetFormulas(t *testing.T) {
	tenantID, resourceID, commentID := mustUUIDv7(t), mustUUIDv7(t), mustUUIDv7(t)
	value := CustomerPortalExport{
		TenantID: tenantID, ResourceID: resourceID, Kind: kernel.AggregateAlert,
		Reference: "ALT-42", Title: "=HYPERLINK(\"https://invalid\")",
		Summary: "\u200b@SUM(1,1)", Description: "+cmd|' /C calc'!A0", State: "investigating",
		Severity: "high", Priority: "urgent", Category: "-1", OccurredAt: time.Date(2026, 8, 25, 9, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2026, 8, 25, 9, 30, 0, 0, time.UTC), Version: 1,
		Comments: []CustomerPortalExportComment{{
			ID: commentID, Visibility: kernel.CommentPublic,
			BodyMarkdown: "=WEBSERVICE(\"https://invalid\")", Author: "@operator",
			Audience: "operator", CreatedAt: time.Date(2026, 8, 25, 9, 20, 0, 0, time.UTC),
		}},
	}
	encoded, err := RenderCustomerPortalCSV(value)
	if err != nil {
		t.Fatal(err)
	}
	reader := csv.NewReader(strings.NewReader(string(encoded)))
	rows, err := reader.ReadAll()
	if err != nil || len(rows) != 3 {
		t.Fatalf("CSV rows = %#v, error=%v", rows, err)
	}
	for _, cell := range []string{rows[1][2], rows[1][3], rows[1][4], rows[1][8], rows[2][4], rows[2][9]} {
		if !strings.HasPrefix(cell, "'") {
			t.Fatalf("dangerous spreadsheet cell was not neutralized: %q", cell)
		}
	}
	if strings.Contains(string(encoded), "body_html") || strings.Contains(string(encoded), "private") {
		t.Fatalf("CSV contains a forbidden field: %q", encoded)
	}
}

func TestCustomerPortalCSVRejectsOversizedOutput(t *testing.T) {
	tenantID, resourceID := mustUUIDv7(t), mustUUIDv7(t)
	now := time.Date(2026, 8, 25, 9, 0, 0, 0, time.UTC)
	comments := make([]CustomerPortalExportComment, maximumCustomerPortalExportComments)
	for index := range comments {
		comments[index] = CustomerPortalExportComment{
			ID: mustUUIDv7(t), Visibility: kernel.CommentPublic,
			BodyMarkdown: strings.Repeat("a", maximumCommentCharacters), Author: "Support team",
			Audience: "operator", CreatedAt: now.Add(time.Duration(index) * time.Microsecond),
		}
	}
	_, err := RenderCustomerPortalCSV(CustomerPortalExport{
		TenantID: tenantID, ResourceID: resourceID, Kind: kernel.AggregateAlert,
		Reference: "ALT-42", Title: "Export", State: "new", Severity: "high",
		Priority: "urgent", Category: "general", OccurredAt: now,
		UpdatedAt: now.Add(time.Hour), Version: 1, Comments: comments,
	})
	if !errors.Is(err, ErrExportLimit) {
		t.Fatalf("RenderCustomerPortalCSV() error = %v, want export limit", err)
	}
}

func validPortalExportFixture(t testing.TB, fixture serviceFixture) CustomerPortalExport {
	t.Helper()
	now := fixture.record.DetectedAt
	return CustomerPortalExport{
		TenantID: fixture.tenantUUID, ResourceID: fixture.ticketUUID, Kind: kernel.AggregateAlert,
		Reference: fixture.record.Number, Title: fixture.record.Title, Summary: "", Description: fixture.record.Description,
		State: fixture.record.Snapshot.State().String(), Severity: fixture.record.Severity,
		Priority: fixture.record.Priority, Category: fixture.record.Category,
		OccurredAt: now, UpdatedAt: fixture.record.UpdatedAt, Version: fixture.record.Snapshot.Version(),
		Comments: []CustomerPortalExportComment{{
			ID: mustUUIDv7(t), Visibility: kernel.CommentPublic, BodyMarkdown: "Public update",
			Author: "Incident team", Audience: "operator", CreatedAt: now,
		}},
	}
}
