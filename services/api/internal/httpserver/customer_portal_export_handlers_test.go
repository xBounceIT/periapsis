package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func TestCustomerPortalExportRoutesReachTheTicketingBoundary(t *testing.T) {
	tenantID, resourceID, userID := mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	now := time.Date(2026, 8, 25, 9, 0, 0, 0, time.UTC)
	tests := []struct {
		kind     kernel.AggregateKind
		pathKind string
		filename string
	}{
		{kind: kernel.AggregateAlert, pathKind: "alerts", filename: "periapsis-customer-alert.csv"},
		{kind: kernel.AggregateCase, pathKind: "cases", filename: "periapsis-customer-case.csv"},
	}
	for _, test := range tests {
		t.Run(string(test.kind), func(t *testing.T) {
			stub := &transportTicketingStub{exportFn: func(
				_ context.Context,
				actor application.Actor,
				requestedTenant uuid.UUID,
				kind kernel.AggregateKind,
				requestedResource uuid.UUID,
			) (application.CustomerPortalExport, error) {
				if actor.UserID != userID || requestedTenant != tenantID ||
					kind != test.kind || requestedResource != resourceID {
					t.Fatalf("export target/actor = %+v %s/%s/%s", actor, requestedTenant, kind, requestedResource)
				}
				return application.CustomerPortalExport{
					TenantID: requestedTenant, ResourceID: requestedResource, Kind: kind,
					Reference: "TKT-42", Title: "Customer-safe incident", State: "investigating",
					Severity: "high", Priority: "urgent", Category: "endpoint",
					OccurredAt: now, UpdatedAt: now, Version: 1,
				}, nil
			}}
			router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
			request := httptest.NewRequest(
				http.MethodGet,
				"/api/v1/tenants/"+tenantID.String()+"/portal/"+test.pathKind+"/"+resourceID.String()+"/export",
				nil,
			)
			prepareTenantLDAPTransportRequest(request, false)
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			if response.Code != http.StatusOK || stub.exportCalls != 1 {
				t.Fatalf("status=%d calls=%d body=%q", response.Code, stub.exportCalls, response.Body.String())
			}
			if got := response.Header().Get("Content-Disposition"); got != `attachment; filename="`+test.filename+`"` {
				t.Fatalf("Content-Disposition = %q", got)
			}
			if !strings.Contains(response.Body.String(), "Customer-safe incident") {
				t.Fatalf("CSV body = %q", response.Body.String())
			}
		})
	}
}

func TestCustomerPortalExportRouteKeepsAuthenticationFailureNoStore(t *testing.T) {
	tenantID, alertID, userID := mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	stub := &transportTicketingStub{}
	router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/tenants/"+tenantID.String()+"/portal/alerts/"+alertID.String()+"/export",
		nil,
	)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusUnauthorized, "authentication_failed")
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if stub.exportCalls != 0 {
		t.Fatalf("export calls = %d, want 0", stub.exportCalls)
	}
}

func TestCustomerPortalExportTransportWritesSafeAttachment(t *testing.T) {
	tenantID, alertID, commentID := mustTransportUUIDv7(t), mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	now := time.Date(2026, 8, 25, 9, 0, 0, 0, time.UTC)
	response := httptest.NewRecorder()
	projection := application.CustomerPortalExport{
		TenantID: tenantID, ResourceID: alertID, Kind: kernel.AggregateAlert, Reference: "ALT-42",
		Title: "=FORMULA()", Description: "Public description", State: "investigating",
		Severity: "high", Priority: "urgent", Category: "endpoint",
		OccurredAt: now, UpdatedAt: now, Version: 1,
		Comments: []application.CustomerPortalExportComment{{
			ID: commentID, Visibility: kernel.CommentPublic, BodyMarkdown: "Public update",
			Author: "Incident team", Audience: "operator", CreatedAt: now,
		}},
	}
	if err := writeCustomerPortalExport(response, kernel.AggregateAlert, projection); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	for header, want := range map[string]string{
		"Cache-Control":          "no-store",
		"Content-Disposition":    `attachment; filename="periapsis-customer-alert.csv"`,
		"Content-Type":           "text/csv; charset=utf-8",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := response.Header().Get(header); got != want {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}
	if !strings.Contains(response.Body.String(), "'=FORMULA()") || strings.Contains(response.Body.String(), "private") {
		t.Fatalf("unsafe customer export body: %q", response.Body.String())
	}
}

func TestCustomerPortalExportTransportRejectsKindMismatchBeforeResponse(t *testing.T) {
	tenantID, resourceID := mustTransportUUIDv7(t), mustTransportUUIDv7(t)
	now := time.Date(2026, 8, 25, 9, 0, 0, 0, time.UTC)
	response := httptest.NewRecorder()
	projection := application.CustomerPortalExport{
		TenantID: tenantID, ResourceID: resourceID, Kind: kernel.AggregateAlert,
		Reference: "ALT-42", Title: "Customer-safe incident", State: "investigating",
		Severity: "high", Priority: "urgent", Category: "endpoint",
		OccurredAt: now, UpdatedAt: now, Version: 1,
	}

	err := writeCustomerPortalExport(response, kernel.AggregateCase, projection)

	if !errors.Is(err, application.ErrUnavailable) {
		t.Fatalf("error = %v, want unavailable", err)
	}
	if response.Code != http.StatusOK || response.Body.Len() != 0 || response.Header().Get("Content-Disposition") != "" {
		t.Fatalf("response started before validation: status=%d headers=%#v body=%q", response.Code, response.Header(), response.Body.String())
	}
}

func TestCustomerPortalExportTransportMapsLimitWithoutStartingResponse(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/example/portal/cases/example/export", nil)
	response := httptest.NewRecorder()

	writeCustomerPortalExportError(response, request, application.ErrExportLimit)

	assertProblem(t, response, http.StatusRequestEntityTooLarge, "export_too_large")
	if response.Header().Get("Content-Disposition") != "" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("error response leaked attachment headers: %#v", response.Header())
	}
}

func TestCustomerPortalExportTransportKeepsEveryErrorNoStore(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/example/portal/alerts/example/export", nil)
	response := httptest.NewRecorder()

	writeCustomerPortalExportError(response, request, application.ErrForbidden)

	assertProblem(t, response, http.StatusForbidden, "forbidden")
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}
