package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	applicationticketing "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func TestAlertMetadataTransportBindsExactReplacementAndStableReplay(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	alertID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	requestID := mustTransportUUIDv7(t)
	updatedAt := time.Date(2026, time.August, 31, 10, 30, 0, 123000000, time.UTC)
	var captured applicationticketing.MetadataReplaceInput
	stub := &transportTicketingStub{replaceMetadataFn: func(
		ctx context.Context,
		actor applicationticketing.Actor,
		requestedTenant uuid.UUID,
		kind kernel.AggregateKind,
		requestedTicket uuid.UUID,
		input applicationticketing.MetadataReplaceInput,
	) (applicationticketing.MetadataMutationResult, error) {
		if ctx.Err() != nil || requestedTenant != tenantID || requestedTicket != alertID ||
			kind != kernel.AggregateAlert || actor.UserID != userID || actor.Audit.RequestID != requestID {
			t.Fatalf("unexpected metadata target, actor, or context")
		}
		captured = input
		return applicationticketing.MetadataMutationResult{
			Metadata: applicationticketing.TicketMetadata{
				TenantID: tenantID, TicketID: alertID, Kind: kind,
				EditableMetadata: input.EditableMetadata, Version: 8, UpdatedAt: updatedAt,
			},
			Replayed: true,
		}, nil
	}}
	router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
	request := ticketingMutationRequest(
		http.MethodPut,
		"/api/v1/tenants/"+tenantID.String()+"/alerts/"+alertID.String()+"/metadata",
		`{"title":"Investigate endpoint","description":"Bounded description","severity":"critical","priority":"urgent","category":"malware","classification":null,"customerVisible":false,"tags":["zeta","alpha"]}`,
	)
	request.Header.Set(ifMatchHeader, `"v7"`)
	request.Header.Set(idempotencyKeyHeader, "alert-metadata-key-0001")
	request.Header.Set(requestIDHeader, requestID.String())
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if response.Header().Get("ETag") != `"v8"` || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("headers = %#v", response.Header())
	}
	if captured.ExpectedVersion != 7 || captured.IdempotencyKey != "alert-metadata-key-0001" ||
		captured.Title != "Investigate endpoint" || captured.Description != "Bounded description" ||
		captured.Severity != "critical" || captured.Priority != "urgent" || captured.Category != "malware" ||
		captured.Classification != nil || captured.CustomerVisible ||
		len(captured.Tags) != 2 || captured.Tags[0] != "alpha" || captured.Tags[1] != "zeta" {
		t.Fatalf("captured input = %+v", captured)
	}
	var result contract.AlertMetadata
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.Id != alertID || result.Version != 8 || !result.UpdatedAt.Equal(updatedAt) ||
		result.Classification != nil || len(result.Tags) != 2 || result.Tags[0] != "alpha" {
		t.Fatalf("response = %+v", result)
	}
}

func TestCaseMetadataTransportBindsSummaryAndClassification(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	caseID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	classification := "restricted"
	updatedAt := time.Date(2026, time.August, 31, 11, 0, 0, 0, time.UTC)
	stub := &transportTicketingStub{replaceMetadataFn: func(
		_ context.Context,
		_ applicationticketing.Actor,
		_ uuid.UUID,
		kind kernel.AggregateKind,
		_ uuid.UUID,
		input applicationticketing.MetadataReplaceInput,
	) (applicationticketing.MetadataMutationResult, error) {
		if kind != kernel.AggregateCase || input.Summary != "Confirmed\r\ncampaign" ||
			input.Description != "First line\n\tSecond line\rThird line" ||
			input.Classification == nil || *input.Classification != classification {
			t.Fatalf("case input = %+v", input)
		}
		return applicationticketing.MetadataMutationResult{Metadata: applicationticketing.TicketMetadata{
			TenantID: tenantID, TicketID: caseID, Kind: kind,
			EditableMetadata: input.EditableMetadata, Version: 4, UpdatedAt: updatedAt,
		}}, nil
	}}
	router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
	request := ticketingMutationRequest(
		http.MethodPut,
		"/api/v1/tenants/"+tenantID.String()+"/cases/"+caseID.String()+"/metadata",
		`{"title":"Campaign","description":"First line\n\tSecond line\rThird line","summary":"Confirmed\r\ncampaign","severity":"high","priority":"high","category":"intrusion","classification":"restricted","customerVisible":true,"tags":[]}`,
	)
	request.Header.Set(ifMatchHeader, `"v3"`)
	request.Header.Set(idempotencyKeyHeader, "case-metadata-key-0001")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if response.Header().Get("ETag") != `"v4"` || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("headers = %#v", response.Header())
	}
	var result contract.CaseMetadata
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result.Id != caseID || result.Summary != "Confirmed\r\ncampaign" ||
		result.Classification == nil || *result.Classification != classification {
		t.Fatalf("response = %+v", result)
	}
}

func TestMetadataTransportRejectsNonExactOrAmbiguousBodiesBeforeUseCase(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	alertID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	valid := `{"title":"Alert","description":"Description","severity":"high","priority":"high","category":"security","classification":null,"customerVisible":false,"tags":[]}`
	tests := []struct {
		name string
		body string
	}{
		{name: "missing nullable classification", body: strings.Replace(valid, `,"classification":null`, "", 1)},
		{name: "missing false customer visibility", body: strings.Replace(valid, `,"customerVisible":false`, "", 1)},
		{name: "missing empty tags", body: strings.Replace(valid, `,"tags":[]`, "", 1)},
		{name: "null description", body: strings.Replace(valid, `"description":"Description"`, `"description":null`, 1)},
		{name: "description vertical tab", body: strings.Replace(valid, `"description":"Description"`, `"description":"first\u000bsecond"`, 1)},
		{name: "deep composite title", body: strings.Replace(
			valid, `"title":"Alert"`,
			`"title":`+strings.Repeat("[", 10_000)+`"Alert"`+strings.Repeat("]", 10_000), 1,
		)},
		{name: "unknown field", body: strings.TrimSuffix(valid, "}") + `,"workflowId":"` + mustTransportUUIDv7(t).String() + `"}`},
		{name: "duplicate field", body: strings.Replace(valid, `"title":"Alert"`, `"title":"Alert","title":"Other"`, 1)},
		{name: "classification object", body: strings.Replace(valid, `"classification":null`, `"classification":{"value":"restricted"}`, 1)},
		{name: "duplicate tag", body: strings.Replace(valid, `"tags":[]`, `"tags":["same","same"]`, 1)},
		{name: "invalid severity", body: strings.Replace(valid, `"severity":"high"`, `"severity":"future"`, 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stub := &transportTicketingStub{}
			router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
			request := ticketingMutationRequest(
				http.MethodPut,
				"/api/v1/tenants/"+tenantID.String()+"/alerts/"+alertID.String()+"/metadata",
				test.body,
			)
			request.Header.Set(ifMatchHeader, `"v1"`)
			request.Header.Set(idempotencyKeyHeader, "alert-metadata-key-0002")
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			assertProblem(t, response, http.StatusBadRequest, "invalid_request")
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
			}
			if stub.metadataCalls != 0 {
				t.Fatalf("metadata calls = %d, want 0", stub.metadataCalls)
			}
		})
	}
}

func TestMetadataTransportRequiresStrongPreconditionAndMapsStaleCAS(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	alertID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	body := `{"title":"Alert","description":"Description","severity":"high","priority":"high","category":"security","classification":null,"customerVisible":false,"tags":[]}`

	t.Run("missing If-Match", func(t *testing.T) {
		stub := &transportTicketingStub{}
		router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
		request := ticketingMutationRequest(http.MethodPut, "/api/v1/tenants/"+tenantID.String()+"/alerts/"+alertID.String()+"/metadata", body)
		request.Header.Set(idempotencyKeyHeader, "alert-metadata-key-0003")
		response := httptest.NewRecorder()

		router.ServeHTTP(response, request)

		assertProblem(t, response, http.StatusPreconditionRequired, "precondition_required")
		if response.Header().Get("Cache-Control") != "no-store" || stub.metadataCalls != 0 {
			t.Fatalf("headers/calls = %#v / %d", response.Header(), stub.metadataCalls)
		}
	})

	t.Run("terminal current version", func(t *testing.T) {
		stub := &transportTicketingStub{}
		router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
		request := ticketingMutationRequest(http.MethodPut, "/api/v1/tenants/"+tenantID.String()+"/alerts/"+alertID.String()+"/metadata", body)
		request.Header.Set(ifMatchHeader, `"v2147483647"`)
		request.Header.Set(idempotencyKeyHeader, "alert-metadata-key-0006")
		response := httptest.NewRecorder()

		router.ServeHTTP(response, request)

		assertProblem(t, response, http.StatusBadRequest, "invalid_request")
		if response.Header().Get("Cache-Control") != "no-store" || stub.metadataCalls != 0 {
			t.Fatalf("headers/calls = %#v / %d", response.Header(), stub.metadataCalls)
		}
	})

	t.Run("maximum incrementable current version", func(t *testing.T) {
		stub := &transportTicketingStub{replaceMetadataFn: func(
			_ context.Context,
			_ applicationticketing.Actor,
			_ uuid.UUID,
			kind kernel.AggregateKind,
			_ uuid.UUID,
			input applicationticketing.MetadataReplaceInput,
		) (applicationticketing.MetadataMutationResult, error) {
			return applicationticketing.MetadataMutationResult{Metadata: applicationticketing.TicketMetadata{
				TenantID: tenantID, TicketID: alertID, Kind: kind,
				EditableMetadata: input.EditableMetadata, Version: 2_147_483_647,
				UpdatedAt: time.Date(2026, time.August, 31, 12, 30, 0, 0, time.UTC),
			}}, nil
		}}
		router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
		request := ticketingMutationRequest(http.MethodPut, "/api/v1/tenants/"+tenantID.String()+"/alerts/"+alertID.String()+"/metadata", body)
		request.Header.Set(ifMatchHeader, `"v2147483646"`)
		request.Header.Set(idempotencyKeyHeader, "alert-metadata-key-0007")
		response := httptest.NewRecorder()

		router.ServeHTTP(response, request)

		if response.Code != http.StatusOK || response.Header().Get("ETag") != `"v2147483647"` || stub.metadataCalls != 1 {
			t.Fatalf("status/etag/calls = %d / %q / %d, body = %s", response.Code, response.Header().Get("ETag"), stub.metadataCalls, response.Body.String())
		}
	})

	t.Run("stale current version", func(t *testing.T) {
		stub := &transportTicketingStub{replaceMetadataFn: func(
			context.Context,
			applicationticketing.Actor,
			uuid.UUID,
			kernel.AggregateKind,
			uuid.UUID,
			applicationticketing.MetadataReplaceInput,
		) (applicationticketing.MetadataMutationResult, error) {
			return applicationticketing.MetadataMutationResult{}, applicationticketing.ErrPreconditionFailed
		}}
		router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
		request := ticketingMutationRequest(http.MethodPut, "/api/v1/tenants/"+tenantID.String()+"/alerts/"+alertID.String()+"/metadata", body)
		request.Header.Set(ifMatchHeader, `"v1"`)
		request.Header.Set(idempotencyKeyHeader, "alert-metadata-key-0004")
		response := httptest.NewRecorder()

		router.ServeHTTP(response, request)

		assertProblem(t, response, http.StatusPreconditionFailed, "precondition_failed")
		if response.Header().Get("Cache-Control") != "no-store" || stub.metadataCalls != 1 {
			t.Fatalf("headers/calls = %#v / %d", response.Header(), stub.metadataCalls)
		}
	})
}

func TestMetadataTransportRejectsDriftedServiceResult(t *testing.T) {
	tenantID := mustTransportUUIDv7(t)
	otherTenantID := mustTransportUUIDv7(t)
	alertID := mustTransportUUIDv7(t)
	userID := mustTransportUUIDv7(t)
	stub := &transportTicketingStub{replaceMetadataFn: func(
		_ context.Context,
		_ applicationticketing.Actor,
		_ uuid.UUID,
		kind kernel.AggregateKind,
		_ uuid.UUID,
		input applicationticketing.MetadataReplaceInput,
	) (applicationticketing.MetadataMutationResult, error) {
		return applicationticketing.MetadataMutationResult{Metadata: applicationticketing.TicketMetadata{
			TenantID: otherTenantID, TicketID: alertID, Kind: kind,
			EditableMetadata: input.EditableMetadata, Version: 2,
			UpdatedAt: time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC),
		}}, nil
	}}
	router := newTicketingTestRouter(t, tenantLDAPTransportAuthentication(tenantID, userID), stub)
	request := ticketingMutationRequest(
		http.MethodPut,
		"/api/v1/tenants/"+tenantID.String()+"/alerts/"+alertID.String()+"/metadata",
		`{"title":"Alert","description":"Description","severity":"high","priority":"high","category":"security","classification":null,"customerVisible":false,"tags":[]}`,
	)
	request.Header.Set(ifMatchHeader, `"v1"`)
	request.Header.Set(idempotencyKeyHeader, "alert-metadata-key-0005")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
	}
}
