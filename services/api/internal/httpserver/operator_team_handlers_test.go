package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/operatorteam"
)

type operatorTeamHTTPStub struct {
	listTeamsFunc       func(context.Context, authentication.Session, operatorteam.ListOperatorTeamsInput) (operatorteam.OperatorTeamPage, error)
	getTeamFunc         func(context.Context, authentication.Session, uuid.UUID) (operatorteam.OperatorTeam, error)
	createTeamFunc      func(context.Context, authentication.Session, operatorteam.CreateOperatorTeamInput) (operatorteam.OperatorTeam, error)
	patchTeamFunc       func(context.Context, authentication.Session, uuid.UUID, operatorteam.PatchOperatorTeamInput) (operatorteam.OperatorTeam, error)
	archiveTeamFunc     func(context.Context, authentication.Session, uuid.UUID, operatorteam.ArchiveOperatorTeamInput) error
	listAssignmentsFunc func(context.Context, authorization.Actor, uuid.UUID, operatorteam.ListTenantAssignmentsInput) (operatorteam.TenantAssignmentPage, error)
	getAssignmentFunc   func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, uuid.UUID) (operatorteam.TenantAssignment, error)
	startAssignmentFunc func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, operatorteam.StartTenantAssignmentInput) (operatorteam.TenantAssignment, error)
	endAssignmentFunc   func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, uuid.UUID, operatorteam.EndTenantAssignmentInput) error
	listRosterFunc      func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, uuid.UUID, operatorteam.ListRosterEntriesInput) (operatorteam.RosterEntryPage, error)
	addRosterFunc       func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, uuid.UUID, operatorteam.AddRosterEntryInput) (operatorteam.RosterEntry, error)
	revokeRosterFunc    func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, operatorteam.RevokeRosterEntryInput) error
}

func (s *operatorTeamHTTPStub) ListOperatorTeams(
	ctx context.Context,
	session authentication.Session,
	input operatorteam.ListOperatorTeamsInput,
) (operatorteam.OperatorTeamPage, error) {
	if s.listTeamsFunc == nil {
		return operatorteam.OperatorTeamPage{}, operatorteam.ErrUnavailable
	}
	return s.listTeamsFunc(ctx, session, input)
}

func (s *operatorTeamHTTPStub) GetOperatorTeam(
	ctx context.Context,
	session authentication.Session,
	operatorTeamID uuid.UUID,
) (operatorteam.OperatorTeam, error) {
	if s.getTeamFunc == nil {
		return operatorteam.OperatorTeam{}, operatorteam.ErrUnavailable
	}
	return s.getTeamFunc(ctx, session, operatorTeamID)
}

func (s *operatorTeamHTTPStub) CreateOperatorTeam(
	ctx context.Context,
	session authentication.Session,
	input operatorteam.CreateOperatorTeamInput,
) (operatorteam.OperatorTeam, error) {
	if s.createTeamFunc == nil {
		return operatorteam.OperatorTeam{}, operatorteam.ErrUnavailable
	}
	return s.createTeamFunc(ctx, session, input)
}

func (s *operatorTeamHTTPStub) PatchOperatorTeam(
	ctx context.Context,
	session authentication.Session,
	operatorTeamID uuid.UUID,
	input operatorteam.PatchOperatorTeamInput,
) (operatorteam.OperatorTeam, error) {
	if s.patchTeamFunc == nil {
		return operatorteam.OperatorTeam{}, operatorteam.ErrUnavailable
	}
	return s.patchTeamFunc(ctx, session, operatorTeamID, input)
}

func (s *operatorTeamHTTPStub) ArchiveOperatorTeam(
	ctx context.Context,
	session authentication.Session,
	operatorTeamID uuid.UUID,
	input operatorteam.ArchiveOperatorTeamInput,
) error {
	if s.archiveTeamFunc == nil {
		return operatorteam.ErrUnavailable
	}
	return s.archiveTeamFunc(ctx, session, operatorTeamID, input)
}

func (s *operatorTeamHTTPStub) ListTenantAssignments(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input operatorteam.ListTenantAssignmentsInput,
) (operatorteam.TenantAssignmentPage, error) {
	if s.listAssignmentsFunc == nil {
		return operatorteam.TenantAssignmentPage{}, operatorteam.ErrUnavailable
	}
	return s.listAssignmentsFunc(ctx, actor, tenantID, input)
}

func (s *operatorTeamHTTPStub) GetTenantAssignment(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, operatorTeamID, epochID uuid.UUID,
) (operatorteam.TenantAssignment, error) {
	if s.getAssignmentFunc == nil {
		return operatorteam.TenantAssignment{}, operatorteam.ErrUnavailable
	}
	return s.getAssignmentFunc(ctx, actor, tenantID, operatorTeamID, epochID)
}

func (s *operatorTeamHTTPStub) StartTenantAssignment(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, operatorTeamID uuid.UUID,
	input operatorteam.StartTenantAssignmentInput,
) (operatorteam.TenantAssignment, error) {
	if s.startAssignmentFunc == nil {
		return operatorteam.TenantAssignment{}, operatorteam.ErrUnavailable
	}
	return s.startAssignmentFunc(ctx, actor, tenantID, operatorTeamID, input)
}

func (s *operatorTeamHTTPStub) EndTenantAssignment(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, operatorTeamID, epochID uuid.UUID,
	input operatorteam.EndTenantAssignmentInput,
) error {
	if s.endAssignmentFunc == nil {
		return operatorteam.ErrUnavailable
	}
	return s.endAssignmentFunc(ctx, actor, tenantID, operatorTeamID, epochID, input)
}

func (s *operatorTeamHTTPStub) ListRosterEntries(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, operatorTeamID, epochID uuid.UUID,
	input operatorteam.ListRosterEntriesInput,
) (operatorteam.RosterEntryPage, error) {
	if s.listRosterFunc == nil {
		return operatorteam.RosterEntryPage{}, operatorteam.ErrUnavailable
	}
	return s.listRosterFunc(ctx, actor, tenantID, operatorTeamID, epochID, input)
}

func (s *operatorTeamHTTPStub) AddRosterEntry(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, operatorTeamID, epochID uuid.UUID,
	input operatorteam.AddRosterEntryInput,
) (operatorteam.RosterEntry, error) {
	if s.addRosterFunc == nil {
		return operatorteam.RosterEntry{}, operatorteam.ErrUnavailable
	}
	return s.addRosterFunc(ctx, actor, tenantID, operatorTeamID, epochID, input)
}

func (s *operatorTeamHTTPStub) RevokeRosterEntry(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, operatorTeamID, epochID, rosterEntryID uuid.UUID,
	input operatorteam.RevokeRosterEntryInput,
) error {
	if s.revokeRosterFunc == nil {
		return operatorteam.ErrUnavailable
	}
	return s.revokeRosterFunc(ctx, actor, tenantID, operatorTeamID, epochID, rosterEntryID, input)
}

func TestCreatePlatformOperatorTeamReturnsCurrentReplayAndStrongETag(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	requestID := uuid.Must(uuid.NewV7())
	team := operatorTeamHTTPFixture(operatorteam.OperatorTeamStateArchived)
	var captured operatorteam.CreateOperatorTeamInput
	service := &operatorTeamHTTPStub{createTeamFunc: func(
		_ context.Context,
		session authentication.Session,
		input operatorteam.CreateOperatorTeamInput,
	) (operatorteam.OperatorTeam, error) {
		if session.User.ID != userID {
			t.Fatalf("session user = %s", session.User.ID)
		}
		captured = input
		return team, nil
	}}
	request := operatorTeamMutationRequest(
		http.MethodPost, "/api/v1/platform/operator-teams",
		`{"key":"incident_response","name":"Incident response","description":"Global IR"}`,
	)
	request.Header.Set(idempotencyKeyHeader, "operator-team-create-0001")
	request.Header.Set(requestIDHeader, requestID.String())
	response := httptest.NewRecorder()

	newOperatorTeamTestRouter(t, groupTransportAuthentication(tenantID, userID), service).ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("ETag") != `"v7"` {
		t.Fatalf("ETag = %q", response.Header().Get("ETag"))
	}
	if captured.IdempotencyKey != "operator-team-create-0001" || captured.Key != "incident_response" ||
		captured.Description != "Global IR" || captured.Audit.RequestID != requestID {
		t.Fatalf("captured input = %#v", captured)
	}
	var body contract.OperatorTeam
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Id != team.ID || body.State != contract.OperatorTeamStateArchived || body.ArchivedAt == nil ||
		body.Version != team.Version {
		t.Fatalf("response body = %#v", body)
	}
}

func TestOperatorTeamMutationBodiesAndCSRFRejectBeforeService(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	teamID := uuid.Must(uuid.NewV7())
	for _, test := range []struct {
		name       string
		body       string
		csrf       bool
		wantStatus int
		wantCode   string
	}{
		{name: "unknown field", body: `{"key":"incident_response","name":"IR","unexpected":true}`, csrf: true, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "duplicate field", body: `{"key":"incident_response","key":"other","name":"IR"}`, csrf: true, wantStatus: http.StatusBadRequest, wantCode: "invalid_request"},
		{name: "missing csrf", body: `{"key":"incident_response","name":"IR"}`, wantStatus: http.StatusForbidden, wantCode: "forbidden"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			called := false
			service := &operatorTeamHTTPStub{createTeamFunc: func(
				context.Context,
				authentication.Session,
				operatorteam.CreateOperatorTeamInput,
			) (operatorteam.OperatorTeam, error) {
				called = true
				return operatorTeamHTTPFixture(operatorteam.OperatorTeamStateActive), nil
			}}
			request := operatorTeamMutationRequest(http.MethodPost, "/api/v1/platform/operator-teams", test.body)
			request.Header.Set(idempotencyKeyHeader, "operator-team-create-0001")
			if !test.csrf {
				request.Header.Del(csrfTokenHeader)
			}
			response := httptest.NewRecorder()

			newOperatorTeamTestRouter(t, groupTransportAuthentication(tenantID, userID), service).
				ServeHTTP(response, request)

			assertProblem(t, response, test.wantStatus, test.wantCode)
			if called {
				t.Fatalf("service called for invalid request against %s", teamID)
			}
		})
	}
}

func TestArchiveOperatorTeamForwardsRequiredReasonAndPrecondition(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	teamID := uuid.Must(uuid.NewV7())
	var captured operatorteam.ArchiveOperatorTeamInput
	service := &operatorTeamHTTPStub{archiveTeamFunc: func(
		_ context.Context,
		_ authentication.Session,
		requestedTeamID uuid.UUID,
		input operatorteam.ArchiveOperatorTeamInput,
	) error {
		if requestedTeamID != teamID {
			t.Fatalf("team ID = %s", requestedTeamID)
		}
		captured = input
		return nil
	}}
	request := operatorTeamMutationRequest(
		http.MethodDelete, "/api/v1/platform/operator-teams/"+teamID.String(),
		`{"reason":"Consolidated into the retained team"}`,
	)
	request.Header.Set(ifMatchHeader, `"v3"`)
	response := httptest.NewRecorder()

	newOperatorTeamTestRouter(t, groupTransportAuthentication(tenantID, userID), service).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if captured.Reason != "Consolidated into the retained team" || captured.ExpectedVersion == nil ||
		*captured.ExpectedVersion != 3 {
		t.Fatalf("captured input = %#v", captured)
	}

	missing := operatorTeamMutationRequest(
		http.MethodDelete, "/api/v1/platform/operator-teams/"+teamID.String(), `{"reason":"Archive"}`,
	)
	missingResponse := httptest.NewRecorder()
	newOperatorTeamTestRouter(t, groupTransportAuthentication(tenantID, userID), service).
		ServeHTTP(missingResponse, missing)
	assertProblem(t, missingResponse, http.StatusPreconditionRequired, "precondition_required")
}

func TestOperatorTeamUpdateMapsFailedPrecondition(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	teamID := uuid.Must(uuid.NewV7())
	service := &operatorTeamHTTPStub{patchTeamFunc: func(
		context.Context,
		authentication.Session,
		uuid.UUID,
		operatorteam.PatchOperatorTeamInput,
	) (operatorteam.OperatorTeam, error) {
		return operatorteam.OperatorTeam{}, operatorteam.ErrPreconditionFailed
	}}
	request := operatorTeamMutationRequest(
		http.MethodPatch, "/api/v1/platform/operator-teams/"+teamID.String(), `{"name":"New IR"}`,
	)
	request.Header.Set("Content-Type", "application/merge-patch+json")
	request.Header.Set(ifMatchHeader, `"v2"`)
	response := httptest.NewRecorder()

	newOperatorTeamTestRouter(t, groupTransportAuthentication(tenantID, userID), service).ServeHTTP(response, request)

	assertProblem(t, response, http.StatusPreconditionFailed, "precondition_failed")
}

func TestOperatorTeamTenantRoutesEnforceSelectedTenantBeforeService(t *testing.T) {
	t.Parallel()

	selectedTenantID := uuid.Must(uuid.NewV7())
	requestedTenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	called := false
	service := &operatorTeamHTTPStub{listAssignmentsFunc: func(
		context.Context,
		authorization.Actor,
		uuid.UUID,
		operatorteam.ListTenantAssignmentsInput,
	) (operatorteam.TenantAssignmentPage, error) {
		called = true
		return operatorteam.TenantAssignmentPage{}, nil
	}}
	request := httptest.NewRequest(
		http.MethodGet, "/api/v1/tenants/"+requestedTenantID.String()+"/operator-teams", nil,
	)
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	response := httptest.NewRecorder()

	newOperatorTeamTestRouter(t, groupTransportAuthentication(selectedTenantID, userID), service).
		ServeHTTP(response, request)

	assertProblem(t, response, http.StatusForbidden, "forbidden")
	if called {
		t.Fatal("service called for a tenant other than the selected tenant")
	}
}

func TestOperatorTeamTenantRoutesRejectNonV7TenantBeforeService(t *testing.T) {
	t.Parallel()

	selectedTenantID := uuid.Must(uuid.NewV7())
	requestedTenantID := uuid.New()
	userID := uuid.Must(uuid.NewV7())
	called := false
	service := &operatorTeamHTTPStub{listAssignmentsFunc: func(
		context.Context,
		authorization.Actor,
		uuid.UUID,
		operatorteam.ListTenantAssignmentsInput,
	) (operatorteam.TenantAssignmentPage, error) {
		called = true
		return operatorteam.TenantAssignmentPage{}, nil
	}}
	request := httptest.NewRequest(
		http.MethodGet, "/api/v1/tenants/"+requestedTenantID.String()+"/operator-teams", nil,
	)
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	response := httptest.NewRecorder()

	newOperatorTeamTestRouter(t, groupTransportAuthentication(selectedTenantID, userID), service).
		ServeHTTP(response, request)

	assertProblem(t, response, http.StatusBadRequest, "invalid_request")
	if called {
		t.Fatal("service called for a non-v7 tenant path")
	}
}

func TestOperatorTeamReadAndStartRoutesForwardContractParameters(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	teamID := uuid.Must(uuid.NewV7())
	epochID := uuid.Must(uuid.NewV7())
	after := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	team := operatorTeamHTTPFixture(operatorteam.OperatorTeamStateActive)
	team.ID = teamID
	assignment := operatorTeamAssignmentHTTPFixture(tenantID, teamID, epochID, userID)
	endedAt := assignment.StartedAt.Add(time.Hour)
	endReason := "Coverage completed"
	assignment.State = operatorteam.AssignmentStateEnded
	assignment.EndedAt = &endedAt
	assignment.EndedByUserID = &userID
	assignment.EndReason = &endReason
	assignment.UpdatedAt = endedAt
	listTeamCalls := 0
	getTeamCalls := 0
	listAssignmentCalls := 0
	startAssignmentCalls := 0
	getAssignmentCalls := 0
	service := &operatorTeamHTTPStub{
		listTeamsFunc: func(
			_ context.Context,
			_ authentication.Session,
			input operatorteam.ListOperatorTeamsInput,
		) (operatorteam.OperatorTeamPage, error) {
			listTeamCalls++
			if input.After == nil || *input.After != after || input.Limit != 25 || !input.IncludeArchived {
				t.Fatalf("platform list input = %#v", input)
			}
			return operatorteam.OperatorTeamPage{}, nil
		},
		getTeamFunc: func(
			_ context.Context,
			_ authentication.Session,
			requestedTeamID uuid.UUID,
		) (operatorteam.OperatorTeam, error) {
			getTeamCalls++
			if requestedTeamID != teamID {
				t.Fatalf("platform get team ID = %s", requestedTeamID)
			}
			return team, nil
		},
		listAssignmentsFunc: func(
			_ context.Context,
			_ authorization.Actor,
			requestedTenantID uuid.UUID,
			input operatorteam.ListTenantAssignmentsInput,
		) (operatorteam.TenantAssignmentPage, error) {
			listAssignmentCalls++
			if requestedTenantID != tenantID || input.After == nil || *input.After != after ||
				input.Limit != 25 || !input.IncludeEnded {
				t.Fatalf("tenant list input = %s %#v", requestedTenantID, input)
			}
			return operatorteam.TenantAssignmentPage{}, nil
		},
		startAssignmentFunc: func(
			_ context.Context,
			_ authorization.Actor,
			requestedTenantID, requestedTeamID uuid.UUID,
			input operatorteam.StartTenantAssignmentInput,
		) (operatorteam.TenantAssignment, error) {
			startAssignmentCalls++
			if requestedTenantID != tenantID || requestedTeamID != teamID || input.Reason != "Emergency coverage" ||
				input.IdempotencyKey != "operator-team-epoch-0001" {
				t.Fatalf("start path/input = %s/%s %#v", requestedTenantID, requestedTeamID, input)
			}
			return assignment, nil
		},
		getAssignmentFunc: func(
			_ context.Context,
			_ authorization.Actor,
			requestedTenantID, requestedTeamID, requestedEpochID uuid.UUID,
		) (operatorteam.TenantAssignment, error) {
			getAssignmentCalls++
			if requestedTenantID != tenantID || requestedTeamID != teamID || requestedEpochID != epochID {
				t.Fatalf("get path = %s/%s/%s", requestedTenantID, requestedTeamID, requestedEpochID)
			}
			return assignment, nil
		},
	}
	router := newOperatorTeamTestRouter(t, groupTransportAuthentication(tenantID, userID), service)

	for _, path := range []string{
		"/api/v1/platform/operator-teams?after=" + after.String() + "&limit=25&includeArchived=true",
		"/api/v1/tenants/" + tenantID.String() + "/operator-teams?after=" + after.String() + "&limit=25&includeEnded=true",
	} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d: %s", path, response.Code, response.Body.String())
		}
	}

	getTeamRequest := httptest.NewRequest(
		http.MethodGet, "/api/v1/platform/operator-teams/"+teamID.String(), nil,
	)
	getTeamRequest.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	getTeamResponse := httptest.NewRecorder()
	router.ServeHTTP(getTeamResponse, getTeamRequest)
	if getTeamResponse.Code != http.StatusOK || getTeamResponse.Header().Get("ETag") != `"v7"` {
		t.Fatalf("get team response = %d/%q: %s", getTeamResponse.Code, getTeamResponse.Header().Get("ETag"), getTeamResponse.Body.String())
	}

	assignmentBase := "/api/v1/tenants/" + tenantID.String() + "/operator-teams/" + teamID.String() +
		"/assignment-epochs"
	startRequest := operatorTeamMutationRequest(http.MethodPost, assignmentBase, `{"reason":"Emergency coverage"}`)
	startRequest.Header.Set(idempotencyKeyHeader, "operator-team-epoch-0001")
	startResponse := httptest.NewRecorder()
	router.ServeHTTP(startResponse, startRequest)
	if startResponse.Code != http.StatusCreated || startResponse.Header().Get("ETag") != `"v5"` {
		t.Fatalf("start response = %d/%q: %s", startResponse.Code, startResponse.Header().Get("ETag"), startResponse.Body.String())
	}
	var started contract.OperatorTeamAssignmentEpoch
	if err := json.NewDecoder(startResponse.Body).Decode(&started); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	if started.State != contract.OperatorTeamAssignmentEpochStateEnded || started.EndedAt == nil {
		t.Fatalf("start replay did not preserve current ended state: %#v", started)
	}

	getAssignmentRequest := httptest.NewRequest(http.MethodGet, assignmentBase+"/"+epochID.String(), nil)
	getAssignmentRequest.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	getAssignmentResponse := httptest.NewRecorder()
	router.ServeHTTP(getAssignmentResponse, getAssignmentRequest)
	if getAssignmentResponse.Code != http.StatusOK || getAssignmentResponse.Header().Get("ETag") != `"v5"` {
		t.Fatalf("get assignment response = %d/%q: %s", getAssignmentResponse.Code, getAssignmentResponse.Header().Get("ETag"), getAssignmentResponse.Body.String())
	}

	if listTeamCalls != 1 || getTeamCalls != 1 || listAssignmentCalls != 1 ||
		startAssignmentCalls != 1 || getAssignmentCalls != 1 {
		t.Fatalf(
			"handler calls = listTeam:%d getTeam:%d listAssignment:%d startAssignment:%d getAssignment:%d",
			listTeamCalls, getTeamCalls, listAssignmentCalls, startAssignmentCalls, getAssignmentCalls,
		)
	}
}

func TestAddAndListOperatorTeamRosterPreserveExactEpochAndEntityTag(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	teamID := uuid.Must(uuid.NewV7())
	epochID := uuid.Must(uuid.NewV7())
	membershipID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	entry := operatorTeamRosterHTTPFixture(tenantID, teamID, epochID, membershipID, userID)
	expiresAt := time.Date(2090, time.January, 2, 3, 4, 5, 123456000, time.UTC)
	revokedAt := entry.UpdatedAt.Add(time.Hour)
	revokeReason := "Current replay is already revoked"
	entry.Provenance.ExpiresAt = &expiresAt
	entry.State = operatorteam.RosterEntryStateRevoked
	entry.RevokedAt = &revokedAt
	entry.RevokedByUserID = &userID
	entry.RevokeReason = &revokeReason
	entry.Version = 4
	entry.UpdatedAt = revokedAt
	var addInput operatorteam.AddRosterEntryInput
	listCalls := 0
	service := &operatorTeamHTTPStub{
		addRosterFunc: func(
			_ context.Context,
			actor authorization.Actor,
			requestedTenantID, requestedTeamID, requestedEpochID uuid.UUID,
			input operatorteam.AddRosterEntryInput,
		) (operatorteam.RosterEntry, error) {
			if actor.UserID != userID || requestedTenantID != tenantID || requestedTeamID != teamID || requestedEpochID != epochID {
				t.Fatalf("actor/path = %#v/%s/%s/%s", actor, requestedTenantID, requestedTeamID, requestedEpochID)
			}
			addInput = input
			return entry, nil
		},
		listRosterFunc: func(
			_ context.Context,
			_ authorization.Actor,
			requestedTenantID, requestedTeamID, requestedEpochID uuid.UUID,
			input operatorteam.ListRosterEntriesInput,
		) (operatorteam.RosterEntryPage, error) {
			listCalls++
			if requestedTenantID != tenantID || requestedTeamID != teamID || requestedEpochID != epochID ||
				!input.IncludeRevoked {
				t.Fatalf("list path/input = %s/%s/%s %#v", requestedTenantID, requestedTeamID, requestedEpochID, input)
			}
			return operatorteam.RosterEntryPage{Items: []operatorteam.RosterEntry{entry}}, nil
		},
	}
	basePath := "/api/v1/tenants/" + tenantID.String() + "/operator-teams/" + teamID.String() +
		"/assignment-epochs/" + epochID.String() + "/roster"
	request := operatorTeamMutationRequest(
		http.MethodPost, basePath,
		`{"membershipId":"`+membershipID.String()+`","reason":"On-call coverage","expiresAt":"2090-01-02T03:04:05.123456Z"}`,
	)
	request.Header.Set(idempotencyKeyHeader, "operator-team-roster-0001")
	response := httptest.NewRecorder()

	newOperatorTeamTestRouter(t, groupTransportAuthentication(tenantID, userID), service).ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if addInput.MembershipID != membershipID || addInput.IdempotencyKey != "operator-team-roster-0001" ||
		addInput.ExpiresAt == nil || addInput.ExpiresAt.Nanosecond() != 123456000 {
		t.Fatalf("captured add input = %#v", addInput)
	}
	var created contract.OperatorTeamRosterEntry
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.AssignmentEpochId != epochID || created.OperatorTeamId != teamID || created.TenantId != tenantID ||
		created.Member.MembershipId != membershipID || !created.ManagedByOperatorTeamApi ||
		created.State != contract.AuthorizationEdgeStateRevoked || created.RevokedAt == nil ||
		response.Header().Get("ETag") == "" || response.Header().Get("ETag") != string(created.Etag) {
		t.Fatalf("created response/header = %#v / %q", created, response.Header().Get("ETag"))
	}

	listRequest := httptest.NewRequest(http.MethodGet, basePath+"?includeRevoked=true", nil)
	listRequest.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	listResponse := httptest.NewRecorder()
	newOperatorTeamTestRouter(t, groupTransportAuthentication(tenantID, userID), service).
		ServeHTTP(listResponse, listRequest)
	if listResponse.Code != http.StatusOK || listCalls != 1 {
		t.Fatalf("list status/calls = %d/%d: %s", listResponse.Code, listCalls, listResponse.Body.String())
	}
	var listed contract.OperatorTeamRosterEntryList
	if err := json.NewDecoder(listResponse.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(listed.Items) != 1 || listed.Items[0].Etag != created.Etag {
		t.Fatalf("listed roster = %#v", listed)
	}
}

func TestOperatorTeamRosterHTTPAcceptsGenericDependencyExpiry(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		status authorization.MembershipStatus
	}{
		{name: "ended assignment dependency", status: authorization.MembershipStatusActive},
		{name: "suspended membership dependency", status: authorization.MembershipStatusSuspended},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			tenantID := uuid.Must(uuid.NewV7())
			teamID := uuid.Must(uuid.NewV7())
			epochID := uuid.Must(uuid.NewV7())
			userID := uuid.Must(uuid.NewV7())
			entry := operatorTeamRosterHTTPFixture(
				tenantID, teamID, epochID, uuid.Must(uuid.NewV7()), userID,
			)
			entry.Member.Status = test.status
			entry.State = operatorteam.RosterEntryStateExpired
			service := &operatorTeamHTTPStub{listRosterFunc: func(
				context.Context,
				authorization.Actor,
				uuid.UUID,
				uuid.UUID,
				uuid.UUID,
				operatorteam.ListRosterEntriesInput,
			) (operatorteam.RosterEntryPage, error) {
				return operatorteam.RosterEntryPage{Items: []operatorteam.RosterEntry{entry}}, nil
			}}
			path := "/api/v1/tenants/" + tenantID.String() + "/operator-teams/" + teamID.String() +
				"/assignment-epochs/" + epochID.String() + "/roster"
			request := httptest.NewRequest(http.MethodGet, path, nil)
			request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
			response := httptest.NewRecorder()

			newOperatorTeamTestRouter(t, groupTransportAuthentication(tenantID, userID), service).
				ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", response.Code, response.Body.String())
			}
			var page contract.OperatorTeamRosterEntryList
			if err := json.NewDecoder(response.Body).Decode(&page); err != nil {
				t.Fatalf("decode roster response: %v", err)
			}
			if len(page.Items) != 1 || page.Items[0].State != contract.AuthorizationEdgeStateExpired ||
				page.Items[0].Provenance.ExpiresAt != nil || page.Items[0].Provenance.RetiredAt != nil {
				t.Fatalf("roster response = %#v", page)
			}
		})
	}
}

func TestOperatorTeamRosterHTTPRejectsActiveSuspendedMembership(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	teamID := uuid.Must(uuid.NewV7())
	epochID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	entry := operatorTeamRosterHTTPFixture(
		tenantID, teamID, epochID, uuid.Must(uuid.NewV7()), userID,
	)
	entry.Member.Status = authorization.MembershipStatusSuspended
	service := &operatorTeamHTTPStub{listRosterFunc: func(
		context.Context,
		authorization.Actor,
		uuid.UUID,
		uuid.UUID,
		uuid.UUID,
		operatorteam.ListRosterEntriesInput,
	) (operatorteam.RosterEntryPage, error) {
		return operatorteam.RosterEntryPage{Items: []operatorteam.RosterEntry{entry}}, nil
	}}
	path := "/api/v1/tenants/" + tenantID.String() + "/operator-teams/" + teamID.String() +
		"/assignment-epochs/" + epochID.String() + "/roster"
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	response := httptest.NewRecorder()

	newOperatorTeamTestRouter(t, groupTransportAuthentication(tenantID, userID), service).
		ServeHTTP(response, request)

	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
}

func TestOperatorTeamRosterExpiryLexicalHardeningRunsBeforeService(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	teamID := uuid.Must(uuid.NewV7())
	epochID := uuid.Must(uuid.NewV7())
	membershipID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	for _, expiresAt := range []string{
		"2090-01-02T03:04:60Z",
		"2090-01-02T03:04:05.1234567Z",
		"2090-01-02T03:04:05+24:00",
	} {
		expiresAt := expiresAt
		t.Run(expiresAt, func(t *testing.T) {
			t.Parallel()
			called := false
			service := &operatorTeamHTTPStub{addRosterFunc: func(
				context.Context,
				authorization.Actor,
				uuid.UUID,
				uuid.UUID,
				uuid.UUID,
				operatorteam.AddRosterEntryInput,
			) (operatorteam.RosterEntry, error) {
				called = true
				return operatorteam.RosterEntry{}, nil
			}}
			path := "/api/v1/tenants/" + tenantID.String() + "/operator-teams/" + teamID.String() +
				"/assignment-epochs/" + epochID.String() + "/roster"
			request := operatorTeamMutationRequest(
				http.MethodPost, path,
				`{"membershipId":"`+membershipID.String()+`","reason":"On-call","expiresAt":"`+expiresAt+`"}`,
			)
			request.Header.Set(idempotencyKeyHeader, "operator-team-roster-0001")
			response := httptest.NewRecorder()

			newOperatorTeamTestRouter(t, groupTransportAuthentication(tenantID, userID), service).
				ServeHTTP(response, request)

			assertProblem(t, response, http.StatusBadRequest, "invalid_request")
			if called {
				t.Fatal("service called for an unrepresentable expiry")
			}
		})
	}
}

func TestEndAndRevokeOperatorTeamRoutesForwardEveryNestedID(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	teamID := uuid.Must(uuid.NewV7())
	epochID := uuid.Must(uuid.NewV7())
	rosterEntryID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	entry := operatorTeamRosterHTTPFixture(tenantID, teamID, epochID, uuid.Must(uuid.NewV7()), userID)
	entityTag, err := operatorteam.RosterEntryEntityTag(entry)
	if err != nil {
		t.Fatalf("RosterEntryEntityTag() error = %v", err)
	}
	endCalls := 0
	revokeCalls := 0
	service := &operatorTeamHTTPStub{
		endAssignmentFunc: func(
			_ context.Context,
			_ authorization.Actor,
			requestedTenantID, requestedTeamID, requestedEpochID uuid.UUID,
			input operatorteam.EndTenantAssignmentInput,
		) error {
			endCalls++
			if requestedTenantID != tenantID || requestedTeamID != teamID || requestedEpochID != epochID ||
				input.Reason != "Rotation complete" || input.ExpectedVersion == nil || *input.ExpectedVersion != 4 {
				t.Fatalf("end path/input = %s/%s/%s %#v", requestedTenantID, requestedTeamID, requestedEpochID, input)
			}
			return nil
		},
		revokeRosterFunc: func(
			_ context.Context,
			_ authorization.Actor,
			requestedTenantID, requestedTeamID, requestedEpochID, requestedRosterID uuid.UUID,
			input operatorteam.RevokeRosterEntryInput,
		) error {
			revokeCalls++
			if requestedTenantID != tenantID || requestedTeamID != teamID || requestedEpochID != epochID ||
				requestedRosterID != rosterEntryID || input.Reason != "Shift ended" ||
				input.ExpectedEntityTag == nil || *input.ExpectedEntityTag != entityTag {
				t.Fatalf("revoke path/input = %s/%s/%s/%s %#v", requestedTenantID, requestedTeamID, requestedEpochID, requestedRosterID, input)
			}
			return nil
		},
	}
	basePath := "/api/v1/tenants/" + tenantID.String() + "/operator-teams/" + teamID.String() +
		"/assignment-epochs/" + epochID.String()
	endRequest := operatorTeamMutationRequest(http.MethodPost, basePath+"/end", `{"reason":"Rotation complete"}`)
	endRequest.Header.Set(ifMatchHeader, `"v4"`)
	endResponse := httptest.NewRecorder()
	newOperatorTeamTestRouter(t, groupTransportAuthentication(tenantID, userID), service).
		ServeHTTP(endResponse, endRequest)
	if endResponse.Code != http.StatusNoContent || endCalls != 1 {
		t.Fatalf("end status/calls = %d/%d: %s", endResponse.Code, endCalls, endResponse.Body.String())
	}

	revokeRequest := operatorTeamMutationRequest(
		http.MethodPost, basePath+"/roster/"+rosterEntryID.String()+"/revoke", `{"reason":"Shift ended"}`,
	)
	revokeRequest.Header.Set(ifMatchHeader, entityTag)
	revokeResponse := httptest.NewRecorder()
	newOperatorTeamTestRouter(t, groupTransportAuthentication(tenantID, userID), service).
		ServeHTTP(revokeResponse, revokeRequest)
	if revokeResponse.Code != http.StatusNoContent || revokeCalls != 1 {
		t.Fatalf("revoke status/calls = %d/%d: %s", revokeResponse.Code, revokeCalls, revokeResponse.Body.String())
	}
}

func TestOperatorTeamDomainErrorsUseContractStatusCodes(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		err    error
		status int
		code   string
	}{
		{operatorteam.ErrInvalidInput, http.StatusBadRequest, "invalid_request"},
		{operatorteam.ErrForbidden, http.StatusForbidden, "forbidden"},
		{operatorteam.ErrNotFound, http.StatusNotFound, "not_found"},
		{operatorteam.ErrConflict, http.StatusConflict, "conflict"},
		{operatorteam.ErrPreconditionFailed, http.StatusPreconditionFailed, "precondition_failed"},
		{operatorteam.ErrPreconditionRequired, http.StatusPreconditionRequired, "precondition_required"},
		{operatorteam.ErrUnavailable, http.StatusServiceUnavailable, "service_unavailable"},
		{context.DeadlineExceeded, http.StatusServiceUnavailable, "service_unavailable"},
	} {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request = request.WithContext(context.WithValue(
			request.Context(), requestIDKey{}, uuid.Must(uuid.NewV7()).String(),
		))
		response := httptest.NewRecorder()

		(&Handler{}).writeOperatorTeamError(response, request, test.err)

		assertProblem(t, response, test.status, test.code)
	}
}

func TestOperatorTeamMappingFailsClosedOnDivergentRepositoryProjection(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	teamID := uuid.Must(uuid.NewV7())
	epochID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	entry := operatorTeamRosterHTTPFixture(tenantID, teamID, epochID, uuid.Must(uuid.NewV7()), userID)
	entry.AssignmentEpochID = uuid.Must(uuid.NewV7())
	service := &operatorTeamHTTPStub{listRosterFunc: func(
		context.Context,
		authorization.Actor,
		uuid.UUID,
		uuid.UUID,
		uuid.UUID,
		operatorteam.ListRosterEntriesInput,
	) (operatorteam.RosterEntryPage, error) {
		return operatorteam.RosterEntryPage{Items: []operatorteam.RosterEntry{entry}}, nil
	}}
	path := "/api/v1/tenants/" + tenantID.String() + "/operator-teams/" + teamID.String() +
		"/assignment-epochs/" + epochID.String() + "/roster"
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	response := httptest.NewRecorder()

	newOperatorTeamTestRouter(t, groupTransportAuthentication(tenantID, userID), service).ServeHTTP(response, request)

	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
}

func TestOperatorTeamListFailsClosedOnDivergentNextCursor(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	team := operatorTeamHTTPFixture(operatorteam.OperatorTeamStateActive)
	divergentCursor := uuid.Must(uuid.NewV7())
	service := &operatorTeamHTTPStub{listTeamsFunc: func(
		context.Context,
		authentication.Session,
		operatorteam.ListOperatorTeamsInput,
	) (operatorteam.OperatorTeamPage, error) {
		return operatorteam.OperatorTeamPage{
			Items: []operatorteam.OperatorTeam{team}, NextCursor: &divergentCursor,
		}, nil
	}}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/platform/operator-teams", nil)
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	response := httptest.NewRecorder()

	newOperatorTeamTestRouter(t, groupTransportAuthentication(tenantID, userID), service).ServeHTTP(response, request)

	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
}

func TestValidOperatorTeamPageCursor(t *testing.T) {
	t.Parallel()

	lastItemID := uuid.Must(uuid.NewV7())
	invalidVersion := uuid.New()
	if !validOperatorTeamPageCursor(nil, 0, func() uuid.UUID { return uuid.Nil }) {
		t.Fatal("terminal empty page was rejected")
	}
	if validOperatorTeamPageCursor(&lastItemID, 0, func() uuid.UUID { return lastItemID }) {
		t.Fatal("cursor was accepted for an empty page")
	}
	if validOperatorTeamPageCursor(&invalidVersion, 1, func() uuid.UUID { return invalidVersion }) {
		t.Fatal("non-v7 cursor was accepted")
	}
	if !validOperatorTeamPageCursor(&lastItemID, 1, func() uuid.UUID { return lastItemID }) {
		t.Fatal("last-item cursor was rejected")
	}
}

func newOperatorTeamTestRouter(
	t *testing.T,
	auth AuthenticationService,
	service OperatorTeamService,
) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, logger, "test", time.Second,
		ApplicationOptions{
			Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: auth, Authorization: &transportAuthorizationStub{},
			Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{},
			Environment: "test", IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{}, MFA: &transportMFAStub{}, Notifications: &transportNotificationStub{}, OperatorTeams: service, Platform: &transportPlatformStub{},
			PublicOrigin: "http://localhost:8081", ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{}, Ticketing: &transportTicketingStub{}, WorkflowAdministration: &transportWorkflowAdministrationStub{},
		},
	)
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}

func operatorTeamMutationRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.Header.Set(csrfTokenHeader, "csrf-value")
	return request
}

func operatorTeamHTTPFixture(state operatorteam.OperatorTeamState) operatorteam.OperatorTeam {
	createdAt := time.Date(2026, time.August, 24, 10, 0, 0, 0, time.UTC)
	updatedAt := createdAt.Add(time.Hour)
	userID := uuid.Must(uuid.NewV7())
	value := operatorteam.OperatorTeam{
		OperatorTeamSummary: operatorteam.OperatorTeamSummary{
			ID: uuid.Must(uuid.NewV7()), Key: "incident_response", Name: "Incident response", State: state,
		},
		Description: "Global IR", CreatedByUserID: &userID,
		Version: 7, CreatedAt: createdAt, UpdatedAt: updatedAt,
	}
	if state == operatorteam.OperatorTeamStateArchived {
		reason := "Consolidated"
		value.ArchivedAt = &updatedAt
		value.ArchivedByUserID = &userID
		value.ArchiveReason = &reason
	}
	return value
}

func operatorTeamRosterHTTPFixture(
	tenantID, teamID, epochID, membershipID, userID uuid.UUID,
) operatorteam.RosterEntry {
	grantedAt := time.Date(2026, time.August, 24, 10, 0, 0, 0, time.UTC)
	sourceID := uuid.Must(uuid.NewV7())
	return operatorteam.RosterEntry{
		ID: uuid.Must(uuid.NewV7()), TenantID: tenantID, OperatorTeamID: teamID,
		AssignmentEpochID: epochID,
		Member: operatorteam.TenantMember{
			MembershipID: membershipID, UserID: userID,
			DisplayName: "SOC Analyst", Status: authorization.MembershipStatusActive,
		},
		Provenance: authorization.AuthorizationEdgeProvenance{
			SourceKind: authorization.AuthorizationSourceManual, SourceID: &sourceID,
			GrantedByUserID: &userID, GrantedAt: grantedAt, Reason: "On-call coverage",
		},
		State: operatorteam.RosterEntryStateActive, Version: 3,
		UpdatedAt: grantedAt, ManagedByOperatorTeamAPI: true,
	}
}

func operatorTeamAssignmentHTTPFixture(
	tenantID, teamID, epochID, userID uuid.UUID,
) operatorteam.TenantAssignment {
	startedAt := time.Date(2026, time.August, 24, 10, 0, 0, 0, time.UTC)
	return operatorteam.TenantAssignment{
		EpochID: epochID, TenantID: tenantID,
		OperatorTeam: operatorteam.OperatorTeamSummary{
			ID: teamID, Key: "incident_response", Name: "Incident response",
			State: operatorteam.OperatorTeamStateActive,
		},
		State: operatorteam.AssignmentStateActive, StartedAt: startedAt,
		StartedByUserID: userID, StartReason: "Emergency coverage",
		Version: 5, UpdatedAt: startedAt,
	}
}

var _ OperatorTeamService = (*operatorTeamHTTPStub)(nil)
