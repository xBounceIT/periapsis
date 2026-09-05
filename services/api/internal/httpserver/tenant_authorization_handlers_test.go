package httpserver

import (
	"bytes"
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
)

func TestGenericAuthorizationBodyRejectsUnpairedJSONSurrogate(t *testing.T) {
	t.Parallel()

	type input struct {
		Value string `json:"value"`
	}
	for _, test := range []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "valid pair", body: `{"value":"\ud83d\ude00"}`},
		{name: "unpaired high", body: `{"value":"\ud83d"}`, wantErr: true},
		{name: "unpaired low", body: `{"value":"\ude00"}`, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/json")
			var decoded input
			err := decodeAuthorizationBody(request, &decoded, "application/json")
			if (err != nil) != test.wantErr {
				t.Fatalf("decodeAuthorizationBody(%s) error=%v, wantErr=%t", test.body, err, test.wantErr)
			}
			if !test.wantErr && decoded.Value != "😀" {
				t.Fatalf("decoded value=%q, want emoji scalar", decoded.Value)
			}
		})
	}
}

type tenantAuthorizationTransportStub struct {
	getAuthorityFunc          func(context.Context, authorization.Actor, uuid.UUID) (authorization.TenantAuthority, error)
	listPermissionsFunc       func(context.Context, authorization.Actor, uuid.UUID, authorization.PageInput) (authorization.TenantPermissionPage, error)
	listRolesFunc             func(context.Context, authorization.Actor, uuid.UUID, authorization.ListTenantRolesInput) (authorization.TenantRolePage, error)
	changeMembershipFunc      func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, authorization.MembershipStatus, authorization.TenantMembershipLifecycleInput) (authorization.TenantMembershipLifecycleReceipt, error)
	createRoleFunc            func(context.Context, authorization.Actor, uuid.UUID, authorization.CreateTenantRoleInput) (authorization.TenantRole, error)
	updateRoleFunc            func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, authorization.UpdateTenantRoleInput) (authorization.TenantRole, error)
	revokeRoleGrantFunc       func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, authorization.RevokeRoleGrantInput) error
	createGroupFunc           func(context.Context, authorization.Actor, uuid.UUID, authorization.CreateTenantSecurityGroupInput) (authorization.TenantSecurityGroup, error)
	listGroupMembershipsFunc  func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, authorization.ListTenantSecurityGroupEdgesInput) (authorization.TenantSecurityGroupMembershipPage, error)
	addGroupMembershipFunc    func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, authorization.AddTenantSecurityGroupMembershipInput) (authorization.TenantSecurityGroupMembership, error)
	revokeGroupMembershipFunc func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, uuid.UUID, authorization.RevokeTenantSecurityGroupMembershipInput) error
	revokeGroupRoleGrantFunc  func(context.Context, authorization.Actor, uuid.UUID, uuid.UUID, uuid.UUID, authorization.RevokeTenantSecurityGroupRoleGrantInput) error
}

func (s *tenantAuthorizationTransportStub) GetTenantAuthority(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
) (authorization.TenantAuthority, error) {
	if s.getAuthorityFunc == nil {
		return authorization.TenantAuthority{}, authorization.ErrUnavailable
	}
	return s.getAuthorityFunc(ctx, actor, tenantID)
}

func (s *tenantAuthorizationTransportStub) ListTenantPermissions(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input authorization.PageInput,
) (authorization.TenantPermissionPage, error) {
	if s.listPermissionsFunc != nil {
		return s.listPermissionsFunc(ctx, actor, tenantID, input)
	}
	return authorization.TenantPermissionPage{}, authorization.ErrUnavailable
}

func (s *tenantAuthorizationTransportStub) ListTenantRoles(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input authorization.ListTenantRolesInput,
) (authorization.TenantRolePage, error) {
	if s.listRolesFunc != nil {
		return s.listRolesFunc(ctx, actor, tenantID, input)
	}
	return authorization.TenantRolePage{}, authorization.ErrUnavailable
}

func (s *tenantAuthorizationTransportStub) CreateTenantRole(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input authorization.CreateTenantRoleInput,
) (authorization.TenantRole, error) {
	if s.createRoleFunc == nil {
		return authorization.TenantRole{}, authorization.ErrUnavailable
	}
	return s.createRoleFunc(ctx, actor, tenantID, input)
}

func (*tenantAuthorizationTransportStub) GetTenantRole(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
) (authorization.TenantRole, error) {
	return authorization.TenantRole{}, authorization.ErrUnavailable
}

func (s *tenantAuthorizationTransportStub) UpdateTenantRole(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	roleID uuid.UUID,
	input authorization.UpdateTenantRoleInput,
) (authorization.TenantRole, error) {
	if s.updateRoleFunc == nil {
		return authorization.TenantRole{}, authorization.ErrUnavailable
	}
	return s.updateRoleFunc(ctx, actor, tenantID, roleID, input)
}

func (*tenantAuthorizationTransportStub) ArchiveTenantRole(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
	authorization.ArchiveTenantRoleInput,
) error {
	return authorization.ErrUnavailable
}

func (*tenantAuthorizationTransportStub) ReplaceTenantRolePolicy(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
	authorization.ReplaceTenantRolePolicyInput,
) (authorization.TenantRole, error) {
	return authorization.TenantRole{}, authorization.ErrUnavailable
}

func (*tenantAuthorizationTransportStub) ListTenantUsers(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	authorization.PageInput,
) (authorization.TenantUserPage, error) {
	return authorization.TenantUserPage{}, authorization.ErrUnavailable
}

func (s *tenantAuthorizationTransportStub) ChangeTenantMembershipLifecycle(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	userID uuid.UUID,
	target authorization.MembershipStatus,
	input authorization.TenantMembershipLifecycleInput,
) (authorization.TenantMembershipLifecycleReceipt, error) {
	if s.changeMembershipFunc == nil {
		return authorization.TenantMembershipLifecycleReceipt{}, authorization.ErrUnavailable
	}
	return s.changeMembershipFunc(ctx, actor, tenantID, userID, target, input)
}

func (*tenantAuthorizationTransportStub) ListUserRoleGrants(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
	authorization.ListUserRoleGrantsInput,
) (authorization.DirectUserRoleGrantPage, error) {
	return authorization.DirectUserRoleGrantPage{}, authorization.ErrUnavailable
}

func (*tenantAuthorizationTransportStub) GrantUserRole(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
	authorization.GrantUserRoleInput,
) (authorization.DirectUserRoleGrant, error) {
	return authorization.DirectUserRoleGrant{}, authorization.ErrUnavailable
}

func (s *tenantAuthorizationTransportStub) RevokeRoleGrant(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	grantID uuid.UUID,
	input authorization.RevokeRoleGrantInput,
) error {
	if s.revokeRoleGrantFunc != nil {
		return s.revokeRoleGrantFunc(ctx, actor, tenantID, grantID, input)
	}
	return authorization.ErrUnavailable
}

func (*tenantAuthorizationTransportStub) ListTenantSecurityGroups(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	authorization.ListTenantSecurityGroupsInput,
) (authorization.TenantSecurityGroupPage, error) {
	return authorization.TenantSecurityGroupPage{}, authorization.ErrUnavailable
}

func (s *tenantAuthorizationTransportStub) CreateTenantSecurityGroup(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	input authorization.CreateTenantSecurityGroupInput,
) (authorization.TenantSecurityGroup, error) {
	if s.createGroupFunc == nil {
		return authorization.TenantSecurityGroup{}, authorization.ErrUnavailable
	}
	return s.createGroupFunc(ctx, actor, tenantID, input)
}

func (*tenantAuthorizationTransportStub) GetTenantSecurityGroup(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
) (authorization.TenantSecurityGroup, error) {
	return authorization.TenantSecurityGroup{}, authorization.ErrUnavailable
}

func (*tenantAuthorizationTransportStub) UpdateTenantSecurityGroup(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
	authorization.UpdateTenantSecurityGroupInput,
) (authorization.TenantSecurityGroup, error) {
	return authorization.TenantSecurityGroup{}, authorization.ErrUnavailable
}

func (*tenantAuthorizationTransportStub) ArchiveTenantSecurityGroup(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
	authorization.ArchiveTenantSecurityGroupInput,
) error {
	return authorization.ErrUnavailable
}

func (s *tenantAuthorizationTransportStub) ListTenantSecurityGroupMemberships(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	groupID uuid.UUID,
	input authorization.ListTenantSecurityGroupEdgesInput,
) (authorization.TenantSecurityGroupMembershipPage, error) {
	if s.listGroupMembershipsFunc == nil {
		return authorization.TenantSecurityGroupMembershipPage{}, authorization.ErrUnavailable
	}
	return s.listGroupMembershipsFunc(ctx, actor, tenantID, groupID, input)
}

func (s *tenantAuthorizationTransportStub) AddTenantSecurityGroupMembership(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	groupID uuid.UUID,
	input authorization.AddTenantSecurityGroupMembershipInput,
) (authorization.TenantSecurityGroupMembership, error) {
	if s.addGroupMembershipFunc != nil {
		return s.addGroupMembershipFunc(ctx, actor, tenantID, groupID, input)
	}
	return authorization.TenantSecurityGroupMembership{}, authorization.ErrUnavailable
}

func (s *tenantAuthorizationTransportStub) RevokeTenantSecurityGroupMembership(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	groupID uuid.UUID,
	membershipID uuid.UUID,
	input authorization.RevokeTenantSecurityGroupMembershipInput,
) error {
	if s.revokeGroupMembershipFunc == nil {
		return authorization.ErrUnavailable
	}
	return s.revokeGroupMembershipFunc(ctx, actor, tenantID, groupID, membershipID, input)
}

func (*tenantAuthorizationTransportStub) ListTenantSecurityGroupRoleGrants(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
	authorization.ListTenantSecurityGroupEdgesInput,
) (authorization.TenantSecurityGroupRoleGrantPage, error) {
	return authorization.TenantSecurityGroupRoleGrantPage{}, authorization.ErrUnavailable
}

func (*tenantAuthorizationTransportStub) GrantTenantSecurityGroupRole(
	context.Context,
	authorization.Actor,
	uuid.UUID,
	uuid.UUID,
	authorization.GrantTenantSecurityGroupRoleInput,
) (authorization.TenantSecurityGroupRoleGrant, error) {
	return authorization.TenantSecurityGroupRoleGrant{}, authorization.ErrUnavailable
}

func (s *tenantAuthorizationTransportStub) RevokeTenantSecurityGroupRoleGrant(
	ctx context.Context,
	actor authorization.Actor,
	tenantID uuid.UUID,
	groupID uuid.UUID,
	grantID uuid.UUID,
	input authorization.RevokeTenantSecurityGroupRoleGrantInput,
) error {
	if s.revokeGroupRoleGrantFunc != nil {
		return s.revokeGroupRoleGrantFunc(ctx, actor, tenantID, groupID, grantID, input)
	}
	return authorization.ErrUnavailable
}

func TestTenantAuthorityUsesAuthenticatedActiveTenantAndCannotBeCached(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	sessionID := uuid.Must(uuid.NewV7())
	membershipID := uuid.Must(uuid.NewV7())
	operatorTeamID := uuid.Must(uuid.NewV7())
	assignmentEpochID := uuid.Must(uuid.NewV7())
	auth := &transportAuthStub{authenticateResult: authentication.Session{
		ID: sessionID, User: authentication.User{ID: userID},
		ActiveTenantID: &tenantID, AuthenticationMethod: "totp",
	}}
	var captured authorization.Actor
	authorizationService := &tenantAuthorizationTransportStub{
		getAuthorityFunc: func(
			_ context.Context,
			actor authorization.Actor,
			requestedTenantID uuid.UUID,
		) (authorization.TenantAuthority, error) {
			captured = actor
			if requestedTenantID != tenantID {
				t.Fatalf("tenant ID = %s, want %s", requestedTenantID, tenantID)
			}
			return authorization.TenantAuthority{
				TenantID:     tenantID,
				Principal:    authorization.TenantPrincipal{ID: userID, Kind: authorization.PrincipalKindHuman},
				MembershipID: membershipID, MembershipStatus: authorization.MembershipStatusActive,
				LegacyRole: authorization.LegacyMembershipRoleTenantAdmin,
				Permissions: []authorization.ScopedPermission{{
					Permission: authorization.TenantPermissionRoleRead, Scope: authorization.ScopeTenant,
				}},
				OperatorTeamRelationships: []authorization.OperatorTeamRelationship{{
					OperatorTeamID: operatorTeamID, AssignmentEpochID: assignmentEpochID,
				}},
				EvaluatedAt: time.Now().UTC(),
			}, nil
		},
	}
	router := newTenantAuthorizationTestRouter(t, auth, authorizationService)
	request := httptest.NewRequest(
		http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/me/authority", nil,
	)
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
	}
	if captured.UserID != userID || captured.SessionID != sessionID ||
		captured.ActiveTenantID != tenantID || captured.AuthenticationMethod != "totp" {
		t.Fatalf("captured actor = %#v", captured)
	}
	var body struct {
		TenantID                  uuid.UUID                                `json:"tenantId"`
		UserID                    uuid.UUID                                `json:"userId"`
		OperatorTeamRelationships []authorization.OperatorTeamRelationship `json:"operatorTeamRelationships"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.TenantID != tenantID || body.UserID != userID ||
		len(body.OperatorTeamRelationships) != 1 ||
		body.OperatorTeamRelationships[0].OperatorTeamID != operatorTeamID ||
		body.OperatorTeamRelationships[0].AssignmentEpochID != assignmentEpochID {
		t.Fatalf("response identity = %#v", body)
	}
}

func TestCreateTenantRoleValidatesRequestIntegrityAndWritesStrongETag(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	sessionID := uuid.Must(uuid.NewV7())
	roleID := uuid.Must(uuid.NewV7())
	requestID := uuid.Must(uuid.NewV7())
	auth := &transportAuthStub{authenticateResult: authentication.Session{
		ID: sessionID, User: authentication.User{ID: userID},
		ActiveTenantID: &tenantID, AuthenticationMethod: "totp",
	}}
	var captured authorization.CreateTenantRoleInput
	authorizationService := &tenantAuthorizationTransportStub{
		createRoleFunc: func(
			_ context.Context,
			actor authorization.Actor,
			requestedTenantID uuid.UUID,
			input authorization.CreateTenantRoleInput,
		) (authorization.TenantRole, error) {
			if actor.UserID != userID || requestedTenantID != tenantID {
				t.Fatalf("actor/tenant = %#v/%s", actor, requestedTenantID)
			}
			captured = input
			now := time.Now().UTC()
			return authorization.TenantRole{
				TenantRoleSummary: authorization.TenantRoleSummary{
					ID: roleID, TenantID: tenantID, Key: input.Key, Name: input.Name,
					Description: input.Description, Version: 3, CreatedAt: now, UpdatedAt: now,
				},
				Policy: input.Policy,
			}, nil
		},
	}
	router := newTenantAuthorizationTestRouter(t, auth, authorizationService)
	body := `{"key":"triage_lead","name":"Triage lead","description":"Coordinates triage","policy":{"permissions":[{"permissionKey":"role.read","scope":"tenant"}],"delegationCeiling":[]}}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+tenantID.String()+"/roles", strings.NewReader(body))
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.Header.Set(csrfTokenHeader, "csrf-value")
	request.Header.Set(idempotencyKeyHeader, "role-create-0123456789")
	request.Header.Set(requestIDHeader, requestID.String())
	request.RemoteAddr = "198.51.100.31:4312"
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("ETag") != `"v3"` {
		t.Fatalf("ETag = %q, want %q", response.Header().Get("ETag"), `"v3"`)
	}
	if auth.authenticateCalls != 1 || auth.csrfCalls != 1 {
		t.Fatalf("authentication/CSRF calls = %d/%d, want 1/1", auth.authenticateCalls, auth.csrfCalls)
	}
	if captured.IdempotencyKey != "role-create-0123456789" || captured.Audit.RequestID != requestID ||
		captured.Audit.RemoteAddress.String() != "198.51.100.31" {
		t.Fatalf("captured input = %#v", captured)
	}
	if len(captured.Policy.Permissions) != 1 ||
		captured.Policy.Permissions[0].Permission != authorization.TenantPermissionRoleRead ||
		captured.Policy.Permissions[0].Scope != authorization.ScopeTenant {
		t.Fatalf("captured policy = %#v", captured.Policy)
	}
}

func TestTenantRoleMutationRejectsMissingOrWeakPrecondition(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	roleID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	auth := &transportAuthStub{authenticateResult: authentication.Session{
		ID: uuid.Must(uuid.NewV7()), User: authentication.User{ID: userID},
		ActiveTenantID: &tenantID, AuthenticationMethod: "totp",
	}}
	called := 0
	authorizationService := &tenantAuthorizationTransportStub{
		updateRoleFunc: func(
			context.Context,
			authorization.Actor,
			uuid.UUID,
			uuid.UUID,
			authorization.UpdateTenantRoleInput,
		) (authorization.TenantRole, error) {
			called++
			return authorization.TenantRole{}, nil
		},
	}
	router := newTenantAuthorizationTestRouter(t, auth, authorizationService)
	for _, test := range []struct {
		name   string
		etag   string
		status int
		code   string
	}{
		{name: "missing", status: http.StatusPreconditionRequired, code: "precondition_required"},
		{name: "weak", etag: `W/"v1"`, status: http.StatusBadRequest, code: "invalid_request"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(
				http.MethodPatch,
				"/api/v1/tenants/"+tenantID.String()+"/roles/"+roleID.String(),
				strings.NewReader(`{"name":"Updated role"}`),
			)
			request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
			request.Header.Set("Content-Type", "application/merge-patch+json")
			request.Header.Set("Origin", "http://localhost:8081")
			request.Header.Set(csrfTokenHeader, "csrf-value")
			if test.etag != "" {
				request.Header.Set(ifMatchHeader, test.etag)
			}
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			assertProblem(t, response, test.status, test.code)
		})
	}
	if called != 0 {
		t.Fatalf("authorization mutation called %d times", called)
	}
}

func TestTenantRoleMutationRejectsMissingRequiredAndExplicitNullFields(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	roleID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	auth := &transportAuthStub{authenticateResult: authentication.Session{
		ID: uuid.Must(uuid.NewV7()), User: authentication.User{ID: userID},
		ActiveTenantID: &tenantID, AuthenticationMethod: "totp",
	}}
	called := 0
	authorizationService := &tenantAuthorizationTransportStub{
		createRoleFunc: func(
			context.Context,
			authorization.Actor,
			uuid.UUID,
			authorization.CreateTenantRoleInput,
		) (authorization.TenantRole, error) {
			called++
			return authorization.TenantRole{}, nil
		},
		updateRoleFunc: func(
			context.Context,
			authorization.Actor,
			uuid.UUID,
			uuid.UUID,
			authorization.UpdateTenantRoleInput,
		) (authorization.TenantRole, error) {
			called++
			return authorization.TenantRole{}, nil
		},
	}
	router := newTenantAuthorizationTestRouter(t, auth, authorizationService)
	for _, test := range []struct {
		name        string
		method      string
		path        string
		contentType string
		body        string
		idempotent  bool
		versioned   bool
	}{
		{
			name: "create role missing required policy", method: http.MethodPost,
			path:        "/api/v1/tenants/" + tenantID.String() + "/roles",
			contentType: "application/json", idempotent: true,
			body: `{"key":"custom_role","name":"Custom role"}`,
		},
		{
			name: "create role case variant field", method: http.MethodPost,
			path:        "/api/v1/tenants/" + tenantID.String() + "/roles",
			contentType: "application/json", idempotent: true,
			body: `{"key":"custom_role","Name":"Custom role","policy":{"permissions":[],"delegationCeiling":[]}}`,
		},
		{
			name: "create role duplicate field", method: http.MethodPost,
			path:        "/api/v1/tenants/" + tenantID.String() + "/roles",
			contentType: "application/json", idempotent: true,
			body: `{"key":"custom_role","name":"First","name":"Second","policy":{"permissions":[],"delegationCeiling":[]}}`,
		},
		{
			name: "replace policy missing required arrays", method: http.MethodPut,
			path:        "/api/v1/tenants/" + tenantID.String() + "/roles/" + roleID.String() + "/policy",
			contentType: "application/json", versioned: true, body: `{}`,
		},
		{
			name: "replace policy null root", method: http.MethodPut,
			path:        "/api/v1/tenants/" + tenantID.String() + "/roles/" + roleID.String() + "/policy",
			contentType: "application/json", versioned: true, body: `null`,
		},
		{
			name: "merge patch explicit null", method: http.MethodPatch,
			path:        "/api/v1/tenants/" + tenantID.String() + "/roles/" + roleID.String(),
			contentType: "application/merge-patch+json", versioned: true,
			body: `{"name":"Still valid","description":null}`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
			request.Header.Set("Content-Type", test.contentType)
			request.Header.Set("Origin", "http://localhost:8081")
			request.Header.Set(csrfTokenHeader, "csrf-value")
			if test.idempotent {
				request.Header.Set(idempotencyKeyHeader, "role-create-0123456789")
			}
			if test.versioned {
				request.Header.Set(ifMatchHeader, `"v1"`)
			}
			response := httptest.NewRecorder()

			router.ServeHTTP(response, request)

			assertProblem(t, response, http.StatusBadRequest, "invalid_request")
		})
	}
	if called != 0 {
		t.Fatalf("authorization mutation called %d times", called)
	}
}

func TestTenantRoleMutationRejectsInvalidUTF8BeforeJSONDecoding(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	auth := &transportAuthStub{authenticateResult: authentication.Session{
		ID: uuid.Must(uuid.NewV7()), User: authentication.User{ID: userID},
		ActiveTenantID: &tenantID, AuthenticationMethod: "totp",
	}}
	called := 0
	authorizationService := &tenantAuthorizationTransportStub{
		createRoleFunc: func(
			context.Context,
			authorization.Actor,
			uuid.UUID,
			authorization.CreateTenantRoleInput,
		) (authorization.TenantRole, error) {
			called++
			return authorization.TenantRole{}, nil
		},
	}
	body := append([]byte(`{"key":"custom_role","name":"`), byte(0xff))
	body = append(body, []byte(`","policy":{"permissions":[],"delegationCeiling":[]}}`)...)
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/tenants/"+tenantID.String()+"/roles",
		bytes.NewReader(body),
	)
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.Header.Set(csrfTokenHeader, "csrf-value")
	request.Header.Set(idempotencyKeyHeader, "role-create-0123456789")
	response := httptest.NewRecorder()

	newTenantAuthorizationTestRouter(t, auth, authorizationService).ServeHTTP(response, request)

	assertProblem(t, response, http.StatusBadRequest, "invalid_request")
	if called != 0 {
		t.Fatalf("authorization mutation called %d times", called)
	}
}

func TestTenantMembershipSuspendRequiresMatchingRevisionAndReturnsExactReceipt(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	membershipID := uuid.Must(uuid.NewV7())
	requestID := uuid.Must(uuid.NewV7())
	auth := &transportAuthStub{authenticateResult: authentication.Session{
		ID: uuid.Must(uuid.NewV7()), User: authentication.User{ID: uuid.Must(uuid.NewV7())},
		ActiveTenantID: &tenantID, AuthenticationMethod: "ldap",
	}}
	updatedAt := time.Now().UTC().Truncate(time.Microsecond)
	calls := 0
	authorizationService := &tenantAuthorizationTransportStub{
		changeMembershipFunc: func(
			_ context.Context,
			actor authorization.Actor,
			requestedTenantID uuid.UUID,
			requestedUserID uuid.UUID,
			target authorization.MembershipStatus,
			input authorization.TenantMembershipLifecycleInput,
		) (authorization.TenantMembershipLifecycleReceipt, error) {
			calls++
			if actor.AuthenticationMethod != "ldap" || requestedTenantID != tenantID ||
				requestedUserID != userID || target != authorization.MembershipStatusSuspended ||
				input.ExpectedRevision == nil || *input.ExpectedRevision != 7 ||
				input.Reason != "Suspend access during offboarding review" ||
				input.IdempotencyKey != "membership-lifecycle-key-0001" ||
				input.Audit.RequestID != requestID {
				t.Fatalf("membership lifecycle input = actor=%+v tenant=%s user=%s target=%s input=%+v", actor, requestedTenantID, requestedUserID, target, input)
			}
			return authorization.TenantMembershipLifecycleReceipt{
				TenantID: tenantID, MembershipID: membershipID, UserID: userID,
				PreviousStatus:    authorization.MembershipStatusActive,
				Status:            authorization.MembershipStatusSuspended,
				LifecycleRevision: 8, EntityTag: `"v8"`, UpdatedAt: updatedAt,
				RevokedSessionCount: 2, RevokedContinuationCount: 1,
			}, nil
		},
	}
	router := newTenantAuthorizationTestRouter(t, auth, authorizationService)
	path := "/api/v1/tenants/" + tenantID.String() + "/users/" + userID.String() + "/suspend"

	mismatched := httptest.NewRequest(
		http.MethodPost, path,
		strings.NewReader(`{"expectedRevision":6,"reason":"Suspend access during offboarding review"}`),
	)
	mismatched.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	mismatched.Header.Set("Content-Type", "application/json")
	mismatched.Header.Set("Origin", "http://localhost:8081")
	mismatched.Header.Set(csrfTokenHeader, "csrf-value")
	mismatched.Header.Set(ifMatchHeader, `"v7"`)
	mismatched.Header.Set(idempotencyKeyHeader, "membership-lifecycle-key-0001")
	mismatchedResponse := httptest.NewRecorder()
	router.ServeHTTP(mismatchedResponse, mismatched)
	assertProblem(t, mismatchedResponse, http.StatusBadRequest, "invalid_request")
	if calls != 0 {
		t.Fatalf("membership lifecycle calls after mismatched revision = %d, want 0", calls)
	}

	request := httptest.NewRequest(
		http.MethodPost, path,
		strings.NewReader(`{"expectedRevision":7,"reason":"Suspend access during offboarding review"}`),
	)
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.Header.Set(csrfTokenHeader, "csrf-value")
	request.Header.Set(ifMatchHeader, `"v7"`)
	request.Header.Set(idempotencyKeyHeader, "membership-lifecycle-key-0001")
	request.Header.Set(requestIDHeader, requestID.String())
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if calls != 1 || auth.csrfCalls != 2 {
		t.Fatalf("membership lifecycle/CSRF calls = %d/%d, want 1/2", calls, auth.csrfCalls)
	}
	if response.Header().Get("ETag") != `"v8"` || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("ETag/Cache-Control = %q/%q", response.Header().Get("ETag"), response.Header().Get("Cache-Control"))
	}
	var body struct {
		Reason                   string    `json:"reason"`
		MembershipID             uuid.UUID `json:"membershipId"`
		LifecycleRevision        int64     `json:"lifecycleRevision"`
		RevokedSessionCount      int       `json:"revokedSessionCount"`
		RevokedContinuationCount int       `json:"revokedContinuationCount"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode membership receipt: %v", err)
	}
	if body.Reason != "" || body.MembershipID != membershipID || body.LifecycleRevision != 8 ||
		body.RevokedSessionCount != 2 || body.RevokedContinuationCount != 1 {
		t.Fatalf("membership receipt = %+v", body)
	}
}

func TestTenantAuthorizationListRejectsExplicitZeroLimit(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	auth := &transportAuthStub{authenticateResult: authentication.Session{
		ID: uuid.Must(uuid.NewV7()), User: authentication.User{ID: userID},
		ActiveTenantID: &tenantID, AuthenticationMethod: "totp",
	}}
	router := newTenantAuthorizationTestRouter(t, auth, &tenantAuthorizationTransportStub{})
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/tenants/"+tenantID.String()+"/roles?limit=0",
		nil,
	)
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusBadRequest, "invalid_request")
}

func TestTenantRoleInventoriesFailClosedOnNonImmediateCursorCycles(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	cursors := []uuid.UUID{
		uuid.MustParse("018f0000-0000-7000-8000-000000000001"),
		uuid.MustParse("018f0000-0000-7000-8000-000000000002"),
	}
	auth := &transportAuthStub{authenticateResult: authentication.Session{
		ID: uuid.Must(uuid.NewV7()), User: authentication.User{ID: userID},
		ActiveTenantID: &tenantID, AuthenticationMethod: "totp",
	}}

	for _, inventory := range []struct {
		name    string
		path    string
		service func(*testing.T, *int) AuthorizationService
	}{
		{
			name: "permissions",
			path: "/api/v1/tenants/" + tenantID.String() + "/permissions",
			service: func(t *testing.T, calls *int) AuthorizationService {
				t.Helper()
				return &tenantAuthorizationTransportStub{
					listPermissionsFunc: func(
						_ context.Context,
						_ authorization.Actor,
						_ uuid.UUID,
						input authorization.PageInput,
					) (authorization.TenantPermissionPage, error) {
						id := inventoryCursorForRequest(t, calls, input.After, cursors)
						return authorization.TenantPermissionPage{
							Items: []authorization.TenantPermissionDefinition{{
								ID: id, Key: authorization.TenantPermissionRoleRead,
								Name: "Read roles", Description: "Lists tenant roles.",
								AllowedScopes:  []authorization.Scope{authorization.ScopeTenant},
								PrincipalKinds: []authorization.PrincipalKind{authorization.PrincipalKindHuman},
							}},
							NextCursor: &id,
						}, nil
					},
				}
			},
		},
		{
			name: "roles",
			path: "/api/v1/tenants/" + tenantID.String() + "/roles",
			service: func(t *testing.T, calls *int) AuthorizationService {
				t.Helper()
				return &tenantAuthorizationTransportStub{
					listRolesFunc: func(
						_ context.Context,
						_ authorization.Actor,
						_ uuid.UUID,
						input authorization.ListTenantRolesInput,
					) (authorization.TenantRolePage, error) {
						id := inventoryCursorForRequest(t, calls, input.After, cursors)
						now := time.Now().UTC()
						return authorization.TenantRolePage{
							Items: []authorization.TenantRoleSummary{{
								ID: id, TenantID: tenantID, Key: "custom_role", Name: "Custom role",
								Version: 1, CreatedAt: now, UpdatedAt: now,
							}},
							NextCursor: &id,
						}, nil
					},
				}
			},
		},
	} {
		t.Run(inventory.name, func(t *testing.T) {
			calls := 0
			router := newTenantAuthorizationTestRouter(t, auth, inventory.service(t, &calls))
			paths := []string{
				inventory.path,
				inventory.path + "?after=" + cursors[0].String(),
				inventory.path + "?after=" + cursors[1].String(),
			}
			for index, path := range paths {
				request := httptest.NewRequest(http.MethodGet, path, nil)
				request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
				response := httptest.NewRecorder()

				router.ServeHTTP(response, request)

				if index < 2 {
					if response.Code != http.StatusOK {
						t.Fatalf("request %d status = %d: %s", index+1, response.Code, response.Body.String())
					}
					continue
				}
				assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
			}
			if calls != len(paths) {
				t.Fatalf("inventory calls = %d, want %d", calls, len(paths))
			}
		})
	}
}

func TestTenantAuthorizationPageValidationRejectsDivergenceDuplicatesAndOversize(t *testing.T) {
	first := uuid.MustParse("018f0000-0000-7000-8000-000000000001")
	second := uuid.MustParse("018f0000-0000-7000-8000-000000000002")
	itemCursor := func(item uuid.UUID) uuid.UUID { return item }

	if validTenantAuthorizationPage(
		authorization.PageInput{Limit: 1}, []uuid.UUID{first}, &second, itemCursor,
	) {
		t.Fatal("divergent next cursor was accepted")
	}
	if validTenantAuthorizationPage(
		authorization.PageInput{Limit: 2}, []uuid.UUID{first, first}, nil, itemCursor,
	) {
		t.Fatal("duplicate item cursor was accepted")
	}
	if validTenantAuthorizationPage(
		authorization.PageInput{Limit: 1}, []uuid.UUID{first, second}, &second, itemCursor,
	) {
		t.Fatal("oversize page was accepted")
	}
}

func inventoryCursorForRequest(
	t *testing.T,
	calls *int,
	after *uuid.UUID,
	cursors []uuid.UUID,
) uuid.UUID {
	t.Helper()
	*calls = *calls + 1
	switch *calls {
	case 1:
		if after != nil {
			t.Fatalf("first inventory cursor = %v, want omitted", after)
		}
		return cursors[0]
	case 2:
		if after == nil || *after != cursors[0] {
			t.Fatalf("second inventory cursor = %v, want %s", after, cursors[0])
		}
		return cursors[1]
	case 3:
		if after == nil || *after != cursors[1] {
			t.Fatalf("third inventory cursor = %v, want %s", after, cursors[1])
		}
		return cursors[0]
	default:
		t.Fatalf("unexpected inventory request %d", *calls)
		return uuid.Nil
	}
}

func TestAuthorizationDomainErrorsUseContractStatusCodes(t *testing.T) {
	for _, test := range []struct {
		err    error
		status int
		code   string
	}{
		{authorization.ErrInvalidInput, http.StatusBadRequest, "invalid_request"},
		{authorization.ErrForbidden, http.StatusForbidden, "forbidden"},
		{authorization.ErrNotFound, http.StatusNotFound, "not_found"},
		{authorization.ErrConflict, http.StatusConflict, "conflict"},
		{authorization.ErrPreconditionFailed, http.StatusPreconditionFailed, "precondition_failed"},
		{authorization.ErrPreconditionRequired, http.StatusPreconditionRequired, "precondition_required"},
		{authorization.ErrUnavailable, http.StatusServiceUnavailable, "service_unavailable"},
	} {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request = request.WithContext(context.WithValue(request.Context(), requestIDKey{}, uuid.Must(uuid.NewV7()).String()))
		response := httptest.NewRecorder()

		writeDomainError(response, request, test.err)

		assertProblem(t, response, test.status, test.code)
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("error %v did not set no-store", test.err)
		}
	}
}

func newTenantAuthorizationTestRouter(
	t *testing.T,
	auth AuthenticationService,
	authorizationService AuthorizationService,
) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler, err := NewApplicationHandler(
		fixedChecker{ready: true}, logger, "test", time.Second,
		ApplicationOptions{
			Alerts: &transportAlertStub{}, Audit: &transportSecurityAuditStub{}, Authentication: auth, Authorization: authorizationService,
			Contacts: &transportContactStub{}, CustomFields: &transportCustomFieldStub{}, DFIR: &transportDFIRStub{},
			Environment: "test", IdentityProviders: &transportIdentityProviderStub{}, LDAPAdministration: &transportLDAPAdministrationStub{}, MFA: &transportMFAStub{}, Notifications: &transportNotificationStub{}, OperatorTeams: &transportOperatorTeamStub{}, Platform: &transportPlatformStub{},
			PublicOrigin: "http://localhost:8081", ServiceAccounts: &transportServiceAccountStub{}, SLA: &transportSLAStub{}, Ticketing: &transportTicketingStub{}, WorkflowAdministration: &transportWorkflowAdministrationStub{},
		},
	)
	if err != nil {
		t.Fatalf("NewApplicationHandler() error = %v", err)
	}
	return Router(handler, logger, false)
}
