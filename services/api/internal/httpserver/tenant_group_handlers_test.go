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

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
)

func TestCreateTenantSecurityGroupReturnsArchivedCurrentReplayWithStrongETag(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	groupID := uuid.Must(uuid.NewV7())
	requestID := uuid.Must(uuid.NewV7())
	auth := groupTransportAuthentication(tenantID, userID)
	var captured authorization.CreateTenantSecurityGroupInput
	authorizationService := &tenantAuthorizationTransportStub{
		createGroupFunc: func(
			_ context.Context,
			actor authorization.Actor,
			requestedTenantID uuid.UUID,
			input authorization.CreateTenantSecurityGroupInput,
		) (authorization.TenantSecurityGroup, error) {
			if actor.UserID != userID || requestedTenantID != tenantID {
				t.Fatalf("actor/tenant = %#v/%s", actor, requestedTenantID)
			}
			captured = input
			now := time.Now().UTC()
			return authorization.TenantSecurityGroup{
				ID: groupID, TenantID: tenantID, Key: input.Key, Name: input.Name,
				Description: input.Description, Archived: true, ArchivedAt: &now,
				Version: 2, CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
			}, nil
		},
	}
	request := tenantGroupMutationRequest(
		tenantID,
		http.MethodPost,
		"/api/v1/tenants/"+tenantID.String()+"/groups",
		`{"key":"soc_l2","name":"SOC L2","description":"Senior analysts"}`,
	)
	request.Header.Set(idempotencyKeyHeader, "group-create-0123456789")
	request.Header.Set(requestIDHeader, requestID.String())
	request.RemoteAddr = "198.51.100.45:4231"
	response := httptest.NewRecorder()

	newTenantAuthorizationTestRouter(t, auth, authorizationService).ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("ETag") != `"v2"` {
		t.Fatalf("ETag = %q", response.Header().Get("ETag"))
	}
	if captured.IdempotencyKey != "group-create-0123456789" ||
		captured.Audit.RequestID != requestID || captured.Audit.RemoteAddress.String() != "198.51.100.45" {
		t.Fatalf("captured input = %#v", captured)
	}
	var body contract.TenantSecurityGroup
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Id != groupID || body.Key != "soc_l2" || !body.Archived || body.ArchivedAt == nil ||
		body.Description == nil || *body.Description != "Senior analysts" {
		t.Fatalf("response body = %#v", body)
	}
}

func TestCreateTenantSecurityGroupMapsIdempotencyPayloadDriftToConflict(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	service := &tenantAuthorizationTransportStub{
		createGroupFunc: func(
			context.Context,
			authorization.Actor,
			uuid.UUID,
			authorization.CreateTenantSecurityGroupInput,
		) (authorization.TenantSecurityGroup, error) {
			return authorization.TenantSecurityGroup{}, authorization.ErrConflict
		},
	}
	request := tenantGroupMutationRequest(
		tenantID,
		http.MethodPost,
		"/api/v1/tenants/"+tenantID.String()+"/groups",
		`{"key":"soc_l2","name":"Drifted SOC L2"}`,
	)
	request.Header.Set(idempotencyKeyHeader, "group-create-0123456789")
	response := httptest.NewRecorder()

	newTenantAuthorizationTestRouter(t, groupTransportAuthentication(tenantID, userID), service).
		ServeHTTP(response, request)

	assertProblem(t, response, http.StatusConflict, "conflict")
}

func TestTenantSecurityGroupBodiesRejectNonCanonicalJSONBeforeService(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	tests := []struct {
		name string
		body string
	}{
		{"null", `{"key":"soc_l2","name":"SOC L2","description":null}`},
		{"duplicate", `{"key":"soc_l2","key":"soc_l3","name":"SOC L2"}`},
		{"case variant", `{"Key":"soc_l2","name":"SOC L2"}`},
		{"unknown", `{"key":"soc_l2","name":"SOC L2","nested":{}}`},
		{"c0 control", "{\"key\":\"soc_l2\",\"name\":\"SOC\\u000aL2\"}"},
		{"c1 control", "{\"key\":\"soc_l2\",\"name\":\"SOC\\u0085L2\"}"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			called := false
			service := &tenantAuthorizationTransportStub{
				createGroupFunc: func(
					context.Context,
					authorization.Actor,
					uuid.UUID,
					authorization.CreateTenantSecurityGroupInput,
				) (authorization.TenantSecurityGroup, error) {
					called = true
					return authorization.TenantSecurityGroup{}, nil
				},
			}
			request := tenantGroupMutationRequest(
				tenantID,
				http.MethodPost,
				"/api/v1/tenants/"+tenantID.String()+"/groups",
				test.body,
			)
			request.Header.Set(idempotencyKeyHeader, "group-create-0123456789")
			response := httptest.NewRecorder()

			newTenantAuthorizationTestRouter(t, groupTransportAuthentication(tenantID, userID), service).
				ServeHTTP(response, request)

			assertProblem(t, response, http.StatusBadRequest, "invalid_request")
			if called {
				t.Fatal("authorization service was called for an invalid body")
			}
		})
	}
}

func TestTenantSecurityGroupMembershipResponsePreservesSourceOwnership(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	groupID := uuid.Must(uuid.NewV7())
	edgeID := uuid.Must(uuid.NewV7())
	membershipID := uuid.Must(uuid.NewV7())
	sourceID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Second)
	revokedAt := now.Add(-30 * time.Second)
	revokeReason := "Removed by identity reconciliation"
	edge := authorization.TenantSecurityGroupMembership{
		ID: edgeID, TenantID: tenantID,
		ManagedByAuthorizationAPI: false,
		Group: authorization.TenantSecurityGroup{
			ID: groupID, TenantID: tenantID, Key: "soc_l2", Name: "SOC L2",
			Version: 1, CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
		},
		Member: authorization.TenantUserSummary{
			TenantID: tenantID, MembershipID: membershipID,
			User:                 authorization.TenantUserProfile{ID: userID, Email: "analyst@example.test", DisplayName: "SOC Analyst", Active: true},
			MembershipStatus:     authorization.MembershipStatusActive,
			LegacyMembershipRole: authorization.LegacyMembershipRoleAnalyst,
			CreatedAt:            now.Add(-time.Hour), UpdatedAt: now,
		},
		Provenance: authorization.AuthorizationEdgeProvenance{
			SourceKind: authorization.AuthorizationSourceIdentityMapping, SourceID: &sourceID,
			Authoritative: true, GrantedAt: now.Add(-time.Minute), Reason: "OIDC group mapping",
		},
		State:     authorization.AuthorizationEdgeStateRevoked,
		RevokedAt: &revokedAt, RevokedByUserID: &userID, RevokeReason: &revokeReason,
		Version: 2, UpdatedAt: now,
	}
	service := &tenantAuthorizationTransportStub{
		listGroupMembershipsFunc: func(
			context.Context,
			authorization.Actor,
			uuid.UUID,
			uuid.UUID,
			authorization.ListTenantSecurityGroupEdgesInput,
		) (authorization.TenantSecurityGroupMembershipPage, error) {
			return authorization.TenantSecurityGroupMembershipPage{Items: []authorization.TenantSecurityGroupMembership{edge}}, nil
		},
	}
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/tenants/"+tenantID.String()+"/groups/"+groupID.String()+"/memberships?includeRevoked=true",
		nil,
	)
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	response := httptest.NewRecorder()

	newTenantAuthorizationTestRouter(t, groupTransportAuthentication(tenantID, userID), service).
		ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	var document map[string]any
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	items := document["items"].([]any)
	item := items[0].(map[string]any)
	provenance := item["provenance"].(map[string]any)
	if provenance["sourceKind"] != "identity_mapping" || provenance["sourceId"] != sourceID.String() ||
		provenance["authoritative"] != true {
		t.Fatalf("provenance = %#v", provenance)
	}
	if _, exists := provenance["sourceType"]; exists {
		t.Fatalf("new edge provenance conflated path type: %#v", provenance)
	}
	if item["state"] != "revoked" || item["revokeReason"] != revokeReason {
		t.Fatalf("revocation history = %#v", item)
	}
	if ownership, exists := item["managedByAuthorizationApi"]; !exists || ownership != false {
		t.Fatalf("ownership hint = %#v", ownership)
	}
}

func TestTenantSecurityGroupRevokeRequiresStrongIfMatch(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	groupID := uuid.Must(uuid.NewV7())
	edgeID := uuid.Must(uuid.NewV7())
	for _, test := range []struct {
		name    string
		ifMatch string
		status  int
		code    string
	}{
		{"missing", "", http.StatusPreconditionRequired, "precondition_required"},
		{"weak", `W/"v1"`, http.StatusBadRequest, "invalid_request"},
		{"wildcard", "*", http.StatusBadRequest, "invalid_request"},
		{"multiple", `"v1", "v2"`, http.StatusBadRequest, "invalid_request"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			called := false
			service := &tenantAuthorizationTransportStub{
				revokeGroupMembershipFunc: func(
					context.Context,
					authorization.Actor,
					uuid.UUID,
					uuid.UUID,
					uuid.UUID,
					authorization.RevokeTenantSecurityGroupMembershipInput,
				) error {
					called = true
					return nil
				},
			}
			request := tenantGroupMutationRequest(
				tenantID,
				http.MethodPost,
				"/api/v1/tenants/"+tenantID.String()+"/groups/"+groupID.String()+"/memberships/"+edgeID.String()+"/revoke",
				`{"reason":"Remove manual membership"}`,
			)
			if test.ifMatch != "" {
				request.Header.Set(ifMatchHeader, test.ifMatch)
			}
			response := httptest.NewRecorder()

			newTenantAuthorizationTestRouter(t, groupTransportAuthentication(tenantID, userID), service).
				ServeHTTP(response, request)

			assertProblem(t, response, test.status, test.code)
			if called {
				t.Fatal("service called without one valid strong precondition")
			}
		})
	}
}

func TestAuthorizationEdgeRevokesForwardExactStrongEntityTag(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	groupID := uuid.Must(uuid.NewV7())
	edgeID := uuid.Must(uuid.NewV7())
	entityTag := `"v7-` + strings.Repeat("A", 43) + `"`
	reason := "Remove superseded manual authority"

	tests := []struct {
		name      string
		path      string
		configure func(*testing.T, *tenantAuthorizationTransportStub, *int)
	}{
		{
			name: "direct user role grant",
			path: "/api/v1/tenants/" + tenantID.String() + "/role-grants/" + edgeID.String() + "/revoke",
			configure: func(t *testing.T, service *tenantAuthorizationTransportStub, calls *int) {
				t.Helper()
				service.revokeRoleGrantFunc = func(
					_ context.Context,
					actor authorization.Actor,
					requestedTenantID uuid.UUID,
					requestedEdgeID uuid.UUID,
					input authorization.RevokeRoleGrantInput,
				) error {
					*calls++
					if actor.UserID != userID || requestedTenantID != tenantID || requestedEdgeID != edgeID ||
						input.ExpectedEntityTag == nil || *input.ExpectedEntityTag != entityTag || input.Reason != reason {
						t.Fatalf("direct role-grant revoke = actor %#v, tenant %s, edge %s, input %#v", actor, requestedTenantID, requestedEdgeID, input)
					}
					return nil
				}
			},
		},
		{
			name: "group membership",
			path: "/api/v1/tenants/" + tenantID.String() + "/groups/" + groupID.String() + "/memberships/" + edgeID.String() + "/revoke",
			configure: func(t *testing.T, service *tenantAuthorizationTransportStub, calls *int) {
				t.Helper()
				service.revokeGroupMembershipFunc = func(
					_ context.Context,
					actor authorization.Actor,
					requestedTenantID uuid.UUID,
					requestedGroupID uuid.UUID,
					requestedEdgeID uuid.UUID,
					input authorization.RevokeTenantSecurityGroupMembershipInput,
				) error {
					*calls++
					if actor.UserID != userID || requestedTenantID != tenantID || requestedGroupID != groupID ||
						requestedEdgeID != edgeID || input.ExpectedEntityTag == nil ||
						*input.ExpectedEntityTag != entityTag || input.Reason != reason {
						t.Fatalf("group-membership revoke = actor %#v, tenant %s, group %s, edge %s, input %#v", actor, requestedTenantID, requestedGroupID, requestedEdgeID, input)
					}
					return nil
				}
			},
		},
		{
			name: "group role grant",
			path: "/api/v1/tenants/" + tenantID.String() + "/groups/" + groupID.String() + "/role-grants/" + edgeID.String() + "/revoke",
			configure: func(t *testing.T, service *tenantAuthorizationTransportStub, calls *int) {
				t.Helper()
				service.revokeGroupRoleGrantFunc = func(
					_ context.Context,
					actor authorization.Actor,
					requestedTenantID uuid.UUID,
					requestedGroupID uuid.UUID,
					requestedEdgeID uuid.UUID,
					input authorization.RevokeTenantSecurityGroupRoleGrantInput,
				) error {
					*calls++
					if actor.UserID != userID || requestedTenantID != tenantID || requestedGroupID != groupID ||
						requestedEdgeID != edgeID || input.ExpectedEntityTag == nil ||
						*input.ExpectedEntityTag != entityTag || input.Reason != reason {
						t.Fatalf("group-role-grant revoke = actor %#v, tenant %s, group %s, edge %s, input %#v", actor, requestedTenantID, requestedGroupID, requestedEdgeID, input)
					}
					return nil
				}
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			calls := 0
			service := &tenantAuthorizationTransportStub{}
			test.configure(t, service, &calls)
			request := tenantGroupMutationRequest(
				tenantID,
				http.MethodPost,
				test.path,
				`{"reason":"`+reason+`"}`,
			)
			request.Header.Set(ifMatchHeader, entityTag)
			response := httptest.NewRecorder()

			newTenantAuthorizationTestRouter(t, groupTransportAuthentication(tenantID, userID), service).
				ServeHTTP(response, request)

			if response.Code != http.StatusNoContent {
				t.Fatalf("status = %d: %s", response.Code, response.Body.String())
			}
			if calls != 1 {
				t.Fatalf("service calls = %d, want 1", calls)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
			}
		})
	}
}

func TestMapTenantAuthorityPreservesBothGroupPathSources(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	membershipID := uuid.Must(uuid.NewV7())
	groupID := uuid.Must(uuid.NewV7())
	roleID := uuid.Must(uuid.NewV7())
	roleGrantID := uuid.Must(uuid.NewV7())
	memberEdgeID := uuid.Must(uuid.NewV7())
	membershipSourceID := uuid.Must(uuid.NewV7())
	roleSourceID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Second)
	roleExpiry := now.Add(time.Hour)
	membershipExpiry := now.Add(2 * time.Hour)
	roleEdge := authorization.AuthorizationEdgeProvenance{
		SourceKind: authorization.AuthorizationSourceManual, SourceID: &roleSourceID,
		GrantedByUserID: &userID, GrantedAt: now.Add(-time.Hour), Reason: "Group role", ExpiresAt: &roleExpiry,
	}
	mapped, err := mapTenantAuthority(authorization.TenantAuthority{
		TenantID: tenantID, Principal: authorization.TenantPrincipal{ID: userID, Kind: authorization.PrincipalKindHuman},
		MembershipID: membershipID, MembershipStatus: authorization.MembershipStatusActive,
		LegacyRole: authorization.LegacyMembershipRoleAnalyst, EvaluatedAt: now,
		RoleGrants: []authorization.EffectiveTenantRoleGrant{{
			GrantID: roleGrantID, RoleID: roleID, RoleKey: "soc_role", RoleName: "SOC role",
			Provenance: authorization.RoleGrantProvenance{
				SourceType: authorization.RoleGrantSourceGroup, SourceKind: roleEdge.SourceKind,
				SourceID: roleEdge.SourceID, GrantedByUserID: roleEdge.GrantedByUserID,
				GrantedAt: roleEdge.GrantedAt, Reason: roleEdge.Reason, ExpiresAt: roleEdge.ExpiresAt,
			},
			Path: authorization.EffectiveTenantRoleAuthorityPath{
				PathType: authorization.RoleGrantPathGroup,
				Group: &authorization.GroupTenantRoleAuthorityPath{
					Group: authorization.TenantSecurityGroupAuthoritySummary{ID: groupID, Key: "soc_l2", Name: "SOC L2"},
					MembershipEdge: authorization.TenantSecurityGroupAuthorityEdge{
						ID: memberEdgeID,
						Provenance: authorization.AuthorizationEdgeProvenance{
							SourceKind: authorization.AuthorizationSourceIdentityMapping,
							SourceID:   &membershipSourceID, Authoritative: true,
							GrantedAt: now.Add(-time.Hour), Reason: "OIDC mapping", ExpiresAt: &membershipExpiry,
						},
					},
					RoleGrantEdge: authorization.TenantSecurityGroupAuthorityEdge{ID: roleGrantID, Provenance: roleEdge},
				},
			},
			EffectiveExpiresAt: &roleExpiry,
		}},
	})
	if err != nil {
		t.Fatalf("mapTenantAuthority() error = %v", err)
	}
	path, err := mapped.RoleGrants[0].Path.AsGroupEffectiveTenantRoleAuthorityPath()
	if err != nil {
		t.Fatalf("mapTenantAuthority() group path error = %v", err)
	}
	if path.PathType != contract.GroupEffectiveTenantRoleAuthorityPathPathTypeGroup ||
		path.Group.Group.Id != groupID || path.Group.MembershipEdge.Provenance.SourceId != membershipSourceID ||
		path.Group.RoleGrantEdge.Provenance.SourceId != roleSourceID ||
		mapped.RoleGrants[0].EffectiveExpiresAt == nil || !mapped.RoleGrants[0].EffectiveExpiresAt.Equal(roleExpiry) {
		t.Fatalf("mapped group path = %#v", mapped.RoleGrants[0])
	}
}

func TestMapEffectiveAuthorityRejectsRetiredSourceProvenance(t *testing.T) {
	t.Parallel()

	sourceID := uuid.Must(uuid.NewV7())
	retiredAt := time.Now().UTC().Truncate(time.Second)
	if _, err := mapEffectiveRoleGrantProvenance(authorization.RoleGrantProvenance{
		SourceType: authorization.RoleGrantSourceDirect,
		SourceKind: authorization.AuthorizationSourceManual,
		SourceID:   &sourceID,
		RetiredAt:  &retiredAt,
	}); err == nil {
		t.Fatal("retired direct provenance mapped into live authority")
	}
	if _, err := mapEffectiveAuthorizationEdgeProvenance(authorization.AuthorizationEdgeProvenance{
		SourceKind: authorization.AuthorizationSourceManual,
		SourceID:   &sourceID,
		RetiredAt:  &retiredAt,
	}); err == nil {
		t.Fatal("retired group-edge provenance mapped into live authority")
	}
}

func groupTransportAuthentication(tenantID, userID uuid.UUID) *transportAuthStub {
	sessionID := uuid.Must(uuid.NewV7())
	return &transportAuthStub{authenticateResult: authentication.Session{
		ID: sessionID, User: authentication.User{ID: userID}, ActiveTenantID: &tenantID,
		AuthenticationMethod: "totp",
	}}
}

func tenantGroupMutationRequest(
	tenantID uuid.UUID,
	method, path, body string,
) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.AddCookie(&http.Cookie{Name: developmentCookie, Value: "opaque-session"})
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:8081")
	request.Header.Set(csrfTokenHeader, "csrf-value")
	return request
}
