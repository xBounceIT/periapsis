package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type idempotencyReplayTransportStub struct {
	tenantAuthorizationTransportStub
	grantUserRoleFunc func(
		context.Context,
		authorization.Actor,
		uuid.UUID,
		uuid.UUID,
		authorization.GrantUserRoleInput,
	) (authorization.DirectUserRoleGrant, error)
	grantGroupRoleFunc func(
		context.Context,
		authorization.Actor,
		uuid.UUID,
		uuid.UUID,
		authorization.GrantTenantSecurityGroupRoleInput,
	) (authorization.TenantSecurityGroupRoleGrant, error)
}

func (s *idempotencyReplayTransportStub) GrantUserRole(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, userID uuid.UUID,
	input authorization.GrantUserRoleInput,
) (authorization.DirectUserRoleGrant, error) {
	return s.grantUserRoleFunc(ctx, actor, tenantID, userID, input)
}

func (s *idempotencyReplayTransportStub) GrantTenantSecurityGroupRole(
	ctx context.Context,
	actor authorization.Actor,
	tenantID, groupID uuid.UUID,
	input authorization.GrantTenantSecurityGroupRoleInput,
) (authorization.TenantSecurityGroupRoleGrant, error) {
	return s.grantGroupRoleFunc(ctx, actor, tenantID, groupID, input)
}

func TestEdgeCreateHTTPExpiryBoundaryHandling(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	actorID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	groupID := uuid.Must(uuid.NewV7())
	roleID := uuid.Must(uuid.NewV7())
	microsecondExpiry := time.Date(
		2026, time.August, 24, 16, 30, 0, 123456000, time.UTC,
	)
	unknownOffsetExpiry := time.Date(2026, time.August, 24, 16, 30, 0, 0, time.UTC)
	shapes := []struct {
		name        string
		path        string
		body        func(string) string
		makeService func(func(*time.Time)) AuthorizationService
	}{
		{
			name: "direct role grant",
			path: "/api/v1/tenants/" + tenantID.String() + "/users/" + userID.String() + "/role-grants",
			body: func(expiry string) string {
				return fmt.Sprintf(`{"roleId":%q,"reason":"Temporary access"%s}`, roleID.String(), expiry)
			},
			makeService: func(capture func(*time.Time)) AuthorizationService {
				return &idempotencyReplayTransportStub{grantUserRoleFunc: func(
					_ context.Context,
					_ authorization.Actor,
					_, _ uuid.UUID,
					input authorization.GrantUserRoleInput,
				) (authorization.DirectUserRoleGrant, error) {
					capture(input.ExpiresAt)
					return authorization.DirectUserRoleGrant{}, authorization.ErrInvalidInput
				}}
			},
		},
		{
			name: "group membership",
			path: "/api/v1/tenants/" + tenantID.String() + "/groups/" + groupID.String() + "/memberships",
			body: func(expiry string) string {
				return fmt.Sprintf(`{"userId":%q,"reason":"Temporary access"%s}`, userID.String(), expiry)
			},
			makeService: func(capture func(*time.Time)) AuthorizationService {
				return &idempotencyReplayTransportStub{tenantAuthorizationTransportStub: tenantAuthorizationTransportStub{
					addGroupMembershipFunc: func(
						_ context.Context,
						_ authorization.Actor,
						_, _ uuid.UUID,
						input authorization.AddTenantSecurityGroupMembershipInput,
					) (authorization.TenantSecurityGroupMembership, error) {
						capture(input.ExpiresAt)
						return authorization.TenantSecurityGroupMembership{}, authorization.ErrInvalidInput
					},
				}}
			},
		},
		{
			name: "group role grant",
			path: "/api/v1/tenants/" + tenantID.String() + "/groups/" + groupID.String() + "/role-grants",
			body: func(expiry string) string {
				return fmt.Sprintf(`{"roleId":%q,"reason":"Temporary access"%s}`, roleID.String(), expiry)
			},
			makeService: func(capture func(*time.Time)) AuthorizationService {
				return &idempotencyReplayTransportStub{grantGroupRoleFunc: func(
					_ context.Context,
					_ authorization.Actor,
					_, _ uuid.UUID,
					input authorization.GrantTenantSecurityGroupRoleInput,
				) (authorization.TenantSecurityGroupRoleGrant, error) {
					capture(input.ExpiresAt)
					return authorization.TenantSecurityGroupRoleGrant{}, authorization.ErrInvalidInput
				}}
			},
		},
	}
	cases := []struct {
		name       string
		expiryJSON string
		attempts   int
		wantCalled bool
		wantExpiry *time.Time
	}{
		{name: "omitted", wantCalled: true},
		{name: "explicit null", expiryJSON: `,"expiresAt":null`},
		{name: "zero instant", expiryJSON: `,"expiresAt":"0001-01-01T00:00:00Z"`},
		{
			name:       "equivalent trailing zeros",
			expiryJSON: `,"expiresAt":"2026-08-24T16:30:00.1234560000Z"`,
			wantCalled: true,
			wantExpiry: &microsecondExpiry,
		},
		{
			name:       "unknown local offset",
			expiryJSON: `,"expiresAt":"2026-08-24T16:30:00-00:00"`,
			wantCalled: true,
			wantExpiry: &unknownOffsetExpiry,
		},
		{name: "leap second", expiryJSON: `,"expiresAt":"2016-12-31T23:59:60Z"`},
		{
			name:       "UTC year overflow",
			expiryJSON: `,"expiresAt":"9999-12-31T23:59:59.999999-23:59"`,
			attempts:   2,
		},
		{
			name:       "UTC year underflow",
			expiryJSON: `,"expiresAt":"0000-01-01T00:00:00+23:59"`,
			attempts:   2,
		},
		{name: "seventh digit nonzero", expiryJSON: `,"expiresAt":"2026-08-24T16:30:00.1234567Z"`},
		{name: "beyond nanosecond nonzero", expiryJSON: `,"expiresAt":"2026-08-24T16:30:00.1234560001Z"`},
		{name: "comma fraction", expiryJSON: `,"expiresAt":"2026-08-24T16:30:00,123456Z"`},
		{name: "offset above maximum", expiryJSON: `,"expiresAt":"2026-08-24T16:30:00+24:00"`},
	}

	for _, shape := range shapes {
		for _, test := range cases {
			t.Run(shape.name+"/"+test.name, func(t *testing.T) {
				attempts := test.attempts
				if attempts == 0 {
					attempts = 1
				}
				for attempt := 1; attempt <= attempts; attempt++ {
					called := false
					service := shape.makeService(func(expiresAt *time.Time) {
						called = true
						if test.wantExpiry == nil {
							if expiresAt != nil {
								t.Fatalf("omitted expiry reached service as %v", expiresAt)
							}
							return
						}
						if expiresAt == nil || !expiresAt.Equal(*test.wantExpiry) {
							t.Fatalf("decoded expiry = %v, want %v", expiresAt, test.wantExpiry)
						}
					})
					request := tenantGroupMutationRequest(
						tenantID, http.MethodPost, shape.path, shape.body(test.expiryJSON),
					)
					request.Header.Set(idempotencyKeyHeader, "edge-create-expiry-test-key")
					response := httptest.NewRecorder()

					newTenantAuthorizationTestRouter(
						t, groupTransportAuthentication(tenantID, actorID), service,
					).ServeHTTP(response, request)

					assertProblem(t, response, http.StatusBadRequest, "invalid_request")
					if called != test.wantCalled {
						t.Fatalf(
							"attempt %d authorization service called = %t, want %t",
							attempt, called, test.wantCalled,
						)
					}
				}
			})
		}
	}
}

func TestExpiredEdgeCreateHTTPOutcomesPreserveIdempotencySemantics(t *testing.T) {
	t.Parallel()

	tenantID := uuid.Must(uuid.NewV7())
	actorID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	groupID := uuid.Must(uuid.NewV7())
	roleID := uuid.Must(uuid.NewV7())
	edgeID := uuid.Must(uuid.NewV7())
	sourceID := uuid.Must(uuid.NewV7())
	membershipID := uuid.Must(uuid.NewV7())
	expiresAt := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	grantedAt := expiresAt.Add(-time.Hour)
	updatedAt := expiresAt.Add(time.Minute)
	group := authorization.TenantSecurityGroup{
		ID: groupID, TenantID: tenantID, Key: "soc_l2", Name: "SOC L2",
		Version: 1, CreatedAt: grantedAt, UpdatedAt: updatedAt,
	}
	role := authorization.TenantRoleSummary{
		ID: roleID, TenantID: tenantID, Key: "incident_reader", Name: "Incident reader",
		Version: 1, CreatedAt: grantedAt, UpdatedAt: updatedAt,
	}
	provenance := authorization.AuthorizationEdgeProvenance{
		SourceKind: authorization.AuthorizationSourceManual, SourceID: &sourceID,
		GrantedByUserID: &actorID, GrantedAt: grantedAt, Reason: "Temporary access", ExpiresAt: &expiresAt,
	}
	directProvenance := authorization.RoleGrantProvenance{
		SourceType: authorization.RoleGrantSourceDirect, SourceKind: authorization.AuthorizationSourceManual,
		SourceID: &sourceID, GrantedByUserID: &actorID, GrantedAt: grantedAt,
		Reason: "Temporary access", ExpiresAt: &expiresAt,
	}

	shapes := []struct {
		name        string
		path        string
		body        string
		makeService func(error, func(*time.Time, string)) AuthorizationService
	}{
		{
			name: "direct role grant",
			path: "/api/v1/tenants/" + tenantID.String() + "/users/" + userID.String() + "/role-grants",
			body: fmt.Sprintf(
				`{"roleId":%q,"reason":"Temporary access","expiresAt":%q}`,
				roleID.String(), expiresAt.Format(time.RFC3339),
			),
			makeService: func(resultErr error, capture func(*time.Time, string)) AuthorizationService {
				return &idempotencyReplayTransportStub{grantUserRoleFunc: func(
					_ context.Context,
					_ authorization.Actor,
					_, requestedUserID uuid.UUID,
					input authorization.GrantUserRoleInput,
				) (authorization.DirectUserRoleGrant, error) {
					capture(input.ExpiresAt, input.IdempotencyKey)
					if resultErr != nil {
						return authorization.DirectUserRoleGrant{}, resultErr
					}
					return authorization.DirectUserRoleGrant{
						ID: edgeID, TenantID: tenantID, UserID: requestedUserID, Role: role,
						ManagedByAuthorizationAPI: true,
						Provenance:                directProvenance, PathType: authorization.RoleGrantPathDirect,
						State: authorization.DirectRoleGrantStateExpired, Version: 1, UpdatedAt: updatedAt,
					}, nil
				}}
			},
		},
		{
			name: "group membership",
			path: "/api/v1/tenants/" + tenantID.String() + "/groups/" + groupID.String() + "/memberships",
			body: fmt.Sprintf(
				`{"userId":%q,"reason":"Temporary access","expiresAt":%q}`,
				userID.String(), expiresAt.Format(time.RFC3339),
			),
			makeService: func(resultErr error, capture func(*time.Time, string)) AuthorizationService {
				return &idempotencyReplayTransportStub{tenantAuthorizationTransportStub: tenantAuthorizationTransportStub{
					addGroupMembershipFunc: func(
						_ context.Context,
						_ authorization.Actor,
						_, _ uuid.UUID,
						input authorization.AddTenantSecurityGroupMembershipInput,
					) (authorization.TenantSecurityGroupMembership, error) {
						capture(input.ExpiresAt, input.IdempotencyKey)
						if resultErr != nil {
							return authorization.TenantSecurityGroupMembership{}, resultErr
						}
						return authorization.TenantSecurityGroupMembership{
							ID: edgeID, TenantID: tenantID, Group: group,
							ManagedByAuthorizationAPI: true,
							Member: authorization.TenantUserSummary{
								TenantID: tenantID, MembershipID: membershipID,
								User: authorization.TenantUserProfile{
									ID: userID, Email: "analyst@example.test", DisplayName: "SOC Analyst", Active: true,
								},
								MembershipStatus:     authorization.MembershipStatusActive,
								LegacyMembershipRole: authorization.LegacyMembershipRoleAnalyst,
								CreatedAt:            grantedAt, UpdatedAt: updatedAt,
							},
							Provenance: provenance, State: authorization.AuthorizationEdgeStateExpired,
							Version: 1, UpdatedAt: updatedAt,
						}, nil
					},
				}}
			},
		},
		{
			name: "group role grant",
			path: "/api/v1/tenants/" + tenantID.String() + "/groups/" + groupID.String() + "/role-grants",
			body: fmt.Sprintf(
				`{"roleId":%q,"reason":"Temporary access","expiresAt":%q}`,
				roleID.String(), expiresAt.Format(time.RFC3339),
			),
			makeService: func(resultErr error, capture func(*time.Time, string)) AuthorizationService {
				return &idempotencyReplayTransportStub{grantGroupRoleFunc: func(
					_ context.Context,
					_ authorization.Actor,
					_, _ uuid.UUID,
					input authorization.GrantTenantSecurityGroupRoleInput,
				) (authorization.TenantSecurityGroupRoleGrant, error) {
					capture(input.ExpiresAt, input.IdempotencyKey)
					if resultErr != nil {
						return authorization.TenantSecurityGroupRoleGrant{}, resultErr
					}
					return authorization.TenantSecurityGroupRoleGrant{
						ID: edgeID, TenantID: tenantID, Group: group, Role: role,
						ManagedByAuthorizationAPI: true,
						Provenance:                provenance, State: authorization.AuthorizationEdgeStateExpired,
						Version: 1, UpdatedAt: updatedAt,
					}, nil
				}}
			},
		},
	}
	outcomes := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{name: "exact expired replay", status: http.StatusCreated},
		{name: "fresh past expiry", err: authorization.ErrInvalidInput, status: http.StatusBadRequest, code: "invalid_request"},
		{name: "payload drift", err: authorization.ErrConflict, status: http.StatusConflict, code: "conflict"},
	}

	for _, shape := range shapes {
		shape := shape
		t.Run(shape.name, func(t *testing.T) {
			for _, outcome := range outcomes {
				outcome := outcome
				t.Run(outcome.name, func(t *testing.T) {
					called := false
					service := shape.makeService(outcome.err, func(gotExpiry *time.Time, gotKey string) {
						called = true
						if gotExpiry == nil || !gotExpiry.Equal(expiresAt) || gotKey != "edge-create-replay-key" {
							t.Fatalf("service input expiry/key = %v/%q", gotExpiry, gotKey)
						}
					})
					request := tenantGroupMutationRequest(tenantID, http.MethodPost, shape.path, shape.body)
					request.Header.Set(idempotencyKeyHeader, "edge-create-replay-key")
					response := httptest.NewRecorder()

					newTenantAuthorizationTestRouter(
						t, groupTransportAuthentication(tenantID, actorID), service,
					).ServeHTTP(response, request)

					if !called {
						t.Fatal("expired payload did not reach the authorization service")
					}
					if outcome.code == "" {
						if response.Code != outcome.status {
							t.Fatalf("status = %d: %s", response.Code, response.Body.String())
						}
						entityTag := response.Header().Get("ETag")
						if _, err := authorization.ParseEdgeEntityTag(entityTag); err != nil {
							t.Fatalf("edge ETag = %q: %v", entityTag, err)
						}
						var document struct {
							EntityTag                 string `json:"etag"`
							ManagedByAuthorizationAPI *bool  `json:"managedByAuthorizationApi"`
						}
						if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
							t.Fatalf("decode edge response: %v", err)
						}
						if document.EntityTag != entityTag {
							t.Fatalf("body/header ETag = %q/%q", document.EntityTag, entityTag)
						}
						if document.ManagedByAuthorizationAPI == nil || !*document.ManagedByAuthorizationAPI {
							t.Fatalf("ownership hint = %#v", document.ManagedByAuthorizationAPI)
						}
						return
					}
					assertProblem(t, response, outcome.status, outcome.code)
				})
			}
		})
	}
}
