package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
)

func TestMapDirectRoleGrantPreservesCompleteRevocationLifecycle(t *testing.T) {
	t.Parallel()

	grant := revokedDirectGrantResponseFixture(t)
	mapped, err := mapDirectRoleGrant(grant)
	if err != nil {
		t.Fatalf("mapDirectRoleGrant(): %v", err)
	}
	if mapped.RevokeReason == nil || *mapped.RevokeReason != *grant.RevokeReason ||
		mapped.RevokedAt == nil || mapped.RevokedByUserId == nil {
		t.Fatalf("mapped revocation metadata = %#v", mapped)
	}
	if mapped.ManagedByAuthorizationApi == nil || !*mapped.ManagedByAuthorizationApi {
		t.Fatalf("mapped ownership hint = %#v", mapped.ManagedByAuthorizationApi)
	}

	changedReason := "Access removed after incident handoff"
	changed := grant
	changed.RevokeReason = &changedReason
	changedMapped, err := mapDirectRoleGrant(changed)
	if err != nil {
		t.Fatalf("mapDirectRoleGrant(changed reason): %v", err)
	}
	if changedMapped.Etag == mapped.Etag {
		t.Fatalf("representation-bound ETag did not change with revoke reason: %q", mapped.Etag)
	}
}

func TestMapDirectRoleGrantRejectsIncompleteRevocationLifecycle(t *testing.T) {
	t.Parallel()

	base := revokedDirectGrantResponseFixture(t)
	for _, test := range []struct {
		name   string
		mutate func(*authorization.DirectUserRoleGrant)
	}{
		{
			name: "revoked without reason",
			mutate: func(value *authorization.DirectUserRoleGrant) {
				value.RevokeReason = nil
			},
		},
		{
			name: "active with revocation metadata",
			mutate: func(value *authorization.DirectUserRoleGrant) {
				value.State = authorization.DirectRoleGrantStateActive
			},
		},
		{
			name: "expired without expiry",
			mutate: func(value *authorization.DirectUserRoleGrant) {
				value.State = authorization.DirectRoleGrantStateExpired
				value.Provenance.ExpiresAt = nil
				value.RevokedAt = nil
				value.RevokedByUserID = nil
				value.RevokeReason = nil
			},
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := base
			test.mutate(&value)
			if _, err := mapDirectRoleGrant(value); err == nil {
				t.Fatal("mapDirectRoleGrant() unexpectedly accepted an invalid lifecycle")
			}
		})
	}
}

func TestDirectRoleGrantExactReplayReturnsRevokedCurrentRepresentation(t *testing.T) {
	t.Parallel()

	grant := revokedDirectGrantResponseFixture(t)
	var captured authorization.GrantUserRoleInput
	service := &idempotencyReplayTransportStub{grantUserRoleFunc: func(
		_ context.Context,
		_ authorization.Actor,
		tenantID, userID uuid.UUID,
		input authorization.GrantUserRoleInput,
	) (authorization.DirectUserRoleGrant, error) {
		if tenantID != grant.TenantID || userID != grant.UserID {
			t.Fatalf("tenant/user = %s/%s", tenantID, userID)
		}
		captured = input
		return grant, nil
	}}
	request := tenantGroupMutationRequest(
		grant.TenantID,
		http.MethodPost,
		"/api/v1/tenants/"+grant.TenantID.String()+"/users/"+grant.UserID.String()+"/role-grants",
		`{"roleId":"`+grant.Role.ID.String()+`","reason":"Temporary incident response access"}`,
	)
	request.Header.Set(idempotencyKeyHeader, "direct-grant-replay-0123456789")
	response := httptest.NewRecorder()

	newTenantAuthorizationTestRouter(
		t,
		groupTransportAuthentication(grant.TenantID, *grant.RevokedByUserID),
		service,
	).ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if captured.IdempotencyKey != "direct-grant-replay-0123456789" {
		t.Fatalf("idempotency key = %q", captured.IdempotencyKey)
	}
	wantETag, err := authorization.DirectUserRoleGrantEntityTag(grant)
	if err != nil {
		t.Fatalf("DirectUserRoleGrantEntityTag(): %v", err)
	}
	if response.Header().Get("ETag") != wantETag {
		t.Fatalf("ETag = %q, want %q", response.Header().Get("ETag"), wantETag)
	}
	var document contract.DirectUserRoleGrant
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if document.State != contract.DirectRoleGrantStateRevoked ||
		document.RevokeReason == nil || *document.RevokeReason != *grant.RevokeReason ||
		document.RevokedAt == nil || document.RevokedByUserId == nil ||
		string(document.Etag) != wantETag {
		t.Fatalf("current replay response = %#v", document)
	}
}

func revokedDirectGrantResponseFixture(t *testing.T) authorization.DirectUserRoleGrant {
	t.Helper()

	tenantID := uuid.Must(uuid.NewV7())
	userID := uuid.Must(uuid.NewV7())
	roleID := uuid.Must(uuid.NewV7())
	edgeID := uuid.Must(uuid.NewV7())
	sourceID := uuid.Must(uuid.NewV7())
	revokerID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Second)
	revokedAt := now.Add(-time.Minute)
	revokeReason := "Access removed after incident closure"
	return authorization.DirectUserRoleGrant{
		ID: edgeID, TenantID: tenantID, UserID: userID,
		ManagedByAuthorizationAPI: true,
		Role: authorization.TenantRoleSummary{
			ID: roleID, TenantID: tenantID, Key: "incident_responder", Name: "Incident responder",
			Version: 1, CreatedAt: now.Add(-24 * time.Hour), UpdatedAt: now.Add(-time.Hour),
		},
		Provenance: authorization.RoleGrantProvenance{
			SourceType: authorization.RoleGrantSourceDirect,
			SourceKind: authorization.AuthorizationSourceManual,
			SourceID:   &sourceID, GrantedByUserID: &revokerID,
			GrantedAt: now.Add(-2 * time.Hour), Reason: "Temporary incident response access",
		},
		PathType:  authorization.RoleGrantPathDirect,
		State:     authorization.DirectRoleGrantStateRevoked,
		RevokedAt: &revokedAt, RevokedByUserID: &revokerID, RevokeReason: &revokeReason,
		Version: 2, UpdatedAt: now,
	}
}
