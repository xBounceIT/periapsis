package httpserver

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
)

func (h *Handler) ListTenantSecurityGroups(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.ListTenantSecurityGroupsParams,
) {
	actor, ok := h.tenantAuthorizationActor(w, r)
	if !ok {
		return
	}
	pageInput, err := pageInput(params.After, params.Limit)
	if err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	page, err := h.authorization.ListTenantSecurityGroups(
		r.Context(),
		actor,
		uuid.UUID(tenantID),
		authorization.ListTenantSecurityGroupsInput{
			PageInput:       pageInput,
			IncludeArchived: params.IncludeArchived != nil && *params.IncludeArchived,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	items := make([]contract.TenantSecurityGroup, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, mapTenantSecurityGroup(item))
	}
	writeSensitiveJSON(w, http.StatusOK, contract.TenantSecurityGroupList{
		Items: items, NextCursor: page.NextCursor,
	})
}

func (h *Handler) CreateTenantSecurityGroup(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	_ contract.CreateTenantSecurityGroupParams,
) {
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	var body contract.TenantSecurityGroupCreateRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	description := ""
	if body.Description != nil {
		description = *body.Description
	}
	group, err := h.authorization.CreateTenantSecurityGroup(
		r.Context(), actor, uuid.UUID(tenantID), authorization.CreateTenantSecurityGroupInput{
			Key: body.Key, Name: body.Name, Description: description,
			IdempotencyKey: idempotencyKey, Audit: audit,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeTenantSecurityGroup(w, r, http.StatusCreated, group)
}

func (h *Handler) GetTenantSecurityGroup(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	groupID contract.GroupId,
) {
	actor, ok := h.tenantAuthorizationActor(w, r)
	if !ok {
		return
	}
	group, err := h.authorization.GetTenantSecurityGroup(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(groupID),
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeTenantSecurityGroup(w, r, http.StatusOK, group)
}

func (h *Handler) UpdateTenantSecurityGroup(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	groupID contract.GroupId,
	_ contract.UpdateTenantSecurityGroupParams,
) {
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return
	}
	version, err := requestedVersion(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body contract.TenantSecurityGroupPatchRequest
	if err := decodeAuthorizationBody(r, &body, "application/merge-patch+json"); err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	group, err := h.authorization.UpdateTenantSecurityGroup(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(groupID),
		authorization.UpdateTenantSecurityGroupInput{
			Name: body.Name, Description: body.Description, ExpectedVersion: version, Audit: audit,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeTenantSecurityGroup(w, r, http.StatusOK, group)
}

func (h *Handler) ArchiveTenantSecurityGroup(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	groupID contract.GroupId,
	_ contract.ArchiveTenantSecurityGroupParams,
) {
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return
	}
	version, err := requestedVersion(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if err := h.authorization.ArchiveTenantSecurityGroup(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(groupID),
		authorization.ArchiveTenantSecurityGroupInput{ExpectedVersion: version, Audit: audit},
	); err != nil {
		writeDomainError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ListTenantSecurityGroupMemberships(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	groupID contract.GroupId,
	params contract.ListTenantSecurityGroupMembershipsParams,
) {
	actor, ok := h.tenantAuthorizationActor(w, r)
	if !ok {
		return
	}
	pageInput, err := pageInput(params.After, params.Limit)
	if err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	page, err := h.authorization.ListTenantSecurityGroupMemberships(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(groupID),
		authorization.ListTenantSecurityGroupEdgesInput{
			PageInput:      pageInput,
			IncludeRevoked: params.IncludeRevoked != nil && *params.IncludeRevoked,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	items := make([]contract.TenantSecurityGroupMembership, 0, len(page.Items))
	for _, item := range page.Items {
		mapped, mapErr := mapTenantSecurityGroupMembership(item)
		if mapErr != nil {
			writeDomainError(w, r, authorization.ErrUnavailable)
			return
		}
		items = append(items, mapped)
	}
	writeSensitiveJSON(w, http.StatusOK, contract.TenantSecurityGroupMembershipList{
		Items: items, NextCursor: page.NextCursor,
	})
}

func (h *Handler) CreateTenantSecurityGroupMembership(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	groupID contract.GroupId,
	_ contract.CreateTenantSecurityGroupMembershipParams,
) {
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	var body contract.TenantSecurityGroupMembershipCreateRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	edge, err := h.authorization.AddTenantSecurityGroupMembership(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(groupID),
		authorization.AddTenantSecurityGroupMembershipInput{
			UserID: uuid.UUID(body.UserId), Reason: body.Reason, ExpiresAt: body.ExpiresAt,
			IdempotencyKey: idempotencyKey, Audit: audit,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapTenantSecurityGroupMembership(edge)
	if err != nil || !setEdgeEntityTag(w, string(mapped.Etag)) {
		writeDomainError(w, r, authorization.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) RevokeTenantSecurityGroupMembership(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	groupID contract.GroupId,
	membershipID contract.GroupMembershipId,
	_ contract.RevokeTenantSecurityGroupMembershipParams,
) {
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return
	}
	entityTag, err := requestedEdgeEntityTag(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body contract.AuthorizationEdgeRevokeRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	if err := h.authorization.RevokeTenantSecurityGroupMembership(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(groupID), uuid.UUID(membershipID),
		authorization.RevokeTenantSecurityGroupMembershipInput{
			Reason: body.Reason, ExpectedEntityTag: entityTag, Audit: audit,
		},
	); err != nil {
		writeDomainError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ListTenantSecurityGroupRoleGrants(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	groupID contract.GroupId,
	params contract.ListTenantSecurityGroupRoleGrantsParams,
) {
	actor, ok := h.tenantAuthorizationActor(w, r)
	if !ok {
		return
	}
	pageInput, err := pageInput(params.After, params.Limit)
	if err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	page, err := h.authorization.ListTenantSecurityGroupRoleGrants(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(groupID),
		authorization.ListTenantSecurityGroupEdgesInput{
			PageInput:      pageInput,
			IncludeRevoked: params.IncludeRevoked != nil && *params.IncludeRevoked,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	items := make([]contract.TenantSecurityGroupRoleGrant, 0, len(page.Items))
	for _, item := range page.Items {
		mapped, mapErr := mapTenantSecurityGroupRoleGrant(item)
		if mapErr != nil {
			writeDomainError(w, r, authorization.ErrUnavailable)
			return
		}
		items = append(items, mapped)
	}
	writeSensitiveJSON(w, http.StatusOK, contract.TenantSecurityGroupRoleGrantList{
		Items: items, NextCursor: page.NextCursor,
	})
}

func (h *Handler) GrantTenantSecurityGroupRole(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	groupID contract.GroupId,
	_ contract.GrantTenantSecurityGroupRoleParams,
) {
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	var body contract.TenantSecurityGroupRoleGrantRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	edge, err := h.authorization.GrantTenantSecurityGroupRole(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(groupID),
		authorization.GrantTenantSecurityGroupRoleInput{
			RoleID: uuid.UUID(body.RoleId), Reason: body.Reason, ExpiresAt: body.ExpiresAt,
			IdempotencyKey: idempotencyKey, Audit: audit,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapTenantSecurityGroupRoleGrant(edge)
	if err != nil || !setEdgeEntityTag(w, string(mapped.Etag)) {
		writeDomainError(w, r, authorization.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) RevokeTenantSecurityGroupRoleGrant(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	groupID contract.GroupId,
	grantID contract.GroupRoleGrantId,
	_ contract.RevokeTenantSecurityGroupRoleGrantParams,
) {
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return
	}
	entityTag, err := requestedEdgeEntityTag(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body contract.AuthorizationEdgeRevokeRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	if err := h.authorization.RevokeTenantSecurityGroupRoleGrant(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(groupID), uuid.UUID(grantID),
		authorization.RevokeTenantSecurityGroupRoleGrantInput{
			Reason: body.Reason, ExpectedEntityTag: entityTag, Audit: audit,
		},
	); err != nil {
		writeDomainError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) writeTenantSecurityGroup(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	group authorization.TenantSecurityGroup,
) {
	if !setVersionETag(w, group.Version) {
		writeDomainError(w, r, authorization.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, status, mapTenantSecurityGroup(group))
}
