package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/alert"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/serviceaccount"
)

var (
	serviceAccountKeyPattern       = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)
	serviceAccountSourceKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,126}[a-z0-9]$`)
)

func (h *Handler) ListTenantServiceAccounts(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.ListTenantServiceAccountsParams,
) {
	actor, tenant, ok := h.serviceAccountHumanActor(w, r, tenantID)
	if !ok {
		return
	}
	page, err := serviceAccountPageInput(params.After, params.Limit)
	if err != nil {
		h.writeServiceAccountError(w, r, err)
		return
	}
	result, err := h.serviceAccounts.ListAccounts(r.Context(), actor, tenant, serviceaccount.ListAccountsInput{
		PageInput: page, IncludeArchived: params.IncludeArchived != nil && *params.IncludeArchived,
	})
	if err != nil {
		h.writeServiceAccountError(w, r, err)
		return
	}
	if !validServiceAccountPage(page, result.Items, result.NextCursor, func(value serviceaccount.Account) uuid.UUID { return value.ID }) {
		h.writeServiceAccountError(w, r, serviceaccount.ErrUnavailable)
		return
	}
	items := make([]contract.ServiceAccount, 0, len(result.Items))
	for _, item := range result.Items {
		mapped, mapErr := mapServiceAccount(item, tenant)
		if mapErr != nil {
			h.writeServiceAccountError(w, r, serviceaccount.ErrUnavailable)
			return
		}
		items = append(items, mapped)
	}
	writeSensitiveJSON(w, http.StatusOK, contract.ServiceAccountList{Items: items, NextCursor: result.NextCursor})
}

func (h *Handler) CreateTenantServiceAccount(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId) {
	actor, audit, tenant, ok := h.prepareServiceAccountMutation(w, r, tenantID)
	if !ok {
		return
	}
	var body contract.ServiceAccountCreateRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		h.writeServiceAccountError(w, r, serviceaccount.ErrInvalidInput)
		return
	}
	description := ""
	if body.Description != nil {
		description = *body.Description
	}
	result, err := h.serviceAccounts.CreateAccount(r.Context(), actor, tenant, serviceaccount.CreateAccountInput{
		Key: body.Key, DisplayName: body.DisplayName, Description: description, Audit: audit,
	})
	if err != nil {
		h.writeServiceAccountError(w, r, err)
		return
	}
	if result.State != serviceaccount.AccountStateActive {
		h.writeServiceAccountError(w, r, serviceaccount.ErrUnavailable)
		return
	}
	mapped, err := mapServiceAccount(result, tenant)
	if err != nil || !setVersionETag(w, result.Version) {
		h.writeServiceAccountError(w, r, serviceaccount.ErrUnavailable)
		return
	}
	w.Header().Set("Location", serviceAccountLocation(tenant, result.ID))
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) GetTenantServiceAccount(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	serviceAccountID contract.ServiceAccountId,
) {
	actor, tenant, ok := h.serviceAccountHumanActor(w, r, tenantID)
	if !ok {
		return
	}
	result, err := h.serviceAccounts.GetAccount(r.Context(), actor, tenant, uuid.UUID(serviceAccountID))
	if err != nil {
		h.writeServiceAccountError(w, r, err)
		return
	}
	if result.ID != uuid.UUID(serviceAccountID) {
		h.writeServiceAccountError(w, r, serviceaccount.ErrUnavailable)
		return
	}
	h.writeServiceAccount(w, r, http.StatusOK, tenant, result)
}

func (h *Handler) UpdateTenantServiceAccount(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	serviceAccountID contract.ServiceAccountId,
	_ contract.UpdateTenantServiceAccountParams,
) {
	actor, audit, tenant, ok := h.prepareServiceAccountMutation(w, r, tenantID)
	if !ok {
		return
	}
	version, err := requestedVersion(r)
	if err != nil {
		h.writeServiceAccountError(w, r, mapAuthorizationToServiceAccountError(err))
		return
	}
	var body contract.ServiceAccountPatchRequest
	if err := decodeAuthorizationBody(r, &body, "application/merge-patch+json"); err != nil {
		h.writeServiceAccountError(w, r, serviceaccount.ErrInvalidInput)
		return
	}
	result, err := h.serviceAccounts.UpdateAccount(
		r.Context(), actor, tenant, uuid.UUID(serviceAccountID), serviceaccount.UpdateAccountInput{
			DisplayName: body.DisplayName, Description: body.Description, ExpectedVersion: version, Audit: audit,
		},
	)
	if err != nil {
		h.writeServiceAccountError(w, r, err)
		return
	}
	if result.ID != uuid.UUID(serviceAccountID) {
		h.writeServiceAccountError(w, r, serviceaccount.ErrUnavailable)
		return
	}
	if result.State != serviceaccount.AccountStateActive {
		h.writeServiceAccountError(w, r, serviceaccount.ErrUnavailable)
		return
	}
	h.writeServiceAccount(w, r, http.StatusOK, tenant, result)
}

func (h *Handler) ArchiveTenantServiceAccount(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	serviceAccountID contract.ServiceAccountId,
	_ contract.ArchiveTenantServiceAccountParams,
) {
	actor, audit, tenant, ok := h.prepareServiceAccountMutation(w, r, tenantID)
	if !ok {
		return
	}
	version, err := requestedVersion(r)
	if err != nil {
		h.writeServiceAccountError(w, r, mapAuthorizationToServiceAccountError(err))
		return
	}
	var body contract.ServiceAccountArchiveRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		h.writeServiceAccountError(w, r, serviceaccount.ErrInvalidInput)
		return
	}
	if err := h.serviceAccounts.ArchiveAccount(
		r.Context(), actor, tenant, uuid.UUID(serviceAccountID),
		serviceaccount.ArchiveAccountInput{Reason: body.Reason, ExpectedVersion: version, Audit: audit},
	); err != nil {
		h.writeServiceAccountError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ListTenantServiceAccountRoleGrants(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	serviceAccountID contract.ServiceAccountId,
	params contract.ListTenantServiceAccountRoleGrantsParams,
) {
	actor, tenant, ok := h.serviceAccountHumanActor(w, r, tenantID)
	if !ok {
		return
	}
	page, err := serviceAccountPageInput(params.After, params.Limit)
	if err != nil {
		h.writeServiceAccountError(w, r, err)
		return
	}
	accountID := uuid.UUID(serviceAccountID)
	result, err := h.serviceAccounts.ListRoleGrants(r.Context(), actor, tenant, accountID, serviceaccount.ListRoleGrantsInput{
		PageInput: page, IncludeRevoked: params.IncludeRevoked != nil && *params.IncludeRevoked,
	})
	if err != nil {
		h.writeServiceAccountError(w, r, err)
		return
	}
	if !validServiceAccountPage(page, result.Items, result.NextCursor, func(value serviceaccount.RoleGrant) uuid.UUID { return value.ID }) {
		h.writeServiceAccountError(w, r, serviceaccount.ErrUnavailable)
		return
	}
	items := make([]contract.ServiceAccountRoleGrant, 0, len(result.Items))
	for _, item := range result.Items {
		mapped, mapErr := mapServiceAccountRoleGrant(item, tenant, accountID)
		if mapErr != nil {
			h.writeServiceAccountError(w, r, serviceaccount.ErrUnavailable)
			return
		}
		items = append(items, mapped)
	}
	writeSensitiveJSON(w, http.StatusOK, contract.ServiceAccountRoleGrantList{Items: items, NextCursor: result.NextCursor})
}

func (h *Handler) GrantTenantServiceAccountRole(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	serviceAccountID contract.ServiceAccountId,
) {
	actor, audit, tenant, ok := h.prepareServiceAccountMutation(w, r, tenantID)
	if !ok {
		return
	}
	var body contract.ServiceAccountRoleGrantRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		h.writeServiceAccountError(w, r, serviceaccount.ErrInvalidInput)
		return
	}
	accountID := uuid.UUID(serviceAccountID)
	result, err := h.serviceAccounts.GrantRole(r.Context(), actor, tenant, accountID, serviceaccount.GrantRoleInput{
		RoleID: uuid.UUID(body.RoleId), Reason: body.Reason, ExpiresAt: body.ExpiresAt, Audit: audit,
	})
	if err != nil {
		h.writeServiceAccountError(w, r, err)
		return
	}
	if result.State != serviceaccount.RoleGrantStateActive || !result.ManagedByServiceAccountAPI {
		h.writeServiceAccountError(w, r, serviceaccount.ErrUnavailable)
		return
	}
	mapped, err := mapServiceAccountRoleGrant(result, tenant, accountID)
	if err != nil || !setEdgeEntityTag(w, string(mapped.Etag)) {
		h.writeServiceAccountError(w, r, serviceaccount.ErrUnavailable)
		return
	}
	w.Header().Set("Location", serviceAccountRoleGrantLocation(tenant, accountID, result.ID))
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) RevokeTenantServiceAccountRoleGrant(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	serviceAccountID contract.ServiceAccountId,
	grantID contract.ServiceAccountRoleGrantId,
	_ contract.RevokeTenantServiceAccountRoleGrantParams,
) {
	actor, audit, tenant, ok := h.prepareServiceAccountMutation(w, r, tenantID)
	if !ok {
		return
	}
	entityTag, err := requestedEdgeEntityTag(r)
	if err != nil {
		h.writeServiceAccountError(w, r, mapAuthorizationToServiceAccountError(err))
		return
	}
	var body contract.ServiceAccountRoleGrantRevokeRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		h.writeServiceAccountError(w, r, serviceaccount.ErrInvalidInput)
		return
	}
	if err := h.serviceAccounts.RevokeRoleGrant(
		r.Context(), actor, tenant, uuid.UUID(serviceAccountID), uuid.UUID(grantID),
		serviceaccount.RevokeRoleGrantInput{Reason: body.Reason, ExpectedEntityTag: entityTag, Audit: audit},
	); err != nil {
		h.writeServiceAccountError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ListTenantServiceAccountCredentials(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	serviceAccountID contract.ServiceAccountId,
	params contract.ListTenantServiceAccountCredentialsParams,
) {
	actor, tenant, ok := h.serviceAccountHumanActor(w, r, tenantID)
	if !ok {
		return
	}
	page, err := serviceAccountPageInput(params.After, params.Limit)
	if err != nil {
		h.writeServiceAccountError(w, r, err)
		return
	}
	accountID := uuid.UUID(serviceAccountID)
	result, err := h.serviceAccounts.ListCredentials(r.Context(), actor, tenant, accountID, serviceaccount.ListCredentialsInput{
		PageInput: page, IncludeRevoked: params.IncludeRevoked != nil && *params.IncludeRevoked,
	})
	if err != nil {
		h.writeServiceAccountError(w, r, err)
		return
	}
	if !validServiceAccountPage(page, result.Items, result.NextCursor, func(value serviceaccount.CredentialMetadata) uuid.UUID { return value.ID }) {
		h.writeServiceAccountError(w, r, serviceaccount.ErrUnavailable)
		return
	}
	items := make([]contract.ServiceAccountCredential, 0, len(result.Items))
	for _, item := range result.Items {
		mapped, mapErr := mapServiceAccountCredential(item, tenant, accountID)
		if mapErr != nil {
			h.writeServiceAccountError(w, r, serviceaccount.ErrUnavailable)
			return
		}
		items = append(items, mapped)
	}
	writeSensitiveJSON(w, http.StatusOK, contract.ServiceAccountCredentialList{Items: items, NextCursor: result.NextCursor})
}

func (h *Handler) IssueTenantServiceAccountCredential(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	serviceAccountID contract.ServiceAccountId,
	_ contract.IssueTenantServiceAccountCredentialParams,
) {
	actor, audit, tenant, ok := h.prepareServiceAccountMutation(w, r, tenantID)
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil {
		h.writeServiceAccountError(w, r, serviceaccount.ErrInvalidInput)
		return
	}
	var body contract.ServiceAccountCredentialIssueRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		h.writeServiceAccountError(w, r, serviceaccount.ErrInvalidInput)
		return
	}
	permissions, networks, err := serviceAccountCredentialRequestParts(body.Permissions, body.AllowedNetworks)
	if err != nil {
		h.writeServiceAccountError(w, r, err)
		return
	}
	accountID := uuid.UUID(serviceAccountID)
	result, err := h.serviceAccounts.IssueCredential(r.Context(), actor, tenant, accountID, serviceaccount.IssueCredentialInput{
		Label: body.Label, ExpiresAt: body.ExpiresAt, Permissions: permissions, Networks: networks,
		IdempotencyKey: idempotencyKey, Audit: audit,
	})
	if err != nil {
		h.writeCredentialMutationError(w, r, tenant, accountID, err)
		return
	}
	h.writeServiceAccountCredentialSecret(w, r, tenant, accountID, nil, result)
}

func (h *Handler) GetTenantServiceAccountCredential(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	serviceAccountID contract.ServiceAccountId,
	credentialID contract.ServiceAccountCredentialId,
) {
	actor, tenant, ok := h.serviceAccountHumanActor(w, r, tenantID)
	if !ok {
		return
	}
	accountID := uuid.UUID(serviceAccountID)
	result, err := h.serviceAccounts.GetCredential(r.Context(), actor, tenant, accountID, uuid.UUID(credentialID))
	if err != nil {
		h.writeServiceAccountError(w, r, err)
		return
	}
	if result.ID != uuid.UUID(credentialID) {
		h.writeServiceAccountError(w, r, serviceaccount.ErrUnavailable)
		return
	}
	mapped, err := mapServiceAccountCredential(result, tenant, accountID)
	if err != nil || !setVersionETag(w, result.Version) {
		h.writeServiceAccountError(w, r, serviceaccount.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) RevokeTenantServiceAccountCredential(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	serviceAccountID contract.ServiceAccountId,
	credentialID contract.ServiceAccountCredentialId,
	_ contract.RevokeTenantServiceAccountCredentialParams,
) {
	actor, audit, tenant, ok := h.prepareServiceAccountMutation(w, r, tenantID)
	if !ok {
		return
	}
	version, err := requestedVersion(r)
	if err != nil {
		h.writeServiceAccountError(w, r, mapAuthorizationToServiceAccountError(err))
		return
	}
	var body contract.ServiceAccountCredentialRevokeRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		h.writeServiceAccountError(w, r, serviceaccount.ErrInvalidInput)
		return
	}
	if err := h.serviceAccounts.RevokeCredential(
		r.Context(), actor, tenant, uuid.UUID(serviceAccountID), uuid.UUID(credentialID),
		serviceaccount.RevokeCredentialInput{Reason: body.Reason, ExpectedVersion: version, Audit: audit},
	); err != nil {
		h.writeServiceAccountError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) RotateTenantServiceAccountCredential(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	serviceAccountID contract.ServiceAccountId,
	credentialID contract.ServiceAccountCredentialId,
	_ contract.RotateTenantServiceAccountCredentialParams,
) {
	actor, audit, tenant, ok := h.prepareServiceAccountMutation(w, r, tenantID)
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil {
		h.writeServiceAccountError(w, r, serviceaccount.ErrInvalidInput)
		return
	}
	version, err := requestedVersion(r)
	if err != nil {
		h.writeServiceAccountError(w, r, mapAuthorizationToServiceAccountError(err))
		return
	}
	var body contract.ServiceAccountCredentialRotateRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		h.writeServiceAccountError(w, r, serviceaccount.ErrInvalidInput)
		return
	}
	permissions, networks, err := serviceAccountCredentialRequestParts(body.Permissions, body.AllowedNetworks)
	if err != nil {
		h.writeServiceAccountError(w, r, err)
		return
	}
	accountID := uuid.UUID(serviceAccountID)
	result, err := h.serviceAccounts.RotateCredential(
		r.Context(), actor, tenant, accountID, uuid.UUID(credentialID), serviceaccount.RotateCredentialInput{
			Label: body.Label, ExpiresAt: body.ExpiresAt, Permissions: permissions, Networks: networks,
			Reason: body.RevokeReason, IdempotencyKey: idempotencyKey, ExpectedVersion: version, Audit: audit,
		},
	)
	if err != nil {
		h.writeCredentialMutationError(w, r, tenant, accountID, err)
		return
	}
	previousCredentialID := uuid.UUID(credentialID)
	h.writeServiceAccountCredentialSecret(w, r, tenant, accountID, &previousCredentialID, result)
}

func (h *Handler) CreateTenantAlert(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	_ contract.CreateTenantAlertParams,
) {
	w = &alertAuthenticationResponseWriter{ResponseWriter: w}
	if !h.requireApplication(w, r) {
		return
	}
	tenant := uuid.UUID(tenantID)
	if !validTenantAuthorizationCursor(tenant) {
		h.writeAlertError(w, r, alert.ErrInvalidInput)
		return
	}
	hasCookie := requestHasSessionCookie(r, h.cookie.name)
	hasAuthorization := len(r.Header.Values("Authorization")) != 0
	if hasCookie == hasAuthorization {
		h.writeAlertError(w, r, alert.ErrUnauthenticated)
		return
	}
	var (
		actor authorization.Actor
		audit authorization.AuditContext
		token string
	)
	if hasCookie {
		var ok bool
		actor, audit, _, ok = h.prepareServiceAccountMutation(w, r, tenantID)
		if !ok {
			return
		}
	} else {
		if len(r.Header.Values(csrfTokenHeader)) != 0 {
			h.writeAlertError(w, r, alert.ErrUnauthenticated)
			return
		}
		var err error
		token, err = h.bearerToken(r)
		if err != nil {
			h.writeAlertError(w, r, alert.ErrUnauthenticated)
			return
		}
		event, err := h.eventContext(r)
		if err != nil {
			h.writeAlertError(w, r, alert.ErrInvalidInput)
			return
		}
		audit = authorization.AuditContext{
			RequestID: event.RequestID, CorrelationID: event.CorrelationID,
			RemoteAddress: event.RemoteAddress, UserAgent: event.UserAgent,
		}
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil {
		h.writeAlertError(w, r, alert.ErrInvalidInput)
		return
	}
	var body contract.AlertCreateRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil || !body.Severity.Valid() {
		h.writeAlertError(w, r, alert.ErrInvalidInput)
		return
	}
	customFields, mapErr := contractCustomFields(body.CustomFields)
	if mapErr != nil {
		h.writeAlertError(w, r, alert.ErrInvalidInput)
		return
	}
	rawPayload, mapErr := contractAlertRawPayload(body.RawPayload)
	if mapErr != nil {
		h.writeAlertError(w, r, alert.ErrInvalidInput)
		return
	}
	input := alert.CreateInput{
		ExternalID: body.ExternalId, Title: body.Title, Description: body.Description,
		Severity: alert.Severity(body.Severity), IdempotencyKey: idempotencyKey,
		DeduplicationKey: body.DeduplicationKey, Classification: body.Classification,
		CustomFields: customFields, RawPayload: rawPayload, Audit: audit,
		AssignedTeamID: body.AssignedTeamId, AssigneeUserID: body.AssigneeUserId,
	}
	if body.WorkflowId != nil {
		value := uuid.UUID(*body.WorkflowId)
		input.WorkflowID = &value
	}
	if body.Priority != nil {
		input.Priority = string(*body.Priority)
	}
	if body.Category != nil {
		input.Category = *body.Category
	}
	if body.Source != nil {
		input.Source = *body.Source
	}
	if body.SourceType != nil {
		input.SourceType = *body.SourceType
	}
	if body.CustomerVisible != nil {
		input.CustomerVisible = *body.CustomerVisible
	}
	if body.DetectedAt != nil {
		input.DetectedAt = body.DetectedAt.UTC()
	}
	if body.Tags != nil {
		input.Tags, err = canonicalStrings(*body.Tags)
		if err != nil {
			h.writeAlertError(w, r, alert.ErrInvalidInput)
			return
		}
	}
	var result alert.Alert
	if hasCookie {
		result, err = h.alerts.CreateAsHuman(r.Context(), actor, tenant, input)
	} else {
		result, err = h.alerts.CreateAsBearer(r.Context(), tenant, alert.BearerCreateInput{CreateInput: input, Token: token})
	}
	if err != nil {
		h.writeAlertError(w, r, err)
		return
	}
	mapped, err := mapCreatedAlert(result, tenant)
	if err != nil || !setVersionETag(w, result.Version) {
		h.writeAlertError(w, r, alert.ErrUnavailable)
		return
	}
	w.Header().Set("Location", tenantAlertLocation(tenant, result.ID))
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

type alertAuthenticationResponseWriter struct {
	http.ResponseWriter
}

func (w *alertAuthenticationResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *alertAuthenticationResponseWriter) WriteHeader(status int) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="periapsis"`)
	}
	w.ResponseWriter.WriteHeader(status)
}

func (h *Handler) serviceAccountHumanActor(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
) (authorization.Actor, uuid.UUID, bool) {
	actor, ok := h.tenantAuthorizationActor(w, r)
	if !ok {
		return authorization.Actor{}, uuid.Nil, false
	}
	tenant := uuid.UUID(tenantID)
	if !validTenantAuthorizationCursor(tenant) {
		h.writeServiceAccountError(w, r, serviceaccount.ErrInvalidInput)
		return authorization.Actor{}, uuid.Nil, false
	}
	if actor.ActiveTenantID != tenant {
		h.writeServiceAccountError(w, r, serviceaccount.ErrForbidden)
		return authorization.Actor{}, uuid.Nil, false
	}
	return actor, tenant, true
}

func (h *Handler) prepareServiceAccountMutation(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
) (authorization.Actor, authorization.AuditContext, uuid.UUID, bool) {
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return authorization.Actor{}, authorization.AuditContext{}, uuid.Nil, false
	}
	tenant := uuid.UUID(tenantID)
	if !validTenantAuthorizationCursor(tenant) {
		h.writeServiceAccountError(w, r, serviceaccount.ErrInvalidInput)
		return authorization.Actor{}, authorization.AuditContext{}, uuid.Nil, false
	}
	if actor.ActiveTenantID != tenant {
		h.writeServiceAccountError(w, r, serviceaccount.ErrForbidden)
		return authorization.Actor{}, authorization.AuditContext{}, uuid.Nil, false
	}
	return actor, audit, tenant, true
}

func requestHasSessionCookie(r *http.Request, name string) bool {
	for _, cookie := range r.Cookies() {
		if cookie.Name == name {
			return true
		}
	}
	return false
}

func serviceAccountPageInput(after *contract.AfterCursor, limit *contract.PageSize) (serviceaccount.PageInput, error) {
	input, err := pageInput(after, limit)
	if err != nil {
		return serviceaccount.PageInput{}, serviceaccount.ErrInvalidInput
	}
	return serviceaccount.PageInput{After: input.After, Limit: input.Limit}, nil
}

func validServiceAccountPage[T any](
	input serviceaccount.PageInput,
	items []T,
	nextCursor *uuid.UUID,
	cursor func(T) uuid.UUID,
) bool {
	return validTenantAuthorizationPage(
		authorization.PageInput{After: input.After, Limit: input.Limit}, items, nextCursor, cursor,
	)
}

func serviceAccountCredentialRequestParts(
	permissions []contract.ServiceAccountCredentialPermissionGrant,
	networks []contract.ServiceAccountCredentialCidr,
) ([]authorization.ScopedPermission, []netip.Prefix, error) {
	if permissions == nil || networks == nil || len(permissions) != 1 {
		return nil, nil, serviceaccount.ErrInvalidInput
	}
	mappedPermissions := make([]authorization.ScopedPermission, len(permissions))
	for index, permission := range permissions {
		if !permission.PermissionKey.Valid() || !permission.Scope.Valid() {
			return nil, nil, serviceaccount.ErrInvalidInput
		}
		mappedPermissions[index] = authorization.ScopedPermission{
			Permission: authorization.TenantPermission(permission.PermissionKey),
			Scope:      authorization.Scope(permission.Scope),
		}
	}
	if len(networks) > 32 {
		return nil, nil, serviceaccount.ErrInvalidInput
	}
	mappedNetworks := make([]netip.Prefix, len(networks))
	seen := make(map[netip.Prefix]struct{}, len(networks))
	for index, value := range networks {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || !prefix.IsValid() || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() ||
			prefix != prefix.Masked() || prefix.String() != value {
			return nil, nil, serviceaccount.ErrInvalidInput
		}
		if _, duplicate := seen[prefix]; duplicate {
			return nil, nil, serviceaccount.ErrInvalidInput
		}
		seen[prefix] = struct{}{}
		mappedNetworks[index] = prefix
	}
	return mappedPermissions, mappedNetworks, nil
}

func (h *Handler) writeServiceAccount(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	tenantID uuid.UUID,
	value serviceaccount.Account,
) {
	mapped, err := mapServiceAccount(value, tenantID)
	if err != nil || !setVersionETag(w, value.Version) {
		h.writeServiceAccountError(w, r, serviceaccount.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, status, mapped)
}

func (h *Handler) writeServiceAccountCredentialSecret(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
	serviceAccountID uuid.UUID,
	expectedRotatedFrom *uuid.UUID,
	value serviceaccount.CredentialSecret,
) {
	mapped, err := mapServiceAccountCredential(value.Credential, tenantID, serviceAccountID)
	if err != nil || value.Credential.State != serviceaccount.CredentialStateActive ||
		!equalOptionalServicePrincipalUUID(value.Credential.RotatedFromCredentialID, expectedRotatedFrom) ||
		!validBearerCredential(value.Token) || !setVersionETag(w, value.Credential.Version) {
		h.writeServiceAccountError(w, r, serviceaccount.ErrUnavailable)
		return
	}
	w.Header().Set("Location", serviceAccountCredentialLocation(tenantID, serviceAccountID, value.Credential.ID))
	writeSensitiveJSON(w, http.StatusCreated, contract.ServiceAccountCredentialSecret{
		Credential: mapped, BearerToken: value.Token,
	})
}

func validBearerCredential(value string) bool {
	if len(value) < 64 || len(value) > 512 {
		return false
	}
	for _, character := range value {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._~-", character) {
			continue
		}
		return false
	}
	return true
}

func mapServiceAccount(value serviceaccount.Account, tenantID uuid.UUID) (contract.ServiceAccount, error) {
	state := contract.ServiceAccountState(value.State)
	if !validTenantAuthorizationCursor(value.ID) || value.TenantID != tenantID ||
		!serviceAccountKeyPattern.MatchString(value.Key) ||
		!validBoundedText(value.DisplayName, 1, 120) || value.DisplayName != strings.TrimSpace(value.DisplayName) ||
		!validBoundedText(value.Description, 0, 500) || value.Description != strings.TrimSpace(value.Description) ||
		!validTenantAuthorizationCursor(value.CreatedByMembershipID) || !state.Valid() ||
		!validResourceVersion(value.Version) || !validServicePrincipalStoredTime(value.CreatedAt) ||
		!validServicePrincipalStoredTime(value.UpdatedAt) || value.UpdatedAt.Before(value.CreatedAt) {
		return contract.ServiceAccount{}, errors.New("invalid service-account projection")
	}
	if state == contract.ServiceAccountStateActive &&
		(value.ArchivedAt != nil || value.ArchivedByMembershipID != nil || value.ArchiveReason != nil) {
		return contract.ServiceAccount{}, errors.New("active service account contains archive metadata")
	}
	if state == contract.ServiceAccountStateArchived &&
		(value.ArchivedAt == nil || value.ArchivedByMembershipID == nil || value.ArchiveReason == nil ||
			!validServicePrincipalStoredTime(*value.ArchivedAt) || !validTenantAuthorizationCursor(*value.ArchivedByMembershipID) ||
			value.ArchivedAt.Before(value.CreatedAt) || value.UpdatedAt.Before(*value.ArchivedAt) ||
			!validBoundedText(*value.ArchiveReason, 1, 500) || *value.ArchiveReason != strings.TrimSpace(*value.ArchiveReason)) {
		return contract.ServiceAccount{}, errors.New("archived service account lacks archive metadata")
	}
	return contract.ServiceAccount{
		Id: value.ID, TenantId: value.TenantID, Key: value.Key, DisplayName: value.DisplayName,
		Description: value.Description, PrincipalType: contract.ServiceAccountPrincipalTypeServiceAccount,
		State: state, CreatedByMembershipId: value.CreatedByMembershipID,
		ArchivedAt: value.ArchivedAt, ArchivedByMembershipId: value.ArchivedByMembershipID,
		ArchiveReason: value.ArchiveReason, Version: value.Version,
		CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt,
	}, nil
}

func mapServiceAccountRoleGrant(
	value serviceaccount.RoleGrant,
	tenantID uuid.UUID,
	serviceAccountID uuid.UUID,
) (contract.ServiceAccountRoleGrant, error) {
	state := contract.AuthorizationEdgeState(value.State)
	sourceKind := contract.AuthorizationSourceKind(value.SourceKind)
	if !validTenantAuthorizationCursor(value.ID) || value.TenantID != tenantID || value.ServiceAccountID != serviceAccountID ||
		!validTenantAuthorizationCursor(value.Role.ID) || !serviceAccountKeyPattern.MatchString(value.Role.Key) ||
		!validBoundedText(value.Role.DisplayName, 1, 120) || value.Role.DisplayName != strings.TrimSpace(value.Role.DisplayName) ||
		!validTenantAuthorizationCursor(value.SourceID) || !sourceKind.Valid() || !serviceAccountSourceKeyPattern.MatchString(value.SourceKey) ||
		!validTenantAuthorizationCursor(value.GrantedByMembershipID) || !validTenantAuthorizationCursor(value.GrantedByUserID) ||
		!validBoundedText(value.GrantReason, 1, 500) || value.GrantReason != strings.TrimSpace(value.GrantReason) ||
		!validServicePrincipalStoredTime(value.GrantedAt) || !state.Valid() || !validResourceVersion(value.Version) ||
		!validServicePrincipalStoredTime(value.UpdatedAt) || value.UpdatedAt.Before(value.GrantedAt) {
		return contract.ServiceAccountRoleGrant{}, errors.New("invalid service-account role-grant projection")
	}
	if value.ExpiresAt != nil && (!validServicePrincipalStoredTime(*value.ExpiresAt) || !value.ExpiresAt.After(value.GrantedAt)) {
		return contract.ServiceAccountRoleGrant{}, errors.New("invalid service-account role-grant expiry")
	}
	if value.SourceRetiredAt != nil && !validServicePrincipalStoredTime(*value.SourceRetiredAt) {
		return contract.ServiceAccountRoleGrant{}, errors.New("invalid service-account role-grant source retirement")
	}
	if state == contract.AuthorizationEdgeStateActive && value.SourceRetiredAt != nil {
		return contract.ServiceAccountRoleGrant{}, errors.New("active service-account role grant has a retired source")
	}
	managed := value.SourceKind == authorization.AuthorizationSourceManual && value.SourceKey == "manual" &&
		!value.SourceAuthoritative && value.SourceRetiredAt == nil
	if managed != value.ManagedByServiceAccountAPI {
		return contract.ServiceAccountRoleGrant{}, errors.New("incoherent service-account role-grant ownership")
	}
	if state == contract.AuthorizationEdgeStateRevoked {
		if value.RevokedAt == nil || value.RevokedByMembershipID == nil || value.RevokedByUserID == nil || value.RevokeReason == nil ||
			!validServicePrincipalStoredTime(*value.RevokedAt) || !validTenantAuthorizationCursor(*value.RevokedByMembershipID) ||
			!validTenantAuthorizationCursor(*value.RevokedByUserID) || value.RevokedAt.Before(value.GrantedAt) ||
			value.UpdatedAt.Before(*value.RevokedAt) || !validBoundedText(*value.RevokeReason, 1, 500) ||
			*value.RevokeReason != strings.TrimSpace(*value.RevokeReason) {
			return contract.ServiceAccountRoleGrant{}, errors.New("revoked service-account role grant lacks metadata")
		}
	} else if value.RevokedAt != nil || value.RevokedByMembershipID != nil || value.RevokedByUserID != nil || value.RevokeReason != nil {
		return contract.ServiceAccountRoleGrant{}, errors.New("live service-account role grant contains revocation metadata")
	}
	entityTag, err := serviceaccount.RoleGrantEntityTag(value)
	if err != nil {
		return contract.ServiceAccountRoleGrant{}, err
	}
	grantedByUserID := value.GrantedByUserID
	return contract.ServiceAccountRoleGrant{
		Id: value.ID, TenantId: value.TenantID, ServiceAccountId: value.ServiceAccountID,
		Role: contract.ServiceAccountRoleReference{
			Id: value.Role.ID, Key: value.Role.Key, Name: value.Role.DisplayName,
			PrincipalKind: contract.ServiceAccountRoleReferencePrincipalKindServiceAccount, System: value.Role.System,
		},
		Provenance: contract.AuthorizationEdgeProvenance{
			SourceId: value.SourceID, SourceKind: sourceKind, Authoritative: value.SourceAuthoritative,
			RetiredAt: value.SourceRetiredAt, GrantedByUserId: &grantedByUserID,
			GrantedAt: value.GrantedAt, Reason: value.GrantReason, ExpiresAt: value.ExpiresAt,
		},
		State: state, ManagedByServiceAccountApi: value.ManagedByServiceAccountAPI,
		Etag: entityTag, RevokedAt: value.RevokedAt,
		RevokedByUserId: value.RevokedByUserID, RevokeReason: value.RevokeReason,
		Version: value.Version, UpdatedAt: value.UpdatedAt,
	}, nil
}

func mapServiceAccountCredential(
	value serviceaccount.CredentialMetadata,
	tenantID uuid.UUID,
	serviceAccountID uuid.UUID,
) (contract.ServiceAccountCredential, error) {
	state := contract.ServiceAccountCredentialState(value.State)
	if !validTenantAuthorizationCursor(value.ID) || value.TenantID != tenantID || value.ServiceAccountID != serviceAccountID ||
		!validBoundedText(value.Label, 1, 120) || value.Label != strings.TrimSpace(value.Label) ||
		value.FormatVersion != 1 || value.KeyVersion < 1 || !validTenantAuthorizationCursor(value.IssuedByMembershipID) ||
		!validServicePrincipalStoredTime(value.IssuedAt) || !validServicePrincipalStoredTime(value.ExpiresAt) ||
		!value.ExpiresAt.After(value.IssuedAt) || value.ExpiresAt.After(value.IssuedAt.Add(90*24*time.Hour)) ||
		!state.Valid() || !validResourceVersion(value.Version) || !validServicePrincipalStoredTime(value.UpdatedAt) ||
		value.UpdatedAt.Before(value.IssuedAt) {
		return contract.ServiceAccountCredential{}, errors.New("invalid service-account credential projection")
	}
	permissions := make([]contract.ServiceAccountCredentialPermissionGrant, len(value.Permissions))
	if len(permissions) != 1 {
		return contract.ServiceAccountCredential{}, errors.New("invalid service-account credential permissions")
	}
	for index, permission := range value.Permissions {
		mappedPermission := contract.ServiceAccountCredentialPermissionKey(permission.Permission)
		mappedScope := contract.ServiceAccountCredentialScope(permission.Scope)
		if !mappedPermission.Valid() || !mappedScope.Valid() {
			return contract.ServiceAccountCredential{}, errors.New("unsupported service-account credential permission")
		}
		permissions[index] = contract.ServiceAccountCredentialPermissionGrant{PermissionKey: mappedPermission, Scope: mappedScope}
	}
	networks := make([]contract.ServiceAccountCredentialCidr, len(value.Networks))
	for index, network := range value.Networks {
		if !network.IsValid() || network.Addr().Zone() != "" || network.Addr().Is4In6() || network != network.Masked() ||
			index > 0 && serviceaccount.CompareCredentialNetworks(value.Networks[index-1], network) >= 0 {
			return contract.ServiceAccountCredential{}, errors.New("invalid service-account credential network")
		}
		networks[index] = network.String()
	}
	if value.RotatedFromCredentialID != nil &&
		(!validTenantAuthorizationCursor(*value.RotatedFromCredentialID) || *value.RotatedFromCredentialID == value.ID) {
		return contract.ServiceAccountCredential{}, errors.New("invalid predecessor credential")
	}
	if (value.LastUsedAt == nil) != (value.LastUsedIP == nil) {
		return contract.ServiceAccountCredential{}, errors.New("incomplete service-account credential usage")
	}
	var lastUsedIP *string
	if value.LastUsedAt != nil {
		if !validServicePrincipalStoredTime(*value.LastUsedAt) || value.LastUsedAt.Before(value.IssuedAt) ||
			value.LastUsedAt.After(value.ExpiresAt) || value.LastUsedAt.After(value.UpdatedAt) ||
			!value.LastUsedIP.IsValid() || value.LastUsedIP.Zone() != "" || value.LastUsedIP.Is4In6() {
			return contract.ServiceAccountCredential{}, errors.New("invalid service-account credential usage")
		}
		text := value.LastUsedIP.String()
		lastUsedIP = &text
	}
	if state == contract.ServiceAccountCredentialStateRevoked {
		if value.RevokedAt == nil || value.RevokedByMembershipID == nil || value.RevokedByUserID == nil || value.RevokeReason == nil ||
			!validServicePrincipalStoredTime(*value.RevokedAt) || !validTenantAuthorizationCursor(*value.RevokedByMembershipID) ||
			!validTenantAuthorizationCursor(*value.RevokedByUserID) || value.RevokedAt.Before(value.IssuedAt) ||
			value.UpdatedAt.Before(*value.RevokedAt) || value.LastUsedAt != nil && value.LastUsedAt.After(*value.RevokedAt) ||
			!validBoundedText(*value.RevokeReason, 1, 500) ||
			*value.RevokeReason != strings.TrimSpace(*value.RevokeReason) {
			return contract.ServiceAccountCredential{}, errors.New("revoked service-account credential lacks metadata")
		}
	} else if value.RevokedAt != nil || value.RevokedByMembershipID != nil || value.RevokedByUserID != nil || value.RevokeReason != nil {
		return contract.ServiceAccountCredential{}, errors.New("live service-account credential contains revocation metadata")
	}
	entityTag, err := strongVersionETag(value.Version)
	if err != nil {
		return contract.ServiceAccountCredential{}, err
	}
	return contract.ServiceAccountCredential{
		Id: value.ID, TenantId: value.TenantID, ServiceAccountId: value.ServiceAccountID,
		Label: value.Label, State: state, IssuedByMembershipId: value.IssuedByMembershipID,
		IssuedAt: value.IssuedAt, ExpiresAt: value.ExpiresAt,
		RotatedFromCredentialId: value.RotatedFromCredentialID,
		RevokedAt:               value.RevokedAt, RevokedByUserId: value.RevokedByUserID, RevokeReason: value.RevokeReason,
		LastUsedAt: value.LastUsedAt, LastUsedIp: lastUsedIP, Permissions: permissions,
		AllowedNetworks: networks, Etag: entityTag, Version: value.Version, UpdatedAt: value.UpdatedAt,
	}, nil
}

func mapCreatedAlert(value alert.Alert, tenantID uuid.UUID) (contract.Alert, error) {
	severity := contract.AlertSeverity(value.Severity)
	status := contract.AlertStatus(value.Status)
	if !validTenantAuthorizationCursor(value.ID) || value.TenantID != tenantID || !severity.Valid() || !status.Valid() ||
		!validBoundedText(value.Title, 1, 240) || !validResourceVersion(value.Version) ||
		!validServicePrincipalStoredTime(value.CreatedAt) || !validServicePrincipalStoredTime(value.UpdatedAt) ||
		value.UpdatedAt.Before(value.CreatedAt) {
		return contract.Alert{}, errors.New("invalid created Alert projection")
	}
	if value.Title != strings.TrimSpace(value.Title) ||
		value.ExternalID != nil && (!validBoundedText(*value.ExternalID, 1, 200) || *value.ExternalID != strings.TrimSpace(*value.ExternalID)) ||
		value.Description != nil && (!validBoundedText(*value.Description, 0, 10_000) || *value.Description != strings.TrimSpace(*value.Description)) {
		return contract.Alert{}, errors.New("invalid created Alert text")
	}
	var creator contract.AlertCreator
	human := value.CreatedByUserID != nil && value.CreatedByMembershipID != nil && value.CreatedByServiceAccountID == nil
	machine := value.CreatedByUserID == nil && value.CreatedByMembershipID == nil && value.CreatedByServiceAccountID != nil
	switch {
	case human && validTenantAuthorizationCursor(*value.CreatedByUserID) && validTenantAuthorizationCursor(*value.CreatedByMembershipID):
		if err := creator.FromHumanAlertCreator(contract.HumanAlertCreator{
			PrincipalType: contract.HumanAlertCreatorPrincipalTypeHuman, MembershipId: *value.CreatedByMembershipID,
		}); err != nil {
			return contract.Alert{}, err
		}
	case machine && validTenantAuthorizationCursor(*value.CreatedByServiceAccountID):
		if err := creator.FromServiceAccountAlertCreator(contract.ServiceAccountAlertCreator{
			PrincipalType:    contract.ServiceAccountAlertCreatorPrincipalTypeServiceAccount,
			ServiceAccountId: *value.CreatedByServiceAccountID,
		}); err != nil {
			return contract.Alert{}, err
		}
	default:
		return contract.Alert{}, errors.New("created Alert has ambiguous creator")
	}
	customFields, err := alertContractCustomFields(value.CustomFields)
	if err != nil {
		return contract.Alert{}, err
	}
	rawPayload := contract.AlertRawPayload(value.RawPayload)
	tags := append(contract.TicketTags(nil), value.Tags...)
	priority := contract.TicketPriority(value.Priority)
	workflow := contract.AlertWorkflowState{
		CustomerVisible: value.CustomerVisible, Initial: value.Version <= 2,
		Kind: contract.AlertWorkflowStateKindAlert, StateKey: contract.WorkflowStateKey(value.StateKey),
		Terminal: value.Status == alert.StatusClosed, Version: value.WorkflowVersion, WorkflowId: value.WorkflowID,
	}
	return contract.Alert{
		Id: value.ID, TenantId: value.TenantID, ExternalId: value.ExternalID,
		Title: value.Title, Description: value.Description, Status: status, Severity: severity,
		AlertNumber: &value.Number, Workflow: &workflow, CustomerVisible: &value.CustomerVisible,
		DeduplicationKey: value.DeduplicationKey, Priority: &priority, Category: &value.Category,
		Classification: value.Classification, Source: &value.Source, SourceType: &value.SourceType,
		Tags: &tags, CustomFields: &customFields, RawPayload: &rawPayload,
		AssignedTeamId: value.AssignedTeamID, AssigneeUserId: value.AssigneeUserID,
		ClaimedBy: value.ClaimedByUserID, DetectedAt: &value.DetectedAt, ReceivedAt: &value.ReceivedAt,
		AcknowledgedAt: value.AcknowledgedAt, ClosedAt: value.ClosedAt, ClaimedAt: value.ClaimedAt,
		Creator: creator, CreatedAt: value.CreatedAt, UpdatedAt: value.UpdatedAt, Version: value.Version,
	}, nil
}

func contractAlertRawPayload(value *contract.AlertRawPayload) (map[string]any, error) {
	if value == nil {
		return map[string]any{}, nil
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > 256*1024 {
		return nil, alert.ErrInvalidInput
	}
	result := make(map[string]any)
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil || len(result) > 200 {
		return nil, alert.ErrInvalidInput
	}
	return result, nil
}

func alertContractCustomFields(value map[string]any) (contract.CustomFieldValues, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var result contract.CustomFieldValues
	if err := json.Unmarshal(encoded, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func validResourceVersion(value int64) bool {
	return value >= 1 && value <= maximumResourceVersion
}

func equalOptionalServicePrincipalUUID(left, right *uuid.UUID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func validServicePrincipalStoredTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%int(time.Microsecond) == 0
}

func validBoundedText(value string, minimum, maximum int) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	length := utf8.RuneCountInString(value)
	return length >= minimum && length <= maximum
}

func serviceAccountLocation(tenantID, serviceAccountID uuid.UUID) string {
	return fmt.Sprintf("/api/v1/tenants/%s/service-accounts/%s", tenantID, serviceAccountID)
}

func serviceAccountRoleGrantLocation(tenantID, serviceAccountID, grantID uuid.UUID) string {
	return fmt.Sprintf("%s/role-grants/%s", serviceAccountLocation(tenantID, serviceAccountID), grantID)
}

func serviceAccountCredentialLocation(tenantID, serviceAccountID, credentialID uuid.UUID) string {
	return fmt.Sprintf("%s/credentials/%s", serviceAccountLocation(tenantID, serviceAccountID), credentialID)
}

func tenantAlertLocation(tenantID, alertID uuid.UUID) string {
	return fmt.Sprintf("/api/v1/tenants/%s/alerts/%s", tenantID, alertID)
}

func mapAuthorizationToServiceAccountError(err error) error {
	switch {
	case errors.Is(err, authorization.ErrInvalidInput):
		return serviceaccount.ErrInvalidInput
	case errors.Is(err, authorization.ErrPreconditionRequired):
		return serviceaccount.ErrPreconditionRequired
	default:
		return err
	}
}

func (h *Handler) writeCredentialMutationError(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
	serviceAccountID uuid.UUID,
	err error,
) {
	var replay *serviceaccount.OneTimeSecretAlreadyIssuedError
	if !errors.As(err, &replay) {
		h.writeServiceAccountError(w, r, err)
		return
	}
	if replay.ServiceAccountID != serviceAccountID || !validTenantAuthorizationCursor(replay.CredentialID) ||
		!validResourceVersion(replay.Version) {
		h.writeServiceAccountError(w, r, serviceaccount.ErrUnavailable)
		return
	}
	requestID, parseErr := uuid.Parse(requestIDFromContext(r.Context()))
	if parseErr != nil {
		h.writeServiceAccountError(w, r, serviceaccount.ErrUnavailable)
		return
	}
	location := serviceAccountCredentialLocation(tenantID, serviceAccountID, replay.CredentialID)
	detail := "The credential command already completed; its one-time bearer token cannot be returned again."
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", location)
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(contract.OneTimeSecretAlreadyIssuedProblem{
		Type:         contract.ProblemsoneTimeSecretAlreadyIssued,
		Title:        contract.OneTimeCredentialSecretAlreadyIssued,
		Status:       contract.OneTimeSecretAlreadyIssuedProblemStatusN409,
		Code:         contract.OneTimeSecretAlreadyIssued,
		RequestId:    requestID,
		CredentialId: replay.CredentialID,
		Location:     location,
		Detail:       &detail,
	})
}

func (h *Handler) writeServiceAccountError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, serviceaccount.ErrInvalidInput):
		writeDomainError(w, r, authorization.ErrInvalidInput)
	case errors.Is(err, serviceaccount.ErrForbidden):
		writeDomainError(w, r, authorization.ErrForbidden)
	case errors.Is(err, serviceaccount.ErrNotFound):
		writeDomainError(w, r, authorization.ErrNotFound)
	case errors.Is(err, serviceaccount.ErrConflict):
		writeDomainError(w, r, authorization.ErrConflict)
	case errors.Is(err, serviceaccount.ErrPreconditionFailed):
		writeDomainError(w, r, authorization.ErrPreconditionFailed)
	case errors.Is(err, serviceaccount.ErrPreconditionRequired):
		writeDomainError(w, r, authorization.ErrPreconditionRequired)
	case errors.Is(err, serviceaccount.ErrUnavailable), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeDomainError(w, r, authorization.ErrUnavailable)
	default:
		writeDomainError(w, r, err)
	}
}

func (h *Handler) writeAlertError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, alert.ErrInvalidInput):
		writeDomainError(w, r, authorization.ErrInvalidInput)
	case errors.Is(err, alert.ErrUnauthenticated):
		w.Header().Set("WWW-Authenticate", `Bearer realm="periapsis"`)
		writeDomainError(w, r, authentication.ErrInvalidAuthentication)
	case errors.Is(err, alert.ErrForbidden):
		writeDomainError(w, r, authorization.ErrForbidden)
	case errors.Is(err, alert.ErrConflict):
		writeDomainError(w, r, authorization.ErrConflict)
	case errors.Is(err, alert.ErrUnavailable), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeDomainError(w, r, authorization.ErrUnavailable)
	default:
		writeDomainError(w, r, err)
	}
}
