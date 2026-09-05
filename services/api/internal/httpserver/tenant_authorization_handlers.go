package httpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
)

func (h *Handler) GetTenantAuthority(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId) {
	actor, ok := h.tenantAuthorizationActor(w, r)
	if !ok {
		return
	}
	authority, err := h.authorization.GetTenantAuthority(r.Context(), actor, uuid.UUID(tenantID))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapTenantAuthority(authority)
	if err != nil {
		writeDomainError(w, r, authorization.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ListTenantPermissions(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.ListTenantPermissionsParams,
) {
	actor, ok := h.tenantAuthorizationActor(w, r)
	if !ok {
		return
	}
	input, err := pageInput(params.After, params.Limit)
	if err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	page, err := h.authorization.ListTenantPermissions(
		r.Context(), actor, uuid.UUID(tenantID), input,
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if !validTenantAuthorizationPage(
		input, page.Items, page.NextCursor,
		func(item authorization.TenantPermissionDefinition) uuid.UUID { return item.ID },
	) {
		writeDomainError(w, r, authorization.ErrUnavailable)
		return
	}
	items := make([]contract.TenantPermission, 0, len(page.Items))
	for _, item := range page.Items {
		mapped, mapErr := mapTenantPermission(item)
		if mapErr != nil {
			writeDomainError(w, r, authorization.ErrUnavailable)
			return
		}
		items = append(items, mapped)
	}
	writeSensitiveJSON(w, http.StatusOK, contract.TenantPermissionList{
		Items: items, NextCursor: page.NextCursor,
	})
}

func (h *Handler) ListTenantRoles(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.ListTenantRolesParams,
) {
	actor, ok := h.tenantAuthorizationActor(w, r)
	if !ok {
		return
	}
	includeArchived := params.IncludeArchived != nil && *params.IncludeArchived
	input, err := pageInput(params.After, params.Limit)
	if err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	page, err := h.authorization.ListTenantRoles(
		r.Context(), actor, uuid.UUID(tenantID), authorization.ListTenantRolesInput{
			PageInput: input, IncludeArchived: includeArchived,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if !validTenantAuthorizationPage(
		input, page.Items, page.NextCursor,
		func(item authorization.TenantRoleSummary) uuid.UUID { return item.ID },
	) {
		writeDomainError(w, r, authorization.ErrUnavailable)
		return
	}
	items := make([]contract.TenantRoleSummary, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, mapTenantRoleSummary(item))
	}
	writeSensitiveJSON(w, http.StatusOK, contract.TenantRoleList{
		Items: items, NextCursor: page.NextCursor,
	})
}

func (h *Handler) CreateTenantRole(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	_ contract.CreateTenantRoleParams,
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
	var body contract.TenantRoleCreateRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	if body.Policy.Permissions == nil || body.Policy.DelegationCeiling == nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	policy, err := tenantRolePolicyInput(body.Policy)
	if err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	description := ""
	if body.Description != nil {
		description = *body.Description
	}
	role, err := h.authorization.CreateTenantRole(
		r.Context(), actor, uuid.UUID(tenantID), authorization.CreateTenantRoleInput{
			Key: body.Key, Name: body.Name, Description: description, Policy: policy,
			IdempotencyKey: idempotencyKey, Audit: audit,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeTenantRole(w, r, http.StatusCreated, role)
}

func (h *Handler) GetTenantRole(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	roleID contract.RoleId,
) {
	actor, ok := h.tenantAuthorizationActor(w, r)
	if !ok {
		return
	}
	role, err := h.authorization.GetTenantRole(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(roleID),
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeTenantRole(w, r, http.StatusOK, role)
}

func (h *Handler) UpdateTenantRole(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	roleID contract.RoleId,
	_ contract.UpdateTenantRoleParams,
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
	var body contract.TenantRolePatchRequest
	if err := decodeAuthorizationBody(r, &body, "application/merge-patch+json"); err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	role, err := h.authorization.UpdateTenantRole(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(roleID),
		authorization.UpdateTenantRoleInput{
			Name: body.Name, Description: body.Description,
			ExpectedVersion: version, Audit: audit,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeTenantRole(w, r, http.StatusOK, role)
}

func (h *Handler) ArchiveTenantRole(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	roleID contract.RoleId,
	_ contract.ArchiveTenantRoleParams,
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
	err = h.authorization.ArchiveTenantRole(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(roleID),
		authorization.ArchiveTenantRoleInput{ExpectedVersion: version, Audit: audit},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ReplaceTenantRolePolicy(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	roleID contract.RoleId,
	_ contract.ReplaceTenantRolePolicyParams,
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
	var body contract.TenantRolePolicy
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	if body.Permissions == nil || body.DelegationCeiling == nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	policy, err := tenantRolePolicyInput(body)
	if err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	role, err := h.authorization.ReplaceTenantRolePolicy(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(roleID),
		authorization.ReplaceTenantRolePolicyInput{
			Policy: policy, ExpectedVersion: version, Audit: audit,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeTenantRole(w, r, http.StatusOK, role)
}

func (h *Handler) ListTenantUsers(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.ListTenantUsersParams,
) {
	actor, ok := h.tenantAuthorizationActor(w, r)
	if !ok {
		return
	}
	input, err := pageInput(params.After, params.Limit)
	if err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	page, err := h.authorization.ListTenantUsers(
		r.Context(), actor, uuid.UUID(tenantID), input,
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	items := make([]contract.TenantUserSummary, 0, len(page.Items))
	for _, item := range page.Items {
		mapped, mapErr := mapTenantUser(item)
		if mapErr != nil {
			writeDomainError(w, r, authorization.ErrUnavailable)
			return
		}
		items = append(items, mapped)
	}
	writeSensitiveJSON(w, http.StatusOK, contract.TenantUserList{
		Items: items, NextCursor: page.NextCursor,
	})
}

func (h *Handler) SuspendTenantMembership(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	userID contract.UserId,
	_ contract.SuspendTenantMembershipParams,
) {
	h.changeTenantMembershipLifecycle(
		w, r, uuid.UUID(tenantID), uuid.UUID(userID), authorization.MembershipStatusSuspended,
	)
}

func (h *Handler) ReactivateTenantMembership(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	userID contract.UserId,
	_ contract.ReactivateTenantMembershipParams,
) {
	h.changeTenantMembershipLifecycle(
		w, r, uuid.UUID(tenantID), uuid.UUID(userID), authorization.MembershipStatusActive,
	)
}

func (h *Handler) changeTenantMembershipLifecycle(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
	userID uuid.UUID,
	target authorization.MembershipStatus,
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
	expectedRevision, err := requestedVersion(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body contract.TenantMembershipLifecycleRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil ||
		expectedRevision == nil || body.ExpectedRevision != *expectedRevision {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	receipt, err := h.authorization.ChangeTenantMembershipLifecycle(
		r.Context(), actor, tenantID, userID, target,
		authorization.TenantMembershipLifecycleInput{
			ExpectedRevision: expectedRevision, Reason: body.Reason,
			IdempotencyKey: idempotencyKey, Audit: audit,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapTenantMembershipLifecycleReceipt(receipt)
	if err != nil || !setVersionETag(w, receipt.LifecycleRevision) ||
		w.Header().Get("ETag") != receipt.EntityTag {
		writeDomainError(w, r, authorization.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ListUserRoleGrants(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	userID contract.UserId,
	params contract.ListUserRoleGrantsParams,
) {
	actor, ok := h.tenantAuthorizationActor(w, r)
	if !ok {
		return
	}
	includeRevoked := params.IncludeRevoked != nil && *params.IncludeRevoked
	input, err := pageInput(params.After, params.Limit)
	if err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	page, err := h.authorization.ListUserRoleGrants(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(userID),
		authorization.ListUserRoleGrantsInput{
			PageInput: input, IncludeRevoked: includeRevoked,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	items := make([]contract.DirectUserRoleGrant, 0, len(page.Items))
	for _, item := range page.Items {
		mapped, mapErr := mapDirectRoleGrant(item)
		if mapErr != nil {
			writeDomainError(w, r, authorization.ErrUnavailable)
			return
		}
		items = append(items, mapped)
	}
	writeSensitiveJSON(w, http.StatusOK, contract.DirectUserRoleGrantList{
		Items: items, NextCursor: page.NextCursor,
	})
}

func (h *Handler) GrantUserRole(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	userID contract.UserId,
	_ contract.GrantUserRoleParams,
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
	var body contract.DirectUserRoleGrantRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	grant, err := h.authorization.GrantUserRole(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(userID),
		authorization.GrantUserRoleInput{
			RoleID: uuid.UUID(body.RoleId), Reason: body.Reason,
			ExpiresAt: body.ExpiresAt, IdempotencyKey: idempotencyKey, Audit: audit,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapDirectRoleGrant(grant)
	if err != nil {
		writeDomainError(w, r, authorization.ErrUnavailable)
		return
	}
	if !setEdgeEntityTag(w, string(mapped.Etag)) {
		writeDomainError(w, r, authorization.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) RevokeRoleGrant(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	grantID contract.RoleGrantId,
	_ contract.RevokeRoleGrantParams,
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
	var body contract.RoleGrantRevokeRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return
	}
	err = h.authorization.RevokeRoleGrant(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(grantID),
		authorization.RevokeRoleGrantInput{
			Reason: body.Reason, ExpectedEntityTag: entityTag, Audit: audit,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) tenantAuthorizationActor(
	w http.ResponseWriter,
	r *http.Request,
) (authorization.Actor, bool) {
	actor, _, ok := h.tenantAuthorizationSession(w, r)
	return actor, ok
}

func (h *Handler) tenantAuthorizationSession(
	w http.ResponseWriter,
	r *http.Request,
) (authorization.Actor, authentication.Session, bool) {
	if !h.requireApplication(w, r) {
		return authorization.Actor{}, authentication.Session{}, false
	}
	token, err := h.sessionToken(r)
	if err != nil {
		writeDomainError(w, r, err)
		return authorization.Actor{}, authentication.Session{}, false
	}
	session, err := h.authenticateRequest(r, token)
	if err != nil {
		writeDomainError(w, r, err)
		return authorization.Actor{}, authentication.Session{}, false
	}
	activeTenantID := uuid.Nil
	if session.ActiveTenantID != nil {
		activeTenantID = *session.ActiveTenantID
	}
	return authorization.Actor{
		UserID: session.User.ID, SessionID: session.ID,
		ActiveTenantID:       activeTenantID,
		AuthenticationMethod: session.AuthenticationMethod,
	}, session, true
}

func (h *Handler) prepareTenantAuthorizationMutation(
	w http.ResponseWriter,
	r *http.Request,
) (authorization.Actor, authorization.AuditContext, bool) {
	if !h.prepareCookieMutation(w, r) {
		return authorization.Actor{}, authorization.AuditContext{}, false
	}
	actor, session, ok := h.tenantAuthorizationSession(w, r)
	if !ok {
		return authorization.Actor{}, authorization.AuditContext{}, false
	}
	csrf, err := singleHeader(r, csrfTokenHeader, 128)
	if err != nil {
		writeDomainError(w, r, authentication.ErrForbidden)
		return authorization.Actor{}, authorization.AuditContext{}, false
	}
	if err := h.authentication.ValidateCSRF(session, csrf); err != nil {
		writeDomainError(w, r, err)
		return authorization.Actor{}, authorization.AuditContext{}, false
	}
	event, err := h.eventContext(r)
	if err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return authorization.Actor{}, authorization.AuditContext{}, false
	}
	return actor, authorization.AuditContext{
		RequestID: event.RequestID, CorrelationID: event.CorrelationID,
		RemoteAddress: event.RemoteAddress, UserAgent: event.UserAgent,
	}, true
}

func pageInput(after *contract.AfterCursor, limit *contract.PageSize) (authorization.PageInput, error) {
	input := authorization.PageInput{}
	if after != nil {
		value := uuid.UUID(*after)
		input.After = &value
	}
	if limit != nil {
		if *limit < 1 || *limit > 100 {
			return authorization.PageInput{}, errors.New("page limit is outside the contract")
		}
		input.Limit = *limit
	}
	return input, nil
}

func validTenantAuthorizationPage[T any](
	input authorization.PageInput,
	items []T,
	nextCursor *uuid.UUID,
	cursor func(T) uuid.UUID,
) bool {
	limit := input.Limit
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 100 || len(items) > limit {
		return false
	}

	var previous uuid.UUID
	hasPrevious := false
	if input.After != nil {
		if !validTenantAuthorizationCursor(*input.After) {
			return false
		}
		previous = *input.After
		hasPrevious = true
	}
	for _, item := range items {
		value := cursor(item)
		if !validTenantAuthorizationCursor(value) ||
			hasPrevious && bytes.Compare(value[:], previous[:]) <= 0 {
			return false
		}
		previous = value
		hasPrevious = true
	}
	if nextCursor == nil {
		return true
	}
	return len(items) > 0 && validTenantAuthorizationCursor(*nextCursor) &&
		*nextCursor == cursor(items[len(items)-1])
}

func validTenantAuthorizationCursor(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func requestedVersion(r *http.Request) (*int64, error) {
	version, present, err := strongVersionPrecondition(r)
	if err != nil {
		return nil, authorization.ErrInvalidInput
	}
	if !present {
		return nil, authorization.ErrPreconditionRequired
	}
	return &version, nil
}

func requestedEdgeEntityTag(r *http.Request) (*string, error) {
	if len(r.Header.Values(ifMatchHeader)) == 0 {
		return nil, authorization.ErrPreconditionRequired
	}
	value, err := singleHeader(r, ifMatchHeader, 96)
	if err != nil {
		return nil, authorization.ErrInvalidInput
	}
	if _, err := authorization.ParseEdgeEntityTag(value); err != nil {
		return nil, authorization.ErrInvalidInput
	}
	return &value, nil
}

func (h *Handler) writeTenantRole(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	role authorization.TenantRole,
) {
	mapped, err := mapTenantRole(role)
	if err != nil || !setVersionETag(w, role.Version) {
		writeDomainError(w, r, authorization.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, status, mapped)
}

func setVersionETag(w http.ResponseWriter, version int64) bool {
	etag, err := strongVersionETag(version)
	if err != nil {
		return false
	}
	w.Header().Set("ETag", etag)
	return true
}

func setEdgeEntityTag(w http.ResponseWriter, value string) bool {
	if _, err := authorization.ParseEdgeEntityTag(value); err != nil {
		return false
	}
	w.Header().Set("ETag", value)
	return true
}

func decodeAuthorizationBody(r *http.Request, destination any, expectedMediaType string) error {
	return decodeAuthorizationBodyWithControls(r, destination, expectedMediaType, false)
}

func decodeTicketCommentBody(r *http.Request, destination any) error {
	return decodeAuthorizationBodyWithControls(r, destination, "application/json", true)
}

func decodeAuthorizationBodyWithControls(
	r *http.Request,
	destination any,
	expectedMediaType string,
	allowLineFormatting bool,
) error {
	mediaType, err := requestMediaType(r)
	if err != nil || mediaType != expectedMediaType {
		return errors.New("unsupported request content type")
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if err != nil || len(body) == 0 || len(body) > 1<<20 || !utf8.Valid(body) {
		return errors.New("request body is invalid")
	}
	if !validJSONUnicodeScalarEscapes(body) {
		return errors.New("request body contains an unpaired Unicode surrogate")
	}
	if err := validateAuthorizationJSONTokens(body, allowLineFormatting); err != nil {
		return err
	}
	var raw any
	if err := json.Unmarshal(body, &raw); err != nil ||
		validateExactJSONShape(raw, reflect.TypeOf(destination)) != nil {
		return errors.New("request body does not match the exact JSON shape")
	}
	if err := validateWritableAuthorizationExpiry(raw, destination); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}

func validateAuthorizationJSONTokens(body []byte, allowLineFormatting bool) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := scanAuthorizationJSONValue(decoder, allowLineFormatting); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}

func scanAuthorizationJSONValue(decoder *json.Decoder, allowLineFormatting bool) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return errors.New("request body contains null")
	}
	if text, ok := token.(string); ok && containsJSONControlCharacterWithLineFormatting(text, allowLineFormatting) {
		return errors.New("request body contains a control character")
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			key, ok := keyToken.(string)
			if keyErr != nil || !ok {
				return errors.New("request body contains an invalid object key")
			}
			if containsJSONControlCharacter(key) {
				return errors.New("request body contains a control character")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("request body contains a duplicate object key")
			}
			seen[key] = struct{}{}
			if err := scanAuthorizationJSONValue(decoder, allowLineFormatting); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim('}') {
			return errors.New("request body contains an unterminated object")
		}
	case '[':
		for decoder.More() {
			if err := scanAuthorizationJSONValue(decoder, allowLineFormatting); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim(']') {
			return errors.New("request body contains an unterminated array")
		}
	default:
		return errors.New("request body contains an invalid delimiter")
	}
	return nil
}

var writableAuthorizationExpiryPattern = regexp.MustCompile(
	`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9](?:\.([0-9]+))?(?:Z|[+-]([0-9]{2}):([0-9]{2}))$`,
)

func validateWritableAuthorizationExpiry(raw any, destination any) error {
	switch destination.(type) {
	case *contract.DirectUserRoleGrantRequest,
		*contract.OperatorTeamRosterEntryCreateRequest,
		*contract.ServiceAccountCredentialIssueRequest,
		*contract.ServiceAccountCredentialRotateRequest,
		*contract.ServiceAccountRoleGrantRequest,
		*contract.TenantSecurityGroupMembershipCreateRequest,
		*contract.TenantSecurityGroupRoleGrantRequest:
	default:
		return nil
	}

	object, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	value, present := object["expiresAt"]
	if !present {
		return nil
	}
	instant, ok := value.(string)
	if !ok || !validWritableAuthorizationExpiry(instant) {
		return errors.New("request expiry is invalid")
	}
	return nil
}

func validWritableAuthorizationExpiry(value string) bool {
	parts := writableAuthorizationExpiryPattern.FindStringSubmatch(value)
	if parts == nil {
		return false
	}
	if parts[2] != "" {
		offsetHour, hourErr := strconv.Atoi(parts[2])
		offsetMinute, minuteErr := strconv.Atoi(parts[3])
		if hourErr != nil || minuteErr != nil || offsetHour > 23 || offsetMinute > 59 {
			return false
		}
	}
	fraction := parts[1]
	if len(fraction) > 6 && strings.Trim(fraction[6:], "0") != "" {
		return false
	}
	instant, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return false
	}
	_, err = authorization.NormalizeWritableExpiry(&instant)
	return err == nil
}

func containsJSONControlCharacter(value string) bool {
	return containsJSONControlCharacterWithLineFormatting(value, false)
}

func containsJSONControlCharacterWithLineFormatting(value string, allowLineFormatting bool) bool {
	for _, character := range value {
		if unicode.IsControl(character) && (!allowLineFormatting || character != '\n' && character != '\t') {
			return true
		}
	}
	return false
}

func validJSONUnicodeScalarEscapes(document []byte) bool {
	inString := false
	for index := 0; index < len(document); index++ {
		switch document[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString || index+1 >= len(document) {
				continue
			}
			if document[index+1] != 'u' {
				index++
				continue
			}
			value, ok := jsonHexCodeUnit(document[index+2:])
			if !ok {
				return false
			}
			index += 5
			if value >= 0xdc00 && value <= 0xdfff {
				return false
			}
			if value < 0xd800 || value > 0xdbff {
				continue
			}
			if index+6 >= len(document) || document[index+1] != '\\' || document[index+2] != 'u' {
				return false
			}
			low, lowOK := jsonHexCodeUnit(document[index+3:])
			if !lowOK || low < 0xdc00 || low > 0xdfff {
				return false
			}
			index += 6
		}
	}
	return true
}

func jsonHexCodeUnit(value []byte) (uint16, bool) {
	if len(value) < 4 {
		return 0, false
	}
	var result uint16
	for _, character := range value[:4] {
		result <<= 4
		switch {
		case character >= '0' && character <= '9':
			result += uint16(character - '0')
		case character >= 'a' && character <= 'f':
			result += uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			result += uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return result, true
}

func validateExactJSONShape(value any, destinationType reflect.Type) error {
	for destinationType.Kind() == reflect.Pointer {
		destinationType = destinationType.Elem()
	}
	switch destinationType.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		fields := make(map[string]reflect.Type, destinationType.NumField())
		for index := 0; index < destinationType.NumField(); index++ {
			field := destinationType.Field(index)
			if !field.IsExported() {
				continue
			}
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "" {
				name = field.Name
			}
			if name != "-" {
				fields[name] = field.Type
			}
		}
		for name, item := range object {
			fieldType, exists := fields[name]
			if !exists {
				return errors.New("request body contains a non-canonical field name")
			}
			if err := validateExactJSONShape(item, fieldType); err != nil {
				return err
			}
		}
	case reflect.Array, reflect.Slice:
		items, ok := value.([]any)
		if !ok {
			return nil
		}
		for _, item := range items {
			if err := validateExactJSONShape(item, destinationType.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}
