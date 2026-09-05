package httpserver

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

func (h *Handler) SearchTenantLDAPAuthProviderUser(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	providerID contract.AuthProviderId,
) {
	actor, audit, ok := h.prepareLDAPAdministrationMutation(w, r, uuid.UUID(tenantID), uuid.UUID(providerID))
	if !ok {
		return
	}
	input, err := decodeLDAPUserSearchBody(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	input.Audit = audit
	result, err := h.ldapAdministration.SearchUser(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(providerID), input,
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapLDAPDirectoryTestResult(result, 1)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) TestTenantLDAPAuthProviderFilter(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	providerID contract.AuthProviderId,
) {
	actor, audit, ok := h.prepareLDAPAdministrationMutation(w, r, uuid.UUID(tenantID), uuid.UUID(providerID))
	if !ok {
		return
	}
	input, err := decodeLDAPFilterTestBody(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	input.Audit = audit
	result, err := h.ldapAdministration.TestFilter(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(providerID), input,
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapLDAPFilterTestResult(result, input.MaxResults)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ListTenantLDAPAuthProviderBindings(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.ListTenantLDAPAuthProviderBindingsParams,
) {
	actor, ok := h.prepareLDAPAdministrationRead(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	pageInput, err := ldapAdministrationPageInput(params.After, params.Limit)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	input := identityprovider.ListBindingsInput{
		PageInput: pageInput, IncludeArchived: params.IncludeArchived != nil && bool(*params.IncludeArchived),
	}
	page, err := h.ldapAdministration.ListBindings(r.Context(), actor, uuid.UUID(tenantID), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if !validLDAPAdministrationPage(pageInput, page.Items, page.NextCursor, func(item identityprovider.Binding) uuid.UUID { return item.ID }) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	items := make([]contract.TenantLDAPAuthProviderBinding, 0, len(page.Items))
	for _, item := range page.Items {
		mapped, mapErr := mapLDAPBinding(item)
		if mapErr != nil || item.TenantID != uuid.UUID(tenantID) || !input.IncludeArchived && item.ArchivedAt != nil {
			writeDomainError(w, r, identityprovider.ErrUnavailable)
			return
		}
		items = append(items, mapped)
	}
	writeSensitiveJSON(w, http.StatusOK, contract.TenantLDAPAuthProviderBindingList{
		Items: items, NextCursor: cloneUUIDPointer(page.NextCursor),
	})
}

func (h *Handler) CreateTenantLDAPAuthProviderBinding(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	_ contract.CreateTenantLDAPAuthProviderBindingParams,
) {
	actor, audit, ok := h.prepareLDAPAdministrationMutation(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	input, err := decodeLDAPBindingCreateBody(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	input.IdempotencyKey, input.Audit = idempotencyKey, audit
	result, err := h.ldapAdministration.CreateBinding(r.Context(), actor, uuid.UUID(tenantID), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if result.TenantID != uuid.UUID(tenantID) || result.ProviderID != input.ProviderID {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	h.writeLDAPBinding(w, r, http.StatusCreated, result, tenantLDAPBindingLocation(uuid.UUID(tenantID), result.ID))
}

func (h *Handler) GetTenantLDAPAuthProviderBinding(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	bindingID contract.AuthProviderBindingId,
) {
	actor, ok := h.prepareLDAPAdministrationRead(w, r, uuid.UUID(tenantID), uuid.UUID(bindingID))
	if !ok {
		return
	}
	result, err := h.ldapAdministration.GetBinding(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(bindingID),
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if result.TenantID != uuid.UUID(tenantID) || result.ID != uuid.UUID(bindingID) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	h.writeLDAPBinding(w, r, http.StatusOK, result, "")
}

func (h *Handler) UpdateTenantLDAPAuthProviderBinding(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	bindingID contract.AuthProviderBindingId,
	_ contract.UpdateTenantLDAPAuthProviderBindingParams,
) {
	actor, audit, ok := h.prepareLDAPAdministrationMutation(w, r, uuid.UUID(tenantID), uuid.UUID(bindingID))
	if !ok {
		return
	}
	entityTag, err := requestedTenantLDAPEntityTag(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	input, err := decodeLDAPBindingUpdateBody(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	input.ExpectedEntityTag, input.Audit = entityTag, audit
	result, err := h.ldapAdministration.UpdateBinding(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(bindingID), input,
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if result.TenantID != uuid.UUID(tenantID) || result.ID != uuid.UUID(bindingID) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	h.writeLDAPBinding(w, r, http.StatusOK, result, "")
}

func (h *Handler) ArchiveTenantLDAPAuthProviderBinding(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	bindingID contract.AuthProviderBindingId,
	_ contract.ArchiveTenantLDAPAuthProviderBindingParams,
) {
	actor, audit, ok := h.prepareLDAPAdministrationMutation(w, r, uuid.UUID(tenantID), uuid.UUID(bindingID))
	if !ok {
		return
	}
	entityTag, err := requestedTenantLDAPEntityTag(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	reason, err := decodeLDAPArchiveReasonBody(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	version, err := h.ldapAdministration.ArchiveBinding(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(bindingID), identityprovider.ArchiveBindingInput{
			Reason: reason, ExpectedEntityTag: entityTag, Audit: audit,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeTenantLDAPNoContent(w, r, version)
}

func (h *Handler) ListTenantLDAPMappings(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.ListTenantLDAPMappingsParams,
) {
	actor, ok := h.prepareLDAPAdministrationRead(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	pageInput, err := ldapMappingAdministrationPageInput(params.After, params.Limit)
	if err != nil || params.BindingId != nil && !validLDAPAdministrationID(uuid.UUID(*params.BindingId)) {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	input := identityprovider.ListMappingsInput{
		After: pageInput.After, Limit: pageInput.Limit,
		IncludeArchived: params.IncludeArchived != nil && bool(*params.IncludeArchived),
	}
	if params.BindingId != nil {
		bindingID := uuid.UUID(*params.BindingId)
		input.BindingID = &bindingID
	}
	page, err := h.ldapAdministration.ListMappings(r.Context(), actor, uuid.UUID(tenantID), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if !validLDAPMappingAdministrationPage(input, page.Items, page.NextCursor) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	items := make([]contract.TenantLDAPMapping, 0, len(page.Items))
	for _, item := range page.Items {
		mapped, mapErr := mapLDAPMapping(item)
		if mapErr != nil || item.TenantID != uuid.UUID(tenantID) ||
			input.BindingID != nil && item.BindingID != *input.BindingID || !input.IncludeArchived && item.ArchivedAt != nil {
			writeDomainError(w, r, identityprovider.ErrUnavailable)
			return
		}
		items = append(items, mapped)
	}
	var nextCursor *contract.TenantLDAPMappingCursor
	if page.NextCursor != nil {
		encoded, encodeErr := identityprovider.EncodeMappingCursor(*page.NextCursor)
		if encodeErr != nil {
			writeDomainError(w, r, identityprovider.ErrUnavailable)
			return
		}
		value := contract.TenantLDAPMappingCursor(encoded)
		nextCursor = &value
	}
	writeSensitiveJSON(w, http.StatusOK, contract.TenantLDAPMappingList{Items: items, NextCursor: nextCursor})
}

func (h *Handler) CreateTenantLDAPMapping(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	_ contract.CreateTenantLDAPMappingParams,
) {
	actor, audit, ok := h.prepareLDAPAdministrationMutation(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	input, err := decodeLDAPMappingCreateBody(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	input.IdempotencyKey, input.Audit = idempotencyKey, audit
	result, err := h.ldapAdministration.CreateMapping(r.Context(), actor, uuid.UUID(tenantID), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if result.TenantID != uuid.UUID(tenantID) || result.BindingID != input.BindingID {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	h.writeLDAPMapping(w, r, http.StatusCreated, result, tenantLDAPMappingLocation(uuid.UUID(tenantID), result.ID))
}

func (h *Handler) DryRunTenantLDAPMappings(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
) {
	actor, audit, ok := h.prepareLDAPAdministrationMutation(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	input, err := decodeLDAPDryRunBody(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	input.Audit = audit
	result, err := h.ldapAdministration.DryRunMappings(r.Context(), actor, uuid.UUID(tenantID), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if result.Snapshot.BindingID != input.BindingID {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	mapped, err := mapLDAPDryRunResult(result)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) GetTenantLDAPMapping(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	mappingID contract.LDAPMappingId,
) {
	actor, ok := h.prepareLDAPAdministrationRead(w, r, uuid.UUID(tenantID), uuid.UUID(mappingID))
	if !ok {
		return
	}
	result, err := h.ldapAdministration.GetMapping(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(mappingID),
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if result.TenantID != uuid.UUID(tenantID) || result.ID != uuid.UUID(mappingID) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	h.writeLDAPMapping(w, r, http.StatusOK, result, "")
}

func (h *Handler) UpdateTenantLDAPMapping(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	mappingID contract.LDAPMappingId,
	_ contract.UpdateTenantLDAPMappingParams,
) {
	actor, audit, ok := h.prepareLDAPAdministrationMutation(w, r, uuid.UUID(tenantID), uuid.UUID(mappingID))
	if !ok {
		return
	}
	entityTag, err := requestedTenantLDAPEntityTag(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	input, err := decodeLDAPMappingUpdateBody(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	input.ExpectedEntityTag, input.Audit = entityTag, audit
	result, err := h.ldapAdministration.UpdateMapping(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(mappingID), input,
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if result.TenantID != uuid.UUID(tenantID) || result.ID != uuid.UUID(mappingID) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	h.writeLDAPMapping(w, r, http.StatusOK, result, "")
}

func (h *Handler) ArchiveTenantLDAPMapping(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	mappingID contract.LDAPMappingId,
	_ contract.ArchiveTenantLDAPMappingParams,
) {
	actor, audit, ok := h.prepareLDAPAdministrationMutation(w, r, uuid.UUID(tenantID), uuid.UUID(mappingID))
	if !ok {
		return
	}
	entityTag, err := requestedTenantLDAPEntityTag(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	reason, err := decodeLDAPArchiveReasonBody(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	version, err := h.ldapAdministration.ArchiveMapping(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(mappingID), identityprovider.ArchiveMappingInput{
			Reason: reason, ExpectedEntityTag: entityTag, Audit: audit,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeTenantLDAPNoContent(w, r, version)
}

func (h *Handler) GetTenantLDAPSyncStatus(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	bindingID contract.AuthProviderBindingId,
) {
	actor, ok := h.prepareLDAPAdministrationRead(w, r, uuid.UUID(tenantID), uuid.UUID(bindingID))
	if !ok {
		return
	}
	result, err := h.ldapAdministration.GetSyncStatus(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(bindingID),
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if result.BindingID != uuid.UUID(bindingID) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	mapped, err := mapLDAPSyncStatus(result)
	if err != nil || !setVersionETag(w, result.Version) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ListTenantLDAPSyncRuns(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	bindingID contract.AuthProviderBindingId,
	params contract.ListTenantLDAPSyncRunsParams,
) {
	actor, ok := h.prepareLDAPAdministrationRead(w, r, uuid.UUID(tenantID), uuid.UUID(bindingID))
	if !ok {
		return
	}
	pageInput, err := ldapAdministrationPageInput(params.After, params.Limit)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	page, err := h.ldapAdministration.ListSyncRuns(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(bindingID), pageInput,
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if !validLDAPAdministrationPage(pageInput, page.Items, page.NextCursor, func(item identityprovider.SyncRun) uuid.UUID { return item.ID }) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	items := make([]contract.TenantLDAPSyncRun, 0, len(page.Items))
	for _, item := range page.Items {
		mapped, mapErr := mapLDAPSyncRun(item)
		if mapErr != nil || item.TenantID != uuid.UUID(tenantID) || item.BindingID != uuid.UUID(bindingID) {
			writeDomainError(w, r, identityprovider.ErrUnavailable)
			return
		}
		items = append(items, mapped)
	}
	writeSensitiveJSON(w, http.StatusOK, contract.TenantLDAPSyncRunList{
		Items: items, NextCursor: cloneUUIDPointer(page.NextCursor),
	})
}

func (h *Handler) StartTenantLDAPManualSync(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	bindingID contract.AuthProviderBindingId,
	_ contract.StartTenantLDAPManualSyncParams,
) {
	actor, audit, ok := h.prepareLDAPAdministrationMutation(w, r, uuid.UUID(tenantID), uuid.UUID(bindingID))
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	entityTag, err := requestedTenantLDAPEntityTag(r)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	input, err := decodeLDAPManualSyncBody(r)
	if err != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return
	}
	input.IdempotencyKey, input.ExpectedEntityTag, input.Audit = idempotencyKey, entityTag, audit
	result, err := h.ldapAdministration.StartManualSync(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(bindingID), input,
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if result.TenantID != uuid.UUID(tenantID) || result.BindingID != uuid.UUID(bindingID) || result.Trigger != "manual" {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	h.writeLDAPSyncRun(
		w, r, http.StatusAccepted, result,
		tenantLDAPSyncRunLocation(uuid.UUID(tenantID), uuid.UUID(bindingID), result.ID),
	)
}

func (h *Handler) GetTenantLDAPSyncRun(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	bindingID contract.AuthProviderBindingId,
	syncRunID contract.LDAPSyncRunId,
) {
	actor, ok := h.prepareLDAPAdministrationRead(
		w, r, uuid.UUID(tenantID), uuid.UUID(bindingID), uuid.UUID(syncRunID),
	)
	if !ok {
		return
	}
	result, err := h.ldapAdministration.GetSyncRun(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(bindingID), uuid.UUID(syncRunID),
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if result.TenantID != uuid.UUID(tenantID) || result.BindingID != uuid.UUID(bindingID) ||
		result.ID != uuid.UUID(syncRunID) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	h.writeLDAPSyncRun(w, r, http.StatusOK, result, "")
}

func (h *Handler) prepareLDAPAdministrationRead(
	w http.ResponseWriter,
	r *http.Request,
	ids ...uuid.UUID,
) (authorization.Actor, bool) {
	actor, ok := h.tenantAuthorizationActor(w, r)
	if !ok {
		return authorization.Actor{}, false
	}
	if !validLDAPAdministrationIDs(ids) || requireTenantLDAPBodyAbsent(r) != nil {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return authorization.Actor{}, false
	}
	if actor.ActiveTenantID != ids[0] {
		writeDomainError(w, r, identityprovider.ErrForbidden)
		return authorization.Actor{}, false
	}
	return actor, true
}

func (h *Handler) prepareLDAPAdministrationMutation(
	w http.ResponseWriter,
	r *http.Request,
	ids ...uuid.UUID,
) (authorization.Actor, authorization.AuditContext, bool) {
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return authorization.Actor{}, authorization.AuditContext{}, false
	}
	if !validLDAPAdministrationIDs(ids) {
		writeDomainError(w, r, identityprovider.ErrInvalidInput)
		return authorization.Actor{}, authorization.AuditContext{}, false
	}
	if actor.ActiveTenantID != ids[0] {
		writeDomainError(w, r, identityprovider.ErrForbidden)
		return authorization.Actor{}, authorization.AuditContext{}, false
	}
	return actor, audit, true
}

func validLDAPAdministrationIDs(values []uuid.UUID) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		if !validLDAPAdministrationID(value) {
			return false
		}
	}
	return true
}

func ldapAdministrationPageInput(
	after *contract.AfterCursor,
	limit *contract.PageSize,
) (identityprovider.PageInput, error) {
	value, err := pageInput(after, limit)
	if err != nil || value.After != nil && !validLDAPAdministrationID(*value.After) {
		return identityprovider.PageInput{}, errors.New("invalid LDAP page")
	}
	return identityprovider.PageInput{After: cloneUUIDPointer(value.After), Limit: value.Limit}, nil
}

func ldapMappingAdministrationPageInput(
	after *contract.LDAPMappingAfterCursor,
	limit *contract.PageSize,
) (identityprovider.ListMappingsInput, error) {
	page, err := ldapAdministrationPageInput(nil, limit)
	if err != nil {
		return identityprovider.ListMappingsInput{}, err
	}
	result := identityprovider.ListMappingsInput{Limit: page.Limit}
	if after != nil {
		cursor, decodeErr := identityprovider.DecodeMappingCursor(string(*after))
		if decodeErr != nil {
			return identityprovider.ListMappingsInput{}, errors.New("invalid LDAP mapping cursor")
		}
		result.After = &cursor
	}
	return result, nil
}

func (h *Handler) writeLDAPBinding(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	value identityprovider.Binding,
	location string,
) {
	mapped, err := mapLDAPBinding(value)
	if err != nil || !setVersionETag(w, value.Version) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	if location != "" {
		w.Header().Set("Location", location)
	}
	writeSensitiveJSON(w, status, mapped)
}

func (h *Handler) writeLDAPMapping(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	value identityprovider.Mapping,
	location string,
) {
	mapped, err := mapLDAPMapping(value)
	if err != nil || !setVersionETag(w, value.Version) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	if location != "" {
		w.Header().Set("Location", location)
	}
	writeSensitiveJSON(w, status, mapped)
}

func (h *Handler) writeLDAPSyncRun(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	value identityprovider.SyncRun,
	location string,
) {
	mapped, err := mapLDAPSyncRun(value)
	if err != nil || !setVersionETag(w, value.Version) {
		writeDomainError(w, r, identityprovider.ErrUnavailable)
		return
	}
	if location != "" {
		w.Header().Set("Location", location)
	}
	writeSensitiveJSON(w, status, mapped)
}

func tenantLDAPBindingLocation(tenantID, bindingID uuid.UUID) string {
	return fmt.Sprintf("/api/v1/tenants/%s/auth-provider-bindings/%s", tenantID, bindingID)
}

func tenantLDAPMappingLocation(tenantID, mappingID uuid.UUID) string {
	return fmt.Sprintf("/api/v1/tenants/%s/ldap-mappings/%s", tenantID, mappingID)
}

func tenantLDAPSyncRunLocation(tenantID, bindingID, runID uuid.UUID) string {
	return fmt.Sprintf(
		"/api/v1/tenants/%s/auth-provider-bindings/%s/sync-runs/%s",
		tenantID, bindingID, runID,
	)
}
