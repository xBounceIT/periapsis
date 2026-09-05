package httpserver

import (
	"math"
	"net/http"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/customfields"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	application "github.com/periapsis-im/periapsis/services/api/internal/customfields"
)

func (h *Handler) ListTenantCustomFieldDefinitions(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, params contract.ListTenantCustomFieldDefinitionsParams) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.phase4ReadActor(w, r, tenant)
	if !ok {
		return
	}
	objectType, err := customFieldObjectType(params.ObjectType)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	input := application.DefinitionListInput{ObjectType: objectType}
	if params.IncludeArchived != nil {
		input.IncludeArchived = bool(*params.IncludeArchived)
	}
	if params.Limit != nil {
		input.Limit = int(*params.Limit)
	}
	if params.After != nil {
		input.After = string(*params.After)
	}
	page, err := h.customFields.ListDefinitions(r.Context(), actor.custom, tenant, input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	items := make([]contract.CustomFieldDefinition, len(page.Items))
	for index, definition := range page.Items {
		items[index], err = customFieldDefinition(definition)
		if err != nil {
			writeDomainError(w, r, application.ErrUnavailable)
			return
		}
	}
	var next *contract.Phase4Cursor
	if page.NextCursor != "" {
		value := contract.Phase4Cursor(page.NextCursor)
		next = &value
	}
	writeSensitiveJSON(w, http.StatusOK, contract.CustomFieldDefinitionPage{Items: items, NextCursor: next})
}

func (h *Handler) CreateTenantCustomFieldDefinition(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, _ contract.CreateTenantCustomFieldDefinitionParams) {
	tenant := uuid.UUID(tenantID)
	actor, audit, _, ok := h.phase4MutationActor(w, r, tenant)
	if !ok {
		return
	}
	key, err := requestIdempotencyKey(r)
	if err != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	var body contract.CustomFieldDefinitionCreateRequest
	if err := decodePhase4Body(r, &body); err != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	input, err := customFieldDefinitionInput(tenant, uuid.UUID(body.DefinitionId), 1, false, body.Definition)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.customFields.CreateDefinition(r.Context(), actor.custom, tenant, application.CreateDefinitionInput{
		Definition: input, IdempotencyKey: key, Audit: audit,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := customFieldDefinition(result.Definition)
	if err != nil || !setVersionETag(w, mapped.SchemaVersion) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set("Location", "/api/v1/tenants/"+tenant.String()+"/custom-field-definitions/"+uuid.UUID(body.DefinitionId).String())
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) GetTenantCustomFieldDefinition(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, definitionID contract.CustomFieldDefinitionId, params contract.GetTenantCustomFieldDefinitionParams) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.phase4ReadActor(w, r, tenant)
	if !ok {
		return
	}
	objectType, err := customFieldObjectType(params.ObjectType)
	id, idErr := customFieldEntityID(uuid.UUID(definitionID))
	if err != nil || idErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	definition, err := h.customFields.GetDefinition(r.Context(), actor.custom, tenant, objectType, id)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := customFieldDefinition(definition)
	if err != nil || !setVersionETag(w, mapped.SchemaVersion) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ReplaceTenantCustomFieldDefinition(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, definitionID contract.CustomFieldDefinitionId, _ contract.ReplaceTenantCustomFieldDefinitionParams) {
	tenant := uuid.UUID(tenantID)
	actor, audit, _, ok := h.phase4MutationActor(w, r, tenant)
	if !ok {
		return
	}
	key, err := requestIdempotencyKey(r)
	if err != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	var body contract.CustomFieldDefinitionReplaceRequest
	if err := decodePhase4Body(r, &body); err != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	if !phase4Precondition(w, r, int64(body.ExpectedVersion)) {
		return
	}
	id, err := customFieldEntityID(uuid.UUID(definitionID))
	if err != nil || body.ExpectedVersion >= math.MaxInt64 {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	input, err := customFieldDefinitionInput(tenant, uuid.UUID(definitionID), uint64(body.ExpectedVersion)+1, false, body.Definition)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.customFields.ReplaceDefinition(r.Context(), actor.custom, tenant, id, application.ReplaceDefinitionInput{
		Definition: input, ExpectedVersion: uint64(body.ExpectedVersion), IdempotencyKey: key, Audit: audit,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := customFieldDefinition(result.Definition)
	if err != nil || !setVersionETag(w, mapped.SchemaVersion) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ArchiveTenantCustomFieldDefinition(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, definitionID contract.CustomFieldDefinitionId, _ contract.ArchiveTenantCustomFieldDefinitionParams) {
	tenant := uuid.UUID(tenantID)
	actor, audit, _, ok := h.phase4MutationActor(w, r, tenant)
	if !ok {
		return
	}
	key, err := requestIdempotencyKey(r)
	if err != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	var body contract.CustomFieldDefinitionArchiveRequest
	if err := decodePhase4Body(r, &body); err != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	objectType, err := customFieldObjectType(body.ObjectType)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if !phase4Precondition(w, r, int64(body.ExpectedVersion)) {
		return
	}
	id, err := customFieldEntityID(uuid.UUID(definitionID))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.customFields.ArchiveDefinition(r.Context(), actor.custom, tenant, objectType, id, application.ArchiveDefinitionInput{
		ExpectedVersion: uint64(body.ExpectedVersion), Reason: body.Reason, IdempotencyKey: key, Audit: audit,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if result.Definition.SchemaVersion() > math.MaxInt64 || !setVersionETag(w, int64(result.Definition.SchemaVersion())) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) GetTenantObjectCustomFields(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, objectType contract.CustomFieldObjectType, objectID uuid.UUID, params contract.GetTenantObjectCustomFieldsParams) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.phase4ReadActor(w, r, tenant)
	if !ok {
		return
	}
	kind, err := customFieldObjectType(objectType)
	if err != nil || !params.Surface.Valid() || objectID == uuid.Nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	projection, err := h.customFields.ProjectObjectFields(r.Context(), actor.custom, tenant, application.ProjectionInput{
		ObjectType: kind, ObjectID: objectID, Surface: kernel.ProjectionSurface(params.Surface),
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	definitions := make([]contract.CustomFieldDefinition, len(projection.Definitions))
	for index, definition := range projection.Definitions {
		definitions[index], err = customFieldDefinition(definition)
		if err != nil {
			writeDomainError(w, r, application.ErrUnavailable)
			return
		}
	}
	values, err := customFieldProjectionValues(projection.Values)
	if err != nil || projection.Version == 0 || projection.Version > math.MaxInt64 || !setVersionETag(w, int64(projection.Version)) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, contract.CustomFieldProjection{
		ObjectType: objectType, ObjectId: objectID, Definitions: definitions, Values: values, Version: int64(projection.Version),
	})
}

func (h *Handler) ReplaceTenantObjectCustomFields(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, objectType contract.CustomFieldObjectType, objectID uuid.UUID, _ contract.ReplaceTenantObjectCustomFieldsParams) {
	tenant := uuid.UUID(tenantID)
	actor, audit, _, ok := h.phase4MutationActor(w, r, tenant)
	if !ok {
		return
	}
	key, err := requestIdempotencyKey(r)
	if err != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	var body contract.CustomFieldValuesReplaceRequest
	if err := decodePhase4Body(r, &body); err != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	if !phase4Precondition(w, r, int64(body.ExpectedVersion)) {
		return
	}
	kind, err := customFieldObjectType(objectType)
	fields, fieldsErr := rawCustomFieldInputs(body.Values)
	if err != nil || fieldsErr != nil || !body.Phase.Valid() || objectID == uuid.Nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	transition := ""
	if body.TransitionKey != nil {
		transition = *body.TransitionKey
	}
	result, err := h.customFields.ValidateAndCommitObjectFields(r.Context(), actor.custom, tenant, application.ObjectWriteInput{
		ObjectType: kind, ObjectID: objectID, Phase: kernel.WritePhase(body.Phase), TransitionKey: transition,
		Fields: fields, ExpectedVersion: uint64(body.ExpectedVersion), IdempotencyKey: key, Audit: audit,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	values, err := customFieldProjectionValues(result.Values)
	if err != nil || result.Version == 0 || result.Version > math.MaxInt64 || !setVersionETag(w, int64(result.Version)) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, contract.CustomFieldValuesResult{Values: values, Version: int64(result.Version)})
}

func phase4Precondition(w http.ResponseWriter, r *http.Request, bodyVersion int64) bool {
	version, present, err := strongVersionPrecondition(r)
	if err != nil {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return false
	}
	if !present {
		writeDomainError(w, r, authorization.ErrPreconditionRequired)
		return false
	}
	if version != bodyVersion || version > maximumIncrementableResourceVersion {
		writeDomainError(w, r, authorization.ErrInvalidInput)
		return false
	}
	return true
}
