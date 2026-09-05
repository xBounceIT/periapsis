package httpserver

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	applicationticketing "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func (h *Handler) ListTenantWorkflows(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.ListTenantWorkflowsParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.workflowReadActor(w, r, tenant)
	if !ok {
		return
	}
	input, err := workflowListInput(params)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	page, err := h.workflowAdministration.ListWorkflows(r.Context(), actor, tenant, input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	items := make([]contract.ManagedWorkflow, len(page.Items))
	for index, record := range page.Items {
		items[index], err = mapManagedWorkflow(record)
		if err != nil {
			writeDomainError(w, r, applicationticketing.ErrUnavailable)
			return
		}
	}
	response := contract.WorkflowAdminPage{Items: items}
	if page.NextCursor != "" {
		response.NextCursor = &page.NextCursor
	}
	writeSensitiveJSON(w, http.StatusOK, response)
}

func (h *Handler) CreateTenantWorkflow(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	_ contract.CreateTenantWorkflowParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, key, ok := h.workflowMutationContext(w, r, tenant)
	if !ok {
		return
	}
	var body workflowCreateBody
	if decodeWorkflowBody(r, &body) != nil {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	kind, err := workflowAggregateKind(body.Kind)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	design, err := workflowDesignInput(body.Design)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.workflowAdministration.CreateWorkflow(r.Context(), actor, tenant, applicationticketing.WorkflowCreateInput{
		Kind: kind, Key: body.Key, DisplayName: body.DisplayName, Description: body.Description,
		Design: design, IdempotencyKey: key,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	workflowID := uuid.UUID(result.Record.Workflow.ID().Bytes())
	w.Header().Set("Location", workflowLocation(tenant, workflowID))
	h.writeWorkflowMutation(w, r, http.StatusCreated, result)
}

func (h *Handler) GetTenantWorkflow(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	workflowID contract.WorkflowId,
) {
	actor, ok := h.workflowReadActor(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	record, err := h.workflowAdministration.GetWorkflow(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(workflowID),
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapManagedWorkflow(record)
	if err != nil || !setWorkflowETag(w, record) {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) UpdateTenantWorkflowMetadata(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	workflowID contract.WorkflowId,
	params contract.UpdateTenantWorkflowMetadataParams,
) {
	actor, key, ok := h.workflowMutationContext(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	var body workflowMetadataBody
	if decodeWorkflowBody(r, &body) != nil {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	if !h.requireWorkflowPrecondition(w, r, uuid.UUID(workflowID), body.ExpectedRevision, string(params.IfMatch)) {
		return
	}
	result, err := h.workflowAdministration.UpdateWorkflowMetadata(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(workflowID), applicationticketing.WorkflowMetadataInput{
			ExpectedRevision: uint64(body.ExpectedRevision), DisplayName: body.DisplayName,
			Description: body.Description, IdempotencyKey: key,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeWorkflowMutation(w, r, http.StatusOK, result)
}

func (h *Handler) ListTenantWorkflowVersions(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	workflowID contract.WorkflowId,
	params contract.ListTenantWorkflowVersionsParams,
) {
	actor, ok := h.workflowReadActor(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	input := applicationticketing.WorkflowVersionListInput{}
	if params.AfterVersion != nil {
		if *params.AfterVersion <= 0 {
			writeDomainError(w, r, applicationticketing.ErrInvalidInput)
			return
		}
		input.AfterVersion = uint64(*params.AfterVersion)
	}
	if params.Limit != nil {
		input.Limit = int(*params.Limit)
	}
	page, err := h.workflowAdministration.ListWorkflowVersions(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(workflowID), input,
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	items := make([]contract.WorkflowVersionRecord, len(page.Items))
	for index, item := range page.Items {
		items[index], err = mapWorkflowVersion(item)
		if err != nil {
			writeDomainError(w, r, applicationticketing.ErrUnavailable)
			return
		}
	}
	response := contract.WorkflowVersionPage{Items: items}
	if page.NextVersion != 0 {
		value := contract.WorkflowResourceVersion(page.NextVersion)
		response.NextVersion = &value
	}
	writeSensitiveJSON(w, http.StatusOK, response)
}

func (h *Handler) PublishTenantWorkflowVersion(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	workflowID contract.WorkflowId,
	params contract.PublishTenantWorkflowVersionParams,
) {
	actor, key, ok := h.workflowMutationContext(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	var body workflowPublishBody
	if decodeWorkflowBody(r, &body) != nil {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	if !h.requireWorkflowPrecondition(w, r, uuid.UUID(workflowID), body.ExpectedRevision, string(params.IfMatch)) {
		return
	}
	design, err := workflowDesignInput(body.Design)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.workflowAdministration.PublishWorkflow(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(workflowID), applicationticketing.WorkflowPublishInput{
			ExpectedRevision: uint64(body.ExpectedRevision), Design: design, IdempotencyKey: key,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeWorkflowMutation(w, r, http.StatusOK, result)
}

func (h *Handler) GetTenantWorkflowVersion(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	workflowID contract.WorkflowId,
	version contract.WorkflowVersion,
) {
	actor, ok := h.workflowReadActor(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	if version <= 0 {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	record, err := h.workflowAdministration.GetWorkflowVersion(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(workflowID), uint64(version),
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapWorkflowVersion(record)
	if err != nil {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) SimulateTenantWorkflow(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	workflowID contract.WorkflowId,
) {
	actor, ok := h.workflowPostReadActor(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	var body workflowSimulationBody
	if decodeWorkflowBody(r, &body) != nil {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	input, err := workflowSimulationInput(body)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.workflowAdministration.SimulateWorkflow(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(workflowID), input,
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapWorkflowSimulation(result)
	if err != nil {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) SetDefaultTenantWorkflow(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	workflowID contract.WorkflowId,
	params contract.SetDefaultTenantWorkflowParams,
) {
	h.workflowLifecycleMutation(w, r, uuid.UUID(tenantID), uuid.UUID(workflowID), string(params.IfMatch),
		func(ctxActor applicationticketing.Actor, input applicationticketing.WorkflowLifecycleInput) (applicationticketing.WorkflowAdminMutationResult, error) {
			return h.workflowAdministration.SetDefaultWorkflow(r.Context(), ctxActor, uuid.UUID(tenantID), uuid.UUID(workflowID), input)
		})
}

func (h *Handler) ArchiveTenantWorkflow(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	workflowID contract.WorkflowId,
	params contract.ArchiveTenantWorkflowParams,
) {
	h.workflowLifecycleMutation(w, r, uuid.UUID(tenantID), uuid.UUID(workflowID), string(params.IfMatch),
		func(ctxActor applicationticketing.Actor, input applicationticketing.WorkflowLifecycleInput) (applicationticketing.WorkflowAdminMutationResult, error) {
			return h.workflowAdministration.ArchiveWorkflow(r.Context(), ctxActor, uuid.UUID(tenantID), uuid.UUID(workflowID), input)
		})
}

func (h *Handler) RestoreTenantWorkflow(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	workflowID contract.WorkflowId,
	params contract.RestoreTenantWorkflowParams,
) {
	h.workflowLifecycleMutation(w, r, uuid.UUID(tenantID), uuid.UUID(workflowID), string(params.IfMatch),
		func(ctxActor applicationticketing.Actor, input applicationticketing.WorkflowLifecycleInput) (applicationticketing.WorkflowAdminMutationResult, error) {
			return h.workflowAdministration.RestoreWorkflow(r.Context(), ctxActor, uuid.UUID(tenantID), uuid.UUID(workflowID), input)
		})
}

func (h *Handler) workflowLifecycleMutation(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
	workflowID uuid.UUID,
	ifMatch string,
	execute func(applicationticketing.Actor, applicationticketing.WorkflowLifecycleInput) (applicationticketing.WorkflowAdminMutationResult, error),
) {
	actor, key, ok := h.workflowMutationContext(w, r, tenantID)
	if !ok {
		return
	}
	var body workflowLifecycleBody
	if decodeWorkflowBody(r, &body) != nil {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	if !h.requireWorkflowPrecondition(w, r, workflowID, body.ExpectedRevision, ifMatch) {
		return
	}
	result, err := execute(actor, applicationticketing.WorkflowLifecycleInput{
		ExpectedRevision: uint64(body.ExpectedRevision), IdempotencyKey: key,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeWorkflowMutation(w, r, http.StatusOK, result)
}

func (h *Handler) workflowReadActor(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID) (applicationticketing.Actor, bool) {
	actor, ok := h.tenantAuthorizationActor(w, r)
	if !ok {
		return applicationticketing.Actor{}, false
	}
	if actor.ActiveTenantID != tenantID {
		writeDomainError(w, r, applicationticketing.ErrForbidden)
		return applicationticketing.Actor{}, false
	}
	if h.workflowAdministration == nil {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return applicationticketing.Actor{}, false
	}
	return applicationticketing.Actor{
		UserID: actor.UserID, SessionID: actor.SessionID, ActiveTenantID: actor.ActiveTenantID,
		AuthenticationMethod: actor.AuthenticationMethod,
	}, true
}

func (h *Handler) workflowPostReadActor(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID) (applicationticketing.Actor, bool) {
	actor, _, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return applicationticketing.Actor{}, false
	}
	if actor.ActiveTenantID != tenantID {
		writeDomainError(w, r, applicationticketing.ErrForbidden)
		return applicationticketing.Actor{}, false
	}
	if h.workflowAdministration == nil {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return applicationticketing.Actor{}, false
	}
	return applicationticketing.Actor{
		UserID: actor.UserID, SessionID: actor.SessionID, ActiveTenantID: actor.ActiveTenantID,
		AuthenticationMethod: actor.AuthenticationMethod,
	}, true
}

func (h *Handler) workflowMutationContext(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
) (applicationticketing.Actor, string, bool) {
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return applicationticketing.Actor{}, "", false
	}
	if actor.ActiveTenantID != tenantID {
		writeDomainError(w, r, applicationticketing.ErrForbidden)
		return applicationticketing.Actor{}, "", false
	}
	if h.workflowAdministration == nil {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return applicationticketing.Actor{}, "", false
	}
	key, err := requestIdempotencyKey(r)
	if err != nil {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return applicationticketing.Actor{}, "", false
	}
	return applicationticketing.Actor{
		UserID: actor.UserID, SessionID: actor.SessionID, ActiveTenantID: actor.ActiveTenantID,
		AuthenticationMethod: actor.AuthenticationMethod,
		Audit: applicationticketing.AuditContext{
			RequestID: audit.RequestID, CorrelationID: audit.CorrelationID,
			RemoteAddress: audit.RemoteAddress, UserAgent: audit.UserAgent,
		},
	}, key, true
}

func (h *Handler) requireWorkflowPrecondition(
	w http.ResponseWriter,
	r *http.Request,
	workflowID uuid.UUID,
	expectedRevision int64,
	boundHeader string,
) bool {
	if expectedRevision <= 0 || expectedRevision > maximumResourceVersion || workflowID == uuid.Nil {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return false
	}
	value, err := singleHeader(r, ifMatchHeader, 128)
	if err != nil || value != boundHeader {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return false
	}
	revision, err := workflowETagRevision(value)
	if err != nil {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return false
	}
	expected := applicationticketing.WorkflowAdminStrongETagFor(workflowID, uint64(expectedRevision))
	if revision != uint64(expectedRevision) || value != expected {
		writeDomainError(w, r, applicationticketing.ErrPreconditionFailed)
		return false
	}
	return true
}

func workflowETagRevision(value string) (uint64, error) {
	if len(value) < 48 || len(value) > 57 || !strings.HasPrefix(value, "\"v") || !strings.HasSuffix(value, "\"") {
		return 0, errors.New("workflow ETag shape is invalid")
	}
	separator := strings.IndexByte(value, '-')
	if separator < 3 || separator >= len(value)-2 {
		return 0, errors.New("workflow ETag shape is invalid")
	}
	revision, err := strconv.ParseUint(value[2:separator], 10, 64)
	if err != nil || revision == 0 || revision > uint64(maximumResourceVersion) || value[2] == '0' {
		return 0, errors.New("workflow ETag revision is invalid")
	}
	digestText := value[separator+1 : len(value)-1]
	digest, err := base64.RawURLEncoding.Strict().DecodeString(digestText)
	if err != nil || len(digest) != 32 || base64.RawURLEncoding.EncodeToString(digest) != digestText {
		return 0, errors.New("workflow ETag digest is invalid")
	}
	return revision, nil
}

func (h *Handler) writeWorkflowMutation(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	result applicationticketing.WorkflowAdminMutationResult,
) {
	mapped, err := mapManagedWorkflow(result.Record)
	if err != nil || !setWorkflowETag(w, result.Record) {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, status, contract.WorkflowAdminMutationResult{Workflow: mapped, Replayed: result.Replayed})
}

func setWorkflowETag(w http.ResponseWriter, record applicationticketing.WorkflowAdminRecord) bool {
	etag := applicationticketing.WorkflowAdminStrongETag(record)
	if _, err := workflowETagRevision(etag); err != nil {
		return false
	}
	w.Header().Set("ETag", etag)
	return true
}

func workflowListInput(params contract.ListTenantWorkflowsParams) (applicationticketing.WorkflowAdminListInput, error) {
	input := applicationticketing.WorkflowAdminListInput{}
	if params.After != nil {
		input.After = *params.After
	}
	if params.Limit != nil {
		input.Limit = int(*params.Limit)
	}
	if params.Search != nil {
		input.Search = *params.Search
	}
	if params.Default != nil {
		input.DefaultOnly = *params.Default
	}
	if params.Kind != nil {
		kind, err := workflowAggregateKind(string(*params.Kind))
		if err != nil {
			return applicationticketing.WorkflowAdminListInput{}, err
		}
		input.Kind = &kind
	}
	if params.Status != nil {
		var status kernel.WorkflowStatus
		switch string(*params.Status) {
		case "active":
			status = kernel.WorkflowActive
		case "archived":
			status = kernel.WorkflowArchived
		default:
			return applicationticketing.WorkflowAdminListInput{}, applicationticketing.ErrInvalidInput
		}
		input.Status = &status
	}
	return input, nil
}

func workflowAggregateKind(value string) (kernel.AggregateKind, error) {
	switch value {
	case "alert":
		return kernel.AggregateAlert, nil
	case "case":
		return kernel.AggregateCase, nil
	default:
		return 0, applicationticketing.ErrInvalidInput
	}
}

func workflowLocation(tenantID, workflowID uuid.UUID) string {
	return "/api/v1/tenants/" + tenantID.String() + "/workflows/" + workflowID.String()
}
