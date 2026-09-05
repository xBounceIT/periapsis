package httpserver

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func (h *Handler) RequestTenantTicketBulkJob(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	_ contract.RequestTenantTicketBulkJobParams,
) {
	actor, key, ok := h.ticketBulkMutationActor(w, r)
	if !ok {
		return
	}
	var body ticketBulkRequestBody
	if decodeTicketBulkBody(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	kind, err := savedViewKind(body.Kind)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	input, err := ticketBulkRequestInput(body, key)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.ticketBulk.Request(r.Context(), actor, uuid.UUID(tenantID), kind, input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapTicketBulkMutationResult(result)
	if err != nil {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	jobID := uuid.UUID(result.Record.Job.Definition().ID().Bytes())
	w.Header().Set("Location", "/api/v1/tenants/"+uuid.UUID(tenantID).String()+"/ticket-bulk-jobs/"+jobID.String())
	writePrivateJSON(w, http.StatusAccepted, mapped)
}

func (h *Handler) GetTenantTicketBulkJob(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	jobID uuid.UUID,
	params contract.GetTenantTicketBulkJobParams,
) {
	actor, ok := h.ticketBulkReadActor(w, r)
	if !ok {
		return
	}
	kind, err := savedViewKind(string(params.Kind))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	record, err := h.ticketBulk.Get(r.Context(), actor, uuid.UUID(tenantID), kind, jobID)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapTicketBulkJob(record)
	if err != nil {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writePrivateJSON(w, http.StatusOK, mapped)
}

func (h *Handler) CancelTenantTicketBulkJob(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	jobID uuid.UUID,
	_ contract.CancelTenantTicketBulkJobParams,
) {
	actor, key, ok := h.ticketBulkMutationActor(w, r)
	if !ok {
		return
	}
	var body ticketBulkCancelBody
	if decodeTicketBulkBody(r, &body) != nil || body.ExpectedRevision <= 0 || body.ExpectedRevision > 2_147_483_647 {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	kind, err := savedViewKind(body.Kind)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.ticketBulk.Cancel(r.Context(), actor, uuid.UUID(tenantID), kind, jobID, application.TicketBulkCancelInput{
		ExpectedRevision: uint64(body.ExpectedRevision), IdempotencyKey: key,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapTicketBulkMutationResult(result)
	if err != nil {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writePrivateJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ListTenantTicketBulkJobResults(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	jobID uuid.UUID,
	params contract.ListTenantTicketBulkJobResultsParams,
) {
	actor, ok := h.ticketBulkReadActor(w, r)
	if !ok {
		return
	}
	kind, err := savedViewKind(string(params.Kind))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	input := application.TicketBulkResultListInput{Limit: 50}
	if params.Limit != nil {
		input.Limit = int(*params.Limit)
	}
	if params.After != nil {
		input.After = *params.After
	}
	page, err := h.ticketBulk.ListResults(r.Context(), actor, uuid.UUID(tenantID), kind, jobID, input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapTicketBulkResultPage(page)
	if err != nil {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writePrivateJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ticketBulkReadActor(w http.ResponseWriter, r *http.Request) (application.Actor, bool) {
	actor, ok := h.ticketingReadActor(w, r)
	if !ok {
		return application.Actor{}, false
	}
	if h.ticketBulk == nil {
		writeDomainError(w, r, application.ErrUnavailable)
		return application.Actor{}, false
	}
	return actor, true
}

func (h *Handler) ticketBulkMutationActor(w http.ResponseWriter, r *http.Request) (application.Actor, string, bool) {
	actor, ok := h.ticketingMutationActor(w, r)
	if !ok {
		return application.Actor{}, "", false
	}
	if h.ticketBulk == nil {
		writeDomainError(w, r, application.ErrUnavailable)
		return application.Actor{}, "", false
	}
	key, err := requestIdempotencyKey(r)
	if err != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return application.Actor{}, "", false
	}
	return actor, key, true
}
