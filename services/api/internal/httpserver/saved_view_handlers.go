package httpserver

import (
	"net/http"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func (h *Handler) ListTenantTicketViews(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.ListTenantTicketViewsParams,
) {
	actor, ok := h.savedViewReadActor(w, r)
	if !ok {
		return
	}
	kind, err := savedViewKind(string(params.Kind))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	input := application.SavedViewListInput{}
	if params.After != nil {
		input.After = string(*params.After)
	}
	if params.Limit != nil {
		input.Limit = int(*params.Limit)
	}
	if params.IncludeArchived != nil {
		input.IncludeArchived = bool(*params.IncludeArchived)
	}
	page, err := h.savedViews.ListSavedViews(r.Context(), actor, uuid.UUID(tenantID), kind, input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	items := make([]contract.SavedTicketView, len(page.Items))
	for index, record := range page.Items {
		items[index], err = mapSavedTicketView(record)
		if err != nil {
			writeDomainError(w, r, application.ErrUnavailable)
			return
		}
	}
	result := contract.SavedTicketViewPage{Items: items}
	if page.NextCursor != "" {
		value := contract.SavedTicketViewCursor(page.NextCursor)
		result.NextCursor = &value
	}
	writePrivateJSON(w, http.StatusOK, result)
}

func (h *Handler) CreateTenantTicketView(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	_ contract.CreateTenantTicketViewParams,
) {
	actor, key, ok := h.savedViewMutationActor(w, r)
	if !ok {
		return
	}
	var body savedViewCreateBody
	if decodeSLABody(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	kind, err := savedViewKind(body.Kind)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	spec, err := savedViewSpecInput(body.Spec)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.savedViews.CreateSavedView(r.Context(), actor, uuid.UUID(tenantID), kind, application.SavedViewCreateInput{
		Name: body.Name, Spec: spec, IdempotencyKey: key,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeSavedViewMutation(w, r, uuid.UUID(tenantID), http.StatusCreated, result, true)
}

func (h *Handler) GetTenantTicketView(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	viewID contract.SavedViewId,
	params contract.GetTenantTicketViewParams,
) {
	actor, ok := h.savedViewReadActor(w, r)
	if !ok {
		return
	}
	kind, err := savedViewKind(string(params.Kind))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	record, err := h.savedViews.GetSavedView(r.Context(), actor, uuid.UUID(tenantID), kind, uuid.UUID(viewID))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapSavedTicketView(record)
	if err != nil || !setSavedViewETag(w, record) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writePrivateJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ReplaceTenantTicketView(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	viewID contract.SavedViewId,
	params contract.ReplaceTenantTicketViewParams,
) {
	actor, key, ok := h.savedViewMutationActor(w, r)
	if !ok {
		return
	}
	var body savedViewReplaceBody
	if decodeSLABody(r, &body) != nil || body.ExpectedRevision <= 0 {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	kind, err := savedViewKind(body.Kind)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	spec, err := savedViewSpecInput(body.Spec)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.savedViews.ReplaceSavedView(r.Context(), actor, uuid.UUID(tenantID), kind, uuid.UUID(viewID), application.SavedViewReplaceInput{
		ExpectedRevision: uint64(body.ExpectedRevision), ExpectedETag: string(params.IfMatch),
		Name: body.Name, Spec: spec, IdempotencyKey: key,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeSavedViewMutation(w, r, uuid.UUID(tenantID), http.StatusOK, result, false)
}

func (h *Handler) ArchiveTenantTicketView(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	viewID contract.SavedViewId,
	params contract.ArchiveTenantTicketViewParams,
) {
	h.savedViewLifecycle(w, r, uuid.UUID(tenantID), uuid.UUID(viewID), string(params.IfMatch), func(
		actor application.Actor, kind kernel.AggregateKind, input application.SavedViewLifecycleInput,
	) (application.SavedViewMutationResult, error) {
		return h.savedViews.ArchiveSavedView(r.Context(), actor, uuid.UUID(tenantID), kind, uuid.UUID(viewID), input)
	})
}

func (h *Handler) RestoreTenantTicketView(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	viewID contract.SavedViewId,
	params contract.RestoreTenantTicketViewParams,
) {
	h.savedViewLifecycle(w, r, uuid.UUID(tenantID), uuid.UUID(viewID), string(params.IfMatch), func(
		actor application.Actor, kind kernel.AggregateKind, input application.SavedViewLifecycleInput,
	) (application.SavedViewMutationResult, error) {
		return h.savedViews.RestoreSavedView(r.Context(), actor, uuid.UUID(tenantID), kind, uuid.UUID(viewID), input)
	})
}

func (h *Handler) savedViewLifecycle(
	w http.ResponseWriter,
	r *http.Request,
	tenantID, viewID uuid.UUID,
	etag string,
	mutate func(application.Actor, kernel.AggregateKind, application.SavedViewLifecycleInput) (application.SavedViewMutationResult, error),
) {
	actor, key, ok := h.savedViewMutationActor(w, r)
	if !ok {
		return
	}
	var body savedViewLifecycleBody
	if decodeSLABody(r, &body) != nil || body.ExpectedRevision <= 0 {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	kind, err := savedViewKind(body.Kind)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := mutate(actor, kind, application.SavedViewLifecycleInput{
		ExpectedRevision: uint64(body.ExpectedRevision), ExpectedETag: etag, IdempotencyKey: key,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeSavedViewMutation(w, r, tenantID, http.StatusOK, result, false)
}

func (h *Handler) savedViewReadActor(w http.ResponseWriter, r *http.Request) (application.Actor, bool) {
	actor, ok := h.ticketingReadActor(w, r)
	if !ok {
		return application.Actor{}, false
	}
	if h.savedViews == nil {
		writeDomainError(w, r, application.ErrUnavailable)
		return application.Actor{}, false
	}
	return actor, true
}

func (h *Handler) savedViewMutationActor(w http.ResponseWriter, r *http.Request) (application.Actor, string, bool) {
	actor, ok := h.ticketingMutationActor(w, r)
	if !ok {
		return application.Actor{}, "", false
	}
	if h.savedViews == nil {
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

func (h *Handler) writeSavedViewMutation(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
	status int,
	result application.SavedViewMutationResult,
	location bool,
) {
	mapped, err := mapSavedTicketView(result.Record)
	if err != nil || !setSavedViewETag(w, result.Record) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	if location {
		w.Header().Set("Location", "/api/v1/tenants/"+tenantID.String()+"/ticket-views/"+uuid.UUID(result.Record.View.ID().Bytes()).String())
	}
	writePrivateJSON(w, status, contract.SavedTicketViewMutationResult{View: mapped, Replayed: result.Replayed})
}

func setSavedViewETag(w http.ResponseWriter, record application.SavedViewRecord) bool {
	value := application.SavedViewStrongETag(record)
	if !application.ValidSavedViewStrongETag(value) {
		return false
	}
	w.Header().Set("ETag", value)
	return true
}

func writePrivateJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "private, no-store")
	writeJSON(w, status, value)
}
