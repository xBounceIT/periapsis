package httpserver

import (
	"net/http"
	"net/url"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func (h *Handler) RequestTenantTicketExport(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	_ contract.RequestTenantTicketExportParams,
) {
	actor, key, ok := h.ticketExportMutationActor(w, r)
	if !ok {
		return
	}
	var body ticketExportRequestBody
	if decodeTicketExportBody(r, &body) != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	kind, err := savedViewKind(body.Kind)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	input, err := ticketExportRequestInput(body, key)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.asyncExports.Request(r.Context(), actor, uuid.UUID(tenantID), kind, input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapRequestedTicketExportMutationResult(
		result, uuid.UUID(tenantID), actor.UserID, kind, input,
	)
	if err != nil {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set("Location", "/api/v1/tenants/"+uuid.UUID(tenantID).String()+"/ticket-exports/"+mapped.Job.Id.String())
	writePrivateJSON(w, http.StatusAccepted, mapped)
}

func (h *Handler) GetTenantTicketExport(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	jobID uuid.UUID,
	params contract.GetTenantTicketExportParams,
) {
	actor, ok := h.ticketExportReadActor(w, r)
	if !ok {
		return
	}
	kind, err := savedViewKind(string(params.Kind))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	record, err := h.asyncExports.Get(
		r.Context(), actor, uuid.UUID(tenantID), kind, kernel.TicketExportAudienceOperator, jobID,
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapOwnedTicketExportJob(record, uuid.UUID(tenantID), actor.UserID, kind)
	if err != nil {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writePrivateJSON(w, http.StatusOK, mapped)
}

func (h *Handler) CancelTenantTicketExport(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	jobID uuid.UUID,
	_ contract.CancelTenantTicketExportParams,
) {
	actor, key, ok := h.ticketExportMutationActor(w, r)
	if !ok {
		return
	}
	var body ticketExportCancelBody
	if decodeTicketExportBody(r, &body) != nil || body.ExpectedRevision < 1 ||
		body.ExpectedRevision >= maximumResourceVersion {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	kind, err := savedViewKind(body.Kind)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.asyncExports.Cancel(
		r.Context(), actor, uuid.UUID(tenantID), kind, kernel.TicketExportAudienceOperator, jobID,
		application.AsyncExportCancelInput{
			ExpectedRevision: uint64(body.ExpectedRevision), IdempotencyKey: key,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapCancelledTicketExportMutationResult(
		result, uuid.UUID(tenantID), actor.UserID, kind, uint64(body.ExpectedRevision),
	)
	if err != nil {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writePrivateJSON(w, http.StatusOK, mapped)
}

func (h *Handler) PrepareTenantTicketExportDownload(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	jobID uuid.UUID,
	params contract.PrepareTenantTicketExportDownloadParams,
) {
	actor, ok := h.ticketExportDownloadActor(w, r)
	if !ok {
		return
	}
	kind, err := savedViewKind(string(params.Kind))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	prepared, err := h.asyncExports.PrepareDownload(
		r.Context(), actor, uuid.UUID(tenantID), kind, kernel.TicketExportAudienceOperator, jobID,
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapPreparedTicketExportDownload(
		prepared, uuid.UUID(tenantID), actor.UserID, kind, jobID,
	)
	if err != nil {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writePrivateJSON(w, http.StatusOK, mapped)
}

func mapPreparedTicketExportDownload(
	prepared application.AsyncExportPreparedDownload,
	tenantID, requesterID uuid.UUID,
	kind kernel.AggregateKind,
	jobID uuid.UUID,
) (contract.TicketExportPreparedDownload, error) {
	job, err := mapOwnedTicketExportJob(prepared.Record, tenantID, requesterID, kind)
	if err != nil || job.Id != jobID || job.State != contract.TicketExportStateSucceeded || job.Artifact == nil {
		return contract.TicketExportPreparedDownload{}, application.ErrUnavailable
	}
	artifact, err := mapTicketExportArtifact(prepared.Artifact, prepared.Record.Job.Definition())
	if err != nil || artifact != *job.Artifact || !validTicketExportDownloadResponseURL(prepared.Grant.TargetURL) ||
		prepared.Grant.ExpiresAt.IsZero() || prepared.Grant.ExpiresAt.After(artifact.ExpiresAt) {
		return contract.TicketExportPreparedDownload{}, application.ErrUnavailable
	}
	return contract.TicketExportPreparedDownload{
		Artifact: artifact, DownloadUrl: prepared.Grant.TargetURL, ExpiresAt: prepared.Grant.ExpiresAt.UTC(),
	}, nil
}

func validTicketExportDownloadResponseURL(raw string) bool {
	if raw == "" || len(raw) > 8_192 || !utf8.ValidString(raw) {
		return false
	}
	for _, character := range raw {
		if unicode.IsControl(character) {
			return false
		}
	}
	parsed, err := url.Parse(raw)
	return err == nil && parsed.IsAbs() && parsed.Host != "" && parsed.User == nil &&
		parsed.Fragment == "" && (parsed.Scheme == "https" || parsed.Scheme == "http")
}

func (h *Handler) ticketExportReadActor(
	w http.ResponseWriter,
	r *http.Request,
) (application.Actor, bool) {
	actor, ok := h.ticketingReadActor(w, r)
	if !ok {
		return application.Actor{}, false
	}
	if h.asyncExports == nil {
		writeDomainError(w, r, application.ErrUnavailable)
		return application.Actor{}, false
	}
	return actor, true
}

func (h *Handler) ticketExportMutationActor(
	w http.ResponseWriter,
	r *http.Request,
) (application.Actor, string, bool) {
	actor, ok := h.ticketingMutationActor(w, r)
	if !ok {
		return application.Actor{}, "", false
	}
	if h.asyncExports == nil {
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

func (h *Handler) ticketExportDownloadActor(
	w http.ResponseWriter,
	r *http.Request,
) (application.Actor, bool) {
	actor, ok := h.ticketingMutationActor(w, r)
	if !ok {
		return application.Actor{}, false
	}
	if h.asyncExports == nil {
		writeDomainError(w, r, application.ErrUnavailable)
		return application.Actor{}, false
	}
	return actor, true
}
