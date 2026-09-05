package httpserver

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	applicationticketing "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func (h *Handler) AssignTenantAlert(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, alertID contract.AlertId, params contract.AssignTenantAlertParams) {
	h.assignTicket(w, r, uuid.UUID(tenantID), kernel.AggregateAlert, uuid.UUID(alertID), params.IfMatch)
}

func (h *Handler) AssignTenantCase(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, params contract.AssignTenantCaseParams) {
	h.assignTicket(w, r, uuid.UUID(tenantID), kernel.AggregateCase, uuid.UUID(caseID), params.IfMatch)
}

func (h *Handler) ClaimTenantAlert(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, alertID contract.AlertId, params contract.ClaimTenantAlertParams) {
	h.claimTicket(w, r, uuid.UUID(tenantID), kernel.AggregateAlert, uuid.UUID(alertID), params.IfMatch)
}

func (h *Handler) ClaimTenantCase(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, params contract.ClaimTenantCaseParams) {
	h.claimTicket(w, r, uuid.UUID(tenantID), kernel.AggregateCase, uuid.UUID(caseID), params.IfMatch)
}

func (h *Handler) ReleaseTenantAlert(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, alertID contract.AlertId, params contract.ReleaseTenantAlertParams) {
	h.releaseTicket(w, r, uuid.UUID(tenantID), kernel.AggregateAlert, uuid.UUID(alertID), params.IfMatch)
}

func (h *Handler) ReleaseTenantCase(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, params contract.ReleaseTenantCaseParams) {
	h.releaseTicket(w, r, uuid.UUID(tenantID), kernel.AggregateCase, uuid.UUID(caseID), params.IfMatch)
}

func (h *Handler) TransferTenantAlert(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, alertID contract.AlertId, params contract.TransferTenantAlertParams) {
	h.transferTicket(w, r, uuid.UUID(tenantID), kernel.AggregateAlert, uuid.UUID(alertID), params.IfMatch)
}

func (h *Handler) TransferTenantCase(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, params contract.TransferTenantCaseParams) {
	h.transferTicket(w, r, uuid.UUID(tenantID), kernel.AggregateCase, uuid.UUID(caseID), params.IfMatch)
}

func (h *Handler) TransitionTenantAlert(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, alertID contract.AlertId, params contract.TransitionTenantAlertParams) {
	h.transitionTicket(w, r, uuid.UUID(tenantID), kernel.AggregateAlert, uuid.UUID(alertID), params.IfMatch, kernel.TransitionIntentAny)
}

func (h *Handler) TransitionTenantCase(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, params contract.TransitionTenantCaseParams) {
	h.transitionTicket(w, r, uuid.UUID(tenantID), kernel.AggregateCase, uuid.UUID(caseID), params.IfMatch, kernel.TransitionIntentAny)
}

func (h *Handler) CloseTenantAlert(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, alertID contract.AlertId, params contract.CloseTenantAlertParams) {
	h.transitionTicket(w, r, uuid.UUID(tenantID), kernel.AggregateAlert, uuid.UUID(alertID), params.IfMatch, kernel.TransitionIntentClose)
}

func (h *Handler) ReopenTenantAlert(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, alertID contract.AlertId, params contract.ReopenTenantAlertParams) {
	h.transitionTicket(w, r, uuid.UUID(tenantID), kernel.AggregateAlert, uuid.UUID(alertID), params.IfMatch, kernel.TransitionIntentReopen)
}

func (h *Handler) CloseTenantCase(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, params contract.CloseTenantCaseParams) {
	h.transitionTicket(w, r, uuid.UUID(tenantID), kernel.AggregateCase, uuid.UUID(caseID), params.IfMatch, kernel.TransitionIntentClose)
}

func (h *Handler) ReopenTenantCase(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, params contract.ReopenTenantCaseParams) {
	h.transitionTicket(w, r, uuid.UUID(tenantID), kernel.AggregateCase, uuid.UUID(caseID), params.IfMatch, kernel.TransitionIntentReopen)
}

func (h *Handler) assignTicket(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, kind kernel.AggregateKind, id uuid.UUID, ifMatch contract.IfMatch) {
	actor, expected, ok := h.ticketingMutationPrecondition(w, r, ifMatch)
	if !ok {
		return
	}
	var body contract.TicketAssignmentRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil || !bodyVersionMatches(body.ExpectedVersion, expected) {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	team := uuid.UUID(body.AssignedTeamId)
	input := applicationticketing.MutationInput{ExpectedVersion: expected, TeamID: &team, AssigneeID: body.AssigneeUserId}
	if body.Reason != nil {
		input.Reason = *body.Reason
	}
	h.executeTicketMutation(w, r, actor, tenantID, kind, id, kernel.ActionAssign, input)
}

func (h *Handler) claimTicket(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, kind kernel.AggregateKind, id uuid.UUID, ifMatch contract.IfMatch) {
	actor, expected, ok := h.ticketingMutationPrecondition(w, r, ifMatch)
	if !ok {
		return
	}
	var body contract.TicketClaimRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil || !bodyVersionMatches(body.ExpectedVersion, expected) {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	input := applicationticketing.MutationInput{ExpectedVersion: expected, TeamID: body.OperatorTeamId}
	if body.Reason != nil {
		input.Reason = *body.Reason
	}
	result, err := h.ticketing.Mutate(r.Context(), actor, tenantID, kind, id, kernel.ActionClaim, input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapTicketView(result.View)
	if err != nil || result.ClaimWinner == nil || !setVersionETag(w, int64(result.View.Record.Snapshot.Version())) {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	key := "alert"
	if kind == kernel.AggregateCase {
		key = "case"
	}
	writeSensitiveJSON(w, http.StatusOK, map[string]any{
		key: mapped,
		"winner": map[string]any{
			"claimedBy": result.ClaimWinner.ClaimedBy, "claimedAt": result.ClaimWinner.ClaimedAt,
			"version": result.ClaimWinner.Version,
		},
		"sideEffects": result.Effects,
	})
}

func (h *Handler) releaseTicket(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, kind kernel.AggregateKind, id uuid.UUID, ifMatch contract.IfMatch) {
	actor, expected, ok := h.ticketingMutationPrecondition(w, r, ifMatch)
	if !ok {
		return
	}
	var body contract.TicketReleaseRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil || !bodyVersionMatches(body.ExpectedVersion, expected) {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	h.executeTicketMutation(w, r, actor, tenantID, kind, id, kernel.ActionRelease, applicationticketing.MutationInput{
		ExpectedVersion: expected, Reason: body.Reason,
	})
}

func (h *Handler) transferTicket(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, kind kernel.AggregateKind, id uuid.UUID, ifMatch contract.IfMatch) {
	actor, expected, ok := h.ticketingMutationPrecondition(w, r, ifMatch)
	if !ok {
		return
	}
	var body contract.TicketTransferRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil || !bodyVersionMatches(body.ExpectedVersion, expected) {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	team := uuid.UUID(body.DestinationTeamId)
	h.executeTicketMutation(w, r, actor, tenantID, kind, id, kernel.ActionTransfer, applicationticketing.MutationInput{
		ExpectedVersion: expected, TeamID: &team, AssigneeID: body.DestinationAssigneeUserId, Reason: body.Reason,
	})
}

func (h *Handler) transitionTicket(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	id uuid.UUID,
	ifMatch contract.IfMatch,
	intent kernel.TransitionIntent,
) {
	actor, expected, ok := h.ticketingMutationPrecondition(w, r, ifMatch)
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	var body contract.TicketTransitionRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil || !bodyVersionMatches(body.ExpectedVersion, expected) {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	if _, err := httpContractKeys([]string{body.TransitionKey}); err != nil {
		writeDomainError(w, r, err)
		return
	}
	if _, err := httpContractKeys([]string{body.TargetStateKey}); err != nil {
		writeDomainError(w, r, err)
		return
	}
	customFields, err := contractCustomFields(body.CustomFields)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	input := applicationticketing.MutationInput{
		ExpectedVersion: expected, TransitionIntent: intent,
		TransitionKey: body.TransitionKey, TargetStateKey: body.TargetStateKey,
		CustomFields: customFields, IdempotencyKey: idempotencyKey,
	}
	if body.Comment != nil {
		input.Comment = *body.Comment
	}
	h.executeTicketMutation(w, r, actor, tenantID, kind, id, kernel.ActionTransition, input)
}

func (h *Handler) executeTicketMutation(w http.ResponseWriter, r *http.Request, actor applicationticketing.Actor, tenantID uuid.UUID, kind kernel.AggregateKind, id uuid.UUID, action kernel.Action, input applicationticketing.MutationInput) {
	result, err := h.ticketing.Mutate(r.Context(), actor, tenantID, kind, id, action, input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapTicketView(result.View)
	if err != nil || !setVersionETag(w, int64(result.View.Record.Snapshot.Version())) {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ticketingMutationPrecondition(w http.ResponseWriter, r *http.Request, ifMatch contract.IfMatch) (applicationticketing.Actor, uint64, bool) {
	actor, ok := h.ticketingMutationActor(w, r)
	if !ok {
		return applicationticketing.Actor{}, 0, false
	}
	version, err := requestedVersion(r)
	if err != nil {
		writeDomainError(w, r, err)
		return applicationticketing.Actor{}, 0, false
	}
	values := r.Header.Values(ifMatchHeader)
	if len(values) != 1 || strings.TrimSpace(values[0]) != string(ifMatch) || *version < 1 {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return applicationticketing.Actor{}, 0, false
	}
	return actor, uint64(*version), true
}

func bodyVersionMatches(bodyVersion int64, headerVersion uint64) bool {
	return bodyVersion > 0 && uint64(bodyVersion) <= 2_147_483_647 && uint64(bodyVersion) == headerVersion
}
