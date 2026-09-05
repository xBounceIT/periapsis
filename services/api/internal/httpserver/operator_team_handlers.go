package httpserver

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/operatorteam"
)

func (h *Handler) ListPlatformOperatorTeams(
	w http.ResponseWriter,
	r *http.Request,
	params contract.ListPlatformOperatorTeamsParams,
) {
	session, ok := h.platformOperatorTeamSession(w, r)
	if !ok {
		return
	}
	pageInput, err := operatorTeamPageInput(params.After, params.Limit)
	if err != nil {
		h.writeOperatorTeamError(w, r, operatorteam.ErrInvalidInput)
		return
	}
	page, err := h.operatorTeams.ListOperatorTeams(r.Context(), session, operatorteam.ListOperatorTeamsInput{
		PageInput:       pageInput,
		IncludeArchived: params.IncludeArchived != nil && *params.IncludeArchived,
	})
	if err != nil {
		h.writeOperatorTeamError(w, r, err)
		return
	}
	items := make([]contract.OperatorTeam, 0, len(page.Items))
	for _, item := range page.Items {
		mapped, mapErr := mapOperatorTeam(item)
		if mapErr != nil {
			h.writeOperatorTeamError(w, r, operatorteam.ErrUnavailable)
			return
		}
		items = append(items, mapped)
	}
	if !validOperatorTeamPageCursor(page.NextCursor, len(page.Items), func() uuid.UUID {
		return page.Items[len(page.Items)-1].ID
	}) {
		h.writeOperatorTeamError(w, r, operatorteam.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, contract.OperatorTeamList{Items: items, NextCursor: page.NextCursor})
}

func (h *Handler) CreatePlatformOperatorTeam(
	w http.ResponseWriter,
	r *http.Request,
	_ contract.CreatePlatformOperatorTeamParams,
) {
	session, audit, ok := h.preparePlatformOperatorTeamMutation(w, r)
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil {
		h.writeOperatorTeamError(w, r, operatorteam.ErrInvalidInput)
		return
	}
	var body contract.OperatorTeamCreateRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		h.writeOperatorTeamError(w, r, operatorteam.ErrInvalidInput)
		return
	}
	description := ""
	if body.Description != nil {
		description = *body.Description
	}
	team, err := h.operatorTeams.CreateOperatorTeam(r.Context(), session, operatorteam.CreateOperatorTeamInput{
		Key: body.Key, Name: body.Name, Description: description,
		IdempotencyKey: idempotencyKey, Audit: audit,
	})
	if err != nil {
		h.writeOperatorTeamError(w, r, err)
		return
	}
	h.writeOperatorTeam(w, r, http.StatusCreated, team)
}

func (h *Handler) GetPlatformOperatorTeam(
	w http.ResponseWriter,
	r *http.Request,
	operatorTeamID contract.OperatorTeamId,
) {
	session, ok := h.platformOperatorTeamSession(w, r)
	if !ok {
		return
	}
	team, err := h.operatorTeams.GetOperatorTeam(r.Context(), session, uuid.UUID(operatorTeamID))
	if err != nil {
		h.writeOperatorTeamError(w, r, err)
		return
	}
	h.writeOperatorTeam(w, r, http.StatusOK, team)
}

func (h *Handler) UpdatePlatformOperatorTeam(
	w http.ResponseWriter,
	r *http.Request,
	operatorTeamID contract.OperatorTeamId,
	_ contract.UpdatePlatformOperatorTeamParams,
) {
	session, audit, ok := h.preparePlatformOperatorTeamMutation(w, r)
	if !ok {
		return
	}
	version, err := requestedVersion(r)
	if err != nil {
		h.writeOperatorTeamError(w, r, err)
		return
	}
	var body contract.OperatorTeamPatchRequest
	if err := decodeAuthorizationBody(r, &body, "application/merge-patch+json"); err != nil {
		h.writeOperatorTeamError(w, r, operatorteam.ErrInvalidInput)
		return
	}
	team, err := h.operatorTeams.PatchOperatorTeam(
		r.Context(), session, uuid.UUID(operatorTeamID),
		operatorteam.PatchOperatorTeamInput{
			Name: body.Name, Description: body.Description, ExpectedVersion: version, Audit: audit,
		},
	)
	if err != nil {
		h.writeOperatorTeamError(w, r, err)
		return
	}
	h.writeOperatorTeam(w, r, http.StatusOK, team)
}

func (h *Handler) ArchivePlatformOperatorTeam(
	w http.ResponseWriter,
	r *http.Request,
	operatorTeamID contract.OperatorTeamId,
	_ contract.ArchivePlatformOperatorTeamParams,
) {
	session, audit, ok := h.preparePlatformOperatorTeamMutation(w, r)
	if !ok {
		return
	}
	version, err := requestedVersion(r)
	if err != nil {
		h.writeOperatorTeamError(w, r, err)
		return
	}
	var body contract.OperatorTeamArchiveRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		h.writeOperatorTeamError(w, r, operatorteam.ErrInvalidInput)
		return
	}
	err = h.operatorTeams.ArchiveOperatorTeam(
		r.Context(), session, uuid.UUID(operatorTeamID),
		operatorteam.ArchiveOperatorTeamInput{
			Reason: body.Reason, ExpectedVersion: version, Audit: audit,
		},
	)
	if err != nil {
		h.writeOperatorTeamError(w, r, err)
		return
	}
	writeOperatorTeamNoContent(w)
}

func (h *Handler) ListTenantOperatorTeamAssignmentEpochs(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.ListTenantOperatorTeamAssignmentEpochsParams,
) {
	actor, ok := h.operatorTeamTenantActor(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	pageInput, err := operatorTeamPageInput(params.After, params.Limit)
	if err != nil {
		h.writeOperatorTeamError(w, r, operatorteam.ErrInvalidInput)
		return
	}
	page, err := h.operatorTeams.ListTenantAssignments(
		r.Context(), actor, uuid.UUID(tenantID), operatorteam.ListTenantAssignmentsInput{
			PageInput: pageInput, IncludeEnded: params.IncludeEnded != nil && *params.IncludeEnded,
		},
	)
	if err != nil {
		h.writeOperatorTeamError(w, r, err)
		return
	}
	items := make([]contract.OperatorTeamAssignmentEpoch, 0, len(page.Items))
	for _, item := range page.Items {
		mapped, mapErr := mapOperatorTeamAssignment(item, uuid.UUID(tenantID), item.OperatorTeam.ID, item.EpochID)
		if mapErr != nil {
			h.writeOperatorTeamError(w, r, operatorteam.ErrUnavailable)
			return
		}
		items = append(items, mapped)
	}
	if !validOperatorTeamPageCursor(page.NextCursor, len(page.Items), func() uuid.UUID {
		return page.Items[len(page.Items)-1].EpochID
	}) {
		h.writeOperatorTeamError(w, r, operatorteam.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, contract.OperatorTeamAssignmentEpochList{
		Items: items, NextCursor: page.NextCursor,
	})
}

func (h *Handler) StartOperatorTeamAssignmentEpoch(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	operatorTeamID contract.OperatorTeamId,
	_ contract.StartOperatorTeamAssignmentEpochParams,
) {
	actor, audit, ok := h.prepareOperatorTeamTenantMutation(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil {
		h.writeOperatorTeamError(w, r, operatorteam.ErrInvalidInput)
		return
	}
	var body contract.OperatorTeamAssignmentEpochStartRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		h.writeOperatorTeamError(w, r, operatorteam.ErrInvalidInput)
		return
	}
	assignment, err := h.operatorTeams.StartTenantAssignment(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(operatorTeamID),
		operatorteam.StartTenantAssignmentInput{
			Reason: body.Reason, IdempotencyKey: idempotencyKey, Audit: audit,
		},
	)
	if err != nil {
		h.writeOperatorTeamError(w, r, err)
		return
	}
	h.writeOperatorTeamAssignment(
		w, r, http.StatusCreated, assignment,
		uuid.UUID(tenantID), uuid.UUID(operatorTeamID), assignment.EpochID,
	)
}

func (h *Handler) GetOperatorTeamAssignmentEpoch(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	operatorTeamID contract.OperatorTeamId,
	assignmentEpochID contract.AssignmentEpochId,
) {
	actor, ok := h.operatorTeamTenantActor(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	assignment, err := h.operatorTeams.GetTenantAssignment(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(operatorTeamID), uuid.UUID(assignmentEpochID),
	)
	if err != nil {
		h.writeOperatorTeamError(w, r, err)
		return
	}
	h.writeOperatorTeamAssignment(
		w, r, http.StatusOK, assignment,
		uuid.UUID(tenantID), uuid.UUID(operatorTeamID), uuid.UUID(assignmentEpochID),
	)
}

func (h *Handler) EndOperatorTeamAssignmentEpoch(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	operatorTeamID contract.OperatorTeamId,
	assignmentEpochID contract.AssignmentEpochId,
	_ contract.EndOperatorTeamAssignmentEpochParams,
) {
	actor, audit, ok := h.prepareOperatorTeamTenantMutation(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	version, err := requestedVersion(r)
	if err != nil {
		h.writeOperatorTeamError(w, r, err)
		return
	}
	var body contract.OperatorTeamAssignmentEpochEndRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		h.writeOperatorTeamError(w, r, operatorteam.ErrInvalidInput)
		return
	}
	err = h.operatorTeams.EndTenantAssignment(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(operatorTeamID), uuid.UUID(assignmentEpochID),
		operatorteam.EndTenantAssignmentInput{
			Reason: body.Reason, ExpectedVersion: version, Audit: audit,
		},
	)
	if err != nil {
		h.writeOperatorTeamError(w, r, err)
		return
	}
	writeOperatorTeamNoContent(w)
}

func (h *Handler) ListOperatorTeamRosterEntries(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	operatorTeamID contract.OperatorTeamId,
	assignmentEpochID contract.AssignmentEpochId,
	params contract.ListOperatorTeamRosterEntriesParams,
) {
	actor, ok := h.operatorTeamTenantActor(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	pageInput, err := operatorTeamPageInput(params.After, params.Limit)
	if err != nil {
		h.writeOperatorTeamError(w, r, operatorteam.ErrInvalidInput)
		return
	}
	page, err := h.operatorTeams.ListRosterEntries(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(operatorTeamID), uuid.UUID(assignmentEpochID),
		operatorteam.ListRosterEntriesInput{
			PageInput: pageInput, IncludeRevoked: params.IncludeRevoked != nil && *params.IncludeRevoked,
		},
	)
	if err != nil {
		h.writeOperatorTeamError(w, r, err)
		return
	}
	items := make([]contract.OperatorTeamRosterEntry, 0, len(page.Items))
	for _, item := range page.Items {
		mapped, mapErr := mapOperatorTeamRosterEntry(
			item, uuid.UUID(tenantID), uuid.UUID(operatorTeamID), uuid.UUID(assignmentEpochID),
		)
		if mapErr != nil {
			h.writeOperatorTeamError(w, r, operatorteam.ErrUnavailable)
			return
		}
		items = append(items, mapped)
	}
	if !validOperatorTeamPageCursor(page.NextCursor, len(page.Items), func() uuid.UUID {
		return page.Items[len(page.Items)-1].ID
	}) {
		h.writeOperatorTeamError(w, r, operatorteam.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, contract.OperatorTeamRosterEntryList{
		Items: items, NextCursor: page.NextCursor,
	})
}

func (h *Handler) AddOperatorTeamRosterEntry(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	operatorTeamID contract.OperatorTeamId,
	assignmentEpochID contract.AssignmentEpochId,
	_ contract.AddOperatorTeamRosterEntryParams,
) {
	actor, audit, ok := h.prepareOperatorTeamTenantMutation(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil {
		h.writeOperatorTeamError(w, r, operatorteam.ErrInvalidInput)
		return
	}
	var body contract.OperatorTeamRosterEntryCreateRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		h.writeOperatorTeamError(w, r, operatorteam.ErrInvalidInput)
		return
	}
	entry, err := h.operatorTeams.AddRosterEntry(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(operatorTeamID), uuid.UUID(assignmentEpochID),
		operatorteam.AddRosterEntryInput{
			MembershipID: uuid.UUID(body.MembershipId), Reason: body.Reason, ExpiresAt: body.ExpiresAt,
			IdempotencyKey: idempotencyKey, Audit: audit,
		},
	)
	if err != nil {
		h.writeOperatorTeamError(w, r, err)
		return
	}
	h.writeOperatorTeamRosterEntry(
		w, r, http.StatusCreated, entry,
		uuid.UUID(tenantID), uuid.UUID(operatorTeamID), uuid.UUID(assignmentEpochID),
	)
}

func (h *Handler) RevokeOperatorTeamRosterEntry(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	operatorTeamID contract.OperatorTeamId,
	assignmentEpochID contract.AssignmentEpochId,
	rosterEntryID contract.RosterEntryId,
	_ contract.RevokeOperatorTeamRosterEntryParams,
) {
	actor, audit, ok := h.prepareOperatorTeamTenantMutation(w, r, uuid.UUID(tenantID))
	if !ok {
		return
	}
	entityTag, err := requestedEdgeEntityTag(r)
	if err != nil {
		h.writeOperatorTeamError(w, r, err)
		return
	}
	var body contract.AuthorizationEdgeRevokeRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		h.writeOperatorTeamError(w, r, operatorteam.ErrInvalidInput)
		return
	}
	err = h.operatorTeams.RevokeRosterEntry(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(operatorTeamID), uuid.UUID(assignmentEpochID),
		uuid.UUID(rosterEntryID), operatorteam.RevokeRosterEntryInput{
			Reason: body.Reason, ExpectedEntityTag: entityTag, Audit: audit,
		},
	)
	if err != nil {
		h.writeOperatorTeamError(w, r, err)
		return
	}
	writeOperatorTeamNoContent(w)
}

func (h *Handler) platformOperatorTeamSession(
	w http.ResponseWriter,
	r *http.Request,
) (authentication.Session, bool) {
	if !h.requireApplication(w, r) {
		return authentication.Session{}, false
	}
	token, err := h.sessionToken(r)
	if err != nil {
		writeDomainError(w, r, err)
		return authentication.Session{}, false
	}
	session, err := h.authenticateRequest(r, token)
	if err != nil {
		writeDomainError(w, r, err)
		return authentication.Session{}, false
	}
	return session, true
}

func (h *Handler) preparePlatformOperatorTeamMutation(
	w http.ResponseWriter,
	r *http.Request,
) (authentication.Session, authorization.AuditContext, bool) {
	if !h.prepareCookieMutation(w, r) {
		return authentication.Session{}, authorization.AuditContext{}, false
	}
	session, ok := h.platformOperatorTeamSession(w, r)
	if !ok {
		return authentication.Session{}, authorization.AuditContext{}, false
	}
	csrf, err := singleHeader(r, csrfTokenHeader, 128)
	if err != nil {
		writeDomainError(w, r, authentication.ErrForbidden)
		return authentication.Session{}, authorization.AuditContext{}, false
	}
	if err := h.authentication.ValidateCSRF(session, csrf); err != nil {
		writeDomainError(w, r, err)
		return authentication.Session{}, authorization.AuditContext{}, false
	}
	event, err := h.eventContext(r)
	if err != nil {
		h.writeOperatorTeamError(w, r, operatorteam.ErrInvalidInput)
		return authentication.Session{}, authorization.AuditContext{}, false
	}
	return session, authorization.AuditContext{
		RequestID: event.RequestID, CorrelationID: event.CorrelationID,
		RemoteAddress: event.RemoteAddress, UserAgent: event.UserAgent,
	}, true
}

func (h *Handler) operatorTeamTenantActor(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
) (authorization.Actor, bool) {
	actor, ok := h.tenantAuthorizationActor(w, r)
	if !ok {
		return authorization.Actor{}, false
	}
	if !validOperatorTeamTransportUUID(tenantID) {
		h.writeOperatorTeamError(w, r, operatorteam.ErrInvalidInput)
		return authorization.Actor{}, false
	}
	if actor.ActiveTenantID != tenantID {
		h.writeOperatorTeamError(w, r, operatorteam.ErrForbidden)
		return authorization.Actor{}, false
	}
	return actor, true
}

func (h *Handler) prepareOperatorTeamTenantMutation(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
) (authorization.Actor, authorization.AuditContext, bool) {
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return authorization.Actor{}, authorization.AuditContext{}, false
	}
	if !validOperatorTeamTransportUUID(tenantID) {
		h.writeOperatorTeamError(w, r, operatorteam.ErrInvalidInput)
		return authorization.Actor{}, authorization.AuditContext{}, false
	}
	if actor.ActiveTenantID != tenantID {
		h.writeOperatorTeamError(w, r, operatorteam.ErrForbidden)
		return authorization.Actor{}, authorization.AuditContext{}, false
	}
	return actor, audit, true
}

func operatorTeamPageInput(after *contract.AfterCursor, limit *contract.PageSize) (operatorteam.PageInput, error) {
	input, err := pageInput(after, limit)
	if err != nil {
		return operatorteam.PageInput{}, err
	}
	return operatorteam.PageInput{After: input.After, Limit: input.Limit}, nil
}

func validOperatorTeamPageCursor(cursor *uuid.UUID, itemCount int, lastItemID func() uuid.UUID) bool {
	if cursor == nil {
		return true
	}
	return itemCount > 0 && validOperatorTeamTransportUUID(*cursor) && *cursor == lastItemID()
}

func (h *Handler) writeOperatorTeam(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	team operatorteam.OperatorTeam,
) {
	mapped, err := mapOperatorTeam(team)
	if err != nil || !setVersionETag(w, team.Version) {
		h.writeOperatorTeamError(w, r, operatorteam.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, status, mapped)
}

func (h *Handler) writeOperatorTeamAssignment(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	assignment operatorteam.TenantAssignment,
	tenantID, operatorTeamID, epochID uuid.UUID,
) {
	mapped, err := mapOperatorTeamAssignment(assignment, tenantID, operatorTeamID, epochID)
	if err != nil || !setVersionETag(w, assignment.Version) {
		h.writeOperatorTeamError(w, r, operatorteam.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, status, mapped)
}

func (h *Handler) writeOperatorTeamRosterEntry(
	w http.ResponseWriter,
	r *http.Request,
	status int,
	entry operatorteam.RosterEntry,
	tenantID, operatorTeamID, epochID uuid.UUID,
) {
	mapped, err := mapOperatorTeamRosterEntry(entry, tenantID, operatorTeamID, epochID)
	if err != nil || !setEdgeEntityTag(w, string(mapped.Etag)) {
		h.writeOperatorTeamError(w, r, operatorteam.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, status, mapped)
}

func (h *Handler) writeOperatorTeamError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, operatorteam.ErrInvalidInput):
		writeDomainError(w, r, authorization.ErrInvalidInput)
	case errors.Is(err, operatorteam.ErrForbidden):
		writeDomainError(w, r, authorization.ErrForbidden)
	case errors.Is(err, operatorteam.ErrNotFound):
		writeDomainError(w, r, authorization.ErrNotFound)
	case errors.Is(err, operatorteam.ErrConflict):
		writeDomainError(w, r, authorization.ErrConflict)
	case errors.Is(err, operatorteam.ErrPreconditionRequired):
		writeDomainError(w, r, authorization.ErrPreconditionRequired)
	case errors.Is(err, operatorteam.ErrPreconditionFailed):
		writeDomainError(w, r, authorization.ErrPreconditionFailed)
	case errors.Is(err, operatorteam.ErrUnavailable),
		errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeDomainError(w, r, authorization.ErrUnavailable)
	default:
		writeDomainError(w, r, err)
	}
}

func writeOperatorTeamNoContent(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
