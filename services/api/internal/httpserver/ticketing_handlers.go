package httpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	applicationticketing "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func (h *Handler) ListTenantAlerts(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, params contract.ListTenantAlertsParams) {
	actor, ok := h.ticketingReadActor(w, r)
	if !ok {
		return
	}
	input, err := alertListInput(params)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeTicketPage(w, r, actor, uuid.UUID(tenantID), kernel.AggregateAlert, input)
}

func (h *Handler) ListTenantCases(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, params contract.ListTenantCasesParams) {
	actor, ok := h.ticketingReadActor(w, r)
	if !ok {
		return
	}
	input, err := caseListInput(params)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	h.writeTicketPage(w, r, actor, uuid.UUID(tenantID), kernel.AggregateCase, input)
}

func (h *Handler) GetTenantAlert(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, alertID contract.AlertId) {
	h.getTicket(w, r, uuid.UUID(tenantID), kernel.AggregateAlert, uuid.UUID(alertID))
}

func (h *Handler) DeleteTenantAlert(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	params contract.DeleteTenantAlertParams,
) {
	actor, expected, ok := h.ticketingMutationPrecondition(w, r, params.IfMatch)
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil || string(params.IdempotencyKey) != idempotencyKey {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	var body contract.AlertDeleteRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil ||
		!bodyVersionMatches(int64(body.ExpectedVersion), expected) {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	receipt, err := h.ticketing.DeleteAlert(
		r.Context(), actor, uuid.UUID(tenantID), uuid.UUID(alertID),
		applicationticketing.DeleteAlertInput{
			ExpectedVersion: expected,
			Reason:          string(body.Reason),
			IdempotencyKey:  idempotencyKey,
		},
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if !setVersionETag(w, int64(receipt.TombstoneVersion)) {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeSensitiveJSON(w, http.StatusOK, contract.AlertDeleteReceipt{
		TenantId:         receipt.TenantID,
		AlertId:          receipt.AlertID,
		PreviousVersion:  int64(receipt.PreviousVersion),
		TombstoneVersion: int64(receipt.TombstoneVersion),
		DeletedAt:        receipt.DeletedAt.UTC(),
		Replayed:         receipt.Replayed,
	})
}

func (h *Handler) GetTenantCase(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId) {
	h.getTicket(w, r, uuid.UUID(tenantID), kernel.AggregateCase, uuid.UUID(caseID))
}

func (h *Handler) ListTenantAlertActivities(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, alertID contract.AlertId, params contract.ListTenantAlertActivitiesParams) {
	h.listTicketActivities(w, r, uuid.UUID(tenantID), kernel.AggregateAlert, uuid.UUID(alertID), cursorPageInput(params.After, params.Limit))
}

func (h *Handler) ListTenantCaseActivities(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, params contract.ListTenantCaseActivitiesParams) {
	h.listTicketActivities(w, r, uuid.UUID(tenantID), kernel.AggregateCase, uuid.UUID(caseID), cursorPageInput(params.After, params.Limit))
}

func (h *Handler) ListTenantAlertActivityFeed(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, params contract.ListTenantAlertActivityFeedParams) {
	h.listTenantActivityFeed(w, r, uuid.UUID(tenantID), kernel.AggregateAlert, cursorPageInput(params.After, params.Limit))
}

func (h *Handler) ListTenantCaseActivityFeed(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, params contract.ListTenantCaseActivityFeedParams) {
	h.listTenantActivityFeed(w, r, uuid.UUID(tenantID), kernel.AggregateCase, cursorPageInput(params.After, params.Limit))
}

func (h *Handler) ListTenantAlertComments(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, alertID contract.AlertId, params contract.ListTenantAlertCommentsParams) {
	h.listTicketComments(w, r, uuid.UUID(tenantID), kernel.AggregateAlert, uuid.UUID(alertID), cursorPageInput(params.After, params.Limit))
}

func (h *Handler) ListTenantCaseComments(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, params contract.ListTenantCaseCommentsParams) {
	h.listTicketComments(w, r, uuid.UUID(tenantID), kernel.AggregateCase, uuid.UUID(caseID), cursorPageInput(params.After, params.Limit))
}

func (h *Handler) ListTenantAlertLinkedCases(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, alertID contract.AlertId, params contract.ListTenantAlertLinkedCasesParams) {
	h.listTicketLinks(w, r, uuid.UUID(tenantID), kernel.AggregateAlert, uuid.UUID(alertID), cursorPageInput(params.After, params.Limit))
}

func (h *Handler) ListTenantCaseLinkedAlerts(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, params contract.ListTenantCaseLinkedAlertsParams) {
	h.listTicketLinks(w, r, uuid.UUID(tenantID), kernel.AggregateCase, uuid.UUID(caseID), cursorPageInput(params.After, params.Limit))
}

func (h *Handler) CreateTenantCase(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, _ contract.CreateTenantCaseParams) {
	actor, ok := h.ticketingMutationActor(w, r)
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	var body contract.CreateTenantCaseJSONRequestBody
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil || !body.Severity.Valid() || !body.Priority.Valid() {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	input, err := createCaseInput(body, idempotencyKey)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.ticketing.CreateCase(r.Context(), actor, uuid.UUID(tenantID), input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapTicketView(result.View)
	if err != nil || !setVersionETag(w, int64(result.View.Record.Snapshot.Version())) {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	caseID := uuid.UUID(result.View.Record.Snapshot.ID().Bytes())
	w.Header().Set("Location", "/api/v1/tenants/"+uuid.UUID(tenantID).String()+"/cases/"+caseID.String())
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) CreateTenantAlertComment(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, alertID contract.AlertId, params contract.CreateTenantAlertCommentParams) {
	h.createTicketComment(w, r, uuid.UUID(tenantID), kernel.AggregateAlert, uuid.UUID(alertID), params.IdempotencyKey)
}

func (h *Handler) CreateTenantCaseComment(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, params contract.CreateTenantCaseCommentParams) {
	h.createTicketComment(w, r, uuid.UUID(tenantID), kernel.AggregateCase, uuid.UUID(caseID), params.IdempotencyKey)
}

func (h *Handler) writeTicketPage(w http.ResponseWriter, r *http.Request, actor applicationticketing.Actor, tenantID uuid.UUID, kind kernel.AggregateKind, input applicationticketing.ListInput) {
	page, err := h.ticketing.List(r.Context(), actor, tenantID, kind, input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapTicketPage(page)
	if err != nil {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) getTicket(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, kind kernel.AggregateKind, id uuid.UUID) {
	actor, ok := h.ticketingReadActor(w, r)
	if !ok {
		return
	}
	view, err := h.ticketing.Get(r.Context(), actor, tenantID, kind, id)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapTicketView(view)
	if err != nil || !setVersionETag(w, int64(view.Record.Snapshot.Version())) {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) listTicketActivities(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, kind kernel.AggregateKind, id uuid.UUID, pageInput applicationticketing.CursorPageInput) {
	actor, ok := h.ticketingReadActor(w, r)
	if !ok {
		return
	}
	page, err := h.ticketing.Activities(r.Context(), actor, tenantID, kind, id, pageInput)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapActivityPage(page))
}

func (h *Handler) listTenantActivityFeed(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, kind kernel.AggregateKind, pageInput applicationticketing.CursorPageInput) {
	actor, ok := h.ticketingReadActor(w, r)
	if !ok {
		return
	}
	page, err := h.ticketing.ActivityFeed(r.Context(), actor, tenantID, kind, pageInput)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapActivityPage(page))
}

func (h *Handler) listTicketComments(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, kind kernel.AggregateKind, id uuid.UUID, pageInput applicationticketing.CursorPageInput) {
	actor, ok := h.ticketingReadActor(w, r)
	if !ok {
		return
	}
	page, err := h.ticketing.Comments(r.Context(), actor, tenantID, kind, id, pageInput)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapOperatorCommentPage(page, tenantID, kind, id)
	if err != nil {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) listTicketLinks(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, kind kernel.AggregateKind, id uuid.UUID, pageInput applicationticketing.CursorPageInput) {
	actor, ok := h.ticketingReadActor(w, r)
	if !ok {
		return
	}
	page, err := h.ticketing.Links(r.Context(), actor, tenantID, kind, id, pageInput)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapLinkPage(page))
}

func (h *Handler) createTicketComment(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	id uuid.UUID,
	parameterKey contract.IdempotencyKey,
) {
	actor, ok := h.ticketingMutationActor(w, r)
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil || string(parameterKey) != idempotencyKey {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	var body contract.CommentCreateRequest
	if err := decodeTicketCommentBody(r, &body); err != nil || !body.Visibility.Valid() {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	visibility := kernel.CommentPublic
	if body.Visibility == contract.CommentVisibilityPrivate {
		visibility = kernel.CommentPrivate
	}
	input := applicationticketing.CommentInput{
		Visibility: visibility, BodyMarkdown: body.BodyMarkdown, IdempotencyKey: idempotencyKey,
	}
	if body.AttachmentIds != nil {
		input.AttachmentIDs = uuidSlice(*body.AttachmentIds)
	}
	if body.MentionedMembershipIds != nil {
		input.MentionedIDs = uuidSlice(*body.MentionedMembershipIds)
	}
	comment, projection, replayed, err := h.ticketing.AddComment(r.Context(), actor, tenantID, kind, id, input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if projection != applicationticketing.ProjectionOperator || comment.Revision != 1 ||
		comment.Visibility != input.Visibility || !commentProjectionMatchesInput(
		comment.BodyMarkdown, comment.Attachments, comment.Mentions,
		input.BodyMarkdown, input.AttachmentIDs, input.MentionedIDs,
	) {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	mapped, err := mapOperatorComment(comment, tenantID, kind, id)
	if err != nil || !setCommentRevisionETag(w, comment.Revision) {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	w.Header().Set("Location", r.URL.Path+"/"+comment.ID.String())
	w.Header().Set(idempotentReplayHeader, strconv.FormatBool(replayed))
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) ticketingReadActor(w http.ResponseWriter, r *http.Request) (applicationticketing.Actor, bool) {
	actor, ok := h.tenantAuthorizationActor(w, r)
	if !ok {
		return applicationticketing.Actor{}, false
	}
	if h.ticketing == nil {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return applicationticketing.Actor{}, false
	}
	return applicationticketing.Actor{
		UserID: actor.UserID, SessionID: actor.SessionID, ActiveTenantID: actor.ActiveTenantID,
		AuthenticationMethod: actor.AuthenticationMethod,
	}, true
}

func (h *Handler) ticketingMutationActor(w http.ResponseWriter, r *http.Request) (applicationticketing.Actor, bool) {
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return applicationticketing.Actor{}, false
	}
	if h.ticketing == nil {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return applicationticketing.Actor{}, false
	}
	return applicationticketing.Actor{
		UserID: actor.UserID, SessionID: actor.SessionID, ActiveTenantID: actor.ActiveTenantID,
		AuthenticationMethod: actor.AuthenticationMethod,
		Audit: applicationticketing.AuditContext{
			RequestID: audit.RequestID, CorrelationID: audit.CorrelationID,
			RemoteAddress: audit.RemoteAddress, UserAgent: audit.UserAgent,
		},
	}, true
}

func cursorPageInput(after *contract.AfterCursor, limit *contract.PageSize) applicationticketing.CursorPageInput {
	result := applicationticketing.CursorPageInput{}
	if after != nil {
		value := uuid.UUID(*after)
		result.After = &value
	}
	if limit != nil {
		result.Limit = int(*limit)
	}
	return result
}

func alertListInput(params contract.ListTenantAlertsParams) (applicationticketing.ListInput, error) {
	input := commonListInput(params.After, params.Limit, params.CustomerVisible, params.Search, params.CustomFieldKey, params.CustomFieldValue, params.AssignedTeamId, params.AssigneeUserId, params.ClaimedBy)
	if params.CustomFieldKey != nil && input.CustomFieldKey == nil {
		return applicationticketing.ListInput{}, applicationticketing.ErrInvalidInput
	}
	if params.ViewId != nil {
		value := uuid.UUID(*params.ViewId)
		input.SavedViewID = &value
	}
	if params.Status != nil {
		keys, err := httpContractKeys(stringsFromStateKeys(*params.Status))
		if err != nil {
			return applicationticketing.ListInput{}, err
		}
		input.States = keys
	}
	if params.Severity != nil {
		for _, value := range *params.Severity {
			if !value.Valid() {
				return applicationticketing.ListInput{}, applicationticketing.ErrInvalidInput
			}
			input.Severities = append(input.Severities, string(value))
		}
	}
	if params.Priority != nil {
		for _, value := range *params.Priority {
			if !value.Valid() {
				return applicationticketing.ListInput{}, applicationticketing.ErrInvalidInput
			}
			input.Priorities = append(input.Priorities, string(value))
		}
	}
	if params.Queue != nil {
		if !params.Queue.Valid() {
			return applicationticketing.ListInput{}, applicationticketing.ErrInvalidInput
		}
		input.Queue = string(*params.Queue)
	}
	if params.Sort != nil {
		if !params.Sort.Valid() {
			return applicationticketing.ListInput{}, applicationticketing.ErrInvalidInput
		}
		input.Sort = string(*params.Sort)
	}
	return input, nil
}

func caseListInput(params contract.ListTenantCasesParams) (applicationticketing.ListInput, error) {
	input := commonListInput(params.After, params.Limit, params.CustomerVisible, params.Search, params.CustomFieldKey, params.CustomFieldValue, params.AssignedTeamId, params.AssigneeUserId, params.ClaimedBy)
	if params.CustomFieldKey != nil && input.CustomFieldKey == nil {
		return applicationticketing.ListInput{}, applicationticketing.ErrInvalidInput
	}
	if params.ViewId != nil {
		value := uuid.UUID(*params.ViewId)
		input.SavedViewID = &value
	}
	if params.Status != nil {
		keys, err := httpContractKeys(stringsFromStateKeys(*params.Status))
		if err != nil {
			return applicationticketing.ListInput{}, err
		}
		input.States = keys
	}
	if params.Severity != nil {
		for _, value := range *params.Severity {
			if !value.Valid() {
				return applicationticketing.ListInput{}, applicationticketing.ErrInvalidInput
			}
			input.Severities = append(input.Severities, string(value))
		}
	}
	if params.Priority != nil {
		for _, value := range *params.Priority {
			if !value.Valid() {
				return applicationticketing.ListInput{}, applicationticketing.ErrInvalidInput
			}
			input.Priorities = append(input.Priorities, string(value))
		}
	}
	if params.Queue != nil {
		if !params.Queue.Valid() {
			return applicationticketing.ListInput{}, applicationticketing.ErrInvalidInput
		}
		input.Queue = string(*params.Queue)
	}
	if params.Sort != nil {
		if !params.Sort.Valid() {
			return applicationticketing.ListInput{}, applicationticketing.ErrInvalidInput
		}
		input.Sort = string(*params.Sort)
	}
	return input, nil
}

func commonListInput(after *contract.TicketAfterCursor, limit *contract.PageSize, customerVisible *bool, search *string, customFieldKey *contract.CustomFieldKey, customFieldValue *string, assignedTeamID, assigneeUserID, claimedBy *uuid.UUID) applicationticketing.ListInput {
	input := applicationticketing.ListInput{CustomerVisible: customerVisible}
	if after != nil {
		input.After = string(*after)
	}
	if limit != nil {
		input.Limit = int(*limit)
	}
	if search != nil {
		input.Search = *search
	}
	if customFieldValue != nil {
		value := *customFieldValue
		input.CustomFieldValue = &value
	}
	if customFieldKey != nil {
		key, err := kernel.NewKey(*customFieldKey)
		if err == nil {
			input.CustomFieldKey = &key
		}
	}
	input.AssignedTeamID = assignedTeamID
	input.AssigneeUserID = assigneeUserID
	input.ClaimedBy = claimedBy
	return input
}

func createCaseInput(body contract.CaseCreateRequest, idempotencyKey string) (applicationticketing.CreateCaseInput, error) {
	customFields, err := contractCustomFields(body.CustomFields)
	if err != nil {
		return applicationticketing.CreateCaseInput{}, err
	}
	input := applicationticketing.CreateCaseInput{
		Title: body.Title, Severity: string(body.Severity), Priority: string(body.Priority),
		CustomFields: customFields, IdempotencyKey: idempotencyKey,
		AssignedTeamID: body.AssignedTeamId, AssigneeUserID: body.AssigneeUserId,
	}
	if body.WorkflowId != nil {
		value := uuid.UUID(*body.WorkflowId)
		input.WorkflowID = &value
	}
	if body.Description != nil {
		input.Description = *body.Description
	}
	if body.Summary != nil {
		input.Summary = *body.Summary
	}
	if body.Category != nil {
		input.Category = *body.Category
	}
	input.Classification = body.Classification
	if body.Tags != nil {
		input.Tags, err = canonicalStrings(*body.Tags)
		if err != nil {
			return applicationticketing.CreateCaseInput{}, err
		}
	}
	if body.CustomerVisible != nil {
		input.CustomerVisible = *body.CustomerVisible
	}
	if body.DetectionTime != nil {
		input.DetectionTime = body.DetectionTime.UTC()
	}
	if err := applicationticketing.ValidateCreateCaseInput(input); err != nil {
		return applicationticketing.CreateCaseInput{}, err
	}
	return input, nil
}

func contractCustomFields(values *contract.CustomFieldValues) (map[string]any, error) {
	if values == nil {
		return map[string]any{}, nil
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return nil, applicationticketing.ErrInvalidInput
	}
	var result map[string]any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil || len(result) > 100 {
		return nil, applicationticketing.ErrInvalidInput
	}
	if err := applicationticketing.ValidateCustomFields(result); err != nil {
		return nil, err
	}
	return result, nil
}

func canonicalStrings(values []string) ([]string, error) {
	result := slices.Clone(values)
	slices.Sort(result)
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, applicationticketing.ErrInvalidInput
		}
	}
	return result, nil
}

func uuidSlice(values []uuid.UUID) []uuid.UUID { return slices.Clone(values) }

func stringsFromStateKeys(values []contract.WorkflowStateKey) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func httpContractKeys(values []string) ([]kernel.Key, error) {
	result := make([]kernel.Key, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
			return nil, applicationticketing.ErrInvalidInput
		}
		for _, character := range value[1:] {
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' || character == '-' {
				continue
			}
			return nil, applicationticketing.ErrInvalidInput
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, applicationticketing.ErrInvalidInput
		}
		seen[value] = struct{}{}
		key, err := kernel.NewKey(value)
		if err != nil {
			return nil, applicationticketing.ErrInvalidInput
		}
		result = append(result, key)
	}
	return result, nil
}

func decodeStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}
