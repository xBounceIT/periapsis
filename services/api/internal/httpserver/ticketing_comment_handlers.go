package httpserver

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

const maximumCommentRevision = 2_147_483_647

func (h *Handler) PreviewTenantAlertComment(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, alertID contract.AlertId) {
	h.previewTicketComment(w, r, uuid.UUID(tenantID), kernel.AggregateAlert, uuid.UUID(alertID), false)
}

func (h *Handler) PreviewTenantCaseComment(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId) {
	h.previewTicketComment(w, r, uuid.UUID(tenantID), kernel.AggregateCase, uuid.UUID(caseID), false)
}

func (h *Handler) PreviewCustomerPortalAlertComment(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, alertID contract.AlertId) {
	h.previewTicketComment(w, r, uuid.UUID(tenantID), kernel.AggregateAlert, uuid.UUID(alertID), true)
}

func (h *Handler) PreviewCustomerPortalCaseComment(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId) {
	h.previewTicketComment(w, r, uuid.UUID(tenantID), kernel.AggregateCase, uuid.UUID(caseID), true)
}

func (h *Handler) previewTicketComment(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID uuid.UUID,
	portal bool,
) {
	actor, ok := h.ticketingReadActor(w, r)
	if !ok {
		return
	}
	if portal {
		var body contract.CustomerPortalCommentPreviewRequest
		if decodeTicketCommentBody(r, &body) != nil {
			writeDomainError(w, r, application.ErrInvalidInput)
			return
		}
		input := application.CommentPreviewInput{
			Visibility: kernel.CommentPublic, BodyMarkdown: body.BodyMarkdown,
			AttachmentIDs: optionalCommentRelatedIDs(body.AttachmentIds),
		}
		preview, err := h.ticketing.PreviewPortalComment(r.Context(), actor, tenantID, kind, ticketID, input)
		if err != nil {
			writeDomainError(w, r, err)
			return
		}
		mapped, err := mapCustomerCommentPreview(preview)
		if err != nil || preview.Projection != application.ProjectionCustomer ||
			preview.Visibility != input.Visibility || !commentProjectionMatchesInput(
			preview.BodyMarkdown, preview.Attachments, preview.Mentions,
			input.BodyMarkdown, input.AttachmentIDs, input.MentionedIDs,
		) {
			writeDomainError(w, r, application.ErrUnavailable)
			return
		}
		writeSensitiveJSON(w, http.StatusOK, mapped)
		return
	}

	var body contract.CommentCreateRequest
	if decodeTicketCommentBody(r, &body) != nil || !body.Visibility.Valid() {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	input := application.CommentPreviewInput{
		Visibility: commentVisibility(body.Visibility), BodyMarkdown: body.BodyMarkdown,
		AttachmentIDs: optionalCommentRelatedIDs(body.AttachmentIds),
		MentionedIDs:  optionalCommentRelatedIDs(body.MentionedMembershipIds),
	}
	preview, err := h.ticketing.PreviewComment(r.Context(), actor, tenantID, kind, ticketID, input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapOperatorCommentPreview(preview)
	if err != nil || preview.Projection != application.ProjectionOperator ||
		preview.Visibility != input.Visibility || !commentProjectionMatchesInput(
		preview.BodyMarkdown, preview.Attachments, preview.Mentions,
		input.BodyMarkdown, input.AttachmentIDs, input.MentionedIDs,
	) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ListTenantAlertCommentMentionCandidates(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	params contract.ListTenantAlertCommentMentionCandidatesParams,
) {
	h.listTicketCommentMentionCandidates(
		w, r, uuid.UUID(tenantID), kernel.AggregateAlert, uuid.UUID(alertID),
		commentMentionSearch(params.Search), commentPageLimit(params.Limit),
	)
}

func (h *Handler) ListTenantCaseCommentMentionCandidates(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	caseID contract.CaseId,
	params contract.ListTenantCaseCommentMentionCandidatesParams,
) {
	h.listTicketCommentMentionCandidates(
		w, r, uuid.UUID(tenantID), kernel.AggregateCase, uuid.UUID(caseID),
		commentMentionSearch(params.Search), commentPageLimit(params.Limit),
	)
}

func (h *Handler) listTicketCommentMentionCandidates(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID uuid.UUID,
	search string,
	limit int,
) {
	actor, ok := h.ticketingReadActor(w, r)
	if !ok {
		return
	}
	result, err := h.ticketing.CommentMentionCandidates(r.Context(), actor, tenantID, kind, ticketID,
		application.CommentMentionCandidateInput{Search: search, Limit: limit})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapCommentMentionCandidates(result)
	if err != nil {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) EditTenantAlertComment(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	commentID contract.CommentId,
	params contract.EditTenantAlertCommentParams,
) {
	h.editTicketComment(w, r, uuid.UUID(tenantID), kernel.AggregateAlert, uuid.UUID(alertID), uuid.UUID(commentID),
		string(params.IfMatch), params.IdempotencyKey, false)
}

func (h *Handler) EditTenantCaseComment(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	caseID contract.CaseId,
	commentID contract.CommentId,
	params contract.EditTenantCaseCommentParams,
) {
	h.editTicketComment(w, r, uuid.UUID(tenantID), kernel.AggregateCase, uuid.UUID(caseID), uuid.UUID(commentID),
		string(params.IfMatch), params.IdempotencyKey, false)
}

func (h *Handler) EditCustomerPortalAlertComment(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	commentID contract.CommentId,
	params contract.EditCustomerPortalAlertCommentParams,
) {
	h.editTicketComment(w, r, uuid.UUID(tenantID), kernel.AggregateAlert, uuid.UUID(alertID), uuid.UUID(commentID),
		string(params.IfMatch), params.IdempotencyKey, true)
}

func (h *Handler) EditCustomerPortalCaseComment(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	caseID contract.CaseId,
	commentID contract.CommentId,
	params contract.EditCustomerPortalCaseCommentParams,
) {
	h.editTicketComment(w, r, uuid.UUID(tenantID), kernel.AggregateCase, uuid.UUID(caseID), uuid.UUID(commentID),
		string(params.IfMatch), params.IdempotencyKey, true)
}

func (h *Handler) editTicketComment(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID, commentID uuid.UUID,
	parameterIfMatch string,
	parameterKey contract.IdempotencyKey,
	portal bool,
) {
	actor, ok := h.ticketingMutationActor(w, r)
	if !ok {
		return
	}
	expectedRevision, ok := commentRevisionPrecondition(w, r, parameterIfMatch)
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil || string(parameterKey) != idempotencyKey {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	input := application.CommentEditInput{ExpectedRevision: expectedRevision, IdempotencyKey: idempotencyKey}
	if portal {
		var body contract.CustomerPortalCommentEditRequest
		if decodeTicketCommentBody(r, &body) != nil {
			writeDomainError(w, r, application.ErrInvalidInput)
			return
		}
		input.BodyMarkdown = body.BodyMarkdown
		input.AttachmentIDs = optionalCommentRelatedIDs(body.AttachmentIds)
		input.Reason = "author_correction"
	} else {
		var body contract.CommentEditRequest
		if decodeTicketCommentBody(r, &body) != nil {
			writeDomainError(w, r, application.ErrInvalidInput)
			return
		}
		input.BodyMarkdown = body.BodyMarkdown
		input.AttachmentIDs = optionalCommentRelatedIDs(body.AttachmentIds)
		input.MentionedIDs = optionalCommentRelatedIDs(body.MentionedMembershipIds)
		input.Reason = body.Reason
	}

	var comment application.Comment
	var projection application.Projection
	var replayed bool
	if portal {
		comment, projection, replayed, err = h.ticketing.EditPortalComment(
			r.Context(), actor, tenantID, kind, ticketID, commentID, input,
		)
	} else {
		comment, projection, replayed, err = h.ticketing.EditComment(
			r.Context(), actor, tenantID, kind, ticketID, commentID, input,
		)
	}
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if comment.ID != commentID || comment.Revision != input.ExpectedRevision+1 ||
		!commentProjectionMatchesInput(
			comment.BodyMarkdown, comment.Attachments, comment.Mentions,
			input.BodyMarkdown, input.AttachmentIDs, input.MentionedIDs,
		) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	if portal {
		if projection != application.ProjectionCustomer {
			writeDomainError(w, r, application.ErrUnavailable)
			return
		}
		mapped, mapErr := mapCustomerComment(comment, tenantID, kind, ticketID)
		if mapErr != nil {
			writeDomainError(w, r, application.ErrUnavailable)
			return
		}
		if !setCommentRevisionETag(w, comment.Revision) {
			writeDomainError(w, r, application.ErrUnavailable)
			return
		}
		w.Header().Set(idempotentReplayHeader, strconv.FormatBool(replayed))
		writeSensitiveJSON(w, http.StatusOK, mapped)
		return
	}
	if projection != application.ProjectionOperator {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	mapped, mapErr := mapOperatorComment(comment, tenantID, kind, ticketID)
	if mapErr != nil {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	if !setCommentRevisionETag(w, comment.Revision) {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set(idempotentReplayHeader, strconv.FormatBool(replayed))
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ListTenantAlertCommentRevisions(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	commentID contract.CommentId,
	params contract.ListTenantAlertCommentRevisionsParams,
) {
	h.listTicketCommentRevisions(w, r, uuid.UUID(tenantID), kernel.AggregateAlert, uuid.UUID(alertID),
		uuid.UUID(commentID), commentRevisionPageInput(params.AfterRevision, params.Limit), false)
}

func (h *Handler) ListTenantCaseCommentRevisions(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	caseID contract.CaseId,
	commentID contract.CommentId,
	params contract.ListTenantCaseCommentRevisionsParams,
) {
	h.listTicketCommentRevisions(w, r, uuid.UUID(tenantID), kernel.AggregateCase, uuid.UUID(caseID),
		uuid.UUID(commentID), commentRevisionPageInput(params.AfterRevision, params.Limit), false)
}

func (h *Handler) ListCustomerPortalAlertCommentRevisions(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	commentID contract.CommentId,
	params contract.ListCustomerPortalAlertCommentRevisionsParams,
) {
	h.listTicketCommentRevisions(w, r, uuid.UUID(tenantID), kernel.AggregateAlert, uuid.UUID(alertID),
		uuid.UUID(commentID), commentRevisionPageInput(params.AfterRevision, params.Limit), true)
}

func (h *Handler) ListCustomerPortalCaseCommentRevisions(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	caseID contract.CaseId,
	commentID contract.CommentId,
	params contract.ListCustomerPortalCaseCommentRevisionsParams,
) {
	h.listTicketCommentRevisions(w, r, uuid.UUID(tenantID), kernel.AggregateCase, uuid.UUID(caseID),
		uuid.UUID(commentID), commentRevisionPageInput(params.AfterRevision, params.Limit), true)
}

func (h *Handler) listTicketCommentRevisions(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	ticketID, commentID uuid.UUID,
	pageInput application.CommentRevisionPageInput,
	portal bool,
) {
	actor, ok := h.ticketingReadActor(w, r)
	if !ok {
		return
	}
	var page application.CommentRevisionPage
	var err error
	if portal {
		page, err = h.ticketing.CommentRevisionsPortal(r.Context(), actor, tenantID, kind, ticketID, commentID, pageInput)
	} else {
		page, err = h.ticketing.CommentRevisions(r.Context(), actor, tenantID, kind, ticketID, commentID, pageInput)
	}
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if portal {
		mapped, mapErr := mapCustomerCommentRevisionPage(page)
		if mapErr != nil {
			writeDomainError(w, r, application.ErrUnavailable)
			return
		}
		writeSensitiveJSON(w, http.StatusOK, mapped)
		return
	}
	mapped, mapErr := mapOperatorCommentRevisionPage(page)
	if mapErr != nil {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func commentProjectionMatchesInput(
	bodyMarkdown string,
	attachments []application.CommentAttachment,
	mentions []application.CommentMention,
	expectedBody string,
	attachmentIDs, mentionedIDs []uuid.UUID,
) bool {
	if bodyMarkdown != expectedBody || len(attachments) != len(attachmentIDs) ||
		len(mentions) != len(mentionedIDs) {
		return false
	}
	for index, attachment := range attachments {
		if attachment.ID != attachmentIDs[index] {
			return false
		}
	}
	for index, mention := range mentions {
		if mention.MembershipID != mentionedIDs[index] {
			return false
		}
	}
	return true
}

func commentRevisionPrecondition(w http.ResponseWriter, r *http.Request, parameterValue string) (int, bool) {
	if len(r.Header.Values(ifMatchHeader)) == 0 {
		writeProblem(w, r, http.StatusPreconditionRequired, "precondition_required", "Precondition required", "A current strong comment If-Match entity tag is required.")
		return 0, false
	}
	value, err := singleHeader(r, ifMatchHeader, 32)
	if err != nil || value != parameterValue || !strings.HasPrefix(value, `"comment-r`) || !strings.HasSuffix(value, `"`) {
		writeDomainError(w, r, application.ErrInvalidInput)
		return 0, false
	}
	digits := value[len(`"comment-r`) : len(value)-1]
	if digits == "" || digits[0] == '0' {
		writeDomainError(w, r, application.ErrInvalidInput)
		return 0, false
	}
	for _, digit := range digits {
		if digit < '0' || digit > '9' {
			writeDomainError(w, r, application.ErrInvalidInput)
			return 0, false
		}
	}
	revision, err := strconv.ParseInt(digits, 10, 32)
	if err != nil || revision < 1 || revision >= maximumCommentRevision {
		writeDomainError(w, r, application.ErrInvalidInput)
		return 0, false
	}
	return int(revision), true
}

func setCommentRevisionETag(w http.ResponseWriter, revision int) bool {
	if revision < 1 || revision > maximumCommentRevision {
		return false
	}
	w.Header().Set("ETag", `"comment-r`+strconv.Itoa(revision)+`"`)
	return true
}

func commentVisibility(value contract.CommentVisibility) kernel.CommentVisibility {
	if value == contract.CommentVisibilityPrivate {
		return kernel.CommentPrivate
	}
	return kernel.CommentPublic
}

func optionalCommentRelatedIDs(values *[]contract.CommentRelatedId) []uuid.UUID {
	if values == nil {
		return nil
	}
	return uuidSlice(*values)
}

func commentMentionSearch(value *contract.CommentMentionSearch) string {
	if value == nil {
		return ""
	}
	return string(*value)
}

func commentPageLimit(value *contract.PageSize) int {
	if value == nil {
		return 0
	}
	return int(*value)
}

func commentRevisionPageInput(
	after *contract.CommentRevisionAfter,
	limit *contract.PageSize,
) application.CommentRevisionPageInput {
	result := application.CommentRevisionPageInput{Limit: commentPageLimit(limit)}
	if after != nil {
		value := int(*after)
		result.AfterRevision = &value
	}
	return result
}
