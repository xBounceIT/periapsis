package httpserver

import (
	"errors"
	"math"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	contactkernel "github.com/periapsis-im/periapsis/modules/contacts"
	ticketkernel "github.com/periapsis-im/periapsis/modules/ticketing"
	applicationcontacts "github.com/periapsis-im/periapsis/services/api/internal/contacts"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	applicationticketing "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func (h *Handler) ListTenantAlertCustomerContacts(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, alertID contract.AlertId, params contract.ListTenantAlertCustomerContactsParams) {
	h.listTicketCustomerContacts(w, r, uuid.UUID(tenantID), contactkernel.TicketAlert, uuid.UUID(alertID), contactLinkListInput(params.After, params.Limit))
}

func (h *Handler) ListTenantCaseCustomerContacts(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, params contract.ListTenantCaseCustomerContactsParams) {
	h.listTicketCustomerContacts(w, r, uuid.UUID(tenantID), contactkernel.TicketCase, uuid.UUID(caseID), contactLinkListInput(params.After, params.Limit))
}

func (h *Handler) listTicketCustomerContacts(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, kind contactkernel.TicketKind, ticketID uuid.UUID, pageInput applicationcontacts.LinkListInput) {
	actor, ok := h.contactReadActor(w, r, tenantID)
	if !ok {
		return
	}
	pageInput.TicketKind = kind
	pageInput.TicketID = ticketID
	page, err := h.contacts.ListLinks(r.Context(), actor, tenantID, pageInput)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	items := make([]contract.TicketCustomerContactLink, len(page.Items))
	for index, link := range page.Items {
		items[index], err = mapTicketCustomerContactLink(link)
		if err != nil {
			writeDomainError(w, r, applicationcontacts.ErrUnavailable)
			return
		}
	}
	result := contract.TicketCustomerContactLinkList{Items: items}
	if page.NextCursor != "" {
		result.NextCursor = &page.NextCursor
	}
	writeSensitiveJSON(w, http.StatusOK, result)
}

func contactLinkListInput(after *contract.ContactAfterCursor, limit *contract.PageSize) applicationcontacts.LinkListInput {
	result := applicationcontacts.LinkListInput{}
	if after != nil {
		result.After = string(*after)
	}
	if limit != nil {
		result.Limit = int(*limit)
	}
	return result
}

func (h *Handler) LinkTenantAlertCustomerContact(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, alertID contract.AlertId, _ contract.LinkTenantAlertCustomerContactParams) {
	h.linkTicketCustomerContact(w, r, uuid.UUID(tenantID), contactkernel.TicketAlert, uuid.UUID(alertID))
}

func (h *Handler) LinkTenantCaseCustomerContact(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, _ contract.LinkTenantCaseCustomerContactParams) {
	h.linkTicketCustomerContact(w, r, uuid.UUID(tenantID), contactkernel.TicketCase, uuid.UUID(caseID))
}

func (h *Handler) linkTicketCustomerContact(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, kind contactkernel.TicketKind, ticketID uuid.UUID) {
	actor, audit, key, ok := h.contactMutationContext(w, r, tenantID)
	if !ok {
		return
	}
	version, ok := contactVersionPrecondition(w, r)
	if !ok {
		return
	}
	var body contract.TicketCustomerContactLinkCreate
	if decodeAuthorizationBody(r, &body, "application/json") != nil || !body.Role.Valid() {
		writeDomainError(w, r, applicationcontacts.ErrInvalidInput)
		return
	}
	role, err := contactLinkRole(body.Role)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.contacts.LinkContact(r.Context(), actor, tenantID, applicationcontacts.LinkInput{
		TicketKind: kind, TicketID: ticketID, ContactID: uuid.UUID(body.ContactId), Role: role,
		ExpectedTicketVersion: version, IdempotencyKey: key, Audit: audit,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapTicketCustomerContactLink(result.Link)
	if err != nil || result.Link.Version() > math.MaxInt64 || !setVersionETag(w, int64(result.Link.Version())) {
		writeDomainError(w, r, applicationcontacts.ErrUnavailable)
		return
	}
	w.Header().Set("Location", r.URL.Path+"/"+mapped.Id.String())
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) ArchiveTenantAlertCustomerContactLink(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, alertID contract.AlertId, contactLinkID contract.ContactLinkId, _ contract.ArchiveTenantAlertCustomerContactLinkParams) {
	h.archiveTicketCustomerContact(w, r, uuid.UUID(tenantID), contactkernel.TicketAlert, uuid.UUID(alertID), uuid.UUID(contactLinkID))
}

func (h *Handler) ArchiveTenantCaseCustomerContactLink(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, contactLinkID contract.ContactLinkId, _ contract.ArchiveTenantCaseCustomerContactLinkParams) {
	h.archiveTicketCustomerContact(w, r, uuid.UUID(tenantID), contactkernel.TicketCase, uuid.UUID(caseID), uuid.UUID(contactLinkID))
}

func (h *Handler) archiveTicketCustomerContact(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, kind contactkernel.TicketKind, ticketID, linkID uuid.UUID) {
	actor, audit, key, ok := h.contactMutationContext(w, r, tenantID)
	if !ok {
		return
	}
	linkVersion, ok := contactVersionPrecondition(w, r)
	if !ok {
		return
	}
	var body contract.TicketCustomerContactLinkArchive
	if decodeAuthorizationBody(r, &body, "application/json") != nil || body.ExpectedTicketVersion < 1 {
		writeDomainError(w, r, applicationcontacts.ErrInvalidInput)
		return
	}
	result, err := h.contacts.ArchiveLink(r.Context(), actor, tenantID, linkID, applicationcontacts.ArchiveLinkInput{
		TicketKind: kind, TicketID: ticketID, ExpectedLinkVersion: linkVersion,
		ExpectedTicketVersion: uint64(body.ExpectedTicketVersion), Reason: body.Reason,
		IdempotencyKey: key, Audit: audit,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapTicketCustomerContactLink(result.Link)
	if err != nil || result.Link.Version() > math.MaxInt64 || !setVersionETag(w, int64(result.Link.Version())) {
		writeDomainError(w, r, applicationcontacts.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ListCustomerPortalAlertComments(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, alertID contract.AlertId, params contract.ListCustomerPortalAlertCommentsParams) {
	h.listCustomerPortalComments(w, r, uuid.UUID(tenantID), ticketkernel.AggregateAlert, uuid.UUID(alertID), cursorPageInput(params.After, params.Limit))
}

func (h *Handler) ListCustomerPortalCaseComments(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, params contract.ListCustomerPortalCaseCommentsParams) {
	h.listCustomerPortalComments(w, r, uuid.UUID(tenantID), ticketkernel.AggregateCase, uuid.UUID(caseID), cursorPageInput(params.After, params.Limit))
}

func (h *Handler) listCustomerPortalComments(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, kind ticketkernel.AggregateKind, ticketID uuid.UUID, pageInput applicationticketing.CursorPageInput) {
	actor, ok := h.ticketingReadActor(w, r)
	if !ok {
		return
	}
	page, err := h.ticketing.CommentsPortal(r.Context(), actor, tenantID, kind, ticketID, pageInput)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if page.Projection != applicationticketing.ProjectionCustomer {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	mapped, err := mapCustomerCommentPage(page, tenantID, kind, ticketID)
	if err != nil {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) CreateCustomerPortalAlertComment(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, alertID contract.AlertId, params contract.CreateCustomerPortalAlertCommentParams) {
	h.createCustomerPortalComment(w, r, uuid.UUID(tenantID), ticketkernel.AggregateAlert, uuid.UUID(alertID), params.IdempotencyKey)
}

func (h *Handler) CreateCustomerPortalCaseComment(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, params contract.CreateCustomerPortalCaseCommentParams) {
	h.createCustomerPortalComment(w, r, uuid.UUID(tenantID), ticketkernel.AggregateCase, uuid.UUID(caseID), params.IdempotencyKey)
}

func (h *Handler) createCustomerPortalComment(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
	kind ticketkernel.AggregateKind,
	ticketID uuid.UUID,
	parameterKey contract.IdempotencyKey,
) {
	actor, ok := h.ticketingMutationActor(w, r)
	if !ok {
		return
	}
	key, err := requestIdempotencyKey(r)
	if err != nil || string(parameterKey) != key {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	var body contract.CustomerPortalCommentCreate
	if decodeTicketCommentBody(r, &body) != nil {
		writeDomainError(w, r, applicationticketing.ErrInvalidInput)
		return
	}
	attachmentIDs := optionalCommentRelatedIDs(body.AttachmentIds)
	comment, projection, replayed, err := h.ticketing.AddPortalComment(r.Context(), actor, tenantID, kind, ticketID,
		applicationticketing.CommentInput{
			Visibility: ticketkernel.CommentPublic, BodyMarkdown: body.BodyMarkdown,
			AttachmentIDs: attachmentIDs, IdempotencyKey: key,
		})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if projection != applicationticketing.ProjectionCustomer || comment.Visibility != ticketkernel.CommentPublic ||
		comment.Revision != 1 || !commentProjectionMatchesInput(
		comment.BodyMarkdown, comment.Attachments, comment.Mentions,
		body.BodyMarkdown, attachmentIDs, nil,
	) {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	mapped, err := mapCustomerComment(comment, tenantID, kind, ticketID)
	if err != nil || !setCommentRevisionETag(w, comment.Revision) {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	w.Header().Set("Location", r.URL.Path+"/"+comment.ID.String())
	w.Header().Set(idempotentReplayHeader, strconv.FormatBool(replayed))
	writeSensitiveJSON(w, http.StatusCreated, mapped)
}

func (h *Handler) ListCustomerPortalAlertActivities(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, alertID contract.AlertId, params contract.ListCustomerPortalAlertActivitiesParams) {
	h.listCustomerPortalActivities(w, r, uuid.UUID(tenantID), ticketkernel.AggregateAlert, uuid.UUID(alertID), cursorPageInput(params.After, params.Limit))
}

func (h *Handler) ListCustomerPortalCaseActivities(w http.ResponseWriter, r *http.Request, tenantID contract.TenantId, caseID contract.CaseId, params contract.ListCustomerPortalCaseActivitiesParams) {
	h.listCustomerPortalActivities(w, r, uuid.UUID(tenantID), ticketkernel.AggregateCase, uuid.UUID(caseID), cursorPageInput(params.After, params.Limit))
}

func (h *Handler) listCustomerPortalActivities(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, kind ticketkernel.AggregateKind, ticketID uuid.UUID, pageInput applicationticketing.CursorPageInput) {
	actor, ok := h.ticketingReadActor(w, r)
	if !ok {
		return
	}
	page, err := h.ticketing.ActivitiesPortal(r.Context(), actor, tenantID, kind, ticketID, pageInput)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	if page.Projection != applicationticketing.ProjectionCustomer {
		writeDomainError(w, r, applicationticketing.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapActivityPage(page))
}

func mapTicketCustomerContactLink(value contactkernel.TicketContactLink) (contract.TicketCustomerContactLink, error) {
	if value.Version() == 0 || value.Version() > math.MaxInt64 {
		return contract.TicketCustomerContactLink{}, errors.New("invalid ticket-contact link version")
	}
	resourceKind := contract.TicketResourceKind(value.TicketKind().String())
	role := contract.TicketCustomerContactRole(value.Role().String())
	origin := contract.TicketCustomerContactLinkOrigin(value.Origin().String())
	if !resourceKind.Valid() || !role.Valid() || !origin.Valid() {
		return contract.TicketCustomerContactLink{}, errors.New("invalid ticket-contact link enum")
	}
	result := contract.TicketCustomerContactLink{
		Id:           openapi_types.UUID(uuid.UUID(value.ID().Bytes())),
		TenantId:     openapi_types.UUID(uuid.UUID(value.TenantID().Bytes())),
		ResourceKind: resourceKind, ResourceId: openapi_types.UUID(uuid.UUID(value.TicketID().Bytes())),
		ContactId: openapi_types.UUID(uuid.UUID(value.ContactID().Bytes())), Role: role, Origin: origin,
		Version: int64(value.Version()), CreatedAt: value.CreatedAt(), ArchivedAt: value.ArchivedAt(),
	}
	if provenance := value.Provenance(); provenance != nil {
		if provenance.SourceAlertVersion() > math.MaxInt64 {
			return contract.TicketCustomerContactLink{}, errors.New("invalid contact-link provenance version")
		}
		result.EscalationProvenance = &contract.TicketCustomerContactEscalationProvenance{
			SourceAlertId:      openapi_types.UUID(uuid.UUID(provenance.SourceAlertID().Bytes())),
			SourceAlertVersion: int64(provenance.SourceAlertVersion()),
		}
	}
	return result, nil
}

func contactLinkRole(value contract.TicketCustomerContactRole) (contactkernel.ContactRole, error) {
	switch value {
	case contract.TicketCustomerContactRolePrimary:
		return contactkernel.RolePrimary, nil
	case contract.TicketCustomerContactRoleEscalation:
		return contactkernel.RoleEscalation, nil
	case contract.TicketCustomerContactRoleWatcher:
		return contactkernel.RoleWatcher, nil
	default:
		return 0, applicationcontacts.ErrInvalidInput
	}
}
