package httpserver

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	applicationcontacts "github.com/periapsis-im/periapsis/services/api/internal/contacts"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func (h *Handler) ListCustomerPortalAlertDfirAttachments(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	params contract.ListCustomerPortalAlertDfirAttachmentsParams,
) {
	h.listCustomerPortalDfirAttachments(
		w, r, uuid.UUID(tenantID), uuid.UUID(alertID), application.PortalTicketAlert,
		params.After, params.Limit,
	)
}

func (h *Handler) PrepareCustomerPortalAlertDfirAttachmentDownload(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	alertID contract.AlertId,
	attachmentID uuid.UUID,
) {
	h.prepareCustomerPortalDfirAttachmentDownload(
		w, r, uuid.UUID(tenantID), uuid.UUID(alertID), attachmentID, application.PortalTicketAlert,
	)
}

func (h *Handler) ListCustomerPortalCaseDfirAttachments(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	caseID contract.CaseId,
	params contract.ListCustomerPortalCaseDfirAttachmentsParams,
) {
	h.listCustomerPortalDfirAttachments(
		w, r, uuid.UUID(tenantID), uuid.UUID(caseID), application.PortalTicketCase,
		params.After, params.Limit,
	)
}

func (h *Handler) PrepareCustomerPortalCaseDfirAttachmentDownload(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	caseID contract.CaseId,
	attachmentID uuid.UUID,
) {
	h.prepareCustomerPortalDfirAttachmentDownload(
		w, r, uuid.UUID(tenantID), uuid.UUID(caseID), attachmentID, application.PortalTicketCase,
	)
}

func (h *Handler) listCustomerPortalDfirAttachments(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
	rootID uuid.UUID,
	kind application.PortalTicketKind,
	after *contract.CustomerPortalAttachmentAfterCursor,
	limit *contract.PageSize,
) {
	actor, ok := h.portalDFIRReadActor(w, r, tenantID)
	if !ok {
		return
	}
	rootEntity, err := dfirEntityID(rootID)
	if err != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	input := application.CustomerPortalAttachmentListInput{}
	if after != nil {
		input.After = string(*after)
	}
	if limit != nil {
		input.Limit = int(*limit)
	}
	portal := h.dfir.(CustomerPortalAttachmentService)
	page, err := portal.ListCustomerPortalAttachments(r.Context(), actor, tenantID, application.PortalAttachmentRoot{
		Kind: kind, ID: rootEntity,
	}, input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapCustomerPortalAttachmentPage(page)
	if err != nil {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) prepareCustomerPortalDfirAttachmentDownload(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
	rootID uuid.UUID,
	attachmentID uuid.UUID,
	kind application.PortalTicketKind,
) {
	if r == nil || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	actor, audit, ok := h.portalDFIRCapabilityActor(w, r, tenantID)
	if !ok {
		return
	}
	rootEntity, rootErr := dfirEntityID(rootID)
	attachmentEntity, attachmentErr := dfirEntityID(attachmentID)
	if rootErr != nil || attachmentErr != nil {
		writeDomainError(w, r, application.ErrInvalidInput)
		return
	}
	portal := h.dfir.(CustomerPortalAttachmentService)
	prepared, err := portal.PrepareCustomerPortalAttachmentDownload(
		r.Context(), actor, tenantID, application.PortalAttachmentRoot{Kind: kind, ID: rootEntity}, attachmentEntity, audit,
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	attachment, err := mapCustomerPortalAttachment(prepared.Attachment)
	if err != nil || prepared.Grant.TargetURL == "" || prepared.Grant.ExpiresAt.IsZero() {
		writeDomainError(w, r, application.ErrUnavailable)
		return
	}
	w.Header().Set("Referrer-Policy", "no-referrer")
	writeSensitiveJSON(w, http.StatusOK, contract.CustomerPortalPreparedAttachmentDownload{
		Attachment: attachment, DownloadUrl: prepared.Grant.TargetURL, ExpiresAt: prepared.Grant.ExpiresAt,
	})
}

func (h *Handler) portalDFIRReadActor(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID) (application.Actor, bool) {
	if h.dfir == nil {
		writeDomainError(w, r, application.ErrUnavailable)
		return application.Actor{}, false
	}
	if _, ok := h.dfir.(CustomerPortalAttachmentService); !ok {
		writeDomainError(w, r, application.ErrUnavailable)
		return application.Actor{}, false
	}
	contactActor, ok := h.portalContactReadActor(w, r, tenantID)
	if !ok {
		return application.Actor{}, false
	}
	return application.Actor{
		TenantID: tenantID, ActiveTenantID: contactActor.ActiveTenantID,
		UserID: contactActor.UserID, MembershipID: contactActor.MembershipID, SessionID: contactActor.SessionID,
		Kind: application.PrincipalCustomer, AuthenticationMethod: contactActor.AuthenticationMethod,
	}, true
}

func (h *Handler) portalDFIRCapabilityActor(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID) (application.Actor, application.AuditContext, bool) {
	if h.dfir == nil {
		writeDomainError(w, r, application.ErrUnavailable)
		return application.Actor{}, application.AuditContext{}, false
	}
	if _, ok := h.dfir.(CustomerPortalAttachmentService); !ok {
		writeDomainError(w, r, application.ErrUnavailable)
		return application.Actor{}, application.AuditContext{}, false
	}
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return application.Actor{}, application.AuditContext{}, false
	}
	contactAudit := applicationcontacts.AuditContext{
		RequestID: audit.RequestID, CorrelationID: audit.CorrelationID,
		RemoteAddress: audit.RemoteAddress, UserAgent: audit.UserAgent,
	}
	contactActor, ok := h.resolveContactActor(
		w, r, actor, contactAudit, tenantID, applicationcontacts.PrincipalCustomer,
	)
	if !ok {
		return application.Actor{}, application.AuditContext{}, false
	}
	return application.Actor{
			TenantID: tenantID, ActiveTenantID: contactActor.ActiveTenantID,
			UserID: contactActor.UserID, MembershipID: contactActor.MembershipID, SessionID: contactActor.SessionID,
			Kind: application.PrincipalCustomer, AuthenticationMethod: contactActor.AuthenticationMethod,
		}, application.AuditContext{
			RequestID: audit.RequestID, CorrelationID: audit.CorrelationID,
			IPAddress: audit.RemoteAddress, UserAgent: audit.UserAgent,
			AuthenticationMethod: contactActor.AuthenticationMethod,
		}, true
}

func mapCustomerPortalAttachmentPage(page application.CustomerPortalAttachmentPage) (contract.CustomerPortalAttachmentList, error) {
	result := contract.CustomerPortalAttachmentList{Items: make([]contract.CustomerPortalAttachment, len(page.Items))}
	for index, value := range page.Items {
		mapped, err := mapCustomerPortalAttachment(value)
		if err != nil {
			return contract.CustomerPortalAttachmentList{}, err
		}
		result.Items[index] = mapped
	}
	if page.NextCursor != "" {
		cursor := contract.CustomerPortalAttachmentCursor(page.NextCursor)
		result.NextCursor = &cursor
	}
	return result, nil
}

func mapCustomerPortalAttachment(value application.CustomerPortalAttachment) (contract.CustomerPortalAttachment, error) {
	id, err := uuid.Parse(value.ID.String())
	rootID, rootErr := uuid.Parse(value.ResourceID.String())
	resourceKind := contract.TicketResourceKind(value.ResourceKind)
	if err != nil || rootErr != nil || id.Version() != 7 || rootID.Version() != 7 ||
		!resourceKind.Valid() || value.OriginalFilename == "" || value.UploadedAt.IsZero() ||
		value.UploadedAt.Location() != time.UTC || value.UploadedAt.Nanosecond()%1_000 != 0 {
		return contract.CustomerPortalAttachment{}, application.ErrUnavailable
	}
	return contract.CustomerPortalAttachment{
		Downloadable: contract.CustomerPortalAttachmentDownloadableTrue,
		Id:           id, OriginalFilename: value.OriginalFilename,
		Projection: contract.CustomerPortalAttachmentProjectionCustomer,
		ResourceId: rootID, ResourceKind: resourceKind, UploadedAt: value.UploadedAt,
	}, nil
}
