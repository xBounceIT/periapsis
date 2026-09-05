package httpserver

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/notificationinbox"
)

const notificationInboxPrivateCacheControl = "private, no-store"

type unavailableNotificationInboxService struct{}

func (unavailableNotificationInboxService) List(
	context.Context,
	notificationinbox.Actor,
	uuid.UUID,
	notificationinbox.ListInput,
) (notificationinbox.Page, error) {
	return notificationinbox.Page{}, notificationinbox.ErrUnavailable
}

func (unavailableNotificationInboxService) CountUnread(
	context.Context,
	notificationinbox.Actor,
	uuid.UUID,
) (notificationinbox.UnreadState, error) {
	return notificationinbox.UnreadState{}, notificationinbox.ErrUnavailable
}

func (unavailableNotificationInboxService) SetReadState(
	context.Context,
	notificationinbox.Actor,
	uuid.UUID,
	notificationinbox.SetReadStateInput,
) (notificationinbox.ReadStateResult, error) {
	return notificationinbox.ReadStateResult{}, notificationinbox.ErrUnavailable
}

func (unavailableNotificationInboxService) MarkAllRead(
	context.Context,
	notificationinbox.Actor,
	uuid.UUID,
	notificationinbox.MarkAllReadInput,
) (notificationinbox.MarkAllReadResult, error) {
	return notificationinbox.MarkAllReadResult{}, notificationinbox.ErrUnavailable
}

func (h *Handler) ListTenantNotificationInbox(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.ListTenantNotificationInboxParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.notificationInboxReadActor(w, r, tenant)
	if !ok {
		return
	}

	input := notificationinbox.ListInput{}
	if params.After != nil {
		after := uuid.UUID(*params.After)
		if !validNotificationInboxUUID(after) {
			writeDomainError(w, r, notificationinbox.ErrInvalidInput)
			return
		}
		input.After = &after
	}
	if params.Limit != nil {
		input.Limit = int(*params.Limit)
	}
	if params.UnreadOnly != nil {
		input.UnreadOnly = *params.UnreadOnly
	}

	result, err := h.notificationInbox.List(r.Context(), actor, tenant, input)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapNotificationInboxPage(result)
	if err != nil {
		writeDomainError(w, r, notificationinbox.ErrUnavailable)
		return
	}
	writeNotificationInboxJSON(w, http.StatusOK, mapped)
}

func (h *Handler) GetTenantNotificationInboxUnreadCount(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.notificationInboxReadActor(w, r, tenant)
	if !ok {
		return
	}
	result, err := h.notificationInbox.CountUnread(r.Context(), actor, tenant)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeNotificationInboxJSON(w, http.StatusOK, contract.NotificationInboxUnreadState{
		TenantId:      result.TenantID,
		UserId:        result.UserID,
		Count:         int64(result.Count),
		InboxRevision: int64(result.InboxRevision),
	})
}

func (h *Handler) SetTenantNotificationInboxReadState(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	itemID contract.NotificationInboxItemId,
	params contract.SetTenantNotificationInboxReadStateParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.notificationInboxMutationActor(w, r, tenant)
	if !ok {
		return
	}
	item := uuid.UUID(itemID)
	if !validNotificationInboxUUID(item) {
		writeDomainError(w, r, notificationinbox.ErrInvalidInput)
		return
	}
	expected, err := notificationInboxExpectedRevision(r, string(params.IfMatch), false)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	key, err := notificationInboxIdempotencyKey(r, string(params.IdempotencyKey))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	var body struct {
		Read *bool `json:"read"`
	}
	if err := decodeJSONBody(r, &body); err != nil || body.Read == nil {
		writeDomainError(w, r, notificationinbox.ErrInvalidInput)
		return
	}
	result, err := h.notificationInbox.SetReadState(r.Context(), actor, tenant, notificationinbox.SetReadStateInput{
		ItemID: item, Read: *body.Read, ExpectedRevision: expected, IdempotencyKey: key,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mappedItem, err := mapNotificationInboxItem(result.Item)
	if err != nil {
		writeDomainError(w, r, notificationinbox.ErrUnavailable)
		return
	}
	etag, err := notificationInboxETag(result.Item.Revision, false)
	if err != nil {
		writeDomainError(w, r, notificationinbox.ErrUnavailable)
		return
	}
	w.Header().Set("ETag", etag)
	writeNotificationInboxJSON(w, http.StatusOK, contract.NotificationInboxReadStateResult{
		Item: mappedItem, InboxRevision: int64(result.InboxRevision),
		Changed: result.Changed, Replayed: result.Replayed,
	})
}

func (h *Handler) MarkAllTenantNotificationInboxRead(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.MarkAllTenantNotificationInboxReadParams,
) {
	tenant := uuid.UUID(tenantID)
	actor, ok := h.notificationInboxMutationActor(w, r, tenant)
	if !ok {
		return
	}
	expected, err := notificationInboxExpectedRevision(r, string(params.IfMatch), true)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	key, err := notificationInboxIdempotencyKey(r, string(params.IdempotencyKey))
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	result, err := h.notificationInbox.MarkAllRead(r.Context(), actor, tenant, notificationinbox.MarkAllReadInput{
		ExpectedRevision: expected, IdempotencyKey: key,
	})
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	etag, err := notificationInboxETag(result.InboxRevision, true)
	if err != nil {
		writeDomainError(w, r, notificationinbox.ErrUnavailable)
		return
	}
	w.Header().Set("ETag", etag)
	writeNotificationInboxJSON(w, http.StatusOK, contract.NotificationInboxMarkAllReadResult{
		TenantId: result.TenantID, UserId: result.UserID, Affected: int64(result.Affected),
		InboxRevision: int64(result.InboxRevision), Changed: result.Changed, Replayed: result.Replayed,
	})
}

func (h *Handler) notificationInboxReadActor(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
) (notificationinbox.Actor, bool) {
	authorizationActor, _, ok := h.tenantAuthorizationSession(w, r)
	if !ok {
		return notificationinbox.Actor{}, false
	}
	if !validNotificationInboxUUID(tenantID) {
		writeDomainError(w, r, notificationinbox.ErrInvalidInput)
		return notificationinbox.Actor{}, false
	}
	if authorizationActor.ActiveTenantID != tenantID {
		writeDomainError(w, r, notificationinbox.ErrForbidden)
		return notificationinbox.Actor{}, false
	}
	event, err := h.eventContext(r)
	if err != nil {
		writeDomainError(w, r, notificationinbox.ErrInvalidInput)
		return notificationinbox.Actor{}, false
	}
	return notificationInboxActor(authorizationActor, authorization.AuditContext{
		RequestID: event.RequestID, CorrelationID: event.CorrelationID,
		RemoteAddress: event.RemoteAddress, UserAgent: event.UserAgent,
	}), true
}

func (h *Handler) notificationInboxMutationActor(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
) (notificationinbox.Actor, bool) {
	authorizationActor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return notificationinbox.Actor{}, false
	}
	if !validNotificationInboxUUID(tenantID) {
		writeDomainError(w, r, notificationinbox.ErrInvalidInput)
		return notificationinbox.Actor{}, false
	}
	if authorizationActor.ActiveTenantID != tenantID {
		writeDomainError(w, r, notificationinbox.ErrForbidden)
		return notificationinbox.Actor{}, false
	}
	return notificationInboxActor(authorizationActor, audit), true
}

func notificationInboxActor(
	actor authorization.Actor,
	audit authorization.AuditContext,
) notificationinbox.Actor {
	return notificationinbox.Actor{
		UserID: actor.UserID, SessionID: actor.SessionID, ActiveTenantID: actor.ActiveTenantID,
		Audit: notificationinbox.AuditMetadata{
			RequestID: audit.RequestID, CorrelationID: audit.CorrelationID,
			RemoteAddress: audit.RemoteAddress, UserAgent: audit.UserAgent,
		},
	}
}

func notificationInboxExpectedRevision(r *http.Request, supplied string, allowZero bool) (uint64, error) {
	values := r.Header.Values(ifMatchHeader)
	if len(values) == 0 {
		return 0, authorization.ErrPreconditionRequired
	}
	if len(values) != 1 || values[0] != supplied {
		return 0, notificationinbox.ErrInvalidInput
	}
	value := values[0]
	if len(value) < len("\"v0\"") || value[:2] != "\"v" || value[len(value)-1:] != "\"" {
		return 0, notificationinbox.ErrInvalidInput
	}
	digits := value[2 : len(value)-1]
	if digits == "" || len(digits) > 1 && digits[0] == '0' {
		return 0, notificationinbox.ErrInvalidInput
	}
	for _, digit := range digits {
		if digit < '0' || digit > '9' {
			return 0, notificationinbox.ErrInvalidInput
		}
	}
	revision, err := strconv.ParseUint(digits, 10, 32)
	if err != nil || revision >= notificationinbox.MaximumRevision || !allowZero && revision == 0 {
		return 0, notificationinbox.ErrInvalidInput
	}
	return revision, nil
}

func notificationInboxIdempotencyKey(r *http.Request, supplied string) (string, error) {
	key, err := requestIdempotencyKey(r)
	if err != nil || key != supplied {
		return "", notificationinbox.ErrInvalidInput
	}
	return key, nil
}

func notificationInboxETag(revision uint64, allowZero bool) (string, error) {
	if revision > notificationinbox.MaximumRevision || !allowZero && revision == 0 {
		return "", errors.New("notification inbox revision is invalid")
	}
	return "\"v" + strconv.FormatUint(revision, 10) + "\"", nil
}

func mapNotificationInboxPage(value notificationinbox.Page) (contract.NotificationInboxPage, error) {
	items := make([]contract.NotificationInboxItem, len(value.Items))
	for index, item := range value.Items {
		mapped, err := mapNotificationInboxItem(item)
		if err != nil {
			return contract.NotificationInboxPage{}, err
		}
		items[index] = mapped
	}
	var nextCursor *uuid.UUID
	if value.NextCursor != nil {
		cursor := *value.NextCursor
		nextCursor = &cursor
	}
	return contract.NotificationInboxPage{
		TenantId: value.TenantID, UserId: value.UserID, Items: items,
		NextCursor: nextCursor, InboxRevision: int64(value.InboxRevision),
	}, nil
}

func mapNotificationInboxItem(value notificationinbox.Item) (contract.NotificationInboxItem, error) {
	audience := contract.NotificationAudience(value.Audience)
	eventType := contract.NotificationEventType(value.EventType)
	resourceKind := contract.NotificationObjectType(value.ResourceKind)
	if !audience.Valid() || !eventType.Valid() || !resourceKind.Valid() {
		return contract.NotificationInboxItem{}, errors.New("notification inbox enum is unsupported")
	}
	var readAt *time.Time
	if value.ReadAt != nil {
		copied := *value.ReadAt
		readAt = &copied
	}
	return contract.NotificationInboxItem{
		Id: value.ID, TenantId: value.TenantID, UserId: value.UserID,
		Audience: audience, EventType: eventType, ResourceKind: resourceKind,
		ResourceId: value.ResourceID, ResourceVersion: int64(value.ResourceVersion),
		Title: value.Title, Summary: value.Summary, OccurredAt: value.OccurredAt,
		ReadAt: readAt, Revision: int64(value.Revision),
	}, nil
}

func validNotificationInboxUUID(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}

func writeNotificationInboxJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", notificationInboxPrivateCacheControl)
	writeJSON(w, status, value)
}
