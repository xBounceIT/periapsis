package httpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"time"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/securityaudit"
)

func (h *Handler) ListTenantAuditEvents(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	params contract.ListTenantAuditEventsParams,
) {
	actor, _, ok := h.tenantAuthorizationSession(w, r)
	if !ok {
		return
	}
	event, err := h.eventContext(r)
	if err != nil {
		writeDomainError(w, r, securityaudit.ErrInvalidInput)
		return
	}
	query, err := tenantAuditQuery(params)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	page, err := h.audit.ListTenant(
		r.Context(), actor, uuid.UUID(tenantID), query, auditContext(event),
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapAuditPage(page)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) VerifyTenantAuditChain(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
) {
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return
	}
	result, err := h.audit.VerifyTenant(
		r.Context(), actor, uuid.UUID(tenantID), audit,
	)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapAuditVerification(result)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) ListPlatformAuditEvents(
	w http.ResponseWriter,
	r *http.Request,
	params contract.ListPlatformAuditEventsParams,
) {
	session, ok := h.platformOperatorTeamSession(w, r)
	if !ok {
		return
	}
	event, err := h.eventContext(r)
	if err != nil {
		writeDomainError(w, r, securityaudit.ErrInvalidInput)
		return
	}
	query, err := platformAuditQuery(params)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	page, err := h.audit.ListPlatform(r.Context(), session, query, event)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapAuditPage(page)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) VerifyPlatformAuditChain(w http.ResponseWriter, r *http.Request) {
	session, event, ok := h.preparePlatformAuditVerification(w, r)
	if !ok {
		return
	}
	result, err := h.audit.VerifyPlatform(r.Context(), session, event)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	mapped, err := mapAuditVerification(result)
	if err != nil {
		writeDomainError(w, r, err)
		return
	}
	writeSensitiveJSON(w, http.StatusOK, mapped)
}

func (h *Handler) preparePlatformAuditVerification(
	w http.ResponseWriter,
	r *http.Request,
) (authentication.Session, authentication.EventContext, bool) {
	if !h.prepareCookieMutation(w, r) {
		return authentication.Session{}, authentication.EventContext{}, false
	}
	session, ok := h.platformOperatorTeamSession(w, r)
	if !ok {
		return authentication.Session{}, authentication.EventContext{}, false
	}
	csrf, err := singleHeader(r, csrfTokenHeader, 128)
	if err != nil || h.authentication.ValidateCSRF(session, csrf) != nil {
		writeDomainError(w, r, authentication.ErrForbidden)
		return authentication.Session{}, authentication.EventContext{}, false
	}
	event, err := h.eventContext(r)
	if err != nil {
		writeDomainError(w, r, securityaudit.ErrInvalidInput)
		return authentication.Session{}, authentication.EventContext{}, false
	}
	return session, event, true
}

func auditContext(event authentication.EventContext) authorization.AuditContext {
	return authorization.AuditContext{
		RequestID: event.RequestID, CorrelationID: event.CorrelationID,
		RemoteAddress: event.RemoteAddress, UserAgent: event.UserAgent,
	}
}

func tenantAuditQuery(params contract.ListTenantAuditEventsParams) (securityaudit.Query, error) {
	return auditQuery(
		params.AfterSequence, params.Limit, params.OccurredFrom,
		params.OccurredBefore, params.ActorType, params.ActorUserId,
		params.ActorServiceAccountId, params.ActionPrefix, params.ResourceType,
		params.ResourceId, params.RequestId, params.CorrelationId, params.Outcome,
		params.Search,
	)
}

func platformAuditQuery(params contract.ListPlatformAuditEventsParams) (securityaudit.Query, error) {
	return auditQuery(
		params.AfterSequence, params.Limit, params.OccurredFrom,
		params.OccurredBefore, params.ActorType, params.ActorUserId, nil,
		params.ActionPrefix, params.ResourceType, params.ResourceId, params.RequestId,
		params.CorrelationId, params.Outcome, params.Search,
	)
}

func auditQuery(
	after *contract.AuditAfterSequence,
	limit *contract.PageSize,
	from *time.Time,
	before *time.Time,
	actorType *contract.AuditActorType,
	actorUserID *openapi_types.UUID,
	actorServiceAccountID *openapi_types.UUID,
	actionPrefix *string,
	resourceType *string,
	resourceID *openapi_types.UUID,
	requestID *openapi_types.UUID,
	correlationID *openapi_types.UUID,
	outcome *contract.AuditOutcome,
	search *string,
) (securityaudit.Query, error) {
	query := securityaudit.Query{}
	if after != nil {
		if *after < 0 {
			return securityaudit.Query{}, securityaudit.ErrInvalidInput
		}
		query.AfterSequence = uint64(*after)
	}
	if limit != nil {
		query.Limit = *limit
	}
	query.OccurredFrom = cloneTime(from)
	query.OccurredBefore = cloneTime(before)
	if actorType != nil {
		value := securityaudit.ActorType(*actorType)
		query.ActorType = &value
	}
	query.ActorUserID = cloneAuditUUID(actorUserID)
	query.ActorServiceAccountID = cloneAuditUUID(actorServiceAccountID)
	query.ActionPrefix = dereferenceString(actionPrefix)
	query.ResourceType = dereferenceString(resourceType)
	query.ResourceID = cloneAuditUUID(resourceID)
	query.RequestID = cloneAuditUUID(requestID)
	query.CorrelationID = cloneAuditUUID(correlationID)
	if outcome != nil {
		value := securityaudit.Outcome(*outcome)
		query.Outcome = &value
	}
	query.Search = dereferenceString(search)
	return query, nil
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneAuditUUID(value *openapi_types.UUID) *uuid.UUID {
	if value == nil {
		return nil
	}
	cloned := uuid.UUID(*value)
	return &cloned
}

func dereferenceString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func mapAuditPage(page securityaudit.Page) (contract.AuditEventPage, error) {
	items := make([]contract.AuditEvent, len(page.Items))
	for index, event := range page.Items {
		mapped, err := mapAuditEvent(event)
		if err != nil {
			return contract.AuditEventPage{}, securityaudit.ErrUnavailable
		}
		items[index] = mapped
	}
	result := contract.AuditEventPage{Items: items}
	if page.NextSequence != nil {
		if *page.NextSequence > math.MaxInt64 {
			return contract.AuditEventPage{}, securityaudit.ErrUnavailable
		}
		value := int64(*page.NextSequence)
		result.NextSequence = &value
	}
	return result, nil
}

func mapAuditEvent(event securityaudit.Event) (contract.AuditEvent, error) {
	if event.Sequence == 0 || event.Sequence > math.MaxInt64 {
		return contract.AuditEvent{}, securityaudit.ErrUnavailable
	}
	before, err := mapAuditDocument(event.Before)
	if err != nil {
		return contract.AuditEvent{}, err
	}
	after, err := mapAuditDocument(event.After)
	if err != nil {
		return contract.AuditEvent{}, err
	}
	metadata, err := mapAuditDocument(event.Metadata)
	if err != nil {
		return contract.AuditEvent{}, err
	}
	result := contract.AuditEvent{
		Id: event.ID, Sequence: int64(event.Sequence), OccurredAt: event.OccurredAt,
		ActorType: contract.AuditActorType(event.ActorType), Action: event.Action,
		ResourceType: event.ResourceType, Outcome: contract.AuditOutcome(event.Outcome),
		Before: before, After: after, Metadata: metadata,
		PreviousHash: event.PreviousHash, EventHash: event.EventHash,
		TenantId:              contractAuditUUID(event.TenantID),
		ActorUserId:           contractAuditUUID(event.ActorUserID),
		ActorServiceAccountId: contractAuditUUID(event.ActorServiceAccountID),
		ImpersonatedByUserId:  contractAuditUUID(event.ImpersonatedByUserID),
		ResourceId:            contractAuditUUID(event.ResourceID),
		RequestId:             contractAuditUUID(event.RequestID),
		CorrelationId:         contractAuditUUID(event.CorrelationID),
		UserAgent:             cloneString(event.UserAgent),
		AuthenticationMethod:  cloneString(event.AuthenticationMethod),
		Reason:                cloneString(event.Reason),
	}
	if event.IPAddress != nil {
		value := event.IPAddress.String()
		result.IpAddress = &value
	}
	return result, nil
}

func mapAuditDocument(document json.RawMessage) (contract.AuditJsonDocument, error) {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil || value == nil {
		return nil, errors.New("invalid redacted audit document")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("audit document contains trailing JSON")
	}
	return contract.AuditJsonDocument(value), nil
}

func contractAuditUUID(value *uuid.UUID) *openapi_types.UUID {
	if value == nil {
		return nil
	}
	mapped := openapi_types.UUID(*value)
	return &mapped
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func mapAuditVerification(value securityaudit.Verification) (contract.AuditChainVerification, error) {
	if value.EventCount > math.MaxInt64 || value.LastSequence > math.MaxInt64 {
		return contract.AuditChainVerification{}, securityaudit.ErrUnavailable
	}
	result := contract.AuditChainVerification{
		EventCount: int64(value.EventCount), LastSequence: int64(value.LastSequence),
		HeadValid: value.HeadValid, Valid: value.Valid, VerifiedAt: value.VerifiedAt,
	}
	if value.FirstInvalidSequence != nil {
		if *value.FirstInvalidSequence == 0 || *value.FirstInvalidSequence > math.MaxInt64 {
			return contract.AuditChainVerification{}, securityaudit.ErrUnavailable
		}
		mapped := int64(*value.FirstInvalidSequence)
		result.FirstInvalidSequence = &mapped
	}
	return result, nil
}
