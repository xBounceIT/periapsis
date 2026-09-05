package httpserver

import (
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"

	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	"github.com/periapsis-im/periapsis/services/api/internal/ticketnumbering"
)

func (h *Handler) GetTenantTicketNumberingPolicy(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	kind contract.TicketNumberingKind,
) {
	session, ok := h.platformIdentityProviderSession(w, r, false)
	if !ok {
		return
	}
	kernelKind, err := ticketNumberingKind(kind)
	if err != nil {
		h.writeTicketNumberingError(w, r, err)
		return
	}
	targetTenantID := uuid.UUID(tenantID)
	policy, err := h.ticketNumbering.Get(r.Context(), session, targetTenantID, kernelKind)
	if err != nil {
		h.writeTicketNumberingError(w, r, err)
		return
	}
	response, err := mapTicketNumberingPolicy(policy, targetTenantID, kernelKind)
	if err != nil || policy.Version() > math.MaxInt64 ||
		!setVersionETag(w, int64(policy.Version())) {
		h.writeTicketNumberingError(w, r, ticketnumbering.ErrUnavailable)
		return
	}
	writeTicketNumberingJSON(w, http.StatusOK, response)
}

func (h *Handler) PreviewTenantTicketNumberingPolicy(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	kind contract.TicketNumberingKind,
) {
	session, ok := h.platformIdentityProviderSession(w, r, true)
	if !ok {
		return
	}
	kernelKind, err := ticketNumberingKind(kind)
	if err != nil {
		h.writeTicketNumberingError(w, r, err)
		return
	}
	var body contract.TicketNumberingDraft
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		h.writeTicketNumberingError(w, r, ticketnumbering.ErrInvalidInput)
		return
	}
	draft, err := ticketNumberingDraft(
		body.Prefix, string(body.Separator), body.Period, body.Width, body.Start,
	)
	if err != nil {
		h.writeTicketNumberingError(w, r, err)
		return
	}
	targetTenantID := uuid.UUID(tenantID)
	preview, err := h.ticketNumbering.Preview(
		r.Context(), session, targetTenantID, kernelKind, draft,
	)
	if err != nil {
		h.writeTicketNumberingError(w, r, err)
		return
	}
	response, err := mapTicketNumberingPreview(preview, targetTenantID, kernelKind)
	if err != nil {
		h.writeTicketNumberingError(w, r, ticketnumbering.ErrUnavailable)
		return
	}
	writeTicketNumberingJSON(w, http.StatusOK, response)
}

func (h *Handler) UpdateTenantTicketNumberingPolicy(
	w http.ResponseWriter,
	r *http.Request,
	tenantID contract.TenantId,
	kind contract.TicketNumberingKind,
	params contract.UpdateTenantTicketNumberingPolicyParams,
) {
	session, ok := h.platformIdentityProviderSession(w, r, true)
	if !ok {
		return
	}
	kernelKind, err := ticketNumberingKind(kind)
	if err != nil {
		h.writeTicketNumberingError(w, r, err)
		return
	}
	var body contract.TicketNumberingUpdateRequest
	if err := decodeAuthorizationBody(r, &body, "application/json"); err != nil {
		h.writeTicketNumberingError(w, r, ticketnumbering.ErrInvalidInput)
		return
	}
	expectedVersion, ok := ticketNumberingPrecondition(
		w, r, params.IfMatch, body.ExpectedVersion,
	)
	if !ok {
		return
	}
	idempotencyKey, err := requestIdempotencyKey(r)
	if err != nil || idempotencyKey != string(params.IdempotencyKey) {
		h.writeTicketNumberingError(w, r, ticketnumbering.ErrInvalidInput)
		return
	}
	reason, err := platformIdentityProviderAuditReason(r, string(params.XAuditReason))
	if err != nil {
		h.writeTicketNumberingError(w, r, ticketnumbering.ErrInvalidInput)
		return
	}
	event, err := h.eventContext(r)
	if err != nil {
		h.writeTicketNumberingError(w, r, ticketnumbering.ErrInvalidInput)
		return
	}
	draft, err := ticketNumberingDraft(
		body.Prefix, string(body.Separator), body.Period, body.Width, body.Start,
	)
	if err != nil {
		h.writeTicketNumberingError(w, r, err)
		return
	}
	targetTenantID := uuid.UUID(tenantID)
	result, err := h.ticketNumbering.Replace(
		r.Context(), session, targetTenantID, kernelKind,
		ticketnumbering.ReplaceInput{
			ExpectedVersion: uint64(expectedVersion),
			Policy:          draft,
			IdempotencyKey:  idempotencyKey,
			Reason:          reason,
			Event:           event,
		},
	)
	if err != nil {
		h.writeTicketNumberingError(w, r, err)
		return
	}
	policy, err := mapTicketNumberingPolicy(result.Policy, targetTenantID, kernelKind)
	if err != nil || result.Policy.Version() > math.MaxInt64 ||
		!setVersionETag(w, int64(result.Policy.Version())) {
		h.writeTicketNumberingError(w, r, ticketnumbering.ErrUnavailable)
		return
	}
	w.Header().Set(idempotentReplayHeader, strconv.FormatBool(result.Replayed))
	writeTicketNumberingJSON(w, http.StatusOK, contract.TicketNumberingMutationResult{
		Policy: policy, Replayed: result.Replayed,
	})
}

func ticketNumberingPrecondition(
	w http.ResponseWriter,
	r *http.Request,
	contractValue contract.IfMatch,
	bodyVersion int32,
) (int32, bool) {
	version, present, err := strongVersionPrecondition(r)
	if !present {
		w.Header().Set("Cache-Control", "no-store")
		writeProblem(
			w, r, http.StatusPreconditionRequired, "precondition_required",
			"Precondition required", "A current strong If-Match entity tag is required.",
		)
		return 0, false
	}
	canonical, canonicalErr := strongVersionETag(version)
	if err != nil || canonicalErr != nil || canonical != string(contractValue) ||
		version < 1 || version >= math.MaxInt32 || bodyVersion < 1 {
		writeTicketNumberingDomainError(w, r, ticketnumbering.ErrInvalidInput)
		return 0, false
	}
	if int64(bodyVersion) != version {
		writeTicketNumberingDomainError(w, r, ticketnumbering.ErrPrecondition)
		return 0, false
	}
	return bodyVersion, true
}

func ticketNumberingKind(value contract.TicketNumberingKind) (kernel.AggregateKind, error) {
	switch value {
	case contract.TicketNumberingKindAlert:
		return kernel.AggregateAlert, nil
	case contract.TicketNumberingKindCase:
		return kernel.AggregateCase, nil
	default:
		return 0, ticketnumbering.ErrInvalidInput
	}
}

func contractTicketNumberingKind(value kernel.AggregateKind) (contract.TicketNumberingKind, error) {
	switch value {
	case kernel.AggregateAlert:
		return contract.TicketNumberingKindAlert, nil
	case kernel.AggregateCase:
		return contract.TicketNumberingKindCase, nil
	default:
		return "", ticketnumbering.ErrUnavailable
	}
}

func ticketNumberingDraft(
	prefix string,
	separator string,
	period contract.TicketNumberingPeriod,
	width int32,
	start int64,
) (ticketnumbering.PolicyDraft, error) {
	if width < 0 || width > math.MaxUint8 || start < 0 {
		return ticketnumbering.PolicyDraft{}, ticketnumbering.ErrInvalidInput
	}
	kernelPeriod, err := ticketNumberingPeriod(period)
	if err != nil {
		return ticketnumbering.PolicyDraft{}, err
	}
	return ticketnumbering.PolicyDraft{
		Prefix: prefix, Separator: separator, Period: kernelPeriod,
		Width: uint8(width), Start: uint64(start),
	}, nil
}

func ticketNumberingPeriod(value contract.TicketNumberingPeriod) (kernel.NumberingPeriod, error) {
	switch value {
	case contract.Annual:
		return kernel.NumberingPeriodAnnual, nil
	case contract.Lifetime:
		return kernel.NumberingPeriodNone, nil
	default:
		return 0, ticketnumbering.ErrInvalidInput
	}
}

func contractTicketNumberingPeriod(value kernel.NumberingPeriod) (contract.TicketNumberingPeriod, error) {
	switch value {
	case kernel.NumberingPeriodAnnual:
		return contract.Annual, nil
	case kernel.NumberingPeriodNone:
		return contract.Lifetime, nil
	default:
		return "", ticketnumbering.ErrUnavailable
	}
}

func mapTicketNumberingPolicy(
	policy kernel.NumberingPolicy,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
) (contract.TicketNumberingPolicy, error) {
	if policy.Tenant() == (kernel.EntityID{}) || policy.VersionID() == (kernel.EntityID{}) ||
		uuid.UUID(policy.Tenant().Bytes()) != tenantID || policy.Kind() != kind ||
		policy.Version() < 1 || policy.Version() > math.MaxInt32 ||
		policy.PublishedAt().IsZero() || policy.PublishedAt().Location() != time.UTC ||
		policy.Spec().Start() > math.MaxInt64 {
		return contract.TicketNumberingPolicy{}, ticketnumbering.ErrUnavailable
	}
	contractKind, err := contractTicketNumberingKind(policy.Kind())
	if err != nil {
		return contract.TicketNumberingPolicy{}, err
	}
	period, err := contractTicketNumberingPeriod(policy.Spec().Period())
	if err != nil {
		return contract.TicketNumberingPolicy{}, err
	}
	publisher := contract.TicketNumberingPublisher{}
	switch policy.Publisher().Kind() {
	case kernel.NumberingPolicyPublisherSystem:
		publisher.Type = contract.TicketNumberingPublisherTypeSystem
	case kernel.NumberingPolicyPublisherMembership:
		membership, ok := policy.Publisher().MembershipID()
		if !ok || membership == (kernel.EntityID{}) {
			return contract.TicketNumberingPolicy{}, ticketnumbering.ErrUnavailable
		}
		membershipID := uuid.UUID(membership.Bytes())
		publisher.Type = contract.TicketNumberingPublisherTypeMembership
		publisher.MembershipId = &membershipID
	default:
		return contract.TicketNumberingPolicy{}, ticketnumbering.ErrUnavailable
	}
	return contract.TicketNumberingPolicy{
		VersionId:   uuid.UUID(policy.VersionID().Bytes()),
		TenantId:    tenantID,
		Kind:        contractKind,
		Version:     contract.ResourceVersion(policy.Version()),
		Prefix:      policy.Spec().Prefix(),
		Separator:   contract.TicketNumberingSeparator(policy.Spec().Separator()),
		Period:      period,
		Width:       int32(policy.Spec().Width()),
		Start:       int64(policy.Spec().Start()),
		Publisher:   publisher,
		PublishedAt: policy.PublishedAt(),
	}, nil
}

func mapTicketNumberingPreview(
	preview ticketnumbering.Preview,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
) (contract.TicketNumberingPreview, error) {
	if preview.TenantID != tenantID || preview.Kind != kind || preview.At.IsZero() ||
		preview.At.Location() != time.UTC || preview.Start > math.MaxInt64 ||
		preview.MaximumSequence > math.MaxInt64 ||
		preview.PeriodKey < math.MinInt32 || preview.PeriodKey > math.MaxInt32 {
		return contract.TicketNumberingPreview{}, ticketnumbering.ErrUnavailable
	}
	contractKind, err := contractTicketNumberingKind(preview.Kind)
	if err != nil {
		return contract.TicketNumberingPreview{}, err
	}
	period, err := contractTicketNumberingPeriod(preview.Period)
	if err != nil {
		return contract.TicketNumberingPreview{}, err
	}
	return contract.TicketNumberingPreview{
		TenantId: tenantID, Kind: contractKind, Prefix: preview.Prefix,
		Separator: contract.TicketNumberingSeparator(preview.Separator),
		Period:    period, Width: int32(preview.Width), Start: int64(preview.Start),
		MaximumSequence: int64(preview.MaximumSequence), At: preview.At,
		PeriodKey: int32(preview.PeriodKey), Example: preview.Example,
	}, nil
}

func writeTicketNumberingJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Cache-Control", "private, no-store")
	writeJSON(w, status, value)
}

func (h *Handler) writeTicketNumberingError(w http.ResponseWriter, r *http.Request, err error) {
	writeTicketNumberingDomainError(w, r, err)
}

func writeTicketNumberingDomainError(w http.ResponseWriter, r *http.Request, err error) {
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case errors.Is(err, ticketnumbering.ErrInvalidInput):
		writeProblem(w, r, http.StatusBadRequest, "invalid_request", "Invalid request", "The ticket numbering request is malformed or fails bounded validation.")
	case errors.Is(err, ticketnumbering.ErrForbidden), errors.Is(err, authentication.ErrForbidden):
		writeProblem(w, r, http.StatusForbidden, "forbidden", "Forbidden", "The action is not permitted.")
	case errors.Is(err, ticketnumbering.ErrNotFound):
		writeProblem(w, r, http.StatusNotFound, "not_found", "Resource not found", "The requested ticket numbering policy does not exist.")
	case errors.Is(err, ticketnumbering.ErrPrecondition):
		writeProblem(w, r, http.StatusPreconditionFailed, "precondition_failed", "Precondition failed", "The numbering policy changed after the supplied entity tag was issued.")
	case errors.Is(err, ticketnumbering.ErrConflict), errors.Is(err, ticketnumbering.ErrNoChange):
		writeProblem(w, r, http.StatusConflict, "conflict", "Conflict", "The numbering policy command conflicts with current protected state or reuses an idempotency key.")
	case errors.Is(err, ticketnumbering.ErrUnavailable):
		w.Header().Set("Retry-After", "5")
		writeProblem(w, r, http.StatusServiceUnavailable, "service_unavailable", "Service unavailable", "A required protected dependency is unavailable.")
	default:
		writeProblem(w, r, http.StatusInternalServerError, "internal_error", "Internal server error", "The request could not be completed.")
	}
}
