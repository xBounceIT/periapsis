package httpserver

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	applicationsla "github.com/periapsis-im/periapsis/services/api/internal/sla"
)

func (h *Handler) slaOperatorReadActor(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
) (applicationsla.Actor, bool) {
	actor, ok := h.tenantAuthorizationActor(w, r)
	if !ok {
		return applicationsla.Actor{}, false
	}
	return h.resolveSLAActor(w, r, actor, tenantID, applicationsla.PrincipalOperator)
}

func (h *Handler) slaCustomerReadActor(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
) (applicationsla.Actor, bool) {
	actor, ok := h.tenantAuthorizationActor(w, r)
	if !ok {
		return applicationsla.Actor{}, false
	}
	return h.resolveSLAActor(w, r, actor, tenantID, applicationsla.PrincipalCustomer)
}

func (h *Handler) slaMutationContext(
	w http.ResponseWriter,
	r *http.Request,
	tenantID uuid.UUID,
) (applicationsla.Actor, applicationsla.MutationEnvelope, bool) {
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return applicationsla.Actor{}, applicationsla.MutationEnvelope{}, false
	}
	resolved, ok := h.resolveSLAActor(w, r, actor, tenantID, applicationsla.PrincipalOperator)
	if !ok {
		return applicationsla.Actor{}, applicationsla.MutationEnvelope{}, false
	}
	key, err := requestIdempotencyKey(r)
	if err != nil {
		writeDomainError(w, r, applicationsla.ErrInvalidInput)
		return applicationsla.Actor{}, applicationsla.MutationEnvelope{}, false
	}
	ipAddress := ""
	if audit.RemoteAddress.IsValid() {
		ipAddress = audit.RemoteAddress.String()
	}
	return resolved, applicationsla.MutationEnvelope{
		IdempotencyKey: key,
		Audit: applicationsla.AuditContext{
			RequestID: audit.RequestID, CorrelationID: audit.CorrelationID,
			IPAddress: ipAddress, UserAgent: audit.UserAgent, AuthMethod: actor.AuthenticationMethod,
		},
	}, true
}

func (h *Handler) resolveSLAActor(
	w http.ResponseWriter,
	r *http.Request,
	actor authorization.Actor,
	tenantID uuid.UUID,
	kind applicationsla.PrincipalKind,
) (applicationsla.Actor, bool) {
	if tenantID == uuid.Nil || actor.ActiveTenantID != tenantID || actor.UserID == uuid.Nil || actor.SessionID == uuid.Nil ||
		(kind != applicationsla.PrincipalOperator && kind != applicationsla.PrincipalCustomer) {
		writeDomainError(w, r, authorization.ErrForbidden)
		return applicationsla.Actor{}, false
	}
	authority, err := h.authorization.GetTenantAuthority(r.Context(), actor, tenantID)
	if err != nil {
		writeDomainError(w, r, err)
		return applicationsla.Actor{}, false
	}
	if authority.TenantID != tenantID || authority.Principal.Kind != authorization.PrincipalKindHuman ||
		authority.Principal.ID != actor.UserID || authority.MembershipID == uuid.Nil ||
		authority.MembershipStatus != authorization.MembershipStatusActive {
		writeDomainError(w, r, authorization.ErrForbidden)
		return applicationsla.Actor{}, false
	}
	return applicationsla.Actor{
		TenantID: tenantID, PrincipalID: actor.UserID, MembershipID: authority.MembershipID,
		SessionID: actor.SessionID, AuthenticationMethod: actor.AuthenticationMethod, Kind: kind,
	}, true
}
