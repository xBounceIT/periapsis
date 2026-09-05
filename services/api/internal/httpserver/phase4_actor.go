package httpserver

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	applicationcustomfields "github.com/periapsis-im/periapsis/services/api/internal/customfields"
	applicationdfir "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

type phase4Actor struct {
	custom applicationcustomfields.Actor
	dfir   applicationdfir.Actor
}

func (h *Handler) phase4ReadActor(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID) (phase4Actor, bool) {
	actor, ok := h.tenantAuthorizationActor(w, r)
	if !ok {
		return phase4Actor{}, false
	}
	return h.resolvePhase4Actor(w, r, actor, authorization.AuditContext{}, tenantID)
}

func (h *Handler) phase4MutationActor(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID) (phase4Actor, applicationcustomfields.AuditContext, applicationdfir.AuditContext, bool) {
	actor, audit, ok := h.prepareTenantAuthorizationMutation(w, r)
	if !ok {
		return phase4Actor{}, applicationcustomfields.AuditContext{}, applicationdfir.AuditContext{}, false
	}
	resolved, ok := h.resolvePhase4Actor(w, r, actor, audit, tenantID)
	if !ok {
		return phase4Actor{}, applicationcustomfields.AuditContext{}, applicationdfir.AuditContext{}, false
	}
	customAudit := applicationcustomfields.AuditContext{
		RequestID: audit.RequestID, CorrelationID: audit.CorrelationID,
		IPAddress: audit.RemoteAddress, UserAgent: audit.UserAgent,
		AuthenticationMethod: actor.AuthenticationMethod,
	}
	dfirAudit := applicationdfir.AuditContext{
		RequestID: audit.RequestID, CorrelationID: audit.CorrelationID,
		IPAddress: audit.RemoteAddress, UserAgent: audit.UserAgent,
		AuthenticationMethod: actor.AuthenticationMethod,
	}
	resolved.custom.Audit = customAudit
	return resolved, customAudit, dfirAudit, true
}

func (h *Handler) resolvePhase4Actor(w http.ResponseWriter, r *http.Request, actor authorization.Actor, _ authorization.AuditContext, tenantID uuid.UUID) (phase4Actor, bool) {
	if tenantID == uuid.Nil || actor.ActiveTenantID != tenantID || actor.UserID == uuid.Nil || actor.SessionID == uuid.Nil {
		writeDomainError(w, r, authorization.ErrForbidden)
		return phase4Actor{}, false
	}
	authority, err := h.authorization.GetTenantAuthority(r.Context(), actor, tenantID)
	if err != nil {
		writeDomainError(w, r, err)
		return phase4Actor{}, false
	}
	if authority.TenantID != tenantID || authority.Principal.Kind != authorization.PrincipalKindHuman ||
		authority.Principal.ID != actor.UserID || authority.MembershipID == uuid.Nil ||
		authority.MembershipStatus != authorization.MembershipStatusActive {
		writeDomainError(w, r, authorization.ErrForbidden)
		return phase4Actor{}, false
	}
	// These handlers are mounted only on the tenant operator surface. The
	// compatibility role is mutable legacy metadata and is not an audience
	// boundary: custom/JIT roles and read-only operators must keep the route's
	// explicit operator intent. A future customer projection must use a
	// separately mounted portal route and prove the linked-contact relationship.
	kindCustom, kindDFIR := applicationcustomfields.PrincipalHuman, applicationdfir.PrincipalHuman
	return phase4Actor{
		custom: applicationcustomfields.Actor{
			TenantID: tenantID, UserID: actor.UserID, SessionID: actor.SessionID,
			ActiveTenantID: actor.ActiveTenantID, MembershipID: authority.MembershipID,
			AuthenticationMethod: actor.AuthenticationMethod, Kind: kindCustom,
		},
		dfir: applicationdfir.Actor{
			TenantID: tenantID, UserID: actor.UserID, SessionID: actor.SessionID,
			ActiveTenantID: actor.ActiveTenantID, MembershipID: authority.MembershipID,
			AuthenticationMethod: actor.AuthenticationMethod, Kind: kindDFIR,
		},
	}, true
}
