package authentication

import (
	"context"

	"github.com/google/uuid"
)

const federatedSessionAudience = "api"

// FederatedSessionAuthorityLookup contains only the already-resolved local
// session identity needed to revalidate its normalized provider provenance.
// No browser credential or provider claim crosses this boundary.
type FederatedSessionAuthorityLookup struct {
	SessionID            uuid.UUID
	TenantID             uuid.UUID
	UserID               uuid.UUID
	AuthenticationMethod string
	Audience             string
}

// FederatedSessionAuthorityResult is deliberately narrower than the
// federated policy decision. Authority and idle touch are granted only when
// both flags are true and every identity echoes the exact lookup.
type FederatedSessionAuthorityResult struct {
	SessionID      uuid.UUID
	TenantID       uuid.UUID
	UserID         uuid.UUID
	AllowAuthority bool
	AllowIdleTouch bool
	Transition     *FederatedSessionTransition
}

// FederatedSessionAuthority revalidates the normalized MFA/session provenance
// owned by the federation kernel (OIDC, SAML, and passkey) in its own
// transaction before the authentication service touches idle expiry or
// exposes the resolved session to an authorization boundary.
type FederatedSessionAuthority interface {
	RevalidateFederatedSession(context.Context, FederatedSessionAuthorityLookup) (FederatedSessionAuthorityResult, error)
}

// BindFederatedSessionAuthority installs the production federation boundary
// exactly once during composition. Local sessions do not depend on this
// optional capability; a resolved OIDC, SAML, or passkey session fails closed
// while it is absent.
func (s *Service) BindFederatedSessionAuthority(authority FederatedSessionAuthority) error {
	if s == nil || authority == nil {
		return ErrInvalidInput
	}
	s.federatedSessionAuthorityMu.Lock()
	defer s.federatedSessionAuthorityMu.Unlock()
	if s.federatedSessionAuthority != nil {
		return ErrConflict
	}
	s.federatedSessionAuthority = authority
	return nil
}

func (s *Service) revalidateFederatedSession(ctx context.Context, session Session) error {
	switch session.AuthenticationMethod {
	case "bootstrap_totp", "totp", "recovery_code":
		return nil
	case "oidc", "saml", "ldap":
		if session.ActiveTenantID == nil {
			return s.revalidateDirectPlatformSession(ctx, session)
		}
	case "passkey":
	default:
		return ErrInvalidAuthentication
	}
	if session.ID == uuid.Nil || session.User.ID == uuid.Nil || session.ActiveTenantID == nil ||
		*session.ActiveTenantID == uuid.Nil {
		return ErrInvalidAuthentication
	}
	s.federatedSessionAuthorityMu.RLock()
	authority := s.federatedSessionAuthority
	s.federatedSessionAuthorityMu.RUnlock()
	if authority == nil {
		return ErrInvalidAuthentication
	}
	lookup := FederatedSessionAuthorityLookup{
		SessionID: session.ID, TenantID: *session.ActiveTenantID, UserID: session.User.ID,
		AuthenticationMethod: session.AuthenticationMethod, Audience: federatedSessionAudience,
	}
	if !validFederatedSessionAuthorityLookup(lookup) {
		return ErrInvalidAuthentication
	}
	result, err := authority.RevalidateFederatedSession(ctx, lookup)
	if err != nil || result.SessionID != lookup.SessionID || result.TenantID != lookup.TenantID ||
		result.UserID != lookup.UserID {
		compensateAndDestroyFederatedSessionTransition(ctx, result.Transition)
		// The public outcome is intentionally non-oracular. A provider lifecycle
		// denial, assurance transition, malformed projection, or unavailable
		// revalidation dependency cannot authorize the current credential.
		return ErrInvalidAuthentication
	}
	if result.Transition != nil {
		if result.AllowAuthority || result.AllowIdleTouch || !result.Transition.validFor(lookup) {
			compensateAndDestroyFederatedSessionTransition(ctx, result.Transition)
			return ErrInvalidAuthentication
		}
		return NewFederatedSessionTransitionError(result.Transition)
	}
	if !result.AllowAuthority || !result.AllowIdleTouch {
		return ErrInvalidAuthentication
	}
	return nil
}

func validFederatedSessionAuthorityLookup(value FederatedSessionAuthorityLookup) bool {
	return validFederatedSessionUUID(value.SessionID) && validFederatedSessionUUID(value.TenantID) &&
		validFederatedSessionUUID(value.UserID) &&
		(value.AuthenticationMethod == "oidc" || value.AuthenticationMethod == "saml" ||
			value.AuthenticationMethod == "passkey" || value.AuthenticationMethod == "ldap") &&
		value.Audience == federatedSessionAudience
}

func validFederatedSessionUUID(value uuid.UUID) bool {
	return value != uuid.Nil && value.Version() == 7 && value.Variant() == uuid.RFC4122
}
