package authentication

import (
	"context"

	"github.com/google/uuid"
)

// DirectPlatformSessionAuthorityLookup identifies a tenantless OIDC, SAML, or LDAP
// session whose authority comes from a platform-owned provider. It deliberately
// has no optional tenant or binding field: tenant-scoped federation uses the
// separate FederatedSessionAuthority port. The bound dispatcher must route the
// exact authentication method to a purpose-specific protocol authority.
type DirectPlatformSessionAuthorityLookup struct {
	SessionID            uuid.UUID
	UserID               uuid.UUID
	AuthenticationMethod string
	Audience             string
}

// DirectPlatformSessionAuthorityResult grants both current authority and an
// idle-expiry touch only after the direct provider provenance has been
// revalidated atomically. A denial remains non-oracular to callers.
type DirectPlatformSessionAuthorityResult struct {
	SessionID      uuid.UUID
	UserID         uuid.UUID
	AllowAuthority bool
	AllowIdleTouch bool
	Transition     *FederatedSessionTransition
}

type DirectPlatformSessionAuthority interface {
	RevalidateDirectPlatformSession(
		context.Context,
		DirectPlatformSessionAuthorityLookup,
	) (DirectPlatformSessionAuthorityResult, error)
}

// BindDirectPlatformSessionAuthority installs the independent direct-provider
// authority dispatcher once. Binding tenant federation does not implicitly
// grant tenantless platform authority, or vice versa.
func (s *Service) BindDirectPlatformSessionAuthority(authority DirectPlatformSessionAuthority) error {
	if s == nil || authority == nil {
		return ErrInvalidInput
	}
	s.directPlatformSessionAuthorityMu.Lock()
	defer s.directPlatformSessionAuthorityMu.Unlock()
	if s.directPlatformSessionAuthority != nil {
		return ErrConflict
	}
	s.directPlatformSessionAuthority = authority
	return nil
}

func (s *Service) revalidateDirectPlatformSession(ctx context.Context, session Session) error {
	if session.ActiveTenantID != nil ||
		(session.AuthenticationMethod != "oidc" && session.AuthenticationMethod != "saml" &&
			session.AuthenticationMethod != "ldap") ||
		!validFederatedSessionUUID(session.ID) || !validFederatedSessionUUID(session.User.ID) {
		return ErrInvalidAuthentication
	}
	s.directPlatformSessionAuthorityMu.RLock()
	authority := s.directPlatformSessionAuthority
	s.directPlatformSessionAuthorityMu.RUnlock()
	if authority == nil {
		return ErrInvalidAuthentication
	}
	lookup := DirectPlatformSessionAuthorityLookup{
		SessionID: session.ID, UserID: session.User.ID,
		AuthenticationMethod: session.AuthenticationMethod, Audience: federatedSessionAudience,
	}
	if !validDirectPlatformSessionAuthorityLookup(lookup) {
		return ErrInvalidAuthentication
	}
	result, err := authority.RevalidateDirectPlatformSession(ctx, lookup)
	if err != nil || result.SessionID != lookup.SessionID || result.UserID != lookup.UserID {
		compensateAndDestroyFederatedSessionTransition(ctx, result.Transition)
		return ErrInvalidAuthentication
	}
	if result.Transition != nil {
		if result.AllowAuthority || result.AllowIdleTouch || !result.Transition.validForDirect(lookup) {
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

func validDirectPlatformSessionAuthorityLookup(value DirectPlatformSessionAuthorityLookup) bool {
	return validFederatedSessionUUID(value.SessionID) && validFederatedSessionUUID(value.UserID) &&
		value.SessionID != value.UserID &&
		(value.AuthenticationMethod == "oidc" || value.AuthenticationMethod == "saml" ||
			value.AuthenticationMethod == "ldap") &&
		value.Audience == federatedSessionAudience
}
