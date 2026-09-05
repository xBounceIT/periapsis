package authentication

import (
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

var _ platformsamlauth.CredentialIssuer = (*Service)(nil)

// ReserveDirectSAMLCredential adapts the single authentication-owned browser
// credential issuer to the purpose-specific direct-platform SAML reservation.
// The generic reservation is consumed exactly once and never crosses the SAML
// apply boundary, while the continuation keeps its SAML authority, factor, and
// exact factor revision.
func (s *Service) ReserveDirectSAMLCredential(
	request platformsamlauth.CredentialRequest,
) (*platformsamlauth.CredentialReservation, error) {
	var totp platformsamlauth.TOTPSelection
	mapped := federatedauth.ApplyCredentialRequest{
		Method:   federatedauth.AuthenticationMethodSAML,
		IssuedAt: request.IssuedAt,
	}
	switch request.Disposition {
	case platformsamlauth.ImmediateSession:
		if request.TOTP != nil {
			return nil, ErrInvalidInput
		}
		mapped.Disposition = federatedauth.ApplySession
		if request.Rotation != nil {
			mapped.Rotation = &federatedauth.SessionRotationAnchor{
				SessionID: request.Rotation.SessionID, FamilyID: request.Rotation.FamilyID,
				AbsoluteExpiresAt: request.Rotation.AbsoluteExpiresAt,
			}
		}
	case platformsamlauth.TOTPContinuation:
		if request.TOTP == nil || request.Rotation != nil {
			return nil, ErrInvalidInput
		}
		totp = *request.TOTP
		mapped.Disposition = federatedauth.ApplyContinuation
		mapped.ContinuationAuthority = federatedauth.ContinuationAuthorityDirectPlatformSAML
	default:
		return nil, ErrInvalidInput
	}

	reserved, err := s.ReserveApplyCredential(mapped)
	if err != nil || reserved == nil {
		return nil, ErrUnavailable
	}
	defer reserved.Destroy()

	if mapped.Disposition == federatedauth.ApplySession {
		return directSAMLSessionCredential(reserved)
	}
	return directSAMLContinuationCredential(reserved, request.IssuedAt, totp)
}

func directSAMLSessionCredential(
	reserved *federatedauth.ApplyCredentialReservation,
) (*platformsamlauth.CredentialReservation, error) {
	session := reserved.Session()
	if session.IsZero() || !reserved.Continuation().IsZero() {
		return nil, ErrUnavailable
	}
	browser, released := reserved.ReleaseBrowserCredential(session.SessionID(), identity.EntityID{})
	if !released || browser == nil {
		if browser != nil {
			browser.Destroy()
		}
		return nil, ErrUnavailable
	}
	defer browser.Destroy()
	material, consumed := browser.Consume()
	if !consumed {
		return nil, ErrUnavailable
	}
	defer material.Destroy()
	if material.Kind != federatedauth.BrowserCredentialSession ||
		material.SessionID != session.SessionID() ||
		material.ContinuationID != (identity.EntityID{}) ||
		material.Authority != federatedauth.ContinuationAuthorityTenant ||
		!material.ExpiresAt.IsZero() || len(material.Receipt) != 0 {
		return nil, ErrUnavailable
	}
	credential, err := platformsamlauth.NewSessionCredentialReservation(
		session,
		material.SessionToken,
		material.CSRFToken,
	)
	if err != nil {
		return nil, ErrUnavailable
	}
	return credential, nil
}

func directSAMLContinuationCredential(
	reserved *federatedauth.ApplyCredentialReservation,
	issuedAt time.Time,
	totp platformsamlauth.TOTPSelection,
) (*platformsamlauth.CredentialReservation, error) {
	continuation := reserved.Continuation()
	if !reserved.Session().IsZero() || continuation.IsZero() ||
		continuation.Authority() != federatedauth.ContinuationAuthorityDirectPlatformSAML {
		return nil, ErrUnavailable
	}
	browser, released := reserved.ReleaseBrowserCredential(identity.EntityID{}, continuation.ContinuationID())
	if !released || browser == nil {
		if browser != nil {
			browser.Destroy()
		}
		return nil, ErrUnavailable
	}
	defer browser.Destroy()
	material, consumed := browser.Consume()
	if !consumed {
		return nil, ErrUnavailable
	}
	defer material.Destroy()
	if material.Kind != federatedauth.BrowserCredentialContinuation ||
		material.SessionID != (identity.EntityID{}) ||
		material.ContinuationID != continuation.ContinuationID() ||
		material.Authority != federatedauth.ContinuationAuthorityDirectPlatformSAML ||
		!material.ExpiresAt.Equal(continuation.ExpiresAt()) ||
		len(material.SessionToken) != 0 || len(material.CSRFToken) != 0 {
		return nil, ErrUnavailable
	}
	samlContinuation, err := platformsamlauth.NewContinuationReservation(
		platformsamlauth.ContinuationMaterial{
			ContinuationID: continuation.ContinuationID(),
			FactorID:       totp.FactorID,
			FactorRevision: totp.Revision,
			ReceiptDigest:  continuation.ReceiptDigest(),
			ExpiresAt:      continuation.ExpiresAt(),
		},
		issuedAt,
	)
	if err != nil {
		return nil, ErrUnavailable
	}
	credential, err := platformsamlauth.NewContinuationCredentialReservation(
		samlContinuation,
		material.Receipt,
	)
	if err != nil {
		return nil, ErrUnavailable
	}
	return credential, nil
}
