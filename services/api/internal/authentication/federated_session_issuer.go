package authentication

import (
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

var _ federatedauth.ApplyCredentialIssuer = (*Service)(nil)

// ReserveApplyCredential allocates browser material before the atomic
// federated apply. The returned reservation owns plaintext until the caller
// either releases it after commit or destroys it on every failure path.
func (s *Service) ReserveApplyCredential(
	request federatedauth.ApplyCredentialRequest,
) (*federatedauth.ApplyCredentialReservation, error) {
	if s == nil || s.tokens == nil || s.newID == nil || s.now == nil ||
		!validFederatedCredentialRequest(request) {
		return nil, ErrUnavailable
	}
	observedAt := s.now().UTC().Truncate(time.Microsecond)
	if observedAt.IsZero() || request.IssuedAt.After(observedAt.Add(time.Second)) ||
		observedAt.After(request.IssuedAt.Add(time.Second)) {
		return nil, ErrUnavailable
	}
	switch request.Disposition {
	case federatedauth.ApplySession:
		var current *Session
		if request.Rotation != nil {
			current = &Session{
				ID: uuid.UUID(request.Rotation.SessionID), RotationFamilyID: uuid.UUID(request.Rotation.FamilyID),
				AbsoluteExpiresAt: request.Rotation.AbsoluteExpiresAt,
			}
		}
		reservation, err := s.reserveMFASessionAt(current, mfa.SessionAuthenticationMethod(request.Method), request.IssuedAt)
		if err != nil {
			return nil, err
		}
		material, ok := reservation.Consume()
		if !ok {
			reservation.Destroy()
			return nil, ErrUnavailable
		}
		defer material.Destroy()
		return federatedauth.NewSessionApplyCredentialReservation(
			reservation.Reservation,
			material.SessionToken,
			material.CSRFToken,
		)
	case federatedauth.ApplyContinuation:
		return s.reserveFederatedContinuation(request.IssuedAt, request.ContinuationAuthority)
	default:
		return nil, ErrInvalidInput
	}
}

func (s *Service) reserveFederatedContinuation(
	issuedAt time.Time,
	authority federatedauth.ContinuationAuthority,
) (*federatedauth.ApplyCredentialReservation, error) {
	continuationID, err := s.newID()
	if err != nil || continuationID == uuid.Nil || continuationID.Version() != 7 {
		return nil, ErrUnavailable
	}
	receipt, err := s.tokens.Opaque()
	if err != nil || !validOpaqueToken(receipt) {
		return nil, ErrUnavailable
	}
	receiptBytes := []byte(receipt)
	defer clear(receiptBytes)
	digest, err := federatedauth.ContinuationReceiptDigest(
		authority,
		identity.EntityID(continuationID),
		receiptBytes,
	)
	if err != nil {
		return nil, ErrUnavailable
	}
	reservation, err := federatedauth.NewPostPrimaryContinuationReservation(
		federatedauth.PostPrimaryContinuationMaterial{
			ContinuationID: identity.EntityID(continuationID), Authority: authority, ReceiptDigest: digest,
			ExpiresAt: issuedAt.Add(s.mfaChallengeTimeout),
		},
		issuedAt,
	)
	if err != nil {
		return nil, ErrUnavailable
	}
	return federatedauth.NewContinuationApplyCredentialReservation(reservation, receiptBytes)
}

func validFederatedCredentialRequest(request federatedauth.ApplyCredentialRequest) bool {
	if request.IssuedAt.IsZero() || request.IssuedAt.Location() != time.UTC ||
		request.IssuedAt.Nanosecond()%int(time.Microsecond) != 0 {
		return false
	}
	switch request.Method {
	case federatedauth.AuthenticationMethodOIDC, federatedauth.AuthenticationMethodSAML,
		federatedauth.AuthenticationMethodPasskey, federatedauth.AuthenticationMethodLDAP:
	default:
		return false
	}
	if request.Disposition == federatedauth.ApplyContinuation {
		if request.Rotation != nil {
			return false
		}
		switch request.ContinuationAuthority {
		case federatedauth.ContinuationAuthorityTenant:
			return true
		case federatedauth.ContinuationAuthorityDirectPlatformOIDC:
			return request.Method == federatedauth.AuthenticationMethodOIDC
		case federatedauth.ContinuationAuthorityDirectPlatformSAML:
			return request.Method == federatedauth.AuthenticationMethodSAML
		default:
			return false
		}
	}
	if request.Disposition != federatedauth.ApplySession {
		return false
	}
	if request.ContinuationAuthority != federatedauth.ContinuationAuthorityTenant {
		return false
	}
	return request.Rotation == nil || uuid.UUID(request.Rotation.SessionID).Version() == 7 &&
		uuid.UUID(request.Rotation.FamilyID).Version() == 7 &&
		request.Rotation.SessionID != request.Rotation.FamilyID &&
		request.Rotation.AbsoluteExpiresAt.After(request.IssuedAt)
}
