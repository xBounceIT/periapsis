package authentication

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

// DirectPlatformTenantSwitchRequest transfers digest-only browser material
// to the dedicated atomic switch boundary. Implementations must revalidate
// the source direct provenance and the full target provider/binding/grant
// graph in the same transaction that revokes the source and creates Target.
type DirectPlatformTenantSwitchRequest struct {
	SourceSessionID      uuid.UUID
	RotationFamilyID     uuid.UUID
	AuthenticationMethod string
	SourceTokenDigest    [sha256.Size]byte
	NewSessionID         uuid.UUID
	NewTokenDigest       [sha256.Size]byte
	NewCSRFDigest        [sha256.Size]byte
	UserID               uuid.UUID
	TargetTenantID       uuid.UUID
	OccurredAt           time.Time
	IdleExpiresAt        time.Time
	AbsoluteExpiresAt    time.Time
	Event                EventContext
	AdmissionRules       []RateLimitRule
}

func (request DirectPlatformTenantSwitchRequest) String() string {
	return fmt.Sprintf(
		"authentication.DirectPlatformTenantSwitchRequest{source:%t,family:%t,method:%q,target:%t,user:%t,material:[REDACTED]}",
		request.SourceSessionID != uuid.Nil, request.RotationFamilyID != uuid.Nil,
		request.AuthenticationMethod, request.TargetTenantID != uuid.Nil, request.UserID != uuid.Nil,
	)
}

func (request DirectPlatformTenantSwitchRequest) GoString() string { return request.String() }

type DirectPlatformTenantSwitcher interface {
	SwitchDirectPlatformTenant(
		context.Context,
		DirectPlatformTenantSwitchRequest,
	) (Session, error)
}

func (s *Service) BindDirectPlatformTenantSwitcher(switcher DirectPlatformTenantSwitcher) error {
	if s == nil || switcher == nil {
		return ErrInvalidInput
	}
	s.directPlatformTenantSwitcherMu.Lock()
	defer s.directPlatformTenantSwitcherMu.Unlock()
	if s.directPlatformTenantSwitcher != nil {
		return ErrConflict
	}
	s.directPlatformTenantSwitcher = switcher
	return nil
}

func (s *Service) switchDirectPlatformTenant(
	ctx context.Context,
	sessionToken string,
	source Session,
	targetTenantID uuid.UUID,
	event EventContext,
) (SessionCredential, error) {
	if !directPlatformTenantSwitchAuthenticationMethod(source.AuthenticationMethod) ||
		source.ActiveTenantID != nil ||
		!validFederatedSessionUUID(source.ID) || !validFederatedSessionUUID(source.RotationFamilyID) ||
		!validFederatedSessionUUID(source.User.ID) || !validFederatedSessionUUID(targetTenantID) ||
		len(source.CSRFDigest) != sha256.Size {
		return SessionCredential{}, ErrForbidden
	}
	var sourceCSRFDigest [sha256.Size]byte
	copy(sourceCSRFDigest[:], source.CSRFDigest)
	defer clear(sourceCSRFDigest[:])
	sourceTokenDigest := sha256.Sum256([]byte(sessionToken))
	defer clear(sourceTokenDigest[:])
	if sourceCSRFDigest == ([sha256.Size]byte{}) ||
		subtle.ConstantTimeCompare(sourceTokenDigest[:], sourceCSRFDigest[:]) == 1 {
		return SessionCredential{}, ErrForbidden
	}
	s.directPlatformTenantSwitcherMu.RLock()
	switcher := s.directPlatformTenantSwitcher
	s.directPlatformTenantSwitcherMu.RUnlock()
	if switcher == nil {
		return SessionCredential{}, ErrForbidden
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	if now.IsZero() || source.AbsoluteExpiresAt.Location() != time.UTC ||
		source.AbsoluteExpiresAt.Nanosecond()%int(time.Millisecond) != 0 ||
		!source.AbsoluteExpiresAt.After(now) {
		return SessionCredential{}, ErrForbidden
	}
	reservation, err := s.reserveMFASessionAt(
		&source,
		mfa.SessionAuthenticationMethod(source.AuthenticationMethod),
		now,
	)
	if err != nil {
		return SessionCredential{}, ErrUnavailable
	}
	defer reservation.Destroy()
	reserved := reservation.Reservation
	newTokenDigest := reserved.TokenDigest()
	defer clear(newTokenDigest[:])
	newCSRFDigest := reserved.CSRFDigest()
	defer clear(newCSRFDigest[:])
	if !reserved.ValidAt(now) || uuid.UUID(reserved.SessionID()) == source.ID ||
		uuid.UUID(reserved.SessionID()) == source.RotationFamilyID ||
		uuid.UUID(reserved.FamilyID()) != source.RotationFamilyID ||
		string(reserved.AuthenticationMethod()) != source.AuthenticationMethod ||
		reserved.AbsoluteExpiresAt() != source.AbsoluteExpiresAt ||
		subtle.ConstantTimeCompare(newTokenDigest[:], sourceTokenDigest[:]) == 1 ||
		subtle.ConstantTimeCompare(newTokenDigest[:], sourceCSRFDigest[:]) == 1 ||
		subtle.ConstantTimeCompare(newTokenDigest[:], newCSRFDigest[:]) == 1 ||
		subtle.ConstantTimeCompare(newCSRFDigest[:], sourceTokenDigest[:]) == 1 ||
		subtle.ConstantTimeCompare(newCSRFDigest[:], sourceCSRFDigest[:]) == 1 {
		return SessionCredential{}, ErrUnavailable
	}
	request := DirectPlatformTenantSwitchRequest{
		SourceSessionID: source.ID, RotationFamilyID: source.RotationFamilyID,
		AuthenticationMethod: source.AuthenticationMethod,
		SourceTokenDigest:    sourceTokenDigest, NewSessionID: uuid.UUID(reserved.SessionID()),
		NewTokenDigest: newTokenDigest,
		NewCSRFDigest:  newCSRFDigest,
		UserID:         source.User.ID, TargetTenantID: targetTenantID,
		OccurredAt: now, IdleExpiresAt: reserved.IdleExpiresAt(),
		AbsoluteExpiresAt: reserved.AbsoluteExpiresAt(), Event: event,
		AdmissionRules: []RateLimitRule{{
			Key: s.rateKey(
				rateScopeTenantSwitch,
				"tenant-switch.user",
				source.User.ID.String(),
			),
			Policy: tenantSwitchRatePolicy,
		}},
	}
	defer clearDirectPlatformTenantSwitchRequestMaterial(&request)
	updated, err := switcher.SwitchDirectPlatformTenant(ctx, request)
	if err != nil {
		var rateLimit *RateLimitError
		if errors.As(err, &rateLimit) {
			return SessionCredential{}, rateLimit
		}
		if errors.Is(err, ErrForbidden) || errors.Is(err, ErrNotFound) ||
			errors.Is(err, ErrInvalidAuthentication) {
			return SessionCredential{}, ErrForbidden
		}
		return SessionCredential{}, ErrUnavailable
	}
	updated = cloneDirectPlatformTenantSwitchSession(updated)
	if !validDirectPlatformTenantSwitchResult(updated, request) {
		return SessionCredential{}, ErrUnavailable
	}
	material, ok := reservation.Consume()
	if !ok || !validOpaqueTokenBytes(material.SessionToken) ||
		!validOpaqueTokenBytes(material.CSRFToken) ||
		subtle.ConstantTimeCompare(material.SessionToken, []byte(sessionToken)) == 1 ||
		subtle.ConstantTimeCompare(material.SessionToken, material.CSRFToken) == 1 {
		material.Destroy()
		return SessionCredential{}, ErrUnavailable
	}
	defer material.Destroy()
	return SessionCredential{
		Session: updated, SessionToken: string(material.SessionToken),
		CSRFToken: string(material.CSRFToken),
	}, nil
}

func directPlatformTenantSwitchAuthenticationMethod(method string) bool {
	switch method {
	case "oidc", "saml":
		return true
	default:
		return false
	}
}

func clearDirectPlatformTenantSwitchRequestMaterial(request *DirectPlatformTenantSwitchRequest) {
	if request == nil {
		return
	}
	clear(request.SourceTokenDigest[:])
	clear(request.NewTokenDigest[:])
	clear(request.NewCSRFDigest[:])
}

func validDirectPlatformTenantSwitchResult(
	result Session,
	request DirectPlatformTenantSwitchRequest,
) bool {
	return result.ID == request.NewSessionID && result.RotationFamilyID == request.RotationFamilyID &&
		result.User.ID == request.UserID && result.ActiveTenantID != nil &&
		*result.ActiveTenantID == request.TargetTenantID &&
		result.AuthenticationMethod == request.AuthenticationMethod &&
		result.RevokedAt == nil && result.CreatedAt.Equal(request.OccurredAt) &&
		result.LastSeenAt.Equal(request.OccurredAt) && result.IdleExpiresAt.Equal(request.IdleExpiresAt) &&
		result.AbsoluteExpiresAt.Equal(request.AbsoluteExpiresAt) &&
		len(result.CSRFDigest) == len(request.NewCSRFDigest) &&
		subtle.ConstantTimeCompare(result.CSRFDigest, request.NewCSRFDigest[:]) == 1
}

func cloneDirectPlatformTenantSwitchSession(value Session) Session {
	value.CSRFDigest = append([]byte(nil), value.CSRFDigest...)
	value.Permissions = append([]authorization.Permission(nil), value.Permissions...)
	if value.ActiveTenantID != nil {
		copyValue := *value.ActiveTenantID
		value.ActiveTenantID = &copyValue
	}
	if value.RevokedAt != nil {
		copyValue := *value.RevokedAt
		value.RevokedAt = &copyValue
	}
	if value.User.Email != nil {
		copyValue := *value.User.Email
		value.User.Email = &copyValue
	}
	return value
}
