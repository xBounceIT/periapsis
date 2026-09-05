package httpserver

import (
	"context"
	"encoding/base64"
	"errors"
	"math"
	"net/http"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

const (
	federatedContinuationCookieVersionV1 byte = 1
	federatedContinuationCookieVersionV2 byte = 2
	federatedContinuationCookieV1Bytes        = 1 + 16 + federatedStartReceiptBytes
	federatedContinuationCookieV2Bytes        = 1 + 1 + 16 + federatedStartReceiptBytes
	sessionTransitionHeader                   = "X-Periapsis-Session-Transition"
)

type federatedContinuationFamily byte

const (
	federatedContinuationTenant federatedContinuationFamily = iota + 1
	federatedContinuationDirectPlatformOIDC
	federatedContinuationDirectPlatformSAML
)

type federatedContinuationCapability struct {
	authority      federatedauth.ContinuationAuthority
	continuationID uuid.UUID
	receipt        []byte
}

func (capability federatedContinuationCapability) receiptDigest() ([32]byte, error) {
	return federatedauth.ContinuationReceiptDigest(
		capability.authority,
		identity.EntityID(capability.continuationID),
		capability.receipt,
	)
}

func (capability *federatedContinuationCapability) destroy() {
	if capability == nil {
		return
	}
	clear(capability.receipt)
	*capability = federatedContinuationCapability{}
}

type federatedSessionCookiePolicies struct {
	session      sessionCookiePolicy
	mfa          sessionCookiePolicy
	continuation sessionCookiePolicy
}

type federatedSessionCookiePoliciesKey struct{}

func federatedSessionCookiePolicyMiddleware(
	session sessionCookiePolicy,
	mfa sessionCookiePolicy,
	continuation sessionCookiePolicy,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		policies := federatedSessionCookiePolicies{session: session, mfa: mfa, continuation: continuation}
		ctx := context.WithValue(r.Context(), federatedSessionCookiePoliciesKey{}, policies)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func writeFederatedSessionTransition(w http.ResponseWriter, r *http.Request, err error) bool {
	var transitionError *authentication.FederatedSessionTransitionError
	if !errors.As(err, &transitionError) {
		return false
	}
	material, consumed := transitionError.Consume()
	if !consumed {
		writeProblem(
			w, r, http.StatusServiceUnavailable, "service_unavailable", "Service unavailable",
			"The session transition could not be completed.",
		)
		return true
	}
	defer material.Destroy()
	deliveryFinalized := false
	defer func() {
		if !deliveryFinalized && !interfaceIsNil(material.Delivery) {
			_ = material.Delivery.CompensateBrowserDelivery(r.Context())
		}
	}()

	policies, configured := r.Context().Value(federatedSessionCookiePoliciesKey{}).(federatedSessionCookiePolicies)
	if !configured || !validSessionTransportCookiePolicy(policies.session) ||
		!validMFATransportCookiePolicy(policies.mfa) ||
		!validFederatedContinuationTransportCookiePolicy(policies.continuation) {
		writeProblem(
			w, r, http.StatusServiceUnavailable, "service_unavailable", "Service unavailable",
			"The session transition could not be completed.",
		)
		return true
	}
	now := time.Now().UTC()
	if !material.ExpiresAt.After(now) {
		clearCookieWithPolicy(w, policies.session)
		clearCookieWithPolicy(w, policies.mfa)
		clearCookieWithPolicy(w, policies.continuation)
		writeProblem(
			w, r, http.StatusUnauthorized, "authentication_failed", "Authentication failed",
			"Authentication could not be completed.",
		)
		return true
	}

	switch material.Kind {
	case authentication.FederatedSessionTransitionRotated:
		if !validFederatedEntityID(identity.EntityID(material.SessionID)) || material.ContinuationID != uuid.Nil ||
			!validMFABrowserHandle(string(material.SessionToken)) ||
			!validMFABrowserHandle(string(material.CSRFToken)) || len(material.Receipt) != 0 ||
			setCookieWithPolicy(w, policies.session, string(material.SessionToken), material.ExpiresAt, now) != nil {
			clearCookieWithPolicy(w, policies.session)
			clearCookieWithPolicy(w, policies.mfa)
			clearCookieWithPolicy(w, policies.continuation)
			writeProblem(
				w, r, http.StatusServiceUnavailable, "service_unavailable", "Service unavailable",
				"The session transition could not be completed.",
			)
			return true
		}
		clearCookieWithPolicy(w, policies.mfa)
		clearCookieWithPolicy(w, policies.continuation)
		w.Header().Set(sessionTransitionHeader, string(authentication.FederatedSessionTransitionRotated))
		writeProblem(
			w, r, http.StatusUnauthorized, "session_rotated", "Session rotated",
			"The session credential was rotated. Refresh the current session before retrying the action.",
		)
		deliveryFinalized = confirmFederatedSessionTransitionDelivery(material.Delivery, r.Context())
		return true
	case authentication.FederatedSessionTransitionStepUp:
		if material.SessionID != uuid.Nil ||
			!validFederatedEntityID(identity.EntityID(material.ContinuationID)) ||
			len(material.SessionToken) != 0 || len(material.CSRFToken) != 0 ||
			setFederatedContinuationCookieForAuthorityWithPolicy(
				w, policies.continuation, material.ContinuationAuthority,
				material.ContinuationID, material.Receipt, material.ExpiresAt, now,
			) != nil {
			clearCookieWithPolicy(w, policies.session)
			clearCookieWithPolicy(w, policies.mfa)
			clearCookieWithPolicy(w, policies.continuation)
			writeProblem(
				w, r, http.StatusServiceUnavailable, "service_unavailable", "Service unavailable",
				"The session transition could not be completed.",
			)
			return true
		}
		clearCookieWithPolicy(w, policies.session)
		clearCookieWithPolicy(w, policies.mfa)
		w.Header().Set(sessionTransitionHeader, string(authentication.FederatedSessionTransitionStepUp))
		w.Header().Set("Location", federatedContinuationPath)
		writeProblem(
			w, r, http.StatusUnauthorized, "mfa_step_up_required", "Additional authentication required",
			"Complete local multi-factor authentication to continue.",
		)
		deliveryFinalized = confirmFederatedSessionTransitionDelivery(material.Delivery, r.Context())
		return true
	default:
		clearCookieWithPolicy(w, policies.session)
		clearCookieWithPolicy(w, policies.mfa)
		clearCookieWithPolicy(w, policies.continuation)
		writeProblem(
			w, r, http.StatusServiceUnavailable, "service_unavailable", "Service unavailable",
			"The session transition could not be completed.",
		)
		return true
	}
}

func confirmFederatedSessionTransitionDelivery(
	delivery authentication.FederatedSessionTransitionDeliveryFinalizer,
	ctx context.Context,
) bool {
	if interfaceIsNil(delivery) {
		return true
	}
	if err := delivery.ConfirmBrowserDelivery(); err != nil {
		_ = delivery.CompensateBrowserDelivery(ctx)
		return false
	}
	return true
}

func setFederatedContinuationCookieWithPolicy(
	w http.ResponseWriter,
	policy sessionCookiePolicy,
	continuationID uuid.UUID,
	receipt []byte,
	expiresAt time.Time,
	now time.Time,
) error {
	return setFederatedContinuationCookieV1WithPolicy(
		w, policy, continuationID, receipt, expiresAt, now,
	)
}

func setFederatedContinuationCookieForAuthorityWithPolicy(
	w http.ResponseWriter,
	policy sessionCookiePolicy,
	authority federatedauth.ContinuationAuthority,
	continuationID uuid.UUID,
	receipt []byte,
	expiresAt time.Time,
	now time.Time,
) error {
	switch authority {
	case federatedauth.ContinuationAuthorityTenant:
		return setFederatedContinuationCookieV1WithPolicy(
			w, policy, continuationID, receipt, expiresAt, now,
		)
	case federatedauth.ContinuationAuthorityDirectPlatformOIDC:
		return setFederatedContinuationCookieForFamilyWithPolicy(
			w, policy, federatedContinuationDirectPlatformOIDC,
			continuationID, receipt, expiresAt, now,
		)
	case federatedauth.ContinuationAuthorityDirectPlatformSAML:
		return setFederatedContinuationCookieForFamilyWithPolicy(
			w, policy, federatedContinuationDirectPlatformSAML,
			continuationID, receipt, expiresAt, now,
		)
	default:
		return authentication.ErrUnavailable
	}
}

func setFederatedContinuationCookieForFamilyWithPolicy(
	w http.ResponseWriter,
	policy sessionCookiePolicy,
	family federatedContinuationFamily,
	continuationID uuid.UUID,
	receipt []byte,
	expiresAt time.Time,
	now time.Time,
) error {
	if family != federatedContinuationDirectPlatformOIDC &&
		family != federatedContinuationDirectPlatformSAML {
		return authentication.ErrUnavailable
	}
	return setFederatedContinuationCookiePayloadWithPolicy(
		w, policy, federatedContinuationCookieVersionV2, family,
		continuationID, receipt, expiresAt, now,
	)
}

func setFederatedContinuationCookieV1WithPolicy(
	w http.ResponseWriter,
	policy sessionCookiePolicy,
	continuationID uuid.UUID,
	receipt []byte,
	expiresAt time.Time,
	now time.Time,
) error {
	return setFederatedContinuationCookiePayloadWithPolicy(
		w, policy, federatedContinuationCookieVersionV1, 0,
		continuationID, receipt, expiresAt, now,
	)
}

func setFederatedContinuationCookiePayloadWithPolicy(
	w http.ResponseWriter,
	policy sessionCookiePolicy,
	version byte,
	family federatedContinuationFamily,
	continuationID uuid.UUID,
	receipt []byte,
	expiresAt time.Time,
	now time.Time,
) error {
	if !validFederatedContinuationTransportCookiePolicy(policy) ||
		!validFederatedEntityID(identity.EntityID(continuationID)) ||
		!validMFABrowserHandle(string(receipt)) || !validFederatedExpiry(expiresAt, now) ||
		(version != federatedContinuationCookieVersionV1 || family != 0) &&
			(version != federatedContinuationCookieVersionV2 ||
				family != federatedContinuationDirectPlatformOIDC &&
					family != federatedContinuationDirectPlatformSAML) {
		return authentication.ErrUnavailable
	}
	rawReceipt := make([]byte, federatedStartReceiptBytes)
	count, err := base64.RawURLEncoding.Strict().Decode(rawReceipt, receipt)
	if err != nil || count != len(rawReceipt) {
		clear(rawReceipt)
		return authentication.ErrUnavailable
	}
	defer clear(rawReceipt)
	payloadBytes := federatedContinuationCookieV1Bytes
	idOffset := 1
	if version == federatedContinuationCookieVersionV2 {
		payloadBytes = federatedContinuationCookieV2Bytes
		idOffset = 2
	}
	payload := make([]byte, payloadBytes)
	defer clear(payload)
	payload[0] = version
	if version == federatedContinuationCookieVersionV2 {
		payload[1] = byte(family)
	}
	copy(payload[idOffset:idOffset+16], continuationID[:])
	copy(payload[idOffset+16:], rawReceipt)
	value := base64.RawURLEncoding.EncodeToString(payload)
	maxAge := int(math.Ceil(expiresAt.Sub(now).Seconds()))
	if maxAge < 1 {
		return authentication.ErrUnavailable
	}
	http.SetCookie(w, &http.Cookie{
		Name: policy.name, Value: value, Path: "/", Expires: expiresAt,
		MaxAge: maxAge, HttpOnly: true, Secure: policy.secure, SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func federatedContinuationCookie(
	r *http.Request,
	policy sessionCookiePolicy,
) (uuid.UUID, []byte, error) {
	capability, err := federatedContinuationCapabilityCookie(r, policy)
	if err != nil || capability.authority != federatedauth.ContinuationAuthorityTenant {
		capability.destroy()
		return uuid.Nil, nil, authentication.ErrInvalidAuthentication
	}
	return capability.continuationID, capability.receipt, nil
}

func federatedContinuationCapabilityCookie(
	r *http.Request,
	policy sessionCookiePolicy,
) (federatedContinuationCapability, error) {
	if r == nil || !validFederatedContinuationTransportCookiePolicy(policy) {
		return federatedContinuationCapability{}, authentication.ErrInvalidAuthentication
	}
	value := ""
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == policy.name {
			count++
			value = cookie.Value
		}
	}
	if count != 1 || len(value) != base64.RawURLEncoding.EncodedLen(federatedContinuationCookieV1Bytes) &&
		len(value) != base64.RawURLEncoding.EncodedLen(federatedContinuationCookieV2Bytes) {
		return federatedContinuationCapability{}, authentication.ErrInvalidAuthentication
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != value {
		clear(payload)
		return federatedContinuationCapability{}, authentication.ErrInvalidAuthentication
	}
	defer clear(payload)
	authority := federatedauth.ContinuationAuthorityTenant
	idOffset := 1
	switch {
	case len(payload) == federatedContinuationCookieV1Bytes &&
		payload[0] == federatedContinuationCookieVersionV1:
	case len(payload) == federatedContinuationCookieV2Bytes &&
		payload[0] == federatedContinuationCookieVersionV2:
		family := federatedContinuationFamily(payload[1])
		idOffset = 2
		switch family {
		case federatedContinuationDirectPlatformOIDC:
			authority = federatedauth.ContinuationAuthorityDirectPlatformOIDC
		case federatedContinuationDirectPlatformSAML:
			authority = federatedauth.ContinuationAuthorityDirectPlatformSAML
		default:
			return federatedContinuationCapability{}, authentication.ErrInvalidAuthentication
		}
	default:
		return federatedContinuationCapability{}, authentication.ErrInvalidAuthentication
	}
	continuationID, err := uuid.FromBytes(payload[idOffset : idOffset+16])
	if err != nil || !validFederatedEntityID(identity.EntityID(continuationID)) {
		return federatedContinuationCapability{}, authentication.ErrInvalidAuthentication
	}
	receipt := []byte(base64.RawURLEncoding.EncodeToString(payload[idOffset+16:]))
	if !validMFABrowserHandle(string(receipt)) {
		clear(receipt)
		return federatedContinuationCapability{}, authentication.ErrInvalidAuthentication
	}
	return federatedContinuationCapability{
		authority: authority, continuationID: continuationID, receipt: receipt,
	}, nil
}

func setCookieWithPolicy(
	w http.ResponseWriter,
	policy sessionCookiePolicy,
	value string,
	expiresAt time.Time,
	now time.Time,
) error {
	if !validSessionTransportCookiePolicy(policy) || !validMFABrowserHandle(value) ||
		expiresAt.IsZero() || expiresAt.Location() != time.UTC || !expiresAt.After(now) {
		return authentication.ErrUnavailable
	}
	maxAge := int(math.Ceil(expiresAt.Sub(now).Seconds()))
	if maxAge < 1 {
		return authentication.ErrUnavailable
	}
	http.SetCookie(w, &http.Cookie{
		Name: policy.name, Value: value, Path: "/", Expires: expiresAt,
		MaxAge: maxAge, HttpOnly: true, Secure: policy.secure, SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func clearCookieWithPolicy(w http.ResponseWriter, policy sessionCookiePolicy) {
	if policy.name == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: policy.name, Value: "", Path: "/", Expires: time.Unix(1, 0).UTC(),
		MaxAge: -1, HttpOnly: true, Secure: policy.secure, SameSite: http.SameSiteStrictMode,
	})
}

func validSessionTransportCookiePolicy(policy sessionCookiePolicy) bool {
	return policy == (sessionCookiePolicy{name: productionCookie, secure: true}) ||
		policy == (sessionCookiePolicy{name: developmentCookie, secure: false})
}

func validMFATransportCookiePolicy(policy sessionCookiePolicy) bool {
	return policy == (sessionCookiePolicy{name: productionMFACookie, secure: true}) ||
		policy == (sessionCookiePolicy{name: developmentMFACookie, secure: false})
}

func validFederatedContinuationTransportCookiePolicy(policy sessionCookiePolicy) bool {
	return policy == (sessionCookiePolicy{name: productionFederatedContinuationCookie, secure: true}) ||
		policy == (sessionCookiePolicy{name: developmentFederatedContinuationCookie, secure: false})
}
