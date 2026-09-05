package authentication

import (
	"context"
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

const federatedSessionTransitionCredentialBytes = 32

// FederatedSessionTransitionKind is a closed request-time browser transition.
// A transition never grants authority to the credential that triggered it.
type FederatedSessionTransitionKind string

const (
	FederatedSessionTransitionRotated FederatedSessionTransitionKind = "rotated"
	FederatedSessionTransitionStepUp  FederatedSessionTransitionKind = "step_up"
)

// FederatedSessionTransitionMaterial transfers ownership of one committed
// successor credential to the HTTP boundary. It must be destroyed after the
// replacement cookie has been constructed.
type FederatedSessionTransitionMaterial struct {
	Kind                  FederatedSessionTransitionKind
	SessionID             uuid.UUID
	ContinuationID        uuid.UUID
	ContinuationAuthority federatedauth.ContinuationAuthority
	ExpiresAt             time.Time
	SessionToken          []byte                                      `json:"-"`
	CSRFToken             []byte                                      `json:"-"`
	Receipt               []byte                                      `json:"-"`
	Delivery              FederatedSessionTransitionDeliveryFinalizer `json:"-"`
}

func (material *FederatedSessionTransitionMaterial) Destroy() {
	if material == nil {
		return
	}
	clear(material.SessionToken)
	clear(material.CSRFToken)
	clear(material.Receipt)
	*material = FederatedSessionTransitionMaterial{}
}

// FederatedSessionTransitionDeliveryFinalizer owns the exact post-commit
// proof needed to confirm browser delivery or compensate only the successor
// created by this transition. Direct-provider transitions require one;
// existing tenant transitions remain compatible until their persistence
// boundary exposes the same delivery protocol.
type FederatedSessionTransitionDeliveryFinalizer interface {
	ConfirmBrowserDelivery() error
	CompensateBrowserDelivery(context.Context) error
}

type federatedSessionTransitionBinding uint8

const (
	federatedSessionTransitionTenant federatedSessionTransitionBinding = iota + 1
	federatedSessionTransitionDirectPlatform
)

func (material FederatedSessionTransitionMaterial) String() string {
	return fmt.Sprintf(
		"authentication.FederatedSessionTransitionMaterial{kind:%q,material:[REDACTED]}",
		material.Kind,
	)
}

func (material FederatedSessionTransitionMaterial) GoString() string { return material.String() }

// FederatedSessionTransition owns plaintext successor material until exactly
// one consumer takes it. The authority lookup is retained only as a
// non-secret confused-deputy binding and is never exposed to HTTP.
type FederatedSessionTransition struct {
	guard                 sync.Mutex
	binding               federatedSessionTransitionBinding
	tenantLookup          FederatedSessionAuthorityLookup
	directLookup          DirectPlatformSessionAuthorityLookup
	kind                  FederatedSessionTransitionKind
	sessionID             uuid.UUID
	continuationID        uuid.UUID
	continuationAuthority federatedauth.ContinuationAuthority
	expiresAt             time.Time
	sessionToken          []byte
	csrfToken             []byte
	receipt               []byte
	delivery              FederatedSessionTransitionDeliveryFinalizer
	consumed              bool
}

// NewFederatedSessionRotationTransition takes a defensive copy of the
// committed replacement credential. The caller retains ownership of its
// input slices and must clear them independently.
func NewFederatedSessionRotationTransition(
	lookup FederatedSessionAuthorityLookup,
	sessionID uuid.UUID,
	expiresAt time.Time,
	sessionToken []byte,
	csrfToken []byte,
) (*FederatedSessionTransition, error) {
	if !validFederatedSessionAuthorityLookup(lookup) || !validFederatedSessionUUID(sessionID) ||
		sessionID == lookup.SessionID || !validFederatedSessionTransitionExpiry(expiresAt) ||
		!validFederatedSessionTransitionCredential(sessionToken) ||
		!validFederatedSessionTransitionCredential(csrfToken) {
		return nil, ErrInvalidInput
	}
	return &FederatedSessionTransition{
		binding: federatedSessionTransitionTenant, tenantLookup: lookup,
		kind: FederatedSessionTransitionRotated, sessionID: sessionID,
		expiresAt: expiresAt, sessionToken: append([]byte(nil), sessionToken...),
		csrfToken: append([]byte(nil), csrfToken...),
	}, nil
}

// NewFederatedSessionStepUpTransition takes a defensive copy of the committed
// continuation receipt. Possession of the UUID alone is never sufficient to
// continue the local MFA ceremony.
func NewFederatedSessionStepUpTransition(
	lookup FederatedSessionAuthorityLookup,
	continuationID uuid.UUID,
	expiresAt time.Time,
	receipt []byte,
) (*FederatedSessionTransition, error) {
	if !validFederatedSessionAuthorityLookup(lookup) || !validFederatedSessionUUID(continuationID) ||
		continuationID == lookup.SessionID || !validFederatedSessionTransitionExpiry(expiresAt) ||
		!validFederatedSessionTransitionCredential(receipt) {
		return nil, ErrInvalidInput
	}
	return &FederatedSessionTransition{
		binding: federatedSessionTransitionTenant, tenantLookup: lookup,
		kind: FederatedSessionTransitionStepUp, continuationID: continuationID,
		continuationAuthority: federatedauth.ContinuationAuthorityTenant,
		expiresAt:             expiresAt, receipt: append([]byte(nil), receipt...),
	}, nil
}

// NewDirectPlatformSessionRotationTransition binds a committed replacement
// session to the exact tenantless protocol lookup. A delivery finalizer is
// mandatory so a failed HTTP handoff can revoke only this successor.
func NewDirectPlatformSessionRotationTransition(
	lookup DirectPlatformSessionAuthorityLookup,
	sessionID uuid.UUID,
	expiresAt time.Time,
	sessionToken []byte,
	csrfToken []byte,
	delivery FederatedSessionTransitionDeliveryFinalizer,
) (*FederatedSessionTransition, error) {
	if !validDirectPlatformSessionAuthorityLookup(lookup) || !validFederatedSessionUUID(sessionID) ||
		sessionID == lookup.SessionID || !validFederatedSessionTransitionExpiry(expiresAt) ||
		!validFederatedSessionTransitionCredential(sessionToken) ||
		!validFederatedSessionTransitionCredential(csrfToken) || federatedSessionTransitionDeliveryIsNil(delivery) {
		return nil, ErrInvalidInput
	}
	return &FederatedSessionTransition{
		binding: federatedSessionTransitionDirectPlatform, directLookup: lookup,
		kind: FederatedSessionTransitionRotated, sessionID: sessionID, expiresAt: expiresAt,
		sessionToken: append([]byte(nil), sessionToken...),
		csrfToken:    append([]byte(nil), csrfToken...), delivery: delivery,
	}, nil
}

// NewDirectPlatformSessionStepUpTransition binds a committed direct-provider
// continuation to its protocol authority. The authority is derived from the
// immutable authentication method rather than accepted from the caller.
func NewDirectPlatformSessionStepUpTransition(
	lookup DirectPlatformSessionAuthorityLookup,
	continuationID uuid.UUID,
	expiresAt time.Time,
	receipt []byte,
	delivery FederatedSessionTransitionDeliveryFinalizer,
) (*FederatedSessionTransition, error) {
	authority, ok := directPlatformContinuationAuthority(lookup.AuthenticationMethod)
	if !validDirectPlatformSessionAuthorityLookup(lookup) || !ok ||
		!validFederatedSessionUUID(continuationID) || continuationID == lookup.SessionID ||
		!validFederatedSessionTransitionExpiry(expiresAt) ||
		!validFederatedSessionTransitionCredential(receipt) || federatedSessionTransitionDeliveryIsNil(delivery) {
		return nil, ErrInvalidInput
	}
	return &FederatedSessionTransition{
		binding: federatedSessionTransitionDirectPlatform, directLookup: lookup,
		kind: FederatedSessionTransitionStepUp, continuationID: continuationID,
		continuationAuthority: authority, expiresAt: expiresAt,
		receipt: append([]byte(nil), receipt...), delivery: delivery,
	}, nil
}

func directPlatformContinuationAuthority(method string) (federatedauth.ContinuationAuthority, bool) {
	switch method {
	case "oidc":
		return federatedauth.ContinuationAuthorityDirectPlatformOIDC, true
	case "saml":
		return federatedauth.ContinuationAuthorityDirectPlatformSAML, true
	default:
		return federatedauth.ContinuationAuthorityTenant, false
	}
}

func (transition *FederatedSessionTransition) validFor(lookup FederatedSessionAuthorityLookup) bool {
	if transition == nil {
		return false
	}
	transition.guard.Lock()
	defer transition.guard.Unlock()
	return !transition.consumed && transition.binding == federatedSessionTransitionTenant &&
		transition.tenantLookup == lookup && transition.validLocked()
}

func (transition *FederatedSessionTransition) validForDirect(lookup DirectPlatformSessionAuthorityLookup) bool {
	if transition == nil {
		return false
	}
	transition.guard.Lock()
	defer transition.guard.Unlock()
	return !transition.consumed && transition.binding == federatedSessionTransitionDirectPlatform &&
		transition.directLookup == lookup && transition.validLocked()
}

func (transition *FederatedSessionTransition) Consume() (FederatedSessionTransitionMaterial, bool) {
	if transition == nil {
		return FederatedSessionTransitionMaterial{}, false
	}
	transition.guard.Lock()
	defer transition.guard.Unlock()
	if transition.consumed || !transition.validLocked() {
		transition.destroyLocked()
		return FederatedSessionTransitionMaterial{}, false
	}
	material := FederatedSessionTransitionMaterial{
		Kind: transition.kind, SessionID: transition.sessionID,
		ContinuationID: transition.continuationID, ExpiresAt: transition.expiresAt,
		ContinuationAuthority: transition.continuationAuthority,
		SessionToken:          transition.sessionToken, CSRFToken: transition.csrfToken,
		Receipt: transition.receipt, Delivery: transition.delivery,
	}
	transition.sessionToken = nil
	transition.csrfToken = nil
	transition.receipt = nil
	transition.delivery = nil
	transition.consumed = true
	return material, true
}

func (transition *FederatedSessionTransition) Destroy() {
	if transition == nil {
		return
	}
	transition.guard.Lock()
	defer transition.guard.Unlock()
	transition.destroyLocked()
}

func (transition *FederatedSessionTransition) String() string {
	if transition == nil {
		return "authentication.FederatedSessionTransition<nil>"
	}
	return "authentication.FederatedSessionTransition{material:[REDACTED]}"
}

func (transition *FederatedSessionTransition) GoString() string { return transition.String() }

func (transition *FederatedSessionTransition) validLocked() bool {
	if !transition.validBindingLocked() || !validFederatedSessionTransitionExpiry(transition.expiresAt) {
		return false
	}
	lookupSessionID := transition.tenantLookup.SessionID
	if transition.binding == federatedSessionTransitionDirectPlatform {
		lookupSessionID = transition.directLookup.SessionID
	}
	switch transition.kind {
	case FederatedSessionTransitionRotated:
		return validFederatedSessionUUID(transition.sessionID) &&
			transition.sessionID != lookupSessionID && transition.continuationID == uuid.Nil &&
			transition.continuationAuthority == federatedauth.ContinuationAuthorityTenant &&
			validFederatedSessionTransitionCredential(transition.sessionToken) &&
			validFederatedSessionTransitionCredential(transition.csrfToken) && len(transition.receipt) == 0 &&
			(transition.binding != federatedSessionTransitionDirectPlatform ||
				!federatedSessionTransitionDeliveryIsNil(transition.delivery))
	case FederatedSessionTransitionStepUp:
		return transition.sessionID == uuid.Nil && validFederatedSessionUUID(transition.continuationID) &&
			transition.continuationID != lookupSessionID && len(transition.sessionToken) == 0 &&
			len(transition.csrfToken) == 0 && validFederatedSessionTransitionCredential(transition.receipt) &&
			transition.validContinuationAuthorityLocked()
	default:
		return false
	}
}

func (transition *FederatedSessionTransition) validBindingLocked() bool {
	switch transition.binding {
	case federatedSessionTransitionTenant:
		return validFederatedSessionAuthorityLookup(transition.tenantLookup) &&
			transition.directLookup == (DirectPlatformSessionAuthorityLookup{}) && transition.delivery == nil
	case federatedSessionTransitionDirectPlatform:
		return transition.tenantLookup == (FederatedSessionAuthorityLookup{}) &&
			validDirectPlatformSessionAuthorityLookup(transition.directLookup) &&
			!federatedSessionTransitionDeliveryIsNil(transition.delivery)
	default:
		return false
	}
}

func (transition *FederatedSessionTransition) validContinuationAuthorityLocked() bool {
	if transition.binding == federatedSessionTransitionTenant {
		return transition.continuationAuthority == federatedauth.ContinuationAuthorityTenant
	}
	authority, ok := directPlatformContinuationAuthority(transition.directLookup.AuthenticationMethod)
	return ok && transition.continuationAuthority == authority
}

func (transition *FederatedSessionTransition) destroyLocked() {
	clear(transition.sessionToken)
	clear(transition.csrfToken)
	clear(transition.receipt)
	transition.binding = 0
	transition.tenantLookup = FederatedSessionAuthorityLookup{}
	transition.directLookup = DirectPlatformSessionAuthorityLookup{}
	transition.kind = ""
	transition.sessionID = uuid.Nil
	transition.continuationID = uuid.Nil
	transition.continuationAuthority = federatedauth.ContinuationAuthorityTenant
	transition.expiresAt = time.Time{}
	transition.sessionToken = nil
	transition.csrfToken = nil
	transition.receipt = nil
	transition.delivery = nil
	transition.consumed = true
}

func compensateAndDestroyFederatedSessionTransition(
	ctx context.Context,
	transition *FederatedSessionTransition,
) {
	if transition == nil {
		return
	}
	transition.guard.Lock()
	delivery := transition.delivery
	transition.guard.Unlock()
	if !federatedSessionTransitionDeliveryIsNil(delivery) {
		_ = delivery.CompensateBrowserDelivery(ctx)
	}
	transition.Destroy()
}

func federatedSessionTransitionDeliveryIsNil(value FederatedSessionTransitionDeliveryFinalizer) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func validFederatedSessionTransitionExpiry(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC
}

func validFederatedSessionTransitionCredential(value []byte) bool {
	if len(value) != base64.RawURLEncoding.EncodedLen(federatedSessionTransitionCredentialBytes) ||
		strings.TrimSpace(string(value)) != string(value) {
		return false
	}
	decoded := make([]byte, federatedSessionTransitionCredentialBytes)
	count, err := base64.RawURLEncoding.Strict().Decode(decoded, value)
	var combined byte
	for _, item := range decoded {
		combined |= item
	}
	valid := err == nil && count == len(decoded) && combined != 0 &&
		base64.RawURLEncoding.EncodeToString(decoded) == string(value)
	clear(decoded)
	return valid
}

// FederatedSessionTransitionError is intentionally non-oracular. Its wrapped
// sentinel remains an authentication failure while trusted HTTP transport can
// consume the one-use replacement material.
type FederatedSessionTransitionError struct {
	transition *FederatedSessionTransition
}

func (err *FederatedSessionTransitionError) Error() string {
	return "federated session transition required"
}
func (err *FederatedSessionTransitionError) Unwrap() error { return ErrInvalidAuthentication }

func (err *FederatedSessionTransitionError) Consume() (FederatedSessionTransitionMaterial, bool) {
	if err == nil {
		return FederatedSessionTransitionMaterial{}, false
	}
	return err.transition.Consume()
}

// NewFederatedSessionTransitionError transfers a valid transition into the
// typed non-authorizing error understood by the trusted HTTP adapter.
func NewFederatedSessionTransitionError(transition *FederatedSessionTransition) error {
	if transition == nil {
		return ErrInvalidAuthentication
	}
	transition.guard.Lock()
	valid := !transition.consumed && transition.validLocked()
	transition.guard.Unlock()
	if !valid {
		transition.Destroy()
		return ErrInvalidAuthentication
	}
	return &FederatedSessionTransitionError{transition: transition}
}
