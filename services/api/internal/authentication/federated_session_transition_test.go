package authentication

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

type federatedSessionTransitionDeliveryStub struct {
	guard       sync.Mutex
	confirmed   int
	compensated int
	confirmErr  error
}

func (stub *federatedSessionTransitionDeliveryStub) ConfirmBrowserDelivery() error {
	stub.guard.Lock()
	defer stub.guard.Unlock()
	stub.confirmed++
	return stub.confirmErr
}

func (stub *federatedSessionTransitionDeliveryStub) CompensateBrowserDelivery(context.Context) error {
	stub.guard.Lock()
	defer stub.guard.Unlock()
	stub.compensated++
	return nil
}

func (stub *federatedSessionTransitionDeliveryStub) counts() (int, int) {
	stub.guard.Lock()
	defer stub.guard.Unlock()
	return stub.confirmed, stub.compensated
}

func TestFederatedSessionTransitionIsBoundRedactedAndOneUse(t *testing.T) {
	t.Parallel()
	lookup := FederatedSessionAuthorityLookup{
		SessionID: uuid.Must(uuid.NewV7()), TenantID: uuid.Must(uuid.NewV7()),
		UserID: uuid.Must(uuid.NewV7()), AuthenticationMethod: "saml", Audience: "api",
	}
	expiresAt := time.Now().UTC().Add(8 * time.Hour).Truncate(time.Millisecond)
	token := []byte(validTestToken(0x81))
	csrf := []byte(validTestToken(0x82))
	transition, err := NewFederatedSessionRotationTransition(
		lookup, uuid.Must(uuid.NewV7()), expiresAt, token, csrf,
	)
	if err != nil {
		t.Fatalf("NewFederatedSessionRotationTransition() error = %v", err)
	}
	clear(token)
	clear(csrf)
	if !transition.validFor(lookup) {
		t.Fatal("transition lost its exact authority binding")
	}
	wrong := lookup
	wrong.UserID = uuid.Must(uuid.NewV7())
	if transition.validFor(wrong) {
		t.Fatal("transition accepted a different authority lookup")
	}
	if rendered := transition.String(); strings.Contains(rendered, lookup.SessionID.String()) ||
		strings.Contains(rendered, string([]byte(validTestToken(0x81)))) {
		t.Fatalf("transition formatting exposed material: %q", rendered)
	}

	typed := NewFederatedSessionTransitionError(transition)
	if !errors.Is(typed, ErrInvalidAuthentication) {
		t.Fatalf("transition error did not wrap invalid authentication: %v", typed)
	}
	var transitionError *FederatedSessionTransitionError
	if !errors.As(typed, &transitionError) {
		t.Fatalf("transition error type was lost: %T", typed)
	}
	material, consumed := transitionError.Consume()
	if !consumed || material.Kind != FederatedSessionTransitionRotated ||
		material.SessionID == uuid.Nil || !material.ExpiresAt.Equal(expiresAt) ||
		!validFederatedSessionTransitionCredential(material.SessionToken) ||
		!validFederatedSessionTransitionCredential(material.CSRFToken) {
		t.Fatalf("transition material = %s, consumed=%t", material, consumed)
	}
	material.Destroy()
	if _, consumed = transitionError.Consume(); consumed {
		t.Fatal("transition error yielded plaintext twice")
	}
}

func TestFederatedAuthorityReturnsTransitionWithoutTouchAuthority(t *testing.T) {
	t.Parallel()
	lookup := FederatedSessionAuthorityLookup{
		SessionID: uuid.Must(uuid.NewV7()), TenantID: uuid.Must(uuid.NewV7()),
		UserID: uuid.Must(uuid.NewV7()), AuthenticationMethod: "oidc", Audience: "api",
	}
	continuationID := uuid.Must(uuid.NewV7())
	transition, err := NewFederatedSessionStepUpTransition(
		lookup, continuationID, time.Now().UTC().Add(5*time.Minute).Truncate(time.Millisecond),
		[]byte(validTestToken(0x91)),
	)
	if err != nil {
		t.Fatalf("NewFederatedSessionStepUpTransition() error = %v", err)
	}
	service := &Service{}
	if err = service.BindFederatedSessionAuthority(federatedSessionAuthorityFunc(func(
		context.Context,
		FederatedSessionAuthorityLookup,
	) (FederatedSessionAuthorityResult, error) {
		return FederatedSessionAuthorityResult{
			SessionID: lookup.SessionID, TenantID: lookup.TenantID, UserID: lookup.UserID,
			Transition: transition,
		}, nil
	})); err != nil {
		t.Fatalf("BindFederatedSessionAuthority() error = %v", err)
	}
	session := Session{
		ID: lookup.SessionID, User: User{ID: lookup.UserID}, ActiveTenantID: &lookup.TenantID,
		AuthenticationMethod: lookup.AuthenticationMethod,
	}
	err = service.revalidateFederatedSession(context.Background(), session)
	var transitionError *FederatedSessionTransitionError
	if !errors.As(err, &transitionError) || !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("revalidateFederatedSession() error = %T %v", err, err)
	}
	material, consumed := transitionError.Consume()
	if !consumed || material.Kind != FederatedSessionTransitionStepUp ||
		material.ContinuationID != continuationID || !validFederatedSessionTransitionCredential(material.Receipt) {
		t.Fatalf("step-up material = %s, consumed=%t", material, consumed)
	}
	material.Destroy()
}

func TestDirectPlatformSessionTransitionIsProtocolBoundAndPurposeSeparated(t *testing.T) {
	t.Parallel()
	lookup := DirectPlatformSessionAuthorityLookup{
		SessionID: uuid.Must(uuid.NewV7()), UserID: uuid.Must(uuid.NewV7()),
		AuthenticationMethod: "saml", Audience: "api",
	}
	delivery := &federatedSessionTransitionDeliveryStub{}
	continuationID := uuid.Must(uuid.NewV7())
	transition, err := NewDirectPlatformSessionStepUpTransition(
		lookup, continuationID, time.Now().UTC().Add(5*time.Minute).Truncate(time.Millisecond),
		[]byte(validTestToken(0xa1)), delivery,
	)
	if err != nil {
		t.Fatalf("NewDirectPlatformSessionStepUpTransition() error = %v", err)
	}
	if !transition.validForDirect(lookup) || transition.validFor(FederatedSessionAuthorityLookup{}) {
		t.Fatal("direct transition lost its exclusive direct binding")
	}
	wrongProtocol := lookup
	wrongProtocol.AuthenticationMethod = "oidc"
	if transition.validForDirect(wrongProtocol) {
		t.Fatal("SAML transition accepted an OIDC lookup")
	}
	material, consumed := transition.Consume()
	if !consumed || material.ContinuationID != continuationID ||
		material.ContinuationAuthority != federatedauth.ContinuationAuthorityDirectPlatformSAML ||
		material.Delivery != delivery {
		t.Fatalf("direct transition material = %s, consumed=%t", material, consumed)
	}
	material.Destroy()
}

func TestDirectPlatformSessionTransitionRejectsMissingOrTypedNilDelivery(t *testing.T) {
	t.Parallel()
	lookup := DirectPlatformSessionAuthorityLookup{
		SessionID: uuid.Must(uuid.NewV7()), UserID: uuid.Must(uuid.NewV7()),
		AuthenticationMethod: "saml", Audience: "api",
	}
	var typedNil *federatedSessionTransitionDeliveryStub
	for name, delivery := range map[string]FederatedSessionTransitionDeliveryFinalizer{
		"nil": nil, "typed nil": typedNil,
	} {
		t.Run(name, func(t *testing.T) {
			transition, err := NewDirectPlatformSessionRotationTransition(
				lookup, uuid.Must(uuid.NewV7()), time.Now().UTC().Add(time.Hour).Truncate(time.Millisecond),
				[]byte(validTestToken(0xa2)), []byte(validTestToken(0xa3)), delivery,
			)
			if !errors.Is(err, ErrInvalidInput) || transition != nil {
				t.Fatalf("constructor = %v, %v", transition, err)
			}
		})
	}
}
