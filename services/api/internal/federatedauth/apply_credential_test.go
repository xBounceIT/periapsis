package federatedauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

type applyCredentialIssuerFunc func(ApplyCredentialRequest) (*ApplyCredentialReservation, error)

func (function applyCredentialIssuerFunc) ReserveApplyCredential(
	request ApplyCredentialRequest,
) (*ApplyCredentialReservation, error) {
	return function(request)
}

func testApplyCredentialIssuer() ApplyCredentialIssuer {
	var guard sync.Mutex
	sequence := byte(180)
	return applyCredentialIssuerFunc(func(request ApplyCredentialRequest) (*ApplyCredentialReservation, error) {
		guard.Lock()
		sequence += 3
		current := sequence
		guard.Unlock()
		switch request.Disposition {
		case ApplySession:
			token := testOpaqueCredential(current)
			csrf := testOpaqueCredential(current + 1)
			familyID := serviceID(current + 1)
			absoluteExpiresAt := request.IssuedAt.Add(8 * time.Hour).Truncate(time.Millisecond)
			if request.Rotation != nil {
				familyID = request.Rotation.FamilyID
				absoluteExpiresAt = request.Rotation.AbsoluteExpiresAt
			}
			reservation, err := mfa.NewSessionReservation(mfa.SessionMaterial{
				SessionID: serviceID(current), FamilyID: familyID,
				TokenDigest: sha256.Sum256(token), CSRFDigest: sha256.Sum256(csrf),
				AuthenticationMethod: mfa.SessionAuthenticationMethod(request.Method),
				IdleExpiresAt:        request.IssuedAt.Add(time.Hour).Truncate(time.Millisecond),
				AbsoluteExpiresAt:    absoluteExpiresAt,
			}, request.IssuedAt.Truncate(time.Millisecond))
			if err != nil {
				return nil, err
			}
			return NewSessionApplyCredentialReservation(reservation, token, csrf)
		case ApplyContinuation:
			receipt := testOpaqueCredential(current)
			continuationID := serviceID(current)
			digest, err := ContinuationReceiptDigest(
				request.ContinuationAuthority, continuationID, receipt,
			)
			if err != nil {
				return nil, err
			}
			reservation, err := NewPostPrimaryContinuationReservation(PostPrimaryContinuationMaterial{
				ContinuationID: continuationID, Authority: request.ContinuationAuthority, ReceiptDigest: digest,
				ExpiresAt: request.IssuedAt.Add(5 * time.Minute),
			}, request.IssuedAt)
			if err != nil {
				return nil, err
			}
			return NewContinuationApplyCredentialReservation(reservation, receipt)
		default:
			return nil, ErrInvalidInput
		}
	})
}

func TestContinuationReceiptDigestBindsDirectAuthorityAndIdentifier(t *testing.T) {
	receipt := testOpaqueCredential(77)
	continuationID := serviceID(77)
	tenantDigest, err := ContinuationReceiptDigest(
		ContinuationAuthorityTenant, continuationID, receipt,
	)
	if err != nil || tenantDigest != sha256.Sum256(receipt) {
		t.Fatalf("tenant digest = %x, %v", tenantDigest, err)
	}
	directDigest, err := ContinuationReceiptDigest(
		ContinuationAuthorityDirectPlatformOIDC, continuationID, receipt,
	)
	if err != nil || directDigest == tenantDigest {
		t.Fatalf("direct digest = %x, %v", directDigest, err)
	}
	otherDigest, err := ContinuationReceiptDigest(
		ContinuationAuthorityDirectPlatformOIDC, serviceID(78), receipt,
	)
	if err != nil || otherDigest == directDigest {
		t.Fatalf("other identifier digest = %x, %v", otherDigest, err)
	}
	samlDigest, err := ContinuationReceiptDigest(
		ContinuationAuthorityDirectPlatformSAML, continuationID, receipt,
	)
	if err != nil || samlDigest == tenantDigest || samlDigest == directDigest {
		t.Fatalf("SAML digest = %x, %v", samlDigest, err)
	}
	wantSAML := sha256.New()
	_, _ = wantSAML.Write([]byte("periapsis/platform-saml/continuation-receipt/v1"))
	_, _ = wantSAML.Write([]byte{0})
	_, _ = wantSAML.Write(continuationID[:])
	_, _ = wantSAML.Write([]byte{0})
	_, _ = wantSAML.Write(receipt)
	if !bytes.Equal(samlDigest[:], wantSAML.Sum(nil)) {
		t.Fatal("SAML HTTP authority digest diverged from platformsamlauth continuation ABI")
	}
	for name, authority := range map[string]ContinuationAuthority{
		"unknown": "unknown",
	} {
		t.Run(name, func(t *testing.T) {
			if digest, digestErr := ContinuationReceiptDigest(authority, continuationID, receipt); digestErr == nil || digest != ([sha256.Size]byte{}) {
				t.Fatalf("invalid authority digest = %x, %v", digest, digestErr)
			}
		})
	}
}

func TestDirectContinuationReservationCannotBeRelabeled(t *testing.T) {
	issuer := testApplyCredentialIssuer()
	request := ApplyCredentialRequest{
		Disposition: ApplyContinuation, Method: AuthenticationMethodOIDC,
		ContinuationAuthority: ContinuationAuthorityDirectPlatformOIDC,
		IssuedAt:              serviceTestNow,
	}
	reservation, err := issuer.ReserveApplyCredential(request)
	if err != nil || reservation == nil ||
		reservation.Continuation().Authority() != ContinuationAuthorityDirectPlatformOIDC {
		t.Fatalf("direct reservation = %v, %v", reservation, err)
	}
	request.ContinuationAuthority = ContinuationAuthorityTenant
	if reservation.validFor(request) {
		t.Fatal("direct continuation reservation accepted as tenant authority")
	}
	credential := reservation.release()
	material, ok := credential.Consume()
	if !ok || material.Authority != ContinuationAuthorityDirectPlatformOIDC {
		t.Fatalf("direct browser material = %v, %t", material, ok)
	}
	material.Destroy()
}

func TestDirectContinuationAuthoritiesAcceptOnlyTheirProtocol(t *testing.T) {
	for _, method := range []AuthenticationMethod{AuthenticationMethodSAML, AuthenticationMethodPasskey, AuthenticationMethodLDAP} {
		request := ApplyCredentialRequest{
			Disposition: ApplyContinuation, Method: method,
			ContinuationAuthority: ContinuationAuthorityDirectPlatformOIDC,
			IssuedAt:              serviceTestNow,
		}
		if validApplyCredentialRequest(request) {
			t.Fatalf("direct platform authority accepted %q", method)
		}
	}
	for _, method := range []AuthenticationMethod{AuthenticationMethodOIDC, AuthenticationMethodPasskey, AuthenticationMethodLDAP} {
		request := ApplyCredentialRequest{
			Disposition: ApplyContinuation, Method: method,
			ContinuationAuthority: ContinuationAuthorityDirectPlatformSAML,
			IssuedAt:              serviceTestNow,
		}
		if validApplyCredentialRequest(request) {
			t.Fatalf("direct platform SAML authority accepted %q", method)
		}
	}
	if !validApplyCredentialRequest(ApplyCredentialRequest{
		Disposition: ApplyContinuation, Method: AuthenticationMethodSAML,
		ContinuationAuthority: ContinuationAuthorityDirectPlatformSAML,
		IssuedAt:              serviceTestNow,
	}) {
		t.Fatal("direct platform SAML authority rejected its SAML method")
	}
}

func TestBrowserCredentialTransfersOnceAndDestroysMaterial(t *testing.T) {
	issuer := testApplyCredentialIssuer()
	for _, disposition := range []ApplyDisposition{ApplySession, ApplyContinuation} {
		reservation, err := issuer.ReserveApplyCredential(ApplyCredentialRequest{
			Disposition: disposition, Method: AuthenticationMethodOIDC, IssuedAt: serviceTestNow,
		})
		if err != nil || reservation == nil {
			t.Fatalf("reserve %s: %v", disposition, err)
		}
		credential := reservation.release()
		material, ok := credential.Consume()
		if !ok || material.Kind == "" {
			t.Fatalf("consume %s = %s, %t", disposition, material.String(), ok)
		}
		if disposition == ApplyContinuation && !material.ExpiresAt.Equal(serviceTestNow.Add(5*time.Minute)) {
			t.Fatalf("continuation expiry = %s", material.ExpiresAt)
		}
		if _, second := credential.Consume(); second {
			t.Fatalf("credential %s consumed twice", disposition)
		}
		material.Destroy()
		if material.Kind != "" || material.SessionID != (identity.EntityID{}) ||
			material.ContinuationID != (identity.EntityID{}) || !material.ExpiresAt.IsZero() || material.SessionToken != nil ||
			material.CSRFToken != nil || material.Receipt != nil {
			t.Fatalf("material survived Destroy: %s", material.String())
		}
	}
}

func TestReleaseBrowserCredentialRequiresExactAppliedIdentifier(t *testing.T) {
	issuer := testApplyCredentialIssuer()
	for _, disposition := range []ApplyDisposition{ApplySession, ApplyContinuation} {
		reservation, err := issuer.ReserveApplyCredential(ApplyCredentialRequest{
			Disposition: disposition, Method: AuthenticationMethodOIDC, IssuedAt: serviceTestNow,
		})
		if err != nil || reservation == nil {
			t.Fatalf("reserve %s: %v", disposition, err)
		}
		sessionID := reservation.Session().SessionID()
		continuationID := reservation.Continuation().ContinuationID()
		wrongSessionID, wrongContinuationID := sessionID, continuationID
		if disposition == ApplySession {
			wrongSessionID = serviceID(230)
		} else {
			wrongContinuationID = serviceID(230)
		}
		if credential, released := reservation.ReleaseBrowserCredential(wrongSessionID, wrongContinuationID); released || credential != nil {
			t.Fatalf("%s credential released for the wrong applied identifier", disposition)
		}
		credential, released := reservation.ReleaseBrowserCredential(sessionID, continuationID)
		if !released || credential == nil {
			t.Fatalf("%s credential was not released for its exact applied identifier", disposition)
		}
		if second, releasedAgain := reservation.ReleaseBrowserCredential(sessionID, continuationID); releasedAgain || second != nil {
			t.Fatalf("%s credential released twice", disposition)
		}
		credential.Destroy()
	}
}

func TestApplyCredentialConstructorsRejectDigestDriftAndRedact(t *testing.T) {
	issuer := testApplyCredentialIssuer()
	reservation, err := issuer.ReserveApplyCredential(ApplyCredentialRequest{
		Disposition: ApplySession, Method: AuthenticationMethodOIDC, IssuedAt: serviceTestNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	session := reservation.Session()
	bad := testOpaqueCredential(99)
	if _, err := NewSessionApplyCredentialReservation(session, bad, bad); err == nil {
		t.Fatal("digest drift accepted")
	}
	const canary = "browser-secret-canary"
	formatted := fmt.Sprintf("%v %#v %v", reservation, reservation, reservation.browser)
	if bytes.Contains([]byte(formatted), []byte(canary)) || !bytes.Contains([]byte(formatted), []byte("[REDACTED]")) {
		t.Fatalf("unsafe formatting: %s", formatted)
	}
	reservation.Destroy()
}

func TestApplyCredentialConstructorsRejectAllZeroOpaqueMaterial(t *testing.T) {
	zero := []byte(base64.RawURLEncoding.EncodeToString(make([]byte, sha256.Size)))
	csrf := testOpaqueCredential(94)
	if validCanonicalOpaqueCredential(zero) {
		t.Fatal("canonical all-zero credential was accepted")
	}
	session, err := mfa.NewSessionReservation(mfa.SessionMaterial{
		SessionID: serviceID(91), FamilyID: serviceID(92),
		TokenDigest: sha256.Sum256(zero), CSRFDigest: sha256.Sum256(csrf),
		AuthenticationMethod: mfa.SessionAuthenticationOIDC,
		IdleExpiresAt:        serviceTestNow.Add(time.Hour), AbsoluteExpiresAt: serviceTestNow.Add(8 * time.Hour),
	}, serviceTestNow.Truncate(time.Millisecond))
	if err != nil {
		t.Fatalf("session reservation: %v", err)
	}
	if reservation, constructorErr := NewSessionApplyCredentialReservation(session, zero, csrf); constructorErr == nil || reservation != nil {
		t.Fatalf("all-zero session material accepted: %s, %v", reservation, constructorErr)
	}
	continuationID := serviceID(93)
	continuation, err := NewPostPrimaryContinuationReservation(PostPrimaryContinuationMaterial{
		ContinuationID: continuationID, ReceiptDigest: sha256.Sum256(zero),
		ExpiresAt: serviceTestNow.Add(5 * time.Minute),
	}, serviceTestNow)
	if err != nil {
		t.Fatalf("continuation reservation: %v", err)
	}
	if reservation, constructorErr := NewContinuationApplyCredentialReservation(continuation, zero); constructorErr == nil || reservation != nil {
		t.Fatalf("all-zero continuation material accepted: %s, %v", reservation, constructorErr)
	}
}

func TestApplyCredentialReservationDefensivelyCopiesBrowserMaterial(t *testing.T) {
	token := testOpaqueCredential(101)
	csrf := testOpaqueCredential(102)
	reservation, err := mfa.NewSessionReservation(mfa.SessionMaterial{
		SessionID: serviceID(101), FamilyID: serviceID(102),
		TokenDigest: sha256.Sum256(token), CSRFDigest: sha256.Sum256(csrf),
		AuthenticationMethod: mfa.SessionAuthenticationOIDC,
		IdleExpiresAt:        serviceTestNow.Add(time.Hour), AbsoluteExpiresAt: serviceTestNow.Add(8 * time.Hour),
	}, serviceTestNow.Truncate(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	owned, err := NewSessionApplyCredentialReservation(reservation, token, csrf)
	if err != nil {
		t.Fatal(err)
	}
	clear(token)
	clear(csrf)
	credential := owned.release()
	material, ok := credential.Consume()
	if !ok || !validCanonicalOpaqueCredential(material.SessionToken) ||
		!validCanonicalOpaqueCredential(material.CSRFToken) {
		t.Fatal("caller mutation changed the owned browser material")
	}
	tokenAlias, csrfAlias := material.SessionToken, material.CSRFToken
	material.Destroy()
	if !allZeroCredential(tokenAlias) || !allZeroCredential(csrfAlias) {
		t.Fatal("destroy did not zero defensively copied browser material")
	}
}

func allZeroCredential(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func testOpaqueCredential(fill byte) []byte {
	return []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, sha256.Size)))
}

func testBrowserCredentialForResult(kind BrowserCredentialKind, id identity.EntityID) *BrowserCredential {
	credential := &BrowserCredential{kind: kind}
	switch kind {
	case BrowserCredentialSession:
		credential.sessionID = id
		credential.sessionToken = testOpaqueCredential(241)
		credential.csrfToken = testOpaqueCredential(242)
	case BrowserCredentialContinuation:
		credential.continuationID = id
		credential.receipt = testOpaqueCredential(243)
	}
	return credential
}
