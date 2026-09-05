package authentication

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

var federatedReservationNow = time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)

func TestReserveApplyCredentialCreatesConsumableSessionAndContinuation(t *testing.T) {
	service := federatedSessionReservationService(t)
	for _, testCase := range []struct {
		name        string
		disposition federatedauth.ApplyDisposition
		method      federatedauth.AuthenticationMethod
		authority   federatedauth.ContinuationAuthority
	}{
		{name: "OIDC session", disposition: federatedauth.ApplySession, method: federatedauth.AuthenticationMethodOIDC},
		{name: "SAML session", disposition: federatedauth.ApplySession, method: federatedauth.AuthenticationMethodSAML},
		{name: "LDAP session", disposition: federatedauth.ApplySession, method: federatedauth.AuthenticationMethodLDAP},
		{name: "post-primary continuation", disposition: federatedauth.ApplyContinuation, method: federatedauth.AuthenticationMethodOIDC},
		{name: "LDAP post-primary continuation", disposition: federatedauth.ApplyContinuation, method: federatedauth.AuthenticationMethodLDAP},
		{
			name: "direct platform OIDC continuation", disposition: federatedauth.ApplyContinuation,
			method:    federatedauth.AuthenticationMethodOIDC,
			authority: federatedauth.ContinuationAuthorityDirectPlatformOIDC,
		},
		{
			name: "direct platform SAML continuation", disposition: federatedauth.ApplyContinuation,
			method:    federatedauth.AuthenticationMethodSAML,
			authority: federatedauth.ContinuationAuthorityDirectPlatformSAML,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			reservation, err := service.ReserveApplyCredential(federatedauth.ApplyCredentialRequest{
				Disposition: testCase.disposition, Method: testCase.method,
				ContinuationAuthority: testCase.authority, IssuedAt: federatedReservationNow,
			})
			if err != nil || reservation == nil {
				t.Fatalf("ReserveApplyCredential() = %s, %v", reservation, err)
			}
			if testCase.disposition == federatedauth.ApplySession {
				if reservation.Session().IsZero() || !reservation.Continuation().IsZero() ||
					reservation.Session().AuthenticationMethod() != mfa.SessionAuthenticationMethod(testCase.method) {
					t.Fatalf("session reservation = %s", reservation)
				}
			} else if !reservation.Session().IsZero() || reservation.Continuation().IsZero() ||
				reservation.Continuation().Authority() != testCase.authority {
				t.Fatalf("continuation reservation = %s", reservation)
			}
			formatted := fmt.Sprintf("%v %#v", reservation, reservation)
			if !bytes.Contains([]byte(formatted), []byte("[REDACTED]")) {
				t.Fatalf("reservation formatting = %s", formatted)
			}
			reservation.Destroy()
		})
	}
}

func TestReserveApplyCredentialRejectsStaleAndUnknownRequests(t *testing.T) {
	service := federatedSessionReservationService(t)
	for name, request := range map[string]federatedauth.ApplyCredentialRequest{
		"stale timestamp": {
			Disposition: federatedauth.ApplySession, Method: federatedauth.AuthenticationMethodOIDC,
			IssuedAt: federatedReservationNow.Add(-2 * time.Second),
		},
		"unknown method": {
			Disposition: federatedauth.ApplySession, Method: federatedauth.AuthenticationMethod("kerberos"),
			IssuedAt: federatedReservationNow,
		},
		"SAML relabeled as OIDC continuation": {
			Disposition: federatedauth.ApplyContinuation, Method: federatedauth.AuthenticationMethodSAML,
			ContinuationAuthority: federatedauth.ContinuationAuthorityDirectPlatformOIDC,
			IssuedAt:              federatedReservationNow,
		},
		"OIDC relabeled as SAML continuation": {
			Disposition: federatedauth.ApplyContinuation, Method: federatedauth.AuthenticationMethodOIDC,
			ContinuationAuthority: federatedauth.ContinuationAuthorityDirectPlatformSAML,
			IssuedAt:              federatedReservationNow,
		},
		"direct passkey continuation": {
			Disposition: federatedauth.ApplyContinuation, Method: federatedauth.AuthenticationMethodPasskey,
			ContinuationAuthority: federatedauth.ContinuationAuthorityDirectPlatformOIDC,
			IssuedAt:              federatedReservationNow,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if reservation, err := service.ReserveApplyCredential(request); err == nil || reservation != nil {
				t.Fatalf("ReserveApplyCredential() = %s, %v", reservation, err)
			}
		})
	}
}

func federatedSessionReservationService(t *testing.T) *Service {
	t.Helper()
	return newAuthenticationServiceAt(
		t, &repositoryStub{}, &passwordEngineStub{}, totpEngineStub{},
		digest("bootstrap-authority-value-000000"), federatedReservationNow,
	)
}
