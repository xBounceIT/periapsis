package authentication

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

func TestReserveDirectSAMLCredentialCreatesPurposeSpecificReservations(t *testing.T) {
	service := federatedSessionReservationService(t)
	factorID := identity.EntityID(uuid.MustParse("01991384-9c00-7000-8000-000000000031"))

	for _, testCase := range []struct {
		name    string
		request platformsamlauth.CredentialRequest
	}{
		{
			name: "session",
			request: platformsamlauth.CredentialRequest{
				Disposition: platformsamlauth.ImmediateSession,
				IssuedAt:    federatedReservationNow,
			},
		},
		{
			name: "TOTP continuation",
			request: platformsamlauth.CredentialRequest{
				Disposition: platformsamlauth.TOTPContinuation,
				TOTP:        &platformsamlauth.TOTPSelection{FactorID: factorID, Revision: 7},
				IssuedAt:    federatedReservationNow,
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			credential, err := service.ReserveDirectSAMLCredential(testCase.request)
			if err != nil || credential == nil {
				t.Fatalf("ReserveDirectSAMLCredential() = %s, %v", credential, err)
			}
			defer credential.Destroy()
			if testCase.request.Disposition == platformsamlauth.ImmediateSession {
				if credential.Session().IsZero() || !credential.Continuation().IsZero() ||
					credential.Session().AuthenticationMethod() != mfa.SessionAuthenticationSAML {
					t.Fatalf("session reservation = %s", credential)
				}
				return
			}
			continuation := credential.Continuation()
			if !credential.Session().IsZero() || continuation.IsZero() ||
				continuation.FactorID() != factorID || continuation.FactorRevision() != 7 ||
				!continuation.ExpiresAt().Equal(federatedReservationNow.Add(5*time.Minute)) {
				t.Fatalf("continuation reservation = %s", credential)
			}
		})
	}
}

func TestReserveDirectSAMLCredentialPreservesRotationFamilyAndAbsoluteExpiry(t *testing.T) {
	t.Parallel()
	service := federatedSessionReservationService(t)
	anchor := &platformsamlauth.SessionRotationAnchor{
		SessionID:         identity.EntityID(uuid.Must(uuid.NewV7())),
		FamilyID:          identity.EntityID(uuid.Must(uuid.NewV7())),
		AbsoluteExpiresAt: federatedReservationNow.Add(4 * time.Hour),
	}
	credential, err := service.ReserveDirectSAMLCredential(platformsamlauth.CredentialRequest{
		Disposition: platformsamlauth.ImmediateSession,
		IssuedAt:    federatedReservationNow,
		Rotation:    anchor,
	})
	if err != nil || credential == nil {
		t.Fatalf("ReserveDirectSAMLCredential(rotation) = %s, %v", credential, err)
	}
	defer credential.Destroy()
	reserved := credential.Session()
	if reserved.SessionID() == anchor.SessionID || reserved.FamilyID() != anchor.FamilyID ||
		!reserved.AbsoluteExpiresAt().Equal(anchor.AbsoluteExpiresAt) {
		t.Fatalf("rotation reservation = %s", reserved)
	}
}

func TestReserveDirectSAMLCredentialRejectsMalformedAndCrossPurposeRequests(t *testing.T) {
	service := federatedSessionReservationService(t)
	validFactor := identity.EntityID(uuid.MustParse("01991384-9c00-7000-8000-000000000032"))
	for name, request := range map[string]platformsamlauth.CredentialRequest{
		"unknown disposition": {
			Disposition: platformsamlauth.Disposition("direct_platform_oidc"),
			IssuedAt:    federatedReservationNow,
		},
		"session carrying TOTP": {
			Disposition: platformsamlauth.ImmediateSession,
			TOTP:        &platformsamlauth.TOTPSelection{FactorID: validFactor, Revision: 1},
			IssuedAt:    federatedReservationNow,
		},
		"continuation without TOTP": {
			Disposition: platformsamlauth.TOTPContinuation,
			IssuedAt:    federatedReservationNow,
		},
		"continuation with non-v7 factor": {
			Disposition: platformsamlauth.TOTPContinuation,
			TOTP:        &platformsamlauth.TOTPSelection{FactorID: identity.EntityID(uuid.New()), Revision: 1},
			IssuedAt:    federatedReservationNow,
		},
		"continuation with zero revision": {
			Disposition: platformsamlauth.TOTPContinuation,
			TOTP:        &platformsamlauth.TOTPSelection{FactorID: validFactor},
			IssuedAt:    federatedReservationNow,
		},
		"continuation carrying rotation": {
			Disposition: platformsamlauth.TOTPContinuation,
			TOTP:        &platformsamlauth.TOTPSelection{FactorID: validFactor, Revision: 1},
			IssuedAt:    federatedReservationNow,
			Rotation: &platformsamlauth.SessionRotationAnchor{
				SessionID:         identity.EntityID(uuid.Must(uuid.NewV7())),
				FamilyID:          identity.EntityID(uuid.Must(uuid.NewV7())),
				AbsoluteExpiresAt: federatedReservationNow.Add(time.Hour),
			},
		},
		"rotation with expired absolute deadline": {
			Disposition: platformsamlauth.ImmediateSession,
			IssuedAt:    federatedReservationNow,
			Rotation: &platformsamlauth.SessionRotationAnchor{
				SessionID:         identity.EntityID(uuid.Must(uuid.NewV7())),
				FamilyID:          identity.EntityID(uuid.Must(uuid.NewV7())),
				AbsoluteExpiresAt: federatedReservationNow,
			},
		},
		"stale issue instant": {
			Disposition: platformsamlauth.ImmediateSession,
			IssuedAt:    federatedReservationNow.Add(-2 * time.Second),
		},
	} {
		t.Run(name, func(t *testing.T) {
			credential, err := service.ReserveDirectSAMLCredential(request)
			if err == nil || credential != nil {
				t.Fatalf("ReserveDirectSAMLCredential() = %s, %v", credential, err)
			}
			if errors.Is(err, platformsamlauth.ErrAuthenticationDenied) {
				t.Fatalf("issuer leaked protocol denial error: %v", err)
			}
		})
	}
}
