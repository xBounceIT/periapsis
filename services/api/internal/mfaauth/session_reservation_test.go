package mfaauth

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

func testSessionReservation(
	t testing.TB,
	at time.Time,
	method mfa.SessionAuthenticationMethod,
	sessionSeed byte,
	familySeed byte,
) mfa.SessionReservation {
	t.Helper()
	reservation, err := mfa.NewSessionReservation(mfa.SessionMaterial{
		SessionID: testID(sessionSeed), FamilyID: testID(familySeed),
		TokenDigest:          sha256.Sum256([]byte{0x01, sessionSeed, familySeed}),
		CSRFDigest:           sha256.Sum256([]byte{0x02, sessionSeed, familySeed}),
		AuthenticationMethod: method,
		IdleExpiresAt:        at.Add(time.Hour), AbsoluteExpiresAt: at.Add(24 * time.Hour),
	}, at)
	if err != nil {
		t.Fatal(err)
	}
	return reservation
}
