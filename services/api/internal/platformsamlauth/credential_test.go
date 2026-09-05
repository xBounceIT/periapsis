package platformsamlauth

import (
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

func TestCredentialReservationOwnershipHandoffIsConcurrentAndOneUse(t *testing.T) {
	issuedAt := time.Now().UTC().Truncate(time.Millisecond)
	token := opaqueCredential(1)
	csrf := opaqueCredential(2)
	session, err := mfa.NewSessionReservation(mfa.SessionMaterial{
		SessionID: testID(1), FamilyID: testID(2), TokenDigest: sha256.Sum256(token),
		CSRFDigest: sha256.Sum256(csrf), AuthenticationMethod: mfa.SessionAuthenticationSAML,
		IdleExpiresAt: issuedAt.Add(time.Hour), AbsoluteExpiresAt: issuedAt.Add(8 * time.Hour),
	}, issuedAt)
	if err != nil {
		t.Fatalf("NewSessionReservation() error = %v", err)
	}
	reservation, err := NewSessionCredentialReservation(session, token, csrf)
	if err != nil {
		t.Fatalf("NewSessionCredentialReservation() error = %v", err)
	}

	var released atomic.Int64
	var consumed atomic.Int64
	var wait sync.WaitGroup
	start := make(chan struct{})
	for index := range 64 {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			switch index % 4 {
			case 0:
				_ = reservation.Session()
			case 1:
				_ = reservation.Continuation()
			case 2:
				credential, ok := reservation.release(session.SessionID(), [16]byte{})
				if ok {
					released.Add(1)
					if material, consumedOK := credential.Consume(); consumedOK {
						consumed.Add(1)
						material.Destroy()
					}
					credential.Destroy()
				}
			default:
				reservation.Destroy()
			}
		}(index)
	}
	close(start)
	wait.Wait()
	reservation.Destroy()
	if released.Load() > 1 || consumed.Load() > 1 {
		t.Fatalf("release/consume counts = %d/%d", released.Load(), consumed.Load())
	}
}

func TestCredentialConstructorsAndStringFormsArePurposeBoundAndRedacted(t *testing.T) {
	issuedAt := time.Now().UTC().Truncate(time.Millisecond)
	receipt := opaqueCredential(3)
	id := testID(3)
	digest, err := ContinuationReceiptDigest(id, receipt)
	if err != nil {
		t.Fatal(err)
	}
	continuation, err := NewContinuationReservation(ContinuationMaterial{
		ContinuationID: id, FactorID: testID(4), FactorRevision: 5,
		ReceiptDigest: digest, ExpiresAt: issuedAt.Add(time.Minute),
	}, issuedAt)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := NewContinuationCredentialReservation(continuation, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if got := reservation.String(); got != "platformsamlauth.CredentialReservation{authority:direct_platform_saml,material:[REDACTED]}" {
		t.Fatalf("String() = %q", got)
	}
	changed := append([]byte(nil), receipt...)
	changed[0] ^= 1
	if _, err := NewContinuationCredentialReservation(continuation, changed); err == nil {
		t.Fatal("continuation receipt substitution was accepted")
	}
	reservation.Destroy()
}
