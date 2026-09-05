package mfaauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
	"github.com/periapsis-im/periapsis/modules/identity/webauthn"
)

func TestCompletionTicketAcceptsLDAPOnlyAsResultAuthenticationMethod(t *testing.T) {
	t.Parallel()

	if !validResultAuthenticationMethod(string(mfa.SessionAuthenticationLDAP)) {
		t.Fatal("LDAP result authentication method was rejected")
	}
	if validReservationAuthenticationMethod(mfa.SessionAuthenticationLDAP) {
		t.Fatal("LDAP reservation authentication method was accepted")
	}
}

type completionSourceStub struct {
	mu      sync.Mutex
	calls   int
	resolve func(CompletionTicketLookup) (CompletionTicketResolutionInput, error)
}

func (source *completionSourceStub) ResolveMFACompletion(
	_ context.Context,
	lookup CompletionTicketLookup,
) (CompletionTicketResolutionInput, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.calls++
	return source.resolve(lookup)
}

func (source *completionSourceStub) callCount() int {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.calls
}

func TestCompletionTicketCopiesAndConcurrentConsumersShareOneUse(t *testing.T) {
	t.Parallel()

	issuer, source, request, resolution := completionTicketFixture(t)
	ticket, err := issuer.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	reservation := completionReservationFixture(t, resolution)

	const consumers = 32
	var successes atomic.Int32
	var wait sync.WaitGroup
	wait.Add(consumers)
	for range consumers {
		copyOfTicket := ticket
		go func() {
			defer wait.Done()
			if _, ok := copyOfTicket.consumePrepared(reservation); ok {
				successes.Add(1)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful consumes = %d", successes.Load())
	}
	if source.callCount() != 1 {
		t.Fatalf("authority resolutions = %d", source.callCount())
	}
	if plan, ok := ticket.ReservationPlan(); ok || plan != (CompletionReservationPlan{}) {
		t.Fatalf("consumed ticket exposed plan = %#v, %t", plan, ok)
	}
}

func TestCompletionTicketMismatchBurnsTicketBeforeArtifactClaim(t *testing.T) {
	t.Parallel()

	issuer, _, request, resolution := completionTicketFixture(t)
	ticket, err := issuer.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	reservation := completionReservationFixture(t, resolution)
	wrongBrowser := completionBrowserHandle(0x72)
	if _, ok := ticket.consume(
		request.ArtifactKind, request.ArtifactID, wrongBrowser, request.FactorKind, request.FactorID, reservation,
	); ok {
		t.Fatal("mismatched browser consumed ticket successfully")
	}
	if _, ok := ticket.consume(
		request.ArtifactKind, request.ArtifactID, request.BrowserHandle,
		request.FactorKind, request.FactorID, reservation,
	); ok {
		t.Fatal("mismatched consume did not burn the single-use ticket")
	}
}

func TestCompletionTicketRejectsWebAuthnCrossPurposeBeforeClaim(t *testing.T) {
	t.Parallel()

	issuer, _, request, resolution := completionTicketFixture(t)
	request.ArtifactKind = CompletionArtifactWebAuthnRegistration
	request.FactorKind = CompletionFactorPasskey
	request.FactorID = []byte("new-credential")
	request.ContinuationID = testID(14)
	request.ContinuationReceiptDigest = [32]byte{0x31}
	request.SessionSource = nil
	resolution.ArtifactKind = request.ArtifactKind
	resolution.FactorKind = request.FactorKind
	resolution.FactorID = append([]byte(nil), request.FactorID...)
	resolution.Flow = CompletionFlowContinuation
	resolution.SessionID = identity.EntityID{}
	resolution.SessionFamilyID = identity.EntityID{}
	resolution.ContinuationID = request.ContinuationID
	resolution.ContinuationReceiptDigest = request.ContinuationReceiptDigest
	resolution.ReservationDisposition = CompletionReservationNone
	resolution.ReservationAuthenticationMethod = ""
	resolution.ResultAuthenticationMethod = ""
	resolution.SourceSessionID = identity.EntityID{}
	resolution.SourceSessionFamilyID = identity.EntityID{}
	resolution.SourceSessionVersion = 0
	resolution.SourceAbsoluteExpiresAt = time.Time{}
	issuer.source.(*completionSourceStub).resolve = func(lookup CompletionTicketLookup) (CompletionTicketResolutionInput, error) {
		resolution.BrowserDigest = lookup.BrowserDigest
		return resolution, nil
	}

	ticket, err := issuer.Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ticket.consume(
		CompletionArtifactWebAuthnAuthentication, request.ArtifactID, request.BrowserHandle,
		request.FactorKind, request.FactorID, mfa.SessionReservation{},
	); ok {
		t.Fatal("registration ticket crossed into authentication completion")
	}
}

func TestCompletionTicketPrimaryPasskeyKnownAndDiscoverable(t *testing.T) {
	t.Parallel()

	for _, discoverable := range []bool{false, true} {
		t.Run(map[bool]string{false: "known", true: "discoverable"}[discoverable], func(t *testing.T) {
			issuer, _, request, resolution := completionTicketFixture(t)
			request.ArtifactKind = CompletionArtifactWebAuthnAuthentication
			request.FactorKind = CompletionFactorPasskey
			request.FactorID = []byte("credential-id")
			request.SessionSource = nil
			resolution.ArtifactKind = request.ArtifactKind
			resolution.FactorKind = request.FactorKind
			resolution.FactorID = append([]byte(nil), request.FactorID...)
			resolution.Flow = CompletionFlowPrimary
			resolution.SessionID = identity.EntityID{}
			resolution.SessionFamilyID = identity.EntityID{}
			resolution.AnchorVersion = 0
			resolution.AnchorExpiresAt = time.Time{}
			resolution.ReservationDisposition = CompletionReservationCreate
			resolution.ReservationAuthenticationMethod = mfa.SessionAuthenticationPasskey
			resolution.ResultAuthenticationMethod = string(mfa.SessionAuthenticationPasskey)
			resolution.SourceSessionID = identity.EntityID{}
			resolution.SourceSessionFamilyID = identity.EntityID{}
			resolution.SourceSessionVersion = 0
			resolution.SourceAbsoluteExpiresAt = time.Time{}
			if discoverable {
				resolution.UserID = identity.EntityID{}
				resolution.IdentityEpoch = 0
			}
			issuer.source.(*completionSourceStub).resolve = func(lookup CompletionTicketLookup) (CompletionTicketResolutionInput, error) {
				resolution.BrowserDigest = lookup.BrowserDigest
				return resolution, nil
			}
			if _, err := issuer.Prepare(context.Background(), request); err != nil {
				t.Fatalf("Prepare() error = %v", err)
			}
		})
	}
}

func TestCompletionTicketRequiresExactReceiptAndDatabaseTimeBounds(t *testing.T) {
	t.Parallel()

	issuer, source, request, resolution := completionTicketFixture(t)
	request.ContinuationID = testID(14)
	request.ContinuationReceiptDigest = [32]byte{0x31}
	request.SessionSource = nil
	resolution.Flow = CompletionFlowContinuation
	resolution.SessionID = identity.EntityID{}
	resolution.SessionFamilyID = identity.EntityID{}
	resolution.ContinuationID = request.ContinuationID
	resolution.ContinuationReceiptDigest = request.ContinuationReceiptDigest
	resolution.ReservationDisposition = CompletionReservationCreate
	resolution.SourceSessionID = identity.EntityID{}
	resolution.SourceSessionFamilyID = identity.EntityID{}
	resolution.SourceSessionVersion = 0
	resolution.SourceAbsoluteExpiresAt = time.Time{}
	resolution.ResultAuthenticationMethod = string(mfa.SessionAuthenticationOIDC)
	source.resolve = func(lookup CompletionTicketLookup) (CompletionTicketResolutionInput, error) {
		if lookup.ContinuationReceiptDigest != request.ContinuationReceiptDigest {
			return CompletionTicketResolutionInput{}, errors.New("receipt rejected")
		}
		resolution.BrowserDigest = lookup.BrowserDigest
		return resolution, nil
	}

	zeroReceipt := request
	zeroReceipt.ContinuationReceiptDigest = [32]byte{}
	if _, err := issuer.Prepare(context.Background(), zeroReceipt); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("zero receipt error = %v", err)
	}
	if source.callCount() != 0 {
		t.Fatal("zero receipt reached protected resolver")
	}
	wrongReceipt := request
	wrongReceipt.ContinuationReceiptDigest[31] ^= 0xff
	if _, err := issuer.Prepare(context.Background(), wrongReceipt); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong receipt error = %v", err)
	}

	for _, loadedAt := range []time.Time{
		testNow.Add(-time.Microsecond),
		testNow.Add(5*time.Minute + time.Second + time.Microsecond),
	} {
		source.resolve = func(lookup CompletionTicketLookup) (CompletionTicketResolutionInput, error) {
			value := resolution
			value.LoadedAt = loadedAt
			value.BrowserDigest = lookup.BrowserDigest
			return value, nil
		}
		if _, err := issuer.Prepare(context.Background(), request); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("LoadedAt %s error = %v", loadedAt, err)
		}
	}
}

func TestCompletionTicketRejectsReservationMethodNotSelectedFactor(t *testing.T) {
	t.Parallel()

	issuer, source, request, resolution := completionTicketFixture(t)
	resolution.ReservationAuthenticationMethod = mfa.SessionAuthenticationRecovery
	source.resolve = func(lookup CompletionTicketLookup) (CompletionTicketResolutionInput, error) {
		resolution.BrowserDigest = lookup.BrowserDigest
		return resolution, nil
	}
	if _, err := issuer.Prepare(context.Background(), request); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("Prepare() error = %v", err)
	}
}

func TestCompletionTicketContinuationRotationRequiresSourceVersionHeadroom(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		version uint64
		wantErr bool
	}{
		{name: "maximum minus one", version: maximumStoredVersion - 1},
		{name: "maximum", version: maximumStoredVersion, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			issuer, source, request, resolution := completionTicketFixture(t)
			request.SessionSource = nil
			request.ContinuationID = testID(14)
			request.ContinuationReceiptDigest = [sha256.Size]byte{0x44}
			resolution.Flow = CompletionFlowContinuation
			resolution.SessionID = identity.EntityID{}
			resolution.SessionFamilyID = identity.EntityID{}
			resolution.ContinuationID = request.ContinuationID
			resolution.ContinuationReceiptDigest = request.ContinuationReceiptDigest
			resolution.ReservationDisposition = CompletionReservationRotate
			resolution.SourceSessionID = testID(15)
			resolution.SourceSessionFamilyID = testID(16)
			resolution.SourceSessionVersion = test.version
			resolution.SourceAbsoluteExpiresAt = testNow.Add(24 * time.Hour).Truncate(time.Millisecond)
			source.resolve = func(lookup CompletionTicketLookup) (CompletionTicketResolutionInput, error) {
				resolution.BrowserDigest = lookup.BrowserDigest
				return resolution, nil
			}
			ticket, err := issuer.Prepare(context.Background(), request)
			if test.wantErr && !errors.Is(err, ErrAuthentication) {
				t.Fatalf("Prepare() error = %v", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("Prepare() error = %v", err)
			}
			if test.wantErr {
				return
			}
			plan, ok := ticket.ReservationPlan()
			if !ok || plan.Disposition != CompletionReservationRotate ||
				plan.AuthenticationMethod != mfa.SessionAuthenticationTOTP ||
				plan.ResultAuthenticationMethod != string(mfa.SessionAuthenticationOIDC) ||
				plan.SourceSessionID != resolution.SourceSessionID ||
				plan.SourceSessionFamilyID != resolution.SourceSessionFamilyID ||
				!plan.SourceAbsoluteExpiresAt.Equal(resolution.SourceAbsoluteExpiresAt) ||
				!plan.IssuedAt.Equal(resolution.LoadedAt) {
				t.Fatalf("reservation plan = %#v", plan)
			}
			reservation := completionReservationFixture(t, resolution)
			if _, ok := ticket.consumePrepared(reservation); !ok {
				t.Fatal("exact continuation rotation reservation was rejected")
			}
		})
	}
}

func TestCompletionTicketContinuationRotationRejectsChangedSourceTuple(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		mutate func(*mfa.SessionMaterial)
	}{
		{name: "family", mutate: func(material *mfa.SessionMaterial) {
			material.FamilyID = testID(31)
		}},
		{name: "absolute expiry", mutate: func(material *mfa.SessionMaterial) {
			material.AbsoluteExpiresAt = material.AbsoluteExpiresAt.Add(time.Millisecond)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			issuer, source, request, resolution := completionTicketFixture(t)
			request.SessionSource = nil
			request.ContinuationID = testID(14)
			request.ContinuationReceiptDigest = [sha256.Size]byte{0x44}
			resolution.Flow = CompletionFlowContinuation
			resolution.SessionID = identity.EntityID{}
			resolution.SessionFamilyID = identity.EntityID{}
			resolution.ContinuationID = request.ContinuationID
			resolution.ContinuationReceiptDigest = request.ContinuationReceiptDigest
			resolution.ReservationDisposition = CompletionReservationRotate
			resolution.SourceSessionID = testID(15)
			resolution.SourceSessionFamilyID = testID(16)
			resolution.SourceSessionVersion = 8
			resolution.SourceAbsoluteExpiresAt = testNow.Add(24 * time.Hour).Truncate(time.Millisecond)
			source.resolve = func(lookup CompletionTicketLookup) (CompletionTicketResolutionInput, error) {
				resolution.BrowserDigest = lookup.BrowserDigest
				return resolution, nil
			}
			ticket, err := issuer.Prepare(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			material := mfa.SessionMaterial{
				SessionID: testID(21), FamilyID: resolution.SourceSessionFamilyID,
				TokenDigest: sha256.Sum256([]byte("token")), CSRFDigest: sha256.Sum256([]byte("csrf")),
				AuthenticationMethod: resolution.ReservationAuthenticationMethod,
				IdleExpiresAt:        resolution.LoadedAt.Add(time.Hour).Truncate(time.Millisecond),
				AbsoluteExpiresAt:    resolution.SourceAbsoluteExpiresAt,
			}
			test.mutate(&material)
			reservation, err := mfa.NewSessionReservation(material, resolution.LoadedAt)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := ticket.consumePrepared(reservation); ok {
				t.Fatal("changed continuation source tuple was accepted")
			}
		})
	}
}

func completionTicketFixture(t *testing.T) (
	*CompletionTicketIssuer,
	*completionSourceStub,
	CompletionTicketRequest,
	CompletionTicketResolutionInput,
) {
	t.Helper()
	browser := completionBrowserHandle(0x41)
	artifactID := bytes.Repeat([]byte{0x51}, sha256.Size)
	factorID := testID(11)
	sourceSessionID := testID(12)
	sourceFamilyID := testID(13)
	absoluteExpiresAt := testNow.Add(24 * time.Hour).Truncate(time.Millisecond)
	sessionSource := &CompletionSessionSource{
		TenantID: testID(1), UserID: testID(2), SessionID: sourceSessionID,
		SessionFamilyID: sourceFamilyID, AuthenticationMethod: string(mfa.SessionAuthenticationOIDC),
		AbsoluteExpiresAt: absoluteExpiresAt,
	}
	request := CompletionTicketRequest{
		Admission: validAdmissionContext(), ArtifactKind: CompletionArtifactStepUp,
		ArtifactID: artifactID, BrowserHandle: browser, FactorKind: CompletionFactorTOTP,
		FactorID: factorID[:], SessionSource: sessionSource,
	}
	resolution := CompletionTicketResolutionInput{
		LoadedAt: testNow.Add(123 * time.Microsecond), ArtifactKind: request.ArtifactKind,
		ArtifactID: append([]byte(nil), request.ArtifactID...), BrowserDigest: sha256.Sum256(browser),
		FactorKind: request.FactorKind, FactorID: append([]byte(nil), request.FactorID...),
		Flow: CompletionFlowSession, TenantID: sessionSource.TenantID, UserID: sessionSource.UserID,
		IdentityEpoch: 7, ResolvedUserID: sessionSource.UserID, ResolvedIdentityEpoch: 7,
		SessionID: sourceSessionID, SessionFamilyID: sourceFamilyID, AnchorVersion: 4,
		AnchorExpiresAt: testNow.Add(time.Hour).Truncate(time.Millisecond),
		Action:          "case.export", Audience: "tenant-console",
		ReservationDisposition:          CompletionReservationRotate,
		ReservationAuthenticationMethod: mfa.SessionAuthenticationTOTP,
		ResultAuthenticationMethod:      string(mfa.SessionAuthenticationOIDC),
		SourceSessionID:                 sourceSessionID, SourceSessionFamilyID: sourceFamilyID,
		SourceSessionVersion: 4, SourceAbsoluteExpiresAt: absoluteExpiresAt,
	}
	source := &completionSourceStub{resolve: func(CompletionTicketLookup) (CompletionTicketResolutionInput, error) {
		return resolution, nil
	}}
	gate := &gateStub{decision: AdmissionDecision{Outcome: AdmissionAllowed}}
	issuer, err := NewCompletionTicketIssuer(CompletionTicketOptions{
		Source: source, Admissions: gate, Now: func() time.Time { return testNow }, OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return issuer, source, request, resolution
}

func completionReservationFixture(t *testing.T, resolution CompletionTicketResolutionInput) mfa.SessionReservation {
	t.Helper()
	reservation, err := mfa.NewSessionReservation(mfa.SessionMaterial{
		SessionID: testID(21), FamilyID: resolution.SourceSessionFamilyID,
		TokenDigest: sha256.Sum256([]byte("token")), CSRFDigest: sha256.Sum256([]byte("csrf")),
		AuthenticationMethod: resolution.ReservationAuthenticationMethod,
		IdleExpiresAt:        resolution.LoadedAt.Add(time.Hour).Truncate(time.Millisecond),
		AbsoluteExpiresAt:    resolution.SourceAbsoluteExpiresAt,
	}, resolution.LoadedAt)
	if err != nil {
		t.Fatal(err)
	}
	return reservation
}

func completionBrowserHandle(value byte) []byte {
	return []byte(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, sha256.Size)))
}

func testEnrollmentCompletionTicket(
	start TOTPEnrollmentStartArtifact,
	binding mfa.StepUpBinding,
	session mfa.SessionReservation,
	receipt [sha256.Size]byte,
) CompletionTicket {
	enrollmentID := start.EnrollmentID()
	factorID := start.FactorID()
	disposition := CompletionReservationRotate
	reservationMethod := mfa.SessionAuthenticationTOTP
	resultMethod := string(mfa.SessionAuthenticationTOTP)
	sourceSessionID := binding.SessionID
	sourceFamilyID := binding.SessionFamilyID
	sourceVersion := binding.AnchorVersion
	sourceAbsoluteExpiresAt := session.AbsoluteExpiresAt()
	if binding.Flow == mfa.FlowPostPrimaryContinuation {
		disposition = CompletionReservationNone
		reservationMethod = ""
		resultMethod = ""
		sourceSessionID = identity.EntityID{}
		sourceFamilyID = identity.EntityID{}
		sourceVersion = 0
		sourceAbsoluteExpiresAt = time.Time{}
	}
	return testCompletionTicket(CompletionTicketResolutionInput{
		LoadedAt: testNow, ArtifactKind: CompletionArtifactTOTPEnrollment,
		ArtifactID: enrollmentID[:], BrowserDigest: sha256.Sum256(start.BrowserHandle()),
		FactorKind: CompletionFactorTOTP, FactorID: factorID[:], Flow: completionFlow(binding.Flow),
		TenantID: binding.TenantID, UserID: binding.UserID, IdentityEpoch: binding.IdentityEpoch,
		ResolvedUserID: binding.UserID, ResolvedIdentityEpoch: binding.IdentityEpoch,
		SessionID: binding.SessionID, SessionFamilyID: binding.SessionFamilyID,
		ContinuationID: binding.ContinuationID, ContinuationReceiptDigest: receipt,
		AnchorVersion: binding.AnchorVersion, AnchorExpiresAt: binding.AnchorExpiresAt,
		Action: binding.Action, Audience: binding.Audience, ReservationDisposition: disposition,
		ReservationAuthenticationMethod: reservationMethod, ResultAuthenticationMethod: resultMethod,
		SourceSessionID: sourceSessionID, SourceSessionFamilyID: sourceFamilyID,
		SourceSessionVersion: sourceVersion, SourceAbsoluteExpiresAt: sourceAbsoluteExpiresAt,
	})
}

func testLocalCompletionTicket(
	artifact mfa.StepUpArtifact,
	challengeID mfa.ChallengeID,
	browserHandle []byte,
	factorKind CompletionFactorKind,
	factorID []byte,
	reservation mfa.SessionReservation,
) CompletionTicket {
	return testCompletionTicket(CompletionTicketResolutionInput{
		LoadedAt: testNow, ArtifactKind: CompletionArtifactStepUp,
		ArtifactID: challengeID[:], BrowserDigest: sha256.Sum256(browserHandle),
		FactorKind: factorKind, FactorID: append([]byte(nil), factorID...), Flow: CompletionFlowSession,
		TenantID: artifact.TenantID, UserID: artifact.UserID, IdentityEpoch: artifact.IdentityEpoch,
		ResolvedUserID: artifact.UserID, ResolvedIdentityEpoch: artifact.IdentityEpoch,
		SessionID: artifact.SessionID, SessionFamilyID: artifact.SessionFamilyID,
		AnchorVersion: artifact.SessionVersion - 1, AnchorExpiresAt: reservation.AbsoluteExpiresAt(),
		Action: artifact.Action, Audience: artifact.Audience, ReservationDisposition: CompletionReservationRotate,
		ReservationAuthenticationMethod: reservation.AuthenticationMethod(),
		ResultAuthenticationMethod:      string(reservation.AuthenticationMethod()),
		SourceSessionID:                 artifact.SessionID, SourceSessionFamilyID: artifact.SessionFamilyID,
		SourceSessionVersion: artifact.SessionVersion - 1, SourceAbsoluteExpiresAt: reservation.AbsoluteExpiresAt(),
	})
}

func testPasskeyAuthenticationCommand(
	completion webauthn.AuthenticationCompletion,
	session mfa.SessionReservation,
	receipt [sha256.Size]byte,
) FinishPasskeyAuthenticationCommand {
	browserHandle := opaqueHandle(70)
	disposition := CompletionReservationRotate
	sourceSessionID := completion.Binding.SessionID
	sourceFamilyID := completion.Binding.SessionFamilyID
	sourceVersion := completion.Binding.AnchorVersion
	sourceAbsoluteExpiresAt := session.AbsoluteExpiresAt()
	if completion.Binding.Purpose == webauthn.PurposePrimaryAuthentication ||
		completion.Binding.Purpose == webauthn.PurposeContinuationAuthentication {
		disposition = CompletionReservationCreate
		sourceSessionID = identity.EntityID{}
		sourceFamilyID = identity.EntityID{}
		sourceVersion = 0
		sourceAbsoluteExpiresAt = time.Time{}
	}
	resolution := CompletionTicketResolutionInput{
		LoadedAt: testNow, ArtifactKind: CompletionArtifactWebAuthnAuthentication,
		ArtifactID: completion.CeremonyID[:], BrowserDigest: sha256.Sum256(browserHandle),
		FactorKind: CompletionFactorPasskey, FactorID: append([]byte(nil), completion.CredentialID...),
		Flow: completionFlowForPurpose(completion.Binding.Purpose), TenantID: completion.Binding.TenantID,
		UserID: completion.Binding.UserID, IdentityEpoch: completion.Binding.IdentityEpoch,
		ResolvedUserID: completion.ResolvedUserID, ResolvedIdentityEpoch: completion.ExpectedIdentityEpoch,
		SessionID: completion.Binding.SessionID, SessionFamilyID: completion.Binding.SessionFamilyID,
		ContinuationID: completion.Binding.ContinuationID, ContinuationReceiptDigest: receipt,
		AnchorVersion: completion.Binding.AnchorVersion, AnchorExpiresAt: completion.Binding.AnchorExpiresAt,
		Action: completion.Binding.Action, Audience: completion.Binding.Audience,
		ReservationDisposition: disposition, ReservationAuthenticationMethod: mfa.SessionAuthenticationPasskey,
		ResultAuthenticationMethod: string(mfa.SessionAuthenticationPasskey),
		SourceSessionID:            sourceSessionID, SourceSessionFamilyID: sourceFamilyID,
		SourceSessionVersion: sourceVersion, SourceAbsoluteExpiresAt: sourceAbsoluteExpiresAt,
	}
	return FinishPasskeyAuthenticationCommand{
		Ticket: testCompletionTicket(resolution),
		Response: webauthn.AuthenticationResponse{
			CeremonyID: completion.CeremonyID, BrowserHandle: browserHandle,
			CredentialID: append([]byte(nil), completion.CredentialID...),
		},
		Session: session,
	}
}

func testPasskeyRegistrationCommand(
	completion webauthn.RegistrationCompletion,
	session mfa.SessionReservation,
	receipt [sha256.Size]byte,
) FinishPasskeyRegistrationCommand {
	browserHandle := opaqueHandle(71)
	disposition := CompletionReservationRotate
	reservationMethod := mfa.SessionAuthenticationPasskey
	resultMethod := string(mfa.SessionAuthenticationPasskey)
	sourceSessionID := completion.Binding.SessionID
	sourceFamilyID := completion.Binding.SessionFamilyID
	sourceVersion := completion.Binding.AnchorVersion
	sourceAbsoluteExpiresAt := session.AbsoluteExpiresAt()
	flow := CompletionFlowSession
	if completion.Binding.Purpose == webauthn.PurposeRegistration &&
		completion.Binding.ContinuationID != (identity.EntityID{}) {
		flow = CompletionFlowContinuation
		disposition = CompletionReservationNone
		reservationMethod = ""
		resultMethod = ""
		sourceSessionID = identity.EntityID{}
		sourceFamilyID = identity.EntityID{}
		sourceVersion = 0
		sourceAbsoluteExpiresAt = time.Time{}
	}
	resolution := CompletionTicketResolutionInput{
		LoadedAt: testNow, ArtifactKind: CompletionArtifactWebAuthnRegistration,
		ArtifactID: completion.CeremonyID[:], BrowserDigest: sha256.Sum256(browserHandle),
		FactorKind: CompletionFactorPasskey, FactorID: append([]byte(nil), completion.Credential.ID...),
		Flow: flow, TenantID: completion.Binding.TenantID,
		UserID: completion.Binding.UserID, IdentityEpoch: completion.Binding.IdentityEpoch,
		ResolvedUserID: completion.Binding.UserID, ResolvedIdentityEpoch: completion.Binding.IdentityEpoch,
		SessionID: completion.Binding.SessionID, SessionFamilyID: completion.Binding.SessionFamilyID,
		ContinuationID: completion.Binding.ContinuationID, ContinuationReceiptDigest: receipt,
		AnchorVersion: completion.Binding.AnchorVersion, AnchorExpiresAt: completion.Binding.AnchorExpiresAt,
		Action: completion.Binding.Action, Audience: completion.Binding.Audience,
		ReservationDisposition: disposition, ReservationAuthenticationMethod: reservationMethod,
		ResultAuthenticationMethod: resultMethod,
		SourceSessionID:            sourceSessionID, SourceSessionFamilyID: sourceFamilyID,
		SourceSessionVersion: sourceVersion, SourceAbsoluteExpiresAt: sourceAbsoluteExpiresAt,
	}
	return FinishPasskeyRegistrationCommand{
		Ticket: testCompletionTicket(resolution),
		Response: webauthn.RegistrationResponse{
			CeremonyID: completion.CeremonyID, BrowserHandle: browserHandle,
			CredentialID: append([]byte(nil), completion.Credential.ID...),
		},
		Session: session,
	}
}

func testCompletionTicket(resolution CompletionTicketResolutionInput) CompletionTicket {
	return CompletionTicket{state: &completionTicketState{resolution: cloneCompletionResolution(resolution)}}
}

func completionFlow(flow mfa.StepUpFlow) CompletionFlow {
	if flow == mfa.FlowPostPrimaryContinuation {
		return CompletionFlowContinuation
	}
	return CompletionFlowSession
}

func completionFlowForPurpose(purpose webauthn.CeremonyPurpose) CompletionFlow {
	switch purpose {
	case webauthn.PurposePrimaryAuthentication:
		return CompletionFlowPrimary
	case webauthn.PurposeContinuationAuthentication:
		return CompletionFlowContinuation
	default:
		return CompletionFlowSession
	}
}
