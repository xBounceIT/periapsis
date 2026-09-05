package webauthn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func TestCompileRelyingPartyIsCanonicalAndImmutable(t *testing.T) {
	rp, err := CompileRelyingParty("example.com", []string{
		"https://login.example.com", "https://example.com",
	}, 9)
	if err != nil {
		t.Fatal(err)
	}
	if got := rp.Origins(); len(got) != 2 || got[0] != "https://example.com" || got[1] != "https://login.example.com" {
		t.Fatalf("origins = %v", got)
	}
	origins := rp.Origins()
	origins[0] = "https://evil.example"
	if rp.Origins()[0] != "https://example.com" || strings.Contains(fmt.Sprintf("%#v", rp), "example.com") {
		t.Fatal("RP snapshot is mutable or formats deployment hostnames")
	}

	for name, values := range map[string]struct {
		id      string
		origins []string
	}{
		"uppercase id":          {"Example.com", []string{"https://example.com"}},
		"public suffix escape":  {"example.com", []string{"https://example.com.evil.test"}},
		"userinfo":              {"example.com", []string{"https://user@example.com"}},
		"path":                  {"example.com", []string{"https://example.com/login"}},
		"query":                 {"example.com", []string{"https://example.com?next=evil"}},
		"http":                  {"example.com", []string{"http://example.com"}},
		"nondefault port":       {"example.com", []string{"https://example.com:8443"}},
		"explicit default port": {"example.com", []string{"https://example.com:443"}},
		"IP relying party":      {"127.0.0.1", []string{"https://127.0.0.1"}},
		"duplicate":             {"example.com", []string{"https://example.com", "https://example.com"}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, compileErr := CompileRelyingParty(values.id, values.origins, 1); !errors.Is(compileErr, ErrInvalidOptions) {
				t.Fatalf("got %v", compileErr)
			}
		})
	}
}

func TestRegistrationBindsTenantUserBrowserRPPolicyAndStoresPublicMaterial(t *testing.T) {
	fixture := newKernelFixture(t)
	start, artifact, err := fixture.register()
	if err != nil {
		t.Fatal(err)
	}
	if artifact.TenantID != fixture.binding.TenantID || artifact.UserID != fixture.binding.UserID ||
		artifact.CredentialVersion != 1 || !artifact.Discoverable ||
		len(artifact.Transports) != 1 || artifact.Transports[0] != TransportInternal {
		t.Fatalf("artifact = %#v", artifact)
	}
	fixture.repository.mu.Lock()
	stored := fixture.repository.ceremonies[start.CeremonyID()]
	credential := fixture.repository.credentials[string(fixture.credentialID)]
	fixture.repository.mu.Unlock()
	if stored.State != CeremonyCompleted || stored.Binding.TenantID != fixture.binding.TenantID ||
		stored.Binding.UserID != fixture.binding.UserID || stored.RP.Revision() != fixture.rp.Revision() ||
		stored.UserHandleDigest == ([32]byte{}) || credential.UserHandleDigest != stored.UserHandleDigest ||
		!bytes.Equal(credential.PublicKey, bytes.Repeat([]byte{0xa1}, 64)) {
		t.Fatal("registration did not preserve exact pins")
	}
	challenge := start.Challenge()
	challenge[0] ^= 0xff
	handle := start.BrowserHandle()
	handle[0] ^= 0xff
	if bytes.Equal(challenge, start.Challenge()) || bytes.Equal(handle, start.BrowserHandle()) {
		t.Fatal("start artifact accessors expose mutable storage")
	}
}

func TestRecoveryRestrictedSessionCanRegisterRepairFactorOnlyWithRecoveryEvidence(t *testing.T) {
	fixture := newKernelFixture(t)
	fixture.binding.AnchorRecoveryRestricted = true
	fixture.binding.BaselineEvidence[0].Kind = identity.AssuranceEvidenceRecovery
	start, err := fixture.kernel.StartRegistration(context.Background(), RegistrationStartRequest{
		RP: fixture.rp, Binding: fixture.binding, Policy: fixture.registrationPolicy(),
		UserHandle: fixture.userHandle,
	})
	if err != nil || start.CeremonyID() == (CeremonyID{}) || !start.Binding().AnchorRecoveryRestricted {
		t.Fatalf("repair registration start = %#v, err = %v", start, err)
	}

	fixture = newKernelFixture(t)
	fixture.binding.AnchorRecoveryRestricted = true
	if _, err = fixture.kernel.StartRegistration(context.Background(), RegistrationStartRequest{
		RP: fixture.rp, Binding: fixture.binding, Policy: fixture.registrationPolicy(),
		UserHandle: fixture.userHandle,
	}); !errors.Is(err, ErrCeremonyRejected) {
		t.Fatalf("restricted registration without recovery evidence = %v", err)
	}
}

func TestRegistrationRejectsAdversarialVerifiedProofsTerminally(t *testing.T) {
	tests := map[string]func(*RegistrationProof){
		"challenge substitution":  func(proof *RegistrationProof) { proof.ChallengeDigest[0] ^= 1 },
		"origin substitution":     func(proof *RegistrationProof) { proof.Origin = "https://evil.example" },
		"RP substitution":         func(proof *RegistrationProof) { proof.RPIDHash[0] ^= 1 },
		"cross origin":            func(proof *RegistrationProof) { proof.CrossOrigin = true },
		"missing presence":        func(proof *RegistrationProof) { proof.UserPresent = false },
		"missing verification":    func(proof *RegistrationProof) { proof.UserVerified = false },
		"credential substitution": func(proof *RegistrationProof) { proof.CredentialID[0] ^= 1 },
		"backup contradiction":    func(proof *RegistrationProof) { proof.BackedUp = true },
		"attestation upgrade": func(proof *RegistrationProof) {
			proof.AttestationType = AttestationTypeBasic
			proof.AttestationTrusted = true
			proof.MetadataRevision = 4
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newKernelFixture(t)
			fixture.verifier.registrationMutate = mutate
			start, err := fixture.kernel.StartRegistration(context.Background(), RegistrationStartRequest{
				RP: fixture.rp, Binding: fixture.binding, Policy: fixture.registrationPolicy(), UserHandle: fixture.userHandle,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = fixture.kernel.FinishRegistrationWithConsumer(context.Background(), RegistrationResponse{
				CeremonyID: start.CeremonyID(), BrowserHandle: start.BrowserHandle(), CredentialID: fixture.credentialID,
				ClientDataJSON: []byte("client"), AttestationObject: []byte("attestation"),
				Transports: []CredentialTransport{TransportInternal},
			}, fixture.repository)
			if !errors.Is(err, ErrVerificationRejected) {
				t.Fatalf("got %v", err)
			}
			fixture.repository.mu.Lock()
			state := fixture.repository.ceremonies[start.CeremonyID()].State
			_, created := fixture.repository.credentials[string(fixture.credentialID)]
			fixture.repository.mu.Unlock()
			if state != CeremonyFailed || created {
				t.Fatal("rejected proof remained replayable or created a credential")
			}
		})
	}
}

func TestDirectAttestationRequiresPinnedTrustRevision(t *testing.T) {
	fixture := newKernelFixture(t)
	policy := fixture.registrationPolicy()
	policy.Attestation = AttestationDirect
	policy.MetadataRevision = 42
	fixture.verifier.registrationMutate = func(proof *RegistrationProof) {
		proof.AttestationFormat = "packed"
		proof.AttestationType = AttestationTypeBasic
		proof.AttestationTrusted = true
		proof.MetadataRevision = 42
	}
	start, err := fixture.kernel.StartRegistration(context.Background(), RegistrationStartRequest{
		RP: fixture.rp, Binding: fixture.binding, Policy: policy, UserHandle: fixture.userHandle,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.kernel.FinishRegistrationWithConsumer(context.Background(), RegistrationResponse{
		CeremonyID: start.CeremonyID(), BrowserHandle: start.BrowserHandle(), CredentialID: fixture.credentialID,
		ClientDataJSON: []byte("client"), AttestationObject: []byte("attestation"),
	}, fixture.repository); err != nil {
		t.Fatal(err)
	}
}

func TestKnownUserAuthenticationProducesOneNewLocalEvidence(t *testing.T) {
	fixture := newKernelFixture(t)
	if _, _, err := fixture.register(); err != nil {
		t.Fatal(err)
	}
	start, err := fixture.startAuthentication(AuthenticationKnownUser)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := fixture.finishAuthentication(start, fixture.userHandle)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.UserID != fixture.binding.UserID || artifact.TenantID != fixture.binding.TenantID ||
		artifact.Evidence.Level != identity.AssurancePhishingResistant ||
		artifact.Evidence.Kind != identity.AssuranceEvidenceFactor || !artifact.Evidence.Source.Local ||
		artifact.Evidence.FactorRevision == nil || *artifact.Evidence.FactorRevision != 1 ||
		artifact.CounterUnsupported || artifact.BackupStateChanged {
		t.Fatalf("artifact = %#v", artifact)
	}
	if strings.Contains(fmt.Sprintf("%#v", artifact), fmt.Sprintf("%x", fixture.credentialID)) {
		t.Fatal("authentication artifact formats credential material")
	}
	fixture.repository.mu.Lock()
	credential := fixture.repository.credentials[string(fixture.credentialID)]
	fixture.repository.mu.Unlock()
	if credential.Version != 2 || credential.SecurityRevision != 1 {
		t.Fatalf("ordinary authentication revisions = %#v", credential)
	}
}

func TestPresenceOnlyCredentialCannotSelfPromotePrimaryToMFA(t *testing.T) {
	fixture := newKernelFixture(t)
	if _, _, err := fixture.register(); err != nil {
		t.Fatal(err)
	}
	binding := fixture.binding
	binding.Purpose = PurposePrimaryAuthentication
	binding.SessionID = identity.EntityID{}
	binding.SessionFamilyID = identity.EntityID{}
	binding.AnchorVersion = 0
	binding.AnchorExpiresAt = time.Time{}
	binding.BaselineEvidence = nil
	binding.Action = "login"
	policy := fixture.registrationPolicy()
	policy.UserVerification = UserVerificationPreferred
	start, err := fixture.kernel.StartAuthentication(context.Background(), AuthenticationStartRequest{
		RP: fixture.rp, Binding: binding, Policy: policy, Mode: AuthenticationKnownUser,
		UserHandle: fixture.userHandle, AllowedCredentialIDs: [][]byte{fixture.credentialID},
	})
	if !errors.Is(err, ErrCeremonyRejected) {
		t.Fatalf("MFA primary accepted presence-only policy: %#v, %v", start, err)
	}
}

func TestZeroCounterBackupChangeAndDeviceRevocation(t *testing.T) {
	fixture := newKernelFixture(t)
	if _, _, err := fixture.register(); err != nil {
		t.Fatal(err)
	}
	fixture.repository.mu.Lock()
	credential := fixture.repository.credentials[string(fixture.credentialID)]
	credential.BackupEligible = true
	fixture.repository.credentials[string(fixture.credentialID)] = credential
	fixture.repository.mu.Unlock()
	fixture.verifier.authenticationMutate = func(proof *AuthenticationProof) {
		proof.SignCount = 0
		proof.BackupEligible = true
		proof.BackedUp = true
	}
	start, err := fixture.startAuthentication(AuthenticationKnownUser)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := fixture.finishAuthentication(start, fixture.userHandle)
	if err != nil || !artifact.CounterUnsupported || !artifact.BackupStateChanged {
		t.Fatalf("zero/backup artifact = %#v, %v", artifact, err)
	}
	fixture.repository.mu.Lock()
	credential = fixture.repository.credentials[string(fixture.credentialID)]
	if !credential.BackupEligible || !credential.BackedUp || credential.Status != CredentialActive {
		fixture.repository.mu.Unlock()
		t.Fatal("backup flags did not commit")
	}
	credential.Status = CredentialRevoked
	credential.Version++
	fixture.repository.credentials[string(fixture.credentialID)] = credential
	fixture.repository.mu.Unlock()

	start, err = fixture.startAuthentication(AuthenticationKnownUser)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.finishAuthentication(start, fixture.userHandle); !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("revoked device = %v", err)
	}
}

func TestBackupEligibilityChangeAdvancesSecurityRevision(t *testing.T) {
	fixture := newKernelFixture(t)
	if _, _, err := fixture.register(); err != nil {
		t.Fatal(err)
	}
	fixture.verifier.authenticationMutate = func(proof *AuthenticationProof) {
		proof.BackupEligible = true
	}
	start, err := fixture.startAuthentication(AuthenticationKnownUser)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := fixture.finishAuthentication(start, fixture.userHandle)
	if err != nil || !artifact.BackupStateChanged || artifact.Evidence.FactorRevision == nil ||
		*artifact.Evidence.FactorRevision != 2 {
		t.Fatalf("backup eligibility mutation = %#v, %v", artifact, err)
	}
	fixture.repository.mu.Lock()
	credential := fixture.repository.credentials[string(fixture.credentialID)]
	fixture.repository.mu.Unlock()
	if !credential.BackupEligible || credential.BackedUp || credential.Status != CredentialActive ||
		credential.Version != 2 || credential.SecurityRevision != 2 {
		t.Fatalf("backup eligibility transition = %#v", credential)
	}
}

func TestWrongBrowserOrTenantCannotConsumeCredential(t *testing.T) {
	fixture := newKernelFixture(t)
	if _, _, err := fixture.register(); err != nil {
		t.Fatal(err)
	}
	start, err := fixture.startAuthentication(AuthenticationKnownUser)
	if err != nil {
		t.Fatal(err)
	}
	wrongBrowser := start.BrowserHandle()
	wrongBrowser[0] = 'A'
	if _, err = fixture.kernel.FinishAuthenticationWithConsumer(context.Background(), AuthenticationResponse{
		CeremonyID: start.CeremonyID(), BrowserHandle: wrongBrowser, CredentialID: fixture.credentialID,
		ClientDataJSON: []byte("client"), AuthenticatorData: []byte("authenticator"), Signature: []byte("signature"),
	}, fixture.repository); !errors.Is(err, ErrCeremonyRejected) {
		t.Fatalf("wrong browser = %v", err)
	}
	fixture.repository.mu.Lock()
	state := fixture.repository.ceremonies[start.CeremonyID()].State
	fixture.repository.mu.Unlock()
	if state != CeremonyPending {
		t.Fatal("wrong browser consumed ceremony")
	}

	binding := fixture.binding
	binding.Purpose = PurposeStepUpAuthentication
	binding.TenantID = testID(99)
	binding.Action = "case.export"
	crossTenant, err := fixture.kernel.StartAuthentication(context.Background(), AuthenticationStartRequest{
		RP: fixture.rp, Binding: binding, Policy: fixture.registrationPolicy(), Mode: AuthenticationKnownUser,
		UserHandle: fixture.userHandle, AllowedCredentialIDs: [][]byte{fixture.credentialID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.finishAuthentication(crossTenant, fixture.userHandle); !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("cross-tenant credential = %v", err)
	}
}

func TestKnownUserCeremonyRejectsIdentityEpochDriftBeforeVerification(t *testing.T) {
	fixture := newKernelFixture(t)
	if _, _, err := fixture.register(); err != nil {
		t.Fatal(err)
	}
	start, err := fixture.startAuthentication(AuthenticationKnownUser)
	if err != nil {
		t.Fatal(err)
	}
	fixture.repository.mu.Lock()
	credential := fixture.repository.credentials[string(fixture.credentialID)]
	credential.IdentityEpoch++
	fixture.repository.credentials[string(fixture.credentialID)] = credential
	fixture.repository.mu.Unlock()
	_, err = fixture.finishAuthentication(start, fixture.userHandle)
	if !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("got %v", err)
	}
	fixture.verifier.mu.Lock()
	calls := fixture.verifier.authenticationCalls
	fixture.verifier.mu.Unlock()
	if calls != 0 {
		t.Fatalf("identity epoch drift reached verifier: %d calls", calls)
	}
}

func TestRegistrationNormalizesTransportOrderButRejectsDuplicates(t *testing.T) {
	fixture := newKernelFixture(t)
	start, err := fixture.kernel.StartRegistration(context.Background(), RegistrationStartRequest{
		RP: fixture.rp, Binding: fixture.binding, Policy: fixture.registrationPolicy(), UserHandle: fixture.userHandle,
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := fixture.kernel.FinishRegistrationWithConsumer(context.Background(), RegistrationResponse{
		CeremonyID: start.CeremonyID(), BrowserHandle: start.BrowserHandle(), CredentialID: fixture.credentialID,
		ClientDataJSON: []byte("client"), AttestationObject: []byte("attestation"),
		Transports: []CredentialTransport{TransportUSB, TransportInternal},
	}, fixture.repository)
	if err != nil || !slices.Equal(artifact.Transports, []CredentialTransport{TransportInternal, TransportUSB}) {
		t.Fatalf("normalized transports = %v, %v", artifact.Transports, err)
	}

	fixture = newKernelFixture(t)
	start, err = fixture.kernel.StartRegistration(context.Background(), RegistrationStartRequest{
		RP: fixture.rp, Binding: fixture.binding, Policy: fixture.registrationPolicy(), UserHandle: fixture.userHandle,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.kernel.FinishRegistrationWithConsumer(context.Background(), RegistrationResponse{
		CeremonyID: start.CeremonyID(), BrowserHandle: start.BrowserHandle(), CredentialID: fixture.credentialID,
		ClientDataJSON: []byte("client"), AttestationObject: []byte("attestation"),
		Transports: []CredentialTransport{TransportUSB, TransportUSB},
	}, fixture.repository); !errors.Is(err, ErrCeremonyRejected) {
		t.Fatalf("duplicate transports = %v", err)
	}
}

func TestAuthenticatorChosenShortCredentialIDRemainsInteroperable(t *testing.T) {
	fixture := newKernelFixture(t)
	fixture.credentialID = []byte{0x7f}
	if _, artifact, err := fixture.register(); err != nil || artifact.CredentialVersion != 1 {
		t.Fatalf("short credential ID = %#v, %v", artifact, err)
	}
}

func TestDiscoverableAuthenticationResolvesOnlyExactOpaqueHandle(t *testing.T) {
	fixture := newKernelFixture(t)
	if _, _, err := fixture.register(); err != nil {
		t.Fatal(err)
	}
	start, err := fixture.startAuthentication(AuthenticationDiscoverable)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := fixture.finishAuthentication(start, fixture.userHandle)
	if err != nil || artifact.UserID != fixture.binding.UserID || artifact.IdentityEpoch != fixture.binding.IdentityEpoch {
		t.Fatalf("discoverable result = %#v, %v", artifact, err)
	}

	start, err = fixture.startAuthentication(AuthenticationDiscoverable)
	if err != nil {
		t.Fatal(err)
	}
	wrongHandle := bytes.Repeat([]byte{0x99}, stableUserHandleBytes)
	if _, err = fixture.finishAuthentication(start, wrongHandle); !errors.Is(err, ErrCredentialRejected) {
		t.Fatalf("wrong user handle = %v", err)
	}
}

func TestCeremonyReplayRaceHasExactlyOneWinner(t *testing.T) {
	fixture := newKernelFixture(t)
	if _, _, err := fixture.register(); err != nil {
		t.Fatal(err)
	}
	start, err := fixture.startAuthentication(AuthenticationKnownUser)
	if err != nil {
		t.Fatal(err)
	}
	var winners atomic.Int32
	var wait sync.WaitGroup
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, finishErr := fixture.finishAuthentication(start, fixture.userHandle); finishErr == nil {
				winners.Add(1)
			} else if !errors.Is(finishErr, ErrCeremonyRejected) {
				t.Errorf("unexpected error: %v", finishErr)
			}
		}()
	}
	wait.Wait()
	if winners.Load() != 1 {
		t.Fatalf("winners = %d", winners.Load())
	}
}

func TestConcurrentCounterUseHasOneWinner(t *testing.T) {
	fixture := newKernelFixture(t)
	if _, _, err := fixture.register(); err != nil {
		t.Fatal(err)
	}
	first, err := fixture.startAuthentication(AuthenticationKnownUser)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.startAuthentication(AuthenticationKnownUser)
	if err != nil {
		t.Fatal(err)
	}
	barrier := make(chan struct{})
	fixture.verifier.authenticationMutate = func(proof *AuthenticationProof) {
		proof.SignCount = 1
		<-barrier
	}
	var winners atomic.Int32
	var wait sync.WaitGroup
	for _, start := range []StartArtifact{first, second} {
		wait.Add(1)
		go func(start StartArtifact) {
			defer wait.Done()
			if _, finishErr := fixture.finishAuthentication(start, fixture.userHandle); finishErr == nil {
				winners.Add(1)
			} else if !errors.Is(finishErr, ErrCredentialRejected) &&
				!errors.Is(finishErr, ErrCredentialCloneSuspected) {
				t.Errorf("unexpected error: %v", finishErr)
			}
		}(start)
	}
	// The fake verifier serializes calls; release both receives without relying
	// on timing by providing two tokens.
	barrier <- struct{}{}
	barrier <- struct{}{}
	wait.Wait()
	if winners.Load() != 1 {
		t.Fatalf("counter winners = %d", winners.Load())
	}
}

func TestCounterZeroAndCloneSemantics(t *testing.T) {
	for _, test := range []struct {
		stored, observed uint32
		want             CounterDisposition
	}{
		{0, 0, CounterUnsupported},
		{0, 1, CounterAdvance},
		{1, 2, CounterAdvance},
		{1, 1, CounterCloneSuspected},
		{1, 0, CounterCloneSuspected},
		{^uint32(0), ^uint32(0), CounterCloneSuspected},
	} {
		if got := EvaluateSignCount(test.stored, test.observed); got != test.want {
			t.Fatalf("EvaluateSignCount(%d,%d) = %d", test.stored, test.observed, got)
		}
	}
}

func TestCloneIsRevokedBeforeTheKernelReturns(t *testing.T) {
	fixture := newKernelFixture(t)
	if _, _, err := fixture.register(); err != nil {
		t.Fatal(err)
	}
	fixture.repository.mu.Lock()
	credential := fixture.repository.credentials[string(fixture.credentialID)]
	credential.SignCount = 9
	fixture.repository.credentials[string(fixture.credentialID)] = credential
	fixture.repository.mu.Unlock()
	fixture.verifier.authenticationMutate = func(proof *AuthenticationProof) { proof.SignCount = 9 }
	start, err := fixture.startAuthentication(AuthenticationKnownUser)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = fixture.finishAuthentication(start, fixture.userHandle); !errors.Is(err, ErrCredentialCloneSuspected) {
		t.Fatalf("got %v", err)
	}
	fixture.repository.mu.Lock()
	credential = fixture.repository.credentials[string(fixture.credentialID)]
	fixture.repository.mu.Unlock()
	if credential.Status != CredentialCloneSuspected || credential.Version != 2 || credential.SecurityRevision != 2 {
		t.Fatal("clone error returned before atomic revocation")
	}
}

func TestMalformedOrExpiredResponseNeverReachesVerifier(t *testing.T) {
	fixture := newKernelFixture(t)
	start, err := fixture.kernel.StartRegistration(context.Background(), RegistrationStartRequest{
		RP: fixture.rp, Binding: fixture.binding, Policy: fixture.registrationPolicy(), UserHandle: fixture.userHandle,
	})
	if err != nil {
		t.Fatal(err)
	}
	oversized := bytes.Repeat([]byte{'x'}, fixture.kernel.limits.MaxResponseBytes+1)
	if _, err = fixture.kernel.FinishRegistrationWithConsumer(context.Background(), RegistrationResponse{
		CeremonyID: start.CeremonyID(), BrowserHandle: start.BrowserHandle(), CredentialID: fixture.credentialID,
		ClientDataJSON: oversized, AttestationObject: []byte("attestation"),
	}, fixture.repository); !errors.Is(err, ErrCeremonyRejected) {
		t.Fatalf("oversized = %v", err)
	}
	fixture.verifier.mu.Lock()
	calls := fixture.verifier.registrationCalls
	fixture.verifier.mu.Unlock()
	fixture.repository.mu.Lock()
	state := fixture.repository.ceremonies[start.CeremonyID()].State
	fixture.repository.mu.Unlock()
	if calls != 0 || state != CeremonyPending {
		t.Fatal("malformed response reached verifier or consumed ceremony")
	}

	*fixture.now = start.ExpiresAt()
	if _, err = fixture.kernel.FinishRegistrationWithConsumer(context.Background(), RegistrationResponse{
		CeremonyID: start.CeremonyID(), BrowserHandle: start.BrowserHandle(), CredentialID: fixture.credentialID,
		ClientDataJSON: []byte("client"), AttestationObject: []byte("attestation"),
	}, fixture.repository); !errors.Is(err, ErrCeremonyRejected) {
		t.Fatalf("expiry boundary = %v", err)
	}
}

func TestCancellationAndErrorsAreSanitized(t *testing.T) {
	fixture := newKernelFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fixture.kernel.StartRegistration(ctx, RegistrationStartRequest{
		RP: fixture.rp, Binding: fixture.binding, Policy: fixture.registrationPolicy(), UserHandle: fixture.userHandle,
	}); !errors.Is(err, ErrCeremonyRejected) {
		t.Fatalf("cancelled start = %v", err)
	}

	start, err := fixture.kernel.StartRegistration(context.Background(), RegistrationStartRequest{
		RP: fixture.rp, Binding: fixture.binding, Policy: fixture.registrationPolicy(), UserHandle: fixture.userHandle,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.verifier.err = errors.New("hostile credential and clientData canary")
	_, err = fixture.kernel.FinishRegistrationWithConsumer(context.Background(), RegistrationResponse{
		CeremonyID: start.CeremonyID(), BrowserHandle: start.BrowserHandle(), CredentialID: fixture.credentialID,
		ClientDataJSON: []byte("client"), AttestationObject: []byte("attestation"),
	}, fixture.repository)
	if !errors.Is(err, ErrVerificationRejected) || strings.Contains(err.Error(), "canary") {
		t.Fatalf("unsanitized error = %v", err)
	}
}

func TestVerificationFailureTerminalizesAfterRequestCancellation(t *testing.T) {
	fixture := newKernelFixture(t)
	if _, _, err := fixture.register(); err != nil {
		t.Fatal(err)
	}
	start, err := fixture.startAuthentication(AuthenticationKnownUser)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	fixture.verifier.authenticationHook = cancel
	fixture.verifier.err = errors.New("verification failed")
	_, err = fixture.finishAuthenticationWithContext(ctx, start, fixture.userHandle)
	if !errors.Is(err, ErrVerificationRejected) {
		t.Fatalf("got %v", err)
	}
	fixture.repository.mu.Lock()
	defer fixture.repository.mu.Unlock()
	if fixture.repository.failContext != nil || len(fixture.repository.failures) != 1 {
		t.Fatalf("fail context = %v, failures = %d", fixture.repository.failContext, len(fixture.repository.failures))
	}
}

func TestResponseFormattingRedactsAllRawMaterial(t *testing.T) {
	canary := "credential-clientdata-authenticator-signature-userhandle-canary"
	values := []any{
		RegistrationResponse{ClientDataJSON: []byte(canary), AttestationObject: []byte(canary)},
		AuthenticationResponse{ClientDataJSON: []byte(canary), AuthenticatorData: []byte(canary), Signature: []byte(canary)},
		Credential{ID: []byte(canary), PublicKey: []byte(canary)},
		CredentialLookup{CredentialID: []byte(canary), UserHandle: []byte(canary)},
		RegistrationCompletion{Credential: Credential{ID: []byte(canary)}},
		AuthenticationCompletion{CredentialID: []byte(canary)},
		RegistrationVerificationRequest{ClientDataJSON: []byte(canary), AttestationObject: []byte(canary)},
		RegistrationProof{CredentialID: []byte(canary), PublicKey: []byte(canary)},
		AuthenticationVerificationRequest{ClientDataJSON: []byte(canary), Signature: []byte(canary)},
		AuthenticationProof{CredentialID: []byte(canary), UserHandle: []byte(canary)},
		RegistrationStartRequest{UserHandle: []byte(canary)},
		AuthenticationStartRequest{UserHandle: []byte(canary)},
		PendingCeremony{AllowedCredentialIDs: [][]byte{[]byte(canary)}},
		ClaimedCeremony{PendingCeremony: PendingCeremony{AllowedCredentialIDs: [][]byte{[]byte(canary)}}},
		StartArtifact{challenge: []byte(canary), browserHandle: []byte(canary)},
		CeremonyBinding{Action: canary, Audience: canary},
	}
	for _, value := range values {
		if formatted := fmt.Sprintf("%#v", value); strings.Contains(formatted, canary) {
			t.Fatalf("unsafe format %T: %s", value, formatted)
		}
	}
}

func TestStartArtifactCanBeDestroyedAfterTransport(t *testing.T) {
	fixture := newKernelFixture(t)
	artifact, err := fixture.kernel.StartRegistration(context.Background(), RegistrationStartRequest{
		RP: fixture.rp, Binding: fixture.binding, Policy: fixture.registrationPolicy(), UserHandle: fixture.userHandle,
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact.Destroy()
	if len(artifact.Challenge()) != 0 || len(artifact.BrowserHandle()) != 0 || len(artifact.UserHandle()) != 0 ||
		len(artifact.CredentialIDs()) != 0 || artifact.Binding().TenantID != (identity.EntityID{}) {
		t.Fatalf("artifact survived Destroy: %#v", artifact)
	}
}

func FuzzEvaluateSignCount(f *testing.F) {
	f.Add(uint32(0), uint32(0))
	f.Add(uint32(1), uint32(0))
	f.Add(uint32(1), uint32(2))
	f.Fuzz(func(t *testing.T, stored, observed uint32) {
		got := EvaluateSignCount(stored, observed)
		if stored == 0 && observed == 0 && got != CounterUnsupported {
			t.Fatal("zero counter was marked as clone risk")
		}
		if observed > stored && got != CounterAdvance {
			t.Fatal("strictly increasing counter was not advanced")
		}
		if stored > 0 && observed <= stored && got != CounterCloneSuspected {
			t.Fatal("non-increasing nonzero counter was accepted")
		}
	})
}

func FuzzCompileRelyingPartyNeverAcceptsNonHTTPS(f *testing.F) {
	f.Add("example.com", "https://example.com")
	f.Add("example.com", "http://example.com")
	f.Fuzz(func(t *testing.T, id, origin string) {
		rp, err := CompileRelyingParty(id, []string{origin}, 1)
		if err != nil {
			return
		}
		if !strings.HasPrefix(rp.Origins()[0], "https://") || !validRP(rp) {
			t.Fatalf("unsafe RP accepted: %#v", rp)
		}
	})
}

var _ = time.Second
