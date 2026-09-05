package webauthn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"sync"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

var testNow = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

type deterministicReader struct {
	mu   sync.Mutex
	next byte
}

func (reader *deterministicReader) Read(destination []byte) (int, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	if len(destination) == 0 {
		return 0, nil
	}
	reader.next++
	if reader.next == 0 {
		reader.next++
	}
	for index := range destination {
		destination[index] = reader.next
	}
	return len(destination), nil
}

type memoryRepository struct {
	mu          sync.Mutex
	ceremonies  map[CeremonyID]PendingCeremony
	credentials map[string]Credential
	claims      int
	failures    []CeremonyFailure
	failContext error
}

func newMemoryRepository() *memoryRepository {
	return &memoryRepository{
		ceremonies: make(map[CeremonyID]PendingCeremony), credentials: make(map[string]Credential),
	}
}

func (repository *memoryRepository) Create(_ context.Context, value PendingCeremony) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if _, exists := repository.ceremonies[value.ID]; exists {
		return errors.New("duplicate")
	}
	repository.ceremonies[value.ID] = clonePending(value)
	return nil
}

func (repository *memoryRepository) Claim(_ context.Context, claim CeremonyClaim) (ClaimedCeremony, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	value, exists := repository.ceremonies[claim.ID]
	if !exists || value.State != CeremonyPending || value.BrowserDigest != claim.BrowserDigest ||
		!claim.ClaimedAt.Before(value.ExpiresAt) {
		return ClaimedCeremony{}, errors.New("claim rejected")
	}
	value.State = CeremonyClaimed
	value.Version++
	repository.ceremonies[claim.ID] = value
	repository.claims++
	return ClaimedCeremony{PendingCeremony: clonePending(value), ClaimedAt: claim.ClaimedAt}, nil
}

func (repository *memoryRepository) Fail(ctx context.Context, failure CeremonyFailure) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.failContext = ctx.Err()
	if repository.failContext != nil {
		return repository.failContext
	}
	value, exists := repository.ceremonies[failure.ID]
	if !exists || value.State != CeremonyClaimed || value.Version != failure.ExpectedVersion {
		return errors.New("stale")
	}
	value.State = failure.State
	value.Version++
	repository.ceremonies[failure.ID] = value
	repository.failures = append(repository.failures, failure)
	return nil
}

func (repository *memoryRepository) LoadForAuthentication(_ context.Context, lookup CredentialLookup) (Credential, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	value, exists := repository.credentials[string(lookup.CredentialID)]
	if !exists || value.TenantID != lookup.TenantID {
		return Credential{}, errors.New("not found")
	}
	return cloneCredential(value), nil
}

func (repository *memoryRepository) CompleteRegistration(_ context.Context, completion RegistrationCompletion) (Credential, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	ceremony, exists := repository.ceremonies[completion.CeremonyID]
	if !exists || ceremony.State != CeremonyClaimed || ceremony.Version != completion.ExpectedCeremonyVersion {
		return Credential{}, errors.New("stale ceremony")
	}
	key := string(completion.Credential.ID)
	if _, duplicate := repository.credentials[key]; duplicate {
		return Credential{}, errors.New("credential collision")
	}
	credential := cloneCredential(completion.Credential)
	repository.credentials[key] = credential
	ceremony.State = CeremonyCompleted
	ceremony.Version++
	repository.ceremonies[completion.CeremonyID] = ceremony
	return cloneCredential(credential), nil
}

func (repository *memoryRepository) CompleteAuthentication(_ context.Context, completion AuthenticationCompletion) (AuthenticationApplyResult, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	ceremony, exists := repository.ceremonies[completion.CeremonyID]
	credential, credentialExists := repository.credentials[string(completion.CredentialID)]
	if !exists || ceremony.State != CeremonyClaimed || ceremony.Version != completion.ExpectedCeremonyVersion ||
		!credentialExists || credential.Status != CredentialActive || credential.Version != completion.ExpectedCredentialVersion ||
		credential.SecurityRevision != completion.ExpectedSecurityRevision ||
		credential.UserID != completion.ResolvedUserID || credential.IdentityEpoch != completion.ExpectedIdentityEpoch ||
		credential.SignCount != completion.ExpectedSignCount ||
		credential.BackupEligible != completion.ExpectedBackupEligible ||
		credential.BackedUp != completion.ExpectedBackedUp ||
		EvaluateSignCount(credential.SignCount, completion.ObservedSignCount) != completion.CounterDisposition {
		return AuthenticationApplyResult{}, errors.New("stale completion")
	}
	credential.Version++
	if completion.CounterDisposition == CounterCloneSuspected ||
		credential.BackupEligible != completion.BackupEligible || credential.BackedUp != completion.BackedUp {
		credential.SecurityRevision++
	}
	credential.BackupEligible = completion.BackupEligible
	credential.BackedUp = completion.BackedUp
	switch completion.CounterDisposition {
	case CounterUnsupported:
		credential.SignCount = 0
	case CounterAdvance:
		credential.SignCount = completion.ObservedSignCount
	case CounterCloneSuspected:
		credential.Status = CredentialCloneSuspected
	}
	repository.credentials[string(completion.CredentialID)] = credential
	ceremony.State = CeremonyCompleted
	ceremony.Version++
	repository.ceremonies[completion.CeremonyID] = ceremony
	return AuthenticationApplyResult{
		CredentialVersion: credential.Version, SecurityRevision: credential.SecurityRevision,
		Status: credential.Status, SignCount: credential.SignCount,
		BackupEligible: credential.BackupEligible, BackedUp: credential.BackedUp,
	}, nil
}

func clonePending(value PendingCeremony) PendingCeremony {
	value.RP = cloneRP(value.RP)
	value.Binding = cloneBinding(value.Binding)
	value.AllowedCredentialIDs = cloneBytes2D(value.AllowedCredentialIDs)
	return value
}

type fakeVerifier struct {
	mu                   sync.Mutex
	registrationCalls    int
	authenticationCalls  int
	registrationMutate   func(*RegistrationProof)
	authenticationMutate func(*AuthenticationProof)
	authenticationHook   func()
	err                  error
}

func (verifier *fakeVerifier) VerifyRegistration(_ context.Context, request RegistrationVerificationRequest) (RegistrationProof, error) {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	verifier.registrationCalls++
	if verifier.err != nil {
		return RegistrationProof{}, verifier.err
	}
	proof := RegistrationProof{
		ChallengeDigest: request.ChallengeDigest, Origin: request.AllowedOrigins[0],
		RPIDHash: sha256.Sum256([]byte(request.RPID)), UserPresent: true, UserVerified: true,
		CredentialID: append([]byte(nil), request.CredentialID...), PublicKey: bytes.Repeat([]byte{0xa1}, 64),
		Discoverable: true, Transports: append([]CredentialTransport(nil), request.Transports...),
		AttestationFormat: "none", AttestationType: AttestationTypeNone,
	}
	if verifier.registrationMutate != nil {
		verifier.registrationMutate(&proof)
	}
	return proof, nil
}

func (verifier *fakeVerifier) VerifyAuthentication(_ context.Context, request AuthenticationVerificationRequest) (AuthenticationProof, error) {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	verifier.authenticationCalls++
	if verifier.authenticationHook != nil {
		verifier.authenticationHook()
	}
	if verifier.err != nil {
		return AuthenticationProof{}, verifier.err
	}
	proof := AuthenticationProof{
		ChallengeDigest: request.ChallengeDigest, Origin: request.AllowedOrigins[0],
		RPIDHash: sha256.Sum256([]byte(request.RPID)), UserPresent: true,
		UserVerified:   request.Policy.UserVerification == UserVerificationRequired,
		CredentialID:   append([]byte(nil), request.CredentialID...),
		UserHandle:     append([]byte(nil), request.UserHandle...),
		SignCount:      request.Credential.SignCount + 1,
		BackupEligible: request.Credential.BackupEligible, BackedUp: request.Credential.BackedUp,
	}
	if verifier.authenticationMutate != nil {
		verifier.authenticationMutate(&proof)
	}
	return proof, nil
}

type kernelFixture struct {
	kernel       *Kernel
	repository   *memoryRepository
	verifier     *fakeVerifier
	now          *time.Time
	rp           RelyingParty
	binding      CeremonyBinding
	userHandle   []byte
	credentialID []byte
}

func newKernelFixture(testingT interface {
	Helper()
	Fatal(...any)
}) kernelFixture {
	testingT.Helper()
	repository := newMemoryRepository()
	verifier := &fakeVerifier{}
	now := testNow
	rp, err := CompileRelyingParty("auth.example.com", []string{"https://auth.example.com"}, 7)
	if err != nil {
		testingT.Fatal(err)
	}
	kernel, err := NewKernel(KernelOptions{
		Ceremonies: repository, Credentials: repository, Verifier: verifier,
		Random: &deterministicReader{}, Now: func() time.Time { return now },
		CeremonyTTL: 5 * time.Minute, OperationTimeout: time.Second, Limits: DefaultLimits(),
	})
	if err != nil {
		testingT.Fatal(err)
	}
	requirement := identity.EffectiveAssuranceRequirement{
		Level:           identity.AssuranceMFA,
		PolicyRevisions: []identity.AssurancePolicyRevision{{PolicyID: testID(20), Revision: 3}},
	}
	registrationRevision := int64(4)
	return kernelFixture{
		kernel: kernel, repository: repository, verifier: verifier, now: &now, rp: rp,
		binding: CeremonyBinding{
			Purpose: PurposeRegistration, TenantID: testID(1), UserID: testID(2),
			IdentityEpoch: 9, SessionID: testID(4), SessionFamilyID: testID(3), AnchorVersion: 6,
			AnchorExpiresAt: now.Add(30 * time.Minute), Action: "webauthn.register", Audience: "tenant-console",
			Requirement: requirement,
			BaselineEvidence: []identity.AssuranceEvidence{{
				Level: identity.AssuranceMFA, Kind: identity.AssuranceEvidenceFactor,
				Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: now,
				FactorRevision: &registrationRevision,
			}},
		},
		userHandle:   bytes.Repeat([]byte{0x44}, stableUserHandleBytes),
		credentialID: bytes.Repeat([]byte{0x55}, 32),
	}
}

func (fixture kernelFixture) registrationPolicy() CeremonyPolicy {
	return CeremonyPolicy{
		RequireUserPresence: true, UserVerification: UserVerificationRequired,
		ResidentKey: ResidentKeyPreferred, Attestation: AttestationNone,
	}
}

func (fixture kernelFixture) register() (StartArtifact, RegistrationArtifact, error) {
	start, err := fixture.kernel.StartRegistration(context.Background(), RegistrationStartRequest{
		RP: fixture.rp, Binding: fixture.binding, Policy: fixture.registrationPolicy(), UserHandle: fixture.userHandle,
	})
	if err != nil {
		return StartArtifact{}, RegistrationArtifact{}, err
	}
	artifact, err := fixture.kernel.FinishRegistrationWithConsumer(context.Background(), RegistrationResponse{
		CeremonyID: start.CeremonyID(), BrowserHandle: start.BrowserHandle(), CredentialID: fixture.credentialID,
		ClientDataJSON: []byte("client-data"), AttestationObject: []byte("attestation"),
		Transports: []CredentialTransport{TransportInternal},
	}, fixture.repository)
	return start, artifact, err
}

func (fixture kernelFixture) startAuthentication(mode AuthenticationMode) (StartArtifact, error) {
	binding := fixture.binding
	binding.Purpose = PurposeStepUpAuthentication
	binding.Action = "case.export"
	primaryRevision := int64(3)
	binding.BaselineEvidence = []identity.AssuranceEvidence{{
		Level: identity.AssurancePrimary, Kind: identity.AssuranceEvidenceFactor,
		Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: *fixture.now,
		FactorRevision: &primaryRevision,
	}}
	policy := fixture.registrationPolicy()
	request := AuthenticationStartRequest{
		RP: fixture.rp, Binding: binding, Policy: policy, Mode: mode,
	}
	if mode == AuthenticationKnownUser {
		request.UserHandle = fixture.userHandle
		request.AllowedCredentialIDs = [][]byte{fixture.credentialID}
	} else {
		binding.Purpose = PurposePrimaryAuthentication
		binding.UserID = identity.EntityID{}
		binding.SessionID = identity.EntityID{}
		binding.SessionFamilyID = identity.EntityID{}
		binding.AnchorVersion = 0
		binding.AnchorExpiresAt = time.Time{}
		binding.IdentityEpoch = 0
		binding.BaselineEvidence = nil
		binding.Action = "login"
		request.Binding = binding
		request.Policy.ResidentKey = ResidentKeyRequired
	}
	return fixture.kernel.StartAuthentication(context.Background(), request)
}

func (fixture kernelFixture) finishAuthentication(start StartArtifact, userHandle []byte) (AuthenticationArtifact, error) {
	return fixture.finishAuthenticationWithContext(context.Background(), start, userHandle)
}

func (fixture kernelFixture) finishAuthenticationWithContext(
	ctx context.Context,
	start StartArtifact,
	userHandle []byte,
) (AuthenticationArtifact, error) {
	return fixture.kernel.FinishAuthenticationWithConsumer(ctx, AuthenticationResponse{
		CeremonyID: start.CeremonyID(), BrowserHandle: start.BrowserHandle(), CredentialID: fixture.credentialID,
		ClientDataJSON: []byte("client-data"), AuthenticatorData: []byte("authenticator-data"),
		Signature: []byte("signature"), UserHandle: userHandle,
	}, fixture.repository)
}

func testID(value byte) identity.EntityID {
	var id identity.EntityID
	id[15] = value
	return id
}

var _ io.Reader = (*deterministicReader)(nil)
