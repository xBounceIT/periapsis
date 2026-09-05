package mfa

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

var mfaTestNow = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

type deterministicReader struct {
	mu   sync.Mutex
	next byte
}

func (reader *deterministicReader) Read(destination []byte) (int, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.next++
	for index := range destination {
		destination[index] = reader.next
	}
	return len(destination), nil
}

type memoryStepUpStore struct {
	mu             sync.Mutex
	challenges     map[ChallengeID]PendingChallenge
	totp           TOTPFactor
	recovery       RecoverySet
	usedRecovery   map[[sha256.Size]byte]struct{}
	sessionVersion uint64
	consumerCalls  int
	totpLoadCalls  int
	recoveryLoads  int
	resultMutate   func(*FactorCompletionResult)
	failContext    error
	lastFailure    ChallengeFailure
	lastClaimedAt  time.Time
}

func newMemoryStepUpStore() *memoryStepUpStore {
	return &memoryStepUpStore{
		challenges: make(map[ChallengeID]PendingChallenge), usedRecovery: make(map[[sha256.Size]byte]struct{}),
		totp: TOTPFactor{
			ID: mfaID(30), TenantID: mfaID(1), UserID: mfaID(2), RecordVersion: 1,
			SecurityRevision: 7, Status: FactorActive, LastCounter: -1,
			Secret: ProtectedTOTPSecret{KeyVersion: 2, Ciphertext: bytes.Repeat([]byte{0xa1}, 32)},
		},
		recovery: RecoverySet{
			ID: mfaID(40), TenantID: mfaID(1), UserID: mfaID(2), RecordVersion: 1,
			SecurityRevision: 8, Status: FactorActive, DigestKeyVersion: 3,
		},
		sessionVersion: 10,
	}
}

func (store *memoryStepUpStore) Create(_ context.Context, value PendingChallenge) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, duplicate := store.challenges[value.ID]; duplicate {
		return errors.New("duplicate")
	}
	store.challenges[value.ID] = clonePendingChallenge(value)
	return nil
}

func (store *memoryStepUpStore) Claim(_ context.Context, claim ChallengeClaim) (ClaimedChallenge, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, exists := store.challenges[claim.ID]
	if !exists || value.State != ChallengePending || value.BrowserDigest != claim.BrowserDigest ||
		!slicesContainsFactor(value.AllowedFactors, claim.Factor) || !claim.ClaimedAt.Before(value.ExpiresAt) {
		return ClaimedChallenge{}, errors.New("claim rejected")
	}
	value.State = ChallengeClaimed
	value.Version++
	store.challenges[claim.ID] = value
	store.lastClaimedAt = claim.ClaimedAt
	return ClaimedChallenge{
		PendingChallenge: clonePendingChallenge(value), ClaimedAt: claim.ClaimedAt, ClaimedFactor: claim.Factor,
	}, nil
}

func (store *memoryStepUpStore) Fail(ctx context.Context, failure ChallengeFailure) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.failContext = ctx.Err()
	if store.failContext != nil {
		return store.failContext
	}
	value, exists := store.challenges[failure.ID]
	if !exists || value.State != ChallengeClaimed || value.Version != failure.ExpectedVersion {
		return errors.New("stale")
	}
	value.State = failure.State
	value.Version++
	store.challenges[failure.ID] = value
	store.lastFailure = failure
	return nil
}

func (store *memoryStepUpStore) LoadTOTP(_ context.Context, tenantID, userID, factorID identity.EntityID) (TOTPFactor, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.totpLoadCalls++
	if store.totp.TenantID != tenantID || store.totp.UserID != userID || store.totp.ID != factorID {
		return TOTPFactor{}, errors.New("not found")
	}
	result := store.totp
	result.Secret = cloneProtectedSecret(result.Secret)
	return result, nil
}

func (store *memoryStepUpStore) LoadRecoverySet(_ context.Context, tenantID, userID identity.EntityID) (RecoverySet, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.recoveryLoads++
	if store.recovery.TenantID != tenantID || store.recovery.UserID != userID {
		return RecoverySet{}, errors.New("not found")
	}
	return store.recovery, nil
}

func (store *memoryStepUpStore) CompleteTOTP(_ context.Context, completion TOTPCompletion) (FactorCompletionResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	challenge, exists := store.challenges[completion.ChallengeID]
	if !exists || challenge.State != ChallengeClaimed || challenge.Version != completion.ExpectedChallengeVersion ||
		store.totp.ID != completion.FactorID || store.totp.RecordVersion != completion.ExpectedFactorVersion ||
		store.totp.SecurityRevision != completion.ExpectedSecurityRevision || completion.Counter <= store.totp.LastCounter ||
		completion.Intent != completionIntent(completion.Binding, AuditTOTPStepUpCompleted, false) ||
		!completion.Session.ValidAt(completion.CompletedAt) {
		return FactorCompletionResult{}, errors.New("stale")
	}
	store.totp.LastCounter = completion.Counter
	store.totp.RecordVersion++
	challenge.State = ChallengeCompleted
	challenge.Version++
	store.challenges[completion.ChallengeID] = challenge
	store.sessionVersion++
	store.consumerCalls++
	result := FactorCompletionResult{
		TenantID: store.totp.TenantID, UserID: store.totp.UserID, IdentityEpoch: completion.Binding.IdentityEpoch,
		FactorSecurityRevision: store.totp.SecurityRevision,
		AuditID:                mfaID(40),
		NewSessionID:           completion.Session.SessionID(),
		NewSessionFamilyID:     completion.Session.FamilyID(),
		ConsumedContinuationID: completion.Binding.ContinuationID,
		SessionVersion:         store.sessionVersion,
	}
	if store.resultMutate != nil {
		store.resultMutate(&result)
	}
	return result, nil
}

func (store *memoryStepUpStore) CompleteRecovery(_ context.Context, completion RecoveryCompletion) (FactorCompletionResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	challenge, exists := store.challenges[completion.ChallengeID]
	_, used := store.usedRecovery[completion.CodeDigest]
	if !exists || challenge.State != ChallengeClaimed || challenge.Version != completion.ExpectedChallengeVersion ||
		store.recovery.ID != completion.SetID || store.recovery.RecordVersion != completion.ExpectedSetVersion ||
		store.recovery.SecurityRevision != completion.ExpectedSecurityRevision || used ||
		completion.Intent != completionIntent(completion.Binding, AuditRecoveryCodeUsed, true) ||
		!completion.Session.ValidAt(completion.CompletedAt) {
		return FactorCompletionResult{}, errors.New("stale or used")
	}
	store.usedRecovery[completion.CodeDigest] = struct{}{}
	store.recovery.RecordVersion++
	challenge.State = ChallengeCompleted
	challenge.Version++
	store.challenges[completion.ChallengeID] = challenge
	store.sessionVersion++
	store.consumerCalls++
	result := FactorCompletionResult{
		TenantID: store.recovery.TenantID, UserID: store.recovery.UserID, IdentityEpoch: completion.Binding.IdentityEpoch,
		FactorSecurityRevision: store.recovery.SecurityRevision,
		AuditID:                mfaID(41),
		NewSessionID:           completion.Session.SessionID(),
		NewSessionFamilyID:     completion.Session.FamilyID(),
		ConsumedContinuationID: completion.Binding.ContinuationID,
		SessionVersion:         store.sessionVersion, RecoveryRestricted: true,
	}
	if store.resultMutate != nil {
		store.resultMutate(&result)
	}
	return result, nil
}

type fakeTOTPVerifier struct {
	mu      sync.Mutex
	counter int64
	err     error
	calls   int
	hook    func()
}

func (verifier *fakeTOTPVerifier) VerifyTOTP(ctx context.Context, request TOTPVerificationRequest) (TOTPProof, error) {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	verifier.calls++
	if verifier.hook != nil {
		verifier.hook()
	}
	if _, ok := ctx.Deadline(); !ok || request.TenantID == (identity.EntityID{}) ||
		request.UserID == (identity.EntityID{}) || request.FactorID == (identity.EntityID{}) ||
		len(request.Code) == 0 || request.Secret.KeyVersion == 0 {
		return TOTPProof{}, errors.New("invalid port request")
	}
	if verifier.err != nil {
		return TOTPProof{}, verifier.err
	}
	return TOTPProof{Counter: verifier.counter}, nil
}

type fakeRecoveryDigester struct {
	err error
}

func (digester *fakeRecoveryDigester) DigestRecoveryCode(_ context.Context, request RecoveryDigestRequest) ([sha256.Size]byte, error) {
	if digester.err != nil {
		return [sha256.Size]byte{}, digester.err
	}
	message := append([]byte(nil), request.SetID[:]...)
	message = append(message, request.Code...)
	digest := sha256.Sum256(message)
	clear(message)
	return digest, nil
}

type stepUpFixture struct {
	stepUp   *StepUp
	store    *memoryStepUpStore
	verifier *fakeTOTPVerifier
	digester *fakeRecoveryDigester
	now      *time.Time
	binding  StepUpBinding
}

func newStepUpFixture(t interface {
	Helper()
	Fatal(...any)
}) stepUpFixture {
	t.Helper()
	store := newMemoryStepUpStore()
	verifier := &fakeTOTPVerifier{counter: 100}
	digester := &fakeRecoveryDigester{}
	now := mfaTestNow
	stepUp, err := NewStepUp(StepUpOptions{
		Challenges: store, Factors: store, TOTP: verifier, Recovery: digester, Consumer: store,
		Random: &deterministicReader{}, Now: func() time.Time { return now },
		ChallengeTTL: 5 * time.Minute, OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	primaryRevision := int64(2)
	return stepUpFixture{
		stepUp: stepUp, store: store, verifier: verifier, digester: digester, now: &now,
		binding: StepUpBinding{
			Flow: FlowExistingSession, TenantID: mfaID(1), UserID: mfaID(2),
			IdentityEpoch: 8, SessionID: mfaID(4), SessionFamilyID: mfaID(3), AnchorVersion: 10,
			AnchorExpiresAt: now.Add(30 * time.Minute), Action: "case.export", Audience: "tenant-console",
			Requirement: identity.EffectiveAssuranceRequirement{
				Level:           identity.AssuranceMFA,
				PolicyRevisions: []identity.AssurancePolicyRevision{{PolicyID: mfaID(9), Revision: 4}},
			},
			BaselineEvidence: []identity.AssuranceEvidence{{
				Level: identity.AssurancePrimary, Kind: identity.AssuranceEvidenceFactor,
				Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: now, FactorRevision: &primaryRevision,
			}},
		},
	}
}

func expectedStepUpBinding(value StepUpBinding) StepUpCompletionBinding {
	return StepUpCompletionBinding{
		Flow: value.Flow, TenantID: value.TenantID, UserID: value.UserID,
		IdentityEpoch: value.IdentityEpoch, SessionID: value.SessionID,
		SessionFamilyID: value.SessionFamilyID, ContinuationID: value.ContinuationID,
		AnchorVersion: value.AnchorVersion, AnchorExpiresAt: value.AnchorExpiresAt,
		Action: value.Action, Audience: value.Audience,
	}
}

func clonePendingChallenge(value PendingChallenge) PendingChallenge {
	value.Binding = cloneStepUpBinding(value.Binding)
	value.AllowedFactors = append([]FactorKind(nil), value.AllowedFactors...)
	return value
}

func slicesContainsFactor(values []FactorKind, target FactorKind) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func mfaID(value byte) identity.EntityID {
	var id identity.EntityID
	id[6] = 0x70
	id[8] = 0x80
	id[15] = value
	return id
}

func mfaTestSessionReservation(binding StepUpBinding, method SessionAuthenticationMethod) SessionReservation {
	familyID := binding.SessionFamilyID
	if familyID == (identity.EntityID{}) {
		familyID = mfaID(30)
	}
	reservation, err := NewSessionReservation(SessionMaterial{
		SessionID: mfaID(31), FamilyID: familyID,
		TokenDigest:          sha256.Sum256([]byte{0x01, byte(method[0])}),
		CSRFDigest:           sha256.Sum256([]byte{0x02, byte(method[0])}),
		AuthenticationMethod: method,
		IdleExpiresAt:        mfaTestNow.Add(time.Hour), AbsoluteExpiresAt: mfaTestNow.Add(24 * time.Hour),
	}, mfaTestNow)
	if err != nil {
		panic(err)
	}
	return reservation
}
