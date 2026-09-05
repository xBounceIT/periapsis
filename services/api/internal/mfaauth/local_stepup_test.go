package mfaauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

type gateStub struct {
	mu       sync.Mutex
	decision AdmissionDecision
	err      error
	calls    int
}

func (gate *gateStub) Admit(_ context.Context, _ AdmissionContext, _ time.Time) (AdmissionDecision, error) {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	gate.calls++
	return gate.decision, gate.err
}

type localSourceStub struct {
	snapshot AuthoritySnapshot
	err      error
	calls    int
}

func (source *localSourceStub) ResolveLocalStepUp(_ context.Context, _ AuthorityLookup) (AuthoritySnapshot, error) {
	source.calls++
	return source.snapshot, source.err
}

type localKernelStub struct {
	startCalls    int
	totpCalls     int
	recoveryCalls int
	totp          func(mfa.TOTPCompletionRequest) (mfa.StepUpArtifact, error)
	recovery      func(mfa.RecoveryCompletionRequest) (mfa.StepUpArtifact, error)
}

func (kernel *localKernelStub) Start(_ context.Context, _ mfa.StepUpStartRequest) (mfa.StepUpStartArtifact, error) {
	kernel.startCalls++
	return mfa.StepUpStartArtifact{}, mfa.ErrStepUpRejected
}

func (kernel *localKernelStub) CompleteTOTP(_ context.Context, request mfa.TOTPCompletionRequest) (mfa.StepUpArtifact, error) {
	kernel.totpCalls++
	return kernel.totp(request)
}

func (kernel *localKernelStub) CompleteRecovery(_ context.Context, request mfa.RecoveryCompletionRequest) (mfa.StepUpArtifact, error) {
	kernel.recoveryCalls++
	return kernel.recovery(request)
}

func TestAdmissionBlocksBeforeAuthorityOrFactorLookup(t *testing.T) {
	gate := &gateStub{decision: AdmissionDecision{Outcome: AdmissionLocked, RetryAt: testNow.Add(2 * time.Minute)}}
	source := &localSourceStub{}
	kernel := &localKernelStub{}
	service, err := NewLocalStepUp(LocalStepUpOptions{
		Source: source, Admissions: gate, Kernel: kernel, Now: func() time.Time { return testNow },
		OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Start(context.Background(), StartLocalStepUpCommand{Lookup: AuthorityLookup{
		Flow: mfa.FlowExistingSession, AnchorID: testID(3), Action: "case.export", Audience: "tenant-console",
		Admission: validAdmissionContext(),
	}})
	var limited *RateLimitError
	if !errors.As(err, &limited) || !limited.Locked() || limited.RetryAfter() != 2*time.Minute {
		t.Fatalf("got %#v", err)
	}
	if source.calls != 0 || kernel.startCalls != 0 {
		t.Fatal("blocked request reached an authority/factor lookup")
	}
}

func TestAdmissionRejectsUnboundedRetryProjection(t *testing.T) {
	gate := &gateStub{decision: AdmissionDecision{
		Outcome: AdmissionLocked, RetryAt: testNow.Add(maximumAdmissionRetry + time.Millisecond),
	}}
	source := &localSourceStub{}
	service, err := NewLocalStepUp(LocalStepUpOptions{
		Source: source, Admissions: gate, Kernel: &localKernelStub{}, Now: func() time.Time { return testNow },
		OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Start(context.Background(), StartLocalStepUpCommand{Lookup: AuthorityLookup{
		Flow: mfa.FlowExistingSession, AnchorID: testID(3), Action: "case.export", Audience: "tenant-console",
		Admission: validAdmissionContext(),
	}})
	if !errors.Is(err, ErrUnavailable) || source.calls != 0 {
		t.Fatalf("err = %v, source calls = %d", err, source.calls)
	}
}

func TestAuthorityLookupMismatchDeniesBeforeChallengeCreation(t *testing.T) {
	localRevision := int64(2)
	snapshot, err := NewAuthoritySnapshot(authorityInput([]identity.AssuranceEvidence{{
		Level: identity.AssurancePrimary, Kind: identity.AssuranceEvidenceFactor,
		Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: testNow, FactorRevision: &localRevision,
	}}, false, mfa.FlowExistingSession))
	if err != nil {
		t.Fatal(err)
	}
	gate := &gateStub{decision: AdmissionDecision{Outcome: AdmissionAllowed}}
	source := &localSourceStub{snapshot: snapshot}
	kernel := &localKernelStub{}
	service, err := NewLocalStepUp(LocalStepUpOptions{
		Source: source, Admissions: gate, Kernel: kernel, Now: func() time.Time { return testNow },
		OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Start(context.Background(), StartLocalStepUpCommand{Lookup: AuthorityLookup{
		Flow: mfa.FlowExistingSession, AnchorID: testID(99), Action: "case.export", Audience: "tenant-console",
		Admission: validAdmissionContext(),
	}})
	if !errors.Is(err, ErrDenied) || kernel.startCalls != 0 {
		t.Fatalf("err = %v, kernel calls = %d", err, kernel.startCalls)
	}
}

func TestStaleAuthoritySnapshotCannotCreateChallenge(t *testing.T) {
	localRevision := int64(2)
	snapshot, err := NewAuthoritySnapshot(authorityInput([]identity.AssuranceEvidence{{
		Level: identity.AssurancePrimary, Kind: identity.AssuranceEvidenceFactor,
		Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: testNow, FactorRevision: &localRevision,
	}}, false, mfa.FlowExistingSession))
	if err != nil {
		t.Fatal(err)
	}
	kernel := &localKernelStub{}
	service, err := NewLocalStepUp(LocalStepUpOptions{
		Source:     &localSourceStub{snapshot: snapshot},
		Admissions: &gateStub{decision: AdmissionDecision{Outcome: AdmissionAllowed}}, Kernel: kernel,
		Now: func() time.Time { return testNow.Add(time.Millisecond) }, OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Start(context.Background(), StartLocalStepUpCommand{Lookup: AuthorityLookup{
		Flow: mfa.FlowExistingSession, AnchorID: testID(3), Action: "case.export", Audience: "tenant-console",
		Admission: validAdmissionContext(),
	}})
	if !errors.Is(err, ErrDenied) || kernel.startCalls != 0 {
		t.Fatalf("err = %v, kernel calls = %d", err, kernel.startCalls)
	}
}

func TestLocalCompletionCopiesProofAndRequiresExplicitRecoveryRestriction(t *testing.T) {
	gate := &gateStub{decision: AdmissionDecision{Outcome: AdmissionAllowed}}
	source := &localSourceStub{}
	newSessionID, newFamilyID := testID(20), testID(4)
	factorRevision := int64(6)
	kernel := &localKernelStub{}
	totpArtifact := mfa.StepUpArtifact{
		TenantID: testID(1), UserID: testID(2), IdentityEpoch: 4,
		SessionID: testID(3), SessionFamilyID: testID(4),
		NewSessionID: newSessionID, NewSessionFamilyID: newFamilyID, SessionVersion: 6,
		Action: "case.export", Audience: "tenant-console", NewEvidence: identity.AssuranceEvidence{
			Level: identity.AssuranceMFA, Kind: identity.AssuranceEvidenceFactor,
			Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: testNow,
			FactorRevision: &factorRevision,
		},
	}
	kernel.totp = func(request mfa.TOTPCompletionRequest) (mfa.StepUpArtifact, error) {
		if string(request.Code) != "123456" {
			t.Fatalf("code = %q", request.Code)
		}
		request.Code[0] = '9'
		return totpArtifact, nil
	}
	recoveryArtifact := totpArtifact
	recoveryArtifact.RecoveryRestricted = true
	recoveryArtifact.NewEvidence.Kind = identity.AssuranceEvidenceRecovery
	kernel.recovery = func(mfa.RecoveryCompletionRequest) (mfa.StepUpArtifact, error) {
		return recoveryArtifact, nil
	}
	service, err := NewLocalStepUp(LocalStepUpOptions{
		Source: source, Admissions: gate, Kernel: kernel, Now: func() time.Time { return testNow },
		OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	code := []byte("123456")
	totpReservation := testSessionReservation(t, testNow, mfa.SessionAuthenticationTOTP, 20, 4)
	totpChallenge := challengeID(1)
	totpBrowser := opaqueHandle(2)
	totpFactorID := testID(7)
	result, err := service.CompleteTOTP(context.Background(), CompleteTOTPCommand{
		Ticket: testLocalCompletionTicket(
			totpArtifact, totpChallenge, totpBrowser, CompletionFactorTOTP, totpFactorID[:], totpReservation,
		),
		Code: code, Session: totpReservation,
	})
	if err != nil || result.RecoveryRestricted || !bytes.Equal(code, []byte("123456")) {
		t.Fatalf("result = %#v, code = %q, err = %v", result, code, err)
	}
	recoveryReservation := testSessionReservation(t, testNow, mfa.SessionAuthenticationRecovery, 20, 4)
	recoveryChallenge := challengeID(2)
	recoveryBrowser := opaqueHandle(3)
	recoverySetID := testID(8)
	recovery, err := service.CompleteRecovery(context.Background(), CompleteRecoveryCommand{
		Ticket: testLocalCompletionTicket(
			recoveryArtifact, recoveryChallenge, recoveryBrowser,
			CompletionFactorRecovery, recoverySetID[:], recoveryReservation,
		),
		Code: []byte("RECOVERY-CODE-1234"), Session: recoveryReservation,
	})
	if err != nil || !recovery.RecoveryRestricted {
		t.Fatalf("recovery = %#v, err = %v", recovery, err)
	}
}

func TestLocalCompletionRejectsMalformedAuthorityArtifacts(t *testing.T) {
	revision := int64(6)
	base := mfa.StepUpArtifact{
		TenantID: testID(1), UserID: testID(2), IdentityEpoch: 4,
		SessionID: testID(3), SessionFamilyID: testID(4),
		NewSessionID: testID(20), NewSessionFamilyID: testID(4), Action: "case.export",
		Audience: "tenant-console", SessionVersion: 6,
		NewEvidence: identity.AssuranceEvidence{
			Level: identity.AssuranceMFA, Kind: identity.AssuranceEvidenceFactor,
			Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: testNow, FactorRevision: &revision,
		},
	}
	tests := map[string]func(*mfa.StepUpArtifact){
		"missing tenant": func(value *mfa.StepUpArtifact) { value.TenantID = identity.EntityID{} },
		"missing user":   func(value *mfa.StepUpArtifact) { value.UserID = identity.EntityID{} },
		"missing epoch":  func(value *mfa.StepUpArtifact) { value.IdentityEpoch = 0 },
		"unsafe audience": func(value *mfa.StepUpArtifact) {
			value.Audience = "tenant\u202econsole"
		},
		"federated evidence": func(value *mfa.StepUpArtifact) {
			value.NewEvidence.Source = identity.AssuranceSource{ProviderID: testID(8), BindingID: testID(9)}
		},
		"wrong family": func(value *mfa.StepUpArtifact) { value.NewSessionFamilyID = testID(99) },
		"same session": func(value *mfa.StepUpArtifact) { value.NewSessionID = value.SessionID },
		"future evidence": func(value *mfa.StepUpArtifact) {
			value.NewEvidence.AuthenticatedAt = testNow.Add(time.Minute)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := base
			mutate(&value)
			if validLocalStepUpArtifact(value, testNow.Add(-time.Second), testNow, false) {
				t.Fatal("malformed authority artifact was accepted")
			}
		})
	}
}

func validAdmissionContext() AdmissionContext {
	return AdmissionContext{
		OperationID: testID(100), NetworkDigest: admissionDigest(1),
		PrincipalDigest: admissionDigest(2), ResourceDigest: admissionDigest(3),
	}
}

func admissionDigest(value byte) AdmissionDigest {
	var digest AdmissionDigest
	digest[31] = value
	return digest
}

func opaqueHandle(value byte) []byte {
	raw := bytes.Repeat([]byte{value}, 32)
	return []byte(base64.RawURLEncoding.EncodeToString(raw))
}

func challengeID(value byte) mfa.ChallengeID {
	var id mfa.ChallengeID
	id[31] = value
	return id
}
