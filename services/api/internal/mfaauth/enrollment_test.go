package mfaauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/mfa"
)

type enrollmentSourceStub struct {
	authority AuthoritySnapshot
	calls     int
}

func (source *enrollmentSourceStub) ResolveFactorEnrollment(
	context.Context,
	AuthorityLookup,
) (AuthoritySnapshot, error) {
	source.calls++
	return source.authority, nil
}

type totpMaterialSourceStub struct {
	material TOTPEnrollmentMaterial
}

func (source *totpMaterialSourceStub) NewTOTPEnrollmentMaterial(
	context.Context,
	identity.EntityID,
	identity.EntityID,
) (TOTPEnrollmentMaterial, error) {
	value := source.material
	value.BrowserHandle = append([]byte(nil), value.BrowserHandle...)
	value.ProtectedSecret = cloneProtectedSecret(value.ProtectedSecret)
	value.DisplaySecret = append([]byte(nil), value.DisplaySecret...)
	value.ProvisioningURI = append([]byte(nil), value.ProvisioningURI...)
	return value, nil
}

type totpVerifierStub struct {
	counter int64
	err     error
}

func (verifier *totpVerifierStub) VerifyTOTP(
	_ context.Context,
	request mfa.TOTPVerificationRequest,
) (mfa.TOTPProof, error) {
	if request.TenantID == (identity.EntityID{}) || request.UserID == (identity.EntityID{}) ||
		request.FactorID == (identity.EntityID{}) || len(request.Code) == 0 || len(request.Secret.Ciphertext) == 0 {
		return mfa.TOTPProof{}, errors.New("missing proof")
	}
	return mfa.TOTPProof{Counter: verifier.counter}, verifier.err
}

type totpEnrollmentStoreStub struct {
	mu          sync.Mutex
	start       StartTOTPEnrollmentWrite
	claimed     bool
	completed   int
	failed      int
	applyMutate func(*TOTPEnrollmentApplyResult)
}

func (store *totpEnrollmentStoreStub) StartTOTPEnrollment(
	_ context.Context,
	request StartTOTPEnrollmentWrite,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.start = request
	store.start.ProtectedSecret = cloneProtectedSecret(request.ProtectedSecret)
	return nil
}

func (store *totpEnrollmentStoreStub) ClaimTOTPEnrollment(
	_ context.Context,
	request ClaimTOTPEnrollmentRequest,
) (ClaimedTOTPEnrollment, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.claimed || request.EnrollmentID != store.start.EnrollmentID ||
		request.BrowserDigest != store.start.BrowserDigest || !request.ClaimedAt.Before(store.start.ExpiresAt) {
		return ClaimedTOTPEnrollment{}, errors.New("claimed")
	}
	store.claimed = true
	return ClaimedTOTPEnrollment{
		EnrollmentID: store.start.EnrollmentID, FactorID: store.start.FactorID, Version: 2,
		BrowserDigest: request.BrowserDigest,
		Binding:       store.start.Binding, ProtectedSecret: cloneProtectedSecret(store.start.ProtectedSecret),
		CreatedAt: store.start.CreatedAt, ExpiresAt: store.start.ExpiresAt, ClaimedAt: request.ClaimedAt,
	}, nil
}

func (store *totpEnrollmentStoreStub) CompleteTOTPEnrollment(
	_ context.Context,
	request CompleteTOTPEnrollmentWrite,
) (TOTPEnrollmentApplyResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.claimed || request.ExpectedVersion != 2 || request.AcceptedCounter < 0 ||
		request.Binding.Action != "case.export" || request.Audit.Action != "case.export" {
		return TOTPEnrollmentApplyResult{}, errors.New("stale")
	}
	store.completed++
	result := TOTPEnrollmentApplyResult{
		TenantID: request.Binding.TenantID, UserID: request.Binding.UserID,
		IdentityEpoch: request.Binding.IdentityEpoch,
		FactorID:      request.FactorID, FactorSecurityRevision: 1, AuditID: testID(50),
		Mutation: SessionRotate, NewSessionID: testID(20),
		NewSessionFamilyID: request.Binding.SessionFamilyID, SessionVersion: 6,
	}
	if request.Binding.Flow == mfa.FlowPostPrimaryContinuation {
		result.Mutation = SessionRetainContinuation
		result.NewSessionID = identity.EntityID{}
		result.NewSessionFamilyID = identity.EntityID{}
		result.RetainedContinuationID = request.Binding.ContinuationID
		result.SessionVersion = request.Binding.AnchorVersion + 1
	}
	if store.applyMutate != nil {
		store.applyMutate(&result)
	}
	return result, nil
}

func (store *totpEnrollmentStoreStub) FailTOTPEnrollment(
	context.Context,
	FailTOTPEnrollmentWrite,
) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.failed++
	return nil
}

func TestFactorEnrollmentIntentsRetainContinuationWithoutCreatingSession(t *testing.T) {
	continuationID := testID(44)
	binding := mfa.StepUpBinding{
		Flow:     mfa.FlowPostPrimaryContinuation,
		TenantID: testID(1), UserID: testID(2), IdentityEpoch: 3,
		ContinuationID: continuationID, AnchorVersion: 7,
		AnchorExpiresAt: testNow.Add(15 * time.Minute),
		Action:          "session.create", Audience: "api",
	}
	audit, session, ok := factorEnrollmentIntents(
		binding,
		AuditTOTPEnrolled,
		testNow,
		mfa.SessionReservation{},
		[32]byte{1},
	)
	if !ok || audit.Kind != AuditTOTPEnrolled || audit.Action != "session.create" ||
		session.Mutation != SessionRetainContinuation ||
		session.ExpectedContinuationID != continuationID || !session.Reservation.IsZero() {
		t.Fatalf("continuation enrollment intents = audit %#v session %#v ok %t", audit, session, ok)
	}
}

type recoveryGeneratorStub struct {
	batch   RecoveryCodeBatch
	request RecoveryCodeGenerationRequest
}

func (generator *recoveryGeneratorStub) GenerateRecoveryCodes(
	_ context.Context,
	request RecoveryCodeGenerationRequest,
) (RecoveryCodeBatch, error) {
	generator.request = request
	result := RecoveryCodeBatch{
		SetID: generator.batch.SetID, DigestKeyVersion: generator.batch.DigestKeyVersion,
		Codes: make([]RecoveryCodeMaterial, len(generator.batch.Codes)),
	}
	for index := range generator.batch.Codes {
		result.Codes[index] = RecoveryCodeMaterial{
			Code: append([]byte(nil), generator.batch.Codes[index].Code...), Digest: generator.batch.Codes[index].Digest,
		}
	}
	return result, nil
}

type recoveryStoreStub struct {
	request ReplaceRecoveryCodesWrite
	calls   int
}

func (store *recoveryStoreStub) ReplaceRecoveryCodes(
	_ context.Context,
	request ReplaceRecoveryCodesWrite,
) (RecoveryCodesApplyResult, error) {
	store.calls++
	store.request = request
	store.request.Digests = append([]RecoveryCodeDigest(nil), request.Digests...)
	return RecoveryCodesApplyResult{
		TenantID: request.Binding.TenantID, UserID: request.Binding.UserID,
		IdentityEpoch: request.Binding.IdentityEpoch,
		SetID:         request.NewSetID, SetVersion: 1, AuditID: testID(51), NewSessionID: testID(21),
		NewSessionFamilyID: request.Binding.SessionFamilyID, SessionVersion: request.Binding.AnchorVersion + 1,
	}, nil
}

func TestTOTPEnrollmentIsOneTimeAndCouplesFactorSessionAudit(t *testing.T) {
	service, store, lookup := newFactorEnrollmentService(t)
	start, err := service.StartTOTP(context.Background(), lookup)
	if err != nil || start.EnrollmentID() == (identity.EntityID{}) || len(start.DisplaySecret()) == 0 ||
		!strings.HasPrefix(start.ProvisioningURI(), "otpauth://totp/") {
		t.Fatalf("start = %#v, err = %v", start, err)
	}
	reservation := testSessionReservation(t, testNow, mfa.SessionAuthenticationTOTP, 20, 4)
	command := FinishTOTPEnrollmentCommand{
		Ticket:  testEnrollmentCompletionTicket(start, store.start.Binding, reservation, [32]byte{}),
		Code:    []byte("123456"),
		Session: reservation,
	}
	result, err := service.FinishTOTP(context.Background(), command)
	if err != nil || result.FactorID != start.FactorID() || result.AuditID == (identity.EntityID{}) ||
		result.NewSessionID == (identity.EntityID{}) || result.NewSessionFamilyID != testID(4) {
		t.Fatalf("result = %#v, err = %v", result, err)
	}
	if _, err := service.FinishTOTP(context.Background(), command); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("replay = %v", err)
	}
	store.mu.Lock()
	completed := store.completed
	store.mu.Unlock()
	if completed != 1 {
		t.Fatalf("completion count = %d", completed)
	}
}

func TestContinuationTOTPEnrollmentRetainsExactAnchorWithoutSessionReservation(t *testing.T) {
	service, store, lookup := newFactorEnrollmentService(t)
	lookup = configureContinuationEnrollment(t, service, lookup)
	start, err := service.StartTOTP(context.Background(), lookup)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.FinishTOTP(context.Background(), FinishTOTPEnrollmentCommand{
		Ticket: testEnrollmentCompletionTicket(
			start, store.start.Binding, mfa.SessionReservation{}, lookup.ContinuationReceiptDigest,
		),
		Code: []byte("123456"),
	})
	if err != nil || result.Mutation != SessionRetainContinuation ||
		result.RetainedContinuationID != lookup.AnchorID || result.NewSessionID != (identity.EntityID{}) ||
		result.NewSessionFamilyID != (identity.EntityID{}) ||
		store.start.Binding.ContinuationID != lookup.AnchorID ||
		store.start.Binding.SessionID != (identity.EntityID{}) {
		t.Fatalf("result = %#v, start binding = %#v, err = %v", result, store.start.Binding, err)
	}
	if store.completed != 1 {
		t.Fatalf("completion count = %d", store.completed)
	}
}

func TestContinuationTOTPEnrollmentRejectsMixedPossessionBeforeMutation(t *testing.T) {
	for name, configure := range map[string]func(*CompletionTicketResolutionInput){
		"missing receipt": func(resolution *CompletionTicketResolutionInput) {
			resolution.ContinuationReceiptDigest = [32]byte{}
		},
		"wrong continuation": func(resolution *CompletionTicketResolutionInput) {
			resolution.ContinuationID = testID(99)
		},
	} {
		t.Run(name, func(t *testing.T) {
			service, store, lookup := newFactorEnrollmentService(t)
			lookup = configureContinuationEnrollment(t, service, lookup)
			start, err := service.StartTOTP(context.Background(), lookup)
			if err != nil {
				t.Fatal(err)
			}
			ticket := testEnrollmentCompletionTicket(
				start, store.start.Binding, mfa.SessionReservation{}, lookup.ContinuationReceiptDigest,
			)
			configure(&ticket.state.resolution)
			command := FinishTOTPEnrollmentCommand{Ticket: ticket, Code: []byte("123456")}
			if _, err := service.FinishTOTP(context.Background(), command); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("FinishTOTP() error = %v", err)
			}
			if store.completed != 0 {
				t.Fatalf("store = completed %d failed %d", store.completed, store.failed)
			}
		})
	}
}

func TestConcurrentTOTPEnrollmentCompletionHasOneWinner(t *testing.T) {
	service, _, lookup := newFactorEnrollmentService(t)
	start, err := service.StartTOTP(context.Background(), lookup)
	if err != nil {
		t.Fatal(err)
	}
	reservation := testSessionReservation(t, testNow, mfa.SessionAuthenticationTOTP, 20, 4)
	command := FinishTOTPEnrollmentCommand{
		Ticket:  testEnrollmentCompletionTicket(start, service.totpStore.(*totpEnrollmentStoreStub).start.Binding, reservation, [32]byte{}),
		Code:    []byte("123456"),
		Session: reservation,
	}
	var winners atomic.Int32
	var wait sync.WaitGroup
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, completeErr := service.FinishTOTP(context.Background(), command); completeErr == nil {
				winners.Add(1)
			} else if !errors.Is(completeErr, ErrAuthentication) {
				t.Errorf("unexpected error: %v", completeErr)
			}
		}()
	}
	wait.Wait()
	if winners.Load() != 1 {
		t.Fatalf("winners = %d", winners.Load())
	}
}

func TestTOTPEnrollmentExpiryNeverExceedsAuthorityAnchor(t *testing.T) {
	service, _, lookup := newFactorEnrollmentService(t)
	source := service.source.(*enrollmentSourceStub)
	source.authority.anchorExpiresAt = testNow.Add(2 * time.Minute)
	artifact, err := service.StartTOTP(context.Background(), lookup)
	if err != nil || !artifact.ExpiresAt().Equal(source.authority.anchorExpiresAt) {
		t.Fatalf("expires = %s, anchor = %s, err = %v", artifact.ExpiresAt(), source.authority.anchorExpiresAt, err)
	}
}

func TestTOTPVerificationFailureTerminallyRecordsAttempt(t *testing.T) {
	service, store, lookup := newFactorEnrollmentService(t)
	service.totpVerifier = &totpVerifierStub{err: errors.New("invalid")}
	start, err := service.StartTOTP(context.Background(), lookup)
	if err != nil {
		t.Fatal(err)
	}
	reservation := testSessionReservation(t, testNow, mfa.SessionAuthenticationTOTP, 20, 4)
	_, err = service.FinishTOTP(context.Background(), FinishTOTPEnrollmentCommand{
		Ticket: testEnrollmentCompletionTicket(
			start, store.start.Binding, reservation, [32]byte{},
		),
		Code: []byte("123456"), Session: reservation,
	})
	store.mu.Lock()
	failed := store.failed
	store.mu.Unlock()
	if !errors.Is(err, ErrAuthentication) || failed != 1 {
		t.Fatalf("err = %v, failures = %d", err, failed)
	}
}

func TestTOTPEnrollmentRejectsWrongCommittedAuthorityProjection(t *testing.T) {
	tests := map[string]func(*TOTPEnrollmentApplyResult){
		"tenant": func(result *TOTPEnrollmentApplyResult) { result.TenantID = testID(99) },
		"user":   func(result *TOTPEnrollmentApplyResult) { result.UserID = testID(99) },
		"identity epoch": func(result *TOTPEnrollmentApplyResult) {
			result.IdentityEpoch++
		},
		"session version": func(result *TOTPEnrollmentApplyResult) { result.SessionVersion = 5 },
		"restriction retained": func(result *TOTPEnrollmentApplyResult) {
			result.RecoveryRestricted = true
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			service, store, lookup := newFactorEnrollmentService(t)
			store.applyMutate = mutate
			start, err := service.StartTOTP(context.Background(), lookup)
			if err != nil {
				t.Fatal(err)
			}
			reservation := testSessionReservation(t, testNow, mfa.SessionAuthenticationTOTP, 20, 4)
			_, err = service.FinishTOTP(context.Background(), FinishTOTPEnrollmentCommand{
				Ticket:  testEnrollmentCompletionTicket(start, store.start.Binding, reservation, [32]byte{}),
				Code:    []byte("123456"),
				Session: reservation,
			})
			if !errors.Is(err, ErrAuthentication) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestRecoveryRegenerationPersistsOnlyDigestsAndRotatesSession(t *testing.T) {
	service, _, lookup := newFactorEnrollmentService(t)
	artifact, err := service.RegenerateRecoveryCodes(context.Background(), RegenerateRecoveryCodesCommand{
		Lookup: lookup, Session: testSessionReservation(t, testNow, mfa.SessionAuthenticationTOTP, 21, 4),
	})
	if err != nil || len(artifact.Codes()) != 10 || artifact.SetID() == (identity.EntityID{}) ||
		artifact.NewSessionID() != testID(21) || artifact.NewSessionFamilyID() != testID(4) ||
		artifact.SessionVersion() != 6 {
		t.Fatalf("artifact = %#v, err = %v", artifact, err)
	}
	store := service.recoveryStore.(*recoveryStoreStub)
	formatted := fmt.Sprintf("%#v", store.request)
	for _, code := range artifact.Codes() {
		if strings.Contains(formatted, string(code)) {
			t.Fatalf("plaintext recovery code reached persistence request: %s", formatted)
		}
	}
	if store.calls != 1 || len(store.request.Digests) != 10 || store.request.DigestKeyVersion != 1 ||
		service.recovery.(*recoveryGeneratorStub).request.TenantID != testID(1) ||
		service.recovery.(*recoveryGeneratorStub).request.UserID != testID(2) ||
		service.recovery.(*recoveryGeneratorStub).request.Count != 10 ||
		store.request.Session.Mutation != SessionRotate ||
		store.request.Audit.Kind != AuditRecoveryRegenerated || store.request.Audit.Action != "case.export" {
		t.Fatalf("request = %#v", store.request)
	}
}

func TestInitialRecoveryCodeIssueUsesAbsentSetCompareAndSwap(t *testing.T) {
	service, _, lookup := newFactorEnrollmentService(t)
	source := service.source.(*enrollmentSourceStub)
	input := authorityInput(source.authority.evidence, false, mfa.FlowExistingSession)
	input.RecoveryAvailable = false
	input.RecoverySetID = identity.EntityID{}
	input.RecoverySetVersion = 0
	authority, err := NewAuthoritySnapshot(input)
	if err != nil {
		t.Fatal(err)
	}
	source.authority = authority

	artifact, err := service.RegenerateRecoveryCodes(context.Background(), RegenerateRecoveryCodesCommand{
		Lookup: lookup, Session: testSessionReservation(t, testNow, mfa.SessionAuthenticationTOTP, 21, 4),
	})
	if err != nil || len(artifact.Codes()) != 10 {
		t.Fatalf("artifact = %#v, err = %v", artifact, err)
	}
	store := service.recoveryStore.(*recoveryStoreStub)
	if store.request.ExpectedSetID != (identity.EntityID{}) || store.request.ExpectedSetVersion != 0 ||
		store.request.Audit.Kind != AuditRecoveryCreated {
		t.Fatalf("initial request = %#v", store.request)
	}
}

func TestTOTPEnrollmentMaterialRejectsNonCanonicalSecretAndURI(t *testing.T) {
	valid := TOTPEnrollmentMaterial{
		EnrollmentID: testID(30), FactorID: testID(31), BrowserHandle: opaqueHandle(7),
		ProtectedSecret: mfa.ProtectedTOTPSecret{KeyVersion: 1, Ciphertext: bytes.Repeat([]byte{8}, 32)},
		DisplaySecret:   []byte("JBSWY3DPEHPK3PXP"),
		ProvisioningURI: []byte("otpauth://totp/Periapsis:operator?secret=JBSWY3DPEHPK3PXP"),
	}
	valid.BrowserDigest = sha256.Sum256(valid.BrowserHandle)
	tests := map[string]func(*TOTPEnrollmentMaterial){
		"key version": func(value *TOTPEnrollmentMaterial) {
			value.ProtectedSecret.KeyVersion = maximumMFAKeyVersion + 1
		},
		"lowercase secret": func(value *TOTPEnrollmentMaterial) {
			value.DisplaySecret = []byte("jbswy3dpehpk3pxp")
			value.ProvisioningURI = []byte("otpauth://totp/Periapsis:operator?secret=jbswy3dpehpk3pxp")
		},
		"secret mismatch": func(value *TOTPEnrollmentMaterial) {
			value.ProvisioningURI = []byte("otpauth://totp/Periapsis:operator?secret=MZXW6YTBOI")
		},
		"userinfo": func(value *TOTPEnrollmentMaterial) {
			value.ProvisioningURI = []byte("otpauth://operator@totp/Periapsis?secret=JBSWY3DPEHPK3PXP")
		},
		"fragment": func(value *TOTPEnrollmentMaterial) {
			value.ProvisioningURI = append(value.ProvisioningURI, []byte("#secret")...)
		},
		"bidi control": func(value *TOTPEnrollmentMaterial) {
			value.ProvisioningURI = []byte("otpauth://totp/Periapsis\u202eoperator?secret=JBSWY3DPEHPK3PXP")
		},
		"encoded control": func(value *TOTPEnrollmentMaterial) {
			value.ProvisioningURI = []byte("otpauth://totp/Periapsis%0Aoperator?secret=JBSWY3DPEHPK3PXP")
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := valid
			value.BrowserHandle = append([]byte(nil), valid.BrowserHandle...)
			value.ProtectedSecret = cloneProtectedSecret(valid.ProtectedSecret)
			value.DisplaySecret = append([]byte(nil), valid.DisplaySecret...)
			value.ProvisioningURI = append([]byte(nil), valid.ProvisioningURI...)
			mutate(&value)
			if validTOTPEnrollmentMaterial(value) {
				t.Fatal("hostile provisioning material was accepted")
			}
		})
	}
}

func TestOneTimeArtifactsCanBeDestroyedAfterTransport(t *testing.T) {
	totp := TOTPEnrollmentStartArtifact{
		browserHandle: []byte("browser-secret"), displaySecret: []byte("display-secret"),
		uri: []byte("otpauth://totp/secret"),
	}
	totp.Destroy()
	if len(totp.BrowserHandle()) != 0 || len(totp.DisplaySecret()) != 0 || totp.ProvisioningURI() != "" {
		t.Fatalf("TOTP artifact survived Destroy: %#v", totp)
	}
	recovery := RecoveryCodesArtifact{codes: [][]byte{[]byte("RECOVERY-CODE-0001")}}
	recovery.Destroy()
	if len(recovery.Codes()) != 0 {
		t.Fatalf("recovery artifact survived Destroy: %#v", recovery)
	}
}

func TestClaimedTOTPEnrollmentCannotPredateCreation(t *testing.T) {
	service, store, lookup := newFactorEnrollmentService(t)
	start, err := service.StartTOTP(context.Background(), lookup)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	claimed := ClaimedTOTPEnrollment{
		EnrollmentID: store.start.EnrollmentID, FactorID: store.start.FactorID, Version: 2,
		BrowserDigest: store.start.BrowserDigest,
		Binding:       store.start.Binding, ProtectedSecret: cloneProtectedSecret(store.start.ProtectedSecret),
		CreatedAt: store.start.CreatedAt, ExpiresAt: store.start.ExpiresAt,
		ClaimedAt: store.start.CreatedAt.Add(-time.Millisecond),
	}
	store.mu.Unlock()
	if validClaimedTOTPEnrollment(
		claimed, start.EnrollmentID(), claimed.BrowserDigest, claimed.ClaimedAt, claimed.ClaimedAt, time.Second,
	) {
		t.Fatal("claim predating creation was accepted")
	}
	claimed.ClaimedAt = claimed.CreatedAt
	wrongDigest := claimed.BrowserDigest
	wrongDigest[0] ^= 0xff
	if validClaimedTOTPEnrollment(
		claimed, start.EnrollmentID(), wrongDigest, claimed.ClaimedAt, claimed.ClaimedAt, time.Second,
	) {
		t.Fatal("claim with a mismatched browser digest was accepted")
	}
}

func TestEnrollmentFormattingRedactsAllOneTimeMaterial(t *testing.T) {
	canary := "RECOVERY-OR-TOTP-CANARY"
	values := []any{
		TOTPEnrollmentMaterial{DisplaySecret: []byte(canary), ProvisioningURI: []byte(canary)},
		TOTPEnrollmentStartArtifact{displaySecret: []byte(canary), uri: []byte(canary)},
		FinishTOTPEnrollmentCommand{Code: []byte(canary)},
		RecoveryCodeMaterial{Code: []byte(canary)}, RecoveryCodeBatch{Codes: []RecoveryCodeMaterial{{Code: []byte(canary)}}},
		RecoveryCodesArtifact{codes: [][]byte{[]byte(canary)}}, ReplaceRecoveryCodesWrite{},
	}
	for _, value := range values {
		if formatted := fmt.Sprintf("%#v", value); strings.Contains(formatted, canary) {
			t.Fatalf("unsafe format %T: %s", value, formatted)
		}
	}
}

func FuzzRecoveryBatchRejectsUnsafeCodes(f *testing.F) {
	f.Add("RECOVERY-CODE-1234")
	f.Add(" bad recovery code ")
	f.Add("secret\ncode-value")
	f.Fuzz(func(t *testing.T, code string) {
		batch := RecoveryCodeBatch{SetID: testID(1), DigestKeyVersion: 1, Codes: make([]RecoveryCodeMaterial, 8)}
		for index := range batch.Codes {
			value := []byte(fmt.Sprintf("%s-%02d", code, index))
			batch.Codes[index] = RecoveryCodeMaterial{Code: value, Digest: RecoveryCodeDigest(sha256.Sum256(value))}
		}
		if validRecoveryBatch(batch, 8) {
			for _, material := range batch.Codes {
				if !printableASCII(material.Code) {
					t.Fatal("unsafe recovery code was accepted")
				}
			}
		}
	})
}

func newFactorEnrollmentService(t *testing.T) (*FactorEnrollment, *totpEnrollmentStoreStub, AuthorityLookup) {
	t.Helper()
	localRevision := int64(4)
	authority, err := NewAuthoritySnapshot(authorityInput([]identity.AssuranceEvidence{{
		Level: identity.AssuranceMFA, Kind: identity.AssuranceEvidenceFactor,
		Source: identity.AssuranceSource{Local: true}, AuthenticatedAt: testNow, FactorRevision: &localRevision,
	}}, false, mfa.FlowExistingSession))
	if err != nil {
		t.Fatal(err)
	}
	handle := opaqueHandle(7)
	material := TOTPEnrollmentMaterial{
		EnrollmentID: testID(30), FactorID: testID(31), BrowserHandle: handle,
		BrowserDigest:   sha256.Sum256(handle),
		ProtectedSecret: mfa.ProtectedTOTPSecret{KeyVersion: 1, Ciphertext: bytes.Repeat([]byte{8}, 32)},
		DisplaySecret:   []byte("JBSWY3DPEHPK3PXP"),
		ProvisioningURI: []byte("otpauth://totp/Periapsis:operator?secret=JBSWY3DPEHPK3PXP"),
	}
	store := &totpEnrollmentStoreStub{}
	recovery := &recoveryGeneratorStub{batch: recoveryBatch(10)}
	service, err := NewFactorEnrollment(FactorEnrollmentOptions{
		Source:     &enrollmentSourceStub{authority: authority},
		Admissions: &gateStub{decision: AdmissionDecision{Outcome: AdmissionAllowed}},
		TOTP:       &totpMaterialSourceStub{material: material}, TOTPVerifier: &totpVerifierStub{counter: 100},
		TOTPStore: store, Recovery: recovery, RecoveryStore: &recoveryStoreStub{},
		Now: func() time.Time { return testNow }, EnrollmentTTL: 5 * time.Minute,
		RecoveryCodeCount: 10, OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	lookup := AuthorityLookup{
		Flow: mfa.FlowExistingSession, AnchorID: testID(3), Action: "case.export",
		Audience: "tenant-console", Admission: validAdmissionContext(),
	}
	return service, store, lookup
}

func configureContinuationEnrollment(
	t *testing.T,
	service *FactorEnrollment,
	lookup AuthorityLookup,
) AuthorityLookup {
	t.Helper()
	providerRevision := int64(4)
	input := authorityInput([]identity.AssuranceEvidence{{
		Level: identity.AssurancePrimary, Kind: identity.AssuranceEvidenceFactor,
		Source:          identity.AssuranceSource{ProviderID: testID(80), BindingID: testID(81)},
		AuthenticatedAt: testNow, TrustRuleRevision: &providerRevision,
	}}, true, mfa.FlowPostPrimaryContinuation)
	deadline := testNow.Add(10 * time.Minute)
	input.Policies[0].Policy.EnrollmentDeadline = &deadline
	authority, err := NewAuthoritySnapshot(input)
	if err != nil {
		t.Fatal(err)
	}
	service.source.(*enrollmentSourceStub).authority = authority
	lookup.Flow = mfa.FlowPostPrimaryContinuation
	lookup.AnchorID = input.ContinuationID
	lookup.ContinuationReceiptDigest = input.ContinuationReceiptDigest
	return lookup
}

func recoveryBatch(count int) RecoveryCodeBatch {
	batch := RecoveryCodeBatch{SetID: testID(60), DigestKeyVersion: 1, Codes: make([]RecoveryCodeMaterial, count)}
	for index := range batch.Codes {
		code := []byte(fmt.Sprintf("RECOVERY-CODE-%04d", index))
		batch.Codes[index] = RecoveryCodeMaterial{Code: code, Digest: RecoveryCodeDigest(sha256.Sum256(code))}
	}
	return batch
}
