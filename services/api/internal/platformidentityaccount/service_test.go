package platformidentityaccount

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
)

type accountRepositoryStub struct {
	calls   int
	list    func(context.Context, ListParams) ([]Account, error)
	get     func(context.Context, GetParams) (Account, error)
	prelink func(context.Context, PrelinkParams) (PrelinkResult, error)
	retire  func(context.Context, RetireParams) (RetireResult, error)
}

func (stub *accountRepositoryStub) List(ctx context.Context, params ListParams) ([]Account, error) {
	stub.calls++
	if stub.list == nil {
		return nil, authentication.ErrUnavailable
	}
	return stub.list(ctx, params)
}

func (stub *accountRepositoryStub) Get(ctx context.Context, params GetParams) (Account, error) {
	stub.calls++
	if stub.get == nil {
		return Account{}, authentication.ErrUnavailable
	}
	return stub.get(ctx, params)
}

func (stub *accountRepositoryStub) Prelink(ctx context.Context, params PrelinkParams) (PrelinkResult, error) {
	stub.calls++
	if stub.prelink == nil {
		return PrelinkResult{}, authentication.ErrUnavailable
	}
	return stub.prelink(ctx, params)
}

func (stub *accountRepositoryStub) Retire(ctx context.Context, params RetireParams) (RetireResult, error) {
	stub.calls++
	if stub.retire == nil {
		return RetireResult{}, authentication.ErrUnavailable
	}
	return stub.retire(ctx, params)
}

func TestServiceListAndGetReturnOnlySafeBoundedProjections(t *testing.T) {
	providerID := mustUUIDv7(t)
	firstID := mustUUIDv7(t)
	secondID := largerUUIDv7(t, firstID)
	thirdID := largerUUIDv7(t, secondID)
	repository := &accountRepositoryStub{}
	service := mustService(t, repository)
	repository.list = func(_ context.Context, params ListParams) ([]Account, error) {
		if params.ProviderID != providerID || params.Limit != 3 || params.IncludeRetired {
			t.Fatalf("List() params = %#v", params)
		}
		return []Account{
			accountFixture(providerID, firstID, mustUUIDv7(t), 1),
			accountFixture(providerID, secondID, mustUUIDv7(t), 1),
			accountFixture(providerID, thirdID, mustUUIDv7(t), 1),
		}, nil
	}
	page, err := service.List(context.Background(), readSession(t), providerID, ListInput{Limit: 2})
	if err != nil || len(page.Items) != 2 || page.NextCursor == nil || *page.NextCursor != secondID {
		t.Fatalf("List() = %#v, %v", page, err)
	}
	if page.Items[0].User.Email == nil {
		t.Fatal("List() omitted safe email fixture")
	}
	*page.Items[0].User.Email = "tampered@example.test"

	repository.get = func(_ context.Context, params GetParams) (Account, error) {
		if params.ProviderID != providerID || params.AccountID != firstID {
			t.Fatalf("Get() params = %#v", params)
		}
		return accountFixture(providerID, firstID, mustUUIDv7(t), 1), nil
	}
	account, err := service.Get(context.Background(), readSession(t), providerID, firstID)
	if err != nil || account.ID != firstID || account.User.Email == nil ||
		*account.User.Email != "operator@example.test" {
		t.Fatalf("Get() = %#v, %v", account, err)
	}

	accountType := reflect.TypeOf(Account{})
	for _, forbidden := range []string{"Issuer", "Subject", "Ciphertext", "Nonce", "Aliases", "KeyVersion"} {
		if _, present := accountType.FieldByName(forbidden); present {
			t.Fatalf("safe Account unexpectedly exposes %s", forbidden)
		}
	}

	repository.list = func(context.Context, ListParams) ([]Account, error) {
		return []Account{
			accountFixture(providerID, secondID, mustUUIDv7(t), 1),
			accountFixture(providerID, firstID, mustUUIDv7(t), 1),
		}, nil
	}
	if _, err := service.List(context.Background(), readSession(t), providerID, ListInput{Limit: 2}); !errors.Is(err, authentication.ErrUnavailable) {
		t.Fatalf("List() non-monotonic error = %v", err)
	}

	retired := retiredAccountFixture(providerID, firstID, mustUUIDv7(t), 2)
	repository.list = func(context.Context, ListParams) ([]Account, error) { return []Account{retired}, nil }
	if _, err := service.List(context.Background(), readSession(t), providerID, ListInput{}); !errors.Is(err, authentication.ErrUnavailable) {
		t.Fatalf("List() leaked retired row = %v", err)
	}
}

func TestServicePrelinkProtectsExactTupleAndValidatesInitialProjection(t *testing.T) {
	providerID, userID := mustUUIDv7(t), mustUUIDv7(t)
	commandID, accountID := mustUUIDv7(t), mustUUIDv7(t)
	repository := &accountRepositoryStub{}
	keyring := testKeyring(t)
	service := mustServiceWithProtector(t, repository, keyring)
	ids := []uuid.UUID{commandID, accountID}
	service.newID = func() (uuid.UUID, error) {
		value := ids[0]
		ids = ids[1:]
		return value, nil
	}
	input := validPrelinkInput(t, userID)
	var aliasReferences []identity.SubjectAlias
	var ciphertextReference []byte
	repository.prelink = func(_ context.Context, params PrelinkParams) (PrelinkResult, error) {
		if params.ActorID == uuid.Nil || params.SessionID == uuid.Nil || params.AuthenticationMethod != "totp" ||
			params.CommandID != commandID || params.AccountID != accountID ||
			params.ProviderID != providerID || params.UserID != userID ||
			params.Issuer != input.Issuer || params.Reason != "Link corporate operator" ||
			params.ValidateResult == nil {
			t.Fatalf("Prelink() params = %#v", params)
		}
		if got, want := params.KeyDigest, sha256.Sum256([]byte(input.IdempotencyKey)); got != want {
			t.Fatalf("Prelink() key digest = %x, want %x", got, want)
		}
		if params.PublicRequestDigest == ([sha256.Size]byte{}) || !validProtectedSubject(params.Subject) {
			t.Fatalf("Prelink() protected material = %#v", params)
		}
		aliasReferences = params.Subject.Aliases
		ciphertextReference = params.Subject.Envelope.Ciphertext
		assertProtectedTuple(t, keyring, providerID, accountID, input.Issuer, input.Subject, params.Subject)
		formatted := fmt.Sprintf("%#v", params)
		for _, secret := range []string{input.Issuer, input.Subject, input.IdempotencyKey, input.Reason} {
			if strings.Contains(formatted, secret) {
				t.Fatalf("PrelinkParams formatting exposed %q: %s", secret, formatted)
			}
		}
		account := accountFixture(providerID, accountID, userID, 1)
		return params.ValidateResult(mustPrelinkResult(t, accountID, false, account))
	}
	result, err := service.Prelink(context.Background(), manageSession(t), providerID, input)
	if err != nil || result.Replayed() || result.AccountID() != accountID || result.Version() != 1 ||
		result.Account().State != AccountStateActive {
		t.Fatalf("Prelink() = %#v, %v", result, err)
	}
	for _, alias := range aliasReferences {
		if alias.Digest != ([sha256.Size]byte{}) {
			t.Fatal("Prelink() retained a subject alias after persistence returned")
		}
	}
	if !allZeroBytes(ciphertextReference) {
		t.Fatal("Prelink() retained protected subject material after persistence returned")
	}
	formatted := fmt.Sprintf("%#v %#v", input, result)
	if strings.Contains(formatted, input.Issuer) || strings.Contains(formatted, input.Subject) {
		t.Fatalf("prelink formatting exposed immutable identity: %s", formatted)
	}
}

func TestServiceRejectsPoisonedMutationProjections(t *testing.T) {
	providerID, accountID, userID := mustUUIDv7(t), mustUUIDv7(t), mustUUIDv7(t)
	repository := &accountRepositoryStub{}
	service := mustService(t, repository)
	service.newID = uuid.NewV7

	repository.prelink = func(_ context.Context, params PrelinkParams) (PrelinkResult, error) {
		account := accountFixture(providerID, accountID, mustUUIDv7(t), 1)
		return params.ValidateResult(mustPrelinkResult(t, accountID, false, account))
	}
	if _, err := service.Prelink(
		context.Background(), manageSession(t), providerID, validPrelinkInput(t, userID),
	); !errors.Is(err, authentication.ErrUnavailable) {
		t.Fatalf("Prelink() wrong-user projection = %v", err)
	}

	tag, err := EntityTag(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	repository.retire = func(_ context.Context, params RetireParams) (RetireResult, error) {
		receipt, receiptErr := RestoreRetireReceipt(RetireReceiptInput{AccountID: accountID, Version: 2})
		if receiptErr != nil {
			t.Fatal(receiptErr)
		}
		active := accountFixture(providerID, accountID, userID, 2)
		return params.ValidateResult(
			accountFixture(providerID, accountID, userID, 1),
			RetireResult{receipt: receipt, account: active},
		)
	}
	if _, err := service.Retire(context.Background(), manageSession(t), providerID, accountID, RetireInput{
		Reason: "Retire exact link", ExpectedEntityTag: &tag, Event: testEvent(t),
	}); !errors.Is(err, authentication.ErrUnavailable) {
		t.Fatalf("Retire() active post-projection = %v", err)
	}
}

func TestServicePrelinkReplayReturnsCurrentRetiredProjectionWithoutResurrection(t *testing.T) {
	providerID, userID := mustUUIDv7(t), mustUUIDv7(t)
	originalID := mustUUIDv7(t)
	repository := &accountRepositoryStub{}
	service := mustService(t, repository)
	service.newID = uuid.NewV7
	repository.prelink = func(_ context.Context, params PrelinkParams) (PrelinkResult, error) {
		account := retiredAccountFixture(providerID, originalID, userID, 3)
		return params.ValidateResult(mustPrelinkResult(t, originalID, true, account))
	}
	result, err := service.Prelink(
		context.Background(), manageSession(t), providerID, validPrelinkInput(t, userID),
	)
	if err != nil || !result.Replayed() || result.AccountID() != originalID || result.Version() != 1 ||
		result.Account().Version != 3 || result.Account().State != AccountStateRetired {
		t.Fatalf("Prelink() replay = %#v, %v", result, err)
	}

	repository.prelink = func(context.Context, PrelinkParams) (PrelinkResult, error) {
		return PrelinkResult{}, authentication.ErrConflict
	}
	if _, err := service.Prelink(
		context.Background(), manageSession(t), providerID, validPrelinkInput(t, userID),
	); !errors.Is(err, authentication.ErrConflict) {
		t.Fatalf("Prelink() retained collision = %v", err)
	}
}

func TestServiceRetireUsesStrongCASAndRequiresNormalizedReason(t *testing.T) {
	providerID, accountID, userID := mustUUIDv7(t), mustUUIDv7(t), mustUUIDv7(t)
	repository := &accountRepositoryStub{}
	service := mustService(t, repository)
	tag, err := EntityTag(3, 1)
	if err != nil {
		t.Fatal(err)
	}
	repository.retire = func(_ context.Context, params RetireParams) (RetireResult, error) {
		if params.ProviderID != providerID || params.AccountID != accountID ||
			params.ExpectedVersion != 3 || params.ExpectedUserVersion != 1 ||
			params.Reason != "Operator left the company" ||
			params.ValidateResult == nil {
			t.Fatalf("Retire() params = %#v", params)
		}
		account := retiredAccountFixture(providerID, accountID, userID, 4)
		return params.ValidateResult(
			accountFixture(providerID, accountID, userID, 3), mustRetireResult(t, account),
		)
	}
	result, err := service.Retire(context.Background(), manageSession(t), providerID, accountID, RetireInput{
		Reason: "  Operator left the company  ", ExpectedEntityTag: &tag, Event: testEvent(t),
	})
	if err != nil || result.AccountID() != accountID || result.Version() != 4 ||
		result.Account().State != AccountStateRetired {
		t.Fatalf("Retire() = %#v, %v", result, err)
	}

	for _, input := range []RetireInput{
		{ExpectedEntityTag: &tag, Event: testEvent(t)},
		{Reason: "approved", Event: testEvent(t)},
		{Reason: "bad\nreason", ExpectedEntityTag: &tag, Event: testEvent(t)},
	} {
		before := repository.calls
		if _, err := service.Retire(context.Background(), manageSession(t), providerID, accountID, input); !errors.Is(err, authentication.ErrInvalidInput) || repository.calls != before {
			t.Fatalf("Retire() malformed = %v, calls %d -> %d", err, before, repository.calls)
		}
	}
}

func TestAccountRetirementValidationRejectsTemporalAndUserProjectionDrift(t *testing.T) {
	providerID, accountID, userID := mustUUIDv7(t), mustUUIDv7(t), mustUUIDv7(t)
	previous := accountFixture(providerID, accountID, userID, 3)
	lastObservedAt := previous.CreatedAt.Add(time.Minute)
	previous.LastObservedAt = &lastObservedAt
	previous.UpdatedAt = previous.CreatedAt.Add(2 * time.Minute)

	next := previous
	retiredAt := previous.CreatedAt.Add(3 * time.Minute)
	next.State = AccountStateRetired
	next.RetiredAt = &retiredAt
	next.Version++
	next.UpdatedAt = retiredAt
	if !validRetirementTransition(previous, next) {
		t.Fatal("validRetirementTransition rejected canonical retirement")
	}

	beforePreviousUpdate := next
	tooEarly := previous.CreatedAt.Add(90 * time.Second)
	beforePreviousUpdate.RetiredAt = &tooEarly
	beforePreviousUpdate.UpdatedAt = tooEarly
	if !validAccount(beforePreviousUpdate) {
		t.Fatal("temporal transition fixture should remain a valid standalone retired account")
	}
	if validRetirementTransition(previous, beforePreviousUpdate) {
		t.Fatal("validRetirementTransition accepted retirement before previous updatedAt")
	}

	beforeObservation := next
	tooEarly = previous.CreatedAt.Add(30 * time.Second)
	beforeObservation.RetiredAt = &tooEarly
	beforeObservation.UpdatedAt = tooEarly
	if validAccount(beforeObservation) {
		t.Fatal("validAccount accepted retiredAt before lastObservedAt")
	}

	changedUserRevision := next
	changedUserRevision.User.Version++
	if validRetirementTransition(previous, changedUserRevision) {
		t.Fatal("validRetirementTransition accepted a changed user projection revision")
	}
}

func TestAccountValidationAcceptsOnlyTruthfulLegacyUnknownObservation(t *testing.T) {
	providerID, accountID, userID := mustUUIDv7(t), mustUUIDv7(t), mustUUIDv7(t)
	legacy := retiredAccountFixture(providerID, accountID, userID, 1)
	legacy.LastObservationState = LastObservationStateLegacyUnknown
	legacy.LastObservedAt = nil
	if !validAccount(legacy) {
		t.Fatal("validAccount rejected the explicit legacy-unknown projection")
	}

	for name, mutate := range map[string]func(*Account){
		"active": func(value *Account) {
			value.State = AccountStateActive
			value.RetiredAt = nil
		},
		"fabricated timestamp": func(value *Account) {
			observedAt := value.CreatedAt
			value.LastObservedAt = &observedAt
		},
		"advanced identity revision": func(value *Account) { value.Version = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneAccount(legacy)
			mutate(&candidate)
			if validAccount(candidate) {
				t.Fatalf("validAccount accepted invalid legacy projection %#v", candidate)
			}
		})
	}
}

func TestServicePermissionsCancellationAndErrorsFailClosed(t *testing.T) {
	providerID, accountID, userID := mustUUIDv7(t), mustUUIDv7(t), mustUUIDv7(t)
	repository := &accountRepositoryStub{}
	service := mustService(t, repository)

	if _, err := service.List(context.Background(), authentication.Session{}, providerID, ListInput{}); !errors.Is(err, authentication.ErrForbidden) {
		t.Fatalf("List() permission error = %v", err)
	}
	manageOnly := manageSession(t)
	manageOnly.Permissions = []authorization.Permission{authorization.PermissionPlatformIdentityAccountManage}
	if _, err := service.Prelink(context.Background(), manageOnly, providerID, validPrelinkInput(t, userID)); !errors.Is(err, authentication.ErrForbidden) {
		t.Fatalf("Prelink() missing read permission = %v", err)
	}
	invalidSession := readSession(t)
	invalidSession.AuthenticationMethod = "bearer"
	if _, err := service.Get(context.Background(), invalidSession, providerID, accountID); !errors.Is(err, authentication.ErrUnavailable) {
		t.Fatalf("Get() invalid session = %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := service.List(canceled, readSession(t), providerID, ListInput{}); !errors.Is(err, context.Canceled) || repository.calls != 0 {
		t.Fatalf("List() canceled = %v, calls = %d", err, repository.calls)
	}
	if _, err := service.List(nil, readSession(t), providerID, ListInput{}); !errors.Is(err, authentication.ErrUnavailable) || repository.calls != 0 {
		t.Fatalf("List(nil) = %v, calls = %d", err, repository.calls)
	}

	for _, test := range []struct {
		input error
		want  error
	}{
		{authentication.ErrForbidden, authentication.ErrForbidden},
		{authentication.ErrNotFound, authentication.ErrNotFound},
		{authentication.ErrConflict, authentication.ErrConflict},
		{authentication.ErrInvalidInput, authentication.ErrInvalidInput},
		{ErrPreconditionFailed, ErrPreconditionFailed},
		{context.Canceled, context.Canceled},
		{context.DeadlineExceeded, context.DeadlineExceeded},
		{errors.New("private database diagnostic"), authentication.ErrUnavailable},
	} {
		repository.get = func(context.Context, GetParams) (Account, error) {
			return Account{}, test.input
		}
		_, err := service.Get(context.Background(), readSession(t), providerID, accountID)
		if !errors.Is(err, test.want) || strings.Contains(fmt.Sprint(err), "private database diagnostic") {
			t.Fatalf("Get() error = %v, want %v", err, test.want)
		}
	}
}

func TestServiceRejectsMalformedPrelinkBeforeProtectionOrPersistence(t *testing.T) {
	providerID, userID := mustUUIDv7(t), mustUUIDv7(t)
	repository := &accountRepositoryStub{}
	protector := &countingProtector{active: 1}
	service := mustServiceWithProtector(t, repository, protector)
	session := manageSession(t)

	cases := []PrelinkInput{
		func() PrelinkInput { value := validPrelinkInput(t, userID); value.UserID = uuid.New(); return value }(),
		func() PrelinkInput {
			value := validPrelinkInput(t, userID)
			value.Issuer = "http://id.example.test"
			return value
		}(),
		func() PrelinkInput {
			value := validPrelinkInput(t, userID)
			value.Issuer += "?tenant=platform"
			return value
		}(),
		func() PrelinkInput { value := validPrelinkInput(t, userID); value.Subject = ""; return value }(),
		func() PrelinkInput {
			value := validPrelinkInput(t, userID)
			value.Subject = strings.Repeat("s", 1025)
			return value
		}(),
		func() PrelinkInput { value := validPrelinkInput(t, userID); value.Reason = " "; return value }(),
		func() PrelinkInput {
			value := validPrelinkInput(t, userID)
			value.IdempotencyKey = "short"
			return value
		}(),
		func() PrelinkInput {
			value := validPrelinkInput(t, userID)
			value.Event.UserAgent = "bad\nagent"
			return value
		}(),
	}
	for _, input := range cases {
		if _, err := service.Prelink(context.Background(), session, providerID, input); !errors.Is(err, authentication.ErrInvalidInput) {
			t.Fatalf("Prelink() malformed input error = %v", err)
		}
	}
	if repository.calls != 0 || protector.calls != 0 {
		t.Fatalf("malformed prelinks reached dependencies: repository=%d protector=%d", repository.calls, protector.calls)
	}
	if _, err := service.Prelink(context.Background(), session, uuid.New(), validPrelinkInput(t, userID)); !errors.Is(err, authentication.ErrInvalidInput) {
		t.Fatalf("Prelink() UUIDv4 provider error = %v", err)
	}
}

func TestPrelinkPublicDigestOmitsSubjectAndAliasesBindExactSubjectAcrossRotation(t *testing.T) {
	providerID, userID := mustUUIDv7(t), mustUUIDv7(t)
	base := validPrelinkInput(t, userID)
	base.Reason = "  approved link  "
	normalized, subject, digest, err := normalizePrelink(providerID, base)
	if err != nil {
		t.Fatal(err)
	}
	subject.Clear()
	if normalized.Reason != "approved link" {
		t.Fatalf("normalized reason = %q", normalized.Reason)
	}
	mutations := []func(*PrelinkInput){
		func(value *PrelinkInput) { value.UserID = mustUUIDv7(t) },
		func(value *PrelinkInput) { value.Issuer = "https://other.example.test" },
		func(value *PrelinkInput) { value.Reason = "another reason" },
	}
	for _, mutate := range mutations {
		candidate := normalized
		mutate(&candidate)
		_, candidateSubject, candidateDigest, candidateErr := normalizePrelink(providerID, candidate)
		if candidateErr != nil {
			t.Fatal(candidateErr)
		}
		candidateSubject.Clear()
		if candidateDigest == digest {
			t.Fatal("prelink request digest did not bind a changed field")
		}
	}
	otherProvider := mustUUIDv7(t)
	_, otherSubject, otherDigest, err := normalizePrelink(otherProvider, normalized)
	if err != nil {
		t.Fatal(err)
	}
	otherSubject.Clear()
	if otherDigest == digest {
		t.Fatal("prelink request digest did not bind provider")
	}

	changedSubject := normalized
	changedSubject.Subject = "another-subject"
	_, changedCanonical, changedDigest, err := normalizePrelink(providerID, changedSubject)
	if err != nil {
		t.Fatal(err)
	}
	defer changedCanonical.Clear()
	if changedDigest != digest {
		t.Fatal("public prelink digest unexpectedly disclosed or bound the confidential subject")
	}

	originalCanonical, err := identity.CanonicalOIDCIssuerSubject(normalized.Issuer, normalized.Subject)
	if err != nil {
		t.Fatal(err)
	}
	defer originalCanonical.Clear()
	provider := identity.ProviderContext{
		Scope: identity.PlatformProviderScope, ProviderID: identity.EntityID(providerID),
	}
	beforeRotation, err := identity.NewKeyring(2, map[int16][]byte{
		1: bytes.Repeat([]byte{0x41}, 32),
		2: bytes.Repeat([]byte{0x42}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	afterRotation, err := identity.NewKeyring(3, map[int16][]byte{
		2: bytes.Repeat([]byte{0x42}, 32),
		3: bytes.Repeat([]byte{0x43}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	originalBefore, err := beforeRotation.SubjectAliases(provider, originalCanonical)
	if err != nil {
		t.Fatal(err)
	}
	changedBefore, err := beforeRotation.SubjectAliases(provider, changedCanonical)
	if err != nil {
		t.Fatal(err)
	}
	originalAfter, err := afterRotation.SubjectAliases(provider, originalCanonical)
	if err != nil {
		t.Fatal(err)
	}
	defer clearSubjectAliases(originalBefore)
	defer clearSubjectAliases(changedBefore)
	defer clearSubjectAliases(originalAfter)
	if reflect.DeepEqual(originalBefore, changedBefore) {
		t.Fatal("versioned subject aliases did not distinguish divergent subjects")
	}
	if originalBefore[1].KeyVersion != 2 || originalAfter[0].KeyVersion != 2 ||
		originalBefore[1].Digest != originalAfter[0].Digest {
		t.Fatal("retained successor alias did not remain stable across active-key rotation")
	}
}

func TestClosedReceiptsConstructorAndProtectorFailures(t *testing.T) {
	accountID := mustUUIDv7(t)
	if _, err := RestorePrelinkReceipt(PrelinkReceiptInput{AccountID: uuid.New(), Version: 1}); err == nil {
		t.Fatal("RestorePrelinkReceipt accepted UUIDv4")
	}
	if _, err := RestorePrelinkReceipt(PrelinkReceiptInput{AccountID: accountID, Version: 2}); err == nil {
		t.Fatal("RestorePrelinkReceipt accepted noninitial version")
	}
	if _, err := RestoreRetireReceipt(RetireReceiptInput{AccountID: accountID, Version: 1}); err == nil {
		t.Fatal("RestoreRetireReceipt accepted initial version")
	}
	var nilRepository *accountRepositoryStub
	if _, err := NewService(nilRepository, testKeyring(t)); err == nil {
		t.Fatal("NewService accepted typed nil repository")
	}
	if _, err := NewService(&accountRepositoryStub{}, identity.Keyring{}); err == nil {
		t.Fatal("NewService accepted empty keyring")
	}

	repository := &accountRepositoryStub{}
	protector := &countingProtector{active: 1, err: errors.New("private keyring diagnostic")}
	service := mustServiceWithProtector(t, repository, protector)
	if _, err := service.Prelink(
		context.Background(), manageSession(t), mustUUIDv7(t), validPrelinkInput(t, mustUUIDv7(t)),
	); !errors.Is(err, authentication.ErrUnavailable) || strings.Contains(fmt.Sprint(err), "private keyring diagnostic") {
		t.Fatalf("Prelink() protector failure = %v", err)
	}

	staleProtector := &countingProtector{active: 2, outputVersion: 1}
	service = mustServiceWithProtector(t, repository, staleProtector)
	if _, err := service.Prelink(
		context.Background(), manageSession(t), mustUUIDv7(t), validPrelinkInput(t, mustUUIDv7(t)),
	); !errors.Is(err, authentication.ErrUnavailable) || repository.calls != 0 {
		t.Fatalf("Prelink() stale protector output = %v, repository calls = %d", err, repository.calls)
	}
}

type countingProtector struct {
	active        int16
	outputVersion int16
	calls         int
	err           error
}

func (protector *countingProtector) ActiveVersion() int16 { return protector.active }

func (protector *countingProtector) SubjectAliases(
	identity.ProviderContext,
	identity.Subject,
) ([]identity.SubjectAlias, error) {
	protector.calls++
	if protector.err != nil {
		return nil, protector.err
	}
	version := protector.outputVersion
	if version == 0 {
		version = 1
	}
	return []identity.SubjectAlias{{KeyVersion: version, Digest: [sha256.Size]byte{1}}}, nil
}

func (protector *countingProtector) EncryptExternalSubject(
	identity.ExternalSubjectContext,
	identity.Subject,
) (identity.ExternalSubjectEnvelope, error) {
	protector.calls++
	if protector.err != nil {
		return identity.ExternalSubjectEnvelope{}, protector.err
	}
	version := protector.outputVersion
	if version == 0 {
		version = 1
	}
	return identity.ExternalSubjectEnvelope{
		KeyVersion: version, Format: identity.UTF8ExactSubject,
		Nonce: [12]byte{1}, Ciphertext: bytes.Repeat([]byte{1}, 17),
	}, nil
}

func mustService(t *testing.T, repository Repository) *Service {
	t.Helper()
	return mustServiceWithProtector(t, repository, testKeyring(t))
}

func mustServiceWithProtector(t *testing.T, repository Repository, protector SubjectProtector) *Service {
	t.Helper()
	service, err := NewService(repository, protector)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func testKeyring(t *testing.T) identity.Keyring {
	t.Helper()
	keyring, err := identity.NewKeyring(2, map[int16][]byte{
		1: bytes.Repeat([]byte{0x31}, 32),
		2: bytes.Repeat([]byte{0x32}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}

func validPrelinkInput(t *testing.T, userID uuid.UUID) PrelinkInput {
	t.Helper()
	return PrelinkInput{
		UserID: userID, Issuer: "https://id.example.test/oidc", Subject: "opaque-subject-123",
		Reason: " Link corporate operator ", IdempotencyKey: "prelink-account-0001", Event: testEvent(t),
	}
}

func testEvent(t *testing.T) authentication.EventContext {
	t.Helper()
	return authentication.EventContext{
		RequestID: mustUUIDv7(t), CorrelationID: mustUUIDv7(t),
		RemoteAddress: netip.MustParseAddr("192.0.2.10"), UserAgent: "account-admin-test/1.0",
	}
}

func readSession(t *testing.T) authentication.Session {
	t.Helper()
	return authentication.Session{
		ID: mustUUIDv7(t), User: authentication.User{ID: mustUUIDv7(t)}, AuthenticationMethod: "totp",
		Permissions: []authorization.Permission{authorization.PermissionPlatformIdentityAccountRead},
	}
}

func manageSession(t *testing.T) authentication.Session {
	t.Helper()
	session := readSession(t)
	session.Permissions = append(session.Permissions, authorization.PermissionPlatformIdentityAccountManage)
	return session
}

func accountFixture(providerID, accountID, userID uuid.UUID, version int64) Account {
	now := time.Date(2026, 8, 30, 12, 0, 0, 123_000, time.UTC)
	email := "operator@example.test"
	return Account{
		ID: accountID, ProviderID: providerID,
		User: UserSummary{
			ID: userID, DisplayName: "Platform Operator", Email: &email, Active: true, Version: 1,
		},
		State: AccountStateActive, AdmittedConfigurationRevision: 7, AdmittedSecurityRevision: 11,
		LastObservationState: LastObservationStateKnown,
		LastObservedAt:       &now, Version: version, CreatedAt: now, UpdatedAt: now,
	}
}

func retiredAccountFixture(providerID, accountID, userID uuid.UUID, version int64) Account {
	account := accountFixture(providerID, accountID, userID, version)
	retiredAt := account.CreatedAt.Add(time.Minute)
	account.State = AccountStateRetired
	account.RetiredAt = &retiredAt
	account.UpdatedAt = retiredAt
	return account
}

func mustPrelinkResult(t *testing.T, accountID uuid.UUID, replayed bool, account Account) PrelinkResult {
	t.Helper()
	result, err := RestorePrelinkResult(PrelinkResultInput{
		AccountID: accountID, Version: 1, Replayed: replayed, Account: account,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func mustRetireResult(t *testing.T, account Account) RetireResult {
	t.Helper()
	result, err := RestoreRetireResult(RetireResultInput{
		AccountID: account.ID, Version: account.Version, Account: account,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertProtectedTuple(
	t *testing.T,
	keyring identity.Keyring,
	providerID, accountID uuid.UUID,
	issuer, rawSubject string,
	protected ProtectedSubject,
) {
	t.Helper()
	provider := identity.ProviderContext{
		Scope: identity.PlatformProviderScope, ProviderID: identity.EntityID(providerID),
	}
	context := identity.ExternalSubjectContext{
		Provider: provider, ExternalIdentityID: identity.EntityID(accountID),
	}
	decrypted, err := keyring.DecryptExternalSubject(context, protected.Envelope)
	if err != nil {
		t.Fatalf("DecryptExternalSubject() error = %v", err)
	}
	defer decrypted.Clear()
	aliases, err := keyring.SubjectAliases(provider, decrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(aliases, protected.Aliases) {
		t.Fatalf("protected aliases = %#v, want %#v", protected.Aliases, aliases)
	}
	expected, err := identity.CanonicalOIDCIssuerSubject(issuer, rawSubject)
	if err != nil {
		t.Fatal(err)
	}
	defer expected.Clear()
	expectedAliases, err := keyring.SubjectAliases(provider, expected)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expectedAliases, protected.Aliases) {
		t.Fatal("protected subject does not represent the exact issuer and subject")
	}
}

func mustUUIDv7(t *testing.T) uuid.UUID {
	t.Helper()
	value, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func largerUUIDv7(t *testing.T, lower uuid.UUID) uuid.UUID {
	t.Helper()
	for range 10_000 {
		candidate := mustUUIDv7(t)
		if bytes.Compare(candidate[:], lower[:]) > 0 {
			return candidate
		}
	}
	t.Fatal("could not generate a larger UUIDv7")
	return uuid.Nil
}

func allZeroBytes(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
