package identityprovider

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

func TestKeyringReadinessVerifierSubmitsBoundedEvidence(t *testing.T) {
	t.Parallel()

	keyring := testIdentityKeyring(t)
	stub := &keyringEvidenceVerifierStub{verified: true}
	verifier, err := NewKeyringReadinessVerifier(stub, keyring)
	if err != nil {
		t.Fatalf("NewKeyringReadinessVerifier() error = %v", err)
	}
	if err := verifier.Verify(context.Background()); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if stub.activeVersion != 1 || !reflect.DeepEqual(stub.versions, []int16{1}) || len(stub.verifiers) != 1 || len(stub.verifiers[0]) != 32 {
		t.Fatalf("evidence = active %d versions %v verifiers %v", stub.activeVersion, stub.versions, stub.verifiers)
	}
}

func TestKeyringReadinessVerifierFailsClosedAndPreservesCancellation(t *testing.T) {
	t.Parallel()

	keyring := testIdentityKeyring(t)
	for _, test := range []struct {
		name      string
		stub      *keyringEvidenceVerifierStub
		wantError error
	}{
		{name: "database mismatch", stub: &keyringEvidenceVerifierStub{}, wantError: ErrIdentityKeyringUnavailable},
		{name: "database failure", stub: &keyringEvidenceVerifierStub{err: errors.New("database detail")}, wantError: ErrIdentityKeyringUnavailable},
		{name: "cancellation", stub: &keyringEvidenceVerifierStub{err: context.Canceled}, wantError: context.Canceled},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier, err := NewKeyringReadinessVerifier(test.stub, keyring)
			if err != nil {
				t.Fatalf("NewKeyringReadinessVerifier() error = %v", err)
			}
			if err := verifier.Verify(context.Background()); !errors.Is(err, test.wantError) {
				t.Fatalf("Verify() error = %v, want %v", err, test.wantError)
			}
		})
	}
}

func TestKeyringReadinessVerifierRetriesTransientFalseAndBoundsMismatch(t *testing.T) {
	for _, succeeds := range []bool{true, false} {
		stub := &keyringEvidenceVerifierStub{verified: succeeds, falseCalls: 12}
		verifier, err := NewKeyringReadinessVerifier(stub, testIdentityKeyring(t))
		if err != nil {
			t.Fatal(err)
		}
		err = verifier.Verify(context.Background())
		if succeeds && (err != nil || stub.calls != 13) {
			t.Fatalf("transient verification: calls=%d error=%v", stub.calls, err)
		}
		if !succeeds && (!errors.Is(err, ErrIdentityKeyringUnavailable) || stub.calls < 2) {
			t.Fatalf("persistent mismatch: calls=%d error=%v", stub.calls, err)
		}
	}
}

func TestKeyringReadinessVerifierCancelsRetryWait(t *testing.T) {
	stub := &keyringEvidenceVerifierStub{}
	verifier, err := NewKeyringReadinessVerifier(stub, testIdentityKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := verifier.Verify(ctx); !errors.Is(err, context.DeadlineExceeded) || stub.calls != 1 {
		t.Fatalf("retry cancellation: calls=%d error=%v", stub.calls, err)
	}
}

type keyringEvidenceVerifierStub struct {
	calls         int
	falseCalls    int
	verified      bool
	err           error
	activeVersion int16
	versions      []int16
	verifiers     [][]byte
}

func (s *keyringEvidenceVerifierStub) VerifyIdentityKeyring(_ context.Context, evidence identity.ReadinessEvidence) (bool, error) {
	s.calls++
	s.activeVersion = evidence.ActiveVersion
	s.versions = make([]int16, len(evidence.Versions))
	s.verifiers = make([][]byte, len(evidence.Versions))
	for index, version := range evidence.Versions {
		s.versions[index] = version.KeyVersion
		s.verifiers[index] = append([]byte(nil), version.Verifier[:]...)
	}
	return s.verified && s.calls > s.falseCalls, s.err
}
