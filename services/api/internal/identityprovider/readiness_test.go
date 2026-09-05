package identityprovider

import (
	"context"
	"errors"
	"reflect"
	"testing"

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

type keyringEvidenceVerifierStub struct {
	verified      bool
	err           error
	activeVersion int16
	versions      []int16
	verifiers     [][]byte
}

func (s *keyringEvidenceVerifierStub) VerifyIdentityKeyring(_ context.Context, evidence identity.ReadinessEvidence) (bool, error) {
	s.activeVersion = evidence.ActiveVersion
	s.versions = make([]int16, len(evidence.Versions))
	s.verifiers = make([][]byte, len(evidence.Versions))
	for index, version := range evidence.Versions {
		s.versions[index] = version.KeyVersion
		s.verifiers[index] = append([]byte(nil), version.Verifier[:]...)
	}
	return s.verified, s.err
}
