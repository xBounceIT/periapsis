package serviceaccount

import (
	"context"
	"errors"
	"testing"
)

type keyVersionInventoryStub struct {
	versions []int16
	err      error
	limit    int32
}

func (s *keyVersionInventoryStub) ListLiveAPIKeyVersions(_ context.Context, limit int32) ([]int16, error) {
	s.limit = limit
	return append([]int16(nil), s.versions...), s.err
}

func TestKeyringReadinessRequiresEveryLiveVersion(t *testing.T) {
	keyring, err := NewCredentialKeyring(2, map[int16][]byte{
		1: make([]byte, credentialSourceKeyBytes),
		2: make([]byte, credentialSourceKeyBytes),
	})
	if err != nil {
		t.Fatalf("NewCredentialKeyring() error = %v", err)
	}
	inventory := &keyVersionInventoryStub{versions: []int16{1, 2}}
	verifier, err := NewKeyringReadinessVerifier(inventory, keyring)
	if err != nil {
		t.Fatalf("NewKeyringReadinessVerifier() error = %v", err)
	}

	if err := verifier.VerifyLiveKeyVersions(context.Background()); err != nil {
		t.Fatalf("VerifyLiveKeyVersions() error = %v", err)
	}
	if inventory.limit != liveKeyVersionInventoryLimit {
		t.Fatalf("inventory limit = %d, want %d", inventory.limit, liveKeyVersionInventoryLimit)
	}

	inventory.versions = []int16{1, 3}
	if err := verifier.VerifyLiveKeyVersions(context.Background()); !errors.Is(err, ErrCredentialKeyringUnavailable) {
		t.Fatalf("missing key error = %v", err)
	}
}

func TestKeyringReadinessRejectsMalformedOrTruncatedInventory(t *testing.T) {
	keys := make(map[int16][]byte, 16)
	for version := int16(1); version <= 16; version++ {
		keys[version] = make([]byte, credentialSourceKeyBytes)
	}
	keyring, err := NewCredentialKeyring(16, keys)
	if err != nil {
		t.Fatalf("NewCredentialKeyring() error = %v", err)
	}

	tests := []struct {
		name     string
		versions []int16
	}{
		{name: "zero version", versions: []int16{0}},
		{name: "duplicate", versions: []int16{1, 1}},
		{name: "unsorted", versions: []int16{2, 1}},
		{name: "truncated overflow", versions: []int16{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verifier, err := NewKeyringReadinessVerifier(&keyVersionInventoryStub{versions: test.versions}, keyring)
			if err != nil {
				t.Fatalf("NewKeyringReadinessVerifier() error = %v", err)
			}
			if err := verifier.VerifyLiveKeyVersions(context.Background()); !errors.Is(err, ErrCredentialKeyringUnavailable) {
				t.Fatalf("VerifyLiveKeyVersions() error = %v", err)
			}
		})
	}
}

func TestKeyringReadinessPreservesCancellationButHidesRepositoryFailures(t *testing.T) {
	keyring, err := NewCredentialKeyring(1, map[int16][]byte{1: make([]byte, credentialSourceKeyBytes)})
	if err != nil {
		t.Fatalf("NewCredentialKeyring() error = %v", err)
	}

	for _, test := range []struct {
		name string
		err  error
		want error
	}{
		{name: "canceled", err: context.Canceled, want: context.Canceled},
		{name: "deadline", err: context.DeadlineExceeded, want: context.DeadlineExceeded},
		{name: "repository", err: errors.New("sensitive database detail"), want: ErrCredentialKeyringUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			verifier, err := NewKeyringReadinessVerifier(&keyVersionInventoryStub{err: test.err}, keyring)
			if err != nil {
				t.Fatalf("NewKeyringReadinessVerifier() error = %v", err)
			}
			if err := verifier.VerifyLiveKeyVersions(context.Background()); !errors.Is(err, test.want) {
				t.Fatalf("VerifyLiveKeyVersions() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestNewKeyringReadinessVerifierRejectsMissingDependencies(t *testing.T) {
	keyring, err := NewCredentialKeyring(1, map[int16][]byte{1: make([]byte, credentialSourceKeyBytes)})
	if err != nil {
		t.Fatalf("NewCredentialKeyring() error = %v", err)
	}
	if _, err := NewKeyringReadinessVerifier(nil, keyring); err == nil {
		t.Fatal("NewKeyringReadinessVerifier() accepted nil inventory")
	}
	if _, err := NewKeyringReadinessVerifier(&keyVersionInventoryStub{}, CredentialKeyring{}); err == nil {
		t.Fatal("NewKeyringReadinessVerifier() accepted zero keyring")
	}
}
