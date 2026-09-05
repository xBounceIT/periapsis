package postgres

import (
	"context"
	"errors"
	"reflect"
	"testing"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

func TestIdentityKeyringEvidenceVerifierUsesOnlyBoundedEvidence(t *testing.T) {
	t.Parallel()

	stub := &identityKeyringQueriesStub{verified: true}
	verifier := IdentityKeyringEvidenceVerifier{queries: stub}
	evidence := identity.ReadinessEvidence{
		ActiveVersion: 2,
		Versions: []identity.VersionVerifier{
			{KeyVersion: 1, Verifier: verifierBytes(0x11)},
			{KeyVersion: 2, Verifier: verifierBytes(0x22)},
		},
	}
	verified, err := verifier.VerifyIdentityKeyring(context.Background(), evidence)
	if err != nil || !verified {
		t.Fatalf("VerifyIdentityKeyring() = (%v, %v)", verified, err)
	}
	if !reflect.DeepEqual(stub.params.KeyVersions, []int32{1, 2}) || stub.params.ActiveVersion != 2 ||
		len(stub.params.Verifiers) != 2 || len(stub.params.Verifiers[0]) != 32 {
		t.Fatalf("query params = %#v", stub.params)
	}
}

func TestIdentityKeyringEvidenceVerifierRejectsMalformedEvidence(t *testing.T) {
	t.Parallel()

	verifier := IdentityKeyringEvidenceVerifier{queries: &identityKeyringQueriesStub{verified: true}}
	for _, evidence := range []identity.ReadinessEvidence{
		{},
		{ActiveVersion: 1},
		{ActiveVersion: 1, Versions: []identity.VersionVerifier{{KeyVersion: 0}}},
		{ActiveVersion: 1, Versions: []identity.VersionVerifier{{KeyVersion: 2}, {KeyVersion: 1}}},
	} {
		if _, err := verifier.VerifyIdentityKeyring(context.Background(), evidence); !errors.Is(err, identityprovider.ErrInvalidInput) {
			t.Fatalf("VerifyIdentityKeyring(%#v) error = %v", evidence, err)
		}
	}
}

type identityKeyringQueriesStub struct {
	params   dbsql.VerifyIdentityKeyringParams
	verified bool
	err      error
}

func (s *identityKeyringQueriesStub) VerifyIdentityKeyring(_ context.Context, params dbsql.VerifyIdentityKeyringParams) (bool, error) {
	s.params = dbsql.VerifyIdentityKeyringParams{
		KeyVersions: append([]int32(nil), params.KeyVersions...), ActiveVersion: params.ActiveVersion,
		Verifiers: make([][]byte, len(params.Verifiers)),
	}
	for index := range params.Verifiers {
		s.params.Verifiers[index] = append([]byte(nil), params.Verifiers[index]...)
	}
	return s.verified, s.err
}

func verifierBytes(value byte) [32]byte {
	var result [32]byte
	for index := range result {
		result[index] = value
	}
	return result
}
