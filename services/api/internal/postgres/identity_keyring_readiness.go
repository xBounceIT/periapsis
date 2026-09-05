package postgres

import (
	"context"
	"errors"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
)

type identityKeyringQueries interface {
	VerifyIdentityKeyring(context.Context, dbsql.VerifyIdentityKeyringParams) (bool, error)
}

type IdentityKeyringEvidenceVerifier struct {
	queries identityKeyringQueries
}

func NewIdentityKeyringEvidenceVerifier(database dbsql.DBTX) IdentityKeyringEvidenceVerifier {
	if database == nil {
		return IdentityKeyringEvidenceVerifier{}
	}
	return IdentityKeyringEvidenceVerifier{queries: dbsql.New(database)}
}

var _ identityprovider.KeyringEvidenceVerifier = IdentityKeyringEvidenceVerifier{}

func (v IdentityKeyringEvidenceVerifier) VerifyIdentityKeyring(
	ctx context.Context,
	evidence identity.ReadinessEvidence,
) (bool, error) {
	if v.queries == nil || evidence.ActiveVersion < 1 ||
		len(evidence.Versions) < 1 || len(evidence.Versions) > 16 {
		return false, identityprovider.ErrInvalidInput
	}
	versions := make([]int32, len(evidence.Versions))
	verifiers := make([][]byte, len(evidence.Versions))
	defer func() {
		for index := range verifiers {
			clear(verifiers[index])
		}
	}()
	for index, version := range evidence.Versions {
		if version.KeyVersion < 1 ||
			index > 0 && evidence.Versions[index-1].KeyVersion >= version.KeyVersion {
			return false, identityprovider.ErrInvalidInput
		}
		versions[index] = int32(version.KeyVersion)
		verifiers[index] = append([]byte(nil), version.Verifier[:]...)
	}
	verified, err := v.queries.VerifyIdentityKeyring(ctx, dbsql.VerifyIdentityKeyringParams{
		KeyVersions: versions, Verifiers: verifiers, ActiveVersion: int32(evidence.ActiveVersion),
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return false, err
		}
		return false, identityprovider.ErrUnavailable
	}
	return verified, nil
}
