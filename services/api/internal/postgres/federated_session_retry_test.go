package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"testing"
)

func TestFederatedSessionAuthorityClassifiesOnlyAbortedTransientStatements(t *testing.T) {
	for _, test := range []struct {
		query, code string
		conflict    bool
	}{
		{applyFederatedSessionRevalidationSQL, "40001", true}, {applyFederatedSessionRevalidationSQL, "55P03", true},
		{applyFederatedSessionRevalidationSQL, "42501", false}, {createOIDCAuthenticationTransactionSQL, "40001", false},
	} {
		t.Run(test.query+test.code, func(t *testing.T) {
			calls := 0
			var retained []byte
			repository := &FederatedAuthRepository{queryer: federatedAuthQueryerStub{query: func(_ context.Context, _ string, args ...any) pgx.Row {
				calls++
				retained = args[0].([]byte)
				return federatedAuthRowFunc(func(...any) error { return &pgconn.PgError{Code: test.code, Message: "private database detail"} })
			}}}
			var response struct{}
			err := repository.queryJSON(context.Background(), test.query, map[string]string{"mutation": "synthetic"}, &response)
			if errors.Is(err, federatedauth.ErrSessionRevalidationConflict) != test.conflict || calls != 1 {
				t.Fatalf("error=%v calls=%d", err, calls)
			}
			if !test.conflict && !errors.Is(err, errFederatedAuthPersistence) {
				t.Fatal("database detail escaped")
			}
			for _, value := range retained {
				if value != 0 {
					t.Fatal("mutation payload was not cleared")
				}
			}
		})
	}
}
