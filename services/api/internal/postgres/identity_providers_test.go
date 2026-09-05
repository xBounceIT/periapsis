package postgres

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/identityprovider"
)

func TestMapIdentityProviderDatabaseErrorUsesStableDomainSemantics(t *testing.T) {
	t.Parallel()
	tests := []struct {
		code string
		want error
	}{
		{code: "22023", want: identityprovider.ErrInvalidInput},
		{code: "42501", want: identityprovider.ErrForbidden},
		{code: "P0002", want: identityprovider.ErrNotFound},
		{code: "40001", want: identityprovider.ErrPreconditionFailed},
		{code: "23505", want: identityprovider.ErrConflict},
		{code: "55000", want: identityprovider.ErrConflict},
		{code: "53300", want: identityprovider.ErrRateLimited},
	}
	for _, test := range tests {
		t.Run(test.code, func(t *testing.T) {
			t.Parallel()
			mapped := mapIdentityProviderDatabaseError(&pgconn.PgError{Code: test.code, Message: "sensitive database detail"})
			if !errors.Is(mapped, test.want) {
				t.Fatalf("mapped error = %v, want %v", mapped, test.want)
			}
		})
	}
	if !errors.Is(mapIdentityProviderDatabaseError(context.Canceled), context.Canceled) {
		t.Fatal("context cancellation was not preserved")
	}
}

func TestIdentityProviderMutationAuditRequiresRequestAndCorrelationIDs(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC().Truncate(time.Microsecond)
	valid := authorization.AuditContext{
		RequestID: uuid.Must(uuid.NewV7()), CorrelationID: uuid.Must(uuid.NewV7()),
		RemoteAddress: netip.MustParseAddr("192.0.2.44"), UserAgent: "identity-provider adapter test",
	}
	if _, err := identityProviderAuditArgumentsFor(valid, now, "totp"); err != nil {
		t.Fatalf("valid audit context rejected: %v", err)
	}
	for _, mutate := range []func(*authorization.AuditContext){
		func(value *authorization.AuditContext) { value.RequestID = uuid.Nil },
		func(value *authorization.AuditContext) { value.CorrelationID = uuid.Nil },
	} {
		candidate := valid
		mutate(&candidate)
		if _, err := identityProviderAuditArgumentsFor(candidate, now, "totp"); !errors.Is(err, identityprovider.ErrInvalidInput) {
			t.Fatalf("missing transactional audit identifier error = %v", err)
		}
	}
}
