package postgres

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/periapsis-im/periapsis/services/api/internal/mfapolicy"
)

func TestMapMFAPolicyDatabaseErrorPreservesConflictTaxonomy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		code    string
		message string
		want    error
	}{
		{name: "create collision", code: "40001", message: "MFA policy create revision conflict", want: mfapolicy.ErrConflict},
		{name: "simulation create collision", code: "40001", message: "MFA policy simulation create conflict", want: mfapolicy.ErrConflict},
		{name: "stale replacement", code: "40001", message: "MFA policy revision conflict", want: mfapolicy.ErrPreconditionFailed},
		{name: "replay mismatch", code: "23505", message: "MFA policy command replay payload mismatch", want: mfapolicy.ErrConflict},
		{name: "unsafe recovery", code: "55000", message: "MFA policy would violate direct recovery safety", want: mfapolicy.ErrRecoveryUnsafe},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := mapMFAPolicyDatabaseError(&pgconn.PgError{Code: test.code, Message: test.message})
			if !errors.Is(err, test.want) {
				t.Fatalf("map error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestDecodeMFAPolicyRequirementRejectsFreshnessOverflow(t *testing.T) {
	t.Parallel()
	_, err := decodeMFAPolicyRequirement(mfaPolicyRequirementWire{
		Level: "primary", FreshnessSeconds: 9_223_372_036_854_775_000,
	})
	if !errors.Is(err, mfapolicy.ErrUnavailable) {
		t.Fatalf("decode error = %v, want unavailable", err)
	}
}

func TestDecodeMFAPolicyProjectionRejectsNonCanonicalInstants(t *testing.T) {
	t.Parallel()
	for _, instant := range []string{
		"2026-08-30T00:00:00+00:00",
		"2026-08-30T01:00:00.000+01:00",
		"2026-08-30T00:00:00Z",
		"2026-08-30T00:00:00.000000Z",
	} {
		t.Run(instant, func(t *testing.T) {
			t.Parallel()
			document := []byte(`{"id":"018f0000-0000-7000-8000-000000000001","revision":1,` +
				`"target":{"scope":"platform_floor"},` +
				`"requirement":{"level":"primary","localRequired":true,` +
				`"freshnessSeconds":0,"enrollmentDeadline":null},` +
				`"status":"live","createdAt":"` + instant + `","retiredAt":null}`)
			_, err := decodeMFAPolicyDocument(document, uuid.Nil)
			if !errors.Is(err, mfapolicy.ErrUnavailable) {
				t.Fatalf("decode error = %v, want unavailable", err)
			}
		})
	}
}

func TestMFAPolicyProjectionShapeRejectsMissingNestedZeroValueFields(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		document string
		check    func([]byte) error
	}{
		{
			name: "document localRequired omitted",
			document: `{"id":"018f0000-0000-7000-8000-000000000001","revision":1,` +
				`"target":{"scope":"platform_floor"},` +
				`"requirement":{"level":"primary","freshnessSeconds":0,"enrollmentDeadline":null},` +
				`"status":"live","createdAt":"2026-08-30T00:00:00.000Z","retiredAt":null}`,
			check: requireMFAPolicyDocumentShape,
		},
		{
			name: "simulation recovery safe omitted",
			document: `{"operation":"create","target":{"scope":"platform_floor"},"context":null,` +
				`"current":null,"candidate":null,"effective":{"requirement":null,"sources":[]},` +
				`"recovery":{"eligibleDirectAdministrators":0,"readyDirectAdministrators":0,` +
				`"reasonCodes":["no_eligible_direct_administrator"]}}`,
			check: requireMFAPolicySimulationShape,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.check([]byte(test.document)); !errors.Is(err, mfapolicy.ErrUnavailable) {
				t.Fatalf("shape error = %v, want unavailable", err)
			}
		})
	}
}
