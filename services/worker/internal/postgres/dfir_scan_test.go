package postgres

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/periapsis-im/periapsis/services/worker/internal/dfirscan"
)

func TestClassifyDFIRScanDatabaseError(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		code string
		want error
	}{
		{"P5401", dfirscan.ErrEvidenceCustodyLimit},
		{"54000", dfirscan.ErrUnavailable},
		{"40001", dfirscan.ErrFenceLost},
		{"55000", dfirscan.ErrUnavailable},
		{"23514", dfirscan.ErrUnavailable},
	} {
		err := fmt.Errorf("transition: %w", &pgconn.PgError{Code: test.code})
		if got := classifyDFIRScanDatabaseError(err); !errors.Is(got, test.want) {
			t.Fatalf("classify(%s) = %v, want %v", test.code, got, test.want)
		}
	}
}
