package postgres

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/periapsis-im/periapsis/services/worker/internal/dfirscan"
)

func TestRestoreDFIRStorageObjectNormalizesDatabaseTimes(t *testing.T) {
	t.Parallel()
	created := time.Date(2026, 9, 8, 10, 0, 0, 123000, time.FixedZone("database", 7200))
	verified, retention := created.Add(time.Minute), created.Add(24*time.Hour)
	id := uuid.MustParse("01991234-5678-7000-8000-000000000001")
	mime := "text/plain"
	for _, state := range []string{"pending_upload", "available", "retained"} {
		t.Run(state, func(t *testing.T) {
			var digest []byte
			var size int64
			var detected *string
			var verifiedAt, retentionUntil *time.Time
			updated := created
			if state != "pending_upload" {
				digest, size, detected = make([]byte, 32), 64, &mime
				verifiedAt, updated = &verified, verified
				if state == "retained" {
					retentionUntil = &retention
				}
			}
			object, err := restoreDFIRStorageObject(id, id, "periapsis-evidence", id.String()+"/evidence", "evidence.txt", "internal", 64,
				created.Add(15*time.Minute), id, created, updated, state, digest, size, detected, verifiedAt, retentionUntil, false, 1)
			if err != nil {
				t.Fatal(err)
			}
			for _, pair := range [][2]time.Time{{object.CreatedAt(), created}, {object.UpdatedAt(), updated}, {object.UploadExpiresAt(), created.Add(15 * time.Minute)}} {
				if pair[0].Location() != time.UTC || !pair[0].Equal(pair[1]) {
					t.Fatal("storage instant changed or is not canonical UTC")
				}
			}
			if state != "pending_upload" {
				if object.CanIssueDownload() != (state == "available") || object.VerifiedAt().Location() != time.UTC || !object.VerifiedAt().Equal(verified) {
					t.Fatal("verified storage timestamps or capability were lost")
				}
				if state == "retained" && (object.RetentionUntil().Location() != time.UTC || !object.RetentionUntil().Equal(retention)) {
					t.Fatal("retention instant changed or is not canonical UTC")
				}
				if verified.Location() == time.UTC || retention.Location() == time.UTC {
					t.Fatal("mapper mutated input pointers")
				}
			}
		})
	}
}

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
