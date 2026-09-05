package postgres

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestScanSecurityAuditEventCanonicalizesNullableDocuments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		before []byte
		after  []byte
	}{
		{name: "SQL NULL"},
		{name: "JSON null", before: []byte("null"), after: []byte(" \nnull\t")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			event, err := scanSecurityAuditEvent(securityAuditProjectionRow{
				before: test.before,
				after:  test.after,
			})
			if err != nil {
				t.Fatalf("scanSecurityAuditEvent() error = %v", err)
			}
			if string(event.Before) != `{}` || string(event.After) != `{}` {
				t.Fatalf("canonical documents = %s / %s", event.Before, event.After)
			}
			if string(event.Metadata) != `{}` {
				t.Fatalf("metadata = %s", event.Metadata)
			}
		})
	}
}

func TestScanSecurityAuditEventPreservesAndCopiesObjects(t *testing.T) {
	t.Parallel()

	before := []byte(`{"state":"open"}`)
	after := []byte(`{"state":"assigned"}`)
	event, err := scanSecurityAuditEvent(securityAuditProjectionRow{
		before: before,
		after:  after,
	})
	if err != nil {
		t.Fatalf("scanSecurityAuditEvent() error = %v", err)
	}
	before[2] = 'X'
	after[2] = 'X'
	if string(event.Before) != `{"state":"open"}` || string(event.After) != `{"state":"assigned"}` {
		t.Fatalf("scanned documents alias row storage: %s / %s", event.Before, event.After)
	}
}

func TestCanonicalAuditObjectPreservesMalformedNonNullInput(t *testing.T) {
	t.Parallel()

	for _, document := range [][]byte{{}, []byte(" \n\t"), []byte(`[]`)} {
		actual := canonicalAuditObject(document)
		if string(actual) != string(document) {
			t.Fatalf("canonicalAuditObject(%q) = %q", document, actual)
		}
	}
}

type securityAuditProjectionRow struct {
	before []byte
	after  []byte
}

func (row securityAuditProjectionRow) Scan(destinations ...any) error {
	if len(destinations) != 23 {
		return fmt.Errorf("audit projection destination count = %d", len(destinations))
	}
	eventID := uuid.MustParse("00000000-0000-7000-8000-000000000101")
	tenantID := uuid.MustParse("00000000-0000-7000-8000-000000000102")
	userID := uuid.MustParse("00000000-0000-7000-8000-000000000103")
	resourceID := uuid.MustParse("00000000-0000-7000-8000-000000000104")
	requestID := uuid.MustParse("00000000-0000-7000-8000-000000000105")
	correlationID := uuid.MustParse("00000000-0000-7000-8000-000000000106")
	address := netip.MustParseAddr("198.51.100.42")
	zeroUUID := pgtype.UUID{}

	*destinations[0].(*uuid.UUID) = eventID
	*destinations[1].(*pgtype.UUID) = databaseAuditUUID(tenantID)
	*destinations[2].(*int64) = 1
	*destinations[3].(*time.Time) = time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)
	*destinations[4].(*string) = "user"
	*destinations[5].(*pgtype.UUID) = databaseAuditUUID(userID)
	*destinations[6].(*pgtype.UUID) = zeroUUID
	*destinations[7].(*pgtype.UUID) = zeroUUID
	*destinations[8].(*string) = "audit.fixture"
	*destinations[9].(*string) = "audit_log"
	*destinations[10].(*pgtype.UUID) = databaseAuditUUID(resourceID)
	*destinations[11].(*pgtype.UUID) = databaseAuditUUID(requestID)
	*destinations[12].(*pgtype.UUID) = databaseAuditUUID(correlationID)
	*destinations[13].(**netip.Addr) = &address
	*destinations[14].(*pgtype.Text) = pgtype.Text{String: "audit-test", Valid: true}
	*destinations[15].(*pgtype.Text) = pgtype.Text{String: "totp", Valid: true}
	*destinations[16].(*string) = "success"
	*destinations[17].(*pgtype.Text) = pgtype.Text{}
	*destinations[18].(*[]byte) = row.before
	*destinations[19].(*[]byte) = row.after
	*destinations[20].(*[]byte) = []byte(`{}`)
	*destinations[21].(*string) = strings.Repeat("0", 64)
	*destinations[22].(*string) = strings.Repeat("a", 64)
	return nil
}

func databaseAuditUUID(identifier uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: [16]byte(identifier), Valid: true}
}
