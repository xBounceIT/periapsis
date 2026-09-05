package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"

	"github.com/periapsis-im/periapsis/services/api/internal/ticketnumbering"
)

func TestMapTicketNumberingPolicyRestoresClosedPublisherAndFormatVariants(t *testing.T) {
	t.Parallel()
	publishedAt := time.Date(2026, 9, 3, 11, 0, 0, 123_000, time.UTC)
	tenantID := uuid.MustParse("019d7800-2400-7000-8000-000000000001")
	versionID := uuid.MustParse("019d7800-2400-7000-8000-000000000002")
	publisherID := uuid.MustParse("019d7800-2400-7000-8000-000000000003")

	systemPolicy, err := mapTicketNumberingPolicy(
		toDatabaseUUID(versionID), toDatabaseUUID(tenantID), "alert", 1,
		"ALT", "-", "annual", 6, 1, pgtype.UUID{}, databaseTime(publishedAt),
	)
	if err != nil {
		t.Fatalf("map system policy: %v", err)
	}
	if systemPolicy.VersionID().String() != versionID.String() ||
		systemPolicy.Tenant().String() != tenantID.String() ||
		systemPolicy.Kind() != kernel.AggregateAlert || systemPolicy.Version() != 1 ||
		systemPolicy.Publisher().Kind() != kernel.NumberingPolicyPublisherSystem ||
		systemPolicy.PublishedBy() != (kernel.EntityID{}) ||
		!systemPolicy.PublishedAt().Equal(publishedAt) ||
		systemPolicy.Spec().Prefix() != "ALT" || systemPolicy.Spec().Separator() != "-" ||
		systemPolicy.Spec().Period() != kernel.NumberingPeriodAnnual ||
		systemPolicy.Spec().Width() != 6 || systemPolicy.Spec().Start() != 1 {
		t.Fatalf("unexpected system policy projection: %+v", systemPolicy)
	}

	membershipPolicy, err := mapTicketNumberingPolicy(
		toDatabaseUUID(versionID), toDatabaseUUID(tenantID), "case", 2,
		"INC", "/", "lifetime", 8, 100, toDatabaseUUID(publisherID), databaseTime(publishedAt),
	)
	if err != nil {
		t.Fatalf("map membership policy: %v", err)
	}
	if membershipPolicy.Kind() != kernel.AggregateCase || membershipPolicy.Version() != 2 ||
		membershipPolicy.PublishedBy().String() != publisherID.String() ||
		membershipPolicy.Spec().Period() != kernel.NumberingPeriodNone ||
		membershipPolicy.Spec().Prefix() != "INC" || membershipPolicy.Spec().Separator() != "/" ||
		membershipPolicy.Spec().Width() != 8 || membershipPolicy.Spec().Start() != 100 {
		t.Fatalf("unexpected membership policy projection: %+v", membershipPolicy)
	}
}

func TestMapTicketNumberingPolicyRejectsMalformedDatabaseRows(t *testing.T) {
	t.Parallel()
	now := databaseTime(time.Date(2026, 9, 3, 11, 0, 0, 0, time.UTC))
	validID := toDatabaseUUID(uuid.MustParse("019d7800-2400-7000-8000-000000000011"))
	tests := []struct {
		name      string
		versionID pgtype.UUID
		tenantID  pgtype.UUID
		kind      string
		version   int32
		prefix    string
		separator string
		period    string
		width     int32
		start     int64
		publisher pgtype.UUID
		at        pgtype.Timestamptz
	}{
		{name: "null version id", tenantID: validID, kind: "alert", version: 1, prefix: "ALT", separator: "-", period: "annual", width: 6, start: 1, at: now},
		{name: "non v7 tenant", versionID: validID, tenantID: toDatabaseUUID(uuid.MustParse("3d5c5f40-3421-4c36-a439-71870ad11ec3")), kind: "alert", version: 1, prefix: "ALT", separator: "-", period: "annual", width: 6, start: 1, at: now},
		{name: "unknown kind", versionID: validID, tenantID: validID, kind: "task", version: 1, prefix: "ALT", separator: "-", period: "annual", width: 6, start: 1, at: now},
		{name: "zero version", versionID: validID, tenantID: validID, kind: "alert", version: 0, prefix: "ALT", separator: "-", period: "annual", width: 6, start: 1, at: now},
		{name: "invalid prefix", versionID: validID, tenantID: validID, kind: "alert", version: 1, prefix: "bad", separator: "-", period: "annual", width: 6, start: 1, at: now},
		{name: "unknown period", versionID: validID, tenantID: validID, kind: "case", version: 1, prefix: "CAS", separator: "-", period: "monthly", width: 6, start: 1, at: now},
		{name: "narrow width", versionID: validID, tenantID: validID, kind: "case", version: 1, prefix: "CAS", separator: "-", period: "annual", width: 3, start: 1, at: now},
		{name: "zero start", versionID: validID, tenantID: validID, kind: "case", version: 1, prefix: "CAS", separator: "-", period: "annual", width: 6, start: 0, at: now},
		{name: "null timestamp", versionID: validID, tenantID: validID, kind: "case", version: 1, prefix: "CAS", separator: "-", period: "annual", width: 6, start: 1},
		{name: "membership version without publisher", versionID: validID, tenantID: validID, kind: "case", version: 2, prefix: "CAS", separator: "-", period: "annual", width: 6, start: 1, at: now},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := mapTicketNumberingPolicy(
				test.versionID, test.tenantID, test.kind, test.version, test.prefix,
				test.separator, test.period, test.width, test.start, test.publisher, test.at,
			); err == nil {
				t.Fatal("malformed database policy was accepted")
			}
		})
	}
}

func TestTicketNumberingDatabaseMappingsRemainClosed(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		code string
		want error
	}{
		{code: "22023", want: ticketnumbering.ErrRepositoryInvalidInput},
		{code: "23514", want: ticketnumbering.ErrRepositoryInvalidInput},
		{code: "42501", want: ticketnumbering.ErrRepositoryForbidden},
		{code: "P0002", want: ticketnumbering.ErrRepositoryNotFound},
		{code: "40001", want: ticketnumbering.ErrRepositoryPrecondition},
		{code: "23505", want: ticketnumbering.ErrRepositoryConflict},
	} {
		if err := mapTicketNumberingDatabaseError(&pgconn.PgError{Code: test.code}); !errors.Is(err, test.want) {
			t.Fatalf("database code %s mapped to %v, want %v", test.code, err, test.want)
		}
	}
	if _, err := ticketNumberingDatabaseKind(kernel.AggregateKind(255)); !errors.Is(err, ticketnumbering.ErrRepositoryInvalidInput) {
		t.Fatalf("unknown aggregate kind mapped to %v", err)
	}
	if _, err := ticketNumberingDatabasePeriod(kernel.NumberingPeriod(255)); !errors.Is(err, ticketnumbering.ErrRepositoryInvalidInput) {
		t.Fatalf("unknown period mapped to %v", err)
	}
	if _, err := ticketNumberingKernelKind("task"); err == nil {
		t.Fatal("unknown database aggregate kind was accepted")
	}
	if _, err := ticketNumberingKernelPeriod("monthly"); err == nil {
		t.Fatal("unknown database period was accepted")
	}
}
