package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	kernel "github.com/periapsis-im/periapsis/modules/dfir"
	application "github.com/periapsis-im/periapsis/services/api/internal/dfir"
)

func TestDFIRSQLArrayCodecDistinguishesOmittedAndEmpty(t *testing.T) {
	t.Parallel()
	codec := pgtype.NewMap()
	// This is the pre-fix mapping: pgx sends an omitted Go slice as SQL NULL,
	// even when the database column has an empty-array default.
	var omitted []string
	encoded, err := codec.Encode(pgtype.TextArrayOID, pgtype.TextFormatCode, omitted, nil)
	if err != nil || encoded != nil {
		t.Fatalf("omitted array encoding = %q, error %v; want SQL NULL", encoded, err)
	}
	encoded, err = codec.Encode(pgtype.TextArrayOID, pgtype.TextFormatCode, []string{}, nil)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("empty array encoding = %q, error %v; want {}", encoded, err)
	}
}

func TestDFIRIndicatorSQLArrayMapping(t *testing.T) {
	t.Parallel()
	for _, operation := range []struct {
		name     string
		write    func(context.Context, databaseTransaction, application.IndicatorWrite) error
		tagsSlot int
	}{
		{"insert", insertDFIRIndicator, 13},
		{"update", updateDFIRIndicator, 14},
	} {
		for _, input := range []struct {
			name string
			tags []string
		}{
			{"omitted", nil},
			{"empty", []string{}},
			{"populated", []string{"triaged", "malware"}},
		} {
			t.Run(operation.name+"/"+input.name, func(t *testing.T) {
				observed := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
				value, err := kernel.NewIndicator(kernel.IndicatorInput{
					ID:       entityID(uuid.MustParse("00000000-0000-7000-8000-000000000701")),
					TenantID: entityID(uuid.MustParse("00000000-0000-7000-8000-000000000702")),
					Type:     kernel.IndicatorDomain, Value: "array-mapping.example", Source: "unit-test",
					Confidence: 80, TLP: kernel.TLPAmber, Malicious: kernel.MaliciousSuspicious,
					FirstSeen: observed, LastSeen: observed, Tags: input.tags,
				})
				if err != nil {
					t.Fatalf("valid indicator input: %v", err)
				}
				calls := 0
				tx := &dfirTransactionStub{exec: func(query string, args []any) (pgconn.CommandTag, error) {
					calls++
					if !strings.Contains(query, "public.dfir_iocs") {
						t.Fatal("unexpected IOC SQL relation")
					}
					assertDFIRSQLStringArray(t, "tags", args[operation.tagsSlot], value.Tags())
					return pgconn.NewCommandTag("UPDATE 1"), nil
				}}
				if err := operation.write(t.Context(), tx, application.IndicatorWrite{Indicator: value, ExpectedVersion: 1}); err != nil {
					t.Fatal(err)
				}
				if calls != 1 {
					t.Fatalf("SQL calls = %d, want 1", calls)
				}
			})
		}
	}
}

func TestDFIRAssetSQLArrayMapping(t *testing.T) {
	t.Parallel()
	for _, operation := range []struct {
		name   string
		write  func(context.Context, databaseTransaction, application.AssetWrite) error
		offset int
	}{
		{"insert", insertDFIRAsset, 0},
		{"update", updateDFIRAsset, 1},
	} {
		for _, input := range []struct {
			name                         string
			ips, hardware, tags          []string
			wantIPs, wantMACs, wantMAC8s []string
		}{
			{name: "omitted"},
			{name: "empty", ips: []string{}, hardware: []string{}, tags: []string{}},
			{name: "six_byte_only", hardware: []string{"02-AA-BB-CC-DD-EE"}, wantMACs: []string{"02:aa:bb:cc:dd:ee"}},
			{name: "eight_byte_only", hardware: []string{"02-AA-BB-CC-DD-EE-FF-00"}, wantMAC8s: []string{"02:aa:bb:cc:dd:ee:ff:00"}},
			{
				name: "both_families_and_tags", ips: []string{"2001:0db8::1", "192.0.2.1"},
				hardware: []string{"02-AA-BB-CC-DD-EE-FF-00", "02-AA-BB-CC-DD-EE"},
				tags:     []string{"triaged", "endpoint"}, wantIPs: []string{"192.0.2.1", "2001:db8::1"},
				wantMACs: []string{"02:aa:bb:cc:dd:ee"}, wantMAC8s: []string{"02:aa:bb:cc:dd:ee:ff:00"},
			},
		} {
			t.Run(operation.name+"/"+input.name, func(t *testing.T) {
				observed := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
				value, err := kernel.NewAsset(kernel.AssetInput{
					ID:         entityID(uuid.MustParse("00000000-0000-7000-8000-000000000703")),
					TenantID:   entityID(uuid.MustParse("00000000-0000-7000-8000-000000000702")),
					ExternalID: "array-mapping", AssetType: "endpoint", Environment: "test", Criticality: kernel.AssetCriticalityHigh,
					FirstSeen: observed, LastSeen: observed, Tags: input.tags, IPAddresses: input.ips, MACAddresses: input.hardware,
				})
				if err != nil {
					t.Fatalf("valid asset input: %v", err)
				}
				calls := 0
				tx := &dfirTransactionStub{exec: func(query string, args []any) (pgconn.CommandTag, error) {
					calls++
					if !strings.Contains(query, "public.dfir_assets") {
						t.Fatal("unexpected asset SQL relation")
					}
					assertDFIRSQLStringArray(t, "ip_addresses", args[6+operation.offset], input.wantIPs)
					assertDFIRSQLStringArray(t, "mac_addresses", args[7+operation.offset], input.wantMACs)
					assertDFIRSQLStringArray(t, "mac8_addresses", args[8+operation.offset], input.wantMAC8s)
					assertDFIRSQLStringArray(t, "tags", args[17+operation.offset], value.Tags())
					return pgconn.NewCommandTag("UPDATE 1"), nil
				}}
				if err := operation.write(t.Context(), tx, application.AssetWrite{Asset: value, ExpectedVersion: 1}); err != nil {
					t.Fatal(err)
				}
				if calls != 1 {
					t.Fatalf("SQL calls = %d, want 1", calls)
				}
			})
		}
	}
}

func TestDFIRTimelineSQLArrayMapping(t *testing.T) {
	t.Parallel()
	for _, rootKind := range []string{"case", "alert"} {
		for _, tags := range []struct {
			name   string
			values []string
		}{
			{"omitted", nil},
			{"empty", []string{}},
			{"populated", []string{"triaged", "investigation"}},
		} {
			t.Run(rootKind+"/"+tags.name, func(t *testing.T) {
				observed := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
				rootID := uuid.MustParse("00000000-0000-7000-8000-000000000704")
				input := kernel.TimelineEventInput{
					ID:        entityID(uuid.MustParse("00000000-0000-7000-8000-000000000705")),
					TenantID:  entityID(uuid.MustParse("00000000-0000-7000-8000-000000000702")),
					EventTime: observed, IngestedAt: observed, OriginalTimezone: "UTC", Precision: kernel.PrecisionSecond,
					Source: "unit-test", Category: "observation", Title: "Array mapping", Tags: tags.values,
				}
				if rootKind == "case" {
					input.CaseID = entityID(rootID)
				} else {
					input.AlertID = entityID(rootID)
				}
				value, err := kernel.NewTimelineEvent(input)
				if err != nil {
					t.Fatalf("valid timeline input: %v", err)
				}
				calls := 0
				tx := &dfirTransactionStub{exec: func(query string, args []any) (pgconn.CommandTag, error) {
					calls++
					if !strings.Contains(query, "INSERT INTO public.dfir_timeline_events") {
						t.Fatal("unexpected timeline SQL operation")
					}
					rootSlot, absentSlot := 2, 3
					if rootKind == "case" {
						rootSlot, absentSlot = 3, 2
					}
					if args[rootSlot] != rootID || args[absentSlot] != nil || args[12] != nil {
						t.Fatal("timeline root or optional actor mapping changed")
					}
					assertDFIRSQLStringArray(t, "tags", args[13], value.Tags())
					return pgconn.NewCommandTag("INSERT 0 1"), nil
				}}
				if err := insertDFIRTimelineEvent(t.Context(), tx, application.TimelineWrite{Event: value}); err != nil {
					t.Fatal(err)
				}
				if calls != 1 {
					t.Fatalf("SQL calls = %d, want 1", calls)
				}
			})
		}
	}
}

func TestDFIRAssetReadbackAndReceiptPreserveOmittedTags(t *testing.T) {
	t.Parallel()
	observed := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
	input := kernel.AssetInput{
		ID: alertTestEntityID(111), TenantID: alertTestEntityID(112),
		ExternalID: "empty-arrays", AssetType: "endpoint", Environment: "test", Criticality: kernel.AssetCriticalityHigh,
		FirstSeen: observed, LastSeen: observed,
	}
	omitted, err := kernel.NewAsset(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Tags = []string{}
	readback, err := kernel.NewAsset(input)
	if err != nil {
		t.Fatal(err)
	}
	if !sameDFIRAsset(omitted, readback) || !sameDFIRAsset(readback, omitted) {
		t.Error("SQL empty-array readback differs from the valid omitted-tags asset")
	}
	coordinate := dfirMutationCoordinate{
		tenantID: uuid.UUID(input.TenantID.Bytes()), rootKind: dfirMutationRootAlert, rootID: alertTestUUID(113),
		operation: "dfir.asset.replace", resourceKind: dfirMutationKindAsset,
		resourceID: uuid.UUID(input.ID.Bytes()), resultVersion: 2,
	}
	document, err := encodeDFIRAssetResult(coordinate, omitted)
	if err != nil {
		t.Fatal(err)
	}
	tx := &dfirTransactionStub{row: func(query string, _ []any, destinations []any) error {
		if !strings.Contains(query, "app.reserve_dfir_mutation_command_v1") {
			t.Fatal("unexpected historical receipt query")
		}
		*(destinations[0].(*uuid.UUID)) = alertTestUUID(118)
		*(destinations[1].(*uuid.UUID)) = coordinate.resourceID
		*(destinations[2].(**uuid.UUID)) = nil
		*(destinations[3].(*int64)) = int64(coordinate.resultVersion)
		*(destinations[4].(*[]byte)) = document
		*(destinations[5].(*bool)) = true
		return nil
	}}
	reservation, err := reserveDFIRMutationCommand(t.Context(), tx, alertTestUUID(119), coordinate,
		application.CommandBinding{Operation: coordinate.operation})
	if err != nil || !reservation.replayed || !slices.Equal(reservation.snapshot, document) {
		t.Fatalf("completed historical reservation changed: replayed %t, error %v", reservation.replayed, err)
	}
	replayed, err := decodeDFIRAssetResult(reservation.snapshot, coordinate)
	if err != nil || !sameDFIRAsset(omitted, replayed) {
		t.Errorf("omitted-tags immutable receipt round trip: %v", err)
	}
	for _, change := range []struct {
		name  string
		apply func(*kernel.AssetInput)
	}{
		{"tags", func(value *kernel.AssetInput) { value.Tags = []string{"changed"} }},
		{"owner", func(value *kernel.AssetInput) { value.Owner = "changed" }},
		{"custom_attributes", func(value *kernel.AssetInput) { value.CustomAttributes = json.RawMessage(`{"changed":true}`) }},
	} {
		t.Run(change.name, func(t *testing.T) {
			changedInput := input
			change.apply(&changedInput)
			changed, err := kernel.NewAsset(changedInput)
			if err != nil {
				t.Fatal(err)
			}
			if sameDFIRAsset(omitted, changed) {
				t.Fatal("asset comparison accepted a real content difference")
			}
		})
	}
}

func TestDFIRAlertReplacementReservationMapsOnlyExactLegacyRevisionCollision(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, root, operation, resource string
		version                         uint64
		code, schema, table, constraint string
		precondition                    bool
	}{
		{"ioc_revision", "alert", "dfir.ioc.replace", "ioc", 2, "23505", "public", "alert_dfir_resource_commands", "alert_dfir_resource_commands_result_key", true},
		{"asset_revision", "alert", "dfir.asset.replace", "asset", 2, "23505", "public", "alert_dfir_resource_commands", "alert_dfir_resource_commands_result_key", true},
		{"replay_key", "alert", "dfir.ioc.replace", "ioc", 2, "23505", "public", "alert_dfir_resource_commands", "alert_dfir_resource_commands_replay_key", false},
		{"other_constraint", "alert", "dfir.ioc.replace", "ioc", 2, "23505", "public", "alert_dfir_resource_commands", "dfir_mutation_replay_keys_pkey", false},
		{"wrong_code", "alert", "dfir.ioc.replace", "ioc", 2, "23503", "public", "alert_dfir_resource_commands", "alert_dfir_resource_commands_result_key", false},
		{"wrong_schema", "alert", "dfir.ioc.replace", "ioc", 2, "23505", "other", "alert_dfir_resource_commands", "alert_dfir_resource_commands_result_key", false},
		{"wrong_table", "alert", "dfir.ioc.replace", "ioc", 2, "23505", "public", "dfir_mutation_commands", "alert_dfir_resource_commands_result_key", false},
		{"case_root", "case", "dfir.ioc.replace", "ioc", 2, "23505", "public", "alert_dfir_resource_commands", "alert_dfir_resource_commands_result_key", false},
		{"create", "alert", "dfir.ioc.create", "ioc", 1, "23505", "public", "alert_dfir_resource_commands", "alert_dfir_resource_commands_result_key", false},
		{"asset_create", "alert", "dfir.asset.create", "asset", 1, "23505", "public", "alert_dfir_resource_commands", "alert_dfir_resource_commands_result_key", false},
		{"timeline_create", "alert", "dfir.timeline.create", "timeline_event", 1, "23505", "public", "alert_dfir_resource_commands", "alert_dfir_resource_commands_result_key", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			failure := &pgconn.PgError{Code: test.code, SchemaName: test.schema, TableName: test.table, ConstraintName: test.constraint}
			tx := &dfirTransactionStub{row: func(query string, _ []any, _ []any) error {
				if !strings.Contains(query, "app.reserve_dfir_mutation_command_v1") {
					t.Fatal("unexpected reservation query")
				}
				return failure
			}}
			coordinate := dfirMutationCoordinate{
				tenantID: alertTestUUID(114), rootKind: test.root, rootID: alertTestUUID(115),
				operation: test.operation, resourceKind: test.resource, resourceID: alertTestUUID(116), resultVersion: test.version,
			}
			_, err := reserveDFIRMutationCommand(t.Context(), tx, alertTestUUID(117), coordinate, application.CommandBinding{Operation: test.operation})
			if test.precondition {
				if !errors.Is(err, application.ErrRepositoryPrecondition) {
					t.Fatalf("occupied replacement revision = %v, want precondition", err)
				}
			} else if err != failure {
				t.Fatalf("unrelated reservation error = %v, want original database error", err)
			}
			wantMapped := application.ErrRepositoryConflict
			if test.precondition {
				wantMapped = application.ErrRepositoryPrecondition
			}
			if mapped := mapDFIRDatabaseError(err); !errors.Is(mapped, wantMapped) {
				t.Fatalf("repository error mapping = %v, want %v", mapped, wantMapped)
			}
		})
	}
}

func assertDFIRSQLStringArray(t *testing.T, name string, argument any, want []string) {
	t.Helper()
	values, ok := argument.([]string)
	if !ok {
		t.Errorf("%s SQL argument type = %T, want []string", name, argument)
		return
	}
	if values == nil || !slices.Equal(values, want) {
		t.Errorf("%s SQL argument = %#v, want a non-nil array containing %v", name, values, want)
	}
	// Text-array encoding checks NULL versus empty independently of a running server.
	encoded, err := pgtype.NewMap().Encode(pgtype.TextArrayOID, pgtype.TextFormatCode, values, nil)
	if err != nil || encoded == nil || len(want) == 0 && string(encoded) != "{}" {
		t.Errorf("%s PostgreSQL array encoding = %q, error %v", name, encoded, err)
	}
}
