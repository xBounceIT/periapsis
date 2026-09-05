package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func TestTicketingRepositoryReplaceMetadataUsesBoundTransactionalABI(t *testing.T) {
	t.Parallel()
	write := metadataAdapterWrite(t, kernel.AggregateAlert)
	now := time.Date(2026, 8, 30, 14, 15, 16, 123000000, time.UTC)
	payload := metadataAdapterPayload(write, now, 8)
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	abiCalls := 0
	tx := &platformLocalAccountAdapterTransaction{}
	tx.queryRow = func(query string, arguments []any, destinations []any) error {
		switch {
		case strings.Contains(query, "app.tenant_id"):
			*destinations[0].(*string) = write.TenantID.String()
			*destinations[1].(*string) = write.Actor.UserID.String()
		case strings.Contains(query, "app.traceparent"):
			*destinations[0].(*string) = ""
			*destinations[1].(*string) = ""
		case strings.Contains(query, "replace_tenant_ticket_metadata_v1"):
			abiCalls++
			if len(arguments) != 19 || arguments[0] != "alert" || arguments[1] != write.TicketID ||
				arguments[2] != int64(7) || arguments[3] != write.Content.Title ||
				arguments[4] != write.Content.Description || arguments[5] != (*string)(nil) ||
				arguments[6] != write.Content.Severity || arguments[7] != write.Content.Priority ||
				arguments[8] != write.Content.Category || arguments[9] != write.Content.Classification ||
				arguments[10] != write.Content.CustomerVisible {
				t.Fatalf("metadata ABI arguments = %#v", arguments)
			}
			if tags, ok := arguments[11].([]string); !ok || len(tags) != 2 || tags[0] != "confirmed" {
				t.Fatalf("metadata ABI tags = %#v", arguments[11])
			}
			if key, ok := arguments[12].([]byte); !ok || string(key) != string(write.KeyHash[:]) {
				t.Fatal("metadata ABI key digest mismatch")
			}
			if request, ok := arguments[13].([]byte); !ok || string(request) != string(write.Fingerprint[:]) {
				t.Fatal("metadata ABI request digest mismatch")
			}
			if arguments[14] != write.Audit.RequestID || arguments[15] != write.Audit.CorrelationID ||
				arguments[16] != write.Audit.RemoteAddress.Unmap() || arguments[17] != write.Audit.UserAgent ||
				arguments[18] != write.Actor.AuthenticationMethod {
				t.Fatalf("metadata ABI audit arguments = %#v", arguments[14:])
			}
			*destinations[0].(*int64) = 8
			*destinations[1].(*time.Time) = now
			*destinations[2].(*[]byte) = raw
			*destinations[3].(*bool) = false
		default:
			t.Fatalf("unexpected query: %s", query)
		}
		return nil
	}
	repository := &TicketingRepository{begin: platformLocalAccountAdapterBegin(t, tx)}
	result, err := repository.ReplaceMetadata(context.Background(), write)
	if err != nil || result.Replayed || result.Metadata.Version != 8 ||
		result.Metadata.TenantID != write.TenantID || result.Metadata.TicketID != write.TicketID ||
		result.Metadata.Kind != kernel.AggregateAlert || result.Metadata.Title != write.Content.Title ||
		!result.Metadata.UpdatedAt.Equal(now) {
		t.Fatalf("ReplaceMetadata() = (%#v, %v)", result, err)
	}
	if abiCalls != 1 || !tx.committed || tx.rollbackCalls != 1 {
		t.Fatalf("transaction abi=%d committed=%t rollbacks=%d", abiCalls, tx.committed, tx.rollbackCalls)
	}
}

func TestTicketingRepositoryReplaceMetadataMapsStaleCASAndRejectsCancelledContext(t *testing.T) {
	t.Parallel()
	write := metadataAdapterWrite(t, kernel.AggregateCase)
	tx := &platformLocalAccountAdapterTransaction{}
	tx.queryRow = func(query string, arguments []any, destinations []any) error {
		switch {
		case strings.Contains(query, "app.tenant_id"):
			*destinations[0].(*string) = write.TenantID.String()
			*destinations[1].(*string) = write.Actor.UserID.String()
			return nil
		case strings.Contains(query, "app.traceparent"):
			*destinations[0].(*string), *destinations[1].(*string) = "", ""
			return nil
		case strings.Contains(query, "replace_tenant_ticket_metadata_v1"):
			if len(arguments) != 19 || arguments[0] != "case" {
				t.Fatalf("case metadata ABI arguments = %#v", arguments)
			}
			summary, ok := arguments[5].(*string)
			if !ok || summary == nil || *summary != write.Content.Summary {
				t.Fatalf("case metadata ABI summary = %#v", arguments[5])
			}
			return &pgconn.PgError{Code: "40001", Message: "stale metadata version"}
		default:
			return errors.New("unexpected query")
		}
	}
	repository := &TicketingRepository{begin: platformLocalAccountAdapterBegin(t, tx)}
	if _, err := repository.ReplaceMetadata(context.Background(), write); !errors.Is(err, application.ErrPreconditionFailed) {
		t.Fatalf("stale CAS error = %v", err)
	}
	if tx.committed {
		t.Fatal("stale CAS transaction committed")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	beginCalls := 0
	repository.begin = func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
		beginCalls++
		return tx, nil
	}
	if _, err := repository.ReplaceMetadata(cancelled, write); !errors.Is(err, application.ErrUnavailable) || beginCalls != 0 {
		t.Fatalf("cancelled metadata error=%v begins=%d", err, beginCalls)
	}
}

func TestDecodeTicketMetadataResultFailsClosedOnProjectionDrift(t *testing.T) {
	t.Parallel()
	write := metadataAdapterWrite(t, kernel.AggregateAlert)
	now := time.Date(2026, 8, 30, 14, 15, 16, 0, time.UTC)
	payload := metadataAdapterPayload(write, now, 8)
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "unknown field", mutate: func(value map[string]any) { value["raw_payload"] = map[string]any{"secret": true} }},
		{name: "wrong tenant", mutate: func(value map[string]any) { value["tenant_id"] = uuid.Must(uuid.NewV7()) }},
		{name: "wrong version", mutate: func(value map[string]any) { value["version"] = 9 }},
		{name: "missing tags", mutate: func(value map[string]any) { value["tags"] = nil }},
		{name: "missing nullable classification", mutate: func(value map[string]any) { delete(value, "classification") }},
		{name: "missing false customer visibility", mutate: func(value map[string]any) { delete(value, "customer_visible") }},
		{name: "missing empty alert summary", mutate: func(value map[string]any) { delete(value, "summary") }},
	}
	base, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var value map[string]any
			if err := json.Unmarshal(base, &value); err != nil {
				t.Fatal(err)
			}
			test.mutate(value)
			raw, marshalErr := json.Marshal(value)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			if _, decodeErr := decodeTicketMetadataResult(
				raw, 8, now, false, write.TenantID, write.TicketID, write.Kind,
			); !errors.Is(decodeErr, application.ErrUnavailable) {
				t.Fatalf("decode error = %v", decodeErr)
			}
		})
	}
}

func TestDecodeTicketMetadataResultAcceptsMaximumUnicodeCaseProjection(t *testing.T) {
	t.Parallel()
	write := metadataAdapterWrite(t, kernel.AggregateCase)
	write.Content.Title = strings.Repeat("é", 240)
	write.Content.Summary = strings.Repeat("界", 2_000)
	write.Content.Description = strings.Repeat("界", 20_000)
	write.Content.Category = strings.Repeat("é", 120)
	now := time.Date(2026, 8, 30, 14, 15, 16, 0, time.UTC)
	raw, err := json.Marshal(metadataAdapterPayload(write, now, 8))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= 64*1024 {
		t.Fatalf("fixture is only %d bytes; it does not cover the old result cap", len(raw))
	}
	result, err := decodeTicketMetadataResult(
		raw, 8, now, false, write.TenantID, write.TicketID, write.Kind,
	)
	if err != nil || result.Metadata.Description != write.Content.Description ||
		result.Metadata.Summary != write.Content.Summary {
		t.Fatalf("maximum Unicode projection = (%#v, %v)", result, err)
	}
}

func metadataAdapterWrite(t testing.TB, kind kernel.AggregateKind) application.MetadataWrite {
	t.Helper()
	tenantID, ticketID, actorID := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	classification := "restricted"
	audit := application.AuditContext{
		RequestID: uuid.Must(uuid.NewV7()), CorrelationID: uuid.Must(uuid.NewV7()),
		RemoteAddress: netip.MustParseAddr("192.0.2.80"), UserAgent: "metadata-adapter-test",
	}
	actor := application.Actor{
		UserID: actorID, SessionID: uuid.Must(uuid.NewV7()), ActiveTenantID: tenantID,
		AuthenticationMethod: "totp", Audit: audit,
	}
	key, request := sha256.Sum256([]byte("metadata-key")), sha256.Sum256([]byte("metadata-request"))
	content := application.EditableMetadata{
		Title: "Confirmed intrusion", Description: "Investigation narrative",
		Severity: "critical", Priority: "urgent", Category: "incident",
		Classification: &classification, CustomerVisible: true,
		Tags: []string{"confirmed", "endpoint"},
	}
	if kind == kernel.AggregateCase {
		content.Summary = "Executive summary"
	}
	return application.MetadataWrite{
		Actor: actor, TenantID: tenantID, Kind: kind, TicketID: ticketID,
		Content: content, ExpectedVersion: 7, KeyHash: key, Fingerprint: request, Audit: audit,
	}
}

func metadataAdapterPayload(write application.MetadataWrite, updatedAt time.Time, version int64) ticketMetadataResultPayload {
	return ticketMetadataResultPayload{
		SchemaVersion: 1, TenantID: write.TenantID, TicketID: write.TicketID,
		AggregateKind: write.Kind.String(), Title: write.Content.Title,
		Description: write.Content.Description, Summary: write.Content.Summary,
		Severity: write.Content.Severity, Priority: write.Content.Priority,
		Category: write.Content.Category, Classification: write.Content.Classification,
		CustomerVisible: write.Content.CustomerVisible, Tags: write.Content.Tags,
		Version: version, UpdatedAt: updatedAt,
	}
}
