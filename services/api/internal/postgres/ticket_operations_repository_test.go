package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func TestTicketOperationsReadinessRequiresEveryVersionedSurface(t *testing.T) {
	for _, test := range []struct {
		name      string
		bulk      bool
		export    bool
		metadata  bool
		wantReady bool
	}{
		{name: "all", bulk: true, export: true, metadata: true, wantReady: true},
		{name: "bulk missing", export: true, metadata: true},
		{name: "export missing", bulk: true, metadata: true},
		{name: "metadata missing", bulk: true, export: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx := &savedViewABITransaction{rows: []pgx.Row{
				rowFunc(func(destinations ...any) error {
					*destinations[0].(*bool) = test.bulk
					return nil
				}),
				rowFunc(func(destinations ...any) error {
					*destinations[0].(*bool) = test.export
					return nil
				}),
				rowFunc(func(destinations ...any) error {
					*destinations[0].(*bool) = test.metadata
					return nil
				}),
			}}
			repository := &TicketingRepository{begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
				return tx, nil
			}}
			err := repository.ReadyTicketOperations(context.Background())
			if (err == nil) != test.wantReady {
				t.Fatalf("ReadyTicketOperations() error = %v, want ready %t", err, test.wantReady)
			}
			if !tx.committed || len(tx.queries) != 3 ||
				tx.queries[0] != ticketBulkReadinessABIQuery || tx.queries[1] != ticketExportReadinessABIQuery ||
				tx.queries[2] != ticketMetadataReadinessQuery {
				t.Fatalf("readiness transaction = committed:%t queries:%#v", tx.committed, tx.queries)
			}
		})
	}
}

func TestTicketOperationsReadinessFailsBeforeDatabaseUse(t *testing.T) {
	if err := (*TicketingRepository)(nil).ReadyTicketOperations(context.Background()); !errors.Is(err, application.ErrUnavailable) {
		t.Fatalf("typed-nil readiness error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	repository := &TicketingRepository{begin: func(context.Context, pgx.TxOptions) (databaseTransaction, error) {
		called = true
		return nil, errors.New("unexpected begin")
	}}
	if err := repository.ReadyTicketOperations(ctx); !errors.Is(err, application.ErrUnavailable) || called {
		t.Fatalf("cancelled readiness = (%v, called:%t)", err, called)
	}
}

func TestTicketOperationsInstantNormalizesOnlyCanonicalUTCPrecision(t *testing.T) {
	written := time.Date(2026, 8, 30, 10, 11, 12, 345000000, time.UTC)
	decoded := written.In(time.FixedZone("postgres-json", 0))
	normalized, err := ticketOperationsInstant(decoded)
	if err != nil || !normalized.Equal(written) || normalized.Location() != time.UTC {
		t.Fatalf("ticketOperationsInstant() = (%v, %v)", normalized, err)
	}
	for _, invalid := range []time.Time{
		written.In(time.FixedZone("non-utc", int(time.Hour/time.Second))),
		written.Add(time.Nanosecond),
	} {
		if _, err := ticketOperationsInstant(invalid); err == nil {
			t.Fatalf("ticketOperationsInstant() accepted %v", invalid)
		}
	}
}

func TestTicketOperationInlineSourceUsesAuthorizedMembership(t *testing.T) {
	actorID := mustPostgresUUIDv7(t)
	tenantID := mustPostgresUUIDv7(t)
	membershipID := mustPostgresUUIDv7(t)
	actor := application.Actor{UserID: actorID, ActiveTenantID: tenantID}
	input := application.SavedViewSpecInput{
		Filters: application.SavedViewFiltersInput{Queue: "all"},
		Columns: []application.SavedViewColumnInput{{
			Source: application.SavedViewDefinitionCore, CoreKey: "ticket",
			Width: 320, Visible: true, Pin: "start",
		}},
		Sort: application.SavedViewSortInput{
			Source: application.SavedViewDefinitionCore, CoreKey: "created_at",
			Direction: "desc", Nulls: "last",
		},
	}
	wire, err := ticketOperationsBulkSourceRequest(
		actor, tenantID, membershipID, kernel.AggregateAlert,
		application.TicketBulkQuerySourceInput{Inline: &input},
	)
	if err != nil {
		t.Fatalf("ticketOperationsBulkSourceRequest() error = %v", err)
	}
	document, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Mode string `json:"mode"`
		Spec struct {
			ActorID      uuid.UUID `json:"actorId"`
			MembershipID uuid.UUID `json:"ownerMembershipId"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(document, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Mode != "inline" || envelope.Spec.ActorID != actorID || envelope.Spec.MembershipID != membershipID ||
		envelope.Spec.MembershipID == actorID {
		t.Fatalf("inline source identity binding = %#v", envelope)
	}
}

func TestTicketOperationsWorkerWireUsesNullUnusedTimeAndCanonicalFenceName(t *testing.T) {
	tenantID := mustPostgresUUIDv7(t)
	serviceAccountID := mustPostgresUUIDv7(t)
	workerID := mustPostgresUUIDv7(t)
	access, err := application.NewAsyncExportWorkerAccess(
		tenantID,
		serviceAccountID,
		kernel.AggregateCase,
		kernel.TicketExportAudienceOperator,
		application.AsyncExportCapabilityExecute,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	worker := application.AsyncExportWorker{
		ServiceAccountID: serviceAccountID,
		WorkerID:         workerID,
		Purpose:          application.AsyncExportWorkerPurpose,
	}
	document, err := json.Marshal(ticketOperationsWorkerRequest(
		worker, access, mustPostgresUUIDv7(t).String(), 0, [32]byte{}, time.Time{},
	))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Now         *time.Time `json:"now"`
		FenceSHA256 string     `json:"fenceSha256"`
	}
	if err := json.Unmarshal(document, &envelope); err != nil || envelope.Now != nil || envelope.FenceSHA256 != "" {
		t.Fatalf("legacy worker optional wire = %s, error = %v", document, err)
	}

	leaseDocument, err := json.Marshal(ticketOperationsExportLeaseWireV1{Fence: "digest"})
	if err != nil {
		t.Fatal(err)
	}
	var lease map[string]any
	if err := json.Unmarshal(leaseDocument, &lease); err != nil {
		t.Fatal(err)
	}
	if lease["fenceSha256"] != "digest" {
		t.Fatalf("export lease fence wire = %s", leaseDocument)
	}
	if _, legacy := lease["fence"]; legacy {
		t.Fatalf("export lease emitted ambiguous legacy fence field: %s", leaseDocument)
	}
}

func TestTicketBulkAccessUsesTenantTransactionAndExactVersionedWire(t *testing.T) {
	tenantID := mustPostgresUUIDv7(t)
	actorID := mustPostgresUUIDv7(t)
	membershipID := mustPostgresUUIDv7(t)
	actor := application.Actor{
		UserID: actorID, SessionID: mustPostgresUUIDv7(t), ActiveTenantID: tenantID,
		AuthenticationMethod: "oidc",
	}
	response, err := json.Marshal(ticketOperationsBulkAccessResponseV1{
		SchemaVersion: ticketOperationsWireVersion,
		TenantID:      tenantID.String(), ActorID: actorID.String(), MembershipID: membershipID.String(),
		Kind: kernel.AggregateAlert.String(), Capability: string(application.TicketBulkCapabilityRequest),
		Principal: kernel.PrincipalOperator.String(), MutationAction: kernel.ActionClaim.String(),
		Allowed: boolPointer(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	tx := &savedViewABITransaction{rows: []pgx.Row{
		rowFunc(func(destinations ...any) error {
			*destinations[0].(*string) = tenantID.String()
			*destinations[1].(*string) = actorID.String()
			return nil
		}),
		rowFunc(func(destinations ...any) error {
			*destinations[0].(*string), *destinations[1].(*string) = "", ""
			return nil
		}),
		rowFunc(func(destinations ...any) error {
			*destinations[0].(*[]byte) = append([]byte(nil), response...)
			return nil
		}),
	}}
	var options pgx.TxOptions
	repository := &TicketingRepository{begin: func(ctx context.Context, requested pgx.TxOptions) (databaseTransaction, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("ticket operation transaction lacks a deadline")
		}
		options = requested
		return tx, nil
	}}
	access, err := repository.ResolveTicketBulkAccess(
		context.Background(), actor, tenantID, kernel.AggregateAlert,
		application.TicketBulkCapabilityRequest, kernel.ActionClaim,
	)
	if err != nil || access.Tenant() != tenantID || access.Actor() != actorID ||
		access.Membership() != membershipID || access.Kind() != kernel.AggregateAlert ||
		access.Capability() != application.TicketBulkCapabilityRequest ||
		access.MutationAction() != kernel.ActionClaim || !access.Allowed() {
		t.Fatalf("ResolveTicketBulkAccess() = (%s, %v)", access, err)
	}
	if !tx.committed || len(tx.queries) != 3 || tx.queries[2] != ticketBulkResolveAccessABIQuery ||
		options.IsoLevel != pgx.RepeatableRead || options.AccessMode != pgx.ReadOnly ||
		len(tx.arguments[2]) != 1 {
		t.Fatalf("ticket access transaction = committed:%t options:%+v queries:%#v args:%#v", tx.committed, options, tx.queries, tx.arguments)
	}
	var request struct {
		SchemaVersion  int                         `json:"schemaVersion"`
		Actor          ticketOperationsActorWireV1 `json:"actor"`
		TenantID       string                      `json:"tenantId"`
		Kind           string                      `json:"kind"`
		Capability     string                      `json:"capability"`
		MutationAction string                      `json:"mutationAction"`
	}
	if err := json.Unmarshal(tx.arguments[2][0].([]byte), &request); err != nil ||
		request.SchemaVersion != ticketOperationsWireVersion || request.Actor.UserID != actorID.String() ||
		request.Actor.SessionID != actor.SessionID.String() || request.TenantID != tenantID.String() ||
		request.Kind != kernel.AggregateAlert.String() ||
		request.Capability != string(application.TicketBulkCapabilityRequest) ||
		request.MutationAction != kernel.ActionClaim.String() {
		t.Fatalf("ticket access wire = %#v, error = %v", request, err)
	}
}
