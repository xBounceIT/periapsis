package postgres

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.opentelemetry.io/otel/trace"

	"github.com/periapsis-im/periapsis/services/api/internal/alert"
	"github.com/periapsis-im/periapsis/services/api/internal/authorization"
	"github.com/periapsis-im/periapsis/services/api/internal/postgres/dbsql"
	"github.com/periapsis-im/periapsis/services/api/internal/serviceaccount"
)

type alertMutationQueriesStub struct {
	alertMutationQueries
	setCalls      int
	humanCalls    int
	machineCalls  int
	humanRow      *dbsql.CreateTenantAlertAsHumanRow
	machineRow    *dbsql.CreateTenantAlertAsServiceAccountRow
	humanArgs     dbsql.CreateTenantAlertAsHumanParams
	machineArgs   dbsql.CreateTenantAlertAsServiceAccountParams
	machineDigest []byte
}

func (s *alertMutationQueriesStub) SetTenantContext(
	_ context.Context,
	params dbsql.SetTenantContextParams,
) (*dbsql.SetTenantContextRow, error) {
	s.setCalls++
	tenantID := uuid.UUID(params.TenantID.Bytes)
	userID := uuid.UUID(params.UserID.Bytes)
	return &dbsql.SetTenantContextRow{TenantID: tenantID.String(), UserID: userID.String()}, nil
}

func (s *alertMutationQueriesStub) CreateTenantAlertAsHuman(
	_ context.Context,
	params dbsql.CreateTenantAlertAsHumanParams,
) (*dbsql.CreateTenantAlertAsHumanRow, error) {
	s.humanCalls++
	s.humanArgs = params
	return s.humanRow, nil
}

func (s *alertMutationQueriesStub) CreateTenantAlertAsServiceAccount(
	_ context.Context,
	params dbsql.CreateTenantAlertAsServiceAccountParams,
) (*dbsql.CreateTenantAlertAsServiceAccountRow, error) {
	s.machineCalls++
	s.machineArgs = params
	s.machineDigest = append([]byte(nil), params.SecretDigest...)
	return s.machineRow, nil
}

func TestAlertBearerCreateCallsOnlyBoundedDefinerWithoutHumanGUCs(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	serviceAccountID := uuid.Must(uuid.NewV7())
	alertID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	description := "Endpoint telemetry"
	payload := canonicalAdapterAlertPayload("Suspicious process", alert.SeverityHigh)
	payload.Description = &description
	credential := serviceaccount.PresentedCredential{KeyVersion: 9}
	copy(credential.Locator[:], []byte("0123456789abcdef"))
	for index := range credential.Digest {
		credential.Digest[index] = byte(index + 1)
	}
	machineRow := adapterMachineAlertRow(alertID, serviceAccountID, payload, now)
	machineRow.HasDescription, machineRow.Description = true, description
	queries := &alertMutationQueriesStub{machineRow: machineRow}
	tx := &recordingTransaction{}
	var options pgx.TxOptions
	repository := &AlertRepository{
		begin: func(_ context.Context, value pgx.TxOptions) (databaseTransaction, error) {
			options = value
			return tx, nil
		},
		queryFactory: func(databaseTransaction) alertMutationQueries { return queries },
	}
	audit := alertAdapterTestAudit()
	traceContext, wantTraceparent, wantTracestate := alertAdapterTraceContext(t)
	result, err := repository.CreateAsServiceAccount(traceContext, alert.CreateAsServiceAccountParams{
		Credential: credential, TenantID: tenantID, Payload: payload, Audit: audit,
	})
	if err != nil {
		t.Fatalf("CreateAsServiceAccount() error = %v", err)
	}
	if options.IsoLevel != pgx.ReadCommitted || queries.setCalls != 0 || queries.humanCalls != 0 ||
		queries.machineCalls != 1 || !tx.committed || result.Alert.ID != alertID ||
		queries.machineArgs.TenantID != toDatabaseUUID(tenantID) ||
		!equalBytes(queries.machineArgs.Locator, credential.Locator[:]) ||
		!equalBytes(queries.machineDigest, credential.Digest[:]) ||
		!allZeroBytes(queries.machineArgs.SecretDigest) ||
		queries.machineArgs.ClientAddress != audit.RemoteAddress ||
		queries.machineArgs.Traceparent == nil || *queries.machineArgs.Traceparent != wantTraceparent ||
		queries.machineArgs.Tracestate == nil || *queries.machineArgs.Tracestate != wantTracestate {
		t.Fatalf("options=%+v calls=(set:%d human:%d machine:%d) committed=%t result=%+v args=%+v", options, queries.setCalls, queries.humanCalls, queries.machineCalls, tx.committed, result, queries.machineArgs)
	}
}

func TestAlertHumanCreateInstallsContextBeforeDefiner(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	membershipID := uuid.Must(uuid.NewV7())
	alertID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	payload := canonicalAdapterAlertPayload("Manual escalation", alert.SeverityCritical)
	queries := &alertMutationQueriesStub{humanRow: adapterHumanAlertRow(alertID, actor.UserID, membershipID, payload, now)}
	tx := &recordingTransaction{}
	repository := &AlertRepository{
		begin:        func(context.Context, pgx.TxOptions) (databaseTransaction, error) { return tx, nil },
		queryFactory: func(databaseTransaction) alertMutationQueries { return queries },
	}
	traceContext, wantTraceparent, wantTracestate := alertAdapterTraceContext(t)
	result, err := repository.CreateAsHuman(traceContext, alert.CreateAsHumanParams{
		Actor: actor, MembershipID: membershipID, TenantID: tenantID,
		Payload: payload, Audit: alertAdapterTestAudit(),
	})
	if err != nil {
		t.Fatalf("CreateAsHuman() error = %v", err)
	}
	if queries.setCalls != 1 || queries.humanCalls != 1 || queries.machineCalls != 0 ||
		!tx.committed || result.Alert.ID != alertID ||
		queries.humanArgs.Traceparent == nil || *queries.humanArgs.Traceparent != wantTraceparent ||
		queries.humanArgs.Tracestate == nil || *queries.humanArgs.Tracestate != wantTracestate {
		t.Fatalf("calls=(set:%d human:%d machine:%d) committed=%t result=%+v", queries.setCalls, queries.humanCalls, queries.machineCalls, tx.committed, result)
	}
}

func alertAdapterTraceContext(t *testing.T) (context.Context, string, string) {
	t.Helper()
	traceID, err := trace.TraceIDFromHex("11111111111111111111111111111111")
	if err != nil {
		t.Fatal(err)
	}
	spanID, err := trace.SpanIDFromHex("2222222222222222")
	if err != nil {
		t.Fatal(err)
	}
	state, err := trace.ParseTraceState("vendor=value")
	if err != nil {
		t.Fatal(err)
	}
	span := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: spanID, TraceFlags: trace.FlagsSampled,
		TraceState: state,
	})
	return trace.ContextWithSpanContext(context.Background(), span),
		"00-11111111111111111111111111111111-2222222222222222-01",
		"vendor=value"
}

func TestAlertHumanCreatePreservesPresentEmptyDescription(t *testing.T) {
	tenantID := uuid.Must(uuid.NewV7())
	actor := authorizationRepositoryTestActor(t, tenantID)
	membershipID := uuid.Must(uuid.NewV7())
	alertID := uuid.Must(uuid.NewV7())
	now := time.Now().UTC().Truncate(time.Microsecond)
	empty := ""
	payload := canonicalAdapterAlertPayload("Manual escalation", alert.SeverityHigh)
	payload.Description = &empty
	humanRow := adapterHumanAlertRow(alertID, actor.UserID, membershipID, payload, now)
	humanRow.HasDescription, humanRow.Description = true, empty
	queries := &alertMutationQueriesStub{humanRow: humanRow}
	tx := &recordingTransaction{}
	repository := &AlertRepository{
		begin:        func(context.Context, pgx.TxOptions) (databaseTransaction, error) { return tx, nil },
		queryFactory: func(databaseTransaction) alertMutationQueries { return queries },
	}

	result, err := repository.CreateAsHuman(context.Background(), alert.CreateAsHumanParams{
		Actor: actor, MembershipID: membershipID, TenantID: tenantID,
		Payload: payload, Audit: alertAdapterTestAudit(),
	})
	if err != nil {
		t.Fatalf("CreateAsHuman() error = %v", err)
	}
	if queries.humanArgs.Description == nil || *queries.humanArgs.Description != "" ||
		result.Alert.Description == nil || *result.Alert.Description != "" || !tx.committed {
		t.Fatalf("present-empty description lost: args=%#v result=%#v committed=%t", queries.humanArgs.Description, result.Alert.Description, tx.committed)
	}
}

func TestAlertMappingRejectsMixedCreatorAttribution(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err := mapCreatedAlert(uuid.Must(uuid.NewV7()), alertRecord{
		id: toDatabaseUUID(uuid.Must(uuid.NewV7())), title: "Invalid attribution",
		status: string(alert.StatusNew), severity: string(alert.SeverityLow),
		createdByUserID:           toDatabaseUUID(uuid.Must(uuid.NewV7())),
		createdByMembershipID:     toDatabaseUUID(uuid.Must(uuid.NewV7())),
		createdByServiceAccountID: toDatabaseUUID(uuid.Must(uuid.NewV7())),
		createdAt:                 databaseTime(now), updatedAt: databaseTime(now), version: 1,
	})
	if !errors.Is(err, alert.ErrUnavailable) {
		t.Fatalf("mapCreatedAlert() error = %v, want unavailable", err)
	}
}

func TestAlertFreshProjectionRequiresInitialVersionAndTimestamps(t *testing.T) {
	t.Parallel()

	createdAt := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	description := "Endpoint telemetry"
	payload := canonicalAdapterAlertPayload("Suspicious process", alert.SeverityHigh)
	payload.Description = &description
	base := alert.Alert{
		Status: alert.StatusNew, Version: 1, CreatedAt: createdAt, UpdatedAt: createdAt,
		Title: payload.Title, Description: payload.Description, Severity: payload.Severity,
		Priority: payload.Priority, Category: payload.Category, Source: payload.Source,
		SourceType: payload.SourceType, CustomerVisible: payload.CustomerVisible,
	}
	for _, test := range []struct {
		name   string
		mutate func(*alert.Alert)
	}{
		{name: "advanced version", mutate: func(value *alert.Alert) { value.Version = 2 }},
		{name: "advanced update timestamp", mutate: func(value *alert.Alert) { value.UpdatedAt = value.CreatedAt.Add(time.Microsecond) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := base
			test.mutate(&value)
			if alertProjectionMatchesPayload(value, payload) {
				t.Fatal("non-fresh Alert projection matched create payload")
			}
		})
	}
}

func TestAlertDatabaseErrorHidesCredentialAuthenticationDetails(t *testing.T) {
	authenticationErr := &pgconn.PgError{Code: "28000", Message: "specific private credential failure"}
	if !errors.Is(mapAlertDatabaseError(authenticationErr), alert.ErrUnauthenticated) {
		t.Fatalf("mapAlertDatabaseError() = %v", mapAlertDatabaseError(authenticationErr))
	}
}

func alertAdapterTestAudit() authorization.AuditContext {
	return authorization.AuditContext{
		RequestID: uuid.New(), CorrelationID: uuid.New(),
		RemoteAddress: netip.MustParseAddr("198.51.100.23"), UserAgent: "Alert adapter test",
	}
}

func canonicalAdapterAlertPayload(title string, severity alert.Severity) alert.CreatePayload {
	return alert.CreatePayload{
		Title: title, Severity: severity, Priority: "medium", Category: "general",
		Source: "manual", SourceType: "manual", Tags: []string{},
		CustomFields: map[string]any{}, RawPayload: map[string]any{},
	}
}

func adapterHumanAlertRow(
	alertID, userID, membershipID uuid.UUID,
	payload alert.CreatePayload,
	now time.Time,
) *dbsql.CreateTenantAlertAsHumanRow {
	workflowID := uuid.Must(uuid.NewV7())
	return &dbsql.CreateTenantAlertAsHumanRow{
		ID: toDatabaseUUID(alertID), Number: "ALT-2026-000001", WorkflowID: toDatabaseUUID(workflowID),
		WorkflowVersion: 1, StateKey: "new", CustomerVisible: payload.CustomerVisible,
		Title: payload.Title, Status: string(alert.StatusNew), Severity: string(payload.Severity),
		Priority: payload.Priority, Category: payload.Category, Source: payload.Source, SourceType: payload.SourceType,
		Tags: []string{}, CustomFields: []byte(`{}`), CustomerCustomFields: []byte(`{}`), RawPayload: []byte(`{}`),
		CreatedByUserID: toDatabaseUUID(userID), CreatedByMembershipID: toDatabaseUUID(membershipID),
		DetectedAt: databaseTime(now), ReceivedAt: databaseTime(now), CreatedAt: databaseTime(now),
		UpdatedAt: databaseTime(now), Version: 1,
	}
}

func adapterMachineAlertRow(
	alertID, serviceAccountID uuid.UUID,
	payload alert.CreatePayload,
	now time.Time,
) *dbsql.CreateTenantAlertAsServiceAccountRow {
	workflowID := uuid.Must(uuid.NewV7())
	return &dbsql.CreateTenantAlertAsServiceAccountRow{
		ID: toDatabaseUUID(alertID), Number: "ALT-2026-000001", WorkflowID: toDatabaseUUID(workflowID),
		WorkflowVersion: 1, StateKey: "new", CustomerVisible: payload.CustomerVisible,
		Title: payload.Title, Status: string(alert.StatusNew), Severity: string(payload.Severity),
		Priority: payload.Priority, Category: payload.Category, Source: payload.Source, SourceType: payload.SourceType,
		Tags: []string{}, CustomFields: []byte(`{}`), CustomerCustomFields: []byte(`{}`), RawPayload: []byte(`{}`),
		CreatedByServiceAccountID: toDatabaseUUID(serviceAccountID), DetectedAt: databaseTime(now),
		ReceivedAt: databaseTime(now), CreatedAt: databaseTime(now), UpdatedAt: databaseTime(now), Version: 1,
	}
}
