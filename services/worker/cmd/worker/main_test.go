package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/worker/internal/postgres"
	"github.com/periapsis-im/periapsis/services/worker/internal/slaaction"
	"github.com/periapsis-im/periapsis/services/worker/internal/slaengine"
	"github.com/periapsis-im/periapsis/services/worker/internal/slaevent"
	"github.com/periapsis-im/periapsis/services/worker/internal/telemetry"
	"github.com/periapsis-im/periapsis/services/worker/internal/ticketbulk"
	"github.com/periapsis-im/periapsis/services/worker/internal/ticketexport"
	"go.opentelemetry.io/otel/trace"
)

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		value string
		want  slog.Level
	}{
		{value: "", want: slog.LevelInfo},
		{value: "info", want: slog.LevelInfo},
		{value: "error", want: slog.LevelError},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			got, err := parseLogLevel(tt.value)
			if err != nil {
				t.Fatalf("parseLogLevel(%q): %v", tt.value, err)
			}
			if got != tt.want {
				t.Fatalf("parseLogLevel(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
	for _, value := range []string{"debug", "INFO", " info "} {
		if _, err := parseLogLevel(value); err == nil {
			t.Fatalf("parseLogLevel(%q) unexpectedly succeeded", value)
		}
	}
}

func TestDatabasePoolConfigPinsUTCRuntimeParameters(t *testing.T) {
	want := map[string]string{
		"application_name":                    "periapsis-worker",
		"timezone":                            "UTC",
		"statement_timeout":                   "2500",
		"lock_timeout":                        "2500",
		"idle_in_transaction_session_timeout": "5000",
	}
	tests := []struct {
		name        string
		databaseURL string
	}{
		{
			name: "URL DSN",
			databaseURL: "postgresql://worker@localhost:5432/periapsis?sslmode=disable" +
				"&application_name=untrusted&Application_Name=also-untrusted" +
				"&timezone=Asia%2FTokyo&TimeZone=Europe%2FRome" +
				"&statement_timeout=1&Statement_Timeout=2" +
				"&lock_timeout=1&Lock_Timeout=2" +
				"&idle_in_transaction_session_timeout=3&Idle_In_Transaction_Session_Timeout=4",
		},
		{
			name: "keyword DSN",
			databaseURL: "host=localhost user=worker dbname=periapsis sslmode=disable " +
				"application_name=untrusted Application_Name=also-untrusted " +
				"timezone=Asia/Tokyo TimeZone=Europe/Rome " +
				"statement_timeout=1 Statement_Timeout=2 " +
				"lock_timeout=1 Lock_Timeout=2 " +
				"idle_in_transaction_session_timeout=3 Idle_In_Transaction_Session_Timeout=4",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, err := databasePoolConfig(test.databaseURL, 2500*time.Millisecond, nil)
			if err != nil {
				t.Fatalf("databasePoolConfig() error = %v", err)
			}
			assertPinnedRuntimeParameters(t, config.ConnConfig.RuntimeParams, want)
		})
	}
}

func assertPinnedRuntimeParameters(t *testing.T, runtimeParams, want map[string]string) {
	t.Helper()
	for name, value := range want {
		matchingNames := 0
		for actualName, actualValue := range runtimeParams {
			if !strings.EqualFold(actualName, name) {
				continue
			}
			matchingNames++
			if actualName != name || actualValue != value {
				t.Fatalf(
					"runtime parameter %q = %q, want canonical %q = %q",
					actualName, actualValue, name, value,
				)
			}
		}
		if matchingNames != 1 {
			t.Fatalf("case-insensitive runtime parameter count for %q = %d, want 1", name, matchingNames)
		}
	}
}

func TestMaintainAuthenticationStateRunsImmediatelyAndStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cleaner := &stubAuthStatePruner{called: make(chan struct{}, 1)}
	ready := &workerReadiness{}
	done := make(chan struct{})
	go func() {
		maintainAuthenticationState(
			ctx,
			cleaner,
			time.Hour,
			time.Second,
			250,
			ready,
			slog.New(slog.NewTextHandler(io.Discard, nil)),
			&telemetry.Metrics{},
			nil,
		)
		close(done)
	}()

	select {
	case <-cleaner.called:
	case <-time.After(time.Second):
		t.Fatal("authentication cleanup did not run immediately")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("authentication cleanup did not stop after cancellation")
	}

	cleaner.mu.Lock()
	defer cleaner.mu.Unlock()
	if cleaner.calls != 1 || cleaner.batch != 250 {
		t.Fatalf("cleanup calls/batch = %d/%d", cleaner.calls, cleaner.batch)
	}
	if !ready.cleanup.Load() {
		t.Fatal("successful cleanup did not satisfy cleanup readiness")
	}
}

func TestMaintainAuthenticationStateFailureClearsReadiness(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cleaner := &stubAuthStatePruner{called: make(chan struct{}, 1), err: context.DeadlineExceeded}
	ready := &workerReadiness{}
	ready.cleanup.Store(true)
	done := make(chan struct{})
	go func() {
		maintainAuthenticationState(
			ctx,
			cleaner,
			time.Hour,
			time.Second,
			250,
			ready,
			slog.New(slog.NewTextHandler(io.Discard, nil)),
			&telemetry.Metrics{},
			nil,
		)
		close(done)
	}()

	select {
	case <-cleaner.called:
	case <-time.After(time.Second):
		t.Fatal("authentication cleanup failure was not observed")
	}
	assertEventually(t, func() bool { return !ready.cleanup.Load() })
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed authentication cleanup did not stop")
	}
}

func TestWorkerReadinessRequiresEveryBackgroundLoop(t *testing.T) {
	ready := &workerReadiness{}
	if ready.Ready() {
		t.Fatal("new worker readiness failed open")
	}
	ready.audit.Store(true)
	ready.database.Store(true)
	if ready.Ready() {
		t.Fatal("database-only readiness passed")
	}
	ready.cleanup.Store(true)
	if ready.Ready() {
		t.Fatal("database and cleanup passed without a healthy LDAP sync loop")
	}
	ready.sync.Store(true)
	if ready.Ready() {
		t.Fatal("database, cleanup, and LDAP sync passed without a healthy SLA loop")
	}
	ready.sla.Store(true)
	if ready.Ready() {
		t.Fatal("database, cleanup, LDAP sync, and SLA passed without a healthy SLA action loop")
	}
	ready.slaAction.Store(true)
	if ready.Ready() {
		t.Fatal("SLA evaluation and action loops passed without healthy event ingress")
	}
	ready.slaEvent.Store(true)
	if ready.Ready() {
		t.Fatal("SLA loops passed without a healthy ticket runtime")
	}
	ready.ticket.Store(true)
	if ready.Ready() {
		t.Fatal("ticket runtime passed without a healthy custom-field import runtime")
	}
	ready.customFieldImport.Store(true)
	if ready.Ready() {
		t.Fatal("custom-field import passed without a healthy OIDC maintenance runtime")
	}
	ready.oidcMaintenance.Store(true)
	if ready.Ready() {
		t.Fatal("OIDC maintenance passed without a healthy DFIR scan loop")
	}
	ready.dfirScan.Store(true)
	if ready.Ready() {
		t.Fatal("DFIR scan passed without a healthy DFIR orphan cleanup loop")
	}
	ready.dfirCleanup.Store(true)
	if !ready.Ready() {
		t.Fatal("healthy database, cleanup, LDAP sync, SLA, ticket, custom-field import, OIDC, and DFIR loops were not ready")
	}
	ready.database.Store(false)
	if ready.Ready() {
		t.Fatal("database failure left worker ready")
	}
}

func TestWorkerHandlerServesBoundedHealthAndMetrics(t *testing.T) {
	ready := &workerReadiness{}
	metrics := &telemetry.Metrics{}
	handler := newWorkerHandler("test-release", ready, metrics)

	live := httptest.NewRecorder()
	handler.ServeHTTP(live, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if live.Code != http.StatusOK || !strings.Contains(live.Body.String(), `"version":"test-release"`) {
		t.Fatalf("live response = %d %q", live.Code, live.Body.String())
	}

	unready := httptest.NewRecorder()
	handler.ServeHTTP(unready, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if unready.Code != http.StatusServiceUnavailable || !strings.Contains(unready.Body.String(), `"status":503`) {
		t.Fatalf("unready response = %d %q", unready.Code, unready.Body.String())
	}

	ready.database.Store(true)
	ready.audit.Store(true)
	ready.cleanup.Store(true)
	ready.sync.Store(true)
	ready.sla.Store(true)
	ready.slaAction.Store(true)
	ready.slaEvent.Store(true)
	ready.ticket.Store(true)
	ready.customFieldImport.Store(true)
	ready.oidcMaintenance.Store(true)
	ready.dfirScan.Store(true)
	ready.dfirCleanup.Store(true)
	readyResponse := httptest.NewRecorder()
	handler.ServeHTTP(readyResponse, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if readyResponse.Code != http.StatusOK || !strings.Contains(readyResponse.Body.String(), `"status":"ready"`) {
		t.Fatalf("ready response = %d %q", readyResponse.Code, readyResponse.Body.String())
	}

	metrics.SetDatabaseReady(true)
	metricResponse := httptest.NewRecorder()
	handler.ServeHTTP(metricResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if metricResponse.Code != http.StatusOK ||
		metricResponse.Header().Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" ||
		metricResponse.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(metricResponse.Body.String(), "periapsis_worker_database_ready 1") {
		t.Fatalf("metrics response = %d %#v %q", metricResponse.Code, metricResponse.Header(), metricResponse.Body.String())
	}

	methodNotAllowed := httptest.NewRecorder()
	handler.ServeHTTP(methodNotAllowed, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if methodNotAllowed.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /metrics status = %d, want 405", methodNotAllowed.Code)
	}
}

func TestTicketRuntimeRunsEveryQueueFamilyAndStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tenant := mainTestTicketEntity(t, 1)
	service := mainTestTicketEntity(t, 2)
	worker := mainTestTicketEntity(t, 3)
	repository := &ticketRuntimeRepositoryStub{
		queues: []postgres.TicketWorkQueue{
			{TenantID: tenant, Kind: kernel.AggregateAlert},
			{TenantID: tenant, Kind: kernel.AggregateCase, Audience: kernel.TicketExportAudienceOperator, Export: true},
		},
		metrics: postgres.TicketExportReconciliationMetrics{
			PendingEligible: 2, Reclaimable: 1, DeadLettered: 3, OldestPendingMicros: 7_500_000,
		},
	}
	bulk := &ticketBulkRunnerStub{called: make(chan struct{}, 1)}
	export := &ticketExportRunnerStub{called: make(chan struct{}, 1)}
	reconcile := &ticketReconcileRunnerStub{called: make(chan struct{}, 1)}
	ready := &workerReadiness{}
	metrics := &telemetry.Metrics{}
	done := make(chan struct{})
	go func() {
		runTicketRuntime(
			ctx, repository, bulk, export, reconcile, ticketSpoolSweeperStub{}, service, worker,
			time.Hour, time.Second, ready, slog.New(slog.NewTextHandler(io.Discard, nil)), metrics, nil,
		)
		close(done)
	}()
	select {
	case <-bulk.called:
	case <-time.After(time.Second):
		t.Fatal("ticket bulk queue was not run")
	}
	select {
	case <-export.called:
	case <-time.After(time.Second):
		t.Fatal("ticket export queue was not run")
	}
	select {
	case <-reconcile.called:
	case <-time.After(time.Second):
		t.Fatal("ticket export reconciliation queue was not run")
	}
	assertEventually(t, ready.ticket.Load)
	if rendered := metrics.RenderPrometheus(); !strings.Contains(rendered, "periapsis_worker_ticket_runtime_ready 1") ||
		!strings.Contains(rendered, `periapsis_ticket_bulk_worker_runs_total{outcome="empty"} 1`) ||
		!strings.Contains(rendered, `periapsis_ticket_export_worker_runs_total{outcome="empty"} 1`) ||
		!strings.Contains(rendered, `periapsis_ticket_export_reconcile_worker_runs_total{outcome="success"} 1`) ||
		!strings.Contains(rendered, "periapsis_ticket_export_reconcile_queue_pending_eligible 2") ||
		!strings.Contains(rendered, "periapsis_ticket_export_reconcile_queue_reclaimable 1") ||
		!strings.Contains(rendered, "periapsis_ticket_export_reconcile_queue_dead_lettered 3") ||
		!strings.Contains(rendered, "periapsis_ticket_export_reconcile_queue_oldest_pending_seconds 7.500000") {
		t.Fatalf("ticket runtime metrics = %q", rendered)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ticket runtime did not stop after cancellation")
	}
	if ready.ticket.Load() {
		t.Fatal("ticket runtime remained ready after shutdown")
	}
	if strings.Contains(metrics.RenderPrometheus(), "periapsis_ticket_export_reconcile_queue_") {
		t.Fatal("ticket runtime shutdown left a stale reconciliation queue observation")
	}
}

func TestTicketRuntimeFailsClosedWhenReconciliationQueueObservationIsUnavailable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := &workerReadiness{}
	metrics := &telemetry.Metrics{}
	if !metrics.SetTicketExportReconciliationQueueObservation(9, 1, 0, 5_000_000) {
		t.Fatal("failed to seed a prior reconciliation queue observation")
	}
	var logs synchronizedBuffer
	done := make(chan struct{})
	go func() {
		runTicketRuntime(
			ctx,
			&ticketRuntimeRepositoryStub{metricsErr: errors.New("tenant artifact credential detail")},
			&ticketBulkRunnerStub{},
			&ticketExportRunnerStub{},
			&ticketReconcileRunnerStub{},
			ticketSpoolSweeperStub{},
			mainTestTicketEntity(t, 31),
			mainTestTicketEntity(t, 32),
			time.Hour,
			time.Second,
			ready,
			slog.New(slog.NewTextHandler(&logs, nil)),
			metrics,
			nil,
		)
		close(done)
	}()
	assertEventually(t, func() bool {
		return strings.Contains(logs.String(), "ticket export reconciliation queue observation failed")
	})
	if ready.ticket.Load() {
		t.Fatal("unavailable reconciliation queue observation left ticket runtime ready")
	}
	if strings.Contains(metrics.RenderPrometheus(), "periapsis_ticket_export_reconcile_queue_") {
		t.Fatal("unavailable reconciliation queue observation rendered stale gauges")
	}
	if text := logs.String(); strings.Contains(text, "tenant") || strings.Contains(text, "artifact") ||
		strings.Contains(text, "credential") || !strings.Contains(text, "failure=internal") {
		t.Fatalf("reconciliation observation failure log was not bounded: %q", text)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ticket runtime did not stop after cancellation")
	}
}

func TestTicketQueueFamiliesDoNotStarveBulkBehindBlockedExport(t *testing.T) {
	tenant := mainTestTicketEntity(t, 1)
	bulk := &ticketBulkRunnerStub{called: make(chan struct{}, 1)}
	export := &blockingTicketExportRunnerStub{
		entered: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	done := make(chan bool, 1)
	go func() {
		done <- runTicketQueueFamilies(
			context.Background(),
			[]postgres.TicketWorkQueue{
				{TenantID: tenant, Kind: kernel.AggregateCase, Audience: kernel.TicketExportAudienceOperator, Export: true},
				{TenantID: tenant, Kind: kernel.AggregateAlert},
			},
			bulk,
			export,
			&ticketReconcileRunnerStub{},
			slog.New(slog.NewTextHandler(io.Discard, nil)),
			&telemetry.Metrics{},
			nil,
		)
	}()

	select {
	case <-export.entered:
	case <-time.After(time.Second):
		t.Fatal("ticket export queue was not started")
	}
	select {
	case <-bulk.called:
	case <-time.After(time.Second):
		t.Fatal("ticket bulk queue was starved behind blocked export work")
	}
	close(export.release)
	select {
	case healthy := <-done:
		if !healthy {
			t.Fatal("parallel ticket queue families reported an unexpected failure")
		}
	case <-time.After(time.Second):
		t.Fatal("parallel ticket queue families did not finish")
	}
}

func TestTicketRuntimeRejectsTypedNilDependencyBeforeUse(t *testing.T) {
	var repository *ticketRuntimeRepositoryStub
	ready := &workerReadiness{}
	ready.ticket.Store(true)
	runTicketRuntime(
		context.Background(), repository, &ticketBulkRunnerStub{}, &ticketExportRunnerStub{},
		&ticketReconcileRunnerStub{}, ticketSpoolSweeperStub{},
		mainTestTicketEntity(t, 1), mainTestTicketEntity(t, 2),
		time.Second, time.Second, ready, slog.New(slog.NewTextHandler(io.Discard, nil)),
		&telemetry.Metrics{}, nil,
	)
	if ready.ticket.Load() {
		t.Fatal("typed-nil ticket runtime dependency failed open")
	}
}

func TestTicketRuntimeStorageFailureClearsReadinessBeforeQueueUseAndRedactsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	checked := make(chan struct{}, 1)
	bulkCalled := make(chan struct{}, 1)
	tenant := mainTestTicketEntity(t, 1)
	service := mainTestTicketEntity(t, 2)
	worker := mainTestTicketEntity(t, 3)
	ready := &workerReadiness{}
	ready.ticket.Store(true)
	var logs synchronizedBuffer
	done := make(chan struct{})
	go func() {
		runTicketRuntime(
			ctx,
			&ticketRuntimeRepositoryStub{queues: []postgres.TicketWorkQueue{{
				TenantID: tenant, Kind: kernel.AggregateAlert,
			}}},
			&ticketBulkRunnerStub{called: bulkCalled},
			&ticketExportRunnerStub{},
			&ticketReconcileRunnerStub{},
			ticketSpoolSweeperStub{checkErr: errors.New("customer bucket credential detail"), checked: checked},
			service, worker,
			time.Hour, time.Second, ready, slog.New(slog.NewTextHandler(&logs, nil)),
			&telemetry.Metrics{}, nil,
		)
		close(done)
	}()
	select {
	case <-checked:
	case <-time.After(time.Second):
		t.Fatal("ticket storage readiness was not checked")
	}
	assertEventually(t, func() bool { return !ready.ticket.Load() })
	select {
	case <-bulkCalled:
		t.Fatal("ticket queue ran after storage readiness failed")
	default:
	}
	assertEventually(t, func() bool {
		return strings.Contains(logs.String(), "failure=internal")
	})
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ticket runtime did not stop after storage readiness failure")
	}
	if text := logs.String(); strings.Contains(text, "customer") || strings.Contains(text, "credential") ||
		!strings.Contains(text, "failure=internal") {
		t.Fatalf("ticket storage readiness log was not redacted: %q", text)
	}
}

func TestRunSLAActionWorkerRunsExplicitTenantQueuesAndPublishesBoundedMetrics(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tenantID := mainTestUUIDv7(t, 70)
	runner := &stubSLAActionRunner{
		called:  make(chan slaaction.Queue, 1),
		summary: slaaction.Summary{Claimed: 2, Applied: 1, Replayed: 1},
	}
	runtime := &stubSLAActionRuntime{
		queues: []slaaction.Queue{{TenantID: tenantID}},
		metrics: postgres.SLAActionQueueMetrics{
			ObservedAt:     time.Date(2026, time.August, 30, 9, 0, 0, 0, time.UTC),
			PendingActions: 4, OldestPendingMicros: 8_500_000,
		},
	}
	ready := &workerReadiness{}
	metrics := &telemetry.Metrics{}
	done := make(chan struct{})
	go func() {
		runSLAActionWorker(
			ctx, runner, runtime, time.Hour, time.Minute, time.Second, 10,
			ready, slog.New(slog.NewTextHandler(io.Discard, nil)), metrics, nil,
			func() time.Time { return runtime.metrics.ObservedAt },
		)
		close(done)
	}()

	select {
	case queue := <-runner.called:
		if queue.TenantID != tenantID {
			t.Fatalf("queue tenant = %s", queue.TenantID)
		}
	case <-time.After(time.Second):
		t.Fatal("SLA action worker did not run immediately")
	}
	assertEventually(t, func() bool {
		output := metrics.RenderPrometheus()
		return ready.slaAction.Load() &&
			strings.Contains(output, `periapsis_worker_sla_action_ready 1`) &&
			strings.Contains(output, `periapsis_sla_action_worker_runs_total{outcome="success"} 1`) &&
			strings.Contains(output, `periapsis_sla_action_worker_actions_total{outcome="claimed"} 2`) &&
			strings.Contains(output, `periapsis_sla_action_worker_actions_total{outcome="applied"} 1`) &&
			strings.Contains(output, `periapsis_sla_action_worker_actions_total{outcome="replayed"} 1`) &&
			strings.Contains(output, `periapsis_sla_action_queue_pending_actions 4`) &&
			strings.Contains(output, `periapsis_sla_action_queue_oldest_pending_seconds 8.500000`)
	})

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SLA action worker did not stop")
	}
	if ready.slaAction.Load() ||
		strings.Contains(metrics.RenderPrometheus(), "periapsis_sla_action_queue_") {
		t.Fatal("stopped SLA action worker retained readiness or stale queue metrics")
	}
}

func TestRunSLAActionWorkerFailsClosedAndRedactsRepositoryErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runtime := &stubSLAActionRuntime{readyErr: errors.New("tenant@example.invalid credential")}
	runner := &stubSLAActionRunner{called: make(chan slaaction.Queue, 1)}
	ready := &workerReadiness{}
	ready.slaAction.Store(true)
	metrics := &telemetry.Metrics{}
	metrics.SetSLAActionReady(true)
	var logs synchronizedBuffer
	done := make(chan struct{})
	go func() {
		runSLAActionWorker(
			ctx, runner, runtime, time.Hour, time.Minute, time.Second, 10,
			ready, slog.New(slog.NewTextHandler(&logs, nil)), metrics, nil, time.Now,
		)
		close(done)
	}()

	assertEventually(t, func() bool {
		output := metrics.RenderPrometheus()
		return !ready.slaAction.Load() &&
			strings.Contains(output, `periapsis_worker_sla_action_ready 0`) &&
			strings.Contains(output, `periapsis_sla_action_worker_runs_total{outcome="failure"} 1`)
	})
	select {
	case <-runner.called:
		t.Fatal("SLA action runner was called after readiness failed")
	default:
	}
	if text := logs.String(); strings.Contains(text, "tenant@example.invalid") ||
		strings.Contains(text, "credential") || !strings.Contains(text, "failure=internal") {
		t.Fatalf("SLA action failure log was not bounded: %q", text)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed SLA action worker did not stop")
	}
}

func TestRunSLAEventIngressRunsImmediatelyPublishesBoundedMetricsAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runner := &stubSLAEventRunner{
		result: slaevent.RunSummary{
			Claimed: 5, Applied: 1, Replayed: 1, RetryScheduled: 1, DeadLettered: 1, FenceLost: 1,
		},
		called: make(chan struct{}, 1),
	}
	runtime := &stubSLAEventRuntime{metrics: slaevent.QueueMetrics{
		ObservedAt:    time.Date(2026, time.August, 27, 8, 0, 0, 0, time.UTC),
		PendingEvents: 4, ReclaimableEvents: 2, DeadLetteredEvents: 1,
		OldestPendingMicros: 12_250_000,
	}}
	ready := &workerReadiness{}
	metrics := &telemetry.Metrics{}
	done := make(chan struct{})
	go func() {
		runSLAEventIngress(
			ctx, runner, runtime, time.Hour, time.Minute, time.Second, ready,
			slog.New(slog.NewTextHandler(io.Discard, nil)), metrics, nil,
		)
		close(done)
	}()

	select {
	case <-runner.called:
	case <-time.After(time.Second):
		t.Fatal("SLA event ingress did not run immediately")
	}
	assertEventually(t, func() bool {
		output := metrics.RenderPrometheus()
		return ready.slaEvent.Load() &&
			strings.Contains(output, `periapsis_worker_sla_event_ingress_ready 1`) &&
			strings.Contains(output, `periapsis_sla_event_ingress_worker_runs_total{outcome="success"} 1`) &&
			strings.Contains(output, `periapsis_sla_event_ingress_worker_events_total{outcome="claimed"} 5`) &&
			strings.Contains(output, `periapsis_sla_event_ingress_worker_events_total{outcome="applied"} 1`) &&
			strings.Contains(output, `periapsis_sla_event_ingress_worker_events_total{outcome="replayed"} 1`) &&
			strings.Contains(output, `periapsis_sla_event_ingress_worker_events_total{outcome="retry_scheduled"} 1`) &&
			strings.Contains(output, `periapsis_sla_event_ingress_worker_events_total{outcome="dead_lettered"} 1`) &&
			strings.Contains(output, `periapsis_sla_event_ingress_worker_events_total{outcome="fence_lost"} 1`) &&
			strings.Contains(output, `periapsis_sla_event_ingress_queue_pending_events 4`) &&
			strings.Contains(output, `periapsis_sla_event_ingress_queue_reclaimable_events 2`) &&
			strings.Contains(output, `periapsis_sla_event_ingress_queue_dead_lettered_events 1`) &&
			strings.Contains(output, `periapsis_sla_event_ingress_queue_oldest_pending_seconds 12.250000`)
	})

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SLA event ingress did not stop after cancellation")
	}
	if ready.slaEvent.Load() ||
		strings.Contains(metrics.RenderPrometheus(), `periapsis_sla_event_ingress_queue_`) {
		t.Fatal("stopped SLA event ingress retained readiness or stale queue metrics")
	}
}

func TestRunSLAEventIngressReadinessFailureIsRedactedAndSkipsClaim(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runner := &stubSLAEventRunner{called: make(chan struct{}, 1)}
	runtime := &stubSLAEventRuntime{readyErr: errors.New("tenant@example.invalid credential")}
	ready := &workerReadiness{}
	ready.slaEvent.Store(true)
	metrics := &telemetry.Metrics{}
	metrics.SetSLAEventReady(true)
	metrics.SetSLAEventQueueObservation(1, 0, 0, 1)
	var logs synchronizedBuffer
	done := make(chan struct{})
	go func() {
		runSLAEventIngress(
			ctx, runner, runtime, time.Hour, time.Minute, time.Second, ready,
			slog.New(slog.NewTextHandler(&logs, nil)), metrics, nil,
		)
		close(done)
	}()

	assertEventually(t, func() bool {
		output := metrics.RenderPrometheus()
		return !ready.slaEvent.Load() &&
			strings.Contains(output, `periapsis_worker_sla_event_ingress_ready 0`) &&
			strings.Contains(output, `periapsis_sla_event_ingress_worker_runs_total{outcome="failure"} 1`) &&
			!strings.Contains(output, `periapsis_sla_event_ingress_queue_`)
	})
	select {
	case <-runner.called:
		t.Fatal("SLA event ingress claimed after readiness failed")
	default:
	}
	if text := logs.String(); strings.Contains(text, "tenant@example.invalid") ||
		strings.Contains(text, "credential") || !strings.Contains(text, "failure=internal") {
		t.Fatalf("SLA event ingress failure log was not bounded: %q", text)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed SLA event ingress did not stop")
	}
}

func TestRunSLAEngineRunsImmediatelyPublishesBoundedMetricsAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runner := &stubSLARunner{
		results: make(chan stubSLARunResult, 1),
		called:  make(chan struct{}, 1),
	}
	runner.results <- stubSLARunResult{summary: slaengine.RunSummary{
		Claimed: 3, Completed: 1, Retryable: 1, DeadLettered: 1,
	}}
	queueReader := &stubSLAQueueReader{metrics: postgres.SLAQueueMetrics{
		ObservedAt:  time.Date(2026, time.August, 26, 8, 0, 0, 0, time.UTC),
		PendingJobs: 7, OldestPendingMicros: 125_500_000,
	}}
	ready := &workerReadiness{}
	metrics := &telemetry.Metrics{}
	done := make(chan struct{})
	go func() {
		runSLAEngine(
			ctx, runner, queueReader, time.Hour, time.Minute, time.Second, ready,
			slog.New(slog.NewTextHandler(io.Discard, nil)), metrics, nil,
		)
		close(done)
	}()

	select {
	case <-runner.called:
	case <-time.After(time.Second):
		t.Fatal("SLA engine did not run immediately")
	}
	assertEventually(t, func() bool {
		output := metrics.RenderPrometheus()
		return ready.sla.Load() &&
			strings.Contains(output, `periapsis_worker_sla_ready 1`) &&
			strings.Contains(output, `periapsis_sla_worker_runs_total{outcome="success"} 1`) &&
			strings.Contains(output, `periapsis_sla_worker_jobs_total{outcome="claimed"} 3`) &&
			strings.Contains(output, `periapsis_sla_worker_jobs_total{outcome="completed"} 1`) &&
			strings.Contains(output, `periapsis_sla_worker_jobs_total{outcome="retryable"} 1`) &&
			strings.Contains(output, `periapsis_sla_worker_jobs_total{outcome="dead_lettered"} 1`) &&
			strings.Contains(output, `periapsis_sla_queue_pending_jobs 7`) &&
			strings.Contains(output, `periapsis_sla_queue_oldest_pending_seconds 125.500000`)
	})

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SLA engine did not stop after cancellation")
	}
	if ready.sla.Load() || !strings.Contains(metrics.RenderPrometheus(), `periapsis_worker_sla_ready 0`) {
		t.Fatal("stopped SLA engine remained ready")
	}
}

func TestRunSLAEngineFailureClearsReadinessWithoutExposingError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runner := &stubSLARunner{
		results: make(chan stubSLARunResult, 1),
		called:  make(chan struct{}, 1),
	}
	runner.results <- stubSLARunResult{err: errors.New("tenant@example.invalid secret")}
	ready := &workerReadiness{}
	ready.sla.Store(true)
	metrics := &telemetry.Metrics{}
	metrics.SetSLAReady(true)
	metrics.SetSLAQueueObservation(1, 1)
	var logs synchronizedBuffer
	done := make(chan struct{})
	go func() {
		runSLAEngine(
			ctx, runner, &stubSLAQueueReader{}, time.Hour, time.Minute, time.Second, ready,
			slog.New(slog.NewTextHandler(&logs, nil)), metrics, nil,
		)
		close(done)
	}()

	select {
	case <-runner.called:
	case <-time.After(time.Second):
		t.Fatal("SLA engine failure was not observed")
	}
	assertEventually(t, func() bool {
		output := metrics.RenderPrometheus()
		return !ready.sla.Load() &&
			strings.Contains(output, `periapsis_worker_sla_ready 0`) &&
			strings.Contains(output, `periapsis_sla_worker_runs_total{outcome="failure"} 1`) &&
			!strings.Contains(output, `periapsis_sla_queue_`) &&
			!strings.Contains(output, "tenant@example.invalid") &&
			!strings.Contains(output, "secret")
	})
	if strings.Contains(logs.String(), "tenant@example.invalid") || strings.Contains(logs.String(), "secret") ||
		!strings.Contains(logs.String(), "failure=internal") {
		t.Fatalf("SLA failure log was not bounded: %q", logs.String())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed SLA engine did not stop")
	}
}

func TestRunSLAEngineFailsClosedWhenQueueObservationIsUnavailable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runner := &stubSLARunner{
		results: make(chan stubSLARunResult, 1),
		called:  make(chan struct{}, 1),
	}
	runner.results <- stubSLARunResult{summary: slaengine.RunSummary{Claimed: 1, Completed: 1}}
	queueReader := &stubSLAQueueReader{err: errors.New("customer@example.invalid secret")}
	ready := &workerReadiness{}
	metrics := &telemetry.Metrics{}
	metrics.SetSLAQueueObservation(99, 99)
	var logs synchronizedBuffer
	done := make(chan struct{})
	go func() {
		runSLAEngine(
			ctx, runner, queueReader, time.Hour, time.Minute, time.Second, ready,
			slog.New(slog.NewTextHandler(&logs, nil)), metrics, nil,
		)
		close(done)
	}()

	assertEventually(t, func() bool {
		output := metrics.RenderPrometheus()
		return !ready.sla.Load() &&
			strings.Contains(output, `periapsis_sla_worker_runs_total{outcome="failure"} 1`) &&
			strings.Contains(output, `periapsis_sla_worker_jobs_total{outcome="claimed"} 1`) &&
			!strings.Contains(output, `periapsis_sla_queue_`)
	})
	if strings.Contains(logs.String(), "customer@example.invalid") || strings.Contains(logs.String(), "secret") {
		t.Fatalf("queue observation failure leaked into logs: %q", logs.String())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SLA engine did not stop after queue observation failure")
	}
}

func TestRunSLAEnginePropagatesTheStartedLocalTraceToWorkAndObservation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	runnerTrace := make(chan trace.SpanContext, 1)
	queueTrace := make(chan trace.SpanContext, 1)
	finishErrors := make(chan error, 1)
	runner := &stubSLARunner{
		results:   make(chan stubSLARunResult, 1),
		called:    make(chan struct{}, 1),
		traceSeen: runnerTrace,
	}
	runner.results <- stubSLARunResult{}
	queueReader := &stubSLAQueueReader{traceSeen: queueTrace, metrics: postgres.SLAQueueMetrics{
		ObservedAt: time.Date(2026, time.August, 26, 8, 0, 0, 0, time.UTC),
	}}
	tracer := &stubSLAOperationTracer{finishErrors: finishErrors}
	done := make(chan struct{})
	go func() {
		runSLAEngine(
			ctx, runner, queueReader, time.Hour, time.Minute, time.Second,
			&workerReadiness{}, slog.New(slog.NewTextHandler(io.Discard, nil)),
			&telemetry.Metrics{}, tracer,
		)
		close(done)
	}()

	for name, seen := range map[string]<-chan trace.SpanContext{
		"runner": runnerTrace,
		"queue":  queueTrace,
	} {
		select {
		case spanContext := <-seen:
			if !spanContext.IsValid() || spanContext.IsRemote() || !spanContext.IsSampled() ||
				spanContext.TraceID() != tracer.spanContext.TraceID() {
				t.Fatalf("%s trace context = %#v", name, spanContext)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s did not receive the started trace context", name)
		}
	}
	select {
	case finishErr := <-finishErrors:
		if finishErr != nil {
			t.Fatalf("successful SLA trace finished with %v", finishErr)
		}
	case <-time.After(time.Second):
		t.Fatal("SLA operation trace was not finished")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("traced SLA engine did not stop")
	}
}

func TestWaitForBackgroundIsBoundedAndObservesCompletion(t *testing.T) {
	var wait sync.WaitGroup
	wait.Add(1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitForBackground(ctx, &wait) {
		t.Fatal("waitForBackground() ignored cancellation")
	}
	wait.Done()
	readyContext, readyCancel := context.WithTimeout(context.Background(), time.Second)
	defer readyCancel()
	if !waitForBackground(readyContext, &wait) {
		t.Fatal("waitForBackground() missed completed work")
	}
}

type stubAuthStatePruner struct {
	mu     sync.Mutex
	calls  int
	batch  int
	called chan struct{}
	err    error
}

type stubSLARunResult struct {
	summary slaengine.RunSummary
	err     error
}

type stubSLARunner struct {
	results   chan stubSLARunResult
	called    chan struct{}
	traceSeen chan trace.SpanContext
}

type stubSLAQueueReader struct {
	metrics   postgres.SLAQueueMetrics
	err       error
	traceSeen chan trace.SpanContext
}

type stubSLAActionRunner struct {
	called  chan slaaction.Queue
	summary slaaction.Summary
	err     error
}

type stubSLAActionRuntime struct {
	readyErr   error
	queues     []slaaction.Queue
	listErr    error
	metrics    postgres.SLAActionQueueMetrics
	metricsErr error
}

type stubSLAEventRunner struct {
	result slaevent.RunSummary
	err    error
	called chan struct{}
}

type stubSLAEventRuntime struct {
	readyErr  error
	metrics   slaevent.QueueMetrics
	metricErr error
}

type stubSLAOperationTracer struct {
	spanContext  trace.SpanContext
	finishErrors chan error
}

type synchronizedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (buffer *synchronizedBuffer) Write(value []byte) (int, error) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.Write(value)
}

func (buffer *synchronizedBuffer) String() string {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	return buffer.buffer.String()
}

func (reader *stubSLAQueueReader) ReadQueueMetrics(ctx context.Context) (postgres.SLAQueueMetrics, error) {
	if reader.traceSeen != nil {
		reader.traceSeen <- trace.SpanContextFromContext(ctx)
	}
	return reader.metrics, reader.err
}

func (runner *stubSLAActionRunner) RunOnce(
	_ context.Context,
	queue slaaction.Queue,
) (slaaction.Summary, error) {
	if runner.called != nil {
		select {
		case runner.called <- queue:
		default:
		}
	}
	return runner.summary, runner.err
}

func (runtime *stubSLAActionRuntime) Ready(context.Context) error {
	return runtime.readyErr
}

func (runtime *stubSLAActionRuntime) ListQueues(
	context.Context,
	time.Time,
	int,
) ([]slaaction.Queue, error) {
	return append([]slaaction.Queue(nil), runtime.queues...), runtime.listErr
}

func (runtime *stubSLAActionRuntime) ReadQueueMetrics(
	context.Context,
) (postgres.SLAActionQueueMetrics, error) {
	return runtime.metrics, runtime.metricsErr
}

func (runner *stubSLAEventRunner) RunOnce(context.Context) (slaevent.RunSummary, error) {
	if runner.called != nil {
		select {
		case runner.called <- struct{}{}:
		default:
		}
	}
	return runner.result, runner.err
}

func (runtime *stubSLAEventRuntime) Ready(context.Context) error { return runtime.readyErr }

func (runtime *stubSLAEventRuntime) ReadQueueMetrics(context.Context) (slaevent.QueueMetrics, error) {
	return runtime.metrics, runtime.metricErr
}

func (tracer *stubSLAOperationTracer) StartOperation(ctx context.Context, operation string) (context.Context, func(error)) {
	if operation != "sla.evaluate" {
		panic("unexpected operation")
	}
	traceID, _ := trace.TraceIDFromHex("11111111111111111111111111111111")
	spanID, _ := trace.SpanIDFromHex("2222222222222222")
	tracer.spanContext = trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: spanID, TraceFlags: trace.FlagsSampled,
	})
	return trace.ContextWithSpanContext(ctx, tracer.spanContext), func(err error) {
		tracer.finishErrors <- err
	}
}

func (runner *stubSLARunner) RunOnce(ctx context.Context) (slaengine.RunSummary, error) {
	select {
	case runner.called <- struct{}{}:
	default:
	}
	if runner.traceSeen != nil {
		runner.traceSeen <- trace.SpanContextFromContext(ctx)
	}
	select {
	case result := <-runner.results:
		return result.summary, result.err
	case <-ctx.Done():
		return slaengine.RunSummary{}, ctx.Err()
	}
}

func assertEventually(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !predicate() {
		if time.Now().After(deadline) {
			t.Fatal("condition was not satisfied before deadline")
		}
		time.Sleep(time.Millisecond)
	}
}

func (c *stubAuthStatePruner) Prune(
	_ context.Context,
	batch int,
) (postgres.AuthStateCleanupCounts, error) {
	c.mu.Lock()
	c.calls++
	c.batch = batch
	c.mu.Unlock()
	c.called <- struct{}{}
	return postgres.AuthStateCleanupCounts{}, c.err
}

type ticketRuntimeRepositoryStub struct {
	readyErr   error
	queues     []postgres.TicketWorkQueue
	metrics    postgres.TicketExportReconciliationMetrics
	metricsErr error
}

func (stub *ticketRuntimeRepositoryStub) Ready(context.Context) error { return stub.readyErr }

func (stub *ticketRuntimeRepositoryStub) ListQueues(
	_ context.Context,
	_ kernel.EntityID,
	_ kernel.EntityID,
	_ int,
) ([]postgres.TicketWorkQueue, error) {
	return append([]postgres.TicketWorkQueue(nil), stub.queues...), nil
}

func (stub *ticketRuntimeRepositoryStub) ReadReconciliationMetrics(
	context.Context,
	ticketexport.ReconcileIdentity,
) (postgres.TicketExportReconciliationMetrics, error) {
	return stub.metrics, stub.metricsErr
}

type ticketBulkRunnerStub struct{ called chan struct{} }

func (stub *ticketBulkRunnerStub) RunOnce(
	_ context.Context,
	_ ticketbulk.Queue,
) (ticketbulk.Result, error) {
	if stub.called != nil {
		select {
		case stub.called <- struct{}{}:
		default:
		}
	}
	return ticketbulk.Result{Outcome: ticketbulk.OutcomeIdle}, nil
}

type ticketExportRunnerStub struct{ called chan struct{} }

func (stub *ticketExportRunnerStub) RunOnce(
	_ context.Context,
	_ ticketexport.Queue,
) (ticketexport.Result, error) {
	if stub.called != nil {
		select {
		case stub.called <- struct{}{}:
		default:
		}
	}
	return ticketexport.Result{Outcome: ticketexport.OutcomeIdle}, nil
}

type ticketReconcileRunnerStub struct{ called chan struct{} }

func (stub *ticketReconcileRunnerStub) RunOnce(
	_ context.Context,
	_ ticketexport.Queue,
) (ticketexport.ReconcileSummary, error) {
	if stub.called != nil {
		select {
		case stub.called <- struct{}{}:
		default:
		}
	}
	return ticketexport.ReconcileSummary{}, nil
}

type blockingTicketExportRunnerStub struct {
	entered chan struct{}
	release chan struct{}
}

func (stub *blockingTicketExportRunnerStub) RunOnce(
	ctx context.Context,
	_ ticketexport.Queue,
) (ticketexport.Result, error) {
	stub.entered <- struct{}{}
	select {
	case <-ctx.Done():
		return ticketexport.Result{}, ctx.Err()
	case <-stub.release:
		return ticketexport.Result{Outcome: ticketexport.OutcomeIdle}, nil
	}
}

type ticketSpoolSweeperStub struct {
	checkErr error
	checked  chan struct{}
}

func (stub ticketSpoolSweeperStub) Check(context.Context) error {
	if stub.checked != nil {
		select {
		case stub.checked <- struct{}{}:
		default:
		}
	}
	return stub.checkErr
}

func (ticketSpoolSweeperStub) SweepSpoolsBefore(
	context.Context,
	time.Time,
	int,
) (ticketexport.SpoolSweepResult, error) {
	return ticketexport.SpoolSweepResult{}, nil
}

func mainTestTicketEntity(t *testing.T, suffix byte) kernel.EntityID {
	t.Helper()
	var raw [16]byte
	raw[0], raw[6], raw[8], raw[15] = 1, 0x70, 0x80, suffix
	id, err := kernel.NewEntityID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mainTestUUIDv7(t *testing.T, suffix byte) uuid.UUID {
	t.Helper()
	var raw [16]byte
	raw[0], raw[6], raw[8], raw[15] = 1, 0x70, 0x80, suffix
	id, err := uuid.FromBytes(raw[:])
	if err != nil {
		t.Fatal(err)
	}
	return id
}
