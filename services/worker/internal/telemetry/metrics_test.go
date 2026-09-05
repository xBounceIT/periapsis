package telemetry

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/periapsis-im/periapsis/services/worker/internal/oidcmaintenance"
)

func TestMetricsRenderOnlyFixedLabels(t *testing.T) {
	metrics := &Metrics{}
	metrics.SetDatabaseReady(true)
	metrics.SetCleanupReady(true)
	metrics.SetLDAPSyncReady(false)
	metrics.SetSLAReady(true)
	metrics.SetSLAActionReady(true)
	metrics.SetSLAEventReady(true)
	metrics.SetTicketRuntimeReady(true)
	metrics.SetOIDCMaintenanceReady(true)
	metrics.RecordAuthCleanup(nil)
	metrics.RecordAuthCleanup(errors.New("customer@example.invalid secret"))
	metrics.ObserveLDAPSyncPoll(true, false, 250*time.Millisecond)
	metrics.ObserveLDAPSyncPoll(false, true, 750*time.Millisecond)
	if !metrics.ObserveSLARun(3, 1, 1, 1, nil) ||
		!metrics.ObserveSLARun(1, 0, 0, 0, errors.New("tenant detail")) {
		t.Fatal("valid SLA summaries were rejected")
	}
	if !metrics.SetSLAQueueObservation(7, 125_500_000) {
		t.Fatal("valid SLA queue observation was rejected")
	}
	if !metrics.ObserveSLAActionRun(5, 1, 1, 1, 1, 1, nil) ||
		!metrics.SetSLAActionQueueObservation(3, 9_500_000) {
		t.Fatal("valid SLA action metrics were rejected")
	}
	if !metrics.ObserveSLAEventRun(5, 1, 1, 1, 1, 1, nil) ||
		!metrics.SetSLAEventQueueObservation(4, 2, 1, 12_250_000) {
		t.Fatal("valid SLA event ingress metrics were rejected")
	}
	if !metrics.ObserveTicketRuntimeRun("bulk", true, nil) ||
		!metrics.ObserveTicketRuntimeRun("export", false, nil) ||
		!metrics.ObserveTicketRuntimeRun("export", true, errors.New("tenant detail")) ||
		metrics.ObserveTicketRuntimeRun("tenant-secret", true, nil) {
		t.Fatal("ticket runtime metric classification failed")
	}
	if !metrics.ObserveTicketExportReconciliation(5, 1, 1, 1, 1, 1, nil) {
		t.Fatal("valid ticket export reconciliation metrics were rejected")
	}
	if !metrics.SetTicketExportReconciliationQueueObservation(4, 2, 1, 31_250_000) {
		t.Fatal("valid ticket export reconciliation queue observation was rejected")
	}
	if !metrics.ObserveOIDCMaintenanceRun(oidcmaintenance.Summary{
		Dispatches: 7, Claimed: 7, RefreshRotated: 1, LogoutComplete: 1,
		RetryScheduled: 1, LocalDeferred: 1, DeadLettered: 1, Scrubbed: 1, FenceLost: 1,
	}, nil) || !metrics.ObserveOIDCMaintenanceRun(oidcmaintenance.Summary{
		Dispatches: 1, Claimed: 1,
	}, errors.New("tenant endpoint secret")) {
		t.Fatal("valid OIDC maintenance metrics were rejected")
	}
	queueObservedAt := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	if !metrics.SetOIDCMaintenanceQueueObservation(oidcmaintenance.QueueSnapshot{
		ObservedAt: queueObservedAt,
		LogoutRetry: oidcmaintenance.QueueCategorySnapshot{
			DueCount: 4, ReclaimableCount: 2, DeadLetterCount: 1,
			OldestDueAt: queueObservedAt.Add(-1250 * time.Millisecond),
		},
		Refresh: oidcmaintenance.QueueCategorySnapshot{
			DueCount: 3, ReclaimableCount: 1,
			OldestDueAt: queueObservedAt.Add(-2 * time.Second),
		},
		Scrub: oidcmaintenance.QueueCategorySnapshot{
			DueCount: 2, OldestDueAt: queueObservedAt.Add(-3 * time.Second),
		},
	}) {
		t.Fatal("valid OIDC maintenance queue snapshot was rejected")
	}

	if err := metrics.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	output := metrics.RenderPrometheus()
	for _, expected := range []string{
		"periapsis_worker_database_ready 1",
		"periapsis_worker_auth_cleanup_ready 1",
		"periapsis_worker_ldap_sync_ready 0",
		"periapsis_worker_sla_ready 1",
		"periapsis_worker_sla_action_ready 1",
		"periapsis_worker_sla_event_ingress_ready 1",
		"periapsis_worker_ticket_runtime_ready 1",
		"periapsis_worker_oidc_maintenance_ready 1",
		"periapsis_worker_auth_cleanup_total{outcome=\"success\"} 1",
		"periapsis_worker_auth_cleanup_total{outcome=\"failure\"} 1",
		"periapsis_worker_ldap_sync_poll_total{outcome=\"worked\"} 1",
		"periapsis_worker_ldap_sync_poll_total{outcome=\"failure\"} 1",
		"periapsis_worker_ldap_sync_poll_duration_seconds_count 2",
		"periapsis_worker_ldap_sync_poll_duration_seconds_sum 1.000000000",
		"periapsis_sla_worker_runs_total{outcome=\"success\"} 1",
		"periapsis_sla_worker_runs_total{outcome=\"failure\"} 1",
		"periapsis_sla_worker_jobs_total{outcome=\"claimed\"} 4",
		"periapsis_sla_worker_jobs_total{outcome=\"completed\"} 1",
		"periapsis_sla_worker_jobs_total{outcome=\"retryable\"} 1",
		"periapsis_sla_worker_jobs_total{outcome=\"dead_lettered\"} 1",
		"periapsis_sla_queue_pending_jobs 7",
		"periapsis_sla_queue_oldest_pending_seconds 125.500000",
		"periapsis_sla_action_worker_runs_total{outcome=\"success\"} 1",
		"periapsis_sla_action_worker_actions_total{outcome=\"claimed\"} 5",
		"periapsis_sla_action_worker_actions_total{outcome=\"applied\"} 1",
		"periapsis_sla_action_worker_actions_total{outcome=\"replayed\"} 1",
		"periapsis_sla_action_worker_actions_total{outcome=\"retry_scheduled\"} 1",
		"periapsis_sla_action_worker_actions_total{outcome=\"dead_lettered\"} 1",
		"periapsis_sla_action_worker_actions_total{outcome=\"fence_lost\"} 1",
		"periapsis_sla_action_queue_pending_actions 3",
		"periapsis_sla_action_queue_oldest_pending_seconds 9.500000",
		"periapsis_sla_event_ingress_worker_runs_total{outcome=\"success\"} 1",
		"periapsis_sla_event_ingress_worker_events_total{outcome=\"claimed\"} 5",
		"periapsis_sla_event_ingress_worker_events_total{outcome=\"applied\"} 1",
		"periapsis_sla_event_ingress_worker_events_total{outcome=\"replayed\"} 1",
		"periapsis_sla_event_ingress_worker_events_total{outcome=\"retry_scheduled\"} 1",
		"periapsis_sla_event_ingress_worker_events_total{outcome=\"dead_lettered\"} 1",
		"periapsis_sla_event_ingress_worker_events_total{outcome=\"fence_lost\"} 1",
		"periapsis_sla_event_ingress_queue_pending_events 4",
		"periapsis_sla_event_ingress_queue_reclaimable_events 2",
		"periapsis_sla_event_ingress_queue_dead_lettered_events 1",
		"periapsis_sla_event_ingress_queue_oldest_pending_seconds 12.250000",
		"periapsis_ticket_bulk_worker_runs_total{outcome=\"worked\"} 1",
		"periapsis_ticket_export_worker_runs_total{outcome=\"empty\"} 1",
		"periapsis_ticket_export_worker_runs_total{outcome=\"failure\"} 1",
		"periapsis_ticket_export_reconcile_worker_runs_total{outcome=\"success\"} 1",
		"periapsis_ticket_export_reconcile_artifacts_total{outcome=\"claimed\"} 5",
		"periapsis_ticket_export_reconcile_artifacts_total{outcome=\"purged\"} 1",
		"periapsis_ticket_export_reconcile_artifacts_total{outcome=\"replayed\"} 1",
		"periapsis_ticket_export_reconcile_artifacts_total{outcome=\"retry_scheduled\"} 1",
		"periapsis_ticket_export_reconcile_artifacts_total{outcome=\"dead_lettered\"} 1",
		"periapsis_ticket_export_reconcile_artifacts_total{outcome=\"fence_lost\"} 1",
		"periapsis_ticket_export_reconcile_queue_pending_eligible 4",
		"periapsis_ticket_export_reconcile_queue_reclaimable 2",
		"periapsis_ticket_export_reconcile_queue_dead_lettered 1",
		"periapsis_ticket_export_reconcile_queue_oldest_pending_seconds 31.250000",
		"periapsis_worker_oidc_maintenance_runs_total{outcome=\"success\"} 1",
		"periapsis_worker_oidc_maintenance_runs_total{outcome=\"failure\"} 1",
		"periapsis_worker_oidc_maintenance_work_total{outcome=\"claimed\"} 8",
		"periapsis_worker_oidc_maintenance_work_total{outcome=\"rotated\"} 1",
		"periapsis_worker_oidc_maintenance_work_total{outcome=\"logout_complete\"} 1",
		"periapsis_worker_oidc_maintenance_work_total{outcome=\"safe_retry_submitted\"} 1",
		"periapsis_worker_oidc_maintenance_work_total{outcome=\"local_dependency_deferred\"} 1",
		"periapsis_worker_oidc_maintenance_work_total{outcome=\"terminal_failure_submitted\"} 1",
		"periapsis_worker_oidc_maintenance_work_total{outcome=\"scrubbed\"} 1",
		"periapsis_worker_oidc_maintenance_work_total{outcome=\"fence_lost\"} 1",
		"periapsis_worker_oidc_maintenance_queue_due{kind=\"logout_retry\"} 4",
		"periapsis_worker_oidc_maintenance_queue_due{kind=\"refresh\"} 3",
		"periapsis_worker_oidc_maintenance_queue_due{kind=\"scrub\"} 2",
		"periapsis_worker_oidc_maintenance_queue_reclaimable{kind=\"logout_retry\"} 2",
		"periapsis_worker_oidc_maintenance_queue_reclaimable{kind=\"refresh\"} 1",
		"periapsis_worker_oidc_maintenance_queue_dead_lettered{kind=\"logout_retry\"} 1",
		"periapsis_worker_oidc_maintenance_queue_oldest_due_seconds{kind=\"logout_retry\"} 1.250000",
		"periapsis_worker_oidc_maintenance_queue_oldest_due_seconds{kind=\"refresh\"} 2.000000",
		"periapsis_worker_oidc_maintenance_queue_oldest_due_seconds{kind=\"scrub\"} 3.000000",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("metrics output missing %q:\n%s", expected, output)
		}
	}
	if strings.Contains(output, "customer@example.invalid") || strings.Contains(output, "secret") {
		t.Fatalf("metrics output exposed error material: %s", output)
	}
	for _, family := range []string{
		"periapsis_worker_auth_cleanup_total",
		"periapsis_worker_ldap_sync_poll_total",
		"periapsis_sla_worker_runs_total",
		"periapsis_sla_worker_jobs_total",
		"periapsis_sla_action_worker_runs_total",
		"periapsis_sla_action_worker_actions_total",
		"periapsis_sla_event_ingress_worker_runs_total",
		"periapsis_sla_event_ingress_worker_events_total",
		"periapsis_ticket_bulk_worker_runs_total",
		"periapsis_ticket_export_worker_runs_total",
		"periapsis_ticket_export_reconcile_worker_runs_total",
		"periapsis_ticket_export_reconcile_artifacts_total",
		"periapsis_worker_oidc_maintenance_runs_total",
		"periapsis_worker_oidc_maintenance_work_total",
	} {
		if count := strings.Count(output, "# HELP "+family+" "); count != 1 {
			t.Fatalf("HELP declaration count for %s = %d, want 1", family, count)
		}
		if count := strings.Count(output, "# TYPE "+family+" counter"); count != 1 {
			t.Fatalf("TYPE declaration count for %s = %d, want 1", family, count)
		}
	}
	for _, family := range []string{
		"periapsis_sla_queue_pending_jobs",
		"periapsis_sla_queue_oldest_pending_seconds",
		"periapsis_sla_action_queue_pending_actions",
		"periapsis_sla_action_queue_oldest_pending_seconds",
		"periapsis_sla_event_ingress_queue_pending_events",
		"periapsis_sla_event_ingress_queue_reclaimable_events",
		"periapsis_sla_event_ingress_queue_dead_lettered_events",
		"periapsis_sla_event_ingress_queue_oldest_pending_seconds",
		"periapsis_ticket_export_reconcile_queue_pending_eligible",
		"periapsis_ticket_export_reconcile_queue_reclaimable",
		"periapsis_ticket_export_reconcile_queue_dead_lettered",
		"periapsis_ticket_export_reconcile_queue_oldest_pending_seconds",
		"periapsis_worker_oidc_maintenance_queue_due",
		"periapsis_worker_oidc_maintenance_queue_reclaimable",
		"periapsis_worker_oidc_maintenance_queue_dead_lettered",
		"periapsis_worker_oidc_maintenance_queue_oldest_due_seconds",
	} {
		if count := strings.Count(output, "# HELP "+family+" "); count != 1 {
			t.Fatalf("HELP declaration count for %s = %d, want 1", family, count)
		}
		if count := strings.Count(output, "# TYPE "+family+" gauge"); count != 1 {
			t.Fatalf("TYPE declaration count for %s = %d, want 1", family, count)
		}
	}
}

func TestMetricsRejectsContradictoryOIDCMaintenanceSummary(t *testing.T) {
	metrics := &Metrics{}
	if metrics.ObserveOIDCMaintenanceRun(oidcmaintenance.Summary{
		Dispatches: 3, Claimed: 1, RefreshRotated: 1, LogoutComplete: 1,
	}, nil) || metrics.ObserveOIDCMaintenanceRun(oidcmaintenance.Summary{
		Dispatches: 3, Claimed: 1,
	}, nil) {
		t.Fatal("contradictory OIDC maintenance summaries were accepted")
	}
	if metrics.oidcMaintenanceRunFailure.Load() != 2 || metrics.oidcMaintenanceClaimed.Load() != 0 {
		t.Fatal("invalid OIDC maintenance summaries mutated bounded counters")
	}
}

func TestMetricsOmitsUnavailableOIDCQueueAndClearsContradictorySnapshot(t *testing.T) {
	metrics := &Metrics{}
	const family = "periapsis_worker_oidc_maintenance_queue_due"
	if strings.Contains(metrics.RenderPrometheus(), family) {
		t.Fatal("unobserved OIDC queue was rendered as an authoritative zero")
	}
	observedAt := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	if !metrics.SetOIDCMaintenanceQueueObservation(oidcmaintenance.QueueSnapshot{ObservedAt: observedAt}) ||
		!strings.Contains(metrics.RenderPrometheus(), family+"{kind=\"scrub\"} 0") {
		t.Fatal("valid authoritative empty OIDC queue was not rendered")
	}
	if metrics.SetOIDCMaintenanceQueueObservation(oidcmaintenance.QueueSnapshot{
		ObservedAt: observedAt,
		Refresh:    oidcmaintenance.QueueCategorySnapshot{DueCount: 1},
	}) || strings.Contains(metrics.RenderPrometheus(), family) {
		t.Fatal("contradictory OIDC queue remained visible")
	}
	if !metrics.SetOIDCMaintenanceQueueObservation(oidcmaintenance.QueueSnapshot{ObservedAt: observedAt}) {
		t.Fatal("valid OIDC queue was rejected after a failed snapshot")
	}
	metrics.ClearOIDCMaintenanceQueueObservation()
	if strings.Contains(metrics.RenderPrometheus(), family) {
		t.Fatal("cleared OIDC queue remained visible")
	}
}

func TestMetricsOmitsUnavailableReconciliationQueueAndRejectsContradictions(t *testing.T) {
	metrics := &Metrics{}
	if strings.Contains(metrics.RenderPrometheus(), "periapsis_ticket_export_reconcile_queue_") {
		t.Fatal("unobserved reconciliation queue was rendered as an authoritative zero")
	}
	if !metrics.SetTicketExportReconciliationQueueObservation(0, 0, 3, 0) {
		t.Fatal("authoritative queue containing only dead letters was rejected")
	}
	output := metrics.RenderPrometheus()
	for _, expected := range []string{
		"periapsis_ticket_export_reconcile_queue_pending_eligible 0",
		"periapsis_ticket_export_reconcile_queue_reclaimable 0",
		"periapsis_ticket_export_reconcile_queue_dead_lettered 3",
		"periapsis_ticket_export_reconcile_queue_oldest_pending_seconds 0.000000",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("reconciliation queue metrics missing %q:\n%s", expected, output)
		}
	}
	if metrics.SetTicketExportReconciliationQueueObservation(0, 0, 0, 1) {
		t.Fatal("queue age without eligible work was accepted")
	}
	if strings.Contains(metrics.RenderPrometheus(), "periapsis_ticket_export_reconcile_queue_") {
		t.Fatal("invalid reconciliation observation left stale series visible")
	}
	if metrics.SetTicketExportReconciliationQueueObservation(-1, 0, 0, 0) {
		t.Fatal("negative reconciliation queue count was accepted")
	}
	if !metrics.SetTicketExportReconciliationQueueObservation(1, 0, 0, 0) {
		t.Fatal("newly eligible reconciliation work was rejected")
	}
	metrics.ClearTicketExportReconciliationQueueObservation()
	if strings.Contains(metrics.RenderPrometheus(), "periapsis_ticket_export_reconcile_queue_") {
		t.Fatal("cleared reconciliation queue observation remained visible")
	}
}

func TestMetricsOmitsUnavailableQueueAndPublishesAuthoritativeEmptyQueue(t *testing.T) {
	metrics := &Metrics{}
	if strings.Contains(metrics.RenderPrometheus(), "periapsis_sla_queue_") {
		t.Fatal("unobserved SLA queue was rendered as an authoritative zero")
	}
	if !metrics.SetSLAQueueObservation(0, 0) {
		t.Fatal("authoritative empty SLA queue was rejected")
	}
	output := metrics.RenderPrometheus()
	if !strings.Contains(output, "periapsis_sla_queue_pending_jobs 0") ||
		!strings.Contains(output, "periapsis_sla_queue_oldest_pending_seconds 0.000000") {
		t.Fatalf("empty SLA queue metrics missing:\n%s", output)
	}
	if metrics.SetSLAQueueObservation(0, 1) {
		t.Fatal("contradictory SLA queue observation was accepted")
	}
	if strings.Contains(metrics.RenderPrometheus(), "periapsis_sla_queue_") {
		t.Fatal("invalid SLA queue observation left stale series visible")
	}
	if !metrics.SetSLAQueueObservation(1, 0) {
		t.Fatal("newly eligible SLA work was rejected")
	}
	metrics.ClearSLAQueueObservation()
	if strings.Contains(metrics.RenderPrometheus(), "periapsis_sla_queue_") {
		t.Fatal("cleared SLA queue observation remained visible")
	}
}

func TestMetricsRejectsContradictorySLAJobCountsButRecordsFailedRuns(t *testing.T) {
	metrics := &Metrics{}
	if metrics.ObserveSLARun(1, 1, 1, 0, nil) || metrics.ObserveSLARun(-1, 0, 0, 0, nil) {
		t.Fatal("ObserveSLARun() accepted a contradictory summary")
	}
	if metrics.slaRunSuccess.Load() != 0 || metrics.slaRunFailure.Load() != 2 ||
		metrics.slaJobsClaimed.Load() != 0 {
		t.Fatal("invalid SLA summaries were not recorded as count-only failures")
	}
}

func TestMetricsRejectsContradictorySLAActionCountsAndClearsInvalidQueue(t *testing.T) {
	metrics := &Metrics{}
	if metrics.ObserveSLAActionRun(1, 1, 1, 0, 0, 0, nil) {
		t.Fatal("ObserveSLAActionRun() accepted contradictory outcomes")
	}
	if metrics.slaActionRunFailure.Load() != 1 || metrics.slaActionsClaimed.Load() != 0 {
		t.Fatal("invalid SLA action summary mutated bounded counters")
	}
	if !metrics.SetSLAActionQueueObservation(2, 1) ||
		metrics.SetSLAActionQueueObservation(0, 1) ||
		strings.Contains(metrics.RenderPrometheus(), "periapsis_sla_action_queue_") {
		t.Fatal("invalid SLA action queue observation did not fail closed")
	}
}

func TestMetricsRejectsContradictorySLAEventCountsAndClearsInvalidQueue(t *testing.T) {
	metrics := &Metrics{}
	if metrics.ObserveSLAEventRun(1, 1, 1, 0, 0, 0, nil) ||
		metrics.ObserveSLAEventRun(1, 0, 0, 0, 0, 0, nil) {
		t.Fatal("ObserveSLAEventRun() accepted contradictory successful outcomes")
	}
	if metrics.slaEventRunFailure.Load() != 2 || metrics.slaEventsClaimed.Load() != 0 {
		t.Fatal("invalid SLA event summaries mutated bounded counters")
	}
	if !metrics.SetSLAEventQueueObservation(0, 0, 2, 0) ||
		metrics.SetSLAEventQueueObservation(0, 0, 0, 1) ||
		strings.Contains(metrics.RenderPrometheus(), "periapsis_sla_event_ingress_queue_") {
		t.Fatal("invalid SLA event queue observation did not fail closed")
	}
}

func TestMetricsClassifiesEachPollExactlyOnce(t *testing.T) {
	metrics := &Metrics{}
	metrics.ObserveLDAPSyncPoll(false, false, 0)
	metrics.ObserveLDAPSyncPoll(true, false, 0)
	metrics.ObserveLDAPSyncPoll(true, true, 0)
	if err := metrics.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if got := metrics.ldapPollCount.Load(); got != 3 {
		t.Fatalf("poll count = %d, want 3", got)
	}
}

func TestMetricsRejectsContradictoryTicketExportReconciliationCounts(t *testing.T) {
	metrics := &Metrics{}
	if metrics.ObserveTicketExportReconciliation(1, 1, 1, 0, 0, 0, nil) ||
		metrics.ObserveTicketExportReconciliation(-1, 0, 0, 0, 0, 0, nil) ||
		metrics.ObserveTicketExportReconciliation(1, 0, 0, 0, 0, 0, nil) {
		t.Fatal("ObserveTicketExportReconciliation() accepted contradictory summaries")
	}
	if metrics.ticketReconcileRunSuccess.Load() != 0 ||
		metrics.ticketReconcileRunFailure.Load() != 3 ||
		metrics.ticketReconcileClaimed.Load() != 0 {
		t.Fatal("invalid reconciliation summaries mutated bounded artifact counters")
	}
	if !metrics.ObserveTicketExportReconciliation(2, 1, 0, 0, 0, 0, errors.New("transition outcome unknown")) {
		t.Fatal("partial failed reconciliation summary was rejected")
	}
	if err := metrics.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}
