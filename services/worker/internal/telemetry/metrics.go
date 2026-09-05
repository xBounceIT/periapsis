package telemetry

import (
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/periapsis-im/periapsis/services/worker/internal/oidcmaintenance"
)

// Metrics is the worker's bounded, process-local Prometheus registry. It uses
// only fixed labels so tenants, identities, directory endpoints, and errors can
// never become metric dimensions.
type Metrics struct {
	databaseReady        atomic.Int64
	cleanupReady         atomic.Int64
	dfirCleanupReady     atomic.Int64
	dfirScanReady        atomic.Int64
	ldapSyncReady        atomic.Int64
	slaReady             atomic.Int64
	slaActionReady       atomic.Int64
	slaEventReady        atomic.Int64
	ticketRuntimeReady   atomic.Int64
	oidcMaintenanceReady atomic.Int64

	authCleanupSuccess        atomic.Uint64
	authCleanupFailure        atomic.Uint64
	dfirCleanupRunSuccess     atomic.Uint64
	dfirCleanupRunFailure     atomic.Uint64
	dfirCleanupClaimed        atomic.Uint64
	dfirCleanupDeleted        atomic.Uint64
	dfirCleanupRetry          atomic.Uint64
	dfirScanRunSuccess        atomic.Uint64
	dfirScanRunFailure        atomic.Uint64
	dfirScanClaimed           atomic.Uint64
	dfirScanAvailable         atomic.Uint64
	dfirScanRejected          atomic.Uint64
	dfirScanFailed            atomic.Uint64
	dfirScanWaitingUpload     atomic.Uint64
	dfirScanUploadExpired     atomic.Uint64
	dfirScanRetry             atomic.Uint64
	dfirScanFenceLost         atomic.Uint64
	ldapPollWorked            atomic.Uint64
	ldapPollEmpty             atomic.Uint64
	ldapPollFailure           atomic.Uint64
	ldapPollCount             atomic.Uint64
	ldapPollNanos             atomic.Uint64
	slaRunSuccess             atomic.Uint64
	slaRunFailure             atomic.Uint64
	slaJobsClaimed            atomic.Uint64
	slaJobsCompleted          atomic.Uint64
	slaJobsRetryable          atomic.Uint64
	slaJobsDeadLetter         atomic.Uint64
	slaQueue                  atomic.Pointer[slaQueueSnapshot]
	slaActionRunSuccess       atomic.Uint64
	slaActionRunFailure       atomic.Uint64
	slaActionsClaimed         atomic.Uint64
	slaActionsApplied         atomic.Uint64
	slaActionsReplayed        atomic.Uint64
	slaActionsRetry           atomic.Uint64
	slaActionsDead            atomic.Uint64
	slaActionsFenceLost       atomic.Uint64
	slaActionQueue            atomic.Pointer[slaQueueSnapshot]
	slaEventRunSuccess        atomic.Uint64
	slaEventRunFailure        atomic.Uint64
	slaEventsClaimed          atomic.Uint64
	slaEventsApplied          atomic.Uint64
	slaEventsReplayed         atomic.Uint64
	slaEventsRetry            atomic.Uint64
	slaEventsDead             atomic.Uint64
	slaEventsFenceLost        atomic.Uint64
	slaEventQueue             atomic.Pointer[slaEventQueueSnapshot]
	ticketBulkWorked          atomic.Uint64
	ticketBulkIdle            atomic.Uint64
	ticketBulkFailure         atomic.Uint64
	ticketExportWorked        atomic.Uint64
	ticketExportIdle          atomic.Uint64
	ticketExportFailure       atomic.Uint64
	ticketReconcileRunSuccess atomic.Uint64
	ticketReconcileRunFailure atomic.Uint64
	ticketReconcileClaimed    atomic.Uint64
	ticketReconcilePurged     atomic.Uint64
	ticketReconcileReplayed   atomic.Uint64
	ticketReconcileRetry      atomic.Uint64
	ticketReconcileDead       atomic.Uint64
	ticketReconcileFenceLost  atomic.Uint64
	ticketReconcileQueue      atomic.Pointer[ticketReconcileQueueSnapshot]
	oidcMaintenanceRunSuccess atomic.Uint64
	oidcMaintenanceRunFailure atomic.Uint64
	oidcMaintenanceClaimed    atomic.Uint64
	oidcMaintenanceRotated    atomic.Uint64
	oidcMaintenanceLogout     atomic.Uint64
	oidcMaintenanceRetry      atomic.Uint64
	oidcMaintenanceDeferred   atomic.Uint64
	oidcMaintenanceDead       atomic.Uint64
	oidcMaintenanceScrubbed   atomic.Uint64
	oidcMaintenanceFenceLost  atomic.Uint64
	oidcMaintenanceQueue      atomic.Pointer[oidcMaintenanceQueueSnapshot]
}

type slaQueueSnapshot struct {
	pendingJobs         uint64
	oldestPendingMicros uint64
}

type oidcMaintenanceQueueSnapshot struct {
	logoutDue           uint64
	logoutReclaimable   uint64
	logoutDeadLettered  uint64
	logoutOldestMicros  uint64
	refreshDue          uint64
	refreshReclaimable  uint64
	refreshOldestMicros uint64
	scrubDue            uint64
	scrubOldestMicros   uint64
}

type slaEventQueueSnapshot struct {
	pendingEvents       uint64
	reclaimableEvents   uint64
	deadLetteredEvents  uint64
	oldestPendingMicros uint64
}

type ticketReconcileQueueSnapshot struct {
	pendingEligible     uint64
	reclaimable         uint64
	deadLettered        uint64
	oldestPendingMicros uint64
}

func (m *Metrics) SetDatabaseReady(ready bool) {
	if m != nil {
		storeGauge(&m.databaseReady, ready)
	}
}

func (m *Metrics) SetCleanupReady(ready bool) {
	if m != nil {
		storeGauge(&m.cleanupReady, ready)
	}
}

func (m *Metrics) SetDFIRScanReady(ready bool) {
	if m != nil {
		storeGauge(&m.dfirScanReady, ready)
	}
}

func (m *Metrics) SetDFIRCleanupReady(ready bool) {
	if m != nil {
		storeGauge(&m.dfirCleanupReady, ready)
	}
}

// ObserveDFIRScanRun records only fixed scan outcomes. Object, tenant, MIME,
// hash, filename, scanner response, and error values are structurally absent.
func (m *Metrics) ObserveDFIRScanRun(
	claimed, available, rejected, scanFailed, waitingUpload, uploadExpired, retryScheduled, fenceLost int,
	runErr error,
) bool {
	if m == nil {
		return false
	}
	classified := available + rejected + scanFailed + waitingUpload + uploadExpired + retryScheduled + fenceLost
	if claimed < 0 || available < 0 || rejected < 0 || scanFailed < 0 || waitingUpload < 0 ||
		uploadExpired < 0 || retryScheduled < 0 || fenceLost < 0 || classified > claimed ||
		runErr == nil && classified != claimed {
		m.dfirScanRunFailure.Add(1)
		return false
	}
	if runErr == nil {
		m.dfirScanRunSuccess.Add(1)
	} else {
		m.dfirScanRunFailure.Add(1)
	}
	m.dfirScanClaimed.Add(uint64(claimed))
	m.dfirScanAvailable.Add(uint64(available))
	m.dfirScanRejected.Add(uint64(rejected))
	m.dfirScanFailed.Add(uint64(scanFailed))
	m.dfirScanWaitingUpload.Add(uint64(waitingUpload))
	m.dfirScanUploadExpired.Add(uint64(uploadExpired))
	m.dfirScanRetry.Add(uint64(retryScheduled))
	m.dfirScanFenceLost.Add(uint64(fenceLost))
	return true
}

func (m *Metrics) ObserveDFIRCleanupRun(claimed, deleted, retryScheduled int, runErr error) bool {
	if m == nil {
		return false
	}
	if claimed < 0 || deleted < 0 || retryScheduled < 0 || deleted+retryScheduled > claimed ||
		runErr == nil && deleted+retryScheduled != claimed {
		m.dfirCleanupRunFailure.Add(1)
		return false
	}
	if runErr == nil {
		m.dfirCleanupRunSuccess.Add(1)
	} else {
		m.dfirCleanupRunFailure.Add(1)
	}
	m.dfirCleanupClaimed.Add(uint64(claimed))
	m.dfirCleanupDeleted.Add(uint64(deleted))
	m.dfirCleanupRetry.Add(uint64(retryScheduled))
	return true
}

func (m *Metrics) SetLDAPSyncReady(ready bool) {
	if m != nil {
		storeGauge(&m.ldapSyncReady, ready)
	}
}

func (m *Metrics) SetSLAReady(ready bool) {
	if m != nil {
		storeGauge(&m.slaReady, ready)
	}
}

func (m *Metrics) SetSLAActionReady(ready bool) {
	if m != nil {
		storeGauge(&m.slaActionReady, ready)
	}
}

func (m *Metrics) SetSLAEventReady(ready bool) {
	if m != nil {
		storeGauge(&m.slaEventReady, ready)
	}
}

func (m *Metrics) SetTicketRuntimeReady(ready bool) {
	if m != nil {
		storeGauge(&m.ticketRuntimeReady, ready)
	}
}

func (m *Metrics) SetOIDCMaintenanceReady(ready bool) {
	if m != nil {
		storeGauge(&m.oidcMaintenanceReady, ready)
	}
}

func (m *Metrics) SetOIDCMaintenanceQueueObservation(snapshot oidcmaintenance.QueueSnapshot) bool {
	if m == nil {
		return false
	}
	logoutAge, logoutOK := oidcQueueAgeMicros(snapshot.ObservedAt, snapshot.LogoutRetry)
	refreshAge, refreshOK := oidcQueueAgeMicros(snapshot.ObservedAt, snapshot.Refresh)
	scrubAge, scrubOK := oidcQueueAgeMicros(snapshot.ObservedAt, snapshot.Scrub)
	if !logoutOK || !refreshOK || !scrubOK ||
		snapshot.LogoutRetry.ReclaimableCount > snapshot.LogoutRetry.DueCount ||
		snapshot.Refresh.ReclaimableCount > snapshot.Refresh.DueCount ||
		snapshot.Scrub.ReclaimableCount != 0 || snapshot.Scrub.DeadLetterCount != 0 ||
		snapshot.Refresh.DeadLetterCount != 0 {
		m.oidcMaintenanceQueue.Store(nil)
		return false
	}
	m.oidcMaintenanceQueue.Store(&oidcMaintenanceQueueSnapshot{
		logoutDue:           snapshot.LogoutRetry.DueCount,
		logoutReclaimable:   snapshot.LogoutRetry.ReclaimableCount,
		logoutDeadLettered:  snapshot.LogoutRetry.DeadLetterCount,
		logoutOldestMicros:  logoutAge,
		refreshDue:          snapshot.Refresh.DueCount,
		refreshReclaimable:  snapshot.Refresh.ReclaimableCount,
		refreshOldestMicros: refreshAge,
		scrubDue:            snapshot.Scrub.DueCount,
		scrubOldestMicros:   scrubAge,
	})
	return true
}

func (m *Metrics) ClearOIDCMaintenanceQueueObservation() {
	if m != nil {
		m.oidcMaintenanceQueue.Store(nil)
	}
}

func oidcQueueAgeMicros(
	observedAt time.Time,
	category oidcmaintenance.QueueCategorySnapshot,
) (uint64, bool) {
	if !validMetricInstant(observedAt) || category.DueCount > oidcmaintenance.MaximumPersistentCount ||
		category.ReclaimableCount > oidcmaintenance.MaximumPersistentCount ||
		category.DeadLetterCount > oidcmaintenance.MaximumPersistentCount {
		return 0, false
	}
	if category.DueCount == 0 {
		return 0, category.OldestDueAt.IsZero()
	}
	if !validMetricInstant(category.OldestDueAt) || category.OldestDueAt.After(observedAt) {
		return 0, false
	}
	return uint64(observedAt.Sub(category.OldestDueAt) / time.Microsecond), true
}

// ObserveOIDCMaintenanceRun records only fixed outcomes. Provider, tenant,
// endpoint, job, material, and error values can never become metric labels.
func (m *Metrics) ObserveOIDCMaintenanceRun(summary oidcmaintenance.Summary, runErr error) bool {
	if m == nil {
		return false
	}
	classified := summary.RefreshRotated + summary.LogoutComplete + summary.RetryScheduled +
		summary.LocalDeferred + summary.DeadLettered + summary.Scrubbed + summary.FenceLost
	if summary.Dispatches < 0 || summary.Dispatches > oidcmaintenance.MaximumBatchSize ||
		summary.Claimed < 0 || summary.Claimed > summary.Dispatches ||
		summary.RefreshRotated < 0 || summary.LogoutComplete < 0 ||
		summary.RetryScheduled < 0 || summary.LocalDeferred < 0 || summary.DeadLettered < 0 ||
		summary.Scrubbed < 0 ||
		summary.FenceLost < 0 || classified > summary.Claimed || runErr == nil && classified != summary.Claimed {
		m.oidcMaintenanceRunFailure.Add(1)
		return false
	}
	if runErr == nil {
		m.oidcMaintenanceRunSuccess.Add(1)
	} else {
		m.oidcMaintenanceRunFailure.Add(1)
	}
	m.oidcMaintenanceClaimed.Add(uint64(summary.Claimed))
	m.oidcMaintenanceRotated.Add(uint64(summary.RefreshRotated))
	m.oidcMaintenanceLogout.Add(uint64(summary.LogoutComplete))
	m.oidcMaintenanceRetry.Add(uint64(summary.RetryScheduled))
	m.oidcMaintenanceDeferred.Add(uint64(summary.LocalDeferred))
	m.oidcMaintenanceDead.Add(uint64(summary.DeadLettered))
	m.oidcMaintenanceScrubbed.Add(uint64(summary.Scrubbed))
	m.oidcMaintenanceFenceLost.Add(uint64(summary.FenceLost))
	return true
}

// ObserveTicketRuntimeRun records only a fixed queue family and bounded
// outcome. Tenant, ticket kind, audience, identities, and errors are never
// retained as metric labels.
func (m *Metrics) ObserveTicketRuntimeRun(family string, worked bool, runErr error) bool {
	if m == nil {
		return false
	}
	var workedCounter, idleCounter, failureCounter *atomic.Uint64
	switch family {
	case "bulk":
		workedCounter, idleCounter, failureCounter = &m.ticketBulkWorked, &m.ticketBulkIdle, &m.ticketBulkFailure
	case "export":
		workedCounter, idleCounter, failureCounter = &m.ticketExportWorked, &m.ticketExportIdle, &m.ticketExportFailure
	default:
		return false
	}
	if runErr != nil {
		failureCounter.Add(1)
	} else if worked {
		workedCounter.Add(1)
	} else {
		idleCounter.Add(1)
	}
	return true
}

// ObserveTicketExportReconciliation records one database-fenced artifact
// cleanup iteration without retaining tenant, object, queue, or error data.
// Invalid summaries are counted as failed iterations while their contradictory
// artifact counts are discarded.
func (m *Metrics) ObserveTicketExportReconciliation(
	claimed, purged, replayed, retryScheduled, deadLettered, fenceLost int,
	runErr error,
) bool {
	if m == nil {
		return false
	}
	classified := purged + replayed + retryScheduled + deadLettered + fenceLost
	if claimed < 0 || purged < 0 || replayed < 0 || retryScheduled < 0 ||
		deadLettered < 0 || fenceLost < 0 ||
		classified > claimed || runErr == nil && classified != claimed {
		m.ticketReconcileRunFailure.Add(1)
		return false
	}
	if runErr == nil {
		m.ticketReconcileRunSuccess.Add(1)
	} else {
		m.ticketReconcileRunFailure.Add(1)
	}
	m.ticketReconcileClaimed.Add(uint64(claimed))
	m.ticketReconcilePurged.Add(uint64(purged))
	m.ticketReconcileReplayed.Add(uint64(replayed))
	m.ticketReconcileRetry.Add(uint64(retryScheduled))
	m.ticketReconcileDead.Add(uint64(deadLettered))
	m.ticketReconcileFenceLost.Add(uint64(fenceLost))
	return true
}

// SetSLAQueueObservation publishes one authoritative database snapshot. A
// genuinely empty queue is represented by zeroes; invalid or unavailable
// observations must use ClearSLAQueueObservation so stale data is not exposed
// as current state.
func (m *Metrics) SetSLAQueueObservation(pendingJobs, oldestPendingMicros int64) bool {
	if m == nil || pendingJobs < 0 || oldestPendingMicros < 0 ||
		pendingJobs == 0 && oldestPendingMicros != 0 {
		if m != nil {
			m.slaQueue.Store(nil)
		}
		return false
	}
	m.slaQueue.Store(&slaQueueSnapshot{
		pendingJobs:         uint64(pendingJobs),
		oldestPendingMicros: uint64(oldestPendingMicros),
	})
	return true
}

func (m *Metrics) ClearSLAQueueObservation() {
	if m != nil {
		m.slaQueue.Store(nil)
	}
}

func (m *Metrics) SetSLAActionQueueObservation(pendingActions, oldestPendingMicros int64) bool {
	if m == nil || pendingActions < 0 || oldestPendingMicros < 0 ||
		pendingActions == 0 && oldestPendingMicros != 0 {
		if m != nil {
			m.slaActionQueue.Store(nil)
		}
		return false
	}
	m.slaActionQueue.Store(&slaQueueSnapshot{
		pendingJobs:         uint64(pendingActions),
		oldestPendingMicros: uint64(oldestPendingMicros),
	})
	return true
}

func (m *Metrics) ClearSLAActionQueueObservation() {
	if m != nil {
		m.slaActionQueue.Store(nil)
	}
}

// SetSLAEventQueueObservation publishes one authoritative global ingress
// snapshot without retaining tenant or object dimensions. Dead letters remain
// visible even when no event is currently eligible to run.
func (m *Metrics) SetSLAEventQueueObservation(
	pendingEvents, reclaimableEvents, deadLetteredEvents, oldestPendingMicros int64,
) bool {
	if m == nil || pendingEvents < 0 || reclaimableEvents < 0 || deadLetteredEvents < 0 ||
		oldestPendingMicros < 0 ||
		pendingEvents == 0 && reclaimableEvents == 0 && oldestPendingMicros != 0 {
		if m != nil {
			m.slaEventQueue.Store(nil)
		}
		return false
	}
	m.slaEventQueue.Store(&slaEventQueueSnapshot{
		pendingEvents: uint64(pendingEvents), reclaimableEvents: uint64(reclaimableEvents),
		deadLetteredEvents: uint64(deadLetteredEvents), oldestPendingMicros: uint64(oldestPendingMicros),
	})
	return true
}

func (m *Metrics) ClearSLAEventQueueObservation() {
	if m != nil {
		m.slaEventQueue.Store(nil)
	}
}

// SetTicketExportReconciliationQueueObservation publishes one authoritative,
// global database snapshot. Tenant, artifact, and object identifiers are
// structurally absent. An unavailable or contradictory observation clears the
// previous snapshot so stale queue state cannot be mistaken for current data.
func (m *Metrics) SetTicketExportReconciliationQueueObservation(
	pendingEligible, reclaimable, deadLettered, oldestPendingMicros int64,
) bool {
	if m == nil || pendingEligible < 0 || reclaimable < 0 || deadLettered < 0 ||
		oldestPendingMicros < 0 ||
		pendingEligible == 0 && reclaimable == 0 && oldestPendingMicros != 0 {
		if m != nil {
			m.ticketReconcileQueue.Store(nil)
		}
		return false
	}
	m.ticketReconcileQueue.Store(&ticketReconcileQueueSnapshot{
		pendingEligible:     uint64(pendingEligible),
		reclaimable:         uint64(reclaimable),
		deadLettered:        uint64(deadLettered),
		oldestPendingMicros: uint64(oldestPendingMicros),
	})
	return true
}

func (m *Metrics) ClearTicketExportReconciliationQueueObservation() {
	if m != nil {
		m.ticketReconcileQueue.Store(nil)
	}
}

func (m *Metrics) ObserveSLAActionRun(
	claimed, applied, replayed, retryScheduled, deadLettered, fenceLost int,
	runErr error,
) bool {
	if m == nil {
		return false
	}
	if claimed < 0 || applied < 0 || replayed < 0 || retryScheduled < 0 ||
		deadLettered < 0 || fenceLost < 0 ||
		applied+replayed+retryScheduled+deadLettered+fenceLost > claimed {
		m.slaActionRunFailure.Add(1)
		return false
	}
	if runErr == nil {
		m.slaActionRunSuccess.Add(1)
	} else {
		m.slaActionRunFailure.Add(1)
	}
	m.slaActionsClaimed.Add(uint64(claimed))
	m.slaActionsApplied.Add(uint64(applied))
	m.slaActionsReplayed.Add(uint64(replayed))
	m.slaActionsRetry.Add(uint64(retryScheduled))
	m.slaActionsDead.Add(uint64(deadLettered))
	m.slaActionsFenceLost.Add(uint64(fenceLost))
	return true
}

// ObserveSLAEventRun records one ordered ingress iteration. Invalid or
// contradictory summaries increment only the failed-run counter.
func (m *Metrics) ObserveSLAEventRun(
	claimed, applied, replayed, retryScheduled, deadLettered, fenceLost int,
	runErr error,
) bool {
	if m == nil {
		return false
	}
	classified := applied + replayed + retryScheduled + deadLettered + fenceLost
	if claimed < 0 || applied < 0 || replayed < 0 || retryScheduled < 0 ||
		deadLettered < 0 || fenceLost < 0 || classified > claimed ||
		runErr == nil && classified != claimed {
		m.slaEventRunFailure.Add(1)
		return false
	}
	if runErr == nil {
		m.slaEventRunSuccess.Add(1)
	} else {
		m.slaEventRunFailure.Add(1)
	}
	m.slaEventsClaimed.Add(uint64(claimed))
	m.slaEventsApplied.Add(uint64(applied))
	m.slaEventsReplayed.Add(uint64(replayed))
	m.slaEventsRetry.Add(uint64(retryScheduled))
	m.slaEventsDead.Add(uint64(deadLettered))
	m.slaEventsFenceLost.Add(uint64(fenceLost))
	return true
}

// ObserveSLARun records one bounded SLA loop summary. An invalid summary is
// still one failed iteration, but its contradictory job counts are discarded.
func (m *Metrics) ObserveSLARun(claimed, completed, retryable, deadLettered int, runErr error) bool {
	if m == nil {
		return false
	}
	if claimed < 0 || completed < 0 || retryable < 0 || deadLettered < 0 ||
		completed+retryable+deadLettered > claimed {
		m.slaRunFailure.Add(1)
		return false
	}
	if runErr == nil {
		m.slaRunSuccess.Add(1)
	} else {
		m.slaRunFailure.Add(1)
	}
	m.slaJobsClaimed.Add(uint64(claimed))
	m.slaJobsCompleted.Add(uint64(completed))
	m.slaJobsRetryable.Add(uint64(retryable))
	m.slaJobsDeadLetter.Add(uint64(deadLettered))
	return true
}

// RecordAuthCleanup records a fixed success/failure outcome.
func (m *Metrics) RecordAuthCleanup(err error) {
	if m == nil {
		return
	}
	if err == nil {
		m.authCleanupSuccess.Add(1)
		return
	}
	m.authCleanupFailure.Add(1)
}

// ObserveLDAPSyncPoll implements identitysync.PollObserver without retaining
// the error or any directory/customer data.
func (m *Metrics) ObserveLDAPSyncPoll(worked bool, failed bool, elapsed time.Duration) {
	if m == nil {
		return
	}
	switch {
	case failed:
		m.ldapPollFailure.Add(1)
	case worked:
		m.ldapPollWorked.Add(1)
	default:
		m.ldapPollEmpty.Add(1)
	}
	m.ldapPollCount.Add(1)
	if elapsed > 0 {
		m.ldapPollNanos.Add(uint64(elapsed))
	}
}

// RenderPrometheus returns a deterministic OpenMetrics-compatible text
// exposition. Counters intentionally omit tenant and error labels.
func (m *Metrics) RenderPrometheus() string {
	if m == nil {
		return ""
	}
	var output strings.Builder
	writeGauge := func(name, help string, value int64) {
		fmt.Fprintf(&output, "# HELP %s %s\n# TYPE %s gauge\n%s %d\n", name, help, name, name, value)
	}
	type counterSample struct {
		outcome string
		value   uint64
	}
	writeCounterFamily := func(name, help string, values ...counterSample) {
		fmt.Fprintf(&output, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)
		for _, sample := range values {
			if !validMetricOutcome(sample.outcome) {
				panic("telemetry: invalid fixed metric outcome")
			}
			fmt.Fprintf(
				&output,
				"%s{outcome=\"%s\"} %d\n",
				name, sample.outcome, sample.value,
			)
		}
	}
	writeGauge("periapsis_worker_database_ready", "Whether the worker database dependency is ready.", m.databaseReady.Load())
	writeGauge("periapsis_worker_auth_cleanup_ready", "Whether the authorization cleanup loop is healthy.", m.cleanupReady.Load())
	writeGauge("periapsis_worker_dfir_scan_ready", "Whether the fenced DFIR upload verification and scan loop is healthy.", m.dfirScanReady.Load())
	writeGauge("periapsis_worker_dfir_cleanup_ready", "Whether the fenced DFIR orphan cleanup loop is healthy.", m.dfirCleanupReady.Load())
	writeGauge("periapsis_worker_ldap_sync_ready", "Whether every LDAP synchronization poller is healthy.", m.ldapSyncReady.Load())
	writeGauge("periapsis_worker_sla_ready", "Whether the fenced SLA evaluation loop is healthy.", m.slaReady.Load())
	writeGauge("periapsis_worker_sla_action_ready", "Whether the fenced SLA trigger-action loop is healthy.", m.slaActionReady.Load())
	writeGauge("periapsis_worker_sla_event_ingress_ready", "Whether the ordered SLA event ingress loop is healthy.", m.slaEventReady.Load())
	writeGauge("periapsis_worker_ticket_runtime_ready", "Whether the fenced ticket bulk, export, and artifact-reconciliation runtime is healthy.", m.ticketRuntimeReady.Load())
	writeGauge("periapsis_worker_oidc_maintenance_ready", "Whether the bounded OIDC access-expiry, retention, refresh, logout-retry, and scrub runtime is healthy.", m.oidcMaintenanceReady.Load())
	writeCounterFamily(
		"periapsis_worker_auth_cleanup_total",
		"Authorization cleanup iterations by outcome.",
		counterSample{"success", m.authCleanupSuccess.Load()},
		counterSample{"failure", m.authCleanupFailure.Load()},
	)
	writeCounterFamily(
		"periapsis_worker_dfir_scan_runs_total",
		"Fenced DFIR scan iterations by bounded outcome.",
		counterSample{"success", m.dfirScanRunSuccess.Load()},
		counterSample{"failure", m.dfirScanRunFailure.Load()},
	)
	writeCounterFamily(
		"periapsis_worker_dfir_scan_objects_total",
		"Fenced DFIR scan work by bounded outcome.",
		counterSample{"claimed", m.dfirScanClaimed.Load()},
		counterSample{"available", m.dfirScanAvailable.Load()},
		counterSample{"rejected", m.dfirScanRejected.Load()},
		counterSample{"scan_failed", m.dfirScanFailed.Load()},
		counterSample{"waiting_upload", m.dfirScanWaitingUpload.Load()},
		counterSample{"upload_expired", m.dfirScanUploadExpired.Load()},
		counterSample{"retry_scheduled", m.dfirScanRetry.Load()},
		counterSample{"fence_lost", m.dfirScanFenceLost.Load()},
	)
	writeCounterFamily(
		"periapsis_worker_dfir_cleanup_runs_total",
		"Fenced DFIR orphan cleanup iterations by bounded outcome.",
		counterSample{"success", m.dfirCleanupRunSuccess.Load()},
		counterSample{"failure", m.dfirCleanupRunFailure.Load()},
	)
	writeCounterFamily(
		"periapsis_worker_dfir_cleanup_objects_total",
		"Fenced DFIR orphan cleanup work by bounded outcome.",
		counterSample{"claimed", m.dfirCleanupClaimed.Load()},
		counterSample{"deleted", m.dfirCleanupDeleted.Load()},
		counterSample{"retry_scheduled", m.dfirCleanupRetry.Load()},
	)
	writeCounterFamily(
		"periapsis_worker_ldap_sync_poll_total",
		"LDAP synchronization polls by bounded outcome.",
		counterSample{"worked", m.ldapPollWorked.Load()},
		counterSample{"empty", m.ldapPollEmpty.Load()},
		counterSample{"failure", m.ldapPollFailure.Load()},
	)
	writeCounterFamily(
		"periapsis_worker_oidc_maintenance_runs_total",
		"OIDC maintenance dispatch cycles by bounded outcome.",
		counterSample{"success", m.oidcMaintenanceRunSuccess.Load()},
		counterSample{"failure", m.oidcMaintenanceRunFailure.Load()},
	)
	writeCounterFamily(
		"periapsis_worker_oidc_maintenance_work_total",
		"OIDC maintenance work by bounded applied or submitted classification.",
		counterSample{"claimed", m.oidcMaintenanceClaimed.Load()},
		counterSample{"rotated", m.oidcMaintenanceRotated.Load()},
		counterSample{"logout_complete", m.oidcMaintenanceLogout.Load()},
		counterSample{"safe_retry_submitted", m.oidcMaintenanceRetry.Load()},
		counterSample{"local_dependency_deferred", m.oidcMaintenanceDeferred.Load()},
		counterSample{"terminal_failure_submitted", m.oidcMaintenanceDead.Load()},
		counterSample{"scrubbed", m.oidcMaintenanceScrubbed.Load()},
		counterSample{"fence_lost", m.oidcMaintenanceFenceLost.Load()},
	)
	writeCounterFamily(
		"periapsis_sla_worker_runs_total",
		"Fenced SLA evaluation loop iterations by bounded outcome.",
		counterSample{"success", m.slaRunSuccess.Load()},
		counterSample{"failure", m.slaRunFailure.Load()},
	)
	writeCounterFamily(
		"periapsis_sla_worker_jobs_total",
		"Fenced SLA evaluation jobs by bounded outcome.",
		counterSample{"claimed", m.slaJobsClaimed.Load()},
		counterSample{"completed", m.slaJobsCompleted.Load()},
		counterSample{"retryable", m.slaJobsRetryable.Load()},
		counterSample{"dead_lettered", m.slaJobsDeadLetter.Load()},
	)
	writeCounterFamily(
		"periapsis_sla_action_worker_runs_total",
		"Fenced SLA trigger-action loop iterations by bounded outcome.",
		counterSample{"success", m.slaActionRunSuccess.Load()},
		counterSample{"failure", m.slaActionRunFailure.Load()},
	)
	writeCounterFamily(
		"periapsis_sla_action_worker_actions_total",
		"Fenced SLA trigger actions by bounded outcome.",
		counterSample{"claimed", m.slaActionsClaimed.Load()},
		counterSample{"applied", m.slaActionsApplied.Load()},
		counterSample{"replayed", m.slaActionsReplayed.Load()},
		counterSample{"retry_scheduled", m.slaActionsRetry.Load()},
		counterSample{"dead_lettered", m.slaActionsDead.Load()},
		counterSample{"fence_lost", m.slaActionsFenceLost.Load()},
	)
	writeCounterFamily(
		"periapsis_sla_event_ingress_worker_runs_total",
		"Ordered SLA event ingress loop iterations by bounded outcome.",
		counterSample{"success", m.slaEventRunSuccess.Load()},
		counterSample{"failure", m.slaEventRunFailure.Load()},
	)
	writeCounterFamily(
		"periapsis_sla_event_ingress_worker_events_total",
		"Ordered SLA ingress events by bounded outcome.",
		counterSample{"claimed", m.slaEventsClaimed.Load()},
		counterSample{"applied", m.slaEventsApplied.Load()},
		counterSample{"replayed", m.slaEventsReplayed.Load()},
		counterSample{"retry_scheduled", m.slaEventsRetry.Load()},
		counterSample{"dead_lettered", m.slaEventsDead.Load()},
		counterSample{"fence_lost", m.slaEventsFenceLost.Load()},
	)
	writeCounterFamily(
		"periapsis_ticket_bulk_worker_runs_total",
		"Fenced ticket bulk worker iterations by bounded outcome.",
		counterSample{"worked", m.ticketBulkWorked.Load()},
		counterSample{"empty", m.ticketBulkIdle.Load()},
		counterSample{"failure", m.ticketBulkFailure.Load()},
	)
	writeCounterFamily(
		"periapsis_ticket_export_worker_runs_total",
		"Fenced ticket export worker iterations by bounded outcome.",
		counterSample{"worked", m.ticketExportWorked.Load()},
		counterSample{"empty", m.ticketExportIdle.Load()},
		counterSample{"failure", m.ticketExportFailure.Load()},
	)
	writeCounterFamily(
		"periapsis_ticket_export_reconcile_worker_runs_total",
		"Fenced ticket export artifact reconciliation iterations by bounded outcome.",
		counterSample{"success", m.ticketReconcileRunSuccess.Load()},
		counterSample{"failure", m.ticketReconcileRunFailure.Load()},
	)
	writeCounterFamily(
		"periapsis_ticket_export_reconcile_artifacts_total",
		"Fenced ticket export artifact reconciliation work by bounded outcome.",
		counterSample{"claimed", m.ticketReconcileClaimed.Load()},
		counterSample{"purged", m.ticketReconcilePurged.Load()},
		counterSample{"replayed", m.ticketReconcileReplayed.Load()},
		counterSample{"retry_scheduled", m.ticketReconcileRetry.Load()},
		counterSample{"dead_lettered", m.ticketReconcileDead.Load()},
		counterSample{"fence_lost", m.ticketReconcileFenceLost.Load()},
	)
	if queue := m.slaQueue.Load(); queue != nil {
		writeGauge(
			"periapsis_sla_queue_pending_jobs",
			"Number of SLA evaluation jobs currently eligible to be claimed or reclaimed.",
			int64(queue.pendingJobs),
		)
		output.WriteString("# HELP periapsis_sla_queue_oldest_pending_seconds Age of the oldest SLA evaluation job currently eligible to be claimed or reclaimed.\n")
		output.WriteString("# TYPE periapsis_sla_queue_oldest_pending_seconds gauge\n")
		fmt.Fprintf(
			&output,
			"periapsis_sla_queue_oldest_pending_seconds %.6f\n",
			float64(queue.oldestPendingMicros)/float64(time.Second/time.Microsecond),
		)
	}
	if queue := m.slaActionQueue.Load(); queue != nil {
		writeGauge(
			"periapsis_sla_action_queue_pending_actions",
			"Number of SLA trigger actions currently eligible to be claimed or reclaimed.",
			int64(queue.pendingJobs),
		)
		output.WriteString("# HELP periapsis_sla_action_queue_oldest_pending_seconds Age of the oldest SLA trigger action currently eligible to be claimed or reclaimed.\n")
		output.WriteString("# TYPE periapsis_sla_action_queue_oldest_pending_seconds gauge\n")
		fmt.Fprintf(
			&output,
			"periapsis_sla_action_queue_oldest_pending_seconds %.6f\n",
			float64(queue.oldestPendingMicros)/float64(time.Second/time.Microsecond),
		)
	}
	if queue := m.slaEventQueue.Load(); queue != nil {
		writeGauge(
			"periapsis_sla_event_ingress_queue_pending_events",
			"Number of ordered SLA ingress events currently pending.",
			int64(queue.pendingEvents),
		)
		writeGauge(
			"periapsis_sla_event_ingress_queue_reclaimable_events",
			"Number of ordered SLA ingress claims whose leases have expired.",
			int64(queue.reclaimableEvents),
		)
		writeGauge(
			"periapsis_sla_event_ingress_queue_dead_lettered_events",
			"Number of ordered SLA ingress events awaiting operator intervention.",
			int64(queue.deadLetteredEvents),
		)
		output.WriteString("# HELP periapsis_sla_event_ingress_queue_oldest_pending_seconds Age of the oldest SLA ingress event eligible to run.\n")
		output.WriteString("# TYPE periapsis_sla_event_ingress_queue_oldest_pending_seconds gauge\n")
		fmt.Fprintf(
			&output,
			"periapsis_sla_event_ingress_queue_oldest_pending_seconds %.6f\n",
			float64(queue.oldestPendingMicros)/float64(time.Second/time.Microsecond),
		)
	}
	if queue := m.ticketReconcileQueue.Load(); queue != nil {
		writeGauge(
			"periapsis_ticket_export_reconcile_queue_pending_eligible",
			"Number of ticket export artifacts currently eligible for reconciliation.",
			int64(queue.pendingEligible),
		)
		writeGauge(
			"periapsis_ticket_export_reconcile_queue_reclaimable",
			"Number of ticket export artifact reconciliation claims whose leases have expired.",
			int64(queue.reclaimable),
		)
		writeGauge(
			"periapsis_ticket_export_reconcile_queue_dead_lettered",
			"Number of ticket export artifact reconciliation records awaiting operator intervention.",
			int64(queue.deadLettered),
		)
		output.WriteString("# HELP periapsis_ticket_export_reconcile_queue_oldest_pending_seconds Age of the oldest ticket export artifact eligible for reconciliation.\n")
		output.WriteString("# TYPE periapsis_ticket_export_reconcile_queue_oldest_pending_seconds gauge\n")
		fmt.Fprintf(
			&output,
			"periapsis_ticket_export_reconcile_queue_oldest_pending_seconds %.6f\n",
			float64(queue.oldestPendingMicros)/float64(time.Second/time.Microsecond),
		)
	}
	if queue := m.oidcMaintenanceQueue.Load(); queue != nil {
		output.WriteString("# HELP periapsis_worker_oidc_maintenance_queue_due Number of OIDC maintenance items eligible to be claimed or reclaimed at the database observation time.\n")
		output.WriteString("# TYPE periapsis_worker_oidc_maintenance_queue_due gauge\n")
		fmt.Fprintf(&output, "periapsis_worker_oidc_maintenance_queue_due{kind=\"logout_retry\"} %d\n", queue.logoutDue)
		fmt.Fprintf(&output, "periapsis_worker_oidc_maintenance_queue_due{kind=\"refresh\"} %d\n", queue.refreshDue)
		fmt.Fprintf(&output, "periapsis_worker_oidc_maintenance_queue_due{kind=\"scrub\"} %d\n", queue.scrubDue)
		output.WriteString("# HELP periapsis_worker_oidc_maintenance_queue_reclaimable Number of expired OIDC maintenance claims eligible for fenced reclaim.\n")
		output.WriteString("# TYPE periapsis_worker_oidc_maintenance_queue_reclaimable gauge\n")
		fmt.Fprintf(&output, "periapsis_worker_oidc_maintenance_queue_reclaimable{kind=\"logout_retry\"} %d\n", queue.logoutReclaimable)
		fmt.Fprintf(&output, "periapsis_worker_oidc_maintenance_queue_reclaimable{kind=\"refresh\"} %d\n", queue.refreshReclaimable)
		output.WriteString("# HELP periapsis_worker_oidc_maintenance_queue_dead_lettered Number of OIDC logout retries awaiting operator intervention.\n")
		output.WriteString("# TYPE periapsis_worker_oidc_maintenance_queue_dead_lettered gauge\n")
		fmt.Fprintf(&output, "periapsis_worker_oidc_maintenance_queue_dead_lettered{kind=\"logout_retry\"} %d\n", queue.logoutDeadLettered)
		output.WriteString("# HELP periapsis_worker_oidc_maintenance_queue_oldest_due_seconds Age of the oldest OIDC maintenance item eligible to run, derived only from database time.\n")
		output.WriteString("# TYPE periapsis_worker_oidc_maintenance_queue_oldest_due_seconds gauge\n")
		fmt.Fprintf(&output, "periapsis_worker_oidc_maintenance_queue_oldest_due_seconds{kind=\"logout_retry\"} %.6f\n", float64(queue.logoutOldestMicros)/float64(time.Second/time.Microsecond))
		fmt.Fprintf(&output, "periapsis_worker_oidc_maintenance_queue_oldest_due_seconds{kind=\"refresh\"} %.6f\n", float64(queue.refreshOldestMicros)/float64(time.Second/time.Microsecond))
		fmt.Fprintf(&output, "periapsis_worker_oidc_maintenance_queue_oldest_due_seconds{kind=\"scrub\"} %.6f\n", float64(queue.scrubOldestMicros)/float64(time.Second/time.Microsecond))
	}
	output.WriteString("# HELP periapsis_worker_ldap_sync_poll_duration_seconds LDAP synchronization poll duration without customer labels.\n")
	output.WriteString("# TYPE periapsis_worker_ldap_sync_poll_duration_seconds summary\n")
	fmt.Fprintf(&output, "periapsis_worker_ldap_sync_poll_duration_seconds_count %d\n", m.ldapPollCount.Load())
	fmt.Fprintf(&output, "periapsis_worker_ldap_sync_poll_duration_seconds_sum %.9f\n", float64(m.ldapPollNanos.Load())/float64(time.Second))
	return output.String()
}

func storeGauge(target *atomic.Int64, value bool) {
	if target == nil {
		return
	}
	if value {
		target.Store(1)
		return
	}
	target.Store(0)
}

func validMetricInstant(value time.Time) bool {
	if value.IsZero() || value.Year() < 2000 || value.Year() > 9999 || value.Nanosecond()%1000 != 0 {
		return false
	}
	_, offset := value.Zone()
	return offset == 0
}

func validMetricOutcome(value string) bool {
	switch value {
	case "success", "failure", "worked", "empty", "claimed", "completed", "purged", "retryable", "dead_lettered",
		"applied", "replayed", "retry_scheduled", "safe_retry_submitted", "local_dependency_deferred",
		"terminal_failure_submitted", "fence_lost", "rotated", "logout_complete", "scrubbed",
		"available", "rejected", "scan_failed", "waiting_upload", "upload_expired", "deleted":
		return true
	default:
		return false
	}
}

var errMetricInvariant = errors.New("worker metric invariant failed")

// Validate verifies invariants that could otherwise result in contradictory
// process telemetry. It is intended for readiness diagnostics and tests.
func (m *Metrics) Validate() error {
	if m == nil {
		return errMetricInvariant
	}
	classified := m.ldapPollWorked.Load() + m.ldapPollEmpty.Load() + m.ldapPollFailure.Load()
	if classified != m.ldapPollCount.Load() {
		return errMetricInvariant
	}
	classifiedDFIRScan := m.dfirScanAvailable.Load() + m.dfirScanRejected.Load() +
		m.dfirScanFailed.Load() + m.dfirScanWaitingUpload.Load() + m.dfirScanUploadExpired.Load() +
		m.dfirScanRetry.Load() + m.dfirScanFenceLost.Load()
	if classifiedDFIRScan > m.dfirScanClaimed.Load() ||
		m.dfirCleanupDeleted.Load()+m.dfirCleanupRetry.Load() > m.dfirCleanupClaimed.Load() {
		return errMetricInvariant
	}
	classifiedSLA := m.slaJobsCompleted.Load() + m.slaJobsRetryable.Load() + m.slaJobsDeadLetter.Load()
	if classifiedSLA > m.slaJobsClaimed.Load() {
		return errMetricInvariant
	}
	classifiedActions := m.slaActionsApplied.Load() + m.slaActionsReplayed.Load() +
		m.slaActionsRetry.Load() + m.slaActionsDead.Load() + m.slaActionsFenceLost.Load()
	if classifiedActions > m.slaActionsClaimed.Load() {
		return errMetricInvariant
	}
	classifiedEvents := m.slaEventsApplied.Load() + m.slaEventsReplayed.Load() +
		m.slaEventsRetry.Load() + m.slaEventsDead.Load() + m.slaEventsFenceLost.Load()
	if classifiedEvents > m.slaEventsClaimed.Load() {
		return errMetricInvariant
	}
	classifiedReconciliation := m.ticketReconcilePurged.Load() + m.ticketReconcileReplayed.Load() +
		m.ticketReconcileRetry.Load() + m.ticketReconcileDead.Load() + m.ticketReconcileFenceLost.Load()
	if classifiedReconciliation > m.ticketReconcileClaimed.Load() {
		return errMetricInvariant
	}
	classifiedOIDC := m.oidcMaintenanceRotated.Load() + m.oidcMaintenanceLogout.Load() +
		m.oidcMaintenanceRetry.Load() + m.oidcMaintenanceDeferred.Load() + m.oidcMaintenanceDead.Load() +
		m.oidcMaintenanceScrubbed.Load() + m.oidcMaintenanceFenceLost.Load()
	if classifiedOIDC > m.oidcMaintenanceClaimed.Load() {
		return errMetricInvariant
	}
	if queue := m.oidcMaintenanceQueue.Load(); queue != nil {
		if queue.logoutReclaimable > queue.logoutDue || queue.refreshReclaimable > queue.refreshDue {
			return errMetricInvariant
		}
		for _, count := range []uint64{
			queue.logoutDue, queue.logoutReclaimable, queue.logoutDeadLettered,
			queue.refreshDue, queue.refreshReclaimable, queue.scrubDue,
		} {
			if count > oidcmaintenance.MaximumPersistentCount {
				return errMetricInvariant
			}
		}
	}
	if queue := m.slaQueue.Load(); queue != nil && queue.pendingJobs == 0 && queue.oldestPendingMicros != 0 {
		return errMetricInvariant
	}
	if queue := m.slaActionQueue.Load(); queue != nil && queue.pendingJobs == 0 && queue.oldestPendingMicros != 0 {
		return errMetricInvariant
	}
	if queue := m.slaEventQueue.Load(); queue != nil && queue.pendingEvents == 0 &&
		queue.reclaimableEvents == 0 && queue.oldestPendingMicros != 0 {
		return errMetricInvariant
	}
	if queue := m.ticketReconcileQueue.Load(); queue != nil &&
		queue.pendingEligible == 0 && queue.reclaimable == 0 && queue.oldestPendingMicros != 0 {
		return errMetricInvariant
	}
	return nil
}
