package oidcmaintenance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"math"
	"reflect"
	"sync"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
)

const (
	oidcSessionNonceBytes      = 12
	minimumProtectedTokenBytes = oidcSessionNonceBytes + 1 + 16
	maximumProtectedTokenBytes = oidcSessionNonceBytes + 256*1024 + 16
	maximumRefreshTokenBytes   = 256 * 1024
	maximumTerminalWrite       = 5 * time.Second
	terminalSchedulingMargin   = 100 * time.Millisecond
	cycleDeadlineBoundary      = time.Microsecond
	minimumReadinessHeartbeat  = time.Second
	maximumReadinessHeartbeat  = 5 * time.Second
	cycleDatabasePhaseCount    = 2
)

type Worker struct {
	repository         Repository
	keyring            identity.Keyring
	upstream           Upstream
	batchSize          int
	databaseTimeout    time.Duration
	operationTimeout   time.Duration
	leaseSafety        time.Duration
	dispatchTimeout    time.Duration
	pollInterval       time.Duration
	clock              func() time.Time
	logger             *slog.Logger
	observer           Observer
	tracer             OperationTracer
	readinessHeartbeat time.Duration

	mu       sync.Mutex
	nextKind int
}

func New(options Options) (*Worker, error) {
	if nilInterface(options.Repository) || options.Keyring.ActiveVersion() < 1 ||
		nilInterface(options.Upstream) || options.BatchSize < len(orderedKinds) ||
		options.BatchSize > MaximumBatchSize ||
		options.DatabaseTimeout < MinimumDatabaseTimeout || options.DatabaseTimeout > MaximumDatabaseTimeout ||
		options.DatabaseTimeout%time.Microsecond != 0 ||
		options.OperationTimeout < MinimumOperation || options.OperationTimeout > MaximumOperation ||
		options.OperationTimeout%time.Microsecond != 0 ||
		options.LeaseSafety < MinimumLeaseSafety || options.LeaseSafety > MaximumLeaseSafety ||
		options.LeaseSafety%time.Microsecond != 0 || options.PollInterval < 100*time.Millisecond ||
		options.PollInterval > time.Minute || options.PollInterval%time.Microsecond != 0 ||
		options.DatabaseTimeout+options.OperationTimeout+options.LeaseSafety+
			MinimumLeaseSchedulingMargin > NominalLeaseDuration ||
		options.Clock == nil || options.Logger == nil {
		return nil, ErrInvalidConfiguration
	}
	return &Worker{
		repository: options.Repository, keyring: options.Keyring, upstream: options.Upstream,
		batchSize: options.BatchSize, databaseTimeout: options.DatabaseTimeout,
		operationTimeout: options.OperationTimeout,
		leaseSafety:      options.LeaseSafety,
		dispatchTimeout: dispatchCycleTimeout(
			options.BatchSize, options.DatabaseTimeout, options.OperationTimeout,
		),
		pollInterval: options.PollInterval,
		clock:        options.Clock, logger: options.Logger, observer: options.Observer, tracer: options.Tracer,
		readinessHeartbeat: min(max(options.PollInterval, minimumReadinessHeartbeat), maximumReadinessHeartbeat),
	}, nil
}

func (worker *Worker) String() string {
	return "oidcmaintenance.Worker{dependencies:[REDACTED],configuration:[REDACTED]}"
}
func (worker *Worker) GoString() string { return worker.String() }

// Run publishes initial readiness as soon as the trusted database ABI is
// available. An independent heartbeat keeps dependency readiness fresh while
// a valid, bounded upstream operation is in flight; dispatch failures remain
// latched until a complete healthy cycle succeeds. A canceled in-flight
// network request receives one bounded, cancellation-independent terminal
// write before shutdown completes.
func (worker *Worker) Run(ctx context.Context, reportReadiness func(bool)) {
	if worker == nil || ctx == nil || ctx.Err() != nil {
		if reportReadiness != nil {
			reportReadiness(false)
		}
		return
	}

	var readinessMu sync.Mutex
	databaseHealthy, dispatchHealthy := false, true
	publishReadiness := func() {
		worker.reportReady(databaseHealthy && dispatchHealthy, reportReadiness)
	}
	setDatabaseHealthy := func(value bool) {
		readinessMu.Lock()
		databaseHealthy = value
		publishReadiness()
		readinessMu.Unlock()
	}
	setDispatchHealthy := func(value bool) {
		readinessMu.Lock()
		dispatchHealthy = value
		publishReadiness()
		readinessMu.Unlock()
	}
	isDatabaseHealthy := func() bool {
		readinessMu.Lock()
		defer readinessMu.Unlock()
		return databaseHealthy
	}
	checkDatabase := func(parent context.Context) bool {
		readyContext, cancelReady := context.WithTimeout(parent, worker.databaseTimeout)
		readyErr := worker.repository.Ready(readyContext)
		cancelReady()
		healthy := readyErr == nil && parent.Err() == nil && ctx.Err() == nil
		if healthy {
			snapshotContext, cancelSnapshot := context.WithTimeout(parent, worker.databaseTimeout)
			snapshot, snapshotErr := worker.repository.QueueSnapshot(snapshotContext)
			cancelSnapshot()
			healthy = snapshotErr == nil && parent.Err() == nil && ctx.Err() == nil &&
				validQueueSnapshot(snapshot)
			if healthy && worker.observer != nil {
				healthy = worker.observer.SetOIDCMaintenanceQueueObservation(snapshot)
			}
		}
		if !healthy && worker.observer != nil {
			worker.observer.ClearOIDCMaintenanceQueueObservation()
		}
		if !healthy && parent.Err() == nil && ctx.Err() == nil {
			worker.logger.Warn("OIDC maintenance readiness failed", "failure", "database_abi_unavailable")
		}
		return healthy
	}

	setDatabaseHealthy(checkDatabase(ctx))
	monitorContext, cancelMonitor := context.WithCancel(ctx)
	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		ticker := time.NewTicker(worker.readinessHeartbeat)
		defer ticker.Stop()
		for {
			select {
			case <-monitorContext.Done():
				return
			case <-ticker.C:
				setDatabaseHealthy(checkDatabase(monitorContext))
			}
		}
	}()
	defer func() {
		cancelMonitor()
		<-monitorDone
		if worker.observer != nil {
			worker.observer.ClearOIDCMaintenanceQueueObservation()
		}
		readinessMu.Lock()
		databaseHealthy, dispatchHealthy = false, false
		publishReadiness()
		readinessMu.Unlock()
	}()

	runCycle := func() {
		summary, runErr := worker.runBoundedCycle(ctx)
		if worker.observer != nil {
			worker.observer.ObserveOIDCMaintenanceRun(summary, runErr)
		}
		healthy := runErr == nil && ctx.Err() == nil
		setDispatchHealthy(healthy)
		if runErr != nil && ctx.Err() == nil {
			worker.logger.Warn("OIDC maintenance cycle failed", "failure", classifyFailure(runErr))
		} else if summary.DidWork() {
			worker.logger.Info(
				"OIDC maintenance cycle completed",
				"claimed", summary.Claimed,
				"refresh_rotated", summary.RefreshRotated,
				"logout_complete", summary.LogoutComplete,
				"safe_retry_submitted", summary.RetryScheduled,
				"local_dependency_deferred", summary.LocalDeferred,
				"terminal_failure_submitted", summary.DeadLettered,
				"scrubbed", summary.Scrubbed,
				"fence_lost", summary.FenceLost,
			)
		}
	}

	for {
		if isDatabaseHealthy() {
			runCycle()
		}
		timer := time.NewTimer(worker.pollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		case <-timer.C:
		}
	}
}

func (worker *Worker) reportReady(value bool, callback func(bool)) {
	if callback != nil {
		callback(value)
	}
	if worker.observer != nil {
		worker.observer.SetOIDCMaintenanceReady(value)
	}
}

// RunOnce executes access expiry and the three retention categories once,
// then advances through logout_retry, refresh, and scrub in order. It issues
// at most BatchSize claims and never reclaims a returned snapshot.
func (worker *Worker) RunOnce(ctx context.Context) (Summary, error) {
	return worker.runOnce(ctx, false)
}

func (worker *Worker) runBoundedCycle(ctx context.Context) (Summary, error) {
	if worker == nil || ctx == nil {
		return Summary{}, ErrInvalidInput
	}
	if !contextHasFullCycleClaimBudget(ctx, worker.databaseTimeout, worker.operationTimeout) {
		return Summary{}, ErrInterrupted
	}
	dispatchContext, cancelDispatch := context.WithTimeout(ctx, worker.dispatchTimeout)
	summary, runErr := worker.runOnce(dispatchContext, true)
	dispatchErr := dispatchContext.Err()
	cancelDispatch()
	if runErr == nil && dispatchErr != nil {
		return summary, ErrInterrupted
	}
	return summary, runErr
}

func (worker *Worker) runOnce(ctx context.Context, enforceCycleBudget bool) (Summary, error) {
	if worker == nil || ctx == nil {
		return Summary{}, ErrInvalidInput
	}
	if ctx.Err() != nil {
		return Summary{}, ErrInterrupted
	}
	summary := Summary{}
	if err := worker.runDatabasePhase(
		ctx, "oidc.maintenance.expire_access_lease", worker.repository.ExpireAccessLease,
	); err != nil {
		return summary, err
	}
	if err := worker.runDatabasePhase(
		ctx, "oidc.maintenance.cleanup_retention", worker.repository.CleanupFederatedRetention,
	); err != nil {
		return summary, err
	}
	for summary.Dispatches < worker.batchSize {
		if ctx.Err() != nil {
			return summary, ErrInterrupted
		}
		// runBoundedCycle constructs the first full-work reservation. Before
		// every additional claim, stop normally unless another worst-case
		// database read and operation still fit. RunOnce intentionally retains
		// its caller-owned batch semantics.
		if enforceCycleBudget &&
			!contextHasFullCycleClaimBudget(ctx, worker.databaseTimeout, worker.operationTimeout) {
			return summary, nil
		}
		kind := worker.takeNextKind()
		observedAt := worker.now()
		if !validInstant(observedAt) {
			return summary, ErrInvalidConfiguration
		}
		claimContext, cancelClaim := context.WithTimeout(ctx, worker.databaseTimeout)
		claimContext, finishClaim := worker.trace(claimContext, "oidc.maintenance.claim."+string(kind))
		claimStarted := time.Now()
		work, err := worker.repository.ClaimDue(claimContext, kind, observedAt)
		finishClaim(err)
		cancelClaim()
		summary.Dispatches++
		if err != nil {
			if errors.Is(err, ErrInvalidProjection) {
				return summary, ErrInvalidProjection
			}
			if ctx.Err() != nil {
				return summary, errors.Join(ErrOutcomeUnknown, ErrInterrupted)
			}
			return summary, errors.Join(ErrOutcomeUnknown, ErrUnavailable)
		}
		if work == nil {
			continue
		}
		if work.Kind != kind || !validWorkShape(*work) {
			clearWork(work)
			return summary, ErrInvalidProjection
		}
		summary.Claimed++
		processErr := worker.process(ctx, work, claimStarted, &summary)
		clearWork(work)
		if processErr != nil {
			return summary, processErr
		}
	}
	return summary, nil
}

func (worker *Worker) runDatabasePhase(
	ctx context.Context,
	operation string,
	run func(context.Context, time.Time) error,
) error {
	if ctx.Err() != nil {
		return ErrInterrupted
	}
	observedAt := worker.now()
	if !validInstant(observedAt) {
		return ErrInvalidConfiguration
	}
	phaseContext, cancelPhase := context.WithTimeout(ctx, worker.databaseTimeout)
	phaseContext, finishPhase := worker.trace(phaseContext, operation)
	err := run(phaseContext, observedAt)
	phaseErr := phaseContext.Err()
	if err == nil {
		err = phaseErr
	}
	finishPhase(err)
	cancelPhase()
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrInvalidProjection) {
		return ErrInvalidProjection
	}
	if ctx.Err() != nil {
		return errors.Join(ErrOutcomeUnknown, ErrInterrupted)
	}
	return errors.Join(ErrOutcomeUnknown, ErrUnavailable)
}

func (worker *Worker) process(ctx context.Context, work *Work, claimStarted time.Time, summary *Summary) error {
	switch work.Kind {
	case KindRefresh:
		return worker.processRefresh(ctx, *work.Refresh, work.ObservedAt, claimStarted, summary)
	case KindLogoutRetry:
		return worker.processLogout(ctx, *work.LogoutRetry, work.ObservedAt, claimStarted, summary)
	case KindScrub:
		summary.Scrubbed++
		return nil
	default:
		return ErrInvalidProjection
	}
}

func (worker *Worker) processRefresh(
	ctx context.Context,
	claim RefreshClaim,
	observedAt time.Time,
	claimStarted time.Time,
	summary *Summary,
) error {
	claimElapsed := time.Since(claimStarted)
	if !validRefreshClaim(claim, observedAt) || claimElapsed < 0 {
		return ErrInvalidProjection
	}
	now := databaseOperationalTime(observedAt, claimElapsed)
	if !validInstant(now) || now.Before(observedAt) {
		return worker.completeRefresh(ctx, claim, RefreshLocalUnavailable, nil, observedAt, summary)
	}
	if !hasFullRelativeOperationBudget(
		claim.LeaseExpiresAt.Sub(observedAt)-claimElapsed,
		worker.operationTimeout,
		worker.leaseSafety,
	) {
		return worker.completeRefresh(ctx, claim, RefreshLocalUnavailable, nil, now, summary)
	}
	operation, cancel, ok := operationContextWithFullParentBudget(ctx, worker.operationTimeout)
	if !ok {
		return worker.completeRefresh(ctx, claim, RefreshLocalUnavailable, nil, now, summary)
	}
	operation, finish := worker.trace(operation, "oidc.maintenance.refresh")
	outcome, rotated := worker.executeRefresh(operation, claim, now)
	finish(refreshTraceError(outcome, operation.Err()))
	cancel()
	completedAt := databaseOperationalTime(observedAt, time.Since(claimStarted))
	if !validInstant(completedAt) || completedAt.Before(now) {
		completedAt = now
	}
	if outcome == RefreshRotated && (rotated == nil || !rotated.expiresAt.After(completedAt)) {
		if rotated != nil {
			rotated.Destroy()
		}
		rotated = nil
		outcome = RefreshAmbiguous
	}
	if !completedAt.Before(claim.LeaseExpiresAt) &&
		(outcome == RefreshRotated || outcome == RefreshSafeToRetry) {
		if rotated != nil {
			rotated.Destroy()
		}
		rotated = nil
		outcome = RefreshAmbiguous
	}
	return worker.completeRefresh(ctx, claim, outcome, rotated, completedAt, summary)
}

type refreshRotation struct {
	token     []byte
	digest    [sha256.Size]byte
	protected ProtectedToken
	expiresAt time.Time
}

func (rotation *refreshRotation) Destroy() {
	if rotation == nil {
		return
	}
	clear(rotation.token)
	clear(rotation.protected.Ciphertext)
	*rotation = refreshRotation{}
}

func (worker *Worker) executeRefresh(
	ctx context.Context,
	claim RefreshClaim,
	now time.Time,
) (RefreshOutcome, *refreshRotation) {
	token, err := worker.openRefreshToken(ctx, claim.Provider, claim.TenantID, claim.BindingID,
		claim.MaterialID, claim.Token)
	if err != nil || !validRefreshToken(token) {
		clear(token)
		if errors.Is(err, ErrUnavailable) || errors.Is(err, ErrInterrupted) {
			return RefreshLocalUnavailable, nil
		}
		return RefreshRejected, nil
	}
	defer clear(token)
	digest := sha256.Sum256(token)
	if subtle.ConstantTimeCompare(digest[:], claim.TokenDigest[:]) != 1 {
		return RefreshRejected, nil
	}
	secret, err := worker.openClientSecret(ctx, refreshSecretLookup(claim))
	if err != nil || len(secret) == 0 {
		clear(secret)
		if errors.Is(err, ErrUnavailable) || errors.Is(err, ErrInterrupted) {
			return RefreshLocalUnavailable, nil
		}
		return RefreshRejected, nil
	}
	defer clear(secret)
	result, err := worker.upstream.Refresh(ctx, federatedoidc.StoredRefreshExchangeRequest{
		EndpointURL: claim.Endpoint, ClientAuthentication: claim.ClientAuthentication,
		ClientID: claim.ClientID, ClientSecret: append([]byte(nil), secret...),
		RefreshToken: append([]byte(nil), token...),
	}, now)
	defer result.Destroy()
	if err != nil {
		if errors.Is(err, federatedoidc.ErrRefreshSafeToRetry) {
			if ctx.Err() != nil {
				return RefreshLocalUnavailable, nil
			}
			return RefreshSafeToRetry, nil
		}
		return RefreshAmbiguous, nil
	}
	successor := append([]byte(nil), result.RefreshToken...)
	expiresAt := result.AccessExpiresAt
	if !validRefreshToken(successor) || bytes.Equal(successor, token) ||
		!validInstant(expiresAt) || !expiresAt.After(now) ||
		claim.Generation+1 >= MaximumPersistentCount {
		clear(successor)
		return RefreshAmbiguous, nil
	}
	if expiresAt.After(claim.MaterialExpiresAt) {
		expiresAt = claim.MaterialExpiresAt
	}
	if expiresAt.After(claim.AbsoluteSessionExpiry) {
		expiresAt = claim.AbsoluteSessionExpiry
	}
	if !expiresAt.After(now) {
		clear(successor)
		return RefreshAmbiguous, nil
	}
	protected, err := worker.sealRefreshToken(
		ctx, claim.Provider, claim.TenantID, claim.BindingID, claim.MaterialID, successor,
	)
	if err != nil {
		clear(successor)
		clear(protected.Ciphertext)
		return RefreshAmbiguous, nil
	}
	return RefreshRotated, &refreshRotation{
		token: successor, digest: sha256.Sum256(successor), protected: protected, expiresAt: expiresAt,
	}
}

func (worker *Worker) completeRefresh(
	ctx context.Context,
	claim RefreshClaim,
	outcome RefreshOutcome,
	rotation *refreshRotation,
	completedAt time.Time,
	summary *Summary,
) error {
	completion := RefreshCompletion{
		TenantID: claim.TenantID, EffectiveTenantID: claim.EffectiveTenantID,
		MaterialID:      claim.MaterialID,
		SessionFamilyID: claim.SessionFamilyID, ExpectedVersion: claim.Version,
		ExpectedGeneration: claim.Generation, Outcome: outcome, CompletedAt: completedAt,
	}
	if rotation != nil {
		defer rotation.Destroy()
		completion.SuccessorGeneration = claim.Generation + 1
		completion.SuccessorDigest = rotation.digest
		completion.SuccessorToken = ProtectedToken{
			KeyVersion: rotation.protected.KeyVersion,
			Ciphertext: append([]byte(nil), rotation.protected.Ciphertext...),
		}
		completion.AccessExpiresAt = rotation.expiresAt
		defer clear(completion.SuccessorToken.Ciphertext)
	}
	if !validRefreshCompletion(completion, claim) {
		return ErrInvalidProjection
	}
	terminal, cancel := worker.terminalContext(ctx)
	terminal, finish := worker.trace(terminal, "oidc.maintenance.refresh.complete")
	applied, err := worker.repository.CompleteRefresh(terminal, completion)
	finish(err)
	cancel()
	if err != nil {
		return errors.Join(ErrOutcomeUnknown, ErrUnavailable)
	}
	if !applied {
		summary.FenceLost++
		return nil
	}
	switch outcome {
	case RefreshRotated:
		summary.RefreshRotated++
	case RefreshSafeToRetry:
		summary.RetryScheduled++
	case RefreshLocalUnavailable:
		summary.LocalDeferred++
		if ctx.Err() != nil {
			return errors.Join(ErrUnavailable, ErrInterrupted)
		}
		return ErrUnavailable
	case RefreshAmbiguous, RefreshRejected:
		summary.DeadLettered++
	}
	return nil
}

func (worker *Worker) processLogout(
	ctx context.Context,
	claim LogoutRetryClaim,
	observedAt time.Time,
	claimStarted time.Time,
	summary *Summary,
) error {
	claimElapsed := time.Since(claimStarted)
	if !validLogoutClaim(claim, observedAt) || claimElapsed < 0 {
		return ErrInvalidProjection
	}
	now := databaseOperationalTime(observedAt, claimElapsed)
	if !validInstant(now) || now.Before(observedAt) {
		return worker.completeLogout(ctx, claim, LogoutLocalUnavailable, observedAt, summary)
	}
	outcome := LogoutLocalUnavailable
	if hasFullRelativeOperationBudget(
		claim.LeaseExpiresAt.Sub(observedAt)-claimElapsed,
		worker.operationTimeout,
		worker.leaseSafety,
	) {
		operation, cancel, ok := operationContextWithFullParentBudget(ctx, worker.operationTimeout)
		if ok {
			operation, finish := worker.trace(operation, "oidc.maintenance.logout_retry")
			outcome = worker.executeLogout(operation, claim)
			finish(logoutTraceError(outcome, operation.Err()))
			cancel()
		}
	}
	completedAt := databaseOperationalTime(observedAt, time.Since(claimStarted))
	if !validInstant(completedAt) || completedAt.Before(now) {
		completedAt = now
	}
	outcome = logoutOutcomeAtCompletion(outcome, completedAt, claim.LeaseExpiresAt)
	return worker.completeLogout(ctx, claim, outcome, completedAt, summary)
}

func logoutOutcomeAtCompletion(
	outcome LogoutOutcome,
	completedAt time.Time,
	leaseExpiresAt time.Time,
) LogoutOutcome {
	if !completedAt.Before(leaseExpiresAt) &&
		(outcome == LogoutSucceeded || outcome == LogoutSafeToRetry) {
		return LogoutAmbiguous
	}
	return outcome
}

func (worker *Worker) completeLogout(
	ctx context.Context,
	claim LogoutRetryClaim,
	outcome LogoutOutcome,
	completedAt time.Time,
	summary *Summary,
) error {
	completion := LogoutCompletion{
		JobID: claim.JobID, Attempt: claim.Attempt, ExpectedVersion: claim.ClaimVersion,
		Outcome: outcome, CompletedAt: completedAt,
	}
	if outcome == LogoutSafeToRetry && claim.Attempt < claim.MaximumAttempts {
		completion.NextTryAt = completedAt.Add(logoutBackoff(claim.Attempt))
	} else if outcome == LogoutSafeToRetry {
		completion.Outcome = LogoutRejected
	}
	if !validLogoutCompletion(completion, claim) {
		return ErrInvalidProjection
	}
	terminal, cancel := worker.terminalContext(ctx)
	terminal, finish := worker.trace(terminal, "oidc.maintenance.logout_retry.complete")
	applied, err := worker.repository.CompleteLogout(terminal, completion)
	finish(err)
	cancel()
	if err != nil {
		return errors.Join(ErrOutcomeUnknown, ErrUnavailable)
	}
	if !applied {
		summary.FenceLost++
		return nil
	}
	switch completion.Outcome {
	case LogoutSucceeded:
		summary.LogoutComplete++
	case LogoutSafeToRetry:
		summary.RetryScheduled++
	case LogoutLocalUnavailable:
		summary.LocalDeferred++
		if ctx.Err() != nil {
			return errors.Join(ErrUnavailable, ErrInterrupted)
		}
		return ErrUnavailable
	case LogoutAmbiguous, LogoutRejected:
		summary.DeadLettered++
	}
	return nil
}

func (worker *Worker) executeLogout(ctx context.Context, claim LogoutRetryClaim) LogoutOutcome {
	token, err := worker.openRefreshToken(ctx, claim.Provider, claim.TenantID, claim.BindingID,
		claim.MaterialID, claim.OpaqueReference)
	if err != nil || !validRefreshToken(token) {
		clear(token)
		if errors.Is(err, ErrUnavailable) || errors.Is(err, ErrInterrupted) {
			return LogoutLocalUnavailable
		}
		return LogoutRejected
	}
	defer clear(token)
	digest := sha256.Sum256(token)
	if subtle.ConstantTimeCompare(digest[:], claim.TokenDigest[:]) != 1 {
		return LogoutRejected
	}
	secret, err := worker.openClientSecret(ctx, logoutSecretLookup(claim))
	if err != nil || len(secret) == 0 {
		clear(secret)
		if errors.Is(err, ErrUnavailable) || errors.Is(err, ErrInterrupted) {
			return LogoutLocalUnavailable
		}
		return LogoutRejected
	}
	defer clear(secret)
	err = worker.upstream.Revoke(ctx, federatedoidc.StoredRevocationMaterial{
		EndpointURL: claim.Endpoint, TokenKind: federatedoidc.TokenRefresh,
		Token: append([]byte(nil), token...), ClientAuthentication: claim.ClientAuthentication,
		ClientID: claim.ClientID, ClientSecret: append([]byte(nil), secret...),
	})
	switch {
	case err == nil:
		return LogoutSucceeded
	case errors.Is(err, federatedoidc.ErrRevocationSafeToRetry):
		if ctx.Err() != nil {
			return LogoutLocalUnavailable
		}
		return LogoutSafeToRetry
	case errors.Is(err, federatedoidc.ErrRevocationAmbiguous):
		return LogoutAmbiguous
	default:
		return LogoutRejected
	}
}

func (worker *Worker) openRefreshToken(
	ctx context.Context,
	provider identity.ProviderContext,
	tenantID identity.EntityID,
	bindingID identity.EntityID,
	materialID identity.EntityID,
	protected ProtectedToken,
) ([]byte, error) {
	if ctx == nil {
		return nil, ErrInvalidProjection
	}
	if ctx.Err() != nil {
		return nil, ErrInterrupted
	}
	if protected.KeyVersion == 0 || protected.KeyVersion > math.MaxInt16 ||
		len(protected.Ciphertext) < minimumProtectedTokenBytes ||
		len(protected.Ciphertext) > maximumProtectedTokenBytes {
		return nil, ErrInvalidProjection
	}
	if len(worker.keyring.MissingVersions([]int16{int16(protected.KeyVersion)})) != 0 {
		return nil, ErrUnavailable
	}
	envelope := identity.OIDCSessionTokenEnvelope{KeyVersion: int16(protected.KeyVersion)}
	copy(envelope.Nonce[:], protected.Ciphertext[:oidcSessionNonceBytes])
	envelope.Ciphertext = append([]byte(nil), protected.Ciphertext[oidcSessionNonceBytes:]...)
	defer clear(envelope.Nonce[:])
	defer clear(envelope.Ciphertext)
	value, err := worker.keyring.DecryptOIDCRefreshToken(identity.OIDCSessionMaterialContext{
		Provider: provider, TenantID: tenantID, BindingID: bindingID, MaterialID: materialID,
	}, envelope)
	if ctx.Err() != nil {
		clear(value)
		return nil, ErrInterrupted
	}
	if err != nil {
		clear(value)
		return nil, ErrInvalidProjection
	}
	return value, nil
}

func (worker *Worker) sealRefreshToken(
	ctx context.Context,
	provider identity.ProviderContext,
	tenantID identity.EntityID,
	bindingID identity.EntityID,
	materialID identity.EntityID,
	value []byte,
) (ProtectedToken, error) {
	if ctx == nil || ctx.Err() != nil || !validRefreshToken(value) {
		return ProtectedToken{}, ErrUnavailable
	}
	envelope, err := worker.keyring.EncryptOIDCRefreshToken(identity.OIDCSessionMaterialContext{
		Provider: provider, TenantID: tenantID, BindingID: bindingID, MaterialID: materialID,
	}, value)
	if err != nil || ctx.Err() != nil {
		clear(envelope.Nonce[:])
		clear(envelope.Ciphertext)
		return ProtectedToken{}, ErrUnavailable
	}
	defer clear(envelope.Nonce[:])
	defer clear(envelope.Ciphertext)
	ciphertext := make([]byte, 0, len(envelope.Nonce)+len(envelope.Ciphertext))
	ciphertext = append(ciphertext, envelope.Nonce[:]...)
	ciphertext = append(ciphertext, envelope.Ciphertext...)
	return ProtectedToken{KeyVersion: uint32(envelope.KeyVersion), Ciphertext: ciphertext}, nil
}

func (worker *Worker) openClientSecret(ctx context.Context, lookup ClientSecretLookup) ([]byte, error) {
	if !validClientSecretLookup(lookup) || ctx == nil {
		return nil, ErrInvalidProjection
	}
	if ctx.Err() != nil {
		return nil, ErrInterrupted
	}
	loadContext, cancelLoad := context.WithTimeout(ctx, worker.databaseTimeout)
	snapshot, err := worker.repository.LoadClientSecret(loadContext, lookup)
	loadErr := loadContext.Err()
	cancelLoad()
	defer clear(snapshot.Envelope.Nonce[:])
	defer clear(snapshot.Envelope.Ciphertext)
	if err != nil || loadErr != nil {
		if ctx.Err() != nil {
			return nil, ErrInterrupted
		}
		if loadErr != nil {
			return nil, ErrUnavailable
		}
		if errors.Is(err, ErrInvalidInput) || errors.Is(err, ErrInvalidProjection) {
			return nil, ErrInvalidProjection
		}
		return nil, ErrUnavailable
	}
	if snapshot.Lookup != lookup || snapshot.SecretID == (identity.EntityID{}) ||
		snapshot.Envelope.KeyVersion < 1 {
		return nil, ErrInvalidProjection
	}
	if len(worker.keyring.MissingVersions([]int16{snapshot.Envelope.KeyVersion})) != 0 {
		return nil, ErrUnavailable
	}
	value, err := worker.keyring.DecryptOIDCClientSecret(identity.OIDCClientSecretContext{
		Provider: lookup.Provider, BindingID: lookup.BindingID, SecretID: snapshot.SecretID,
	}, snapshot.Envelope)
	if ctx.Err() != nil {
		clear(value)
		return nil, ErrInterrupted
	}
	if err != nil || len(value) == 0 {
		clear(value)
		return nil, ErrInvalidProjection
	}
	return value, nil
}

func refreshSecretLookup(claim RefreshClaim) ClientSecretLookup {
	lookup := ClientSecretLookup{
		Provider: claim.Provider, Revision: claim.ClientSecretRevision,
		Kind: KindRefresh, MaterialID: claim.MaterialID, SessionFamilyID: claim.SessionFamilyID,
		ClaimVersion: claim.Version, RefreshGeneration: claim.Generation,
	}
	if claim.Provider.Scope == identity.TenantProviderScope {
		lookup.BindingID = claim.BindingID
	} else {
		lookup.Admission = claim.Admission
	}
	return lookup
}

func logoutSecretLookup(claim LogoutRetryClaim) ClientSecretLookup {
	lookup := ClientSecretLookup{
		Provider: claim.Provider, Revision: claim.ClientSecretRevision,
		Kind: KindLogoutRetry, MaterialID: claim.MaterialID, SessionFamilyID: claim.SessionFamilyID,
		ClaimVersion: claim.ClaimVersion, RefreshGeneration: claim.RefreshGeneration,
		JobID: claim.JobID, Attempt: claim.Attempt,
	}
	if claim.Provider.Scope == identity.TenantProviderScope {
		lookup.BindingID = claim.BindingID
	} else {
		lookup.Admission = claim.Admission
	}
	return lookup
}

func (worker *Worker) terminalContext(parent context.Context) (context.Context, context.CancelFunc) {
	timeout := terminalWriteTimeout(worker.databaseTimeout, worker.leaseSafety)
	return context.WithTimeout(context.WithoutCancel(parent), timeout)
}

func terminalWriteTimeout(databaseTimeout, leaseSafety time.Duration) time.Duration {
	// operationDeadline already stops upstream work leaseSafety before lease
	// expiry. Keep a scheduling margin inside that reservation so the terminal
	// CAS cannot legitimately run into a concurrent reclaim.
	return min(databaseTimeout, maximumTerminalWrite, leaseSafety-terminalSchedulingMargin)
}

func (worker *Worker) trace(ctx context.Context, name string) (context.Context, func(error)) {
	if worker.tracer == nil {
		return ctx, func(error) {}
	}
	return worker.tracer.StartOperation(ctx, name)
}

func refreshTraceError(outcome RefreshOutcome, operationErr error) error {
	if operationErr != nil {
		return operationErr
	}
	switch outcome {
	case RefreshRotated:
		return nil
	case RefreshSafeToRetry:
		return errTraceRetryScheduled
	case RefreshLocalUnavailable:
		return ErrUnavailable
	case RefreshAmbiguous:
		return ErrOutcomeUnknown
	case RefreshRejected:
		return errTraceRejected
	default:
		return ErrInvalidProjection
	}
}

func logoutTraceError(outcome LogoutOutcome, operationErr error) error {
	if operationErr != nil {
		return operationErr
	}
	switch outcome {
	case LogoutSucceeded:
		return nil
	case LogoutSafeToRetry:
		return errTraceRetryScheduled
	case LogoutLocalUnavailable:
		return ErrUnavailable
	case LogoutAmbiguous:
		return ErrOutcomeUnknown
	case LogoutRejected:
		return errTraceRejected
	default:
		return ErrInvalidProjection
	}
}

func (worker *Worker) takeNextKind() Kind {
	worker.mu.Lock()
	kind := orderedKinds[worker.nextKind]
	worker.nextKind = (worker.nextKind + 1) % len(orderedKinds)
	worker.mu.Unlock()
	return kind
}

func (worker *Worker) now() time.Time {
	worker.mu.Lock()
	value := worker.clock().UTC().Truncate(time.Microsecond)
	worker.mu.Unlock()
	return value
}

func databaseOperationalTime(observedAt time.Time, elapsed time.Duration) time.Time {
	if elapsed < 0 {
		return time.Time{}
	}
	return observedAt.Add(elapsed).UTC().Truncate(time.Microsecond)
}

func hasFullRelativeOperationBudget(remaining, operation, safety time.Duration) bool {
	return remaining >= operation+safety+MinimumLeaseSchedulingMargin
}

func fullCycleClaimBudget(database, operation time.Duration) time.Duration {
	return database + operation + MinimumLeaseSchedulingMargin
}

func dispatchCycleTimeout(batchSize int, database, operation time.Duration) time.Duration {
	horizon := time.Duration(cycleDatabasePhaseCount)*database +
		time.Duration(batchSize)*fullCycleClaimBudget(database, operation)
	if horizon >= NominalLeaseDuration {
		return NominalLeaseDuration
	}
	return horizon + cycleDeadlineBoundary
}

func hasFullCycleClaimBudget(remaining, database, operation time.Duration) bool {
	return remaining > fullCycleClaimBudget(database, operation)
}

func contextHasFullCycleClaimBudget(
	ctx context.Context,
	database time.Duration,
	operation time.Duration,
) bool {
	if ctx == nil || ctx.Err() != nil {
		return false
	}
	deadline, ok := ctx.Deadline()
	return !ok || hasFullCycleClaimBudget(time.Until(deadline), database, operation)
}

func operationContextWithFullParentBudget(
	parent context.Context,
	operation time.Duration,
) (context.Context, context.CancelFunc, bool) {
	if parent == nil || parent.Err() != nil {
		return nil, nil, false
	}
	if deadline, ok := parent.Deadline(); ok &&
		!hasFullParentOperationBudget(time.Until(deadline), operation) {
		return nil, nil, false
	}
	operationContext, cancel := context.WithTimeout(parent, operation)
	return operationContext, cancel, true
}

func hasFullParentOperationBudget(remaining, operation time.Duration) bool {
	return remaining > operation+MinimumLeaseSchedulingMargin
}

func logoutBackoff(attempt int) time.Duration {
	return min(time.Second<<min(attempt-1, 9), 15*time.Minute)
}

func classifyFailure(err error) string {
	switch {
	case errors.Is(err, ErrInvalidConfiguration):
		return "invalid_configuration"
	case errors.Is(err, ErrInvalidInput):
		return "invalid_input"
	case errors.Is(err, ErrInvalidProjection):
		return "invalid_projection"
	case errors.Is(err, ErrInterrupted):
		return "interrupted"
	case errors.Is(err, ErrOutcomeUnknown):
		return "transition_outcome_unknown"
	default:
		return "dependency_unavailable"
	}
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
