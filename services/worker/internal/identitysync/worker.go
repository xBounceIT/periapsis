package identitysync

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
)

type Options struct {
	Repository       Repository
	Directory        DirectoryClient
	Keyring          identity.Keyring
	Lease            time.Duration
	OperationTimeout time.Duration
	TerminalTimeout  time.Duration
	AbsenceBatch     int
	Parallelism      int
	MinBackoff       time.Duration
	MaxBackoff       time.Duration
	Logger           *slog.Logger
	Observer         PollObserver
	Tracer           OperationTracer
}

// PollObserver receives only bounded execution state. Implementations must not
// retain claim, tenant, directory, or error material.
type PollObserver interface {
	ObserveLDAPSyncPoll(worked bool, failed bool, elapsed time.Duration)
}

// OperationTracer provides a process-owned tracing boundary without coupling
// the identity-sync domain to an observability SDK.
type OperationTracer interface {
	StartOperation(context.Context, string) (context.Context, func(error))
}

type Worker struct {
	repository       Repository
	directory        DirectoryClient
	keyring          identity.Keyring
	lease            time.Duration
	operationTimeout time.Duration
	terminalTimeout  time.Duration
	absenceBatch     int
	parallelism      int
	minBackoff       time.Duration
	maxBackoff       time.Duration
	logger           *slog.Logger
	observer         PollObserver
	tracer           OperationTracer
}

type preparedObservation struct {
	Observation identity.LDAPObservation
	Aliases     []identity.SubjectAlias
	Staged      StagedObservation
	ObservedAt  time.Time
}

func New(options Options) (*Worker, error) {
	if options.Repository == nil || options.Directory == nil || options.Keyring.ActiveVersion() < 1 ||
		options.Lease < time.Second || options.Lease > 10*time.Minute ||
		options.OperationTimeout < time.Minute || options.OperationTimeout > 2*time.Hour ||
		options.TerminalTimeout <= 0 || options.TerminalTimeout > time.Minute ||
		options.AbsenceBatch < 1 || options.AbsenceBatch > 200 ||
		options.Parallelism < 1 || options.Parallelism > 16 ||
		options.MinBackoff < 100*time.Millisecond || options.MinBackoff > time.Minute ||
		options.MaxBackoff < options.MinBackoff || options.MaxBackoff > 5*time.Minute ||
		options.Logger == nil {
		return nil, errors.New("invalid LDAP sync worker options")
	}
	return &Worker{
		repository: options.Repository, directory: options.Directory,
		keyring: options.Keyring, lease: options.Lease,
		operationTimeout: options.OperationTimeout,
		terminalTimeout:  options.TerminalTimeout,
		absenceBatch:     options.AbsenceBatch, parallelism: options.Parallelism,
		minBackoff: options.MinBackoff, maxBackoff: options.MaxBackoff,
		logger: options.Logger, observer: options.Observer, tracer: options.Tracer,
	}, nil
}

// Run starts bounded independent claim loops. reportReadiness is called only
// with safe process state and may be nil in tests.
func (worker *Worker) Run(ctx context.Context, reportReadiness func(bool)) {
	if worker == nil || ctx == nil {
		if reportReadiness != nil {
			reportReadiness(false)
		}
		return
	}
	states := make([]bool, worker.parallelism)
	var readinessLock sync.Mutex
	report := func(index int, value bool) {
		if reportReadiness == nil {
			return
		}
		readinessLock.Lock()
		states[index] = value
		ready := slices.Index(states, false) == -1
		readinessLock.Unlock()
		reportReadiness(ready)
	}
	var wait sync.WaitGroup
	wait.Add(worker.parallelism)
	for index := 0; index < worker.parallelism; index++ {
		go func(pollerIndex int) {
			defer wait.Done()
			report(pollerIndex, true)
			worker.runPoller(ctx, func(value bool) { report(pollerIndex, value) })
		}(index)
	}
	wait.Wait()
}

func (worker *Worker) runPoller(ctx context.Context, reportReadiness func(bool)) {
	backoff := worker.minBackoff
	for ctx.Err() == nil {
		started := time.Now()
		pollContext := ctx
		finishTrace := func(error) {}
		if worker.tracer != nil {
			tracedContext, finish := worker.tracer.StartOperation(ctx, "ldap.sync.poll")
			if tracedContext != nil {
				pollContext = tracedContext
			}
			if finish != nil {
				finishTrace = finish
			}
		}
		worked, err := worker.PollOnce(pollContext)
		finishTrace(err)
		if worker.observer != nil {
			worker.observer.ObserveLDAPSyncPoll(worked, err != nil, time.Since(started))
		}
		if err != nil {
			if reportReadiness != nil {
				reportReadiness(false)
			}
			worker.logger.WarnContext(pollContext, "LDAP sync poll failed", "category", "database")
			if !waitContext(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, worker.maxBackoff)
			continue
		}
		if reportReadiness != nil {
			reportReadiness(true)
		}
		if worked {
			backoff = worker.minBackoff
			continue
		}
		if !waitContext(ctx, backoff) {
			return
		}
		backoff = min(backoff*2, worker.maxBackoff)
	}
}

// PollOnce claims and fully drives at most one run. A nil claim is a healthy
// empty queue, not an error.
func (worker *Worker) PollOnce(ctx context.Context) (bool, error) {
	proof, err := newClaimProof()
	if err != nil {
		return false, errors.New("generate LDAP sync claim proof")
	}
	claim, err := retryValue(ctx, func(callContext context.Context) (*Claim, error) {
		return worker.repository.Claim(callContext, proof, int(worker.lease/time.Second))
	})
	if err != nil {
		return false, err
	}
	if claim == nil {
		return false, nil
	}
	defer claim.ClearSensitive()
	if err := validateClaim(*claim, proof); err != nil {
		return true, err
	}
	worker.logger.InfoContext(
		ctx,
		"LDAP sync claimed", "run_id", claim.RunID, "tenant_id", claim.TenantID,
		"fence", claim.Fence, "status", claim.Status,
	)

	operationContext, cancelOperation := context.WithTimeout(ctx, worker.operationTimeout)
	processContext, cancelProcess := context.WithCancelCause(operationContext)
	var finalizing atomic.Bool
	heartbeatDone := make(chan error, 1)
	heartbeatClaim := *claim
	go func() {
		heartbeatDone <- worker.heartbeat(processContext, cancelProcess, heartbeatClaim, &finalizing)
	}()
	processErr := worker.processClaim(processContext, claim, &finalizing)
	cancelProcess(nil)
	heartbeatErr := <-heartbeatDone
	cancelOperation()
	if errors.Is(heartbeatErr, ErrClaimLost) || errors.Is(context.Cause(processContext), ErrClaimLost) {
		worker.logger.WarnContext(
			ctx,
			"LDAP sync claim fenced", "run_id", claim.RunID, "tenant_id", claim.TenantID,
			"fence", claim.Fence,
		)
		return true, nil
	}
	if processErr == nil && heartbeatErr != nil && !errors.Is(heartbeatErr, context.Canceled) {
		processErr = heartbeatErr
	}
	if processErr == nil {
		return true, nil
	}
	if errors.Is(processErr, ErrClaimLost) {
		return true, nil
	}
	category := failureCategory(processErr, ctx)
	terminalContext, cancelTerminal := context.WithTimeout(context.WithoutCancel(ctx), worker.terminalTimeout)
	defer cancelTerminal()
	audit, auditErr := newAuditIDs()
	if auditErr != nil {
		return true, errors.New("generate LDAP sync terminal IDs")
	}
	terminal, failErr := retryValue(terminalContext, func(callContext context.Context) (TerminalResult, error) {
		return worker.repository.Fail(callContext, *claim, claim.Version, category, audit)
	})
	if errors.Is(failErr, ErrClaimLost) {
		return true, nil
	}
	if failErr != nil {
		return true, failErr
	}
	if terminal.Version != claim.Version+1 ||
		(terminal.Status != "failed" && terminal.Status != "cancelled" && terminal.Status != "stale") {
		return true, ErrInvalidSnapshot
	}
	worker.logger.WarnContext(
		ctx,
		"LDAP sync terminated", "run_id", claim.RunID, "tenant_id", claim.TenantID,
		"status", terminal.Status, "category", category,
	)
	return true, nil
}

func (worker *Worker) heartbeat(
	ctx context.Context,
	cancel context.CancelCauseFunc,
	claim Claim,
	finalizing *atomic.Bool,
) error {
	interval := max(worker.lease/3, 250*time.Millisecond)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			renewed, err := retryValue(ctx, func(callContext context.Context) (*Claim, error) {
				return worker.repository.Claim(
					callContext, claim.Proof, int(worker.lease/time.Second),
				)
			})
			if err != nil {
				cancel(err)
				return err
			}
			if renewed == nil {
				if finalizing.Load() {
					return nil
				}
				cancel(ErrClaimLost)
				return ErrClaimLost
			}
			valid := renewed.RunID == claim.RunID && renewed.TenantID == claim.TenantID &&
				renewed.Proof == claim.Proof && renewed.Fence == claim.Fence &&
				(renewed.Status == "enumerating" || renewed.Status == "applying")
			renewed.ClearSensitive()
			if !valid {
				if finalizing.Load() {
					return nil
				}
				cancel(ErrClaimLost)
				return ErrClaimLost
			}
		}
	}
}

func (worker *Worker) processClaim(
	ctx context.Context,
	claim *Claim,
	finalizing *atomic.Bool,
) error {
	prepared, result, err := worker.enumerateAndPrepare(ctx, *claim)
	if err != nil {
		return err
	}
	if result.Category != ldapclient.DirectoryCategorySuccess || !result.Complete || result.Truncated {
		if claim.Status != "enumerating" {
			return categorizedFailure(
				"directory_error", errors.New("applying reclaim could not re-enumerate source"),
			)
		}
		failure := string(result.Category)
		if failure == "" || failure == string(ldapclient.DirectoryCategorySuccess) {
			failure = "directory_error"
		}
		if result.Truncated {
			failure = "limit_exceeded"
		}
		audit, auditErr := newAuditIDs()
		if auditErr != nil {
			return auditErr
		}
		finalizing.Store(true)
		completion, completionErr := retryValue(ctx, func(callContext context.Context) (EnumerationCompletion, error) {
			return worker.repository.CompleteEnumeration(
				callContext, *claim, claim.Version, false, result.Truncated, nil, &failure, audit,
			)
		})
		if completionErr != nil {
			return completionErr
		}
		if completion.Version != claim.Version+1 || completion.ObservedCount < 0 ||
			completion.ObservedCount > maximumStagedObservations || completion.AbsenceAllowed ||
			(completion.Status != "failed" && completion.Status != "cancelled" && completion.Status != "stale") {
			return ErrInvalidSnapshot
		}
		claim.Version = completion.Version
		claim.Status = completion.Status
		worker.logger.WarnContext(
			ctx,
			"LDAP sync enumeration rejected", "run_id", claim.RunID,
			"tenant_id", claim.TenantID, "category", failure,
		)
		return nil
	}
	if len(prepared) > maximumStagedObservations {
		return categorizedFailure("directory_error", errors.New("observation bound exceeded"))
	}
	if err := worker.reconcileInventory(ctx, *claim, prepared); err != nil {
		return err
	}
	if claim.Status == "enumerating" {
		cursor := enumerationDigest(prepared)
		audit, auditErr := newAuditIDs()
		if auditErr != nil {
			return auditErr
		}
		completion, completionErr := retryValue(ctx, func(callContext context.Context) (EnumerationCompletion, error) {
			return worker.repository.CompleteEnumeration(
				callContext, *claim, claim.Version, true, false, &cursor, nil, audit,
			)
		})
		if completionErr != nil {
			return completionErr
		}
		if completion.Status != "applying" || completion.Version != claim.Version+1 ||
			!completion.AbsenceAllowed ||
			completion.ObservedCount != len(prepared) {
			return ErrInvalidSnapshot
		}
		claim.Version = completion.Version
		claim.Status = completion.Status
	}
	for index := range prepared {
		if prepared[index].Staged.Applied {
			continue
		}
		if err := worker.planAndApply(ctx, *claim, prepared[index]); err != nil {
			return err
		}
	}
	for chunks := 0; ; chunks++ {
		if chunks > 100_000 {
			return errors.New("LDAP sync absence chunk bound exceeded")
		}
		audit, auditErr := newAuditIDs()
		if auditErr != nil {
			return auditErr
		}
		absence, absenceErr := retryValue(ctx, func(callContext context.Context) (AbsenceResult, error) {
			return worker.repository.ApplyAbsence(callContext, *claim, worker.absenceBatch, audit)
		})
		if absenceErr != nil {
			return absenceErr
		}
		if absence.Inspected < 0 || absence.Revoked < 0 || absence.Remaining < 0 ||
			absence.Revoked > absence.Inspected {
			return ErrInvalidSnapshot
		}
		if absence.Remaining == 0 {
			break
		}
		if absence.Inspected == 0 {
			return ErrInvalidSnapshot
		}
	}
	audit, err := newAuditIDs()
	if err != nil {
		return err
	}
	finalizing.Store(true)
	completedVersion, err := retryValue(ctx, func(callContext context.Context) (int, error) {
		return worker.repository.Complete(callContext, *claim, claim.Version, audit)
	})
	if err != nil {
		return err
	}
	if completedVersion != claim.Version+1 {
		return ErrInvalidSnapshot
	}
	worker.logger.InfoContext(
		ctx,
		"LDAP sync completed", "run_id", claim.RunID, "tenant_id", claim.TenantID,
		"observed_count", len(prepared),
	)
	return nil
}

func (worker *Worker) enumerateAndPrepare(
	ctx context.Context,
	claim Claim,
) ([]preparedObservation, ldapclient.DirectoryEnumerationResult, error) {
	request, usernameAttribute, err := enumerationRequest(claim)
	if err != nil {
		return nil, ldapclient.DirectoryEnumerationResult{}, err
	}
	secret, err := decryptBindSecret(worker.keyring, claim)
	if err != nil {
		clear(request.Configuration.CustomCAPEM)
		return nil, ldapclient.DirectoryEnumerationResult{}, err
	}
	result, directoryErr := worker.directory.EnumerateDirectoryUsers(ctx, request, secret)
	clear(secret)
	clear(request.Configuration.CustomCAPEM)
	if directoryErr != nil {
		clearEnumeratedUsers(result.Users)
		return nil, ldapclient.DirectoryEnumerationResult{}, categorizedFailure(
			"directory_error", errors.New("directory enumeration failed"),
		)
	}
	if result.Category != ldapclient.DirectoryCategorySuccess || !result.Complete || result.Truncated {
		clearEnumeratedUsers(result.Users)
		result.Users = nil
		return nil, result, nil
	}
	if result.EndpointPriority < 1 || result.EndpointPriority > 8 ||
		len(result.Users) > maximumStagedObservations {
		clearEnumeratedUsers(result.Users)
		return nil, ldapclient.DirectoryEnumerationResult{}, ErrInvalidSnapshot
	}
	defer clearEnumeratedUsers(result.Users)
	prepared := make([]preparedObservation, 0, len(result.Users))
	for index := range result.Users {
		username, usernameErr := ldapclient.DirectoryUsernameFromEntry(
			usernameAttribute, result.Users[index],
		)
		clearDirectoryEntry(&result.Users[index])
		if usernameErr != nil {
			return nil, ldapclient.DirectoryEnumerationResult{}, categorizedFailure(
				"directory_error", errors.New("directory entry is invalid"),
			)
		}
		observationRequest, normalization, requestErr := observationRequest(claim, username)
		if requestErr != nil {
			return nil, ldapclient.DirectoryEnumerationResult{}, requestErr
		}
		secret, decryptErr := decryptBindSecret(worker.keyring, claim)
		if decryptErr != nil {
			clear(observationRequest.Configuration.CustomCAPEM)
			return nil, ldapclient.DirectoryEnumerationResult{}, decryptErr
		}
		observedAt := time.Now().UTC().Truncate(time.Microsecond)
		directoryResult, observeErr := worker.directory.ObserveDirectory(
			ctx, observationRequest, secret,
		)
		clear(secret)
		clear(observationRequest.Configuration.CustomCAPEM)
		if observeErr != nil || directoryResult.Category != ldapclient.DirectoryCategorySuccess ||
			directoryResult.EndpointPriority < 1 || directoryResult.EndpointPriority > 8 {
			clearDirectoryObservation(&directoryResult.Observation)
			return nil, ldapclient.DirectoryEnumerationResult{}, categorizedFailure(
				directoryFailureCategory(directoryResult.Category),
				errors.New("directory observation failed"),
			)
		}
		digest := observationDigest(claim, index+1, directoryResult.Observation)
		normalized, normalizeErr := ldapclient.NormalizeDirectoryObservation(
			normalization, directoryResult.Observation,
		)
		clearDirectoryObservation(&directoryResult.Observation)
		if normalizeErr != nil {
			return nil, ldapclient.DirectoryEnumerationResult{}, categorizedFailure(
				"directory_error", errors.New("directory normalization failed"),
			)
		}
		aliases, aliasErr := normalized.SubjectAliases(worker.keyring, providerContext(claim))
		if aliasErr != nil || len(aliases) < 1 || len(aliases) > maximumSubjectAliases {
			return nil, ldapclient.DirectoryEnumerationResult{}, ErrInvalidSnapshot
		}
		activeAlias, activeErr := activeSubjectAlias(worker.keyring.ActiveVersion(), aliases)
		if activeErr != nil {
			return nil, ldapclient.DirectoryEnumerationResult{}, activeErr
		}
		prepared = append(prepared, preparedObservation{
			Observation: normalized, Aliases: aliases, ObservedAt: observedAt,
			Staged: StagedObservation{
				Ordinal: index + 1, DigestKeyVersion: activeAlias.KeyVersion,
				SubjectDigest: activeAlias.Digest, ObservationDigest: digest,
			},
		})
	}
	return prepared, result, nil
}

func (worker *Worker) reconcileInventory(
	ctx context.Context,
	claim Claim,
	prepared []preparedObservation,
) error {
	if len(claim.Staged) > maximumStagedObservations {
		return ErrInvalidSnapshot
	}
	byOrdinal := make(map[int]StagedObservation, len(claim.Staged))
	for _, existing := range claim.Staged {
		if existing.Ordinal < 1 || existing.Ordinal > maximumStagedObservations ||
			existing.ObservationID == uuid.Nil || existing.ObservationID.Version() != 7 {
			return ErrInvalidSnapshot
		}
		if _, duplicate := byOrdinal[existing.Ordinal]; duplicate {
			return ErrInvalidSnapshot
		}
		byOrdinal[existing.Ordinal] = existing
	}
	for index := range prepared {
		observation := &prepared[index]
		existing, found := byOrdinal[observation.Staged.Ordinal]
		if found {
			if existing.DigestKeyVersion != observation.Staged.DigestKeyVersion ||
				existing.SubjectDigest != observation.Staged.SubjectDigest ||
				existing.ObservationDigest != observation.Staged.ObservationDigest {
				return errors.New("LDAP sync reclaimed inventory diverged")
			}
			observation.Staged = existing
			continue
		}
		if claim.Status != "enumerating" {
			return errors.New("LDAP sync applying inventory is incomplete")
		}
		observationID, err := uuid.NewV7()
		if err != nil {
			return errors.New("generate LDAP sync observation ID")
		}
		observation.Staged.ObservationID = observationID
		externalIdentityID, err := retryValue(ctx, func(callContext context.Context) (*uuid.UUID, error) {
			return worker.repository.Stage(callContext, claim, observation.Staged)
		})
		if err != nil {
			return err
		}
		if externalIdentityID != nil {
			if _, err := entityID(*externalIdentityID); err != nil {
				return err
			}
		}
	}
	if len(byOrdinal) != len(prepared) && claim.Status == "applying" {
		return errors.New("LDAP sync applying inventory changed")
	}
	if claim.Status == "enumerating" {
		for ordinal := range byOrdinal {
			if ordinal > len(prepared) {
				return errors.New("LDAP sync staged inventory is not a prefix")
			}
		}
	}
	return nil
}

func (worker *Worker) planAndApply(
	ctx context.Context,
	claim Claim,
	prepared preparedObservation,
) error {
	projection, err := retryValue(ctx, func(callContext context.Context) (PlanningProjection, error) {
		return worker.repository.Planning(
			callContext, claim, prepared.Staged.ObservationID, prepared.Aliases,
		)
	})
	if err != nil {
		if errors.Is(err, ErrClaimLost) {
			return err
		}
		return categorizedFailure("planning_error", err)
	}
	if projection.ObservationID != prepared.Staged.ObservationID {
		return ErrInvalidSnapshot
	}
	snapshot, rules, err := planningSnapshot(claim, projection)
	if err != nil {
		return err
	}
	plan, err := identity.PlanLDAPMapping(prepared.Observation, snapshot)
	if err != nil {
		return ErrInvalidSnapshot
	}
	request, err := worker.applyRequest(claim, prepared, projection, rules, plan)
	if err != nil {
		return err
	}
	defer request.ClearSensitive()
	result, err := retryValue(ctx, func(callContext context.Context) (ApplyResult, error) {
		return worker.repository.Apply(callContext, claim, request)
	})
	if err != nil {
		return err
	}
	if result.ApplicationID != request.ApplicationID || result.Decision != request.Decision {
		return ErrInvalidSnapshot
	}
	if result.EnsuredEdges < 0 || result.RevokedEdges < 0 ||
		request.Decision == "denied" && (result.ExternalIdentityID != nil || result.UserID != nil ||
			result.MembershipID != nil || result.AccessGrantID != nil) ||
		request.Decision == "admitted" && (!sameOptionalUUID(result.ExternalIdentityID, request.ExternalIdentityID) ||
			!sameOptionalUUID(result.UserID, request.UserID) ||
			!sameOptionalUUID(result.MembershipID, request.MembershipID) ||
			!sameOptionalUUID(result.AccessGrantID, request.AccessGrantID)) {
		return ErrInvalidSnapshot
	}
	return nil
}

func sameOptionalUUID(left, right *uuid.UUID) bool {
	return left != nil && right != nil && *left == *right
}

func (worker *Worker) applyRequest(
	claim Claim,
	prepared preparedObservation,
	projection PlanningProjection,
	rules []planningRuleDocument,
	plan identity.LDAPMappingPlan,
) (ApplyRequest, error) {
	applicationID, err := uuid.NewV7()
	if err != nil {
		return ApplyRequest{}, err
	}
	audit, err := newAuditIDs()
	if err != nil {
		return ApplyRequest{}, err
	}
	request := ApplyRequest{
		ObservationID: prepared.Staged.ObservationID, ApplicationID: applicationID,
		PlanDigest: prepared.Staged.ObservationDigest, ObservedAt: prepared.ObservedAt,
		AuditEventID: audit.EventID, RequestID: audit.RequestID,
		CorrelationID: audit.CorrelationID,
	}
	if plan.Disposition() == identity.LDAPPlanDenied {
		request.Decision = "denied"
		category := string(plan.Reason())
		request.DenialCategory = &category
		request.MatchedEpochIDs = []uuid.UUID{}
		request.RevocationEpochIDs, err = deniedRevocationEpochIDs(plan, rules)
		if err != nil {
			return ApplyRequest{}, err
		}
		if plan.Reason() == identity.LDAPPlanReasonNoMapping && projection.AccessGrantLive {
			if projection.ExternalIdentityID == nil || projection.UserID == nil ||
				projection.MembershipID == nil || projection.AccessGrantID == nil {
				return ApplyRequest{}, ErrInvalidSnapshot
			}
			request.ExistingExternalIdentityID = projection.ExternalIdentityID
			request.ExistingUserID = projection.UserID
			request.ExistingMembershipID = projection.MembershipID
			request.ExistingAccessGrantID = projection.AccessGrantID
		} else if len(request.RevocationEpochIDs) != 0 {
			// Source-owned edges cannot exist without the membership whose exact
			// identifiers were loaded in the same planning snapshot.
			return ApplyRequest{}, ErrInvalidSnapshot
		}
		return request, nil
	}
	if plan.Disposition() != identity.LDAPPlanAdmitted {
		return ApplyRequest{}, ErrInvalidSnapshot
	}
	request.Decision = "admitted"
	externalIdentityID, err := existingOrNewID(projection.ExternalIdentityID)
	if err != nil {
		return ApplyRequest{}, err
	}
	userID, err := existingOrNewID(projection.UserID)
	if err != nil {
		return ApplyRequest{}, err
	}
	membershipID, err := existingOrNewID(projection.MembershipID)
	if err != nil {
		return ApplyRequest{}, err
	}
	accessGrantID, err := existingOrNewID(projection.AccessGrantID)
	if err != nil {
		return ApplyRequest{}, err
	}
	profileID, err := uuid.NewV7()
	if err != nil {
		return ApplyRequest{}, err
	}
	request.ExternalIdentityID = &externalIdentityID
	request.UserID = &userID
	request.MembershipID = &membershipID
	request.AccessGrantID = &accessGrantID
	request.ProfileContributionID = &profileID
	envelope, aliases, err := prepared.Observation.ProtectSubject(
		worker.keyring,
		identity.ExternalSubjectContext{
			Provider: providerContext(claim), ExternalIdentityID: identity.EntityID(externalIdentityID),
		},
	)
	if err != nil || len(aliases) != len(prepared.Aliases) {
		clear(envelope.Ciphertext)
		return ApplyRequest{}, ErrInvalidSnapshot
	}
	for index := range aliases {
		if aliases[index] != prepared.Aliases[index] {
			clear(envelope.Ciphertext)
			return ApplyRequest{}, ErrInvalidSnapshot
		}
	}
	format, err := subjectFormat(envelope.Format)
	if err != nil {
		clear(envelope.Ciphertext)
		return ApplyRequest{}, err
	}
	request.SubjectFormat = &format
	request.SubjectCiphertext = envelope.Ciphertext
	request.SubjectNonce = append([]byte(nil), envelope.Nonce[:]...)
	version := envelope.KeyVersion
	request.SubjectKeyVersion = &version
	request.AliasIDs = make([]uuid.UUID, len(aliases))
	request.AliasKeyVersions = make([]int16, len(aliases))
	request.AliasDigests = make([][]byte, len(aliases))
	for index, alias := range aliases {
		aliasID, idErr := uuid.NewV7()
		if idErr != nil {
			request.ClearSensitive()
			return ApplyRequest{}, idErr
		}
		request.AliasIDs[index] = aliasID
		request.AliasKeyVersions[index] = alias.KeyVersion
		request.AliasDigests[index] = append([]byte(nil), alias.Digest[:]...)
	}
	request.DisplayName, err = revealProfile(plan, identity.LDAPProfileDisplayName, true)
	if err != nil {
		request.ClearSensitive()
		return ApplyRequest{}, err
	}
	request.FirstName, err = revealProfile(plan, identity.LDAPProfileFirstName, false)
	if err != nil {
		request.ClearSensitive()
		return ApplyRequest{}, err
	}
	request.LastName, err = revealProfile(plan, identity.LDAPProfileLastName, false)
	if err != nil {
		request.ClearSensitive()
		return ApplyRequest{}, err
	}
	request.Username, err = revealProfile(plan, identity.LDAPProfileUsername, false)
	if err != nil {
		request.ClearSensitive()
		return ApplyRequest{}, err
	}
	request.Email, err = revealProfile(plan, identity.LDAPProfileEmail, false)
	if err != nil {
		request.ClearSensitive()
		return ApplyRequest{}, err
	}
	request.MatchedEpochIDs, err = matchedEpochIDs(plan, rules)
	if err != nil {
		request.ClearSensitive()
		return ApplyRequest{}, err
	}
	return request, nil
}

func deniedRevocationEpochIDs(
	plan identity.LDAPMappingPlan,
	rules []planningRuleDocument,
) ([]uuid.UUID, error) {
	changes := plan.Changes()
	if len(changes) == 0 {
		return []uuid.UUID{}, nil
	}
	if plan.Reason() != identity.LDAPPlanReasonNoMapping {
		return nil, ErrInvalidSnapshot
	}
	type sourceEpoch struct {
		source uuid.UUID
		epoch  uuid.UUID
	}
	authoritative := make(map[sourceEpoch]struct{}, len(rules))
	for _, rule := range rules {
		if rule.ReconciliationMode == "authoritative" {
			authoritative[sourceEpoch{source: rule.SourceID, epoch: rule.RuleEpochID}] = struct{}{}
		}
	}
	unique := make(map[uuid.UUID]struct{}, len(changes))
	for _, change := range changes {
		epoch := uuid.UUID(change.RuleEpochID)
		source := uuid.UUID(change.SourceID)
		if change.Operation != identity.LDAPMappingRevoke {
			return nil, ErrInvalidSnapshot
		}
		if _, ok := authoritative[sourceEpoch{source: source, epoch: epoch}]; !ok {
			return nil, ErrInvalidSnapshot
		}
		switch change.Key.Kind {
		case identity.LDAPSecurityGroupMembershipEdge,
			identity.LDAPOperatorTeamRosterEdge:
			unique[epoch] = struct{}{}
		case identity.LDAPSecurityGroupRoleGrantEdge:
			// Group-to-role grants are mapping-global configuration. Removing one
			// observed user revokes that user's membership and roster edges, but
			// must not retire the shared grant. Excluding role-only epochs also
			// keeps repeated grace-period no-match runs aligned with the database's
			// exact per-user source proof after the first reconciliation.
		default:
			return nil, ErrInvalidSnapshot
		}
	}
	result := make([]uuid.UUID, 0, len(unique))
	for epoch := range unique {
		result = append(result, epoch)
	}
	slices.SortFunc(result, func(left, right uuid.UUID) int {
		return bytes.Compare(left[:], right[:])
	})
	return result, nil
}

func activeSubjectAlias(version int16, aliases []identity.SubjectAlias) (identity.SubjectAlias, error) {
	for _, alias := range aliases {
		if alias.KeyVersion == version {
			return alias, nil
		}
	}
	return identity.SubjectAlias{}, ErrInvalidSnapshot
}

func existingOrNewID(existing *uuid.UUID) (uuid.UUID, error) {
	if existing != nil {
		if _, err := entityID(*existing); err != nil {
			return uuid.Nil, err
		}
		return *existing, nil
	}
	value, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, err
	}
	return value, nil
}

func subjectFormat(value identity.SubjectFormat) (string, error) {
	switch value {
	case identity.ADObjectGUIDSubject:
		return "ad_object_guid", nil
	case identity.EntryUUIDSubject:
		return "entry_uuid", nil
	case identity.UTF8ExactSubject:
		return "utf8_exact", nil
	case identity.UTF8CaseFoldSubject:
		return "utf8_casefold", nil
	default:
		return "", ErrInvalidSnapshot
	}
}

func revealProfile(
	plan identity.LDAPMappingPlan,
	field identity.LDAPProfileField,
	required bool,
) (*string, error) {
	value, present, err := plan.RevealProfileField(field)
	if err != nil || required && !present {
		return nil, ErrInvalidSnapshot
	}
	if !present {
		return nil, nil
	}
	return &value, nil
}

func validateClaim(claim Claim, proof ClaimProof) error {
	if proof.ID == uuid.Nil || proof.ID.Version() != 7 || claim.Proof != proof ||
		claim.RunID == uuid.Nil || claim.RunID.Version() != 7 ||
		claim.TenantID == uuid.Nil || claim.TenantID.Version() != 7 ||
		claim.ProviderID == uuid.Nil || claim.ProviderID.Version() != 7 ||
		claim.BindingID == uuid.Nil || claim.BindingID.Version() != 7 ||
		claim.SecretID == uuid.Nil || claim.SecretID.Version() != 7 ||
		claim.BindingAccessEpochID == uuid.Nil || claim.BindingAccessEpochID.Version() != 7 ||
		claim.Fence < 1 || claim.Version < 1 || claim.ProviderVersion < 1 ||
		claim.ConfigurationVersion < 1 || claim.SecretVersion < 1 ||
		claim.BindingVersion < 1 || claim.BindingAuthRevision < 1 ||
		claim.RuleSetRevision < 1 || claim.AuthorizationRevision < 1 ||
		(claim.Status != "enumerating" && claim.Status != "applying") ||
		claim.ExpiresAt.IsZero() || claim.QueuedAt.IsZero() || claim.EnumerationStartedAt == nil ||
		len(claim.MappingRevisions) > 1_000 ||
		len(claim.Staged) > maximumStagedObservations ||
		allZero(claim.EndpointSnapshotDigest[:]) || allZero(proof.ReceiptDigest[:]) {
		return ErrInvalidSnapshot
	}
	if _, err := validatedMappingPins(claim.MappingRevisions); err != nil {
		return err
	}
	ordinals := make(map[int]struct{}, len(claim.Staged))
	identifiers := make(map[uuid.UUID]struct{}, len(claim.Staged))
	for _, observation := range claim.Staged {
		if _, err := entityID(observation.ObservationID); err != nil {
			return err
		}
		if observation.Ordinal < 1 || observation.Ordinal > maximumStagedObservations ||
			observation.DigestKeyVersion < 1 || allZero(observation.SubjectDigest[:]) ||
			allZero(observation.ObservationDigest[:]) || observation.Applied && observation.PlanningFence == nil ||
			claim.Status == "enumerating" && observation.Applied {
			return ErrInvalidSnapshot
		}
		if observation.ExternalIdentityID != nil {
			if _, err := entityID(*observation.ExternalIdentityID); err != nil {
				return err
			}
		}
		if observation.PlanningFence != nil && *observation.PlanningFence < 1 {
			return ErrInvalidSnapshot
		}
		if _, duplicate := ordinals[observation.Ordinal]; duplicate {
			return ErrInvalidSnapshot
		}
		if _, duplicate := identifiers[observation.ObservationID]; duplicate {
			return ErrInvalidSnapshot
		}
		ordinals[observation.Ordinal] = struct{}{}
		identifiers[observation.ObservationID] = struct{}{}
	}
	return nil
}

func newAuditIDs() (AuditIDs, error) {
	values := [3]uuid.UUID{}
	for index := range values {
		value, err := uuid.NewV7()
		if err != nil {
			return AuditIDs{}, err
		}
		values[index] = value
	}
	return AuditIDs{EventID: values[0], RequestID: values[1], CorrelationID: values[2]}, nil
}

func failureCategory(err error, parent context.Context) string {
	if parent.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "cancelled"
	}
	if errors.Is(err, ErrInvalidSnapshot) {
		return "planning_error"
	}
	var categorized runFailure
	if errors.As(err, &categorized) {
		return categorized.category
	}
	return "apply_error"
}

func directoryFailureCategory(category ldapclient.DirectoryCategory) string {
	switch category {
	case ldapclient.DirectoryCategoryDNSFailed,
		ldapclient.DirectoryCategoryDestinationBlocked,
		ldapclient.DirectoryCategoryConnectTimeout,
		ldapclient.DirectoryCategoryConnectFailed,
		ldapclient.DirectoryCategoryTLSFailed,
		ldapclient.DirectoryCategoryCertificateRejected:
		return "network_error"
	case ldapclient.DirectoryCategoryCancelled:
		return "cancelled"
	default:
		return "directory_error"
	}
}

func retryValue[T any](ctx context.Context, call func(context.Context) (T, error)) (T, error) {
	var zero T
	var last error
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil {
			return zero, ctx.Err()
		}
		value, err := call(ctx)
		if err == nil {
			return value, nil
		}
		if errors.Is(err, ErrClaimLost) {
			return zero, err
		}
		last = err
	}
	return zero, last
}

func waitContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func clearEnumeratedUsers(users []ldapclient.DirectoryEntry) {
	for index := range users {
		clearDirectoryEntry(&users[index])
	}
}

func allZero(value []byte) bool {
	return slices.IndexFunc(value, func(item byte) bool { return item != 0 }) == -1
}
