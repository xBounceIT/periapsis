package platformsamlauth

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

const (
	minimumOperationTimeout = 100 * time.Millisecond
	maximumOperationTimeout = 2 * time.Minute
	minimumRecoveryTimeout  = 10 * time.Millisecond
	maximumRecoveryTimeout  = 5 * time.Second
)

type ApplicationOptions struct {
	Protocol         ProtocolPort
	Starts           StartSource
	Configurations   ConfigurationSource
	Planner          *Planner
	Credentials      CredentialIssuer
	Apply            AtomicApplyPort
	Keyring          identity.Keyring
	Now              func() time.Time
	OperationTimeout time.Duration
	RecoveryTimeout  time.Duration
}

type Application struct {
	protocol         ProtocolPort
	starts           StartSource
	configurations   ConfigurationSource
	planner          *Planner
	credentials      CredentialIssuer
	apply            AtomicApplyPort
	keyring          identity.Keyring
	now              func() time.Time
	operationTimeout time.Duration
	recoveryTimeout  time.Duration
}

func NewApplication(options ApplicationOptions) (*Application, error) {
	if options.Protocol == nil || options.Starts == nil || options.Configurations == nil || options.Planner == nil ||
		options.Credentials == nil || options.Apply == nil || options.Keyring.ActiveVersion() < 1 || options.Now == nil ||
		options.OperationTimeout < minimumOperationTimeout || options.OperationTimeout > maximumOperationTimeout ||
		options.OperationTimeout%time.Microsecond != 0 || options.RecoveryTimeout < minimumRecoveryTimeout ||
		options.RecoveryTimeout > maximumRecoveryTimeout || options.RecoveryTimeout%time.Microsecond != 0 {
		return nil, ErrInvalidOptions
	}
	return &Application{
		protocol: options.Protocol, starts: options.Starts, configurations: options.Configurations,
		planner: options.Planner, credentials: options.Credentials, apply: options.Apply,
		keyring: options.Keyring, now: options.Now, operationTimeout: options.OperationTimeout,
		recoveryTimeout: options.RecoveryTimeout,
	}, nil
}

func (application *Application) String() string {
	return fmt.Sprintf(
		"platformsamlauth.Application{configured:%t}",
		application != nil && application.protocol != nil && application.starts != nil &&
			application.configurations != nil && application.planner != nil && application.credentials != nil &&
			application.apply != nil && application.keyring.ActiveVersion() > 0,
	)
}

func (application *Application) GoString() string { return application.String() }

type StartRequest struct {
	Lookup                  StartLookup
	ReturnPath              string
	PreviousBrowserHandle   []byte `json:"-"`
	HasAuthenticatedSession bool
	Audit                   AuditContext
}

func (request StartRequest) String() string {
	return fmt.Sprintf(
		"platformsamlauth.StartRequest{lookup:%q,returnPath:%t,previousBrowser:%t,authenticatedSession:%t,audit:%q,material:[REDACTED]}",
		request.Lookup.String(), request.ReturnPath != "", len(request.PreviousBrowserHandle) != 0,
		request.HasAuthenticatedSession, request.Audit.String(),
	)
}

func (request StartRequest) GoString() string { return request.String() }

func (application *Application) Start(
	ctx context.Context,
	request StartRequest,
) (AuthorizationStart, error) {
	if application == nil || application.protocol == nil || application.starts == nil ||
		application.configurations == nil || request.HasAuthenticatedSession || !validStartLookup(request.Lookup) ||
		!validReturnPath(request.ReturnPath) || !validAuditContext(request.Audit) ||
		len(request.PreviousBrowserHandle) != 0 && !canonicalBrowserHandle(request.PreviousBrowserHandle) {
		return AuthorizationStart{}, ErrAuthenticationDenied
	}
	operation, cancel, ok := application.operation(ctx)
	if !ok {
		return AuthorizationStart{}, ErrAuthenticationUnavailable
	}
	defer cancel()
	authority := StartAuthority{Lookup: request.Lookup, ReturnPath: request.ReturnPath, Audit: request.Audit}
	grant, err := application.starts.BeginDirectSAMLLogin(operation, authority)
	if err != nil || operation.Err() != nil {
		return AuthorizationStart{}, ErrAuthenticationUnavailable
	}
	if grant.Authority != authority || !validDirectSAMLPins(grant.Pins) {
		return AuthorizationStart{}, ErrAuthenticationDenied
	}
	snapshot, err := application.configurations.LoadDirectSAMLStartConfiguration(operation, grant)
	snapshot.Configuration = cloneConfigurationSnapshot(snapshot.Configuration)
	now := application.currentTime()
	if err != nil || operation.Err() != nil {
		return AuthorizationStart{}, ErrAuthenticationUnavailable
	}
	if !validInstant(now) || snapshot.Grant != grant || snapshot.Configuration.Pins != grant.Pins ||
		!validConfigurationSnapshot(snapshot.Configuration, now) {
		return AuthorizationStart{}, ErrAuthenticationDenied
	}
	previous := append([]byte(nil), request.PreviousBrowserHandle...)
	defer clear(previous)
	start, err := application.protocol.StartDirectSAML(operation, StartProtocolRequest{
		Protocol: federatedsaml.StartRequest{
			Begin: request.Lookup.Begin, Configuration: cloneConfiguration(snapshot.Configuration.Authentication),
			ReturnPath: request.ReturnPath, PreviousBrowserHandle: previous, HasLiveSession: false,
		},
		Grant: grant,
	})
	if err != nil || operation.Err() != nil {
		start.Destroy()
		return AuthorizationStart{}, ErrAuthenticationUnavailable
	}
	if !validAuthorizationStart(start, now) {
		start.Destroy()
		return AuthorizationStart{}, ErrAuthenticationDenied
	}
	return start, nil
}

type CompleteRequest struct {
	MediaType     string
	RawForm       []byte `json:"-"`
	BrowserHandle []byte `json:"-"`
	Audit         AuditContext
}

func (request CompleteRequest) String() string {
	return fmt.Sprintf(
		"platformsamlauth.CompleteRequest{mediaType:%t,formBytes:%d,browser:%t,audit:%q,material:[REDACTED]}",
		request.MediaType != "", len(request.RawForm), len(request.BrowserHandle) != 0, request.Audit.String(),
	)
}

func (request CompleteRequest) GoString() string { return request.String() }

func (application *Application) Complete(ctx context.Context, request CompleteRequest) (Outcome, error) {
	limits := federatedsaml.DefaultLimits()
	maximumRawFormBytes, limitsErr := federatedsaml.MaximumPOSTFormBytes(limits)
	if application == nil || application.protocol == nil || application.configurations == nil ||
		application.planner == nil || application.credentials == nil || application.apply == nil ||
		limitsErr != nil || application.keyring.ActiveVersion() < 1 || !validAuditContext(request.Audit) ||
		request.MediaType == "" || len(request.MediaType) > 256 || len(request.RawForm) == 0 ||
		len(request.RawForm) > maximumRawFormBytes || !canonicalBrowserHandle(request.BrowserHandle) {
		return Outcome{}, ErrAuthenticationDenied
	}
	operation, cancel, ok := application.operation(ctx)
	if !ok {
		return Outcome{}, ErrAuthenticationUnavailable
	}
	defer cancel()
	rawForm := append([]byte(nil), request.RawForm...)
	browserHandle := append([]byte(nil), request.BrowserHandle...)
	defer clear(rawForm)
	defer clear(browserHandle)
	resolver := &callbackResolver{source: application.configurations, now: application.now}
	validated, err := application.protocol.ValidateDirectSAMLCallbackResolved(
		operation,
		CallbackRequest{
			Protocol: federatedsaml.ResolvedCallbackRequest{
				MediaType: request.MediaType, RawForm: rawForm, BrowserHandle: browserHandle,
			},
			Audit: request.Audit,
		},
		resolver,
	)
	configuration, configurationLookup, resolved, unavailable, violated := resolver.snapshot()
	if err != nil || validated == nil || !resolved || violated ||
		validated.Transaction() != configurationLookup ||
		!validProofForConfiguration(callbackProof(validated), configuration.Authentication) {
		if validated != nil {
			application.abort(ctx, validated, request.Audit)
		}
		if unavailable || operation.Err() != nil {
			return Outcome{}, ErrAuthenticationUnavailable
		}
		return Outcome{}, ErrAuthenticationDenied
	}
	consumer := &applicationConsumer{
		application: application, configuration: configuration,
		expected: callbackProof(validated), audit: request.Audit,
	}
	consumption, consumeErr := application.protocol.ConsumeDirectSAML(operation, validated, consumer)
	consumer.guard.Lock()
	outcome, consumerErr, applied := consumer.outcome, consumer.err, consumer.applied
	committed, committedResult, failureReason := consumer.committed, consumer.committedResult, consumer.failureReason
	consumer.guard.Unlock()
	if consumeErr != nil || consumption.Category != federatedsaml.ConsumerSuccess || !applied || consumer.duplicate.Load() {
		if outcome.Credential != nil {
			outcome.Credential.Destroy()
		}
		cleaned := true
		if committed {
			if failureReason == "" {
				failureReason = CleanupProtocolFailed
			}
			cleaned = application.cleanup(ctx, committedResult, failureReason, request.Audit)
		}
		application.abort(ctx, validated, request.Audit)
		if !cleaned || errors.Is(consumerErr, ErrAuthenticationUnavailable) || operation.Err() != nil {
			return Outcome{}, ErrAuthenticationUnavailable
		}
		return Outcome{}, ErrAuthenticationDenied
	}
	if !validOutcome(outcome) {
		if outcome.Credential != nil {
			outcome.Credential.Destroy()
		}
		cleaned := !committed || application.cleanup(ctx, committedResult, CleanupInvalidOutcome, request.Audit)
		application.abort(ctx, validated, request.Audit)
		if !cleaned {
			return Outcome{}, ErrAuthenticationUnavailable
		}
		return Outcome{}, ErrAuthenticationDenied
	}
	return outcome, nil
}

type callbackResolver struct {
	guard         sync.Mutex
	source        ConfigurationSource
	now           func() time.Time
	configuration ConfigurationSnapshot
	lookup        CallbackConfigurationLookup
	called        bool
	closed        bool
	resolved      bool
	unavailable   bool
	violated      bool
}

func (resolver *callbackResolver) ResolveSAMLCallbackConfiguration(
	ctx context.Context,
	transaction federatedsaml.CallbackConfigurationLookup,
) (federatedsaml.Configuration, error) {
	if resolver == nil {
		return federatedsaml.Configuration{}, ErrAuthenticationDenied
	}
	resolver.guard.Lock()
	if resolver.source == nil || resolver.now == nil {
		resolver.guard.Unlock()
		return federatedsaml.Configuration{}, ErrAuthenticationDenied
	}
	if resolver.called || resolver.closed {
		resolver.violated = true
		resolver.guard.Unlock()
		return federatedsaml.Configuration{}, ErrAuthenticationDenied
	}
	resolver.called = true
	source, nowSource := resolver.source, resolver.now
	resolver.guard.Unlock()
	if ctx == nil || ctx.Err() != nil {
		return federatedsaml.Configuration{}, ErrAuthenticationDenied
	}
	lookup := CallbackConfigurationLookup{Transaction: transaction}
	snapshot, err := source.ResolveDirectSAMLCallbackConfiguration(ctx, lookup)
	snapshot.Configuration = cloneConfigurationSnapshot(snapshot.Configuration)
	if err != nil || ctx.Err() != nil {
		resolver.guard.Lock()
		resolver.unavailable = true
		resolver.guard.Unlock()
		return federatedsaml.Configuration{}, ErrAuthenticationUnavailable
	}
	now := nowSource().UTC().Truncate(time.Microsecond)
	if snapshot.Lookup != lookup || snapshot.Configuration.Pins.Protocol != transaction.Pins ||
		!validConfigurationSnapshot(snapshot.Configuration, now) {
		return federatedsaml.Configuration{}, ErrAuthenticationDenied
	}
	resolver.guard.Lock()
	defer resolver.guard.Unlock()
	if resolver.closed {
		resolver.violated = true
		return federatedsaml.Configuration{}, ErrAuthenticationDenied
	}
	resolver.configuration = snapshot.Configuration
	resolver.lookup = lookup
	resolver.resolved = true
	return cloneConfiguration(snapshot.Configuration.Authentication), nil
}

func (resolver *callbackResolver) snapshot() (ConfigurationSnapshot, CallbackConfigurationLookup, bool, bool, bool) {
	if resolver == nil {
		return ConfigurationSnapshot{}, CallbackConfigurationLookup{}, false, false, true
	}
	resolver.guard.Lock()
	defer resolver.guard.Unlock()
	resolver.closed = true
	return cloneConfigurationSnapshot(resolver.configuration), resolver.lookup,
		resolver.resolved, resolver.unavailable, resolver.violated
}

type applicationConsumer struct {
	application     *Application
	configuration   ConfigurationSnapshot
	expected        AuthenticationProof
	audit           AuditContext
	called          atomic.Bool
	duplicate       atomic.Bool
	guard           sync.Mutex
	applied         bool
	committed       bool
	committedResult ApplyResult
	failureReason   CleanupReason
	outcome         Outcome
	err             error
}

func (consumer *applicationConsumer) ConsumeDirectSAML(
	ctx context.Context,
	consumption Consumption,
) (federatedsaml.ConsumptionResult, error) {
	if consumer == nil || consumer.application == nil {
		return federatedsaml.ConsumptionResult{Category: federatedsaml.ConsumerDenied}, ErrAuthenticationDenied
	}
	if !consumer.called.CompareAndSwap(false, true) {
		consumer.duplicate.Store(true)
		return federatedsaml.ConsumptionResult{Category: federatedsaml.ConsumerDenied}, ErrAuthenticationDenied
	}
	application := consumer.application
	now := application.currentTime()
	if !validInstant(now) || !sameProof(consumer.expected, consumption.Authentication) ||
		!validConsumptionForConfiguration(
			consumption, consumer.configuration.Pins, consumer.configuration.Authentication, now,
		) {
		application.reject(ctx, consumption, RejectMalformed, consumer.audit)
		consumer.set(Outcome{}, ErrAuthenticationDenied, false)
		return federatedsaml.ConsumptionResult{Category: federatedsaml.ConsumerDenied}, ErrAuthenticationDenied
	}
	plan, err := application.planner.plan(
		ctx, cloneConsumption(consumption), consumer.configuration.Pins,
		cloneConfiguration(consumer.configuration.Authentication), now,
	)
	plan = clonePlan(plan)
	defer clearPlan(&plan)
	if err != nil || !validAuthenticationPlan(plan, consumption, now) {
		reason := RejectDenied
		category := federatedsaml.ConsumerDenied
		mapped := ErrAuthenticationDenied
		if errors.Is(err, ErrAuthenticationUnavailable) || ctx != nil && ctx.Err() != nil {
			reason = RejectUnavailable
			category = federatedsaml.ConsumerUnavailable
			mapped = ErrAuthenticationUnavailable
		}
		application.reject(ctx, consumption, reason, consumer.audit)
		consumer.set(Outcome{}, mapped, false)
		return federatedsaml.ConsumptionResult{Category: category}, mapped
	}
	protected, err := protectSessionMaterial(application.keyring, consumption)
	if err != nil {
		application.reject(ctx, consumption, RejectUnavailable, consumer.audit)
		consumer.set(Outcome{}, ErrAuthenticationUnavailable, false)
		return federatedsaml.ConsumptionResult{Category: federatedsaml.ConsumerUnavailable}, ErrAuthenticationUnavailable
	}
	credentialRequest := CredentialRequest{Disposition: plan.Disposition, TOTP: plan.TOTP, IssuedAt: now}
	credential, err := application.credentials.ReserveDirectSAMLCredential(credentialRequest)
	if err != nil || credential == nil || !credential.validFor(credentialRequest) {
		if credential != nil {
			credential.Destroy()
		}
		clearProtectedMaterial(&protected)
		application.reject(ctx, consumption, RejectUnavailable, consumer.audit)
		consumer.set(Outcome{}, ErrAuthenticationUnavailable, false)
		return federatedsaml.ConsumptionResult{Category: federatedsaml.ConsumerUnavailable}, ErrAuthenticationUnavailable
	}
	defer credential.Destroy()
	apply := ApplyRequest{
		Authority: consumptionAuthority(consumption), Plan: clonePlan(plan),
		Session: credential.Session(), Continuation: credential.Continuation(),
		SessionAudience: SessionAudience, RecoveryRestricted: false,
		ProtectedSessionMaterial: protected, AppliedAt: now, Audit: consumer.audit,
	}
	apply.ProofDigest = applyProofDigest(apply)
	defer clearApplyRequest(&apply)
	if !validApplyRequest(apply) {
		application.reject(ctx, consumption, RejectMalformed, consumer.audit)
		consumer.set(Outcome{}, ErrAuthenticationDenied, false)
		return federatedsaml.ConsumptionResult{Category: federatedsaml.ConsumerDenied}, ErrAuthenticationDenied
	}
	submitted := cloneApplyRequest(apply)
	result, applyErr := application.apply.ApplyDirectSAML(ctx, submitted)
	clearApplyRequest(&submitted)
	validSuccess := applyErr == nil && validApplyResult(result, apply)
	validFailure := applyErr == nil && validApplyFailureResult(result, apply)
	ambiguousProjection := applyErr == nil && !validSuccess && !validFailure
	if applyErr != nil || ambiguousProjection {
		recovered, matched := application.recover(ctx, apply)
		if matched {
			result = recovered
			applyErr = nil
			validSuccess = true
			ambiguousProjection = false
		}
	}
	if applyErr != nil {
		application.reject(ctx, consumption, RejectUnavailable, consumer.audit)
		consumer.set(Outcome{}, ErrAuthenticationUnavailable, false)
		return federatedsaml.ConsumptionResult{Category: federatedsaml.ConsumerUnavailable}, ErrAuthenticationUnavailable
	}
	if ambiguousProjection {
		consumer.markCommitted(applyResultForRequest(apply, ApplySuccess))
		consumer.setFailure(CleanupInvalidOutcome)
		application.reject(ctx, consumption, RejectMalformed, consumer.audit)
		consumer.set(Outcome{}, ErrAuthenticationUnavailable, false)
		return federatedsaml.ConsumptionResult{Category: federatedsaml.ConsumerUnavailable}, ErrAuthenticationUnavailable
	}
	if !validSuccess {
		reason, category := applyFailure(result.Category)
		application.reject(ctx, consumption, reason, consumer.audit)
		consumer.set(Outcome{}, ErrAuthenticationDenied, false)
		return federatedsaml.ConsumptionResult{Category: category}, ErrAuthenticationDenied
	}
	consumer.markCommitted(result)
	browserCredential, released := credential.release(result.SessionID, result.ContinuationID)
	if !released || browserCredential == nil {
		if browserCredential != nil {
			browserCredential.Destroy()
		}
		consumer.setFailure(CleanupCredentialReleaseFailed)
		consumer.set(Outcome{}, ErrAuthenticationUnavailable, false)
		return federatedsaml.ConsumptionResult{Category: federatedsaml.ConsumerUnavailable}, ErrAuthenticationUnavailable
	}
	outcome := Outcome{
		Disposition: plan.Disposition, UserID: result.UserID, SessionID: result.SessionID,
		ContinuationID: result.ContinuationID, ReturnPath: result.ReturnPath, Credential: browserCredential,
	}
	outcome.delivery = newBrowserDeliveryAuthority(
		application.apply, application.now, application.recoveryTimeout, result, consumer.audit, outcome,
	)
	if outcome.delivery == nil {
		browserCredential.Destroy()
		consumer.setFailure(CleanupInvalidOutcome)
		consumer.set(Outcome{}, ErrAuthenticationUnavailable, false)
		return federatedsaml.ConsumptionResult{Category: federatedsaml.ConsumerUnavailable}, ErrAuthenticationUnavailable
	}
	consumer.set(outcome, nil, true)
	return federatedsaml.ConsumptionResult{Category: federatedsaml.ConsumerSuccess}, nil
}

func (consumer *applicationConsumer) set(outcome Outcome, err error, applied bool) {
	consumer.guard.Lock()
	defer consumer.guard.Unlock()
	consumer.outcome, consumer.err, consumer.applied = outcome, err, applied
}

func (consumer *applicationConsumer) markCommitted(result ApplyResult) {
	consumer.guard.Lock()
	defer consumer.guard.Unlock()
	consumer.committed = true
	consumer.committedResult = result
}

func (consumer *applicationConsumer) setFailure(reason CleanupReason) {
	consumer.guard.Lock()
	defer consumer.guard.Unlock()
	consumer.failureReason = reason
}

func (application *Application) recover(ctx context.Context, request ApplyRequest) (ApplyResult, bool) {
	recovery, cancel := context.WithTimeout(detachedContext(ctx), application.recoveryTimeout)
	defer cancel()
	lookup := RecoveryLookup{Request: cloneApplyRequest(request)}
	result, err := application.apply.RecoverDirectSAML(recovery, lookup)
	clearApplyRequest(&lookup.Request)
	if err != nil || !result.Matched || !validApplyResult(result.Result, request) {
		return ApplyResult{}, false
	}
	return result.Result, true
}

func (application *Application) reject(
	ctx context.Context,
	consumption Consumption,
	reason RejectReason,
	audit AuditContext,
) {
	rejectedAt := application.currentTime()
	if !validInstant(rejectedAt) {
		rejectedAt = consumption.ConsumedAt
	}
	for range 2 {
		cleanup, cancel := context.WithTimeout(detachedContext(ctx), application.recoveryTimeout)
		err := application.apply.RejectDirectSAML(cleanup, RejectRequest{
			Authority: consumptionAuthority(consumption), Reason: reason,
			RejectedAt: rejectedAt, Audit: audit,
		})
		cancel()
		if err == nil {
			return
		}
	}
}

func (application *Application) abort(ctx context.Context, validated *ValidatedCallback, audit AuditContext) {
	for range 2 {
		cleanup, cancel := context.WithTimeout(detachedContext(ctx), application.recoveryTimeout)
		err := application.protocol.AbortDirectSAMLCallback(cleanup, validated, audit)
		cancel()
		if err == nil {
			return
		}
	}
}

func (application *Application) cleanup(
	ctx context.Context,
	result ApplyResult,
	reason CleanupReason,
	audit AuditContext,
) bool {
	cleanedUpAt := application.currentTime()
	if !validInstant(cleanedUpAt) || cleanedUpAt.Before(result.AppliedAt) {
		cleanedUpAt = result.AppliedAt
	}
	request := CleanupRequest{Result: result, Reason: reason, CleanedUpAt: cleanedUpAt, Audit: audit}
	if !validCleanupRequest(request) {
		return false
	}
	for range 2 {
		cleanup, cancel := context.WithTimeout(detachedContext(ctx), application.recoveryTimeout)
		err := application.apply.CleanupDirectSAML(cleanup, request)
		cancel()
		if err == nil {
			return true
		}
	}
	return false
}

func detachedContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return context.WithoutCancel(ctx)
}

func (application *Application) operation(ctx context.Context) (context.Context, context.CancelFunc, bool) {
	if application == nil || ctx == nil || ctx.Err() != nil || application.operationTimeout <= 0 {
		return nil, nil, false
	}
	bounded, cancel := context.WithTimeout(ctx, application.operationTimeout)
	return bounded, cancel, true
}

func (application *Application) currentTime() time.Time {
	return application.now().UTC().Truncate(time.Microsecond)
}

func validAuthorizationStart(start AuthorizationStart, now time.Time) bool {
	return validAuthorizationStartShape(start) && start.ExpiresAt().After(now)
}

func validAuthorizationStartShape(start AuthorizationStart) bool {
	browserHandle := start.BrowserHandle()
	defer clear(browserHandle)
	if start.TransactionID() == (federatedsaml.TransactionID{}) || !canonicalBrowserHandle(browserHandle) ||
		!validInstant(start.ExpiresAt()) {
		return false
	}
	redirect, err := url.Parse(start.RedirectURL())
	return err == nil && redirect.Scheme == "https" && redirect.Host != "" && redirect.User == nil && redirect.Fragment == ""
}

var _ federatedsaml.CallbackConfigurationResolver = (*callbackResolver)(nil)
var _ Consumer = (*applicationConsumer)(nil)

func validOutcome(outcome Outcome) bool {
	return validUUIDv7(outcome.UserID) && validReturnPath(outcome.ReturnPath) && outcome.Credential != nil &&
		outcome.delivery != nil && outcome.delivery.matches(outcome) &&
		(outcome.Disposition == ImmediateSession && validUUIDv7(outcome.SessionID) &&
			outcome.ContinuationID == (identity.EntityID{}) ||
			outcome.Disposition == TOTPContinuation && outcome.SessionID == (identity.EntityID{}) &&
				validUUIDv7(outcome.ContinuationID))
}

func applyFailure(category ApplyCategory) (RejectReason, federatedsaml.AuthenticationConsumerCategory) {
	switch category {
	case ApplyProtocolReplay:
		return RejectDenied, federatedsaml.ConsumerReplay
	case ApplyStale:
		return RejectStale, federatedsaml.ConsumerStale
	case ApplyCollision:
		return RejectCollision, federatedsaml.ConsumerCollision
	default:
		return RejectDenied, federatedsaml.ConsumerDenied
	}
}

func clearProtectedMaterial(material *ProtectedSessionMaterial) {
	if material == nil {
		return
	}
	clear(material.Envelope.Nonce[:])
	clear(material.Envelope.Ciphertext)
	*material = ProtectedSessionMaterial{}
}

func clearApplyRequest(request *ApplyRequest) {
	if request == nil {
		return
	}
	clear(request.Plan.Subject.Envelope.Nonce[:])
	clear(request.Plan.Subject.Envelope.Ciphertext)
	clear(request.ProtectedSessionMaterial.Envelope.Nonce[:])
	clear(request.ProtectedSessionMaterial.Envelope.Ciphertext)
	request.ProofDigest = [32]byte{}
}

func clearPlan(plan *AuthenticationPlan) {
	if plan == nil {
		return
	}
	clear(plan.Subject.Envelope.Nonce[:])
	clear(plan.Subject.Envelope.Ciphertext)
	plan.Subject.Envelope.Ciphertext = nil
}
