// Package platformsamladapter contains the direct-platform SAML protocol,
// protected-key, metadata, and browser-transport adapters. It deliberately
// has no SQL, generated HTTP contract, tenant fallback, or composition root.
package platformsamladapter

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

var (
	ErrInvalidOptions      = errors.New("invalid direct platform SAML adapter options")
	ErrProtocolRejected    = errors.New("direct platform SAML protocol rejected")
	ErrProtocolUnavailable = errors.New("direct platform SAML protocol unavailable")
)

type DirectSAMLCreateTransactionRequest struct {
	Protocol federatedsaml.CreateTransactionRequest
	Grant    platformsamlauth.StartGrant
}

func (request DirectSAMLCreateTransactionRequest) String() string {
	return fmt.Sprintf(
		"platformsamladapter.DirectSAMLCreateTransactionRequest{transaction:%t,run:%t,version:%t,pins:%q,audit:%q,material:[REDACTED]}",
		validTransactionID(request.Protocol.Current.ID), validUUIDv7(request.Protocol.Begin.OperationRunID),
		request.Protocol.Current.Version != 0, request.Grant.Pins.String(), request.Grant.Authority.Audit.String(),
	)
}

func (request DirectSAMLCreateTransactionRequest) GoString() string { return request.String() }

// DirectSAMLCreateRecoveryLookup is byte-for-byte the original create proof.
// Persistence may use it only to prove an ambiguously committed exact create;
// it must never create a row or admit a second start attempt.
type DirectSAMLCreateRecoveryLookup struct {
	Create DirectSAMLCreateTransactionRequest
}

func (lookup DirectSAMLCreateRecoveryLookup) String() string {
	return fmt.Sprintf("platformsamladapter.DirectSAMLCreateRecoveryLookup{create:%q}", lookup.Create.String())
}

func (lookup DirectSAMLCreateRecoveryLookup) GoString() string { return lookup.String() }

type DirectSAMLCreateReceipt struct {
	TransactionID  federatedsaml.TransactionID
	OperationRunID identity.EntityID
	Version        uint64
	State          federatedsaml.TransactionState
	Pins           platformsamlauth.DirectSAMLPins
}

func (receipt DirectSAMLCreateReceipt) String() string {
	return fmt.Sprintf(
		"platformsamladapter.DirectSAMLCreateReceipt{transaction:%t,run:%t,version:%t,state:%q,pins:%q}",
		validTransactionID(receipt.TransactionID), validUUIDv7(receipt.OperationRunID), receipt.Version != 0,
		receipt.State, receipt.Pins.String(),
	)
}

func (receipt DirectSAMLCreateReceipt) GoString() string { return receipt.String() }

type DirectSAMLTransactionSnapshot struct {
	Pending federatedsaml.PendingTransaction
	Pins    platformsamlauth.DirectSAMLPins
}

func (snapshot DirectSAMLTransactionSnapshot) String() string {
	return fmt.Sprintf(
		"platformsamladapter.DirectSAMLTransactionSnapshot{transaction:%t,run:%t,version:%t,state:%q,pins:%q,material:[REDACTED]}",
		validTransactionID(snapshot.Pending.ID), validUUIDv7(snapshot.Pending.MaterialID), snapshot.Pending.Version != 0,
		snapshot.Pending.State, snapshot.Pins.String(),
	)
}

func (snapshot DirectSAMLTransactionSnapshot) GoString() string { return snapshot.String() }

type DirectSAMLAbortReason string

const (
	AbortCallbackRejected    DirectSAMLAbortReason = "callback_rejected"
	AbortApplicationRejected DirectSAMLAbortReason = "application_rejected"
)

type DirectSAMLAbortRequest struct {
	Transaction    federatedsaml.CallbackConfigurationLookup
	OperationRunID identity.EntityID
	Pins           platformsamlauth.DirectSAMLPins
	Reason         DirectSAMLAbortReason
	FailedAt       time.Time
	Audit          platformsamlauth.AuditContext
}

func (request DirectSAMLAbortRequest) String() string {
	return fmt.Sprintf(
		"platformsamladapter.DirectSAMLAbortRequest{transaction:%t,run:%t,version:%t,pins:%q,reason:%q,failed:%t,audit:%q}",
		validTransactionID(request.Transaction.TransactionID), validUUIDv7(request.OperationRunID),
		request.Transaction.ExpectedVersion != 0, request.Pins.String(), request.Reason,
		!request.FailedAt.IsZero(), request.Audit.String(),
	)
}

func (request DirectSAMLAbortRequest) GoString() string { return request.String() }

type DirectSAMLAbortDisposition string

const (
	AbortTerminalized    DirectSAMLAbortDisposition = "terminalized"
	AbortAlreadyTerminal DirectSAMLAbortDisposition = "already_terminal"
)

// DirectSAMLAbortReceipt proves either the pending-to-failed protocol CAS or
// an exact already-terminal row. In particular, AlreadyTerminal+Completed is
// a no-op: revoking an application session/continuation belongs exclusively
// to platformsamlauth.AtomicApplyPort.CleanupDirectSAML.
type DirectSAMLAbortReceipt struct {
	Disposition    DirectSAMLAbortDisposition
	TransactionID  federatedsaml.TransactionID
	OperationRunID identity.EntityID
	Version        uint64
	State          federatedsaml.TransactionState
	Pins           platformsamlauth.DirectSAMLPins
}

func (receipt DirectSAMLAbortReceipt) String() string {
	return fmt.Sprintf(
		"platformsamladapter.DirectSAMLAbortReceipt{disposition:%q,transaction:%t,run:%t,version:%t,state:%q,pins:%q}",
		receipt.Disposition, validTransactionID(receipt.TransactionID), validUUIDv7(receipt.OperationRunID),
		receipt.Version != 0, receipt.State, receipt.Pins.String(),
	)
}

func (receipt DirectSAMLAbortReceipt) GoString() string { return receipt.String() }

// DirectSAMLTransactionPersistence is the narrow future persistence port.
// Create and RecoverCreate form one idempotency family: RecoverCreate is
// read-only and proves an exact create after a malformed response or an
// ambiguous commit error. Lookup returns the full floor pins although the
// kernel consumes only Pins.Protocol. Abort is idempotent and never changes a
// completed application result into a cancellation.
type DirectSAMLTransactionPersistence interface {
	CreateDirectPlatformSAMLTransaction(context.Context, DirectSAMLCreateTransactionRequest) (DirectSAMLCreateReceipt, error)
	RecoverDirectPlatformSAMLCreate(context.Context, DirectSAMLCreateRecoveryLookup) (DirectSAMLCreateReceipt, error)
	LookupDirectPlatformSAMLTransaction(context.Context, federatedsaml.LookupTransactionRequest) (DirectSAMLTransactionSnapshot, error)
	AbortDirectPlatformSAMLTransaction(context.Context, DirectSAMLAbortRequest) (DirectSAMLAbortReceipt, error)
}

type ProtocolAdapterOptions struct {
	Persistence      DirectSAMLTransactionPersistence
	Keys             federatedsaml.DirectPlatformSPKeySource
	SessionProtector federatedsaml.SessionMaterialProtector
	Limits           federatedsaml.Limits
	TransactionTTL   time.Duration
	OperationTimeout time.Duration
	RecoveryTimeout  time.Duration
	AbortTimeout     time.Duration
	Now              func() time.Time
}

type protocolKernel interface {
	StartAuthentication(context.Context, federatedsaml.StartRequest) (federatedsaml.AuthorizationStart, error)
	ValidateCallbackResolved(context.Context, federatedsaml.ResolvedCallbackRequest, federatedsaml.CallbackConfigurationResolver) (*federatedsaml.ValidatedAuthentication, error)
	Consume(context.Context, *federatedsaml.ValidatedAuthentication, federatedsaml.AuthenticationConsumer) (federatedsaml.ConsumptionResult, error)
	BuildStoredLogoutRequest(context.Context, federatedsaml.StoredLogoutBuildRequest) (federatedsaml.LogoutRequest, error)
}

type protocolCrypto struct {
	signer    federatedsaml.RedirectSigner
	verifier  federatedsaml.XMLSignatureVerifier
	decrypter federatedsaml.AssertionDecrypter
}

type ProtocolAdapter struct {
	kernel       protocolKernel
	repository   *directSAMLTransactionRepository
	persistence  DirectSAMLTransactionPersistence
	now          func() time.Time
	abortTimeout time.Duration

	callbacksGuard sync.Mutex
	callbacks      map[*platformsamlauth.ValidatedCallback]callbackAuthority
}

func NewProtocolAdapter(options ProtocolAdapterOptions) (*ProtocolAdapter, error) {
	if options.Keys == nil {
		return nil, ErrInvalidOptions
	}
	cryptoAdapter, err := federatedsaml.NewDirectPlatformLibraryCryptoAdapter(options.Keys)
	if err != nil {
		return nil, ErrInvalidOptions
	}
	return newProtocolAdapter(options, protocolCrypto{
		signer: cryptoAdapter, verifier: cryptoAdapter, decrypter: cryptoAdapter,
	})
}

func newProtocolAdapter(options ProtocolAdapterOptions, crypto protocolCrypto) (*ProtocolAdapter, error) {
	if options.Persistence == nil || options.SessionProtector == nil || options.Now == nil ||
		crypto.signer == nil || crypto.verifier == nil || crypto.decrypter == nil ||
		options.RecoveryTimeout < 10*time.Millisecond || options.RecoveryTimeout > 5*time.Second ||
		options.RecoveryTimeout%time.Microsecond != 0 ||
		options.AbortTimeout < 10*time.Millisecond || options.AbortTimeout > 5*time.Second ||
		options.AbortTimeout%time.Microsecond != 0 {
		return nil, ErrInvalidOptions
	}
	repository := &directSAMLTransactionRepository{
		persistence:     options.Persistence,
		recoveryTimeout: options.RecoveryTimeout,
		starts:          make(map[identity.EntityID]*startInvocation),
	}
	kernel, err := federatedsaml.New(federatedsaml.Options{
		Authority:          federatedsaml.DirectPlatformCeremonyAuthority,
		Transactions:       repository,
		RedirectSigner:     crypto.signer,
		SignatureVerifier:  crypto.verifier,
		AssertionDecrypter: crypto.decrypter,
		SessionProtector:   options.SessionProtector,
		Limits:             options.Limits,
		TransactionTTL:     options.TransactionTTL,
		OperationTimeout:   options.OperationTimeout,
	})
	if err != nil {
		return nil, ErrInvalidOptions
	}
	return &ProtocolAdapter{
		kernel: kernel, repository: repository, persistence: options.Persistence,
		now: options.Now, abortTimeout: options.AbortTimeout,
		callbacks: make(map[*platformsamlauth.ValidatedCallback]callbackAuthority),
	}, nil
}

func (adapter *ProtocolAdapter) String() string {
	return fmt.Sprintf(
		"platformsamladapter.ProtocolAdapter{authority:direct_platform,configured:%t,material:[REDACTED]}",
		adapter != nil && adapter.kernel != nil && adapter.repository != nil && adapter.persistence != nil,
	)
}

func (adapter *ProtocolAdapter) GoString() string { return adapter.String() }

// BuildStoredLogoutRequest reuses the direct-platform authority and pinned
// key source owned by this protocol adapter. It never consults current
// provider readiness or mutable metadata.
func (adapter *ProtocolAdapter) BuildStoredLogoutRequest(
	ctx context.Context,
	request federatedsaml.StoredLogoutBuildRequest,
) (federatedsaml.LogoutRequest, error) {
	if adapter == nil || adapter.kernel == nil || ctx == nil || ctx.Err() != nil {
		return federatedsaml.LogoutRequest{}, ErrInvalidOptions
	}
	return adapter.kernel.BuildStoredLogoutRequest(ctx, request)
}

func (adapter *ProtocolAdapter) StartDirectSAML(
	ctx context.Context,
	request platformsamlauth.StartProtocolRequest,
) (platformsamlauth.AuthorizationStart, error) {
	if adapter == nil || adapter.kernel == nil || adapter.repository == nil || !activeContext(ctx) ||
		!validStartRequest(request) {
		return platformsamlauth.AuthorizationStart{}, platformsamlauth.ErrAuthenticationDenied
	}
	now, timeOK := canonicalNow(adapter.now)
	if !timeOK || federatedsaml.ValidatePinnedConfiguration(
		request.Protocol.Configuration, request.Grant.Pins.Protocol, now,
	) != nil {
		return platformsamlauth.AuthorizationStart{}, platformsamlauth.ErrAuthenticationDenied
	}
	invocation, release, ok := adapter.repository.registerStart(request.Grant)
	if !ok {
		return platformsamlauth.AuthorizationStart{}, platformsamlauth.ErrAuthenticationDenied
	}
	defer release()
	protocol := cloneStartRequest(request.Protocol)
	defer clearStartRequest(&protocol)
	started, err := adapter.kernel.StartAuthentication(ctx, protocol)
	if err != nil {
		clear(started.BrowserHandle())
		return platformsamlauth.AuthorizationStart{}, platformsamlauth.ErrAuthenticationUnavailable
	}
	receipt, created := invocation.receiptSnapshot()
	if !created || receipt.TransactionID != started.TransactionID() {
		clear(started.BrowserHandle())
		return platformsamlauth.AuthorizationStart{}, platformsamlauth.ErrAuthenticationDenied
	}
	result, err := platformsamlauth.NewAuthorizationStart(started)
	if err != nil {
		clear(started.BrowserHandle())
		return platformsamlauth.AuthorizationStart{}, platformsamlauth.ErrAuthenticationDenied
	}
	return result, nil
}

func (adapter *ProtocolAdapter) ValidateDirectSAMLCallbackResolved(
	ctx context.Context,
	request platformsamlauth.CallbackRequest,
	resolver federatedsaml.CallbackConfigurationResolver,
) (*platformsamlauth.ValidatedCallback, error) {
	if adapter == nil || adapter.kernel == nil || adapter.repository == nil || resolver == nil ||
		!activeContext(ctx) || !validAudit(request.Audit) || request.Protocol.MediaType == "" ||
		len(request.Protocol.RawForm) == 0 || !validBrowserHandle(request.Protocol.BrowserHandle) {
		return nil, platformsamlauth.ErrAuthenticationDenied
	}
	capture := &callbackCapture{}
	operation := context.WithValue(ctx, callbackCaptureContextKey{}, capture)
	guardedResolver := &singleCallbackResolver{target: resolver, capture: capture}
	protocol := federatedsaml.ResolvedCallbackRequest{
		MediaType:     request.Protocol.MediaType,
		RawForm:       append([]byte(nil), request.Protocol.RawForm...),
		BrowserHandle: append([]byte(nil), request.Protocol.BrowserHandle...),
	}
	defer clear(protocol.RawForm)
	defer clear(protocol.BrowserHandle)
	authentication, validationErr := adapter.kernel.ValidateCallbackResolved(operation, protocol, guardedResolver)
	lookup, resolved, violated, resolverUnavailable := guardedResolver.close()
	snapshot, captured, captureViolated := capture.snapshot()
	validCapture := captured && !captureViolated && resolved && !violated &&
		lookup.TransactionID == snapshot.Pending.ID && lookup.ExpectedVersion == snapshot.Pending.Version &&
		lookup.Pins == snapshot.Pins.Protocol
	if validationErr != nil || authentication == nil || !validCapture {
		aborted := true
		if captured {
			aborted = adapter.abortSnapshot(ctx, snapshot, request.Audit, AbortCallbackRejected)
		}
		if captured && !aborted || resolverUnavailable || capture.unavailableSnapshot() || ctx.Err() != nil ||
			errors.Is(validationErr, context.Canceled) || errors.Is(validationErr, context.DeadlineExceeded) {
			return nil, platformsamlauth.ErrAuthenticationUnavailable
		}
		return nil, platformsamlauth.ErrAuthenticationDenied
	}
	validated, err := platformsamlauth.NewValidatedCallback(authentication, lookup)
	if err != nil || !adapter.registerCallback(validated, callbackAuthority{snapshot: snapshot}) {
		_ = adapter.abortSnapshot(ctx, snapshot, request.Audit, AbortCallbackRejected)
		return nil, platformsamlauth.ErrAuthenticationDenied
	}
	return validated, nil
}

func (adapter *ProtocolAdapter) ConsumeDirectSAML(
	ctx context.Context,
	validated *platformsamlauth.ValidatedCallback,
	consumer platformsamlauth.Consumer,
) (federatedsaml.ConsumptionResult, error) {
	if adapter == nil || adapter.kernel == nil || consumer == nil || validated == nil || !activeContext(ctx) {
		return federatedsaml.ConsumptionResult{}, platformsamlauth.ErrAuthenticationDenied
	}
	authority, ok := adapter.callbackAuthority(validated)
	if !ok || validated.Transaction().Transaction.TransactionID != authority.snapshot.Pending.ID ||
		validated.Transaction().Transaction.ExpectedVersion != authority.snapshot.Pending.Version ||
		validated.Transaction().Transaction.Pins != authority.snapshot.Pins.Protocol {
		return federatedsaml.ConsumptionResult{}, platformsamlauth.ErrAuthenticationDenied
	}
	bridge := &singleConsumer{target: consumer, authority: authority}
	result, err := adapter.kernel.Consume(ctx, validated.KernelAuthentication(), bridge)
	bridge.closed.Store(true)
	called, duplicate := bridge.called.Load(), bridge.duplicate.Load()
	if err == nil && result.Category == federatedsaml.ConsumerSuccess && called && !duplicate {
		adapter.removeCallback(validated)
		return result, nil
	}
	if err != nil && !errors.Is(err, federatedsaml.ErrConsumptionRejected) {
		return result, platformsamlauth.ErrAuthenticationUnavailable
	}
	return result, platformsamlauth.ErrAuthenticationDenied
}

func (adapter *ProtocolAdapter) AbortDirectSAMLCallback(
	ctx context.Context,
	validated *platformsamlauth.ValidatedCallback,
	audit platformsamlauth.AuditContext,
) error {
	if adapter == nil || validated == nil || !validAudit(audit) {
		return platformsamlauth.ErrAuthenticationDenied
	}
	authority, ok := adapter.callbackAuthority(validated)
	if !ok || validated.Transaction().Transaction.TransactionID != authority.snapshot.Pending.ID ||
		validated.Transaction().Transaction.ExpectedVersion != authority.snapshot.Pending.Version ||
		validated.Transaction().Transaction.Pins != authority.snapshot.Pins.Protocol {
		return platformsamlauth.ErrAuthenticationDenied
	}
	if !adapter.abortSnapshot(ctx, authority.snapshot, audit, AbortApplicationRejected) {
		return platformsamlauth.ErrAuthenticationUnavailable
	}
	adapter.removeCallback(validated)
	return nil
}

func (adapter *ProtocolAdapter) abortSnapshot(
	ctx context.Context,
	snapshot DirectSAMLTransactionSnapshot,
	audit platformsamlauth.AuditContext,
	reason DirectSAMLAbortReason,
) bool {
	if adapter == nil || adapter.persistence == nil || ctx == nil || !validAudit(audit) ||
		!validDirectPins(snapshot.Pins) || reason != AbortCallbackRejected && reason != AbortApplicationRejected {
		return false
	}
	now, ok := canonicalNow(adapter.now)
	if !ok {
		return false
	}
	request := DirectSAMLAbortRequest{
		Transaction: federatedsaml.CallbackConfigurationLookup{
			TransactionID: snapshot.Pending.ID, ExpectedVersion: snapshot.Pending.Version, Pins: snapshot.Pins.Protocol,
		},
		OperationRunID: snapshot.Pending.MaterialID, Pins: snapshot.Pins,
		Reason: reason, FailedAt: now, Audit: audit,
	}
	for range 2 {
		operation, cancel := context.WithTimeout(context.WithoutCancel(ctx), adapter.abortTimeout)
		receipt, err := adapter.persistence.AbortDirectPlatformSAMLTransaction(operation, request)
		operationErr := operation.Err()
		cancel()
		if err == nil && validAbortReceipt(receipt, request) {
			return true
		}
		if operationErr != nil && !errors.Is(operationErr, context.DeadlineExceeded) {
			return false
		}
	}
	return false
}

type startInvocation struct {
	guard   sync.Mutex
	grant   platformsamlauth.StartGrant
	receipt DirectSAMLCreateReceipt
	created bool
}

func (invocation *startInvocation) setReceipt(receipt DirectSAMLCreateReceipt) {
	invocation.guard.Lock()
	defer invocation.guard.Unlock()
	invocation.receipt = receipt
	invocation.created = true
}

func (invocation *startInvocation) receiptSnapshot() (DirectSAMLCreateReceipt, bool) {
	invocation.guard.Lock()
	defer invocation.guard.Unlock()
	return invocation.receipt, invocation.created
}

type directSAMLTransactionRepository struct {
	persistence     DirectSAMLTransactionPersistence
	recoveryTimeout time.Duration
	startsGuard     sync.Mutex
	starts          map[identity.EntityID]*startInvocation
}

func (repository *directSAMLTransactionRepository) registerStart(
	grant platformsamlauth.StartGrant,
) (*startInvocation, func(), bool) {
	if repository == nil || repository.persistence == nil || !validDirectPins(grant.Pins) ||
		!validBegin(grant.Authority.Lookup.Begin) {
		return nil, func() {}, false
	}
	runID := grant.Authority.Lookup.Begin.OperationRunID
	repository.startsGuard.Lock()
	if _, exists := repository.starts[runID]; exists {
		repository.startsGuard.Unlock()
		return nil, func() {}, false
	}
	invocation := &startInvocation{grant: grant}
	repository.starts[runID] = invocation
	repository.startsGuard.Unlock()
	var once sync.Once
	release := func() {
		once.Do(func() {
			repository.startsGuard.Lock()
			if repository.starts[runID] == invocation {
				delete(repository.starts, runID)
			}
			repository.startsGuard.Unlock()
		})
	}
	return invocation, release, true
}

func (repository *directSAMLTransactionRepository) claimStart(runID identity.EntityID) (*startInvocation, bool) {
	repository.startsGuard.Lock()
	defer repository.startsGuard.Unlock()
	invocation, ok := repository.starts[runID]
	if ok {
		delete(repository.starts, runID)
	}
	return invocation, ok
}

func (repository *directSAMLTransactionRepository) CreateReplacing(
	ctx context.Context,
	request federatedsaml.CreateTransactionRequest,
) error {
	if repository == nil || repository.persistence == nil || !activeContext(ctx) {
		return ErrProtocolUnavailable
	}
	invocation, ok := repository.claimStart(request.Begin.OperationRunID)
	if !ok || !validCreateForGrant(request, invocation.grant) {
		return ErrProtocolRejected
	}
	create := DirectSAMLCreateTransactionRequest{Protocol: request, Grant: invocation.grant}
	receipt, createErr := repository.persistence.CreateDirectPlatformSAMLTransaction(ctx, create)
	if createErr == nil && validCreateReceipt(receipt, create) {
		invocation.setReceipt(receipt)
		return nil
	}
	recoveryContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), repository.recoveryTimeout)
	defer cancel()
	recovered, recoverErr := repository.persistence.RecoverDirectPlatformSAMLCreate(
		recoveryContext, DirectSAMLCreateRecoveryLookup{Create: create},
	)
	if recoverErr != nil || recoveryContext.Err() != nil || !validCreateReceipt(recovered, create) {
		return ErrProtocolUnavailable
	}
	invocation.setReceipt(recovered)
	return nil
}

func (repository *directSAMLTransactionRepository) Lookup(
	ctx context.Context,
	request federatedsaml.LookupTransactionRequest,
) (federatedsaml.PendingTransaction, error) {
	if repository == nil || repository.persistence == nil || !activeContext(ctx) ||
		request.RelayStateDigest == ([32]byte{}) || request.BrowserDigest == ([32]byte{}) ||
		request.RelayStateDigest == request.BrowserDigest || !validInstant(request.ObservedAt) {
		return federatedsaml.PendingTransaction{}, ErrProtocolRejected
	}
	snapshot, err := repository.persistence.LookupDirectPlatformSAMLTransaction(ctx, request)
	capture, _ := ctx.Value(callbackCaptureContextKey{}).(*callbackCapture)
	if err != nil || !activeContext(ctx) || !validPendingForLookup(snapshot.Pending, snapshot.Pins, request) {
		if capture != nil {
			capture.markUnavailable()
		}
		return federatedsaml.PendingTransaction{}, ErrProtocolUnavailable
	}
	if capture != nil {
		if !capture.recordLookup(snapshot) {
			return federatedsaml.PendingTransaction{}, ErrProtocolRejected
		}
	}
	return snapshot.Pending, nil
}

func validCreateForGrant(request federatedsaml.CreateTransactionRequest, grant platformsamlauth.StartGrant) bool {
	current := request.Current
	return validBegin(request.Begin) && request.Begin == grant.Authority.Lookup.Begin &&
		current.MaterialID == request.Begin.OperationRunID && validTransactionID(current.ID) &&
		validText(current.RequestID, 1024, false) && current.Pins == grant.Pins.Protocol &&
		current.State == federatedsaml.TransactionPending && current.Version == 1 &&
		validInstant(current.CreatedAt) && validInstant(current.ExpiresAt) &&
		current.ExpiresAt.Sub(current.CreatedAt) >= time.Minute && current.ExpiresAt.Sub(current.CreatedAt) <= 15*time.Minute &&
		validReturnPath(current.ReturnPath) && current.ReturnPath == grant.Authority.ReturnPath &&
		current.RelayStateDigest != ([32]byte{}) && current.BrowserDigest != ([32]byte{}) &&
		current.RelayStateDigest != current.BrowserDigest &&
		request.HasPreviousBrowserBinding == (request.PreviousBrowserDigest != ([32]byte{})) &&
		(!request.HasPreviousBrowserBinding || request.PreviousBrowserDigest != current.BrowserDigest)
}

func validCreateReceipt(receipt DirectSAMLCreateReceipt, request DirectSAMLCreateTransactionRequest) bool {
	return receipt.TransactionID == request.Protocol.Current.ID &&
		receipt.OperationRunID == request.Protocol.Begin.OperationRunID &&
		receipt.Version == request.Protocol.Current.Version && receipt.State == federatedsaml.TransactionPending &&
		receipt.Pins == request.Grant.Pins && validDirectPins(receipt.Pins)
}

func validAbortReceipt(receipt DirectSAMLAbortReceipt, request DirectSAMLAbortRequest) bool {
	if receipt.TransactionID != request.Transaction.TransactionID || receipt.OperationRunID != request.OperationRunID ||
		receipt.Pins != request.Pins || !validDirectPins(receipt.Pins) ||
		receipt.Version != request.Transaction.ExpectedVersion+1 || !validRevision(receipt.Version) {
		return false
	}
	switch receipt.Disposition {
	case AbortTerminalized:
		return receipt.State == federatedsaml.TransactionFailed
	case AbortAlreadyTerminal:
		return receipt.State == federatedsaml.TransactionFailed || receipt.State == federatedsaml.TransactionExpired ||
			receipt.State == federatedsaml.TransactionCompleted
	default:
		return false
	}
}

type callbackCaptureContextKey struct{}

type callbackCapture struct {
	guard                sync.Mutex
	value                DirectSAMLTransactionSnapshot
	seen                 bool
	expectRevalidation   bool
	revalidationVerified bool
	violated             bool
	unavailable          bool
}

func (capture *callbackCapture) markUnavailable() {
	capture.guard.Lock()
	capture.unavailable = true
	capture.guard.Unlock()
}

func (capture *callbackCapture) unavailableSnapshot() bool {
	capture.guard.Lock()
	defer capture.guard.Unlock()
	return capture.unavailable
}

func (capture *callbackCapture) observe(snapshot DirectSAMLTransactionSnapshot) {
	capture.guard.Lock()
	defer capture.guard.Unlock()
	if capture.seen {
		capture.violated = true
		return
	}
	capture.value = snapshot
	capture.seen = true
}

// expectKernelRevalidation opens exactly one same-snapshot lookup for the
// kernel's inner ValidateCallback pass. It does not permit the resolver or any
// other caller to observe transaction authority a second time.
func (capture *callbackCapture) expectKernelRevalidation(lookup federatedsaml.CallbackConfigurationLookup) bool {
	capture.guard.Lock()
	defer capture.guard.Unlock()
	if !capture.seen || capture.violated || capture.expectRevalidation || capture.revalidationVerified ||
		lookup.TransactionID != capture.value.Pending.ID || lookup.ExpectedVersion != capture.value.Pending.Version ||
		lookup.Pins != capture.value.Pins.Protocol {
		capture.violated = true
		return false
	}
	capture.expectRevalidation = true
	return true
}

func (capture *callbackCapture) recordLookup(snapshot DirectSAMLTransactionSnapshot) bool {
	capture.guard.Lock()
	defer capture.guard.Unlock()
	if !capture.seen {
		capture.value = snapshot
		capture.seen = true
		return true
	}
	if !capture.expectRevalidation || capture.revalidationVerified || capture.value != snapshot {
		capture.violated = true
		return false
	}
	capture.expectRevalidation = false
	capture.revalidationVerified = true
	return true
}

func (capture *callbackCapture) snapshot() (DirectSAMLTransactionSnapshot, bool, bool) {
	capture.guard.Lock()
	defer capture.guard.Unlock()
	return capture.value, capture.seen, capture.violated || !capture.revalidationVerified
}

type singleCallbackResolver struct {
	guard       sync.Mutex
	target      federatedsaml.CallbackConfigurationResolver
	lookup      federatedsaml.CallbackConfigurationLookup
	called      bool
	closed      bool
	violated    bool
	capture     *callbackCapture
	unavailable bool
}

func (resolver *singleCallbackResolver) ResolveSAMLCallbackConfiguration(
	ctx context.Context,
	lookup federatedsaml.CallbackConfigurationLookup,
) (federatedsaml.Configuration, error) {
	resolver.guard.Lock()
	if resolver.target == nil || resolver.closed || resolver.called || !validCallbackLookup(lookup) {
		resolver.violated = true
		resolver.guard.Unlock()
		return federatedsaml.Configuration{}, ErrProtocolRejected
	}
	resolver.called = true
	resolver.lookup = lookup
	target := resolver.target
	resolver.guard.Unlock()
	configuration, err := target.ResolveSAMLCallbackConfiguration(ctx, lookup)
	if err != nil {
		resolver.guard.Lock()
		resolver.unavailable = errors.Is(err, platformsamlauth.ErrAuthenticationUnavailable) ||
			ctx == nil || ctx.Err() != nil
		resolver.guard.Unlock()
		return federatedsaml.Configuration{}, err
	}
	if configuration.Authority != federatedsaml.DirectPlatformCeremonyAuthority ||
		configuration.Provider != lookup.Pins.Provider || configuration.BindingID != (identity.EntityID{}) ||
		configuration.PlatformLoginRevision != lookup.Pins.PlatformLoginRevision ||
		len(configuration.Mapping.Scalars) != 0 || len(configuration.Mapping.Profiles) != 0 ||
		configuration.Mapping.Groups != nil {
		return federatedsaml.Configuration{}, ErrProtocolRejected
	}
	if resolver.capture == nil || !resolver.capture.expectKernelRevalidation(lookup) {
		return federatedsaml.Configuration{}, ErrProtocolRejected
	}
	return cloneConfiguration(configuration), nil
}

func (resolver *singleCallbackResolver) close() (federatedsaml.CallbackConfigurationLookup, bool, bool, bool) {
	resolver.guard.Lock()
	defer resolver.guard.Unlock()
	resolver.closed = true
	return resolver.lookup, resolver.called, resolver.violated, resolver.unavailable
}

type callbackAuthority struct {
	snapshot DirectSAMLTransactionSnapshot
}

func (adapter *ProtocolAdapter) registerCallback(
	callback *platformsamlauth.ValidatedCallback,
	authority callbackAuthority,
) bool {
	if callback == nil || !validDirectPins(authority.snapshot.Pins) || !validInstant(authority.snapshot.Pending.ExpiresAt) {
		return false
	}
	adapter.callbacksGuard.Lock()
	defer adapter.callbacksGuard.Unlock()
	adapter.pruneCallbacksLocked()
	if len(adapter.callbacks) >= 1024 {
		return false
	}
	if _, exists := adapter.callbacks[callback]; exists {
		return false
	}
	adapter.callbacks[callback] = authority
	return true
}

func (adapter *ProtocolAdapter) callbackAuthority(
	callback *platformsamlauth.ValidatedCallback,
) (callbackAuthority, bool) {
	adapter.callbacksGuard.Lock()
	defer adapter.callbacksGuard.Unlock()
	adapter.pruneCallbacksLocked()
	authority, ok := adapter.callbacks[callback]
	return authority, ok
}

func (adapter *ProtocolAdapter) removeCallback(callback *platformsamlauth.ValidatedCallback) {
	adapter.callbacksGuard.Lock()
	delete(adapter.callbacks, callback)
	adapter.callbacksGuard.Unlock()
}

func (adapter *ProtocolAdapter) pruneCallbacksLocked() {
	now, ok := canonicalNow(adapter.now)
	if !ok {
		return
	}
	for callback, authority := range adapter.callbacks {
		if !now.Before(authority.snapshot.Pending.ExpiresAt) {
			delete(adapter.callbacks, callback)
		}
	}
}

type singleConsumer struct {
	target    platformsamlauth.Consumer
	authority callbackAuthority
	called    atomic.Bool
	duplicate atomic.Bool
	closed    atomic.Bool
}

func (consumer *singleConsumer) ConsumeSAML(
	ctx context.Context,
	request federatedsaml.ConsumptionRequest,
) (federatedsaml.ConsumptionResult, error) {
	if consumer == nil || consumer.target == nil || consumer.closed.Load() ||
		!consumer.called.CompareAndSwap(false, true) {
		if consumer != nil {
			consumer.duplicate.Store(true)
		}
		return federatedsaml.ConsumptionResult{Category: federatedsaml.ConsumerDenied}, ErrProtocolRejected
	}
	consumption, err := platformsamlauth.NewConsumption(request)
	snapshot := consumer.authority.snapshot
	if err != nil || consumption.TransactionID != snapshot.Pending.ID ||
		consumption.MaterialID != snapshot.Pending.MaterialID || consumption.ExpectedVersion != snapshot.Pending.Version ||
		consumption.Pins != snapshot.Pins.Protocol || consumption.ReturnPath != snapshot.Pending.ReturnPath {
		return federatedsaml.ConsumptionResult{Category: federatedsaml.ConsumerDenied}, ErrProtocolRejected
	}
	result, err := consumer.target.ConsumeDirectSAML(ctx, consumption)
	if err != nil || !validConsumerCategory(result.Category) {
		return result, err
	}
	return result, nil
}

func validConsumerCategory(category federatedsaml.AuthenticationConsumerCategory) bool {
	switch category {
	case federatedsaml.ConsumerSuccess, federatedsaml.ConsumerReplay, federatedsaml.ConsumerStale,
		federatedsaml.ConsumerCollision, federatedsaml.ConsumerDenied, federatedsaml.ConsumerUnavailable:
		return true
	default:
		return false
	}
}

func activeContext(ctx context.Context) bool { return ctx != nil && ctx.Err() == nil }

var (
	_ platformsamlauth.ProtocolPort               = (*ProtocolAdapter)(nil)
	_ federatedsaml.TransactionRepository         = (*directSAMLTransactionRepository)(nil)
	_ federatedsaml.CallbackConfigurationResolver = (*singleCallbackResolver)(nil)
	_ federatedsaml.AuthenticationConsumer        = (*singleConsumer)(nil)
)
