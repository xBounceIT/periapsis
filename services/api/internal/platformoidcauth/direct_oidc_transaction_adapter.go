package platformoidcauth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

// DirectOIDCTransactionPersistence is the direct-family persistence ABI used
// by the protocol adapter. Every method must be idempotent for an exact retry
// and reject a divergent replay. Implementations must not retain caller-owned
// verifier ciphertext or scope slices.
type DirectOIDCTransactionPersistence interface {
	CreateDirectOIDCTransaction(context.Context, DirectOIDCCreateTransactionRequest) error
	ClaimDirectOIDCTransaction(context.Context, DirectOIDCClaimTransactionRequest) (federatedoidc.ClaimedTransaction, error)
	FailDirectOIDCTransaction(context.Context, DirectOIDCFailureRequest) error
}

// DirectOIDCCreateTransactionRequest is the complete direct transaction
// creation projection. Current.Pins includes plan and platform-floor pins in
// addition to every protocol pin; Audit is exact request attribution.
type DirectOIDCCreateTransactionRequest struct {
	Begin                     federatedoidc.AuthorizationBegin
	Current                   federatedoidc.PendingTransaction
	CodeChallengeMethod       string
	PreviousBrowserDigest     [sha256.Size]byte
	HasPreviousBrowserBinding bool
	BrowserCapabilityDigest   DirectBrowserCapabilityDigest
	Audit                     DirectAuditContext
}

func (request DirectOIDCCreateTransactionRequest) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectOIDCCreateTransactionRequest{begin:%q,current:%q,s256:%t,replacement:%t,browserCapability:[REDACTED],audit:%q,material:[REDACTED]}",
		request.Begin.String(), request.Current.String(), request.CodeChallengeMethod == federatedoidc.CodeChallengeS256,
		request.HasPreviousBrowserBinding,
		request.Audit.String(),
	)
}

func (request DirectOIDCCreateTransactionRequest) GoString() string { return request.String() }

type DirectOIDCClaimTransactionRequest struct {
	AttemptID               federatedoidc.TransactionID
	ExpectedVersion         uint64
	StateDigest             [sha256.Size]byte
	BrowserDigest           [sha256.Size]byte
	AuthorizationCodeDigest [sha256.Size]byte
	ClaimedAt               time.Time
	Audit                   DirectAuditContext
}

func (request DirectOIDCClaimTransactionRequest) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectOIDCClaimTransactionRequest{attempt:%t,version:%t,state:[REDACTED],browser:[REDACTED],code:[REDACTED],claimed:%t,audit:%q}",
		validTransactionID(request.AttemptID), request.ExpectedVersion == 1,
		!request.ClaimedAt.IsZero(), request.Audit.String(),
	)
}

func (request DirectOIDCClaimTransactionRequest) GoString() string { return request.String() }

type DirectOIDCFailureRequest struct {
	TransactionID   federatedoidc.TransactionID
	ExpectedVersion uint64
	FailedAt        time.Time
	Reason          federatedoidc.TransactionFailureReason
	State           federatedoidc.TransactionState
	Audit           DirectAuditContext
}

func (request DirectOIDCFailureRequest) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectOIDCFailureRequest{transaction:%t,version:%t,failed:%t,reason:%q,state:%q,audit:%q}",
		validTransactionID(request.TransactionID), request.ExpectedVersion != 0,
		!request.FailedAt.IsZero(), request.Reason.String(), request.State.String(), request.Audit.String(),
	)
}

func (request DirectOIDCFailureRequest) GoString() string { return request.String() }

type DirectOIDCTransactionAdapterOptions struct {
	Flow        federatedoidc.FlowOptions
	Persistence DirectOIDCTransactionPersistence
}

// DirectOIDCTransactionAdapter owns a dedicated direct-callback Flow and its
// repository bridge. Construction rejects a caller-supplied generic
// transaction repository so the Flow cannot be silently wired to a tenant
// persistence family.
type DirectOIDCTransactionAdapter struct {
	flow             *federatedoidc.Flow
	operationTimeout time.Duration
}

func NewDirectOIDCTransactionAdapter(
	options DirectOIDCTransactionAdapterOptions,
) (*DirectOIDCTransactionAdapter, error) {
	if options.Persistence == nil || options.Flow.Transactions != nil {
		return nil, ErrDirectAuthenticationDenied
	}
	repository := &directOIDCTransactionRepository{persistence: options.Persistence}
	flowOptions := options.Flow
	flowOptions.Transactions = repository
	flowOptions.CallbackEndpoint = federatedoidc.DirectPlatformOIDCCallbackEndpoint
	flow, err := federatedoidc.NewFlow(flowOptions)
	if err != nil {
		return nil, ErrDirectAuthenticationDenied
	}
	return &DirectOIDCTransactionAdapter{
		flow: flow, operationTimeout: flowOptions.Policy.OperationTimeout,
	}, nil
}

func (adapter *DirectOIDCTransactionAdapter) String() string {
	return fmt.Sprintf(
		"platformoidcauth.DirectOIDCTransactionAdapter{configured:%t}",
		adapter != nil && adapter.flow != nil && adapter.operationTimeout > 0,
	)
}

func (adapter *DirectOIDCTransactionAdapter) GoString() string { return adapter.String() }

func (adapter *DirectOIDCTransactionAdapter) StartDirectAuthorization(
	ctx context.Context,
	request DirectOIDCStartAuthorizationRequest,
) (federatedoidc.AuthorizationStart, error) {
	if adapter == nil || adapter.flow == nil || !validDirectStartAdapterRequest(request) {
		return federatedoidc.AuthorizationStart{}, ErrDirectAuthenticationDenied
	}
	bound, ok := bindDirectOIDCConfigurationPins(request.Protocol.Configuration, request.Grant.Pins)
	if !ok {
		return federatedoidc.AuthorizationStart{}, ErrDirectAuthenticationDenied
	}
	protocol := request.Protocol
	protocol.Configuration = bound
	protocol.ApplicationBrowserBindingDigest = [sha256.Size]byte(
		request.Grant.Authority.Lookup.BrowserCapabilityDigest,
	)
	protocol.Audit = transactionAuditContext(request.Grant.Authority.Audit)
	start, err := adapter.flow.StartAuthorization(ctx, protocol)
	if err != nil || !validTransactionID(start.TransactionID()) || start.RedirectURL() == "" ||
		len(start.BrowserHandle()) == 0 || !validInstant(start.ExpiresAt()) {
		return federatedoidc.AuthorizationStart{}, ErrDirectAuthenticationDenied
	}
	return start, nil
}

func (adapter *DirectOIDCTransactionAdapter) ClaimCallbackResolved(
	ctx context.Context,
	request DirectOIDCCallbackRequest,
	resolver federatedoidc.CallbackConfigurationResolver,
) (DirectClaimedAuthorization, error) {
	if adapter == nil || adapter.flow == nil || resolver == nil || !validDirectAuditContext(request.Audit) ||
		!zeroOrExactTransactionAudit(request.Protocol.Audit, request.Audit) {
		return DirectClaimedAuthorization{}, ErrDirectAuthenticationDenied
	}
	protocol := request.Protocol
	protocol.Audit = transactionAuditContext(request.Audit)
	claimed, err := adapter.flow.ClaimCallbackResolved(ctx, protocol, resolver)
	if err != nil || !adapter.validClaimed(claimed, request.Audit) {
		if claimed != nil {
			adapter.abortInvalidClaim(ctx, claimed)
		}
		return DirectClaimedAuthorization{}, ErrDirectAuthenticationDenied
	}
	return DirectClaimedAuthorization{
		Authorization: claimed, ClaimAttemptID: claimed.ClaimAttemptID(),
	}, nil
}

func (adapter *DirectOIDCTransactionAdapter) ExchangeCode(
	ctx context.Context,
	claimed *federatedoidc.ClaimedAuthorization,
	credential federatedoidc.ClientCredential,
) (*federatedoidc.TokenBundle, error) {
	if adapter == nil || adapter.flow == nil || !adapter.validClaimedAuthority(claimed) {
		return nil, ErrDirectAuthenticationDenied
	}
	bundle, err := adapter.flow.ExchangeCode(ctx, claimed, credential)
	if err != nil || bundle == nil {
		return nil, ErrDirectAuthenticationDenied
	}
	return bundle, nil
}

func (adapter *DirectOIDCTransactionAdapter) VerifyIDToken(
	ctx context.Context,
	claimed *federatedoidc.ClaimedAuthorization,
	bundle *federatedoidc.TokenBundle,
	policy federatedoidc.ClaimExtractionPolicy,
) (*federatedoidc.VerifiedAuthentication, error) {
	if adapter == nil || adapter.flow == nil || bundle == nil || !adapter.validClaimedAuthority(claimed) {
		return nil, ErrDirectAuthenticationDenied
	}
	proof, err := adapter.flow.VerifyIDToken(ctx, claimed, bundle, policy)
	if err != nil || proof == nil {
		return nil, ErrDirectAuthenticationDenied
	}
	return proof, nil
}

func (adapter *DirectOIDCTransactionAdapter) TakeSessionMaterial(
	configuration federatedoidc.AuthorizationConfiguration,
	bundle *federatedoidc.TokenBundle,
) (federatedauth.OIDCSessionMaterial, error) {
	if adapter == nil || adapter.flow == nil || bundle == nil {
		return nil, ErrDirectAuthenticationDenied
	}
	material, err := adapter.flow.TakeSessionMaterial(configuration, bundle)
	if err != nil {
		return nil, ErrDirectAuthenticationDenied
	}
	return material, nil
}

func (adapter *DirectOIDCTransactionAdapter) AbortDirectClaimedAuthorization(
	ctx context.Context,
	claimed DirectClaimedAuthorization,
	audit DirectAuditContext,
) error {
	if adapter == nil || adapter.flow == nil || !validDirectAuditContext(audit) ||
		claimed.Authorization == nil || claimed.ClaimAttemptID != claimed.Authorization.ClaimAttemptID() ||
		!adapter.validClaimed(claimed.Authorization, audit) {
		return ErrDirectAuthenticationDenied
	}
	if err := adapter.flow.AbortClaimedAuthorization(ctx, claimed.Authorization); err != nil {
		return ErrDirectAuthenticationDenied
	}
	return nil
}

func (adapter *DirectOIDCTransactionAdapter) validClaimed(
	claimed *federatedoidc.ClaimedAuthorization,
	audit DirectAuditContext,
) bool {
	return adapter.validClaimedAuthority(claimed) && claimed.AuditContext() == transactionAuditContext(audit)
}

func (adapter *DirectOIDCTransactionAdapter) validClaimedAuthority(
	claimed *federatedoidc.ClaimedAuthorization,
) bool {
	if adapter == nil || adapter.flow == nil || claimed == nil ||
		!validTransactionID(claimed.TransactionID()) || !validTransactionID(claimed.ClaimAttemptID()) {
		return false
	}
	pins, direct := directConfigurationPinsFromTransaction(claimed.Pins())
	return direct && validDirectOIDCConfigurationPins(pins)
}

func (adapter *DirectOIDCTransactionAdapter) abortInvalidClaim(
	ctx context.Context,
	claimed *federatedoidc.ClaimedAuthorization,
) {
	if adapter == nil || adapter.flow == nil || claimed == nil || adapter.operationTimeout <= 0 {
		return
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), adapter.operationTimeout)
	defer cancel()
	for range 2 {
		if err := adapter.flow.AbortClaimedAuthorization(cleanup, claimed); err == nil || cleanup.Err() != nil {
			return
		}
	}
}

type directOIDCTransactionRepository struct {
	persistence DirectOIDCTransactionPersistence
}

func (repository *directOIDCTransactionRepository) CreateReplacing(
	ctx context.Context,
	request federatedoidc.CreateTransactionRequest,
) error {
	audit, auditOK := directAuditContext(request.Audit)
	pins, direct := directConfigurationPinsFromTransaction(request.Current.Pins)
	if repository == nil || repository.persistence == nil || ctx == nil || ctx.Err() != nil ||
		!auditOK || !validDirectOIDCConfigurationPins(pins) || !direct ||
		request.ApplicationBrowserBindingDigest == ([sha256.Size]byte{}) ||
		request.ApplicationBrowserBindingDigest == request.Current.BrowserDigest ||
		!validTransactionID(request.Current.ID) || request.Current.State != federatedoidc.TransactionPending ||
		request.Current.Version != 1 || !validDirectReturnPath(request.Current.ReturnPath) ||
		request.HasPreviousBrowserBinding != (request.PreviousBrowserDigest != ([sha256.Size]byte{})) ||
		request.HasPreviousBrowserBinding &&
			(request.PreviousBrowserDigest == request.Current.BrowserDigest ||
				request.PreviousBrowserDigest == request.ApplicationBrowserBindingDigest) {
		return ErrDirectAuthenticationDenied
	}
	persistenceRequest := cloneDirectOIDCCreateTransactionRequest(DirectOIDCCreateTransactionRequest{
		Begin: request.Begin, Current: request.Current, CodeChallengeMethod: federatedoidc.CodeChallengeS256,
		PreviousBrowserDigest:     request.PreviousBrowserDigest,
		HasPreviousBrowserBinding: request.HasPreviousBrowserBinding,
		BrowserCapabilityDigest: DirectBrowserCapabilityDigest(
			request.ApplicationBrowserBindingDigest,
		),
		Audit: audit,
	})
	defer clear(persistenceRequest.Current.Verifier.Ciphertext)
	return repository.persistence.CreateDirectOIDCTransaction(ctx, persistenceRequest)
}

func (repository *directOIDCTransactionRepository) Claim(
	ctx context.Context,
	claim federatedoidc.TransactionClaim,
) (federatedoidc.ClaimedTransaction, error) {
	audit, auditOK := directAuditContext(claim.Audit)
	if repository == nil || repository.persistence == nil || ctx == nil || ctx.Err() != nil ||
		!auditOK || !validTransactionID(claim.AttemptID) ||
		claim.StateDigest == ([sha256.Size]byte{}) || claim.BrowserDigest == ([sha256.Size]byte{}) ||
		claim.AuthorizationCodeDigest == ([sha256.Size]byte{}) || !validInstant(claim.ClaimedAt) {
		return federatedoidc.ClaimedTransaction{}, ErrDirectAuthenticationDenied
	}
	request := DirectOIDCClaimTransactionRequest{
		AttemptID: claim.AttemptID, ExpectedVersion: 1, StateDigest: claim.StateDigest,
		BrowserDigest: claim.BrowserDigest, AuthorizationCodeDigest: claim.AuthorizationCodeDigest,
		ClaimedAt: claim.ClaimedAt, Audit: audit,
	}
	transferred, err := repository.persistence.ClaimDirectOIDCTransaction(ctx, request)
	record := cloneDirectClaimedTransaction(transferred)
	clear(transferred.Verifier.Ciphertext)
	if err != nil {
		clear(record.Verifier.Ciphertext)
		return federatedoidc.ClaimedTransaction{}, err
	}
	pins, direct := directConfigurationPinsFromTransaction(record.Pins)
	if !direct || !validDirectOIDCConfigurationPins(pins) || !validTransactionID(record.ID) ||
		record.State != federatedoidc.TransactionClaimed || record.Version != 2 ||
		record.ClaimAttemptID != claim.AttemptID ||
		record.AuthorizationCodeDigest != claim.AuthorizationCodeDigest ||
		record.StateDigest != claim.StateDigest || record.BrowserDigest != claim.BrowserDigest ||
		!record.ClaimedAt.Equal(claim.ClaimedAt) || !validDirectReturnPath(record.ReturnPath) {
		clear(record.Verifier.Ciphertext)
		return federatedoidc.ClaimedTransaction{}, ErrDirectAuthenticationDenied
	}
	return record, nil
}

func (repository *directOIDCTransactionRepository) Fail(
	ctx context.Context,
	failure federatedoidc.TransactionFailure,
) error {
	audit, auditOK := directAuditContext(failure.Audit)
	if repository == nil || repository.persistence == nil || ctx == nil || ctx.Err() != nil ||
		!auditOK || !validTransactionID(failure.ID) || failure.ExpectedVersion != 2 ||
		!validInstant(failure.FailedAt) || !validDirectFailure(failure.Reason, failure.State) {
		return ErrDirectAuthenticationDenied
	}
	return repository.persistence.FailDirectOIDCTransaction(ctx, DirectOIDCFailureRequest{
		TransactionID: failure.ID, ExpectedVersion: failure.ExpectedVersion,
		FailedAt: failure.FailedAt, Reason: failure.Reason, State: failure.State, Audit: audit,
	})
}

func validDirectStartAdapterRequest(request DirectOIDCStartAuthorizationRequest) bool {
	authority := request.Grant.Authority
	lookup := authority.Lookup
	protocol := request.Protocol
	return validDirectOIDCStartLookup(lookup) && validDirectAuditContext(authority.Audit) &&
		validDirectOIDCConfigurationPins(request.Grant.Pins) &&
		validDirectReturnPath(authority.ReturnPath) && authority.ReturnPath == protocol.ReturnPath &&
		protocol.Begin.OperationRunID == lookup.OperationRunID &&
		protocol.Begin.ReceiptDigest == federatedoidc.StartReceiptDigest(lookup.ReceiptDigest) &&
		protocol.Begin.NetworkDigest == federatedoidc.NetworkThrottleDigest(lookup.NetworkDigest) &&
		protocol.Begin.AccountDigest == federatedoidc.AccountThrottleDigest(lookup.AccountDigest) &&
		protocol.Begin.ProviderDigest == federatedoidc.ProviderThrottleDigest(lookup.ProviderDigest) &&
		(protocol.ApplicationBrowserBindingDigest == ([sha256.Size]byte{}) ||
			protocol.ApplicationBrowserBindingDigest == [sha256.Size]byte(lookup.BrowserCapabilityDigest)) &&
		zeroOrExactTransactionAudit(protocol.Audit, authority.Audit) &&
		validDirectOIDCConfiguration(DirectOIDCConfiguration{Authorization: protocol.Configuration}, request.Grant.Pins)
}

func transactionAuditContext(audit DirectAuditContext) federatedoidc.TransactionAuditContext {
	return federatedoidc.TransactionAuditContext{
		RequestID: audit.RequestID, CorrelationID: audit.CorrelationID,
		RemoteAddress: audit.RemoteAddress, UserAgent: audit.UserAgent,
	}
}

func directAuditContext(audit federatedoidc.TransactionAuditContext) (DirectAuditContext, bool) {
	result := DirectAuditContext{
		RequestID: audit.RequestID, CorrelationID: audit.CorrelationID,
		RemoteAddress: audit.RemoteAddress, UserAgent: audit.UserAgent,
	}
	return result, validDirectAuditContext(result)
}

func zeroOrExactTransactionAudit(
	actual federatedoidc.TransactionAuditContext,
	wanted DirectAuditContext,
) bool {
	return actual == (federatedoidc.TransactionAuditContext{}) || actual == transactionAuditContext(wanted)
}

func validDirectFailure(
	reason federatedoidc.TransactionFailureReason,
	state federatedoidc.TransactionState,
) bool {
	if state != federatedoidc.TransactionFailed && state != federatedoidc.TransactionExpired {
		return false
	}
	switch reason {
	case federatedoidc.FailureExpired:
		return state == federatedoidc.TransactionExpired
	case federatedoidc.FailureProviderResponse, federatedoidc.FailureStaleConfiguration,
		federatedoidc.FailureTokenExchange,
		federatedoidc.FailureTokenValidation, federatedoidc.FailureIdentityApplication:
		return state == federatedoidc.TransactionFailed
	default:
		return false
	}
}

func cloneDirectOIDCCreateTransactionRequest(
	request DirectOIDCCreateTransactionRequest,
) DirectOIDCCreateTransactionRequest {
	request.Current.Verifier.Ciphertext = append([]byte(nil), request.Current.Verifier.Ciphertext...)
	request.Current.Scopes = append([]string(nil), request.Current.Scopes...)
	return request
}

func cloneDirectClaimedTransaction(record federatedoidc.ClaimedTransaction) federatedoidc.ClaimedTransaction {
	record.Verifier.Ciphertext = append([]byte(nil), record.Verifier.Ciphertext...)
	record.Scopes = append([]string(nil), record.Scopes...)
	return record
}

var (
	_ DirectOIDCTransactionPort           = (*DirectOIDCTransactionAdapter)(nil)
	_ federatedoidc.TransactionRepository = (*directOIDCTransactionRepository)(nil)
)
