package federatedauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

var ErrFederatedPersistence = errors.New("federated authentication persistence unavailable")

const (
	minimumProtectedTransactionBytes = 16
	maximumProtectedTransactionBytes = 4 * 1024
	maximumPersistentScopeCount      = 32
	maximumPersistentScopeBytes      = 128
)

// OIDCTransactionWriteReceipt is the bounded projection returned by an
// atomic transaction mutation. Replayed is informational: persistence owns
// exact request-digest binding and may set it only for an exact replay.
type OIDCTransactionWriteReceipt struct {
	TransactionID federatedoidc.TransactionID
	Version       uint64
	State         federatedoidc.TransactionState
	Replayed      bool
}

func (receipt OIDCTransactionWriteReceipt) String() string {
	return fmt.Sprintf(
		"federatedauth.OIDCTransactionWriteReceipt{version:%t,state:%s,replayed:%t,material:[REDACTED]}",
		receipt.Version != 0, receipt.State, receipt.Replayed,
	)
}
func (receipt OIDCTransactionWriteReceipt) GoString() string { return receipt.String() }

// SAMLTransactionWriteReceipt has the same persistence semantics as its OIDC
// counterpart but remains physically typed so protocol identifiers cannot be
// confused at the adapter boundary.
type SAMLTransactionWriteReceipt struct {
	TransactionID federatedsaml.TransactionID
	Version       uint64
	State         federatedsaml.TransactionState
	Replayed      bool
}

func (receipt SAMLTransactionWriteReceipt) String() string {
	return fmt.Sprintf(
		"federatedauth.SAMLTransactionWriteReceipt{version:%t,state:%s,replayed:%t,material:[REDACTED]}",
		receipt.Version != 0, receipt.State, receipt.Replayed,
	)
}
func (receipt SAMLTransactionWriteReceipt) GoString() string { return receipt.String() }

// FederatedTransactionPersistence is the narrow database ABI consumed by the
// protocol adapters. Each method is one SECURITY DEFINER transaction in the
// future PostgreSQL implementation. It derives tenant authority from a
// consumed start receipt or a stored transaction; no caller-selected tenant
// is accepted. Inputs remain owned by the caller and must not be retained.
type FederatedTransactionPersistence interface {
	CreateOIDCTransaction(context.Context, federatedoidc.CreateTransactionRequest) (OIDCTransactionWriteReceipt, error)
	ClaimOIDCTransaction(context.Context, federatedoidc.TransactionClaim) (federatedoidc.ClaimedTransaction, error)
	FailOIDCTransaction(context.Context, federatedoidc.TransactionFailure) (OIDCTransactionWriteReceipt, error)
	CreateSAMLTransaction(context.Context, federatedsaml.CreateTransactionRequest) (SAMLTransactionWriteReceipt, error)
	LookupSAMLTransaction(context.Context, federatedsaml.LookupTransactionRequest) (federatedsaml.PendingTransaction, error)
}

// PersistentOIDCTransactionRepository adapts the shared persistence ABI to
// the kernel's one-shot state machine. It validates echoed projections before
// the protocol can use them and maps all database details to one safe error.
type PersistentOIDCTransactionRepository struct {
	persistence FederatedTransactionPersistence
}

func NewPersistentOIDCTransactionRepository(
	persistence FederatedTransactionPersistence,
) (*PersistentOIDCTransactionRepository, error) {
	if persistence == nil {
		return nil, ErrInvalidOptions
	}
	return &PersistentOIDCTransactionRepository{persistence: persistence}, nil
}

func (repository *PersistentOIDCTransactionRepository) String() string {
	return fmt.Sprintf("federatedauth.PersistentOIDCTransactionRepository{configured:%t}",
		repository != nil && repository.persistence != nil)
}
func (repository *PersistentOIDCTransactionRepository) GoString() string { return repository.String() }

var _ federatedoidc.TransactionRepository = (*PersistentOIDCTransactionRepository)(nil)

func (repository *PersistentOIDCTransactionRepository) CreateReplacing(
	ctx context.Context,
	request federatedoidc.CreateTransactionRequest,
) error {
	if repository == nil || repository.persistence == nil || !activeContext(ctx) ||
		!validOIDCCreateTransactionRequest(request) {
		return ErrFederatedPersistence
	}
	persistenceRequest := cloneOIDCCreateTransactionRequest(request)
	defer clear(persistenceRequest.Current.Verifier.Ciphertext)
	receipt, err := repository.persistence.CreateOIDCTransaction(ctx, persistenceRequest)
	if err != nil || !activeContext(ctx) || receipt.TransactionID != request.Current.ID ||
		receipt.Version != request.Current.Version ||
		receipt.State != federatedoidc.TransactionPending {
		return ErrFederatedPersistence
	}
	return nil
}

func (repository *PersistentOIDCTransactionRepository) Claim(
	ctx context.Context,
	claim federatedoidc.TransactionClaim,
) (federatedoidc.ClaimedTransaction, error) {
	if repository == nil || repository.persistence == nil || !activeContext(ctx) || !validOIDCClaim(claim) {
		return federatedoidc.ClaimedTransaction{}, ErrFederatedPersistence
	}
	claimed, err := repository.persistence.ClaimOIDCTransaction(ctx, claim)
	if err != nil || !activeContext(ctx) || !validClaimedOIDCProjection(claimed, claim) {
		clear(claimed.Verifier.Ciphertext)
		return federatedoidc.ClaimedTransaction{}, ErrFederatedPersistence
	}
	result := cloneOIDCClaimedTransaction(claimed)
	clear(claimed.Verifier.Ciphertext)
	return result, nil
}

func (repository *PersistentOIDCTransactionRepository) Fail(
	ctx context.Context,
	failure federatedoidc.TransactionFailure,
) error {
	if repository == nil || repository.persistence == nil || !activeContext(ctx) || !validOIDCFailure(failure) {
		return ErrFederatedPersistence
	}
	receipt, err := repository.persistence.FailOIDCTransaction(ctx, failure)
	if err != nil || !activeContext(ctx) || receipt.TransactionID != failure.ID ||
		receipt.Version != failure.ExpectedVersion+1 ||
		receipt.State != failure.State {
		return ErrFederatedPersistence
	}
	return nil
}

// PersistentSAMLTransactionRepository adapts the same database boundary to
// the SAML request/RelayState lifecycle. Lookup never consumes replay rows;
// final transaction/response/assertion/session replay consumption remains in
// the later atomic authentication apply.
type PersistentSAMLTransactionRepository struct {
	persistence FederatedTransactionPersistence
}

func NewPersistentSAMLTransactionRepository(
	persistence FederatedTransactionPersistence,
) (*PersistentSAMLTransactionRepository, error) {
	if persistence == nil {
		return nil, ErrInvalidOptions
	}
	return &PersistentSAMLTransactionRepository{persistence: persistence}, nil
}

func (repository *PersistentSAMLTransactionRepository) String() string {
	return fmt.Sprintf("federatedauth.PersistentSAMLTransactionRepository{configured:%t}",
		repository != nil && repository.persistence != nil)
}
func (repository *PersistentSAMLTransactionRepository) GoString() string { return repository.String() }

var _ federatedsaml.TransactionRepository = (*PersistentSAMLTransactionRepository)(nil)

func (repository *PersistentSAMLTransactionRepository) CreateReplacing(
	ctx context.Context,
	request federatedsaml.CreateTransactionRequest,
) error {
	if repository == nil || repository.persistence == nil || !activeContext(ctx) ||
		!validSAMLCreateTransactionRequest(request) {
		return ErrFederatedPersistence
	}
	receipt, err := repository.persistence.CreateSAMLTransaction(ctx, request)
	if err != nil || !activeContext(ctx) || receipt.TransactionID != request.Current.ID ||
		receipt.Version != request.Current.Version ||
		receipt.State != federatedsaml.TransactionPending {
		return ErrFederatedPersistence
	}
	return nil
}

func (repository *PersistentSAMLTransactionRepository) Lookup(
	ctx context.Context,
	request federatedsaml.LookupTransactionRequest,
) (federatedsaml.PendingTransaction, error) {
	if repository == nil || repository.persistence == nil || !activeContext(ctx) || !validSAMLLookup(request) {
		return federatedsaml.PendingTransaction{}, ErrFederatedPersistence
	}
	pending, err := repository.persistence.LookupSAMLTransaction(ctx, request)
	if err != nil || !activeContext(ctx) || !validPendingSAMLProjection(pending, request) {
		return federatedsaml.PendingTransaction{}, ErrFederatedPersistence
	}
	return pending, nil
}

func activeContext(ctx context.Context) bool { return ctx != nil && ctx.Err() == nil }

func validOIDCCreateTransactionRequest(request federatedoidc.CreateTransactionRequest) bool {
	current := request.Current
	return validFederatedBegin(
		request.Begin.OperationRunID,
		[sha256.Size]byte(request.Begin.ReceiptDigest),
		[sha256.Size]byte(request.Begin.NetworkDigest),
		[sha256.Size]byte(request.Begin.AccountDigest),
		[sha256.Size]byte(request.Begin.ProviderDigest),
	) && current.ID != (federatedoidc.TransactionID{}) && current.State == federatedoidc.TransactionPending &&
		validApplyUUIDv7(current.MaterialID) && current.MaterialID == request.Begin.OperationRunID &&
		current.Version == 1 && current.StateDigest != ([sha256.Size]byte{}) &&
		current.BrowserDigest != ([sha256.Size]byte{}) && current.NonceDigest != ([sha256.Size]byte{}) &&
		current.StateDigest != current.BrowserDigest && current.StateDigest != current.NonceDigest &&
		current.BrowserDigest != current.NonceDigest && current.Verifier.KeyVersion > 0 &&
		len(current.Verifier.Ciphertext) >= minimumProtectedTransactionBytes &&
		len(current.Verifier.Ciphertext) <= maximumProtectedTransactionBytes &&
		validOIDCTransactionPins(current.Pins) && validPersistentTimeWindow(current.CreatedAt, current.ExpiresAt) &&
		validPublicPersistenceText(current.ClientID, 1, 1024) &&
		validPublicPersistenceText(current.RedirectURI, 1, 4096) &&
		validPublicPersistenceText(current.PostLogoutRedirectURI, 0, 4096) && validReturnPath(current.ReturnPath) &&
		validPersistentScopes(current.Scopes) &&
		(!request.HasPreviousBrowserBinding && request.PreviousBrowserDigest == ([sha256.Size]byte{}) ||
			request.HasPreviousBrowserBinding && request.PreviousBrowserDigest != ([sha256.Size]byte{}))
}

func validOIDCClaim(claim federatedoidc.TransactionClaim) bool {
	return claim.AttemptID != (federatedoidc.TransactionID{}) && claim.StateDigest != ([sha256.Size]byte{}) &&
		claim.BrowserDigest != ([sha256.Size]byte{}) && claim.StateDigest != claim.BrowserDigest &&
		validPersistentInstant(claim.ClaimedAt)
}

func validClaimedOIDCProjection(
	claimed federatedoidc.ClaimedTransaction,
	claim federatedoidc.TransactionClaim,
) bool {
	return claimed.ID != (federatedoidc.TransactionID{}) && claimed.State == federatedoidc.TransactionClaimed &&
		validApplyUUIDv7(claimed.MaterialID) &&
		claimed.Version == 2 && claimed.ClaimAttemptID == claim.AttemptID && claimed.StateDigest == claim.StateDigest &&
		claimed.BrowserDigest == claim.BrowserDigest && claimed.ClaimedAt.Equal(claim.ClaimedAt) &&
		claimed.NonceDigest != ([sha256.Size]byte{}) && claimed.StateDigest != claimed.BrowserDigest &&
		claimed.StateDigest != claimed.NonceDigest && claimed.BrowserDigest != claimed.NonceDigest &&
		claimed.Verifier.KeyVersion > 0 && len(claimed.Verifier.Ciphertext) >= minimumProtectedTransactionBytes &&
		len(claimed.Verifier.Ciphertext) <= maximumProtectedTransactionBytes &&
		validOIDCTransactionPins(claimed.Pins) && validPersistentTimeWindow(claimed.CreatedAt, claimed.ExpiresAt) &&
		!claimed.ClaimedAt.Before(claimed.CreatedAt) && claimed.ClaimedAt.Before(claimed.ExpiresAt) &&
		validPublicPersistenceText(claimed.ClientID, 1, 1024) &&
		validPublicPersistenceText(claimed.RedirectURI, 1, 4096) &&
		validPublicPersistenceText(claimed.PostLogoutRedirectURI, 0, 4096) && validReturnPath(claimed.ReturnPath) &&
		validPersistentScopes(claimed.Scopes)
}

func validOIDCFailure(failure federatedoidc.TransactionFailure) bool {
	validReason := false
	switch failure.Reason {
	case federatedoidc.FailureProviderResponse, federatedoidc.FailureStaleConfiguration,
		federatedoidc.FailureExpired, federatedoidc.FailureTokenExchange,
		federatedoidc.FailureTokenValidation, federatedoidc.FailureIdentityApplication:
		validReason = true
	}
	return failure.ID != (federatedoidc.TransactionID{}) && failure.ExpectedVersion == 2 &&
		validPersistentInstant(failure.FailedAt) && validReason &&
		(failure.State == federatedoidc.TransactionFailed || failure.State == federatedoidc.TransactionExpired)
}

func validOIDCTransactionPins(pins federatedoidc.TransactionPins) bool {
	admission, validAdmission := pins.TenantAdmission()
	return validAdmission && validTenantAdmission(pins.Provider, admission) &&
		validDatabaseRevision(pins.ProviderRevision) && validDatabaseRevision(pins.BindingRevision) &&
		validDatabaseRevision(pins.ConfigurationRevision) && validDatabaseRevision(pins.SecurityRevision) &&
		validDatabaseRevision(pins.MappingRevision) && validDatabaseRevision(pins.AuthorizationRevision) &&
		validDatabaseRevision(pins.AssurancePolicyRevision) && validDatabaseRevision(pins.ClientSecretRevision) &&
		validDatabaseRevision(pins.DiscoveryRevision) && pins.DiscoveryDigest != ([sha256.Size]byte{}) &&
		validDatabaseRevision(pins.JWKSRevision) && pins.JWKSDigest != ([sha256.Size]byte{})
}

func validSAMLCreateTransactionRequest(request federatedsaml.CreateTransactionRequest) bool {
	current := request.Current
	return validFederatedBegin(
		request.Begin.OperationRunID,
		[sha256.Size]byte(request.Begin.ReceiptDigest),
		[sha256.Size]byte(request.Begin.NetworkDigest),
		[sha256.Size]byte(request.Begin.AccountDigest),
		[sha256.Size]byte(request.Begin.ProviderDigest),
	) && current.ID != (federatedsaml.TransactionID{}) && validPublicPersistenceText(current.RequestID, 1, 1024) &&
		current.MaterialID == request.Begin.OperationRunID &&
		current.RelayStateDigest != ([sha256.Size]byte{}) && current.BrowserDigest != ([sha256.Size]byte{}) &&
		current.RelayStateDigest != current.BrowserDigest && validSAMLTransactionPins(current.Pins) &&
		validPersistentTimeWindow(current.CreatedAt, current.ExpiresAt) &&
		validReturnPath(current.ReturnPath) && current.State == federatedsaml.TransactionPending &&
		current.Version == 1 &&
		(!request.HasPreviousBrowserBinding && request.PreviousBrowserDigest == ([sha256.Size]byte{}) ||
			request.HasPreviousBrowserBinding && request.PreviousBrowserDigest != ([sha256.Size]byte{}))
}

func validSAMLLookup(request federatedsaml.LookupTransactionRequest) bool {
	return request.RelayStateDigest != ([sha256.Size]byte{}) && request.BrowserDigest != ([sha256.Size]byte{}) &&
		request.RelayStateDigest != request.BrowserDigest && validPersistentInstant(request.ObservedAt)
}

func validPendingSAMLProjection(
	pending federatedsaml.PendingTransaction,
	request federatedsaml.LookupTransactionRequest,
) bool {
	return pending.ID != (federatedsaml.TransactionID{}) && validApplyUUIDv7(pending.MaterialID) &&
		validPublicPersistenceText(pending.RequestID, 1, 1024) &&
		pending.RelayStateDigest == request.RelayStateDigest && pending.BrowserDigest == request.BrowserDigest &&
		validSAMLTransactionPins(pending.Pins) && validPersistentTimeWindow(pending.CreatedAt, pending.ExpiresAt) &&
		!pending.CreatedAt.After(request.ObservedAt) && request.ObservedAt.Before(pending.ExpiresAt) &&
		validReturnPath(pending.ReturnPath) && pending.State == federatedsaml.TransactionPending &&
		pending.Version == 1
}

func validSAMLTransactionPins(pins federatedsaml.TransactionPins) bool {
	return validSAMLProviderBindingPersistence(pins.Provider, pins.BindingID) &&
		validDatabaseRevision(pins.ProviderRevision) && validDatabaseRevision(pins.BindingRevision) &&
		validDatabaseRevision(pins.ConfigurationRevision) && validDatabaseRevision(pins.SecurityRevision) &&
		validDatabaseRevision(pins.MappingRevision) && validDatabaseRevision(pins.AuthorizationRevision) &&
		validDatabaseRevision(pins.AssurancePolicyRevision) && validDatabaseRevision(pins.MetadataRevision) &&
		pins.MetadataDigest != ([sha256.Size]byte{}) && validDatabaseRevision(pins.SPKeyRevision) &&
		pins.ConfigurationDigest != ([sha256.Size]byte{})
}

func validFederatedBegin(
	operationID identity.EntityID,
	receipt, network, account, provider [sha256.Size]byte,
) bool {
	zero := [sha256.Size]byte{}
	return operationID != (identity.EntityID{}) && operationID[6]>>4 == 7 && operationID[8]&0xc0 == 0x80 &&
		receipt != zero && network != zero && account != zero && provider != zero &&
		receipt != network && receipt != account && receipt != provider &&
		network != account && network != provider && account != provider
}

func validSAMLProviderBindingPersistence(provider identity.ProviderContext, bindingID identity.EntityID) bool {
	return provider.ProviderID != (identity.EntityID{}) && bindingID != (identity.EntityID{}) &&
		(provider.Scope == identity.TenantProviderScope && provider.TenantID != (identity.EntityID{}) ||
			provider.Scope == identity.PlatformProviderScope && provider.TenantID == (identity.EntityID{}))
}

func validPersistentTimeWindow(createdAt, expiresAt time.Time) bool {
	return validPersistentInstant(createdAt) && validPersistentInstant(expiresAt) && expiresAt.After(createdAt) &&
		expiresAt.Sub(createdAt) >= time.Minute && expiresAt.Sub(createdAt) <= 15*time.Minute
}

func validPersistentInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%int(time.Microsecond) == 0
}

func validPublicPersistenceText(value string, minimum, maximum int) bool {
	if value == "" && minimum == 0 {
		return true
	}
	return len(value) >= minimum && validPublicText(value, maximum)
}

func validPersistentScopes(values []string) bool {
	if len(values) < 1 || len(values) > maximumPersistentScopeCount ||
		values[0] != federatedoidc.RequiredScopeOpenID || !slices.IsSorted(values[1:]) {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validPersistentOIDCScope(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validPersistentOIDCScope(value string) bool {
	if value == "" || len(value) > maximumPersistentScopeBytes {
		return false
	}
	for index := range value {
		character := value[index]
		if character == 0x21 || character >= 0x23 && character <= 0x5b ||
			character >= 0x5d && character <= 0x7e {
			continue
		}
		return false
	}
	return true
}

func cloneOIDCCreateTransactionRequest(value federatedoidc.CreateTransactionRequest) federatedoidc.CreateTransactionRequest {
	value.Current.Verifier.Ciphertext = append([]byte(nil), value.Current.Verifier.Ciphertext...)
	value.Current.Scopes = append([]string(nil), value.Current.Scopes...)
	return value
}

func cloneOIDCClaimedTransaction(value federatedoidc.ClaimedTransaction) federatedoidc.ClaimedTransaction {
	value.Verifier.Ciphertext = append([]byte(nil), value.Verifier.Ciphertext...)
	value.Scopes = append([]string(nil), value.Scopes...)
	return value
}
