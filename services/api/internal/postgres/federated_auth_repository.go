package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

const (
	createOIDCAuthenticationTransactionSQL = `select app.create_oidc_authentication_transaction_v1($1::jsonb)`
	claimOIDCAuthenticationTransactionSQL  = `select app.claim_oidc_authentication_transaction_v1($1::jsonb)`
	failOIDCAuthenticationTransactionSQL   = `select app.fail_oidc_authentication_transaction_v1($1::jsonb)`
	createSAMLAuthenticationTransactionSQL = `select app.create_saml_authentication_transaction_v1($1::jsonb)`
	lookupSAMLAuthenticationTransactionSQL = `select app.lookup_saml_authentication_transaction_v1($1::jsonb)`
	federatedAuthenticationReadinessSQL    = `select app.federated_authentication_schema_readiness_v53()`

	maximumFederatedAuthenticationWireBytes = 2 * 1024 * 1024
)

var errFederatedAuthPersistence = errors.New("federated authentication persistence operation rejected")

type federatedAuthQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// FederatedAuthRepository calls only narrow SECURITY DEFINER ABIs. The
// functions are intentionally absent until the federation schema successor
// is sealed; readiness therefore fails closed instead of falling back to
// process memory or direct table access.
type FederatedAuthRepository struct {
	queryer           federatedAuthQueryer
	begin             transactionBeginner
	samlSessionSealer federatedauth.SAMLSessionMaterialSealer
	oidcClient        *federatedoidc.Client
	newDirectAuditID  func() (uuid.UUID, error)
}

func NewFederatedAuthRepository(pool *pgxpool.Pool) *FederatedAuthRepository {
	return &FederatedAuthRepository{
		queryer: pool, begin: poolTransactionBeginner(pool), newDirectAuditID: uuid.NewV7,
	}
}

func NewFederatedAuthRepositoryWithSAMLSessionSealer(
	pool *pgxpool.Pool,
	sealer federatedauth.SAMLSessionMaterialSealer,
) *FederatedAuthRepository {
	return &FederatedAuthRepository{
		queryer: pool, begin: poolTransactionBeginner(pool), samlSessionSealer: sealer,
		newDirectAuditID: uuid.NewV7,
	}
}

// NewFederatedAuthRepositoryWithRuntimeDependencies constructs the single
// production repository used by tenant federation and the physically
// separate direct-platform OIDC family. The OIDC client is retained only to
// reconstruct executable discovery/JWKS snapshots from exact persisted
// public documents; repository methods never perform network discovery.
func NewFederatedAuthRepositoryWithRuntimeDependencies(
	pool *pgxpool.Pool,
	sealer federatedauth.SAMLSessionMaterialSealer,
	oidcClient *federatedoidc.Client,
) *FederatedAuthRepository {
	return &FederatedAuthRepository{
		queryer: pool, begin: poolTransactionBeginner(pool), samlSessionSealer: sealer,
		oidcClient: oidcClient, newDirectAuditID: uuid.NewV7,
	}
}

func (repository *FederatedAuthRepository) String() string {
	return fmt.Sprintf("postgres.FederatedAuthRepository{configured:%t}",
		repository != nil && repository.queryer != nil)
}

func (repository *FederatedAuthRepository) GoString() string { return repository.String() }

var _ federatedauth.FederatedTransactionPersistence = (*FederatedAuthRepository)(nil)
var _ federatedauth.FederatedRuntimeReadiness = (*FederatedAuthRepository)(nil)

func (repository *FederatedAuthRepository) CreateOIDCTransaction(
	ctx context.Context,
	request federatedoidc.CreateTransactionRequest,
) (federatedauth.OIDCTransactionWriteReceipt, error) {
	wire, err := oidcCreateTransactionToWire(request)
	if err != nil {
		return federatedauth.OIDCTransactionWriteReceipt{}, errFederatedAuthPersistence
	}
	defer clearOIDCCreateTransactionWire(&wire)
	var receipt federatedTransactionReceiptWire
	defer clear(receipt.TransactionID)
	if err := repository.queryJSON(ctx, createOIDCAuthenticationTransactionSQL, wire, &receipt); err != nil {
		return federatedauth.OIDCTransactionWriteReceipt{}, err
	}
	return oidcTransactionReceiptFromWire(receipt)
}

func (repository *FederatedAuthRepository) ClaimOIDCTransaction(
	ctx context.Context,
	claim federatedoidc.TransactionClaim,
) (federatedoidc.ClaimedTransaction, error) {
	wire, err := oidcClaimToWire(claim)
	if err != nil {
		return federatedoidc.ClaimedTransaction{}, errFederatedAuthPersistence
	}
	defer clearOIDCClaimWire(&wire)
	var claimed oidcClaimedTransactionWire
	defer clearOIDCClaimedTransactionWire(&claimed)
	if err := repository.queryJSON(ctx, claimOIDCAuthenticationTransactionSQL, wire, &claimed); err != nil {
		return federatedoidc.ClaimedTransaction{}, err
	}
	return oidcClaimedTransactionFromWire(claimed)
}

func (repository *FederatedAuthRepository) FailOIDCTransaction(
	ctx context.Context,
	failure federatedoidc.TransactionFailure,
) (federatedauth.OIDCTransactionWriteReceipt, error) {
	wire, err := oidcFailureToWire(failure)
	if err != nil {
		return federatedauth.OIDCTransactionWriteReceipt{}, errFederatedAuthPersistence
	}
	defer clear(wire.ID)
	var receipt federatedTransactionReceiptWire
	defer clear(receipt.TransactionID)
	if err := repository.queryJSON(ctx, failOIDCAuthenticationTransactionSQL, wire, &receipt); err != nil {
		return federatedauth.OIDCTransactionWriteReceipt{}, err
	}
	return oidcTransactionReceiptFromWire(receipt)
}

func (repository *FederatedAuthRepository) CreateSAMLTransaction(
	ctx context.Context,
	request federatedsaml.CreateTransactionRequest,
) (federatedauth.SAMLTransactionWriteReceipt, error) {
	wire, err := samlCreateTransactionToWire(request)
	if err != nil {
		return federatedauth.SAMLTransactionWriteReceipt{}, errFederatedAuthPersistence
	}
	defer clearSAMLCreateTransactionWire(&wire)
	var receipt federatedTransactionReceiptWire
	defer clear(receipt.TransactionID)
	if err := repository.queryJSON(ctx, createSAMLAuthenticationTransactionSQL, wire, &receipt); err != nil {
		return federatedauth.SAMLTransactionWriteReceipt{}, err
	}
	return samlTransactionReceiptFromWire(receipt)
}

func (repository *FederatedAuthRepository) LookupSAMLTransaction(
	ctx context.Context,
	request federatedsaml.LookupTransactionRequest,
) (federatedsaml.PendingTransaction, error) {
	wire, err := samlLookupToWire(request)
	if err != nil {
		return federatedsaml.PendingTransaction{}, errFederatedAuthPersistence
	}
	defer clearSAMLLookupWire(&wire)
	var pending samlPendingTransactionWire
	defer clearSAMLPendingTransactionWire(&pending)
	if err := repository.queryJSON(ctx, lookupSAMLAuthenticationTransactionSQL, wire, &pending); err != nil {
		return federatedsaml.PendingTransaction{}, err
	}
	return samlPendingTransactionFromWire(pending)
}

func (repository *FederatedAuthRepository) CheckFederatedAuthenticationReadiness(ctx context.Context) error {
	if repository == nil || repository.queryer == nil || ctx == nil || ctx.Err() != nil {
		return errFederatedAuthPersistence
	}
	if runtimeVerifiedInProbe(ctx, repository.queryer) {
		return nil
	}
	var ready bool
	if err := repository.queryer.QueryRow(ctx, federatedAuthenticationReadinessSQL).Scan(&ready); err != nil ||
		ctx.Err() != nil || !ready {
		return errFederatedAuthPersistence
	}
	return nil
}

func (repository *FederatedAuthRepository) queryJSON(
	ctx context.Context,
	query string,
	request any,
	response any,
) error {
	return repository.queryBoundedJSON(ctx, query, request, response, maximumFederatedAuthenticationWireBytes)
}

func (repository *FederatedAuthRepository) queryJSONWithResponseLimit(
	ctx context.Context,
	query string,
	request any,
	response any,
	maximumResponseBytes int,
) error {
	return repository.queryJSONWithLimits(
		ctx, query, request, response,
		maximumFederatedAuthenticationWireBytes, maximumResponseBytes,
	)
}

func (repository *FederatedAuthRepository) queryBoundedJSON(
	ctx context.Context,
	query string,
	request any,
	response any,
	maximumBytes int,
) error {
	return repository.queryJSONWithLimits(ctx, query, request, response, maximumBytes, maximumBytes)
}

func (repository *FederatedAuthRepository) queryJSONWithLimits(
	ctx context.Context,
	query string,
	request any,
	response any,
	maximumRequestBytes int,
	maximumResponseBytes int,
) error {
	if repository == nil || repository.queryer == nil || ctx == nil || ctx.Err() != nil || response == nil {
		return errFederatedAuthPersistence
	}
	payload, err := json.Marshal(request)
	if err != nil || maximumRequestBytes < 1 || maximumResponseBytes < 1 ||
		len(payload) == 0 || len(payload) > maximumRequestBytes {
		clear(payload)
		return errFederatedAuthPersistence
	}
	defer clear(payload)
	var raw []byte
	if err := repository.queryer.QueryRow(ctx, query, payload).Scan(&raw); err != nil {
		clear(raw)
		return errFederatedAuthPersistence
	}
	defer clear(raw)
	if ctx.Err() != nil || len(raw) == 0 || len(raw) > maximumResponseBytes {
		return errFederatedAuthPersistence
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(response); err != nil {
		return errFederatedAuthPersistence
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errFederatedAuthPersistence
	}
	return nil
}
