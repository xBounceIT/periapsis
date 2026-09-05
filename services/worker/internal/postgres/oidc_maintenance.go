package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/services/worker/internal/oidcmaintenance"
)

const (
	cleanupFederatedMaintenanceQuery = `SELECT app.cleanup_federated_maintenance_retention_v1($1::jsonb)`
	expireOIDCAccessLeaseQuery       = `SELECT app.expire_oidc_access_lease_v1($1::jsonb)`
	claimDueOIDCMaintenanceQuery     = `SELECT app.claim_due_oidc_maintenance_v1($1::jsonb)`
	loadOIDCMaintenanceSecretQuery   = `SELECT app.load_oidc_maintenance_client_secret_envelope_v1($1::jsonb)`
	completeOIDCRefreshQuery         = `SELECT app.complete_tenant_oidc_refresh_rotation_v1($1::jsonb)`
	completeOIDCLogoutQuery          = `SELECT app.complete_tenant_oidc_logout_retry_v1($1::jsonb)`
	oidcMaintenanceQueueQuery        = `SELECT app.get_oidc_maintenance_queue_snapshot_v1($1::jsonb)`
	oidcMaintenanceReadinessQuery    = `SELECT app.tenant_oidc_session_lifecycle_schema_readiness_v1()`

	maximumOIDCMaintenanceWireBytes  = 1024 * 1024
	maximumOIDCSecretCiphertextBytes = 8*1024 + 16
	maximumOIDCMaintenanceClockSkew  = 5 * time.Minute
)

type oidcMaintenanceQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// OIDCMaintenanceRepository calls only the worker-role OIDC maintenance ABI.
// It owns no table privileges and rejects non-canonical JSON projections.
type OIDCMaintenanceRepository struct {
	pool oidcMaintenanceQuerier
}

func NewOIDCMaintenanceRepository(pool *pgxpool.Pool) *OIDCMaintenanceRepository {
	return newOIDCMaintenanceRepositoryWithQuerier(pool)
}

func newOIDCMaintenanceRepositoryWithQuerier(pool oidcMaintenanceQuerier) *OIDCMaintenanceRepository {
	return &OIDCMaintenanceRepository{pool: pool}
}

var _ oidcmaintenance.Repository = (*OIDCMaintenanceRepository)(nil)

type oidcMaintenanceClaimRequestWire struct {
	Kind       oidcmaintenance.Kind `json:"kind"`
	ObservedAt time.Time            `json:"observedAt"`
}

type oidcMaintenancePhaseRequestWire struct {
	Kind       string    `json:"kind"`
	ObservedAt time.Time `json:"observedAt"`
}

type oidcMaintenanceCleanupReceiptWire struct {
	Kind       string    `json:"kind"`
	ObservedAt time.Time `json:"observedAt"`
	Removed    *int      `json:"removed"`
}

type oidcAccessExpiryReceiptWire struct {
	Kind       string    `json:"kind"`
	ObservedAt time.Time `json:"observedAt"`
	Expired    *bool     `json:"expired"`
}

var oidcMaintenanceCleanupKinds = [...]string{
	"logout_continuation",
	"consumed_refresh",
	"saml_material",
}

type oidcProviderWire struct {
	Scope      string  `json:"scope"`
	TenantID   *string `json:"tenantId,omitempty"`
	ProviderID string  `json:"providerId"`
	BindingID  *string `json:"bindingId,omitempty"`
}

type oidcAdmissionWire struct {
	TenantID  string `json:"tenantId"`
	BindingID string `json:"bindingId"`
}

type oidcProtectedTokenWire struct {
	KeyVersion uint32 `json:"keyVersion"`
	Ciphertext []byte `json:"ciphertext"`
}

type oidcRefreshWorkWire struct {
	Kind                  oidcmaintenance.Kind                   `json:"kind"`
	Category              string                                 `json:"category"`
	ObservedAt            time.Time                              `json:"observedAt"`
	TenantID              *string                                `json:"tenantId"`
	EffectiveTenantID     *string                                `json:"effectiveTenantId"`
	MaterialID            string                                 `json:"materialId"`
	SessionFamilyID       string                                 `json:"sessionFamilyId"`
	Generation            uint64                                 `json:"generation"`
	Version               uint64                                 `json:"version"`
	LeaseExpiresAt        time.Time                              `json:"leaseExpiresAt"`
	Provider              oidcProviderWire                       `json:"provider"`
	Admission             *oidcAdmissionWire                     `json:"admission,omitempty"`
	BindingID             *string                                `json:"bindingId"`
	ClientSecretRevision  uint64                                 `json:"clientSecretRevision"`
	Endpoint              string                                 `json:"endpoint"`
	ClientAuthentication  federatedoidc.ClientAuthenticationMode `json:"clientAuthentication"`
	ClientID              string                                 `json:"clientId"`
	Token                 oidcProtectedTokenWire                 `json:"token"`
	TokenDigest           []byte                                 `json:"tokenDigest"`
	MaterialExpiresAt     time.Time                              `json:"materialExpiresAt"`
	AbsoluteSessionExpiry time.Time                              `json:"absoluteSessionExpiry"`
}

type oidcLogoutWorkWire struct {
	Kind                 oidcmaintenance.Kind                   `json:"kind"`
	ObservedAt           time.Time                              `json:"observedAt"`
	JobID                string                                 `json:"jobId"`
	TenantID             *string                                `json:"tenantId"`
	MaterialID           string                                 `json:"materialId"`
	SessionFamilyID      string                                 `json:"sessionFamilyId"`
	Attempt              int                                    `json:"attempt"`
	MaximumAttempts      int                                    `json:"maximumAttempts"`
	ClaimVersion         uint64                                 `json:"claimVersion"`
	LeaseExpiresAt       time.Time                              `json:"leaseExpiresAt"`
	NotBefore            time.Time                              `json:"notBefore"`
	Provider             oidcProviderWire                       `json:"provider"`
	Admission            *oidcAdmissionWire                     `json:"admission,omitempty"`
	ClientSecretRevision uint64                                 `json:"clientSecretRevision"`
	ClientAuthentication federatedoidc.ClientAuthenticationMode `json:"clientAuthentication"`
	ClientID             string                                 `json:"clientId"`
	Endpoint             string                                 `json:"endpoint"`
	RefreshGeneration    uint64                                 `json:"refreshGeneration"`
	TokenDigest          []byte                                 `json:"tokenDigest"`
	MaterialExpiresAt    time.Time                              `json:"materialExpiresAt"`
	OpaqueReference      oidcProtectedTokenWire                 `json:"opaqueReference"`
}

type oidcScrubWorkWire struct {
	Kind           oidcmaintenance.Kind `json:"kind"`
	ObservedAt     time.Time            `json:"observedAt"`
	MaterialID     string               `json:"materialId"`
	OperationRunID string               `json:"operationRunId"`
	CompletedAt    time.Time            `json:"completedAt"`
}

type oidcQueueSnapshotEnvelopeWire struct {
	ObservedAt time.Time       `json:"observedAt"`
	Categories json.RawMessage `json:"categories"`
}

type oidcQueueCategoriesWire struct {
	LogoutRetry json.RawMessage `json:"logout_retry"`
	Refresh     json.RawMessage `json:"refresh"`
	Scrub       json.RawMessage `json:"scrub"`
}

type oidcQueueCategoryWire struct {
	DueCount         int64      `json:"dueCount"`
	ReclaimableCount int64      `json:"reclaimableCount"`
	DeadLetterCount  int64      `json:"deadLetterCount"`
	OldestDueAt      *time.Time `json:"oldestDueAt"`
}

type oidcSecretLookupWire struct {
	Provider          oidcProviderWire     `json:"provider"`
	Admission         *oidcAdmissionWire   `json:"admission,omitempty"`
	BindingID         *string              `json:"bindingId"`
	Revision          uint64               `json:"revision"`
	Kind              oidcmaintenance.Kind `json:"kind"`
	MaterialID        string               `json:"materialId"`
	SessionFamilyID   string               `json:"sessionFamilyId"`
	ClaimVersion      uint64               `json:"claimVersion"`
	RefreshGeneration uint64               `json:"refreshGeneration"`
	JobID             *string              `json:"jobId,omitempty"`
	Attempt           *int                 `json:"attempt,omitempty"`
}

type oidcSecretEnvelopeWire struct {
	Lookup     oidcSecretLookupWire `json:"lookup"`
	SecretID   string               `json:"secretId"`
	KeyVersion int16                `json:"keyVersion"`
	Nonce      []byte               `json:"nonce"`
	Ciphertext []byte               `json:"ciphertext"`
}

type oidcRefreshCompletionWire struct {
	TenantID            *string                        `json:"tenantId"`
	EffectiveTenantID   *string                        `json:"effectiveTenantId"`
	MaterialID          string                         `json:"materialId"`
	SessionFamilyID     string                         `json:"sessionFamilyId"`
	ExpectedVersion     uint64                         `json:"expectedVersion"`
	ExpectedGeneration  uint64                         `json:"expectedGeneration"`
	Outcome             oidcmaintenance.RefreshOutcome `json:"outcome"`
	SuccessorGeneration *uint64                        `json:"successorGeneration,omitempty"`
	SuccessorDigest     []byte                         `json:"successorDigest,omitempty"`
	SuccessorToken      *oidcProtectedTokenWire        `json:"successorToken,omitempty"`
	AccessExpiresAt     *time.Time                     `json:"accessExpiresAt,omitempty"`
	CompletedAt         time.Time                      `json:"completedAt"`
}

type oidcLogoutCompletionWire struct {
	JobID           string                        `json:"jobId"`
	Attempt         int                           `json:"attempt"`
	ExpectedVersion uint64                        `json:"expectedVersion"`
	Outcome         oidcmaintenance.LogoutOutcome `json:"outcome"`
	CompletedAt     time.Time                     `json:"completedAt"`
	NextTryAt       *time.Time                    `json:"nextTryAt,omitempty"`
}

func (repository *OIDCMaintenanceRepository) Ready(ctx context.Context) error {
	if !validOIDCMaintenanceRepositoryCall(repository, ctx) {
		return oidcmaintenance.ErrInvalidInput
	}
	var ready bool
	if err := repository.pool.QueryRow(ctx, oidcMaintenanceReadinessQuery).Scan(&ready); err != nil ||
		!ready || ctx.Err() != nil {
		return oidcmaintenance.ErrUnavailable
	}
	return nil
}

func (repository *OIDCMaintenanceRepository) QueueSnapshot(
	ctx context.Context,
) (oidcmaintenance.QueueSnapshot, error) {
	if !validOIDCMaintenanceRepositoryCall(repository, ctx) {
		return oidcmaintenance.QueueSnapshot{}, oidcmaintenance.ErrInvalidInput
	}
	payload, err := marshalOIDCMaintenanceWire(struct{}{})
	if err != nil {
		return oidcmaintenance.QueueSnapshot{}, oidcmaintenance.ErrInvalidInput
	}
	defer clear(payload)
	var response []byte
	if err := repository.pool.QueryRow(ctx, oidcMaintenanceQueueQuery, payload).Scan(&response); err != nil ||
		ctx.Err() != nil || response == nil {
		clear(response)
		return oidcmaintenance.QueueSnapshot{}, oidcmaintenance.ErrUnavailable
	}
	defer clear(response)
	snapshot, err := decodeOIDCMaintenanceQueueSnapshot(response)
	if err != nil {
		return oidcmaintenance.QueueSnapshot{}, oidcmaintenance.ErrInvalidProjection
	}
	return snapshot, nil
}

func (repository *OIDCMaintenanceRepository) ClaimDue(
	ctx context.Context,
	kind oidcmaintenance.Kind,
	observedAt time.Time,
) (*oidcmaintenance.Work, error) {
	if !validOIDCMaintenanceRepositoryCall(repository, ctx) || !validOIDCMaintenanceKind(kind) ||
		!validOIDCMaintenanceInstant(observedAt) {
		return nil, oidcmaintenance.ErrInvalidInput
	}
	payload, err := marshalOIDCMaintenanceWire(oidcMaintenanceClaimRequestWire{Kind: kind, ObservedAt: observedAt})
	if err != nil {
		return nil, oidcmaintenance.ErrInvalidInput
	}
	defer clear(payload)
	var response []byte
	if err := repository.pool.QueryRow(ctx, claimDueOIDCMaintenanceQuery, payload).Scan(&response); err != nil ||
		ctx.Err() != nil {
		clear(response)
		return nil, oidcmaintenance.ErrUnavailable
	}
	defer clear(response)
	if response == nil {
		return nil, nil
	}
	work, err := decodeOIDCMaintenanceWork(response, kind, observedAt)
	if err != nil {
		return nil, oidcmaintenance.ErrInvalidProjection
	}
	return work, nil
}

func (repository *OIDCMaintenanceRepository) ExpireAccessLease(
	ctx context.Context,
	observedAt time.Time,
) error {
	if !validOIDCMaintenanceRepositoryCall(repository, ctx) ||
		!validOIDCMaintenanceInstant(observedAt) {
		return oidcmaintenance.ErrInvalidInput
	}
	payload, err := marshalOIDCMaintenanceWire(oidcMaintenancePhaseRequestWire{
		Kind: "access_expiry", ObservedAt: observedAt,
	})
	if err != nil {
		return oidcmaintenance.ErrInvalidInput
	}
	defer clear(payload)
	var response []byte
	if err := repository.pool.QueryRow(ctx, expireOIDCAccessLeaseQuery, payload).Scan(&response); err != nil ||
		ctx.Err() != nil || response == nil {
		clear(response)
		return oidcmaintenance.ErrUnavailable
	}
	defer clear(response)
	var receipt oidcAccessExpiryReceiptWire
	properties := []string{"kind", "observedAt", "expired"}
	if err := decodeExactOIDCObject(response, &receipt, properties, properties); err != nil ||
		receipt.Kind != "access_expiry" ||
		receipt.Expired == nil ||
		!validOIDCMaintenanceObservedAt(receipt.ObservedAt, observedAt) {
		return oidcmaintenance.ErrInvalidProjection
	}
	return nil
}

func (repository *OIDCMaintenanceRepository) CleanupFederatedRetention(
	ctx context.Context,
	observedAt time.Time,
) error {
	if !validOIDCMaintenanceRepositoryCall(repository, ctx) ||
		!validOIDCMaintenanceInstant(observedAt) {
		return oidcmaintenance.ErrInvalidInput
	}
	for _, kind := range oidcMaintenanceCleanupKinds {
		if err := repository.cleanupFederatedRetentionKind(ctx, kind, observedAt); err != nil {
			return err
		}
	}
	return nil
}

func (repository *OIDCMaintenanceRepository) cleanupFederatedRetentionKind(
	ctx context.Context,
	kind string,
	observedAt time.Time,
) error {
	payload, err := marshalOIDCMaintenanceWire(oidcMaintenancePhaseRequestWire{
		Kind: kind, ObservedAt: observedAt,
	})
	if err != nil {
		return oidcmaintenance.ErrInvalidInput
	}
	defer clear(payload)
	var response []byte
	if err := repository.pool.QueryRow(ctx, cleanupFederatedMaintenanceQuery, payload).Scan(&response); err != nil ||
		ctx.Err() != nil || response == nil {
		clear(response)
		return oidcmaintenance.ErrUnavailable
	}
	defer clear(response)
	var receipt oidcMaintenanceCleanupReceiptWire
	properties := []string{"kind", "observedAt", "removed"}
	maximumRemoved := 100
	if kind == "saml_material" {
		maximumRemoved = 2
	}
	if err := decodeExactOIDCObject(response, &receipt, properties, properties); err != nil ||
		receipt.Kind != kind ||
		receipt.Removed == nil ||
		!validOIDCMaintenanceObservedAt(receipt.ObservedAt, observedAt) ||
		*receipt.Removed < 0 || *receipt.Removed > maximumRemoved {
		return oidcmaintenance.ErrInvalidProjection
	}
	return nil
}

func (repository *OIDCMaintenanceRepository) LoadClientSecret(
	ctx context.Context,
	lookup oidcmaintenance.ClientSecretLookup,
) (oidcmaintenance.ClientSecretSnapshot, error) {
	if !validOIDCMaintenanceRepositoryCall(repository, ctx) {
		return oidcmaintenance.ClientSecretSnapshot{}, oidcmaintenance.ErrInvalidInput
	}
	wire, err := oidcSecretLookupToWire(lookup)
	if err != nil {
		return oidcmaintenance.ClientSecretSnapshot{}, oidcmaintenance.ErrInvalidInput
	}
	payload, err := marshalOIDCMaintenanceWire(wire)
	if err != nil {
		return oidcmaintenance.ClientSecretSnapshot{}, oidcmaintenance.ErrInvalidInput
	}
	defer clear(payload)
	var response []byte
	if err := repository.pool.QueryRow(ctx, loadOIDCMaintenanceSecretQuery, payload).Scan(&response); err != nil ||
		ctx.Err() != nil || response == nil {
		clear(response)
		return oidcmaintenance.ClientSecretSnapshot{}, oidcmaintenance.ErrUnavailable
	}
	defer clear(response)
	var envelope oidcSecretEnvelopeWire
	if err := decodeExactOIDCObject(
		response, &envelope,
		[]string{"lookup", "secretId", "keyVersion", "nonce", "ciphertext"},
		[]string{"lookup", "secretId", "keyVersion", "nonce", "ciphertext"},
	); err != nil {
		clear(envelope.Nonce)
		clear(envelope.Ciphertext)
		return oidcmaintenance.ClientSecretSnapshot{}, oidcmaintenance.ErrInvalidProjection
	}
	defer clear(envelope.Nonce)
	defer clear(envelope.Ciphertext)
	var responseObject map[string]json.RawMessage
	if err := json.Unmarshal(response, &responseObject); err != nil ||
		validateOIDCSecretLookupDocument(responseObject["lookup"]) != nil {
		return oidcmaintenance.ClientSecretSnapshot{}, oidcmaintenance.ErrInvalidProjection
	}
	returnedLookup, err := oidcSecretLookupFromWire(envelope.Lookup)
	secretID, secretErr := parseOIDCMaintenanceID(envelope.SecretID, false)
	if err != nil || secretErr != nil || returnedLookup != lookup || envelope.KeyVersion < 1 ||
		len(envelope.Nonce) != 12 || allZeroOIDCBytes(envelope.Nonce) ||
		len(envelope.Ciphertext) <= 16 || len(envelope.Ciphertext) > maximumOIDCSecretCiphertextBytes {
		return oidcmaintenance.ClientSecretSnapshot{}, oidcmaintenance.ErrInvalidProjection
	}
	var nonce [12]byte
	copy(nonce[:], envelope.Nonce)
	return oidcmaintenance.ClientSecretSnapshot{
		Lookup: lookup, SecretID: secretID,
		Envelope: identity.OIDCClientSecretEnvelope{
			KeyVersion: envelope.KeyVersion, Nonce: nonce,
			Ciphertext: append([]byte(nil), envelope.Ciphertext...),
		},
	}, nil
}

func (repository *OIDCMaintenanceRepository) CompleteRefresh(
	ctx context.Context,
	completion oidcmaintenance.RefreshCompletion,
) (bool, error) {
	wire, err := oidcRefreshCompletionToWire(completion)
	if err != nil {
		return false, oidcmaintenance.ErrInvalidInput
	}
	defer clear(wire.SuccessorDigest)
	if wire.SuccessorToken != nil {
		defer clear(wire.SuccessorToken.Ciphertext)
	}
	return repository.executeOIDCMaintenanceBoolean(ctx, completeOIDCRefreshQuery, wire)
}

func (repository *OIDCMaintenanceRepository) CompleteLogout(
	ctx context.Context,
	completion oidcmaintenance.LogoutCompletion,
) (bool, error) {
	wire, err := oidcLogoutCompletionToWire(completion)
	if err != nil {
		return false, oidcmaintenance.ErrInvalidInput
	}
	return repository.executeOIDCMaintenanceBoolean(ctx, completeOIDCLogoutQuery, wire)
}

func (repository *OIDCMaintenanceRepository) executeOIDCMaintenanceBoolean(
	ctx context.Context,
	query string,
	wire any,
) (bool, error) {
	if !validOIDCMaintenanceRepositoryCall(repository, ctx) {
		return false, oidcmaintenance.ErrInvalidInput
	}
	payload, err := marshalOIDCMaintenanceWire(wire)
	if err != nil {
		return false, oidcmaintenance.ErrInvalidInput
	}
	defer clear(payload)
	var applied bool
	if err := repository.pool.QueryRow(ctx, query, payload).Scan(&applied); err != nil || ctx.Err() != nil {
		return false, oidcmaintenance.ErrUnavailable
	}
	return applied, nil
}

func decodeOIDCMaintenanceWork(
	payload []byte,
	expectedKind oidcmaintenance.Kind,
	observedAt time.Time,
) (*oidcmaintenance.Work, error) {
	var discriminator struct {
		Kind oidcmaintenance.Kind `json:"kind"`
	}
	if err := json.Unmarshal(payload, &discriminator); err != nil || discriminator.Kind != expectedKind {
		return nil, errors.New("invalid OIDC work discriminator")
	}
	switch discriminator.Kind {
	case oidcmaintenance.KindRefresh:
		return decodeOIDCRefreshWork(payload, observedAt)
	case oidcmaintenance.KindLogoutRetry:
		return decodeOIDCLogoutWork(payload, observedAt)
	case oidcmaintenance.KindScrub:
		return decodeOIDCScrubWork(payload, observedAt)
	default:
		return nil, errors.New("invalid OIDC work discriminator")
	}
}

func decodeOIDCRefreshWork(payload []byte, observedAt time.Time) (*oidcmaintenance.Work, error) {
	var wire oidcRefreshWorkWire
	allowed := []string{"kind", "category", "observedAt", "tenantId", "effectiveTenantId", "materialId", "sessionFamilyId", "generation", "version",
		"leaseExpiresAt", "provider", "admission", "bindingId", "clientSecretRevision", "endpoint",
		"clientAuthentication", "clientId", "token", "tokenDigest", "materialExpiresAt", "absoluteSessionExpiry"}
	required := []string{"kind", "category", "observedAt", "tenantId", "effectiveTenantId", "materialId", "sessionFamilyId", "generation", "version",
		"leaseExpiresAt", "provider", "bindingId", "clientSecretRevision", "endpoint", "clientAuthentication",
		"clientId", "token", "tokenDigest", "materialExpiresAt", "absoluteSessionExpiry"}
	if err := decodeExactOIDCObject(payload, &wire, allowed, required); err != nil ||
		validateOIDCNestedProjection(payload, "token") != nil ||
		wire.Kind != oidcmaintenance.KindRefresh || wire.Category != "claimed" {
		return nil, errors.New("invalid OIDC refresh projection")
	}
	tenantID, err := parseOptionalOIDCMaintenanceID(wire.TenantID)
	effectiveTenantID, effectiveTenantErr := parseOptionalOIDCMaintenanceID(wire.EffectiveTenantID)
	materialID, materialErr := parseOIDCMaintenanceID(wire.MaterialID, false)
	familyID, familyErr := parseOIDCMaintenanceID(wire.SessionFamilyID, false)
	bindingID, bindingErr := parseOptionalOIDCMaintenanceID(wire.BindingID)
	provider, admission, providerErr := oidcProviderFromWire(wire.Provider, wire.Admission, tenantID, bindingID)
	if err != nil || effectiveTenantErr != nil || materialErr != nil || familyErr != nil || bindingErr != nil ||
		providerErr != nil || !validOIDCMaintenanceObservedAt(wire.ObservedAt, observedAt) ||
		len(wire.TokenDigest) != sha256.Size || allZeroOIDCBytes(wire.TokenDigest) {
		return nil, errors.New("invalid OIDC refresh projection")
	}
	claim := &oidcmaintenance.RefreshClaim{
		TenantID: tenantID, EffectiveTenantID: effectiveTenantID,
		MaterialID: materialID, SessionFamilyID: familyID,
		Generation: wire.Generation, Version: wire.Version, LeaseExpiresAt: wire.LeaseExpiresAt,
		Provider: provider, Admission: admission, BindingID: bindingID,
		ClientSecretRevision: wire.ClientSecretRevision, Endpoint: wire.Endpoint,
		ClientAuthentication: wire.ClientAuthentication, ClientID: wire.ClientID,
		Token: oidcmaintenance.ProtectedToken{
			KeyVersion: wire.Token.KeyVersion, Ciphertext: append([]byte(nil), wire.Token.Ciphertext...),
		},
		MaterialExpiresAt: wire.MaterialExpiresAt, AbsoluteSessionExpiry: wire.AbsoluteSessionExpiry,
	}
	copy(claim.TokenDigest[:], wire.TokenDigest)
	work := &oidcmaintenance.Work{
		ObservedAt: wire.ObservedAt, Kind: oidcmaintenance.KindRefresh, Refresh: claim,
	}
	if !validOIDCRefreshProjection(*claim, wire.ObservedAt) {
		clear(claim.Token.Ciphertext)
		return nil, errors.New("invalid OIDC refresh projection")
	}
	return work, nil
}

func decodeOIDCLogoutWork(payload []byte, observedAt time.Time) (*oidcmaintenance.Work, error) {
	var wire oidcLogoutWorkWire
	allowed := []string{"kind", "observedAt", "jobId", "tenantId", "materialId", "sessionFamilyId", "attempt", "maximumAttempts",
		"claimVersion", "leaseExpiresAt", "notBefore", "provider", "admission", "clientSecretRevision",
		"clientAuthentication", "clientId", "endpoint", "refreshGeneration", "tokenDigest", "materialExpiresAt",
		"opaqueReference"}
	required := []string{"kind", "observedAt", "jobId", "tenantId", "materialId", "sessionFamilyId", "attempt", "maximumAttempts",
		"claimVersion", "leaseExpiresAt", "notBefore", "provider", "clientSecretRevision", "clientAuthentication",
		"clientId", "endpoint", "refreshGeneration", "tokenDigest", "materialExpiresAt", "opaqueReference"}
	if err := decodeExactOIDCObject(payload, &wire, allowed, required); err != nil ||
		validateOIDCNestedProjection(payload, "opaqueReference") != nil ||
		wire.Kind != oidcmaintenance.KindLogoutRetry {
		return nil, errors.New("invalid OIDC logout projection")
	}
	jobID, jobErr := parseOIDCMaintenanceID(wire.JobID, false)
	tenantID, tenantErr := parseOptionalOIDCMaintenanceID(wire.TenantID)
	materialID, materialErr := parseOIDCMaintenanceID(wire.MaterialID, false)
	familyID, familyErr := parseOIDCMaintenanceID(wire.SessionFamilyID, false)
	var bindingWire *string
	switch wire.Provider.Scope {
	case "tenant":
		bindingWire = wire.Provider.BindingID
	case "platform":
		if wire.Admission != nil {
			bindingWire = &wire.Admission.BindingID
		}
	}
	bindingID, bindingErr := parseOptionalOIDCMaintenanceID(bindingWire)
	provider, admission, providerErr := oidcProviderFromWire(wire.Provider, wire.Admission, tenantID, bindingID)
	if jobErr != nil || tenantErr != nil || materialErr != nil || familyErr != nil || bindingErr != nil ||
		providerErr != nil || !validOIDCMaintenanceObservedAt(wire.ObservedAt, observedAt) ||
		len(wire.TokenDigest) != sha256.Size || allZeroOIDCBytes(wire.TokenDigest) {
		return nil, errors.New("invalid OIDC logout projection")
	}
	claim := &oidcmaintenance.LogoutRetryClaim{
		JobID: jobID, TenantID: tenantID, MaterialID: materialID, SessionFamilyID: familyID,
		Attempt: wire.Attempt, MaximumAttempts: wire.MaximumAttempts, ClaimVersion: wire.ClaimVersion,
		LeaseExpiresAt: wire.LeaseExpiresAt, NotBefore: wire.NotBefore,
		Provider: provider, Admission: admission, BindingID: bindingID,
		ClientSecretRevision: wire.ClientSecretRevision, ClientAuthentication: wire.ClientAuthentication,
		ClientID: wire.ClientID, Endpoint: wire.Endpoint, RefreshGeneration: wire.RefreshGeneration,
		MaterialExpiresAt: wire.MaterialExpiresAt,
		OpaqueReference: oidcmaintenance.ProtectedToken{
			KeyVersion: wire.OpaqueReference.KeyVersion,
			Ciphertext: append([]byte(nil), wire.OpaqueReference.Ciphertext...),
		},
	}
	copy(claim.TokenDigest[:], wire.TokenDigest)
	if !validOIDCLogoutProjection(*claim, wire.ObservedAt) {
		clear(claim.OpaqueReference.Ciphertext)
		return nil, errors.New("invalid OIDC logout projection")
	}
	return &oidcmaintenance.Work{
		ObservedAt: wire.ObservedAt, Kind: oidcmaintenance.KindLogoutRetry, LogoutRetry: claim,
	}, nil
}

func decodeOIDCScrubWork(payload []byte, observedAt time.Time) (*oidcmaintenance.Work, error) {
	var wire oidcScrubWorkWire
	properties := []string{"kind", "observedAt", "materialId", "operationRunId", "completedAt"}
	if err := decodeExactOIDCObject(payload, &wire, properties, properties); err != nil ||
		wire.Kind != oidcmaintenance.KindScrub || !wire.CompletedAt.Equal(wire.ObservedAt) ||
		!validOIDCMaintenanceObservedAt(wire.ObservedAt, observedAt) {
		return nil, errors.New("invalid OIDC scrub projection")
	}
	materialID, materialErr := parseOIDCMaintenanceID(wire.MaterialID, false)
	operationID, operationErr := parseOIDCMaintenanceID(wire.OperationRunID, false)
	if materialErr != nil || operationErr != nil || !validOIDCMaintenanceInstant(wire.CompletedAt) {
		return nil, errors.New("invalid OIDC scrub projection")
	}
	return &oidcmaintenance.Work{
		ObservedAt: wire.ObservedAt, Kind: oidcmaintenance.KindScrub,
		Scrub: &oidcmaintenance.ScrubReceipt{
			MaterialID: materialID, OperationRunID: operationID, CompletedAt: wire.CompletedAt,
		},
	}, nil
}

func decodeOIDCMaintenanceQueueSnapshot(payload []byte) (oidcmaintenance.QueueSnapshot, error) {
	var envelope oidcQueueSnapshotEnvelopeWire
	properties := []string{"observedAt", "categories"}
	if err := decodeExactOIDCObject(payload, &envelope, properties, properties); err != nil ||
		!validOIDCMaintenanceInstant(envelope.ObservedAt) {
		return oidcmaintenance.QueueSnapshot{}, errors.New("invalid OIDC queue snapshot")
	}
	var categories oidcQueueCategoriesWire
	categoryNames := []string{"logout_retry", "refresh", "scrub"}
	if err := decodeExactOIDCObject(
		envelope.Categories, &categories, categoryNames, categoryNames,
	); err != nil {
		return oidcmaintenance.QueueSnapshot{}, errors.New("invalid OIDC queue snapshot")
	}
	logout, err := decodeOIDCQueueCategory(
		categories.LogoutRetry,
		[]string{"dueCount", "reclaimableCount", "deadLetterCount", "oldestDueAt"},
		envelope.ObservedAt,
	)
	if err != nil {
		return oidcmaintenance.QueueSnapshot{}, err
	}
	refresh, err := decodeOIDCQueueCategory(
		categories.Refresh,
		[]string{"dueCount", "reclaimableCount", "oldestDueAt"},
		envelope.ObservedAt,
	)
	if err != nil {
		return oidcmaintenance.QueueSnapshot{}, err
	}
	scrub, err := decodeOIDCQueueCategory(
		categories.Scrub,
		[]string{"dueCount", "oldestDueAt"},
		envelope.ObservedAt,
	)
	if err != nil {
		return oidcmaintenance.QueueSnapshot{}, err
	}
	return oidcmaintenance.QueueSnapshot{
		ObservedAt: envelope.ObservedAt, LogoutRetry: logout, Refresh: refresh, Scrub: scrub,
	}, nil
}

func decodeOIDCQueueCategory(
	payload []byte,
	properties []string,
	observedAt time.Time,
) (oidcmaintenance.QueueCategorySnapshot, error) {
	var wire oidcQueueCategoryWire
	if err := decodeExactOIDCObject(payload, &wire, properties, properties); err != nil ||
		wire.DueCount < 0 || wire.ReclaimableCount < 0 || wire.DeadLetterCount < 0 ||
		uint64(wire.DueCount) > oidcmaintenance.MaximumPersistentCount ||
		uint64(wire.ReclaimableCount) > oidcmaintenance.MaximumPersistentCount ||
		uint64(wire.DeadLetterCount) > oidcmaintenance.MaximumPersistentCount ||
		wire.ReclaimableCount > wire.DueCount ||
		(wire.DueCount == 0) != (wire.OldestDueAt == nil) ||
		(wire.OldestDueAt != nil && (!validOIDCMaintenanceInstant(*wire.OldestDueAt) ||
			wire.OldestDueAt.After(observedAt))) {
		return oidcmaintenance.QueueCategorySnapshot{}, errors.New("invalid OIDC queue category")
	}
	category := oidcmaintenance.QueueCategorySnapshot{
		DueCount: uint64(wire.DueCount), ReclaimableCount: uint64(wire.ReclaimableCount),
		DeadLetterCount: uint64(wire.DeadLetterCount),
	}
	if wire.OldestDueAt != nil {
		category.OldestDueAt = *wire.OldestDueAt
	}
	return category, nil
}

func oidcSecretLookupToWire(lookup oidcmaintenance.ClientSecretLookup) (oidcSecretLookupWire, error) {
	if !validOIDCSecretLookup(lookup) {
		return oidcSecretLookupWire{}, errors.New("invalid OIDC secret lookup")
	}
	wire := oidcSecretLookupWire{
		Revision: lookup.Revision, Kind: lookup.Kind,
		MaterialID:      uuid.UUID(lookup.MaterialID).String(),
		SessionFamilyID: uuid.UUID(lookup.SessionFamilyID).String(),
		ClaimVersion:    lookup.ClaimVersion, RefreshGeneration: lookup.RefreshGeneration,
	}
	if lookup.Kind == oidcmaintenance.KindLogoutRetry {
		jobID, attempt := uuid.UUID(lookup.JobID).String(), lookup.Attempt
		wire.JobID, wire.Attempt = &jobID, &attempt
	}
	providerID := uuid.UUID(lookup.Provider.ProviderID).String()
	switch lookup.Provider.Scope {
	case identity.TenantProviderScope:
		tenantID := uuid.UUID(lookup.Provider.TenantID).String()
		bindingID := uuid.UUID(lookup.BindingID).String()
		wire.Provider = oidcProviderWire{
			Scope: "tenant", TenantID: &tenantID, ProviderID: providerID, BindingID: &bindingID,
		}
		wire.BindingID = &bindingID
	case identity.PlatformProviderScope:
		wire.Provider = oidcProviderWire{Scope: "platform", ProviderID: providerID}
		if lookup.Admission != (identity.TenantAdmissionContext{}) {
			tenantID := uuid.UUID(lookup.Admission.TenantID).String()
			bindingID := uuid.UUID(lookup.Admission.BindingID).String()
			wire.Admission = &oidcAdmissionWire{TenantID: tenantID, BindingID: bindingID}
			wire.BindingID = &bindingID
		}
	}
	return wire, nil
}

func oidcSecretLookupFromWire(wire oidcSecretLookupWire) (oidcmaintenance.ClientSecretLookup, error) {
	provider, providerBinding, err := oidcProviderContextFromWire(wire.Provider)
	bindingID, bindingErr := parseOptionalOIDCMaintenanceID(wire.BindingID)
	materialID, materialErr := parseOIDCMaintenanceID(wire.MaterialID, false)
	familyID, familyErr := parseOIDCMaintenanceID(wire.SessionFamilyID, false)
	if err != nil || bindingErr != nil || wire.Revision == 0 ||
		wire.Revision >= oidcmaintenance.MaximumPersistentCount || materialErr != nil || familyErr != nil {
		return oidcmaintenance.ClientSecretLookup{}, errors.New("invalid OIDC secret lookup")
	}
	lookup := oidcmaintenance.ClientSecretLookup{
		Provider: provider, Revision: wire.Revision, Kind: wire.Kind,
		MaterialID: materialID, SessionFamilyID: familyID,
		ClaimVersion: wire.ClaimVersion, RefreshGeneration: wire.RefreshGeneration,
	}
	switch wire.Kind {
	case oidcmaintenance.KindRefresh:
		if wire.JobID != nil || wire.Attempt != nil {
			return oidcmaintenance.ClientSecretLookup{}, errors.New("invalid OIDC secret lookup")
		}
	case oidcmaintenance.KindLogoutRetry:
		if wire.JobID == nil || wire.Attempt == nil {
			return oidcmaintenance.ClientSecretLookup{}, errors.New("invalid OIDC secret lookup")
		}
		jobID, jobErr := parseOIDCMaintenanceID(*wire.JobID, false)
		if jobErr != nil {
			return oidcmaintenance.ClientSecretLookup{}, errors.New("invalid OIDC secret lookup")
		}
		lookup.JobID, lookup.Attempt = jobID, *wire.Attempt
	default:
		return oidcmaintenance.ClientSecretLookup{}, errors.New("invalid OIDC secret lookup")
	}
	switch provider.Scope {
	case identity.TenantProviderScope:
		if wire.Admission != nil || bindingID == (identity.EntityID{}) || providerBinding != bindingID {
			return oidcmaintenance.ClientSecretLookup{}, errors.New("invalid OIDC secret lookup")
		}
		lookup.BindingID = bindingID
	case identity.PlatformProviderScope:
		if providerBinding != (identity.EntityID{}) {
			return oidcmaintenance.ClientSecretLookup{}, errors.New("invalid OIDC secret lookup")
		}
		if wire.Admission != nil {
			admission, admissionErr := oidcAdmissionFromWire(*wire.Admission)
			if admissionErr != nil || bindingID == (identity.EntityID{}) || bindingID != admission.BindingID {
				return oidcmaintenance.ClientSecretLookup{}, errors.New("invalid OIDC secret lookup")
			}
			lookup.Admission = admission
		} else if bindingID != (identity.EntityID{}) {
			return oidcmaintenance.ClientSecretLookup{}, errors.New("invalid OIDC secret lookup")
		}
	default:
		return oidcmaintenance.ClientSecretLookup{}, errors.New("invalid OIDC secret lookup")
	}
	if !validOIDCSecretLookup(lookup) {
		return oidcmaintenance.ClientSecretLookup{}, errors.New("invalid OIDC secret lookup")
	}
	return lookup, nil
}

func oidcRefreshCompletionToWire(completion oidcmaintenance.RefreshCompletion) (oidcRefreshCompletionWire, error) {
	tenantID, err := optionalOIDCMaintenanceIDWire(completion.TenantID)
	effectiveTenantID, effectiveTenantErr := optionalOIDCMaintenanceIDWire(completion.EffectiveTenantID)
	materialID, materialErr := requiredOIDCMaintenanceIDWire(completion.MaterialID)
	familyID, familyErr := requiredOIDCMaintenanceIDWire(completion.SessionFamilyID)
	if err != nil || effectiveTenantErr != nil || materialErr != nil || familyErr != nil ||
		completion.ExpectedVersion == 0 ||
		completion.ExpectedVersion >= oidcmaintenance.MaximumPersistentCount || completion.ExpectedGeneration == 0 ||
		completion.ExpectedGeneration >= oidcmaintenance.MaximumPersistentCount ||
		!validOIDCMaintenanceInstant(completion.CompletedAt) {
		return oidcRefreshCompletionWire{}, errors.New("invalid OIDC refresh completion")
	}
	if completion.TenantID != (identity.EntityID{}) && completion.EffectiveTenantID != completion.TenantID {
		return oidcRefreshCompletionWire{}, errors.New("invalid OIDC refresh completion")
	}
	wire := oidcRefreshCompletionWire{
		TenantID: tenantID, EffectiveTenantID: effectiveTenantID,
		MaterialID: materialID, SessionFamilyID: familyID,
		ExpectedVersion: completion.ExpectedVersion, ExpectedGeneration: completion.ExpectedGeneration,
		Outcome: completion.Outcome, CompletedAt: completion.CompletedAt,
	}
	switch completion.Outcome {
	case oidcmaintenance.RefreshRotated:
		if completion.SuccessorGeneration != completion.ExpectedGeneration+1 ||
			completion.SuccessorGeneration >= oidcmaintenance.MaximumPersistentCount ||
			completion.SuccessorDigest == ([sha256.Size]byte{}) ||
			completion.SuccessorToken.KeyVersion == 0 || completion.SuccessorToken.KeyVersion > math.MaxInt16 ||
			len(completion.SuccessorToken.Ciphertext) < 29 || len(completion.SuccessorToken.Ciphertext) > 262172 ||
			!validOIDCMaintenanceInstant(completion.AccessExpiresAt) ||
			!completion.AccessExpiresAt.After(completion.CompletedAt) {
			return oidcRefreshCompletionWire{}, errors.New("invalid OIDC refresh completion")
		}
		generation := completion.SuccessorGeneration
		expiresAt := completion.AccessExpiresAt
		wire.SuccessorGeneration = &generation
		wire.SuccessorDigest = append([]byte(nil), completion.SuccessorDigest[:]...)
		wire.SuccessorToken = &oidcProtectedTokenWire{
			KeyVersion: completion.SuccessorToken.KeyVersion,
			Ciphertext: append([]byte(nil), completion.SuccessorToken.Ciphertext...),
		}
		wire.AccessExpiresAt = &expiresAt
	case oidcmaintenance.RefreshSafeToRetry, oidcmaintenance.RefreshLocalUnavailable,
		oidcmaintenance.RefreshAmbiguous, oidcmaintenance.RefreshRejected:
		if completion.SuccessorGeneration != 0 || completion.SuccessorDigest != ([sha256.Size]byte{}) ||
			completion.SuccessorToken.KeyVersion != 0 || len(completion.SuccessorToken.Ciphertext) != 0 ||
			!completion.AccessExpiresAt.IsZero() {
			return oidcRefreshCompletionWire{}, errors.New("invalid OIDC refresh completion")
		}
	default:
		return oidcRefreshCompletionWire{}, errors.New("invalid OIDC refresh completion")
	}
	return wire, nil
}

func oidcLogoutCompletionToWire(completion oidcmaintenance.LogoutCompletion) (oidcLogoutCompletionWire, error) {
	jobID, err := requiredOIDCMaintenanceIDWire(completion.JobID)
	if err != nil || completion.Attempt < 1 || completion.ExpectedVersion == 0 ||
		completion.ExpectedVersion >= oidcmaintenance.MaximumPersistentCount ||
		!validOIDCMaintenanceInstant(completion.CompletedAt) {
		return oidcLogoutCompletionWire{}, errors.New("invalid OIDC logout completion")
	}
	wire := oidcLogoutCompletionWire{
		JobID: jobID, Attempt: completion.Attempt, ExpectedVersion: completion.ExpectedVersion,
		Outcome: completion.Outcome, CompletedAt: completion.CompletedAt,
	}
	switch completion.Outcome {
	case oidcmaintenance.LogoutSafeToRetry:
		if !validOIDCMaintenanceInstant(completion.NextTryAt) ||
			!completion.NextTryAt.After(completion.CompletedAt) ||
			completion.NextTryAt.After(completion.CompletedAt.Add(15*time.Minute)) {
			return oidcLogoutCompletionWire{}, errors.New("invalid OIDC logout completion")
		}
		next := completion.NextTryAt
		wire.NextTryAt = &next
	case oidcmaintenance.LogoutSucceeded, oidcmaintenance.LogoutLocalUnavailable,
		oidcmaintenance.LogoutAmbiguous, oidcmaintenance.LogoutRejected:
		if !completion.NextTryAt.IsZero() {
			return oidcLogoutCompletionWire{}, errors.New("invalid OIDC logout completion")
		}
	default:
		return oidcLogoutCompletionWire{}, errors.New("invalid OIDC logout completion")
	}
	return wire, nil
}

func oidcProviderFromWire(
	wire oidcProviderWire,
	admissionWire *oidcAdmissionWire,
	tenantID identity.EntityID,
	bindingID identity.EntityID,
) (identity.ProviderContext, identity.TenantAdmissionContext, error) {
	provider, providerBinding, err := oidcProviderContextFromWire(wire)
	if err != nil {
		return identity.ProviderContext{}, identity.TenantAdmissionContext{}, err
	}
	zero := identity.EntityID{}
	switch provider.Scope {
	case identity.TenantProviderScope:
		if admissionWire != nil || tenantID == zero || bindingID == zero || provider.TenantID != tenantID ||
			providerBinding != bindingID {
			return identity.ProviderContext{}, identity.TenantAdmissionContext{}, errors.New("invalid tenant provider")
		}
		return provider, identity.TenantAdmissionContext{}, nil
	case identity.PlatformProviderScope:
		if providerBinding != zero {
			return identity.ProviderContext{}, identity.TenantAdmissionContext{}, errors.New("invalid platform provider")
		}
		if tenantID == zero {
			if admissionWire != nil || bindingID != zero {
				return identity.ProviderContext{}, identity.TenantAdmissionContext{}, errors.New("invalid direct provider")
			}
			return provider, identity.TenantAdmissionContext{}, nil
		}
		if admissionWire == nil || bindingID == zero {
			return identity.ProviderContext{}, identity.TenantAdmissionContext{}, errors.New("missing admission")
		}
		admission, admissionErr := oidcAdmissionFromWire(*admissionWire)
		if admissionErr != nil || admission.TenantID != tenantID || admission.BindingID != bindingID {
			return identity.ProviderContext{}, identity.TenantAdmissionContext{}, errors.New("invalid admission")
		}
		return provider, admission, nil
	default:
		return identity.ProviderContext{}, identity.TenantAdmissionContext{}, errors.New("invalid provider")
	}
}

func oidcProviderContextFromWire(wire oidcProviderWire) (identity.ProviderContext, identity.EntityID, error) {
	providerID, err := parseOIDCMaintenanceID(wire.ProviderID, false)
	if err != nil {
		return identity.ProviderContext{}, identity.EntityID{}, err
	}
	switch wire.Scope {
	case "tenant":
		tenantID, tenantErr := parseOptionalOIDCMaintenanceID(wire.TenantID)
		bindingID, bindingErr := parseOptionalOIDCMaintenanceID(wire.BindingID)
		if tenantErr != nil || bindingErr != nil || tenantID == (identity.EntityID{}) ||
			bindingID == (identity.EntityID{}) {
			return identity.ProviderContext{}, identity.EntityID{}, errors.New("invalid tenant provider")
		}
		return identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: tenantID, ProviderID: providerID,
		}, bindingID, nil
	case "platform":
		if wire.TenantID != nil || wire.BindingID != nil {
			return identity.ProviderContext{}, identity.EntityID{}, errors.New("invalid platform provider")
		}
		return identity.ProviderContext{Scope: identity.PlatformProviderScope, ProviderID: providerID}, identity.EntityID{}, nil
	default:
		return identity.ProviderContext{}, identity.EntityID{}, errors.New("invalid provider scope")
	}
}

func oidcAdmissionFromWire(wire oidcAdmissionWire) (identity.TenantAdmissionContext, error) {
	tenantID, tenantErr := parseOIDCMaintenanceID(wire.TenantID, false)
	bindingID, bindingErr := parseOIDCMaintenanceID(wire.BindingID, false)
	if tenantErr != nil || bindingErr != nil {
		return identity.TenantAdmissionContext{}, errors.New("invalid admission")
	}
	return identity.TenantAdmissionContext{TenantID: tenantID, BindingID: bindingID}, nil
}

func decodeExactOIDCObject(payload []byte, destination any, allowed, required []string) error {
	if len(payload) == 0 || len(payload) > maximumOIDCMaintenanceWireBytes || destination == nil {
		return errors.New("invalid OIDC wire document")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil || object == nil {
		return errors.New("invalid OIDC wire document")
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		allowedSet[name] = struct{}{}
	}
	for name := range object {
		if _, ok := allowedSet[name]; !ok {
			return errors.New("invalid OIDC wire property")
		}
	}
	for _, name := range required {
		if _, ok := object[name]; !ok {
			return errors.New("missing OIDC wire property")
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("invalid OIDC wire document")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("invalid OIDC wire document")
	}
	return nil
}

func validateOIDCNestedProjection(payload []byte, tokenMember string) error {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil || object == nil ||
		validateOIDCProviderDocument(object["provider"]) != nil {
		return errors.New("invalid OIDC nested projection")
	}
	if admission, present := object["admission"]; present && validateOIDCAdmissionDocument(admission) != nil {
		return errors.New("invalid OIDC nested projection")
	}
	if tokenMember != "" && validateOIDCProtectedTokenDocument(object[tokenMember]) != nil {
		return errors.New("invalid OIDC nested projection")
	}
	return nil
}

func validateOIDCSecretLookupDocument(payload []byte) error {
	var wire oidcSecretLookupWire
	var discriminator struct {
		Kind oidcmaintenance.Kind `json:"kind"`
	}
	if err := json.Unmarshal(payload, &discriminator); err != nil {
		return err
	}
	allowed := []string{"provider", "admission", "bindingId", "revision", "kind", "materialId",
		"sessionFamilyId", "claimVersion", "refreshGeneration", "jobId", "attempt"}
	required := []string{"provider", "bindingId", "revision", "kind", "materialId", "sessionFamilyId",
		"claimVersion", "refreshGeneration"}
	if discriminator.Kind == oidcmaintenance.KindLogoutRetry {
		required = append(required, "jobId", "attempt")
	} else if discriminator.Kind != oidcmaintenance.KindRefresh {
		return errors.New("invalid OIDC secret lookup")
	}
	if err := decodeExactOIDCObject(payload, &wire, allowed, required); err != nil {
		return err
	}
	return validateOIDCNestedProjection(payload, "")
}

func validateOIDCProviderDocument(payload []byte) error {
	var discriminator struct {
		Scope string `json:"scope"`
	}
	if err := json.Unmarshal(payload, &discriminator); err != nil {
		return errors.New("invalid OIDC provider")
	}
	var wire oidcProviderWire
	switch discriminator.Scope {
	case "tenant":
		properties := []string{"scope", "tenantId", "providerId", "bindingId"}
		return decodeExactOIDCObject(payload, &wire, properties, properties)
	case "platform":
		properties := []string{"scope", "providerId"}
		return decodeExactOIDCObject(payload, &wire, properties, properties)
	default:
		return errors.New("invalid OIDC provider")
	}
}

func validateOIDCAdmissionDocument(payload []byte) error {
	var wire oidcAdmissionWire
	properties := []string{"tenantId", "bindingId"}
	return decodeExactOIDCObject(payload, &wire, properties, properties)
}

func validateOIDCProtectedTokenDocument(payload []byte) error {
	var wire oidcProtectedTokenWire
	properties := []string{"keyVersion", "ciphertext"}
	return decodeExactOIDCObject(payload, &wire, properties, properties)
}

func marshalOIDCMaintenanceWire(value any) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil || len(payload) == 0 || len(payload) > maximumOIDCMaintenanceWireBytes {
		clear(payload)
		return nil, errors.New("invalid OIDC wire document")
	}
	return payload, nil
}

func parseOptionalOIDCMaintenanceID(value *string) (identity.EntityID, error) {
	if value == nil {
		return identity.EntityID{}, nil
	}
	return parseOIDCMaintenanceID(*value, false)
}

func parseOIDCMaintenanceID(value string, allowZero bool) (identity.EntityID, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed.String() != value || parsed.Version() != 7 || parsed == uuid.Nil {
		if allowZero && value == "" {
			return identity.EntityID{}, nil
		}
		return identity.EntityID{}, errors.New("invalid OIDC identifier")
	}
	return identity.EntityID(parsed), nil
}

func requiredOIDCMaintenanceIDWire(value identity.EntityID) (string, error) {
	parsed := uuid.UUID(value)
	if parsed == uuid.Nil || parsed.Version() != 7 {
		return "", errors.New("invalid OIDC identifier")
	}
	return parsed.String(), nil
}

func optionalOIDCMaintenanceIDWire(value identity.EntityID) (*string, error) {
	if value == (identity.EntityID{}) {
		return nil, nil
	}
	encoded, err := requiredOIDCMaintenanceIDWire(value)
	return &encoded, err
}

func validOIDCMaintenanceRepositoryCall(repository *OIDCMaintenanceRepository, ctx context.Context) bool {
	if repository == nil || repository.pool == nil || ctx == nil || ctx.Err() != nil {
		return false
	}
	value := reflect.ValueOf(repository.pool)
	return value.Kind() != reflect.Pointer || !value.IsNil()
}

func validOIDCMaintenanceKind(kind oidcmaintenance.Kind) bool {
	return kind == oidcmaintenance.KindLogoutRetry || kind == oidcmaintenance.KindRefresh ||
		kind == oidcmaintenance.KindScrub
}

func validOIDCMaintenanceInstant(value time.Time) bool {
	if value.IsZero() || value.Nanosecond()%1000 != 0 || value.Year() < 2000 || value.Year() > 9999 {
		return false
	}
	_, offset := value.Zone()
	return offset == 0
}

func validOIDCMaintenanceObservedAt(databaseObservedAt, requestedAt time.Time) bool {
	if !validOIDCMaintenanceInstant(databaseObservedAt) || !validOIDCMaintenanceInstant(requestedAt) {
		return false
	}
	delta := databaseObservedAt.Sub(requestedAt)
	return delta >= -maximumOIDCMaintenanceClockSkew && delta <= maximumOIDCMaintenanceClockSkew
}

func validOIDCRefreshProjection(claim oidcmaintenance.RefreshClaim, observedAt time.Time) bool {
	return validOIDCMaintenanceID(claim.MaterialID) && validOIDCMaintenanceID(claim.SessionFamilyID) &&
		claim.Generation > 0 && claim.Generation < oidcmaintenance.MaximumPersistentCount &&
		claim.Version > 0 && claim.Version < oidcmaintenance.MaximumPersistentCount &&
		validOIDCRefreshOwnership(
			claim.Provider, claim.TenantID, claim.EffectiveTenantID, claim.Admission, claim.BindingID,
		) &&
		claim.ClientSecretRevision > 0 && claim.ClientSecretRevision < oidcmaintenance.MaximumPersistentCount &&
		validOIDCClientAuthentication(claim.ClientAuthentication) && claim.ClientID != "" &&
		claim.Endpoint != "" && claim.Token.KeyVersion > 0 && claim.Token.KeyVersion <= math.MaxInt16 &&
		len(claim.Token.Ciphertext) >= 29 && len(claim.Token.Ciphertext) <= 262172 &&
		validOIDCMaintenanceInstant(claim.LeaseExpiresAt) && claim.LeaseExpiresAt.After(observedAt) &&
		validOIDCMaintenanceInstant(claim.MaterialExpiresAt) && claim.MaterialExpiresAt.After(observedAt) &&
		!claim.LeaseExpiresAt.After(claim.MaterialExpiresAt) &&
		validOIDCMaintenanceInstant(claim.AbsoluteSessionExpiry) && claim.AbsoluteSessionExpiry.After(observedAt) &&
		!claim.MaterialExpiresAt.After(claim.AbsoluteSessionExpiry)
}

func validOIDCRefreshOwnership(
	provider identity.ProviderContext,
	materialTenant identity.EntityID,
	effectiveTenant identity.EntityID,
	admission identity.TenantAdmissionContext,
	binding identity.EntityID,
) bool {
	if !validOIDCMaintenanceID(provider.ProviderID) {
		return false
	}
	zero := identity.EntityID{}
	switch provider.Scope {
	case identity.TenantProviderScope:
		return validOIDCMaintenanceID(materialTenant) && effectiveTenant == materialTenant &&
			validOIDCMaintenanceID(binding) && provider.TenantID == materialTenant &&
			admission == (identity.TenantAdmissionContext{})
	case identity.PlatformProviderScope:
		if provider.TenantID != zero {
			return false
		}
		if materialTenant == zero {
			return (effectiveTenant == zero || validOIDCMaintenanceID(effectiveTenant)) &&
				binding == zero && admission == (identity.TenantAdmissionContext{})
		}
		return effectiveTenant == materialTenant && validOIDCMaintenanceID(binding) &&
			admission == (identity.TenantAdmissionContext{
				TenantID: materialTenant, BindingID: binding,
			})
	default:
		return false
	}
}

func validOIDCLogoutProjection(claim oidcmaintenance.LogoutRetryClaim, observedAt time.Time) bool {
	return validOIDCMaintenanceID(claim.JobID) && validOIDCMaintenanceID(claim.MaterialID) &&
		validOIDCMaintenanceID(claim.SessionFamilyID) && claim.Attempt > 0 && claim.MaximumAttempts > 0 &&
		claim.MaximumAttempts <= 16 && claim.Attempt <= claim.MaximumAttempts && claim.ClaimVersion > 0 &&
		claim.ClaimVersion < oidcmaintenance.MaximumPersistentCount &&
		validOIDCOwnership(claim.Provider, claim.TenantID, claim.Admission, claim.BindingID) &&
		claim.ClientSecretRevision > 0 && claim.ClientSecretRevision < oidcmaintenance.MaximumPersistentCount &&
		validOIDCClientAuthentication(claim.ClientAuthentication) && claim.ClientID != "" && claim.Endpoint != "" &&
		claim.RefreshGeneration > 0 && claim.RefreshGeneration < oidcmaintenance.MaximumPersistentCount &&
		claim.OpaqueReference.KeyVersion > 0 && claim.OpaqueReference.KeyVersion <= math.MaxInt16 &&
		len(claim.OpaqueReference.Ciphertext) >= 29 && len(claim.OpaqueReference.Ciphertext) <= 262172 &&
		validOIDCMaintenanceInstant(claim.NotBefore) && !claim.NotBefore.After(observedAt) &&
		validOIDCMaintenanceInstant(claim.LeaseExpiresAt) && claim.LeaseExpiresAt.After(observedAt) &&
		validOIDCMaintenanceInstant(claim.MaterialExpiresAt) && claim.MaterialExpiresAt.After(observedAt) &&
		!claim.LeaseExpiresAt.After(claim.MaterialExpiresAt)
}

func validOIDCOwnership(
	provider identity.ProviderContext,
	tenant identity.EntityID,
	admission identity.TenantAdmissionContext,
	binding identity.EntityID,
) bool {
	if !validOIDCMaintenanceID(provider.ProviderID) {
		return false
	}
	zero := identity.EntityID{}
	switch provider.Scope {
	case identity.TenantProviderScope:
		return validOIDCMaintenanceID(tenant) && validOIDCMaintenanceID(binding) && provider.TenantID == tenant &&
			admission == (identity.TenantAdmissionContext{})
	case identity.PlatformProviderScope:
		if provider.TenantID != zero {
			return false
		}
		if tenant == zero {
			return binding == zero && admission == (identity.TenantAdmissionContext{})
		}
		return validOIDCMaintenanceID(tenant) && validOIDCMaintenanceID(binding) &&
			admission == (identity.TenantAdmissionContext{TenantID: tenant, BindingID: binding})
	default:
		return false
	}
}

func validOIDCSecretLookup(lookup oidcmaintenance.ClientSecretLookup) bool {
	if !validOIDCMaintenanceID(lookup.Provider.ProviderID) || lookup.Revision == 0 ||
		lookup.Revision >= oidcmaintenance.MaximumPersistentCount ||
		!validOIDCMaintenanceID(lookup.MaterialID) || !validOIDCMaintenanceID(lookup.SessionFamilyID) ||
		lookup.ClaimVersion == 0 || lookup.ClaimVersion >= oidcmaintenance.MaximumPersistentCount ||
		lookup.RefreshGeneration == 0 || lookup.RefreshGeneration >= oidcmaintenance.MaximumPersistentCount {
		return false
	}
	switch lookup.Kind {
	case oidcmaintenance.KindRefresh:
		if lookup.JobID != (identity.EntityID{}) || lookup.Attempt != 0 {
			return false
		}
	case oidcmaintenance.KindLogoutRetry:
		if !validOIDCMaintenanceID(lookup.JobID) || lookup.Attempt < 1 || lookup.Attempt > 16 {
			return false
		}
	default:
		return false
	}
	zero := identity.EntityID{}
	switch lookup.Provider.Scope {
	case identity.TenantProviderScope:
		return validOIDCMaintenanceID(lookup.Provider.TenantID) && validOIDCMaintenanceID(lookup.BindingID) &&
			lookup.Admission == (identity.TenantAdmissionContext{})
	case identity.PlatformProviderScope:
		return lookup.Provider.TenantID == zero && lookup.BindingID == zero &&
			(lookup.Admission == (identity.TenantAdmissionContext{}) ||
				validOIDCMaintenanceID(lookup.Admission.TenantID) && validOIDCMaintenanceID(lookup.Admission.BindingID))
	default:
		return false
	}
}

func validOIDCMaintenanceID(value identity.EntityID) bool {
	parsed := uuid.UUID(value)
	return parsed != uuid.Nil && parsed.Version() == 7
}

func validOIDCClientAuthentication(value federatedoidc.ClientAuthenticationMode) bool {
	return value == federatedoidc.ClientSecretBasic || value == federatedoidc.ClientSecretPost
}

func allZeroOIDCBytes(value []byte) bool {
	var combined byte
	for _, character := range value {
		combined |= character
	}
	return combined == 0
}
