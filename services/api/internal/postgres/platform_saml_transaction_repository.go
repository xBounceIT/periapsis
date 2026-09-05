package postgres

import (
	"context"
	"crypto/sha256"
	"slices"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamladapter"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamlauth"
)

const (
	createPlatformSAMLTransactionSQL        = `select app.create_platform_saml_authentication_transaction_v1($1::jsonb)`
	recoverPlatformSAMLCreateSQL            = `select app.recover_platform_saml_authentication_transaction_create_v1($1::jsonb)`
	lookupPlatformSAMLTransactionSQL        = `select app.lookup_platform_saml_authentication_transaction_v1($1::jsonb)`
	abortPlatformSAMLTransactionSQL         = `select app.abort_platform_saml_authentication_transaction_v1($1::jsonb)`
	maximumPlatformSAMLTransactionWireBytes = 256 * 1024
)

type platformSAMLBeginTransactionWire struct {
	OperationRunID string `json:"operationRunId"`
	ReceiptDigest  []byte `json:"receiptDigest"`
	NetworkDigest  []byte `json:"networkDigest"`
	AccountDigest  []byte `json:"accountDigest"`
	ProviderDigest []byte `json:"providerDigest"`
}

type platformSAMLPendingTransactionWire struct {
	TransactionID    []byte    `json:"transactionId"`
	MaterialID       string    `json:"materialId"`
	RequestID        string    `json:"requestId"`
	RelayStateDigest []byte    `json:"relayStateDigest"`
	BrowserDigest    []byte    `json:"browserDigest"`
	ReturnPath       string    `json:"returnPath"`
	State            string    `json:"state"`
	Version          uint64    `json:"version"`
	CreatedAt        time.Time `json:"createdAt"`
	ExpiresAt        time.Time `json:"expiresAt"`
}

type platformSAMLCreateTransactionWire struct {
	Begin                 platformSAMLBeginTransactionWire   `json:"begin"`
	Current               platformSAMLPendingTransactionWire `json:"current"`
	Pins                  platformSAMLDirectPinsWire         `json:"pins"`
	PreviousBrowserDigest []byte                             `json:"previousBrowserDigest,omitempty"`
	Audit                 platformSAMLAuditWire              `json:"audit"`
}

type platformSAMLTransactionProjectionWire struct {
	TransactionID    []byte                     `json:"transactionId"`
	OperationRunID   string                     `json:"operationRunId"`
	RequestID        string                     `json:"requestId"`
	RelayStateDigest []byte                     `json:"relayStateDigest"`
	BrowserDigest    []byte                     `json:"browserDigest"`
	Pins             platformSAMLDirectPinsWire `json:"pins"`
	ReturnPath       string                     `json:"returnPath"`
	State            string                     `json:"state"`
	Version          uint64                     `json:"version"`
	CreatedAt        time.Time                  `json:"createdAt"`
	ExpiresAt        time.Time                  `json:"expiresAt"`
}

type platformSAMLTransactionLookupWire struct {
	RelayStateDigest []byte    `json:"relayStateDigest"`
	BrowserDigest    []byte    `json:"browserDigest"`
	ObservedAt       time.Time `json:"observedAt"`
}

type platformSAMLAbortWire struct {
	TransactionID   []byte                     `json:"transactionId"`
	OperationRunID  string                     `json:"operationRunId"`
	ExpectedVersion uint64                     `json:"expectedVersion"`
	Pins            platformSAMLDirectPinsWire `json:"pins"`
	Reason          string                     `json:"reason"`
	FailedAt        time.Time                  `json:"failedAt"`
	Audit           platformSAMLAuditWire      `json:"audit"`
}

type platformSAMLAbortProjectionWire struct {
	Disposition    string                     `json:"disposition"`
	TransactionID  []byte                     `json:"transactionId"`
	OperationRunID string                     `json:"operationRunId"`
	Version        uint64                     `json:"version"`
	State          string                     `json:"state"`
	Pins           platformSAMLDirectPinsWire `json:"pins"`
}

var _ platformsamladapter.DirectSAMLTransactionPersistence = (*FederatedAuthRepository)(nil)

func (repository *FederatedAuthRepository) CreateDirectPlatformSAMLTransaction(
	ctx context.Context,
	request platformsamladapter.DirectSAMLCreateTransactionRequest,
) (platformsamladapter.DirectSAMLCreateReceipt, error) {
	wire, err := platformSAMLCreateTransactionToWire(request)
	if err != nil {
		return platformsamladapter.DirectSAMLCreateReceipt{}, errPlatformSAMLPersistence
	}
	defer clearPlatformSAMLCreateTransactionWire(&wire)
	var response platformSAMLTransactionProjectionWire
	defer clearPlatformSAMLTransactionProjectionWire(&response)
	if err = repository.queryJSONWithResponseLimit(
		ctx, createPlatformSAMLTransactionSQL, wire, &response, maximumPlatformSAMLTransactionWireBytes,
	); err != nil || ctx.Err() != nil {
		return platformsamladapter.DirectSAMLCreateReceipt{}, errPlatformSAMLPersistence
	}
	return platformSAMLCreateReceiptFromWire(response, request)
}

func (repository *FederatedAuthRepository) RecoverDirectPlatformSAMLCreate(
	ctx context.Context,
	lookup platformsamladapter.DirectSAMLCreateRecoveryLookup,
) (platformsamladapter.DirectSAMLCreateReceipt, error) {
	wire, err := platformSAMLCreateTransactionToWire(lookup.Create)
	if err != nil {
		return platformsamladapter.DirectSAMLCreateReceipt{}, errPlatformSAMLPersistence
	}
	defer clearPlatformSAMLCreateTransactionWire(&wire)
	var response platformSAMLTransactionProjectionWire
	defer clearPlatformSAMLTransactionProjectionWire(&response)
	if err = repository.queryJSONWithResponseLimit(
		ctx, recoverPlatformSAMLCreateSQL, wire, &response, maximumPlatformSAMLTransactionWireBytes,
	); err != nil || ctx.Err() != nil {
		return platformsamladapter.DirectSAMLCreateReceipt{}, errPlatformSAMLPersistence
	}
	return platformSAMLCreateReceiptFromWire(response, lookup.Create)
}

func (repository *FederatedAuthRepository) LookupDirectPlatformSAMLTransaction(
	ctx context.Context,
	lookup federatedsaml.LookupTransactionRequest,
) (platformsamladapter.DirectSAMLTransactionSnapshot, error) {
	if repository == nil || repository.queryer == nil || ctx == nil || ctx.Err() != nil ||
		lookup.RelayStateDigest == ([sha256.Size]byte{}) || lookup.BrowserDigest == ([sha256.Size]byte{}) ||
		lookup.RelayStateDigest == lookup.BrowserDigest || !validPlatformSAMLInstant(lookup.ObservedAt) {
		return platformsamladapter.DirectSAMLTransactionSnapshot{}, errPlatformSAMLPersistence
	}
	wire := platformSAMLTransactionLookupWire{
		RelayStateDigest: append([]byte(nil), lookup.RelayStateDigest[:]...),
		BrowserDigest:    append([]byte(nil), lookup.BrowserDigest[:]...), ObservedAt: lookup.ObservedAt,
	}
	defer clear(wire.RelayStateDigest)
	defer clear(wire.BrowserDigest)
	var response platformSAMLTransactionProjectionWire
	defer clearPlatformSAMLTransactionProjectionWire(&response)
	if err := repository.queryJSONWithResponseLimit(
		ctx, lookupPlatformSAMLTransactionSQL, wire, &response, maximumPlatformSAMLTransactionWireBytes,
	); err != nil || ctx.Err() != nil {
		return platformsamladapter.DirectSAMLTransactionSnapshot{}, errPlatformSAMLPersistence
	}
	pending, pins, err := platformSAMLPendingFromProjection(response)
	if err != nil || pending.RelayStateDigest != lookup.RelayStateDigest ||
		pending.BrowserDigest != lookup.BrowserDigest || lookup.ObservedAt.Before(pending.CreatedAt) ||
		!lookup.ObservedAt.Before(pending.ExpiresAt) {
		return platformsamladapter.DirectSAMLTransactionSnapshot{}, errPlatformSAMLPersistence
	}
	return platformsamladapter.DirectSAMLTransactionSnapshot{Pending: pending, Pins: pins}, nil
}

func (repository *FederatedAuthRepository) AbortDirectPlatformSAMLTransaction(
	ctx context.Context,
	request platformsamladapter.DirectSAMLAbortRequest,
) (platformsamladapter.DirectSAMLAbortReceipt, error) {
	pins, err := platformSAMLDirectPinsToWire(request.Pins)
	audit, auditErr := platformSAMLAuditToWire(request.Audit)
	if repository == nil || repository.queryer == nil || ctx == nil || ctx.Err() != nil || err != nil || auditErr != nil ||
		request.Transaction.TransactionID == (federatedsaml.TransactionID{}) ||
		request.Transaction.ExpectedVersion == 0 || request.OperationRunID == (identity.EntityID{}) ||
		request.Transaction.Pins != request.Pins.Protocol ||
		(request.Reason != platformsamladapter.AbortCallbackRejected &&
			request.Reason != platformsamladapter.AbortApplicationRejected) || !validPlatformSAMLInstant(request.FailedAt) {
		return platformsamladapter.DirectSAMLAbortReceipt{}, errPlatformSAMLPersistence
	}
	wire := platformSAMLAbortWire{
		TransactionID:  append([]byte(nil), request.Transaction.TransactionID[:]...),
		OperationRunID: entityIDWire(request.OperationRunID), ExpectedVersion: request.Transaction.ExpectedVersion,
		Pins: pins, Reason: string(request.Reason), FailedAt: request.FailedAt, Audit: audit,
	}
	defer clear(wire.TransactionID)
	defer clearPlatformSAMLProtocolPinsWire(&wire.Pins.Protocol)
	var response platformSAMLAbortProjectionWire
	defer clear(response.TransactionID)
	defer clearPlatformSAMLProtocolPinsWire(&response.Pins.Protocol)
	if err = repository.queryJSONWithResponseLimit(
		ctx, abortPlatformSAMLTransactionSQL, wire, &response, maximumPlatformSAMLTransactionWireBytes,
	); err != nil || ctx.Err() != nil {
		return platformsamladapter.DirectSAMLAbortReceipt{}, errPlatformSAMLPersistence
	}
	responsePins, pinsErr := platformSAMLDirectPinsFromWire(response.Pins)
	transactionID, transactionErr := platformSAMLTransactionIDFromWire(response.TransactionID)
	operationID, operationErr := parseEntityIDWire(response.OperationRunID, false)
	if pinsErr != nil || transactionErr != nil || operationErr != nil || responsePins != request.Pins ||
		transactionID != request.Transaction.TransactionID || operationID != request.OperationRunID ||
		response.Version != request.Transaction.ExpectedVersion+1 {
		return platformsamladapter.DirectSAMLAbortReceipt{}, errPlatformSAMLPersistence
	}
	receipt := platformsamladapter.DirectSAMLAbortReceipt{
		TransactionID: transactionID, OperationRunID: operationID, Version: response.Version,
		State: federatedsaml.TransactionState(response.State), Pins: responsePins,
	}
	switch response.Disposition {
	case string(platformsamladapter.AbortTerminalized):
		receipt.Disposition = platformsamladapter.AbortTerminalized
		if receipt.State != federatedsaml.TransactionFailed {
			return platformsamladapter.DirectSAMLAbortReceipt{}, errPlatformSAMLPersistence
		}
	case string(platformsamladapter.AbortAlreadyTerminal):
		receipt.Disposition = platformsamladapter.AbortAlreadyTerminal
		if receipt.State != federatedsaml.TransactionFailed && receipt.State != federatedsaml.TransactionExpired &&
			receipt.State != federatedsaml.TransactionCompleted {
			return platformsamladapter.DirectSAMLAbortReceipt{}, errPlatformSAMLPersistence
		}
	default:
		return platformsamladapter.DirectSAMLAbortReceipt{}, errPlatformSAMLPersistence
	}
	return receipt, nil
}

func platformSAMLCreateTransactionToWire(
	request platformsamladapter.DirectSAMLCreateTransactionRequest,
) (platformSAMLCreateTransactionWire, error) {
	protocol := request.Protocol
	current := protocol.Current
	pins, err := platformSAMLDirectPinsToWire(request.Grant.Pins)
	audit, auditErr := platformSAMLAuditToWire(request.Grant.Authority.Audit)
	if err != nil || auditErr != nil || protocol.Begin != request.Grant.Authority.Lookup.Begin ||
		current.Pins != request.Grant.Pins.Protocol || current.MaterialID != protocol.Begin.OperationRunID ||
		current.State != federatedsaml.TransactionPending || current.Version != 1 ||
		current.ID == (federatedsaml.TransactionID{}) || current.RelayStateDigest == ([sha256.Size]byte{}) ||
		current.BrowserDigest == ([sha256.Size]byte{}) || current.RelayStateDigest == current.BrowserDigest ||
		protocol.Begin.ReceiptDigest == (federatedsaml.StartReceiptDigest{}) ||
		protocol.Begin.NetworkDigest == (federatedsaml.NetworkThrottleDigest{}) ||
		protocol.Begin.AccountDigest == (federatedsaml.AccountThrottleDigest{}) ||
		protocol.Begin.ProviderDigest == (federatedsaml.ProviderThrottleDigest{}) ||
		!validPlatformSAMLInstant(current.CreatedAt) || !validPlatformSAMLInstant(current.ExpiresAt) ||
		current.ExpiresAt.Sub(current.CreatedAt) < time.Minute || current.ExpiresAt.Sub(current.CreatedAt) > 15*time.Minute ||
		current.ReturnPath != request.Grant.Authority.ReturnPath || current.RequestID == "" ||
		protocol.HasPreviousBrowserBinding != (protocol.PreviousBrowserDigest != ([sha256.Size]byte{})) ||
		(protocol.HasPreviousBrowserBinding && protocol.PreviousBrowserDigest == current.BrowserDigest) {
		return platformSAMLCreateTransactionWire{}, errPlatformSAMLPersistence
	}
	begin := platformSAMLBeginTransactionWire{
		OperationRunID: entityIDWire(protocol.Begin.OperationRunID),
		ReceiptDigest:  append([]byte(nil), protocol.Begin.ReceiptDigest[:]...),
		NetworkDigest:  append([]byte(nil), protocol.Begin.NetworkDigest[:]...),
		AccountDigest:  append([]byte(nil), protocol.Begin.AccountDigest[:]...),
		ProviderDigest: append([]byte(nil), protocol.Begin.ProviderDigest[:]...),
	}
	wire := platformSAMLCreateTransactionWire{
		Begin: begin, Pins: pins, Audit: audit,
		Current: platformSAMLPendingTransactionWire{
			TransactionID: append([]byte(nil), current.ID[:]...), MaterialID: entityIDWire(current.MaterialID),
			RequestID: current.RequestID, RelayStateDigest: append([]byte(nil), current.RelayStateDigest[:]...),
			BrowserDigest: append([]byte(nil), current.BrowserDigest[:]...), ReturnPath: current.ReturnPath,
			State: string(current.State), Version: current.Version, CreatedAt: current.CreatedAt, ExpiresAt: current.ExpiresAt,
		},
	}
	if protocol.HasPreviousBrowserBinding {
		wire.PreviousBrowserDigest = append([]byte(nil), protocol.PreviousBrowserDigest[:]...)
	}
	return wire, nil
}

func platformSAMLCreateReceiptFromWire(
	wire platformSAMLTransactionProjectionWire,
	request platformsamladapter.DirectSAMLCreateTransactionRequest,
) (platformsamladapter.DirectSAMLCreateReceipt, error) {
	pending, pins, err := platformSAMLPendingFromProjection(wire)
	if err != nil || pending.ID != request.Protocol.Current.ID ||
		pending.MaterialID != request.Protocol.Begin.OperationRunID || pending.State != federatedsaml.TransactionPending ||
		pending.Version != 1 || pins != request.Grant.Pins || pending != request.Protocol.Current {
		return platformsamladapter.DirectSAMLCreateReceipt{}, errPlatformSAMLPersistence
	}
	return platformsamladapter.DirectSAMLCreateReceipt{
		TransactionID: pending.ID, OperationRunID: pending.MaterialID,
		Version: pending.Version, State: pending.State, Pins: pins,
	}, nil
}

func platformSAMLPendingFromProjection(
	wire platformSAMLTransactionProjectionWire,
) (federatedsaml.PendingTransaction, platformsamlauth.DirectSAMLPins, error) {
	id, idErr := platformSAMLTransactionIDFromWire(wire.TransactionID)
	materialID, materialErr := parseEntityIDWire(wire.OperationRunID, false)
	pins, pinsErr := platformSAMLDirectPinsFromWire(wire.Pins)
	createdAt := platformSAMLUTC(wire.CreatedAt)
	expiresAt := platformSAMLUTC(wire.ExpiresAt)
	if idErr != nil || materialErr != nil || pinsErr != nil || len(wire.RelayStateDigest) != sha256.Size ||
		len(wire.BrowserDigest) != sha256.Size || slices.Equal(wire.RelayStateDigest, wire.BrowserDigest) ||
		!validPlatformSAMLInstant(createdAt) || !validPlatformSAMLInstant(expiresAt) || !expiresAt.After(createdAt) ||
		wire.RequestID == "" || wire.ReturnPath == "" || wire.Version == 0 {
		return federatedsaml.PendingTransaction{}, platformsamlauth.DirectSAMLPins{}, errPlatformSAMLPersistence
	}
	var relayStateDigest, browserDigest [sha256.Size]byte
	copy(relayStateDigest[:], wire.RelayStateDigest)
	copy(browserDigest[:], wire.BrowserDigest)
	pending := federatedsaml.PendingTransaction{
		ID: id, MaterialID: materialID, RequestID: wire.RequestID,
		RelayStateDigest: relayStateDigest, BrowserDigest: browserDigest, Pins: pins.Protocol,
		CreatedAt: createdAt, ExpiresAt: expiresAt, ReturnPath: wire.ReturnPath,
		State: federatedsaml.TransactionState(wire.State), Version: wire.Version,
	}
	if pending.State != federatedsaml.TransactionPending && pending.State != federatedsaml.TransactionCompleted &&
		pending.State != federatedsaml.TransactionFailed && pending.State != federatedsaml.TransactionExpired {
		return federatedsaml.PendingTransaction{}, platformsamlauth.DirectSAMLPins{}, errPlatformSAMLPersistence
	}
	return pending, pins, nil
}

func platformSAMLTransactionIDFromWire(value []byte) (federatedsaml.TransactionID, error) {
	if len(value) != len(federatedsaml.TransactionID{}) || slices.Equal(value, make([]byte, len(value))) {
		return federatedsaml.TransactionID{}, errPlatformSAMLPersistence
	}
	var result federatedsaml.TransactionID
	copy(result[:], value)
	return result, nil
}

func clearPlatformSAMLCreateTransactionWire(value *platformSAMLCreateTransactionWire) {
	if value == nil {
		return
	}
	clear(value.Begin.ReceiptDigest)
	clear(value.Begin.NetworkDigest)
	clear(value.Begin.AccountDigest)
	clear(value.Begin.ProviderDigest)
	clear(value.Current.TransactionID)
	clear(value.Current.RelayStateDigest)
	clear(value.Current.BrowserDigest)
	clearPlatformSAMLProtocolPinsWire(&value.Pins.Protocol)
	clear(value.PreviousBrowserDigest)
	*value = platformSAMLCreateTransactionWire{}
}

func clearPlatformSAMLTransactionProjectionWire(value *platformSAMLTransactionProjectionWire) {
	if value == nil {
		return
	}
	clear(value.TransactionID)
	clear(value.RelayStateDigest)
	clear(value.BrowserDigest)
	clearPlatformSAMLProtocolPinsWire(&value.Pins.Protocol)
	*value = platformSAMLTransactionProjectionWire{}
}
