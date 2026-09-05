package federatedsaml

import (
	"context"
	"crypto/sha256"
	"errors"
	"strconv"
	"time"
)

// ResolvedCallbackRequest contains only the two independent browser artifacts
// and the bounded POST body. Authority/provider and any applicable tenant
// context are derived from the pending transaction, never from an ACS path or
// caller-selected identifier.
type ResolvedCallbackRequest struct {
	MediaType     string
	RawForm       []byte `json:"-"`
	BrowserHandle []byte `json:"-"`
}

type CallbackConfigurationLookup struct {
	TransactionID   TransactionID
	ExpectedVersion uint64
	Pins            TransactionPins
}

// CallbackConfigurationResolver loads the immutable configuration selected by
// Lookup.Pins. Implementations must establish the exact authority/provider and
// any applicable tenant/RLS context from those pins; they must not synthesize a
// tenant for direct-platform login or accept browser-selected authority data.
type CallbackConfigurationResolver interface {
	ResolveSAMLCallbackConfiguration(context.Context, CallbackConfigurationLookup) (Configuration, error)
}

// ValidateCallbackResolved is the public ACS entry point. It resolves the
// configuration only after a live transaction matches both RelayState and the
// SameSite=None browser handle, then delegates all XML and cryptographic policy
// to ValidateCallback.
func (kernel *Kernel) ValidateCallbackResolved(
	ctx context.Context,
	request ResolvedCallbackRequest,
	resolver CallbackConfigurationResolver,
) (*ValidatedAuthentication, error) {
	if kernel == nil || kernel.transactions == nil || resolver == nil || !validBrowserHandle(request.BrowserHandle) {
		return nil, ErrCallbackRejected
	}
	now, err := canonicalNow(kernel.now)
	if err != nil {
		return nil, ErrCallbackRejected
	}
	responseDocument, relayState, err := parsePOSTForm(request.MediaType, request.RawForm, kernel.limits)
	if err != nil {
		return nil, ErrCallbackRejected
	}
	defer clear(responseDocument)
	bounded, cancel, err := operationContext(ctx, kernel.operationTimeout)
	if err != nil {
		return nil, errors.Join(ErrCallbackRejected, err)
	}
	defer cancel()
	relayDigest := digestOpaque([]byte(relayState))
	browserDigest := digestOpaque(request.BrowserHandle)
	pending, err := kernel.transactions.Lookup(bounded, LookupTransactionRequest{
		RelayStateDigest: relayDigest,
		BrowserDigest:    browserDigest,
		ObservedAt:       now,
	})
	if err != nil || !validPendingTransactionLookup(pending, now, relayDigest, browserDigest) ||
		pending.Pins.Authority != kernel.authority {
		return nil, ErrCallbackRejected
	}
	configuration, err := resolver.ResolveSAMLCallbackConfiguration(bounded, CallbackConfigurationLookup{
		TransactionID: pending.ID, ExpectedVersion: pending.Version, Pins: pending.Pins,
	})
	if err != nil || configuration.Authority != kernel.authority {
		return nil, ErrCallbackRejected
	}
	callback := CallbackRequest{
		Configuration: configuration,
		MediaType:     request.MediaType,
		RawForm:       append([]byte(nil), request.RawForm...),
		BrowserHandle: append([]byte(nil), request.BrowserHandle...),
	}
	validated, validationErr := kernel.ValidateCallback(bounded, callback)
	clear(callback.RawForm)
	clear(callback.BrowserHandle)
	return validated, validationErr
}

func validPendingTransactionLookup(
	pending PendingTransaction,
	observedAt time.Time,
	relayDigest [sha256.Size]byte,
	browserDigest [sha256.Size]byte,
) bool {
	return !allZero(pending.ID[:]) && validUUIDv7(pending.MaterialID) &&
		validXMLID(pending.RequestID) && pending.State == TransactionPending &&
		validPersistentSuccessorRevision(pending.Version) && validInstant(pending.CreatedAt) && validInstant(pending.ExpiresAt) &&
		pending.ExpiresAt.Sub(pending.CreatedAt) >= time.Minute &&
		pending.ExpiresAt.Sub(pending.CreatedAt) <= 15*time.Minute && observedAt.Before(pending.ExpiresAt) &&
		!pending.CreatedAt.After(observedAt) && validReturnPath(pending.ReturnPath) &&
		compareDigest(pending.RelayStateDigest, relayDigest) && compareDigest(pending.BrowserDigest, browserDigest) &&
		validTransactionPins(pending.Pins)
}

func validTransactionPins(pins TransactionPins) bool {
	return validCeremonyAuthority(
		pins.Authority, pins.Provider, pins.BindingID, pins.BindingRevision, pins.MappingRevision,
		pins.AuthorizationRevision, pins.PlatformLoginRevision, pins.PlanRevision,
	) && validPersistentRevision(pins.ProviderRevision) &&
		validPersistentRevision(pins.ConfigurationRevision) && validPersistentRevision(pins.SecurityRevision) &&
		validPersistentRevision(pins.AssurancePolicyRevision) && validPersistentRevision(pins.MetadataRevision) &&
		pins.MetadataDigest != ([sha256.Size]byte{}) && validPersistentRevision(pins.SPKeyRevision) &&
		pins.ConfigurationDigest != ([sha256.Size]byte{})
}

func (request ResolvedCallbackRequest) String() string {
	return "federatedsaml.ResolvedCallbackRequest{" +
		"media_type_present=" + strconv.FormatBool(request.MediaType != "") +
		",form_bytes=" + strconv.Itoa(len(request.RawForm)) +
		",browser_handle_present=" + strconv.FormatBool(len(request.BrowserHandle) != 0) +
		"}"
}
func (request ResolvedCallbackRequest) GoString() string { return request.String() }

func (lookup CallbackConfigurationLookup) String() string {
	return "federatedsaml.CallbackConfigurationLookup{" +
		"transaction=" + strconv.Quote(lookup.TransactionID.String()) +
		",version=" + strconv.FormatBool(lookup.ExpectedVersion > 0) +
		",pins_valid=" + strconv.FormatBool(validTransactionPins(lookup.Pins)) +
		"}"
}
func (lookup CallbackConfigurationLookup) GoString() string { return lookup.String() }
