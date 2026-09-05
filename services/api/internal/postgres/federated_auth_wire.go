package postgres

import (
	"crypto/sha256"
	"time"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
)

type federatedProviderBindingWire struct {
	Scope      string `json:"scope"`
	TenantID   string `json:"tenantId,omitempty"`
	ProviderID string `json:"providerId"`
	BindingID  string `json:"bindingId,omitempty"`
}

// federatedTenantAdmissionWire is emitted only when a platform-scoped
// provider is admitted through one explicit tenant binding. Tenant-provider
// wires keep their sealed legacy provider object byte-for-byte unchanged.
type federatedTenantAdmissionWire struct {
	TenantID  string `json:"tenantId"`
	BindingID string `json:"bindingId"`
}

const (
	federatedTenantProviderScopeWire   = "tenant"
	federatedPlatformProviderScopeWire = "platform"
)

type federatedBeginWire struct {
	OperationRunID string `json:"operationRunId"`
	ReceiptDigest  []byte `json:"receiptDigest"`
	NetworkDigest  []byte `json:"networkDigest"`
	AccountDigest  []byte `json:"accountDigest"`
	ProviderDigest []byte `json:"providerDigest"`
}

type oidcTransactionPinsWire struct {
	Provider                federatedProviderBindingWire  `json:"provider"`
	Admission               *federatedTenantAdmissionWire `json:"admission,omitempty"`
	ProviderRevision        uint64                        `json:"providerRevision"`
	BindingRevision         uint64                        `json:"bindingRevision"`
	ConfigurationRevision   uint64                        `json:"configurationRevision"`
	SecurityRevision        uint64                        `json:"securityRevision"`
	MappingRevision         uint64                        `json:"mappingRevision"`
	AuthorizationRevision   uint64                        `json:"authorizationRevision"`
	AssurancePolicyRevision uint64                        `json:"assurancePolicyRevision"`
	ClientSecretRevision    uint64                        `json:"clientSecretRevision"`
	DiscoveryRevision       uint64                        `json:"discoveryRevision"`
	DiscoveryDigest         []byte                        `json:"discoveryDigest"`
	JWKSRevision            uint64                        `json:"jwksRevision"`
	JWKSDigest              []byte                        `json:"jwksDigest"`
}

type oidcPendingTransactionWire struct {
	ID                    []byte                  `json:"id"`
	MaterialID            string                  `json:"materialId,omitempty"`
	StateDigest           []byte                  `json:"stateDigest"`
	BrowserDigest         []byte                  `json:"browserDigest"`
	NonceDigest           []byte                  `json:"nonceDigest"`
	VerifierKeyVersion    uint32                  `json:"verifierKeyVersion"`
	VerifierCiphertext    []byte                  `json:"verifierCiphertext"`
	Pins                  oidcTransactionPinsWire `json:"pins"`
	ClientID              string                  `json:"clientId"`
	RedirectURI           string                  `json:"redirectUri"`
	PostLogoutRedirectURI string                  `json:"postLogoutRedirectUri"`
	ReturnPath            string                  `json:"returnPath"`
	Scopes                []string                `json:"scopes"`
	AllowRefreshToken     bool                    `json:"allowRefreshToken"`
	UseUserInfo           bool                    `json:"useUserInfo"`
	CreatedAt             time.Time               `json:"createdAt"`
	ExpiresAt             time.Time               `json:"expiresAt"`
	State                 string                  `json:"state"`
	Version               uint64                  `json:"version"`
}

type oidcCreateTransactionWire struct {
	Begin                 federatedBeginWire         `json:"begin"`
	Current               oidcPendingTransactionWire `json:"current"`
	PreviousBrowserDigest []byte                     `json:"previousBrowserDigest,omitempty"`
}

type oidcTransactionClaimWire struct {
	AttemptID     []byte    `json:"attemptId"`
	StateDigest   []byte    `json:"stateDigest"`
	BrowserDigest []byte    `json:"browserDigest"`
	ClaimedAt     time.Time `json:"claimedAt"`
}

type oidcClaimedTransactionWire struct {
	oidcPendingTransactionWire
	ClaimAttemptID []byte    `json:"claimAttemptId"`
	ClaimedAt      time.Time `json:"claimedAt"`
}

type oidcTransactionFailureWire struct {
	ID              []byte    `json:"id"`
	ExpectedVersion uint64    `json:"expectedVersion"`
	FailedAt        time.Time `json:"failedAt"`
	Reason          string    `json:"reason"`
	State           string    `json:"state"`
}

type samlTransactionPinsWire struct {
	Provider                federatedProviderBindingWire `json:"provider"`
	ProviderRevision        uint64                       `json:"providerRevision"`
	BindingRevision         uint64                       `json:"bindingRevision"`
	ConfigurationRevision   uint64                       `json:"configurationRevision"`
	SecurityRevision        uint64                       `json:"securityRevision"`
	MappingRevision         uint64                       `json:"mappingRevision"`
	AuthorizationRevision   uint64                       `json:"authorizationRevision"`
	AssurancePolicyRevision uint64                       `json:"assurancePolicyRevision"`
	MetadataRevision        uint64                       `json:"metadataRevision"`
	MetadataDigest          []byte                       `json:"metadataDigest"`
	SPKeyRevision           uint64                       `json:"spKeyRevision"`
	ConfigurationDigest     []byte                       `json:"configurationDigest"`
}

type samlPendingTransactionWire struct {
	ID               []byte                  `json:"id"`
	MaterialID       string                  `json:"materialId,omitempty"`
	RequestID        string                  `json:"requestId"`
	RelayStateDigest []byte                  `json:"relayStateDigest"`
	BrowserDigest    []byte                  `json:"browserDigest"`
	Pins             samlTransactionPinsWire `json:"pins"`
	CreatedAt        time.Time               `json:"createdAt"`
	ExpiresAt        time.Time               `json:"expiresAt"`
	ReturnPath       string                  `json:"returnPath"`
	State            string                  `json:"state"`
	Version          uint64                  `json:"version"`
}

type samlCreateTransactionWire struct {
	Begin                 federatedBeginWire         `json:"begin"`
	Current               samlPendingTransactionWire `json:"current"`
	PreviousBrowserDigest []byte                     `json:"previousBrowserDigest,omitempty"`
}

type samlTransactionLookupWire struct {
	RelayStateDigest []byte    `json:"relayStateDigest"`
	BrowserDigest    []byte    `json:"browserDigest"`
	ObservedAt       time.Time `json:"observedAt"`
}

type federatedTransactionReceiptWire struct {
	TransactionID []byte `json:"transactionId"`
	Version       uint64 `json:"version"`
	State         string `json:"state"`
	Replayed      bool   `json:"replayed"`
}

func oidcCreateTransactionToWire(request federatedoidc.CreateTransactionRequest) (oidcCreateTransactionWire, error) {
	begin, err := federatedBeginToWire(
		request.Begin.OperationRunID, request.Begin.ReceiptDigest[:], request.Begin.NetworkDigest[:],
		request.Begin.AccountDigest[:], request.Begin.ProviderDigest[:],
	)
	if err != nil {
		return oidcCreateTransactionWire{}, err
	}
	current, err := oidcPendingTransactionToWire(request.Current)
	if err != nil || current.MaterialID != begin.OperationRunID {
		return oidcCreateTransactionWire{}, errFederatedAuthPersistence
	}
	// OperationRunID is the canonical immutable material identity persisted by
	// the transaction row. The create snapshot must not duplicate it.
	current.MaterialID = ""
	previous, err := optionalDigestToWire(request.PreviousBrowserDigest[:], request.HasPreviousBrowserBinding)
	if err != nil {
		return oidcCreateTransactionWire{}, err
	}
	return oidcCreateTransactionWire{Begin: begin, Current: current, PreviousBrowserDigest: previous}, nil
}

func oidcClaimToWire(claim federatedoidc.TransactionClaim) (oidcTransactionClaimWire, error) {
	if !validOpaque32(claim.AttemptID[:]) || !validDigestWire(claim.StateDigest[:]) ||
		!validDigestWire(claim.BrowserDigest[:]) || claim.StateDigest == claim.BrowserDigest ||
		!validFederatedDatabaseTime(claim.ClaimedAt) {
		return oidcTransactionClaimWire{}, errFederatedAuthPersistence
	}
	return oidcTransactionClaimWire{
		AttemptID: append([]byte(nil), claim.AttemptID[:]...), StateDigest: append([]byte(nil), claim.StateDigest[:]...),
		BrowserDigest: append([]byte(nil), claim.BrowserDigest[:]...), ClaimedAt: claim.ClaimedAt,
	}, nil
}

func oidcFailureToWire(failure federatedoidc.TransactionFailure) (oidcTransactionFailureWire, error) {
	if !validOpaque32(failure.ID[:]) || !validFederatedSuccessorRevision(failure.ExpectedVersion) ||
		!validFederatedDatabaseTime(failure.FailedAt) || !validOIDCFailureWire(string(failure.Reason), string(failure.State)) {
		return oidcTransactionFailureWire{}, errFederatedAuthPersistence
	}
	return oidcTransactionFailureWire{
		ID: append([]byte(nil), failure.ID[:]...), ExpectedVersion: failure.ExpectedVersion,
		FailedAt: failure.FailedAt, Reason: string(failure.Reason), State: string(failure.State),
	}, nil
}

func oidcPendingTransactionToWire(value federatedoidc.PendingTransaction) (oidcPendingTransactionWire, error) {
	pins, err := oidcPinsToWire(value.Pins)
	if err != nil || !validOpaque32(value.ID[:]) || entityIDWire(value.MaterialID) == "" ||
		!validDigestWire(value.StateDigest[:]) ||
		!validDigestWire(value.BrowserDigest[:]) || !validDigestWire(value.NonceDigest[:]) ||
		value.StateDigest == value.BrowserDigest || value.StateDigest == value.NonceDigest ||
		value.BrowserDigest == value.NonceDigest || value.Verifier.KeyVersion == 0 ||
		len(value.Verifier.Ciphertext) < 16 || len(value.Verifier.Ciphertext) > 4*1024 ||
		!validFederatedDatabaseTime(value.CreatedAt) || !validFederatedDatabaseTime(value.ExpiresAt) ||
		!value.ExpiresAt.After(value.CreatedAt) || !validOIDCTransactionState(string(value.State)) ||
		!validFederatedSuccessorRevision(value.Version) {
		return oidcPendingTransactionWire{}, errFederatedAuthPersistence
	}
	return oidcPendingTransactionWire{
		ID: append([]byte(nil), value.ID[:]...), MaterialID: entityIDWire(value.MaterialID),
		StateDigest:   append([]byte(nil), value.StateDigest[:]...),
		BrowserDigest: append([]byte(nil), value.BrowserDigest[:]...), NonceDigest: append([]byte(nil), value.NonceDigest[:]...),
		VerifierKeyVersion: value.Verifier.KeyVersion,
		VerifierCiphertext: append([]byte(nil), value.Verifier.Ciphertext...), Pins: pins,
		ClientID: value.ClientID, RedirectURI: value.RedirectURI, PostLogoutRedirectURI: value.PostLogoutRedirectURI,
		ReturnPath: value.ReturnPath, Scopes: append([]string(nil), value.Scopes...),
		AllowRefreshToken: value.AllowRefreshToken, UseUserInfo: value.UseUserInfo,
		CreatedAt: value.CreatedAt, ExpiresAt: value.ExpiresAt, State: string(value.State), Version: value.Version,
	}, nil
}

func oidcClaimedTransactionFromWire(wire oidcClaimedTransactionWire) (federatedoidc.ClaimedTransaction, error) {
	pending, err := oidcPendingTransactionFromWire(wire.oidcPendingTransactionWire)
	claimedAt, validClaimedAt := canonicalFederatedDatabaseTimeFromWire(wire.ClaimedAt)
	if err != nil || !validOpaque32(wire.ClaimAttemptID) || !validClaimedAt {
		return federatedoidc.ClaimedTransaction{}, errFederatedAuthPersistence
	}
	var attempt federatedoidc.TransactionID
	copy(attempt[:], wire.ClaimAttemptID)
	return federatedoidc.ClaimedTransaction{
		PendingTransaction: pending, ClaimAttemptID: attempt, ClaimedAt: claimedAt,
	}, nil
}

func oidcPendingTransactionFromWire(wire oidcPendingTransactionWire) (federatedoidc.PendingTransaction, error) {
	pins, err := oidcPinsFromWire(wire.Pins)
	createdAt, validCreatedAt := canonicalFederatedDatabaseTimeFromWire(wire.CreatedAt)
	expiresAt, validExpiresAt := canonicalFederatedDatabaseTimeFromWire(wire.ExpiresAt)
	materialID, materialErr := parseEntityIDWire(wire.MaterialID, false)
	if err != nil || materialErr != nil || !validOpaque32(wire.ID) || !validDigestWire(wire.StateDigest) ||
		!validDigestWire(wire.BrowserDigest) || !validDigestWire(wire.NonceDigest) ||
		wire.VerifierKeyVersion == 0 || len(wire.VerifierCiphertext) < 16 || len(wire.VerifierCiphertext) > 4*1024 ||
		!validCreatedAt || !validExpiresAt || !expiresAt.After(createdAt) || !validOIDCTransactionState(wire.State) ||
		!validFederatedSuccessorRevision(wire.Version) {
		return federatedoidc.PendingTransaction{}, errFederatedAuthPersistence
	}
	var id federatedoidc.TransactionID
	var stateDigest, browserDigest, nonceDigest [sha256.Size]byte
	copy(id[:], wire.ID)
	copy(stateDigest[:], wire.StateDigest)
	copy(browserDigest[:], wire.BrowserDigest)
	copy(nonceDigest[:], wire.NonceDigest)
	if stateDigest == browserDigest || stateDigest == nonceDigest || browserDigest == nonceDigest {
		return federatedoidc.PendingTransaction{}, errFederatedAuthPersistence
	}
	return federatedoidc.PendingTransaction{
		ID: id, MaterialID: materialID, StateDigest: stateDigest, BrowserDigest: browserDigest, NonceDigest: nonceDigest,
		Verifier: federatedoidc.ProtectedVerifier{
			KeyVersion: wire.VerifierKeyVersion, Ciphertext: append([]byte(nil), wire.VerifierCiphertext...),
		},
		Pins: pins, ClientID: wire.ClientID, RedirectURI: wire.RedirectURI,
		PostLogoutRedirectURI: wire.PostLogoutRedirectURI, ReturnPath: wire.ReturnPath,
		Scopes: append([]string(nil), wire.Scopes...), AllowRefreshToken: wire.AllowRefreshToken,
		UseUserInfo: wire.UseUserInfo, CreatedAt: createdAt, ExpiresAt: expiresAt,
		State: federatedoidc.TransactionState(wire.State), Version: wire.Version,
	}, nil
}

func oidcPinsToWire(value federatedoidc.TransactionPins) (oidcTransactionPinsWire, error) {
	provider, admission, err := oidcProviderAdmissionToWire(value.Provider, value.BindingID, value.Admission)
	if err != nil || !validOIDCPinRevisions(value) || !validDigestWire(value.DiscoveryDigest[:]) ||
		!validDigestWire(value.JWKSDigest[:]) {
		return oidcTransactionPinsWire{}, errFederatedAuthPersistence
	}
	return oidcTransactionPinsWire{
		Provider: provider, Admission: admission,
		ProviderRevision: value.ProviderRevision, BindingRevision: value.BindingRevision,
		ConfigurationRevision: value.ConfigurationRevision, SecurityRevision: value.SecurityRevision,
		MappingRevision: value.MappingRevision, AuthorizationRevision: value.AuthorizationRevision,
		AssurancePolicyRevision: value.AssurancePolicyRevision, ClientSecretRevision: value.ClientSecretRevision,
		DiscoveryRevision: value.DiscoveryRevision, DiscoveryDigest: append([]byte(nil), value.DiscoveryDigest[:]...),
		JWKSRevision: value.JWKSRevision, JWKSDigest: append([]byte(nil), value.JWKSDigest[:]...),
	}, nil
}

func oidcPinsFromWire(wire oidcTransactionPinsWire) (federatedoidc.TransactionPins, error) {
	provider, admission, binding, err := oidcProviderAdmissionFromWire(wire.Provider, wire.Admission)
	value := federatedoidc.TransactionPins{
		Provider: provider, Admission: admission, BindingID: binding, ProviderRevision: wire.ProviderRevision,
		BindingRevision: wire.BindingRevision, ConfigurationRevision: wire.ConfigurationRevision,
		SecurityRevision: wire.SecurityRevision, MappingRevision: wire.MappingRevision,
		AuthorizationRevision: wire.AuthorizationRevision, AssurancePolicyRevision: wire.AssurancePolicyRevision,
		ClientSecretRevision: wire.ClientSecretRevision, DiscoveryRevision: wire.DiscoveryRevision,
		JWKSRevision: wire.JWKSRevision,
	}
	if err != nil || !validDigestWire(wire.DiscoveryDigest) || !validDigestWire(wire.JWKSDigest) ||
		!validOIDCPinRevisions(value) {
		return federatedoidc.TransactionPins{}, errFederatedAuthPersistence
	}
	copy(value.DiscoveryDigest[:], wire.DiscoveryDigest)
	copy(value.JWKSDigest[:], wire.JWKSDigest)
	return value, nil
}

func samlCreateTransactionToWire(request federatedsaml.CreateTransactionRequest) (samlCreateTransactionWire, error) {
	begin, err := federatedBeginToWire(
		request.Begin.OperationRunID, request.Begin.ReceiptDigest[:], request.Begin.NetworkDigest[:],
		request.Begin.AccountDigest[:], request.Begin.ProviderDigest[:],
	)
	if err != nil {
		return samlCreateTransactionWire{}, err
	}
	current, err := samlPendingTransactionToWire(request.Current)
	if err != nil || current.MaterialID != begin.OperationRunID {
		return samlCreateTransactionWire{}, errFederatedAuthPersistence
	}
	// The transaction row already persists Begin.OperationRunID. Do not
	// duplicate it inside the create snapshot; the lookup ABI derives and
	// returns the immutable material identity from that canonical column.
	current.MaterialID = ""
	previous, err := optionalDigestToWire(request.PreviousBrowserDigest[:], request.HasPreviousBrowserBinding)
	if err != nil {
		return samlCreateTransactionWire{}, err
	}
	return samlCreateTransactionWire{Begin: begin, Current: current, PreviousBrowserDigest: previous}, nil
}

func samlLookupToWire(request federatedsaml.LookupTransactionRequest) (samlTransactionLookupWire, error) {
	if !validDigestWire(request.RelayStateDigest[:]) || !validDigestWire(request.BrowserDigest[:]) ||
		request.RelayStateDigest == request.BrowserDigest || !validFederatedDatabaseTime(request.ObservedAt) {
		return samlTransactionLookupWire{}, errFederatedAuthPersistence
	}
	return samlTransactionLookupWire{
		RelayStateDigest: append([]byte(nil), request.RelayStateDigest[:]...),
		BrowserDigest:    append([]byte(nil), request.BrowserDigest[:]...), ObservedAt: request.ObservedAt,
	}, nil
}

func samlPendingTransactionToWire(value federatedsaml.PendingTransaction) (samlPendingTransactionWire, error) {
	pins, err := samlPinsToWire(value.Pins)
	if err != nil || !validOpaque32(value.ID[:]) || entityIDWire(value.MaterialID) == "" ||
		!validDigestWire(value.RelayStateDigest[:]) ||
		!validDigestWire(value.BrowserDigest[:]) || value.RelayStateDigest == value.BrowserDigest ||
		!validFederatedDatabaseTime(value.CreatedAt) || !validFederatedDatabaseTime(value.ExpiresAt) ||
		!value.ExpiresAt.After(value.CreatedAt) || !validSAMLTransactionState(string(value.State)) ||
		!validFederatedSuccessorRevision(value.Version) {
		return samlPendingTransactionWire{}, errFederatedAuthPersistence
	}
	return samlPendingTransactionWire{
		ID: append([]byte(nil), value.ID[:]...), MaterialID: entityIDWire(value.MaterialID), RequestID: value.RequestID,
		RelayStateDigest: append([]byte(nil), value.RelayStateDigest[:]...),
		BrowserDigest:    append([]byte(nil), value.BrowserDigest[:]...), Pins: pins,
		CreatedAt: value.CreatedAt, ExpiresAt: value.ExpiresAt, ReturnPath: value.ReturnPath,
		State: string(value.State), Version: value.Version,
	}, nil
}

func samlPendingTransactionFromWire(wire samlPendingTransactionWire) (federatedsaml.PendingTransaction, error) {
	pins, err := samlPinsFromWire(wire.Pins)
	createdAt, validCreatedAt := canonicalFederatedDatabaseTimeFromWire(wire.CreatedAt)
	expiresAt, validExpiresAt := canonicalFederatedDatabaseTimeFromWire(wire.ExpiresAt)
	materialID, materialErr := parseEntityIDWire(wire.MaterialID, false)
	if err != nil || materialErr != nil || !validOpaque32(wire.ID) || !validDigestWire(wire.RelayStateDigest) ||
		!validDigestWire(wire.BrowserDigest) || !validCreatedAt || !validExpiresAt || !expiresAt.After(createdAt) ||
		!validSAMLTransactionState(wire.State) || !validFederatedSuccessorRevision(wire.Version) {
		return federatedsaml.PendingTransaction{}, errFederatedAuthPersistence
	}
	var id federatedsaml.TransactionID
	var relay, browser [sha256.Size]byte
	copy(id[:], wire.ID)
	copy(relay[:], wire.RelayStateDigest)
	copy(browser[:], wire.BrowserDigest)
	if relay == browser {
		return federatedsaml.PendingTransaction{}, errFederatedAuthPersistence
	}
	return federatedsaml.PendingTransaction{
		ID: id, MaterialID: materialID, RequestID: wire.RequestID, RelayStateDigest: relay, BrowserDigest: browser,
		Pins: pins, CreatedAt: createdAt, ExpiresAt: expiresAt, ReturnPath: wire.ReturnPath,
		State: federatedsaml.TransactionState(wire.State), Version: wire.Version,
	}, nil
}

func samlPinsToWire(value federatedsaml.TransactionPins) (samlTransactionPinsWire, error) {
	provider, err := providerBindingToWire(value.Provider, value.BindingID, false)
	if err != nil || !validSAMLPinRevisions(value) || !validDigestWire(value.MetadataDigest[:]) ||
		!validDigestWire(value.ConfigurationDigest[:]) {
		return samlTransactionPinsWire{}, errFederatedAuthPersistence
	}
	return samlTransactionPinsWire{
		Provider: provider, ProviderRevision: value.ProviderRevision, BindingRevision: value.BindingRevision,
		ConfigurationRevision: value.ConfigurationRevision, SecurityRevision: value.SecurityRevision,
		MappingRevision: value.MappingRevision, AuthorizationRevision: value.AuthorizationRevision,
		AssurancePolicyRevision: value.AssurancePolicyRevision, MetadataRevision: value.MetadataRevision,
		MetadataDigest: append([]byte(nil), value.MetadataDigest[:]...), SPKeyRevision: value.SPKeyRevision,
		ConfigurationDigest: append([]byte(nil), value.ConfigurationDigest[:]...),
	}, nil
}

func samlPinsFromWire(wire samlTransactionPinsWire) (federatedsaml.TransactionPins, error) {
	provider, binding, err := providerBindingFromWire(wire.Provider, false)
	value := federatedsaml.TransactionPins{
		Provider: provider, BindingID: binding, ProviderRevision: wire.ProviderRevision,
		BindingRevision: wire.BindingRevision, ConfigurationRevision: wire.ConfigurationRevision,
		SecurityRevision: wire.SecurityRevision, MappingRevision: wire.MappingRevision,
		AuthorizationRevision: wire.AuthorizationRevision, AssurancePolicyRevision: wire.AssurancePolicyRevision,
		MetadataRevision: wire.MetadataRevision, SPKeyRevision: wire.SPKeyRevision,
	}
	if err != nil || !validSAMLPinRevisions(value) || !validDigestWire(wire.MetadataDigest) ||
		!validDigestWire(wire.ConfigurationDigest) {
		return federatedsaml.TransactionPins{}, errFederatedAuthPersistence
	}
	copy(value.MetadataDigest[:], wire.MetadataDigest)
	copy(value.ConfigurationDigest[:], wire.ConfigurationDigest)
	return value, nil
}

func oidcTransactionReceiptFromWire(wire federatedTransactionReceiptWire) (federatedauth.OIDCTransactionWriteReceipt, error) {
	if !validOpaque32(wire.TransactionID) || !validFederatedRevision(wire.Version) ||
		!validOIDCTransactionState(wire.State) {
		return federatedauth.OIDCTransactionWriteReceipt{}, errFederatedAuthPersistence
	}
	var id federatedoidc.TransactionID
	copy(id[:], wire.TransactionID)
	return federatedauth.OIDCTransactionWriteReceipt{
		TransactionID: id, Version: wire.Version, State: federatedoidc.TransactionState(wire.State), Replayed: wire.Replayed,
	}, nil
}

func samlTransactionReceiptFromWire(wire federatedTransactionReceiptWire) (federatedauth.SAMLTransactionWriteReceipt, error) {
	if !validOpaque32(wire.TransactionID) || !validFederatedRevision(wire.Version) ||
		!validSAMLTransactionState(wire.State) {
		return federatedauth.SAMLTransactionWriteReceipt{}, errFederatedAuthPersistence
	}
	var id federatedsaml.TransactionID
	copy(id[:], wire.TransactionID)
	return federatedauth.SAMLTransactionWriteReceipt{
		TransactionID: id, Version: wire.Version, State: federatedsaml.TransactionState(wire.State), Replayed: wire.Replayed,
	}, nil
}

func federatedBeginToWire(
	operation identity.EntityID,
	receipt, network, account, provider []byte,
) (federatedBeginWire, error) {
	operationID, err := requiredFederatedEntityIDWire(operation)
	if err != nil || !validDigestWire(receipt) || !validDigestWire(network) ||
		!validDigestWire(account) || !validDigestWire(provider) ||
		equalAnyDigest(receipt, network, account, provider) {
		return federatedBeginWire{}, errFederatedAuthPersistence
	}
	return federatedBeginWire{
		OperationRunID: operationID, ReceiptDigest: append([]byte(nil), receipt...),
		NetworkDigest: append([]byte(nil), network...), AccountDigest: append([]byte(nil), account...),
		ProviderDigest: append([]byte(nil), provider...),
	}, nil
}

func providerBindingToWire(
	provider identity.ProviderContext,
	binding identity.EntityID,
	allowPlatformWithoutBinding bool,
) (federatedProviderBindingWire, error) {
	providerID, err := requiredFederatedEntityIDWire(provider.ProviderID)
	if err != nil {
		return federatedProviderBindingWire{}, err
	}
	wire := federatedProviderBindingWire{ProviderID: providerID}
	switch provider.Scope {
	case identity.TenantProviderScope:
		wire.Scope = federatedTenantProviderScopeWire
		wire.TenantID, err = requiredFederatedEntityIDWire(provider.TenantID)
		if err == nil {
			wire.BindingID, err = requiredFederatedEntityIDWire(binding)
		}
	case identity.PlatformProviderScope:
		if provider.TenantID != (identity.EntityID{}) {
			return federatedProviderBindingWire{}, errFederatedAuthPersistence
		}
		wire.Scope = federatedPlatformProviderScopeWire
		if allowPlatformWithoutBinding {
			if binding != (identity.EntityID{}) {
				return federatedProviderBindingWire{}, errFederatedAuthPersistence
			}
		} else {
			wire.BindingID, err = requiredFederatedEntityIDWire(binding)
		}
	default:
		return federatedProviderBindingWire{}, errFederatedAuthPersistence
	}
	if err != nil {
		return federatedProviderBindingWire{}, errFederatedAuthPersistence
	}
	return wire, nil
}

func providerBindingFromWire(
	wire federatedProviderBindingWire,
	allowPlatformWithoutBinding bool,
) (identity.ProviderContext, identity.EntityID, error) {
	providerID, err := parseFederatedEntityIDWire(wire.ProviderID, false)
	if err != nil {
		return identity.ProviderContext{}, identity.EntityID{}, err
	}
	provider := identity.ProviderContext{ProviderID: providerID}
	var binding identity.EntityID
	switch wire.Scope {
	case federatedTenantProviderScopeWire:
		provider.Scope = identity.TenantProviderScope
		provider.TenantID, err = parseFederatedEntityIDWire(wire.TenantID, false)
		if err == nil {
			binding, err = parseFederatedEntityIDWire(wire.BindingID, false)
		}
	case federatedPlatformProviderScopeWire:
		provider.Scope = identity.PlatformProviderScope
		if wire.TenantID != "" {
			return identity.ProviderContext{}, identity.EntityID{}, errFederatedAuthPersistence
		}
		binding, err = parseFederatedEntityIDWire(wire.BindingID, allowPlatformWithoutBinding)
		if allowPlatformWithoutBinding && binding != (identity.EntityID{}) {
			return identity.ProviderContext{}, identity.EntityID{}, errFederatedAuthPersistence
		}
	default:
		return identity.ProviderContext{}, identity.EntityID{}, errFederatedAuthPersistence
	}
	if err != nil {
		return identity.ProviderContext{}, identity.EntityID{}, errFederatedAuthPersistence
	}
	return provider, binding, nil
}

func oidcProviderAdmissionToWire(
	provider identity.ProviderContext,
	cryptographicBinding identity.EntityID,
	admission identity.TenantAdmissionContext,
) (federatedProviderBindingWire, *federatedTenantAdmissionWire, error) {
	switch provider.Scope {
	case identity.TenantProviderScope:
		derived := identity.TenantAdmissionContext{TenantID: provider.TenantID, BindingID: cryptographicBinding}
		if admission != (identity.TenantAdmissionContext{}) && admission != derived {
			return federatedProviderBindingWire{}, nil, errFederatedAuthPersistence
		}
		wire, err := providerBindingToWire(provider, cryptographicBinding, false)
		return wire, nil, err
	case identity.PlatformProviderScope:
		if cryptographicBinding != (identity.EntityID{}) || admission == (identity.TenantAdmissionContext{}) {
			return federatedProviderBindingWire{}, nil, errFederatedAuthPersistence
		}
		wire, err := providerBindingToWire(provider, identity.EntityID{}, true)
		if err != nil {
			return federatedProviderBindingWire{}, nil, err
		}
		admissionWire, err := tenantAdmissionToWire(admission)
		if err != nil {
			return federatedProviderBindingWire{}, nil, err
		}
		return wire, &admissionWire, nil
	default:
		return federatedProviderBindingWire{}, nil, errFederatedAuthPersistence
	}
}

func oidcProviderAdmissionFromWire(
	providerWire federatedProviderBindingWire,
	admissionWire *federatedTenantAdmissionWire,
) (identity.ProviderContext, identity.TenantAdmissionContext, identity.EntityID, error) {
	switch providerWire.Scope {
	case federatedTenantProviderScopeWire:
		if admissionWire != nil {
			return identity.ProviderContext{}, identity.TenantAdmissionContext{}, identity.EntityID{}, errFederatedAuthPersistence
		}
		provider, binding, err := providerBindingFromWire(providerWire, false)
		return provider, identity.TenantAdmissionContext{}, binding, err
	case federatedPlatformProviderScopeWire:
		if admissionWire == nil {
			return identity.ProviderContext{}, identity.TenantAdmissionContext{}, identity.EntityID{}, errFederatedAuthPersistence
		}
		provider, binding, err := providerBindingFromWire(providerWire, true)
		if err != nil || binding != (identity.EntityID{}) {
			return identity.ProviderContext{}, identity.TenantAdmissionContext{}, identity.EntityID{}, errFederatedAuthPersistence
		}
		admission, err := tenantAdmissionFromWire(*admissionWire)
		if err != nil {
			return identity.ProviderContext{}, identity.TenantAdmissionContext{}, identity.EntityID{}, errFederatedAuthPersistence
		}
		return provider, admission, identity.EntityID{}, nil
	default:
		return identity.ProviderContext{}, identity.TenantAdmissionContext{}, identity.EntityID{}, errFederatedAuthPersistence
	}
}

func providerTenantAdmissionToWire(
	provider identity.ProviderContext,
	tenantID identity.EntityID,
	bindingID identity.EntityID,
	explicit identity.TenantAdmissionContext,
) (federatedProviderBindingWire, *federatedTenantAdmissionWire, error) {
	admission := identity.TenantAdmissionContext{TenantID: tenantID, BindingID: bindingID}
	if explicit != (identity.TenantAdmissionContext{}) && explicit != admission {
		return federatedProviderBindingWire{}, nil, errFederatedAuthPersistence
	}
	switch provider.Scope {
	case identity.TenantProviderScope:
		if provider.TenantID != tenantID {
			return federatedProviderBindingWire{}, nil, errFederatedAuthPersistence
		}
		wire, err := providerBindingToWire(provider, bindingID, false)
		return wire, nil, err
	case identity.PlatformProviderScope:
		if explicit != admission {
			return federatedProviderBindingWire{}, nil, errFederatedAuthPersistence
		}
		wire, err := providerBindingToWire(provider, identity.EntityID{}, true)
		if err != nil {
			return federatedProviderBindingWire{}, nil, err
		}
		admissionWire, err := tenantAdmissionToWire(admission)
		if err != nil {
			return federatedProviderBindingWire{}, nil, err
		}
		return wire, &admissionWire, nil
	default:
		return federatedProviderBindingWire{}, nil, errFederatedAuthPersistence
	}
}

func providerTenantAdmissionFromWire(
	providerWire federatedProviderBindingWire,
	admissionWire *federatedTenantAdmissionWire,
	tenantID identity.EntityID,
) (identity.ProviderContext, identity.TenantAdmissionContext, identity.EntityID, error) {
	switch providerWire.Scope {
	case federatedTenantProviderScopeWire:
		if admissionWire != nil {
			return identity.ProviderContext{}, identity.TenantAdmissionContext{}, identity.EntityID{}, errFederatedAuthPersistence
		}
		provider, binding, err := providerBindingFromWire(providerWire, false)
		if err != nil || provider.TenantID != tenantID {
			return identity.ProviderContext{}, identity.TenantAdmissionContext{}, identity.EntityID{}, errFederatedAuthPersistence
		}
		return provider, identity.TenantAdmissionContext{}, binding, nil
	case federatedPlatformProviderScopeWire:
		if admissionWire == nil {
			return identity.ProviderContext{}, identity.TenantAdmissionContext{}, identity.EntityID{}, errFederatedAuthPersistence
		}
		provider, cryptographicBinding, err := providerBindingFromWire(providerWire, true)
		admission, admissionErr := tenantAdmissionFromWire(*admissionWire)
		if err != nil || admissionErr != nil || cryptographicBinding != (identity.EntityID{}) || admission.TenantID != tenantID {
			return identity.ProviderContext{}, identity.TenantAdmissionContext{}, identity.EntityID{}, errFederatedAuthPersistence
		}
		return provider, admission, admission.BindingID, nil
	default:
		return identity.ProviderContext{}, identity.TenantAdmissionContext{}, identity.EntityID{}, errFederatedAuthPersistence
	}
}

func tenantAdmissionToWire(value identity.TenantAdmissionContext) (federatedTenantAdmissionWire, error) {
	tenantID, err := requiredFederatedEntityIDWire(value.TenantID)
	if err != nil {
		return federatedTenantAdmissionWire{}, errFederatedAuthPersistence
	}
	bindingID, err := requiredFederatedEntityIDWire(value.BindingID)
	if err != nil {
		return federatedTenantAdmissionWire{}, errFederatedAuthPersistence
	}
	return federatedTenantAdmissionWire{TenantID: tenantID, BindingID: bindingID}, nil
}

func tenantAdmissionFromWire(value federatedTenantAdmissionWire) (identity.TenantAdmissionContext, error) {
	tenantID, err := parseFederatedEntityIDWire(value.TenantID, false)
	if err != nil {
		return identity.TenantAdmissionContext{}, errFederatedAuthPersistence
	}
	bindingID, err := parseFederatedEntityIDWire(value.BindingID, false)
	if err != nil {
		return identity.TenantAdmissionContext{}, errFederatedAuthPersistence
	}
	return identity.TenantAdmissionContext{TenantID: tenantID, BindingID: bindingID}, nil
}

func effectiveTenantAdmission(
	provider identity.ProviderContext,
	tenantID identity.EntityID,
	bindingID identity.EntityID,
	explicit identity.TenantAdmissionContext,
) (identity.TenantAdmissionContext, bool) {
	derived := identity.TenantAdmissionContext{TenantID: tenantID, BindingID: bindingID}
	if tenantID == (identity.EntityID{}) || bindingID == (identity.EntityID{}) {
		return identity.TenantAdmissionContext{}, false
	}
	switch provider.Scope {
	case identity.TenantProviderScope:
		return derived, provider.TenantID == tenantID &&
			(explicit == (identity.TenantAdmissionContext{}) || explicit == derived)
	case identity.PlatformProviderScope:
		return derived, provider.TenantID == (identity.EntityID{}) && explicit == derived
	default:
		return identity.TenantAdmissionContext{}, false
	}
}

func requiredFederatedEntityIDWire(value identity.EntityID) (string, error) {
	identifier := uuid.UUID(value)
	if identifier == uuid.Nil || identifier.Version() != 7 || identifier.Variant() != uuid.RFC4122 {
		return "", errFederatedAuthPersistence
	}
	return identifier.String(), nil
}

func parseFederatedEntityIDWire(value string, optional bool) (identity.EntityID, error) {
	if value == "" && optional {
		return identity.EntityID{}, nil
	}
	identifier, err := uuid.Parse(value)
	if err != nil || identifier == uuid.Nil || identifier.Version() != 7 || identifier.Variant() != uuid.RFC4122 {
		return identity.EntityID{}, errFederatedAuthPersistence
	}
	return identity.EntityID(identifier), nil
}

func optionalDigestToWire(value []byte, present bool) ([]byte, error) {
	if !present {
		if !allZeroFederatedBytes(value) {
			return nil, errFederatedAuthPersistence
		}
		return nil, nil
	}
	if !validDigestWire(value) {
		return nil, errFederatedAuthPersistence
	}
	return append([]byte(nil), value...), nil
}

func validDigestWire(value []byte) bool {
	return len(value) == sha256.Size && !allZeroFederatedBytes(value)
}

func validOpaque32(value []byte) bool { return validDigestWire(value) }

func validFederatedRevision(value uint64) bool {
	return value > 0 && value <= uint64(maximumMFAJSONSafeInteger)
}

func validFederatedSuccessorRevision(value uint64) bool {
	return value > 0 && value < uint64(maximumMFAJSONSafeInteger)
}

func validFederatedDatabaseTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%int(time.Microsecond) == 0
}

func canonicalFederatedDatabaseTimeFromWire(value time.Time) (time.Time, bool) {
	if value.IsZero() || value.Nanosecond()%int(time.Microsecond) != 0 {
		return time.Time{}, false
	}
	return value.UTC(), true
}

func validOIDCPinRevisions(value federatedoidc.TransactionPins) bool {
	return validFederatedRevision(value.ProviderRevision) && validFederatedRevision(value.BindingRevision) &&
		validFederatedRevision(value.ConfigurationRevision) && validFederatedRevision(value.SecurityRevision) &&
		validFederatedRevision(value.MappingRevision) && validFederatedRevision(value.AuthorizationRevision) &&
		validFederatedRevision(value.AssurancePolicyRevision) && validFederatedRevision(value.ClientSecretRevision) &&
		validFederatedRevision(value.DiscoveryRevision) && validFederatedRevision(value.JWKSRevision)
}

func validSAMLPinRevisions(value federatedsaml.TransactionPins) bool {
	return validFederatedRevision(value.ProviderRevision) && validFederatedRevision(value.BindingRevision) &&
		validFederatedRevision(value.ConfigurationRevision) && validFederatedRevision(value.SecurityRevision) &&
		validFederatedRevision(value.MappingRevision) && validFederatedRevision(value.AuthorizationRevision) &&
		validFederatedRevision(value.AssurancePolicyRevision) && validFederatedRevision(value.MetadataRevision) &&
		validFederatedRevision(value.SPKeyRevision)
}

func validOIDCTransactionState(value string) bool {
	switch federatedoidc.TransactionState(value) {
	case federatedoidc.TransactionPending, federatedoidc.TransactionClaimed, federatedoidc.TransactionCompleted,
		federatedoidc.TransactionFailed, federatedoidc.TransactionExpired:
		return true
	default:
		return false
	}
}

func validSAMLTransactionState(value string) bool {
	switch federatedsaml.TransactionState(value) {
	case federatedsaml.TransactionPending, federatedsaml.TransactionCompleted,
		federatedsaml.TransactionFailed, federatedsaml.TransactionExpired:
		return true
	default:
		return false
	}
}

func validOIDCFailureWire(reason, state string) bool {
	validReason := false
	switch federatedoidc.TransactionFailureReason(reason) {
	case federatedoidc.FailureProviderResponse, federatedoidc.FailureStaleConfiguration,
		federatedoidc.FailureExpired, federatedoidc.FailureTokenExchange,
		federatedoidc.FailureTokenValidation, federatedoidc.FailureIdentityApplication:
		validReason = true
	}
	return validReason && (state == string(federatedoidc.TransactionFailed) ||
		state == string(federatedoidc.TransactionExpired))
}

func equalAnyDigest(values ...[]byte) bool {
	for left := range values {
		for right := left + 1; right < len(values); right++ {
			if bytesEqualFederated(values[left], values[right]) {
				return true
			}
		}
	}
	return false
}

func bytesEqualFederated(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}

func allZeroFederatedBytes(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

func clearFederatedBeginWire(value *federatedBeginWire) {
	if value == nil {
		return
	}
	clear(value.ReceiptDigest)
	clear(value.NetworkDigest)
	clear(value.AccountDigest)
	clear(value.ProviderDigest)
}

func clearOIDCPinsWire(value *oidcTransactionPinsWire) {
	if value == nil {
		return
	}
	clear(value.DiscoveryDigest)
	clear(value.JWKSDigest)
}

func clearOIDCPendingTransactionWire(value *oidcPendingTransactionWire) {
	if value == nil {
		return
	}
	clear(value.ID)
	clear(value.StateDigest)
	clear(value.BrowserDigest)
	clear(value.NonceDigest)
	clear(value.VerifierCiphertext)
	clearOIDCPinsWire(&value.Pins)
}

func clearOIDCCreateTransactionWire(value *oidcCreateTransactionWire) {
	if value == nil {
		return
	}
	clearFederatedBeginWire(&value.Begin)
	clearOIDCPendingTransactionWire(&value.Current)
	clear(value.PreviousBrowserDigest)
}

func clearOIDCClaimWire(value *oidcTransactionClaimWire) {
	if value == nil {
		return
	}
	clear(value.AttemptID)
	clear(value.StateDigest)
	clear(value.BrowserDigest)
}

func clearOIDCClaimedTransactionWire(value *oidcClaimedTransactionWire) {
	if value == nil {
		return
	}
	clearOIDCPendingTransactionWire(&value.oidcPendingTransactionWire)
	clear(value.ClaimAttemptID)
}

func clearSAMLPinsWire(value *samlTransactionPinsWire) {
	if value == nil {
		return
	}
	clear(value.MetadataDigest)
	clear(value.ConfigurationDigest)
}

func clearSAMLPendingTransactionWire(value *samlPendingTransactionWire) {
	if value == nil {
		return
	}
	clear(value.ID)
	clear(value.RelayStateDigest)
	clear(value.BrowserDigest)
	clearSAMLPinsWire(&value.Pins)
}

func clearSAMLCreateTransactionWire(value *samlCreateTransactionWire) {
	if value == nil {
		return
	}
	clearFederatedBeginWire(&value.Begin)
	clearSAMLPendingTransactionWire(&value.Current)
	clear(value.PreviousBrowserDigest)
}

func clearSAMLLookupWire(value *samlTransactionLookupWire) {
	if value == nil {
		return
	}
	clear(value.RelayStateDigest)
	clear(value.BrowserDigest)
}
