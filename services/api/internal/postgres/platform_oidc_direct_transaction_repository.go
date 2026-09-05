package postgres

import (
	"context"
	"crypto/sha256"
	"slices"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

const (
	createPlatformOIDCDirectTransactionSQL = `select app.create_platform_oidc_authentication_transaction_v1($1::jsonb)`
	claimPlatformOIDCDirectTransactionSQL  = `select app.claim_platform_oidc_authentication_transaction_v1($1::jsonb)`
	failPlatformOIDCDirectTransactionSQL   = `select app.fail_platform_oidc_authentication_transaction_v1($1::jsonb)`

	maximumPlatformOIDCDirectTransactionWireBytes = 160 * 1024
	maximumPlatformOIDCDirectVerifierBytes        = 4 * 1024
	maximumPlatformOIDCDirectScopes               = 32
	maximumPlatformOIDCDirectScopeBytes           = 128
	maximumPlatformOIDCDirectClientIDBytes        = 512
)

type platformOIDCDirectBeginWire struct {
	OperationRunID string `json:"operationRunId"`
	ReceiptDigest  []byte `json:"receiptDigest"`
	NetworkDigest  []byte `json:"networkDigest"`
	AccountDigest  []byte `json:"accountDigest"`
	ProviderDigest []byte `json:"providerDigest"`
}

type platformOIDCDirectTransactionWire struct {
	ID                    []byte                     `json:"id"`
	StateDigest           []byte                     `json:"stateDigest"`
	BrowserDigest         []byte                     `json:"browserDigest"`
	NonceDigest           []byte                     `json:"nonceDigest"`
	AuthorizationCode     []byte                     `json:"authorizationCodeDigest,omitempty"`
	CodeChallengeMethod   string                     `json:"codeChallengeMethod"`
	VerifierKeyVersion    uint32                     `json:"verifierKeyVersion"`
	VerifierCiphertext    []byte                     `json:"verifierCiphertext"`
	Pins                  platformOIDCDirectPinsWire `json:"pins"`
	ClientID              string                     `json:"clientId"`
	RedirectURI           string                     `json:"redirectUri"`
	PostLogoutRedirectURI string                     `json:"postLogoutRedirectUri"`
	ReturnPath            string                     `json:"returnPath"`
	Scopes                []string                   `json:"scopes"`
	AllowRefreshToken     bool                       `json:"allowRefreshToken"`
	UseUserInfo           bool                       `json:"useUserInfo"`
	State                 string                     `json:"state"`
	Version               uint64                     `json:"version"`
	ClaimAttemptID        []byte                     `json:"claimAttemptId,omitempty"`
	CreatedAt             time.Time                  `json:"createdAt"`
	ExpiresAt             time.Time                  `json:"expiresAt"`
	ClaimedAt             *time.Time                 `json:"claimedAt,omitempty"`
	CompletedAt           *time.Time                 `json:"completedAt,omitempty"`
	FailureReason         *string                    `json:"failureReason,omitempty"`
}

type platformOIDCDirectCreateTransactionWire struct {
	Begin                   platformOIDCDirectBeginWire       `json:"begin"`
	Current                 platformOIDCDirectTransactionWire `json:"current"`
	PreviousBrowserDigest   []byte                            `json:"previousBrowserDigest,omitempty"`
	BrowserCapabilityDigest []byte                            `json:"browserCapabilityDigest"`
	Audit                   platformOIDCDirectAuditWire       `json:"audit"`
}

type platformOIDCDirectClaimTransactionWire struct {
	StateDigest             []byte                      `json:"stateDigest"`
	BrowserDigest           []byte                      `json:"browserDigest"`
	AuthorizationCodeDigest []byte                      `json:"authorizationCodeDigest"`
	ClaimAttemptID          []byte                      `json:"claimAttemptId"`
	ClaimedAt               time.Time                   `json:"claimedAt"`
	ExpectedVersion         uint64                      `json:"expectedVersion"`
	Audit                   platformOIDCDirectAuditWire `json:"audit"`
}

type platformOIDCDirectFailureWire struct {
	TransactionID   []byte                      `json:"transactionId"`
	ExpectedVersion uint64                      `json:"expectedVersion"`
	State           string                      `json:"state"`
	FailureReason   string                      `json:"failureReason"`
	CompletedAt     time.Time                   `json:"completedAt"`
	Audit           platformOIDCDirectAuditWire `json:"audit"`
}

var _ platformoidcauth.DirectOIDCTransactionPersistence = (*FederatedAuthRepository)(nil)

func (repository *FederatedAuthRepository) CreateDirectOIDCTransaction(
	ctx context.Context,
	request platformoidcauth.DirectOIDCCreateTransactionRequest,
) error {
	eventID, err := platformOIDCDirectStableAuditEventID(
		request.Audit, "transaction.create", request.Begin.OperationRunID[:], request.Current.ID[:],
	)
	if err != nil {
		return errFederatedAuthPersistence
	}
	wire, err := platformOIDCDirectCreateTransactionToWire(request, eventID)
	if err != nil {
		return errFederatedAuthPersistence
	}
	defer clearPlatformOIDCDirectCreateTransactionWire(&wire)
	var response platformOIDCDirectTransactionWire
	defer clearPlatformOIDCDirectTransactionWire(&response)
	if err = repository.queryBoundedJSON(
		ctx, createPlatformOIDCDirectTransactionSQL, wire, &response,
		maximumPlatformOIDCDirectTransactionWireBytes,
	); err != nil || ctx.Err() != nil {
		return errFederatedAuthPersistence
	}
	record, err := platformOIDCDirectTransactionFromWire(response)
	defer clear(record.Verifier.Ciphertext)
	if err != nil || !equalPlatformOIDCDirectPending(record, request.Current) ||
		response.CodeChallengeMethod != request.CodeChallengeMethod ||
		len(response.AuthorizationCode) != 0 || len(response.ClaimAttemptID) != 0 ||
		response.ClaimedAt != nil || response.CompletedAt != nil || response.FailureReason != nil {
		return errFederatedAuthPersistence
	}
	return nil
}

func (repository *FederatedAuthRepository) ClaimDirectOIDCTransaction(
	ctx context.Context,
	request platformoidcauth.DirectOIDCClaimTransactionRequest,
) (federatedoidc.ClaimedTransaction, error) {
	eventID, err := platformOIDCDirectStableAuditEventID(
		request.Audit, "transaction.claim", request.AttemptID[:], request.StateDigest[:],
	)
	if err != nil {
		return federatedoidc.ClaimedTransaction{}, errFederatedAuthPersistence
	}
	wire, err := platformOIDCDirectClaimTransactionToWire(request, eventID)
	if err != nil {
		return federatedoidc.ClaimedTransaction{}, errFederatedAuthPersistence
	}
	defer clearPlatformOIDCDirectClaimTransactionWire(&wire)
	var response platformOIDCDirectTransactionWire
	defer clearPlatformOIDCDirectTransactionWire(&response)
	if err = repository.queryBoundedJSON(
		ctx, claimPlatformOIDCDirectTransactionSQL, wire, &response,
		maximumPlatformOIDCDirectTransactionWireBytes,
	); err != nil || ctx.Err() != nil {
		return federatedoidc.ClaimedTransaction{}, errFederatedAuthPersistence
	}
	pending, err := platformOIDCDirectTransactionFromWire(response)
	if err != nil || pending.State != federatedoidc.TransactionClaimed || pending.Version != 2 ||
		!slices.Equal(response.ClaimAttemptID, request.AttemptID[:]) ||
		!slices.Equal(response.AuthorizationCode, request.AuthorizationCodeDigest[:]) ||
		response.ClaimedAt == nil || response.CompletedAt != nil || response.FailureReason != nil {
		clear(pending.Verifier.Ciphertext)
		return federatedoidc.ClaimedTransaction{}, errFederatedAuthPersistence
	}
	claimedAt, ok := canonicalFederatedDatabaseTimeFromWire(*response.ClaimedAt)
	if !ok || !claimedAt.Equal(request.ClaimedAt) ||
		claimedAt.Before(pending.CreatedAt) || !claimedAt.Before(pending.ExpiresAt) ||
		pending.StateDigest != request.StateDigest || pending.BrowserDigest != request.BrowserDigest {
		clear(pending.Verifier.Ciphertext)
		return federatedoidc.ClaimedTransaction{}, errFederatedAuthPersistence
	}
	var attempt federatedoidc.TransactionID
	var authorizationCode [sha256.Size]byte
	copy(attempt[:], response.ClaimAttemptID)
	copy(authorizationCode[:], response.AuthorizationCode)
	return federatedoidc.ClaimedTransaction{
		PendingTransaction: pending, ClaimAttemptID: attempt,
		AuthorizationCodeDigest: authorizationCode, ClaimedAt: claimedAt,
	}, nil
}

func (repository *FederatedAuthRepository) FailDirectOIDCTransaction(
	ctx context.Context,
	request platformoidcauth.DirectOIDCFailureRequest,
) error {
	eventID, err := platformOIDCDirectStableAuditEventID(
		request.Audit, "transaction.fail", request.TransactionID[:],
	)
	if err != nil {
		return errFederatedAuthPersistence
	}
	wire, err := platformOIDCDirectFailureToWire(request, eventID)
	if err != nil {
		return errFederatedAuthPersistence
	}
	defer clearPlatformOIDCDirectFailureWire(&wire)
	var response platformOIDCDirectTransactionWire
	defer clearPlatformOIDCDirectTransactionWire(&response)
	if err = repository.queryBoundedJSON(
		ctx, failPlatformOIDCDirectTransactionSQL, wire, &response,
		maximumPlatformOIDCDirectTransactionWireBytes,
	); err != nil || ctx.Err() != nil {
		return errFederatedAuthPersistence
	}
	record, err := platformOIDCDirectTransactionFromWire(response)
	defer clear(record.Verifier.Ciphertext)
	if err != nil || record.ID != request.TransactionID || record.State != request.State ||
		record.Version != request.ExpectedVersion+1 || response.CompletedAt == nil ||
		response.FailureReason == nil || *response.FailureReason != string(request.Reason) ||
		!validPlatformOIDCDirectFailureLifecycle(response, request.ExpectedVersion) {
		return errFederatedAuthPersistence
	}
	completedAt, ok := canonicalFederatedDatabaseTimeFromWire(*response.CompletedAt)
	if !ok || !completedAt.Equal(request.FailedAt) {
		return errFederatedAuthPersistence
	}
	return nil
}

func platformOIDCDirectCreateTransactionToWire(
	request platformoidcauth.DirectOIDCCreateTransactionRequest,
	eventID uuid.UUID,
) (platformOIDCDirectCreateTransactionWire, error) {
	begin, err := platformOIDCDirectBeginToWire(request.Begin)
	if err != nil {
		return platformOIDCDirectCreateTransactionWire{}, err
	}
	current, err := platformOIDCDirectPendingToWire(request.Current, request.CodeChallengeMethod)
	if err != nil {
		clearPlatformOIDCDirectBeginWire(&begin)
		return platformOIDCDirectCreateTransactionWire{}, err
	}
	audit, err := platformOIDCDirectAuditToWire(request.Audit, eventID)
	if err != nil || !validPlatformOIDCDigest(request.BrowserCapabilityDigest[:]) ||
		request.HasPreviousBrowserBinding != (request.PreviousBrowserDigest != ([sha256.Size]byte{})) {
		clearPlatformOIDCDirectBeginWire(&begin)
		clearPlatformOIDCDirectTransactionWire(&current)
		return platformOIDCDirectCreateTransactionWire{}, errFederatedAuthPersistence
	}
	previous := []byte(nil)
	if request.HasPreviousBrowserBinding {
		previous = append([]byte(nil), request.PreviousBrowserDigest[:]...)
		if request.PreviousBrowserDigest == request.Current.BrowserDigest ||
			request.PreviousBrowserDigest == [sha256.Size]byte(request.BrowserCapabilityDigest) {
			clearPlatformOIDCDirectBeginWire(&begin)
			clearPlatformOIDCDirectTransactionWire(&current)
			clear(previous)
			return platformOIDCDirectCreateTransactionWire{}, errFederatedAuthPersistence
		}
	}
	digests := [][]byte{
		begin.ReceiptDigest, begin.NetworkDigest, begin.AccountDigest, begin.ProviderDigest,
		current.StateDigest, current.BrowserDigest, request.BrowserCapabilityDigest[:], current.NonceDigest,
	}
	if equalAnyDigest(digests...) {
		clearPlatformOIDCDirectBeginWire(&begin)
		clearPlatformOIDCDirectTransactionWire(&current)
		clear(previous)
		return platformOIDCDirectCreateTransactionWire{}, errFederatedAuthPersistence
	}
	return platformOIDCDirectCreateTransactionWire{
		Begin: begin, Current: current, PreviousBrowserDigest: previous,
		BrowserCapabilityDigest: append([]byte(nil), request.BrowserCapabilityDigest[:]...), Audit: audit,
	}, nil
}

func platformOIDCDirectBeginToWire(
	value federatedoidc.AuthorizationBegin,
) (platformOIDCDirectBeginWire, error) {
	if !platformOIDCDirectUUIDv7(uuid.UUID(value.OperationRunID)) ||
		!validPlatformOIDCDigest(value.ReceiptDigest[:]) || !validPlatformOIDCDigest(value.NetworkDigest[:]) ||
		!validPlatformOIDCDigest(value.AccountDigest[:]) || !validPlatformOIDCDigest(value.ProviderDigest[:]) ||
		equalAnyDigest(value.ReceiptDigest[:], value.NetworkDigest[:], value.AccountDigest[:], value.ProviderDigest[:]) {
		return platformOIDCDirectBeginWire{}, errFederatedAuthPersistence
	}
	return platformOIDCDirectBeginWire{
		OperationRunID: entityIDWire(value.OperationRunID),
		ReceiptDigest:  append([]byte(nil), value.ReceiptDigest[:]...),
		NetworkDigest:  append([]byte(nil), value.NetworkDigest[:]...),
		AccountDigest:  append([]byte(nil), value.AccountDigest[:]...),
		ProviderDigest: append([]byte(nil), value.ProviderDigest[:]...),
	}, nil
}

func platformOIDCDirectPendingToWire(
	value federatedoidc.PendingTransaction,
	codeChallengeMethod string,
) (platformOIDCDirectTransactionWire, error) {
	pins, err := platformOIDCDirectPinsFromTransaction(value.Pins)
	if err != nil {
		return platformOIDCDirectTransactionWire{}, errFederatedAuthPersistence
	}
	wirePins, err := platformOIDCDirectPinsToWire(pins)
	if err != nil || !validOpaque32(value.ID[:]) || !validPlatformOIDCDigest(value.StateDigest[:]) ||
		!validPlatformOIDCDigest(value.BrowserDigest[:]) || !validPlatformOIDCDigest(value.NonceDigest[:]) ||
		equalAnyDigest(value.StateDigest[:], value.BrowserDigest[:], value.NonceDigest[:]) ||
		codeChallengeMethod != federatedoidc.CodeChallengeS256 || value.Verifier.KeyVersion < 1 ||
		value.Verifier.KeyVersion > 32767 || len(value.Verifier.Ciphertext) < 16 ||
		len(value.Verifier.Ciphertext) > maximumPlatformOIDCDirectVerifierBytes ||
		!validFederatedDatabaseTime(value.CreatedAt) || !validFederatedDatabaseTime(value.ExpiresAt) ||
		value.ExpiresAt.Sub(value.CreatedAt) < time.Minute || value.ExpiresAt.Sub(value.CreatedAt) > 15*time.Minute ||
		value.State != federatedoidc.TransactionPending || value.Version != 1 ||
		value.UseUserInfo || !validPlatformOIDCDirectReturnPath(value.ReturnPath) ||
		!validPlatformOIDCDirectTransactionText(value.ClientID, maximumPlatformOIDCDirectClientIDBytes) ||
		value.RedirectURI == "" || value.PostLogoutRedirectURI == "" ||
		!validPlatformOIDCDirectScopes(value.Scopes) ||
		value.AllowRefreshToken != slices.Contains(value.Scopes, "offline_access") {
		return platformOIDCDirectTransactionWire{}, errFederatedAuthPersistence
	}
	return platformOIDCDirectTransactionWire{
		ID: append([]byte(nil), value.ID[:]...), StateDigest: append([]byte(nil), value.StateDigest[:]...),
		BrowserDigest: append([]byte(nil), value.BrowserDigest[:]...),
		NonceDigest:   append([]byte(nil), value.NonceDigest[:]...), CodeChallengeMethod: codeChallengeMethod,
		VerifierKeyVersion: value.Verifier.KeyVersion,
		VerifierCiphertext: append([]byte(nil), value.Verifier.Ciphertext...), Pins: wirePins,
		ClientID: value.ClientID, RedirectURI: value.RedirectURI,
		PostLogoutRedirectURI: value.PostLogoutRedirectURI, ReturnPath: value.ReturnPath,
		Scopes: append([]string(nil), value.Scopes...), AllowRefreshToken: value.AllowRefreshToken, UseUserInfo: false,
		State: string(value.State), Version: value.Version, CreatedAt: value.CreatedAt, ExpiresAt: value.ExpiresAt,
	}, nil
}

func platformOIDCDirectClaimTransactionToWire(
	value platformoidcauth.DirectOIDCClaimTransactionRequest,
	eventID uuid.UUID,
) (platformOIDCDirectClaimTransactionWire, error) {
	audit, auditErr := platformOIDCDirectAuditToWire(value.Audit, eventID)
	if auditErr != nil || value.ExpectedVersion != 1 || !validOpaque32(value.AttemptID[:]) ||
		!validPlatformOIDCDigest(value.StateDigest[:]) || !validPlatformOIDCDigest(value.BrowserDigest[:]) ||
		!validPlatformOIDCDigest(value.AuthorizationCodeDigest[:]) ||
		equalAnyDigest(value.AttemptID[:], value.StateDigest[:], value.BrowserDigest[:], value.AuthorizationCodeDigest[:]) ||
		!validFederatedDatabaseTime(value.ClaimedAt) {
		return platformOIDCDirectClaimTransactionWire{}, errFederatedAuthPersistence
	}
	return platformOIDCDirectClaimTransactionWire{
		StateDigest:             append([]byte(nil), value.StateDigest[:]...),
		BrowserDigest:           append([]byte(nil), value.BrowserDigest[:]...),
		AuthorizationCodeDigest: append([]byte(nil), value.AuthorizationCodeDigest[:]...),
		ClaimAttemptID:          append([]byte(nil), value.AttemptID[:]...), ClaimedAt: value.ClaimedAt,
		ExpectedVersion: value.ExpectedVersion, Audit: audit,
	}, nil
}

func platformOIDCDirectFailureToWire(
	value platformoidcauth.DirectOIDCFailureRequest,
	eventID uuid.UUID,
) (platformOIDCDirectFailureWire, error) {
	audit, auditErr := platformOIDCDirectAuditToWire(value.Audit, eventID)
	if auditErr != nil || !validOpaque32(value.TransactionID[:]) ||
		(value.ExpectedVersion != 1 && value.ExpectedVersion != 2) ||
		!validFederatedDatabaseTime(value.FailedAt) ||
		!validOIDCFailureWire(string(value.Reason), string(value.State)) ||
		(value.Reason == federatedoidc.FailureExpired) != (value.State == federatedoidc.TransactionExpired) {
		return platformOIDCDirectFailureWire{}, errFederatedAuthPersistence
	}
	return platformOIDCDirectFailureWire{
		TransactionID: append([]byte(nil), value.TransactionID[:]...), ExpectedVersion: value.ExpectedVersion,
		State: string(value.State), FailureReason: string(value.Reason), CompletedAt: value.FailedAt, Audit: audit,
	}, nil
}

func platformOIDCDirectTransactionFromWire(
	wire platformOIDCDirectTransactionWire,
) (federatedoidc.PendingTransaction, error) {
	pins, err := platformOIDCDirectPinsFromWire(wire.Pins)
	createdAt, validCreatedAt := canonicalFederatedDatabaseTimeFromWire(wire.CreatedAt)
	expiresAt, validExpiresAt := canonicalFederatedDatabaseTimeFromWire(wire.ExpiresAt)
	if err != nil || !validOpaque32(wire.ID) || !validPlatformOIDCDigest(wire.StateDigest) ||
		!validPlatformOIDCDigest(wire.BrowserDigest) || !validPlatformOIDCDigest(wire.NonceDigest) ||
		equalAnyDigest(wire.StateDigest, wire.BrowserDigest, wire.NonceDigest) ||
		wire.CodeChallengeMethod != federatedoidc.CodeChallengeS256 || wire.VerifierKeyVersion < 1 ||
		wire.VerifierKeyVersion > 32767 || len(wire.VerifierCiphertext) < 16 ||
		len(wire.VerifierCiphertext) > maximumPlatformOIDCDirectVerifierBytes ||
		!validCreatedAt || !validExpiresAt || !expiresAt.After(createdAt) ||
		!validOIDCTransactionState(wire.State) || !validFederatedRevision(wire.Version) ||
		wire.UseUserInfo || !validPlatformOIDCDirectReturnPath(wire.ReturnPath) ||
		!validPlatformOIDCDirectTransactionText(wire.ClientID, maximumPlatformOIDCDirectClientIDBytes) ||
		wire.RedirectURI == "" || wire.PostLogoutRedirectURI == "" ||
		!validPlatformOIDCDirectScopes(wire.Scopes) ||
		wire.AllowRefreshToken != slices.Contains(wire.Scopes, "offline_access") {
		return federatedoidc.PendingTransaction{}, errFederatedAuthPersistence
	}
	var id federatedoidc.TransactionID
	var stateDigest, browserDigest, nonceDigest [sha256.Size]byte
	copy(id[:], wire.ID)
	copy(stateDigest[:], wire.StateDigest)
	copy(browserDigest[:], wire.BrowserDigest)
	copy(nonceDigest[:], wire.NonceDigest)
	return federatedoidc.PendingTransaction{
		ID: id, StateDigest: stateDigest, BrowserDigest: browserDigest, NonceDigest: nonceDigest,
		Verifier: federatedoidc.ProtectedVerifier{
			KeyVersion: wire.VerifierKeyVersion, Ciphertext: append([]byte(nil), wire.VerifierCiphertext...),
		},
		Pins: platformOIDCDirectPinsToTransaction(pins), ClientID: wire.ClientID,
		RedirectURI: wire.RedirectURI, PostLogoutRedirectURI: wire.PostLogoutRedirectURI,
		ReturnPath: wire.ReturnPath, Scopes: append([]string(nil), wire.Scopes...),
		AllowRefreshToken: wire.AllowRefreshToken, UseUserInfo: false, CreatedAt: createdAt, ExpiresAt: expiresAt,
		State: federatedoidc.TransactionState(wire.State), Version: wire.Version,
	}, nil
}

func platformOIDCDirectPinsToTransaction(
	pins platformoidcauth.DirectOIDCConfigurationPins,
) federatedoidc.TransactionPins {
	return federatedoidc.TransactionPins{
		Authority: federatedoidc.DirectPlatformCeremonyAuthority, Provider: pins.Provider,
		ProviderRevision: pins.ProviderRevision, PlatformLoginRevision: pins.PlatformLoginRevision,
		ConfigurationRevision: pins.ConfigurationRevision, SecurityRevision: pins.SecurityRevision,
		PlanRevision: pins.PlanRevision, AssurancePolicyRevision: pins.AssurancePolicyRevision,
		PlatformFloorPolicyID: pins.PlatformFloorPolicyID,
		PlatformFloorRevision: pins.PlatformFloorPolicyRevision,
		ClientSecretRevision:  pins.ClientSecretRevision, DiscoveryRevision: pins.DiscoveryRevision,
		DiscoveryDigest: pins.DiscoveryDigest, JWKSRevision: pins.JWKSRevision, JWKSDigest: pins.JWKSDigest,
	}
}

func equalPlatformOIDCDirectPending(left, right federatedoidc.PendingTransaction) bool {
	return left.ID == right.ID && left.StateDigest == right.StateDigest && left.BrowserDigest == right.BrowserDigest &&
		left.NonceDigest == right.NonceDigest && left.Verifier.KeyVersion == right.Verifier.KeyVersion &&
		slices.Equal(left.Verifier.Ciphertext, right.Verifier.Ciphertext) && left.Pins == right.Pins &&
		left.ClientID == right.ClientID && left.RedirectURI == right.RedirectURI &&
		left.PostLogoutRedirectURI == right.PostLogoutRedirectURI && left.ReturnPath == right.ReturnPath &&
		slices.Equal(left.Scopes, right.Scopes) && left.AllowRefreshToken == right.AllowRefreshToken &&
		left.UseUserInfo == right.UseUserInfo && left.CreatedAt.Equal(right.CreatedAt) &&
		left.ExpiresAt.Equal(right.ExpiresAt) && left.State == right.State && left.Version == right.Version
}

func validPlatformOIDCDirectScopes(values []string) bool {
	if len(values) < 1 || len(values) > maximumPlatformOIDCDirectScopes || values[0] != "openid" {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validPlatformOIDCDirectScope(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validPlatformOIDCDirectScope(value string) bool {
	if value == "" || len(value) > maximumPlatformOIDCDirectScopeBytes {
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

func validPlatformOIDCDirectFailureLifecycle(
	wire platformOIDCDirectTransactionWire,
	expectedVersion uint64,
) bool {
	hasAttempt := len(wire.ClaimAttemptID) != 0
	hasCode := len(wire.AuthorizationCode) != 0
	hasClaimedAt := wire.ClaimedAt != nil
	if hasAttempt != hasCode || hasAttempt != hasClaimedAt {
		return false
	}
	if expectedVersion == 1 {
		return !hasAttempt
	}
	if expectedVersion != 2 || !hasAttempt || !validOpaque32(wire.ClaimAttemptID) ||
		!validPlatformOIDCDigest(wire.AuthorizationCode) || wire.CompletedAt == nil {
		return false
	}
	claimedAt, claimedOK := canonicalFederatedDatabaseTimeFromWire(*wire.ClaimedAt)
	completedAt, completedOK := canonicalFederatedDatabaseTimeFromWire(*wire.CompletedAt)
	return claimedOK && completedOK && !claimedAt.After(completedAt)
}

func validPlatformOIDCDirectTransactionText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

func clearPlatformOIDCDirectBeginWire(value *platformOIDCDirectBeginWire) {
	if value == nil {
		return
	}
	clear(value.ReceiptDigest)
	clear(value.NetworkDigest)
	clear(value.AccountDigest)
	clear(value.ProviderDigest)
	*value = platformOIDCDirectBeginWire{}
}

func clearPlatformOIDCDirectTransactionWire(value *platformOIDCDirectTransactionWire) {
	if value == nil {
		return
	}
	clear(value.ID)
	clear(value.StateDigest)
	clear(value.BrowserDigest)
	clear(value.NonceDigest)
	clear(value.AuthorizationCode)
	clear(value.VerifierCiphertext)
	clear(value.Pins.DiscoveryDigest)
	clear(value.Pins.JWKSDigest)
	clear(value.ClaimAttemptID)
	clear(value.Scopes)
	*value = platformOIDCDirectTransactionWire{}
}

func clearPlatformOIDCDirectCreateTransactionWire(value *platformOIDCDirectCreateTransactionWire) {
	if value == nil {
		return
	}
	clearPlatformOIDCDirectBeginWire(&value.Begin)
	clearPlatformOIDCDirectTransactionWire(&value.Current)
	clear(value.PreviousBrowserDigest)
	clear(value.BrowserCapabilityDigest)
	*value = platformOIDCDirectCreateTransactionWire{}
}

func clearPlatformOIDCDirectClaimTransactionWire(value *platformOIDCDirectClaimTransactionWire) {
	if value == nil {
		return
	}
	clear(value.StateDigest)
	clear(value.BrowserDigest)
	clear(value.AuthorizationCodeDigest)
	clear(value.ClaimAttemptID)
	*value = platformOIDCDirectClaimTransactionWire{}
}

func clearPlatformOIDCDirectFailureWire(value *platformOIDCDirectFailureWire) {
	if value == nil {
		return
	}
	clear(value.TransactionID)
	*value = platformOIDCDirectFailureWire{}
}
