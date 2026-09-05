package federatedoidc

import (
	"context"
	"crypto/sha256"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

func (flow *Flow) StartAuthorization(
	ctx context.Context,
	request StartAuthorizationRequest,
) (AuthorizationStart, error) {
	configuration, scopes, err := flow.normalizeConfiguration(request.Configuration)
	if err != nil || !validAuthorizationBegin(request.Begin) || !validReturnPath(request.ReturnPath) {
		return AuthorizationStart{}, ErrAuthorizationRejected
	}
	now, ok := flow.currentTime()
	if !ok || !trustSnapshotsFreshAtStart(configuration, now) {
		return AuthorizationStart{}, ErrAuthorizationRejected
	}
	operationCtx, cancel, err := flow.operationContext(ctx)
	if err != nil {
		return AuthorizationStart{}, ErrAuthorizationRejected
	}
	defer cancel()

	transactionID, err := generateTransactionID(flow.random)
	if err != nil {
		return AuthorizationStart{}, ErrAuthorizationRejected
	}
	state, err := generateOpaque(flow.random)
	if err != nil {
		return AuthorizationStart{}, ErrAuthorizationRejected
	}
	defer clear(state)
	nonce, err := generateOpaque(flow.random)
	if err != nil {
		return AuthorizationStart{}, ErrAuthorizationRejected
	}
	defer clear(nonce)
	browserHandle, err := generateOpaque(flow.random)
	if err != nil {
		return AuthorizationStart{}, ErrAuthorizationRejected
	}
	defer clear(browserHandle)
	verifier, err := generateOpaque(flow.random)
	if err != nil || !validPKCEVerifier(verifier) {
		clear(verifier)
		return AuthorizationStart{}, ErrAuthorizationRejected
	}
	defer clear(verifier)

	protectionContext := TransactionProtectionContext{
		Authority:             configuration.Authority,
		TransactionID:         transactionID,
		Provider:              configuration.Provider,
		Admission:             configuration.Admission,
		BindingID:             configuration.BindingID,
		PlatformLoginRevision: configuration.PlatformLoginRevision,
	}
	verifierForSeal := append([]byte(nil), verifier...)
	protectedVerifier, protectErr := flow.verifierProtector.SealPKCE(
		operationCtx,
		protectionContext,
		verifierForSeal,
	)
	clear(verifierForSeal)
	if protectErr != nil || !validProtectedVerifier(protectedVerifier) {
		clear(protectedVerifier.Ciphertext)
		return AuthorizationStart{}, ErrAuthorizationRejected
	}
	defer clear(protectedVerifier.Ciphertext)

	query := url.Values{}
	query.Set("client_id", configuration.ClientID)
	query.Set("code_challenge", oauth2.S256ChallengeFromVerifier(string(verifier)))
	query.Set("code_challenge_method", CodeChallengeS256)
	query.Set("max_age", strconv.FormatInt(int64(flow.policy.MaxAuthenticationAge/time.Second), 10))
	query.Set("nonce", string(nonce))
	query.Set("redirect_uri", configuration.RedirectURI)
	query.Set("response_mode", ResponseModeQuery)
	query.Set("response_type", ResponseTypeCode)
	query.Set("scope", strings.Join(scopes, " "))
	query.Set("state", string(state))
	authorizationURL := configuration.Discovery.Endpoints().Authorization + "?" + query.Encode()
	if len(authorizationURL) > maximumAuthorizationURLBytes {
		return AuthorizationStart{}, ErrAuthorizationRejected
	}
	expiresAt := now.Add(flow.policy.TransactionTTL)
	record := PendingTransaction{
		ID:          transactionID,
		MaterialID:  request.Begin.OperationRunID,
		StateDigest: digestValue(state), BrowserDigest: digestValue(browserHandle),
		NonceDigest: digestValue(nonce), Verifier: cloneProtectedVerifier(protectedVerifier),
		Pins: transactionPins(configuration), ClientID: configuration.ClientID,
		RedirectURI:           configuration.RedirectURI,
		PostLogoutRedirectURI: configuration.PostLogoutRedirectURI,
		ReturnPath:            request.ReturnPath,
		Scopes:                append([]string(nil), scopes...), AllowRefreshToken: configuration.AllowRefreshToken,
		UseUserInfo: configuration.UseUserInfo,
		CreatedAt:   now, ExpiresAt: expiresAt, State: TransactionPending, Version: 1,
	}
	defer clear(record.Verifier.Ciphertext)
	create := CreateTransactionRequest{
		Begin: request.Begin, Current: record,
		ApplicationBrowserBindingDigest: request.ApplicationBrowserBindingDigest,
		Audit:                           request.Audit,
	}
	if len(request.PreviousBrowserHandle) != 0 {
		if !validOpaque(request.PreviousBrowserHandle) {
			return AuthorizationStart{}, ErrAuthorizationRejected
		}
		create.PreviousBrowserDigest = sha256.Sum256(request.PreviousBrowserHandle)
		create.HasPreviousBrowserBinding = true
	}
	var repositoryErr error
	for range 2 {
		attempt := cloneCreateTransactionRequest(create)
		repositoryErr = flow.transactions.CreateReplacing(operationCtx, attempt)
		clear(attempt.Current.Verifier.Ciphertext)
		if repositoryErr == nil || operationCtx.Err() != nil {
			break
		}
	}
	if repositoryErr != nil {
		return AuthorizationStart{}, ErrTransactionPersistence
	}

	return AuthorizationStart{
		transactionID: transactionID,
		redirectURL:   authorizationURL,
		browserHandle: append([]byte(nil), browserHandle...),
		expiresAt:     expiresAt,
		valid:         true,
	}, nil
}

func cloneCreateTransactionRequest(source CreateTransactionRequest) CreateTransactionRequest {
	result := source
	result.Current.Verifier = cloneProtectedVerifier(source.Current.Verifier)
	result.Current.Scopes = append([]string(nil), source.Current.Scopes...)
	return result
}
