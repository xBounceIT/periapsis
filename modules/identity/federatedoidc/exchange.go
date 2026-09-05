package federatedoidc

import (
	"bytes"
	"context"
	"encoding/json"
	"mime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
)

// TokenBundle owns raw token bytes in memory. Call Destroy as soon as
// verification and optional UserInfo/upstream artifacts are complete.
type TokenBundle struct {
	state *tokenBundleState
}

// The indirection makes accidental TokenBundle value copies share one
// destruction state instead of copying a mutex and token-bearing slices.
type tokenBundleState struct {
	mu                    sync.Mutex
	owner                 *Flow
	transactionID         TransactionID
	materialID            identity.EntityID
	pins                  TransactionPins
	useUserInfo           bool
	postLogoutRedirectURI string
	idToken               []byte
	accessToken           []byte
	refreshToken          []byte
	tokenType             string
	scopes                []string
	accessExpiry          time.Time
	destroyed             bool
}

func (bundle *TokenBundle) HasAccessToken() bool {
	if bundle == nil || bundle.state == nil {
		return false
	}
	bundle.state.mu.Lock()
	defer bundle.state.mu.Unlock()
	return !bundle.state.destroyed && len(bundle.state.accessToken) != 0
}

func (bundle *TokenBundle) HasRefreshToken() bool {
	if bundle == nil || bundle.state == nil {
		return false
	}
	bundle.state.mu.Lock()
	defer bundle.state.mu.Unlock()
	return !bundle.state.destroyed && len(bundle.state.refreshToken) != 0
}

func (bundle *TokenBundle) AccessTokenExpiry() time.Time {
	if bundle == nil || bundle.state == nil {
		return time.Time{}
	}
	bundle.state.mu.Lock()
	defer bundle.state.mu.Unlock()
	return bundle.state.accessExpiry
}

func (bundle *TokenBundle) Scopes() []string {
	if bundle == nil || bundle.state == nil {
		return nil
	}
	bundle.state.mu.Lock()
	defer bundle.state.mu.Unlock()
	return append([]string(nil), bundle.state.scopes...)
}

func (bundle *TokenBundle) Destroy() {
	if bundle == nil || bundle.state == nil {
		return
	}
	bundle.state.mu.Lock()
	defer bundle.state.mu.Unlock()
	clear(bundle.state.idToken)
	clear(bundle.state.accessToken)
	clear(bundle.state.refreshToken)
	bundle.state.idToken = nil
	bundle.state.accessToken = nil
	bundle.state.refreshToken = nil
	bundle.state.scopes = nil
	bundle.state.tokenType = ""
	bundle.state.accessExpiry = time.Time{}
	bundle.state.transactionID = TransactionID{}
	bundle.state.materialID = identity.EntityID{}
	bundle.state.pins = TransactionPins{}
	bundle.state.owner = nil
	bundle.state.useUserInfo = false
	bundle.state.postLogoutRedirectURI = ""
	bundle.state.destroyed = true
}

func (bundle *TokenBundle) matchesConfiguration(flow *Flow, configuration AuthorizationConfiguration) bool {
	if flow == nil || bundle == nil || bundle.state == nil {
		return false
	}
	bundle.state.mu.Lock()
	defer bundle.state.mu.Unlock()
	return !bundle.state.destroyed && bundle.state.owner == flow &&
		bundle.state.pins == transactionPins(configuration) &&
		bundle.state.useUserInfo == configuration.UseUserInfo &&
		bundle.state.postLogoutRedirectURI == configuration.PostLogoutRedirectURI
}

func (bundle *TokenBundle) matchesTransaction(flow *Flow, id TransactionID) bool {
	if flow == nil || bundle == nil || bundle.state == nil || id == (TransactionID{}) {
		return false
	}
	bundle.state.mu.Lock()
	defer bundle.state.mu.Unlock()
	return !bundle.state.destroyed && bundle.state.owner == flow && bundle.state.transactionID == id
}

func (bundle *TokenBundle) material() (idToken, accessToken, refreshToken []byte, ok bool) {
	if bundle == nil || bundle.state == nil {
		return nil, nil, nil, false
	}
	bundle.state.mu.Lock()
	defer bundle.state.mu.Unlock()
	if bundle.state.destroyed || len(bundle.state.idToken) == 0 || len(bundle.state.accessToken) == 0 {
		return nil, nil, nil, false
	}
	return append([]byte(nil), bundle.state.idToken...),
		append([]byte(nil), bundle.state.accessToken...),
		append([]byte(nil), bundle.state.refreshToken...), true
}

func (flow *Flow) ExchangeCode(
	ctx context.Context,
	claimed *ClaimedAuthorization,
	credential ClientCredential,
) (*TokenBundle, error) {
	if flow == nil || claimed == nil || claimed.owner != flow || credential.Revision == 0 ||
		credential.Revision != claimed.record.Pins.ClientSecretRevision ||
		len(credential.Secret) == 0 || len(credential.Secret) > maximumClientSecretBytes ||
		!claimed.stage.CompareAndSwap(claimedStageReady, claimedStageExchanging) {
		return nil, ErrTokenExchangeFailed
	}
	now, ok := flow.currentTime()
	if !ok || !now.Before(claimed.record.ExpiresAt) {
		flow.exchangeFailed(ctx, claimed, now, FailureExpired)
		return nil, ErrTokenExchangeFailed
	}
	operationCtx, cancel, err := flow.operationContext(ctx)
	if err != nil {
		flow.exchangeFailed(ctx, claimed, now, FailureTokenExchange)
		return nil, ErrTokenExchangeFailed
	}
	defer cancel()
	protectionContext := TransactionProtectionContext{
		Authority:             claimed.record.Pins.Authority,
		TransactionID:         claimed.record.ID,
		Provider:              claimed.record.Pins.Provider,
		Admission:             claimed.record.Pins.Admission,
		BindingID:             claimed.record.Pins.BindingID,
		PlatformLoginRevision: claimed.record.Pins.PlatformLoginRevision,
	}
	verifier, openErr := flow.verifierProtector.OpenPKCE(
		operationCtx,
		protectionContext,
		cloneProtectedVerifier(claimed.record.Verifier),
	)
	if openErr != nil || !validPKCEVerifier(verifier) {
		clear(verifier)
		flow.exchangeFailed(operationCtx, claimed, now, FailureTokenExchange)
		return nil, ErrTokenExchangeFailed
	}
	defer clear(verifier)
	request := TokenExchangeRequest{
		Endpoint: newPinnedEndpoint(
			EndpointToken,
			claimed.configuration.Discovery.endpoints.Token,
			claimed.configuration.Discovery.targets.token,
		),
		GrantType:            GrantAuthorizationCode,
		ClientAuthentication: claimed.configuration.Discovery.clientAuthentication,
		ClientID:             claimed.record.ClientID,
		ClientSecret:         append([]byte(nil), credential.Secret...),
		AuthorizationCode:    append([]byte(nil), claimed.code...),
		RedirectURI:          claimed.record.RedirectURI,
		PKCEVerifier:         append([]byte(nil), verifier...),
	}
	defer request.destroy()
	if !validTokenExchangeRequest(request) {
		flow.exchangeFailed(operationCtx, claimed, now, FailureTokenExchange)
		return nil, ErrTokenExchangeFailed
	}
	response, exchangeErr := flow.tokenEndpoint.Exchange(operationCtx, request)
	defer clear(response.Body)
	if exchangeErr != nil || response.Category != TokenEndpointSuccess || response.StatusCode != 200 ||
		!validJSONMediaType(response.MediaType) || len(response.Body) == 0 ||
		len(response.Body) > flow.policy.Limits.MaxTokenResponseBytes {
		flow.exchangeFailed(operationCtx, claimed, now, FailureTokenExchange)
		return nil, ErrTokenExchangeFailed
	}
	bundle, parseErr := flow.parseTokenResponse(response.Body, claimed.record, now)
	if parseErr != nil {
		flow.exchangeFailed(operationCtx, claimed, now, FailureTokenValidation)
		return nil, ErrTokenResponseRejected
	}
	clear(claimed.code)
	claimed.code = nil
	clear(claimed.record.Verifier.Ciphertext)
	claimed.record.Verifier.Ciphertext = nil
	claimed.stage.Store(claimedStageExchanged)
	return bundle, nil
}

func (request *TokenExchangeRequest) destroy() {
	if request == nil {
		return
	}
	clear(request.ClientSecret)
	clear(request.AuthorizationCode)
	clear(request.PKCEVerifier)
	request.ClientSecret = nil
	request.AuthorizationCode = nil
	request.PKCEVerifier = nil
}

func validTokenExchangeRequest(request TokenExchangeRequest) bool {
	return request.Endpoint.validEndpoint(EndpointToken) &&
		request.GrantType == GrantAuthorizationCode &&
		validClientAuthentication(request.ClientAuthentication) && validClientID(request.ClientID) &&
		len(request.ClientSecret) > 0 && len(request.ClientSecret) <= maximumClientSecretBytes &&
		validAuthorizationCode(string(request.AuthorizationCode)) &&
		request.RedirectURI != "" && validPKCEVerifier(request.PKCEVerifier)
}

func validJSONMediaType(value string) bool {
	mediaType, parameters, err := mime.ParseMediaType(value)
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return false
	}
	for name, parameter := range parameters {
		if !strings.EqualFold(name, "charset") || !strings.EqualFold(parameter, "utf-8") {
			return false
		}
	}
	return true
}

func (flow *Flow) parseTokenResponse(
	document []byte,
	record ClaimedTransaction,
	now time.Time,
) (*TokenBundle, error) {
	if validateBoundedJSONObject(document, flow.policy.Limits.MaxTokenResponseBytes, flow.trust.limits) != nil {
		return nil, ErrTokenResponseRejected
	}
	object, err := decodeObject(document)
	if err != nil {
		return nil, ErrTokenResponseRejected
	}
	if _, ambiguousErrorResponse := object["error"]; ambiguousErrorResponse {
		return nil, ErrTokenResponseRejected
	}
	idToken, _, err := decodeStringMember(
		object, "id_token", true, flow.policy.Limits.MaxCompactTokenBytes,
	)
	if err != nil || !validTokenText(idToken, flow.policy.Limits.MaxCompactTokenBytes) {
		return nil, ErrTokenResponseRejected
	}
	accessToken, _, err := decodeStringMember(
		object, "access_token", true, flow.policy.Limits.MaxTokenValueBytes,
	)
	if err != nil || !validTokenText(accessToken, flow.policy.Limits.MaxTokenValueBytes) {
		return nil, ErrTokenResponseRejected
	}
	tokenType, _, err := decodeStringMember(object, "token_type", true, 32)
	if err != nil || !strings.EqualFold(tokenType, "Bearer") {
		return nil, ErrTokenResponseRejected
	}
	refreshToken, refreshPresent, err := decodeStringMember(
		object, "refresh_token", false, flow.policy.Limits.MaxTokenValueBytes,
	)
	if err != nil || refreshPresent != record.AllowRefreshToken || refreshPresent &&
		!validTokenText(refreshToken, flow.policy.Limits.MaxTokenValueBytes) {
		return nil, ErrTokenResponseRejected
	}
	expiresIn, expiresPresent, err := decodePositiveIntegerMember(object, "expires_in")
	if err != nil || !expiresPresent || expiresIn > int64(flow.policy.MaxTokenLifetime/time.Second) {
		return nil, ErrTokenResponseRejected
	}
	returnedScope, scopePresent, err := decodeStringMember(
		object, "scope", false, maximumScopeCount*maximumScopeBytes,
	)
	if err != nil {
		return nil, ErrTokenResponseRejected
	}
	scopes := append([]string(nil), record.Scopes...)
	if scopePresent {
		scopes, err = validateReturnedScopes(returnedScope, record.Scopes)
		if err != nil {
			return nil, ErrTokenResponseRejected
		}
	}
	accessExpiry := time.Time{}
	if expiresPresent {
		accessExpiry = now.Add(time.Duration(expiresIn) * time.Second)
	}
	return &TokenBundle{state: &tokenBundleState{
		owner: flow, transactionID: record.ID, materialID: record.MaterialID, pins: record.Pins,
		useUserInfo: record.UseUserInfo, postLogoutRedirectURI: record.PostLogoutRedirectURI,
		idToken: append([]byte(nil), idToken...), accessToken: append([]byte(nil), accessToken...),
		refreshToken: append([]byte(nil), refreshToken...), tokenType: "Bearer",
		scopes: scopes, accessExpiry: accessExpiry,
	}}, nil
}

func decodePositiveIntegerMember(
	object map[string]json.RawMessage,
	name string,
) (int64, bool, error) {
	raw, present := object[name]
	if !present {
		return 0, false, nil
	}
	trimmed := bytes.TrimSpace(raw)
	value, err := strconv.ParseInt(string(trimmed), 10, 64)
	if err != nil || value <= 0 || strconv.FormatInt(value, 10) != string(trimmed) {
		return 0, false, ErrTokenResponseRejected
	}
	return value, true, nil
}

func validTokenText(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validTokenBytes(value []byte, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func validateReturnedScopes(returned string, requested []string) ([]string, error) {
	parts := strings.Split(returned, " ")
	if len(parts) == 0 || len(parts) > maximumScopeCount || strings.Join(parts, " ") != returned {
		return nil, ErrTokenResponseRejected
	}
	requestedSet := make(map[string]struct{}, len(requested))
	for _, scope := range requested {
		requestedSet[scope] = struct{}{}
	}
	seen := make(map[string]struct{}, len(parts))
	for _, scope := range parts {
		if !validScope(scope) {
			return nil, ErrTokenResponseRejected
		}
		if _, allowed := requestedSet[scope]; !allowed {
			return nil, ErrTokenResponseRejected
		}
		if _, duplicate := seen[scope]; duplicate {
			return nil, ErrTokenResponseRejected
		}
		seen[scope] = struct{}{}
	}
	if _, openID := seen[RequiredScopeOpenID]; !openID {
		return nil, ErrTokenResponseRejected
	}
	slices.Sort(parts)
	return parts, nil
}

func (flow *Flow) exchangeFailed(
	ctx context.Context,
	claimed *ClaimedAuthorization,
	now time.Time,
	reason TransactionFailureReason,
) {
	if claimed == nil {
		return
	}
	claimed.stage.Store(claimedStageFailed)
	clear(claimed.code)
	claimed.code = nil
	clear(claimed.record.Verifier.Ciphertext)
	claimed.record.Verifier.Ciphertext = nil
	state := TransactionFailed
	if reason == FailureExpired {
		state = TransactionExpired
	}
	flow.failTransaction(ctx, claimed.record, claimed.audit, now, reason, state)
}
