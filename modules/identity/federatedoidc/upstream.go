package federatedoidc

import (
	"net/url"
	"time"
)

type TokenKind string

const (
	TokenAccess  TokenKind = "access_token"
	TokenRefresh TokenKind = "refresh_token"
)

// LocalLogoutConfirmation is implemented by the later session use case only
// after local revocation commits. It prevents an upstream best-effort action
// from being constructed as a substitute for local logout.
type LocalLogoutConfirmation interface {
	OIDCTransactionID() TransactionID
	OIDCTransactionPins() TransactionPins
	LocalSessionRevokedAt() time.Time
}

// UserInfoRequest is a one-use bearer artifact for the pinned UserInfo endpoint.
type UserInfoRequest struct {
	endpoint    PinnedEndpoint
	accessToken []byte
	valid       bool
}

func (request *UserInfoRequest) Endpoint() PinnedEndpoint {
	if request == nil {
		return PinnedEndpoint{}
	}
	return request.endpoint
}
func (request *UserInfoRequest) AccessToken() []byte {
	if request == nil {
		return nil
	}
	return append([]byte(nil), request.accessToken...)
}
func (request *UserInfoRequest) Destroy() {
	if request == nil {
		return
	}
	clear(request.accessToken)
	request.accessToken = nil
	request.valid = false
}

// RevocationRequest is a one-use semantic POST artifact. The future transport
// must encode client authentication exactly as configured and never redirect.
type RevocationRequest struct {
	endpoint             PinnedEndpoint
	tokenKind            TokenKind
	token                []byte
	clientAuthentication ClientAuthenticationMode
	clientID             string
	clientSecret         []byte
	valid                bool
}

func (request *RevocationRequest) Endpoint() PinnedEndpoint {
	if request == nil {
		return PinnedEndpoint{}
	}
	return request.endpoint
}
func (request *RevocationRequest) TokenKind() TokenKind {
	if request == nil {
		return ""
	}
	return request.tokenKind
}
func (request *RevocationRequest) Token() []byte {
	if request == nil {
		return nil
	}
	return append([]byte(nil), request.token...)
}
func (request *RevocationRequest) ClientAuthentication() ClientAuthenticationMode {
	if request == nil {
		return ""
	}
	return request.clientAuthentication
}
func (request *RevocationRequest) ClientID() string {
	if request == nil {
		return ""
	}
	return request.clientID
}
func (request *RevocationRequest) ClientSecret() []byte {
	if request == nil {
		return nil
	}
	return append([]byte(nil), request.clientSecret...)
}
func (request *RevocationRequest) Destroy() {
	if request == nil {
		return
	}
	clear(request.token)
	clear(request.clientSecret)
	request.token = nil
	request.clientSecret = nil
	request.valid = false
}

// EndSessionRequest is a browser-delivery RP-initiated logout artifact.
type EndSessionRequest struct {
	endpoint              PinnedEndpoint
	idTokenHint           []byte
	postLogoutRedirectURI string
	state                 []byte
	createdAt             time.Time
	valid                 bool
	redirectURL           string
}

func (request *EndSessionRequest) Endpoint() PinnedEndpoint {
	if request == nil {
		return PinnedEndpoint{}
	}
	return request.endpoint
}
func (request *EndSessionRequest) IDTokenHint() []byte {
	if request == nil {
		return nil
	}
	return append([]byte(nil), request.idTokenHint...)
}
func (request *EndSessionRequest) PostLogoutRedirectURI() string {
	if request == nil {
		return ""
	}
	return request.postLogoutRedirectURI
}
func (request *EndSessionRequest) State() []byte {
	if request == nil {
		return nil
	}
	return append([]byte(nil), request.state...)
}
func (request *EndSessionRequest) CreatedAt() time.Time {
	if request == nil {
		return time.Time{}
	}
	return request.createdAt
}
func (request *EndSessionRequest) RedirectURL() string {
	if request == nil || !request.valid {
		return ""
	}
	if request.redirectURL != "" {
		return request.redirectURL
	}
	parsed, err := url.Parse(request.endpoint.URL())
	if err != nil {
		return ""
	}
	query := parsed.Query()
	query.Set("id_token_hint", string(request.idTokenHint))
	query.Set("post_logout_redirect_uri", request.postLogoutRedirectURI)
	query.Set("state", string(request.state))
	parsed.RawQuery = query.Encode()
	value := parsed.String()
	if len(value) > maximumAuthorizationURLBytes {
		return ""
	}
	return value
}
func (request *EndSessionRequest) Destroy() {
	if request == nil {
		return
	}
	clear(request.idTokenHint)
	clear(request.state)
	request.idTokenHint = nil
	request.state = nil
	request.redirectURL = ""
	request.valid = false
}

func (flow *Flow) BuildUserInfoRequest(
	configuration AuthorizationConfiguration,
	bundle *TokenBundle,
) (*UserInfoRequest, error) {
	configuration, _, err := flow.normalizeConfiguration(configuration)
	if err != nil || !configuration.UseUserInfo || configuration.Discovery.endpoints.UserInfo == "" ||
		!bundle.matchesConfiguration(flow, configuration) {
		return nil, ErrUpstreamArtifactRejected
	}
	idToken, accessToken, refreshToken, ok := bundle.material()
	clear(idToken)
	clear(refreshToken)
	if !ok {
		clear(accessToken)
		return nil, ErrUpstreamArtifactRejected
	}
	return &UserInfoRequest{
		endpoint: newPinnedEndpoint(
			EndpointUserInfo,
			configuration.Discovery.endpoints.UserInfo,
			configuration.Discovery.targets.userinfo,
		),
		accessToken: accessToken,
		valid:       true,
	}, nil
}

func (flow *Flow) BuildRevocationRequest(
	configuration AuthorizationConfiguration,
	bundle *TokenBundle,
	credential ClientCredential,
	tokenKind TokenKind,
	confirmation LocalLogoutConfirmation,
) (*RevocationRequest, error) {
	configuration, _, err := flow.normalizeConfiguration(configuration)
	if err != nil || configuration.Discovery.endpoints.Revocation == "" ||
		credential.Revision != configuration.ClientSecretRevision ||
		len(credential.Secret) == 0 || len(credential.Secret) > maximumClientSecretBytes ||
		!bundle.matchesConfiguration(flow, configuration) ||
		!flow.confirmedLocalLogout(bundle, confirmation) {
		return nil, ErrUpstreamArtifactRejected
	}
	idToken, accessToken, refreshToken, ok := bundle.material()
	clear(idToken)
	if !ok {
		clear(accessToken)
		clear(refreshToken)
		return nil, ErrUpstreamArtifactRejected
	}
	token := accessToken
	clearOther := refreshToken
	if tokenKind == TokenRefresh {
		token = refreshToken
		clearOther = accessToken
	} else if tokenKind != TokenAccess {
		clear(accessToken)
		clear(refreshToken)
		return nil, ErrUpstreamArtifactRejected
	}
	clear(clearOther)
	if len(token) == 0 {
		clear(token)
		return nil, ErrUpstreamArtifactRejected
	}
	return &RevocationRequest{
		endpoint: newPinnedEndpoint(
			EndpointRevocation,
			configuration.Discovery.endpoints.Revocation,
			configuration.Discovery.targets.revocation,
		),
		tokenKind: tokenKind, token: token,
		clientAuthentication: configuration.Discovery.clientAuthentication,
		clientID:             configuration.ClientID, clientSecret: append([]byte(nil), credential.Secret...),
		valid: true,
	}, nil
}

func (flow *Flow) BuildEndSessionRequest(
	configuration AuthorizationConfiguration,
	bundle *TokenBundle,
	confirmation LocalLogoutConfirmation,
) (*EndSessionRequest, error) {
	configuration, _, err := flow.normalizeConfiguration(configuration)
	if err != nil || configuration.Discovery.endpoints.EndSession == "" ||
		!bundle.matchesConfiguration(flow, configuration) ||
		!flow.confirmedLocalLogout(bundle, confirmation) {
		return nil, ErrUpstreamArtifactRejected
	}
	idToken, accessToken, refreshToken, ok := bundle.material()
	clear(accessToken)
	clear(refreshToken)
	if !ok {
		clear(idToken)
		return nil, ErrUpstreamArtifactRejected
	}
	state, randomErr := generateOpaque(flow.random)
	if randomErr != nil {
		clear(idToken)
		return nil, ErrUpstreamArtifactRejected
	}
	now, validNow := flow.currentTime()
	if !validNow {
		clear(idToken)
		clear(state)
		return nil, ErrUpstreamArtifactRejected
	}
	return &EndSessionRequest{
		endpoint: newPinnedEndpoint(
			EndpointEndSession,
			configuration.Discovery.endpoints.EndSession,
			configuration.Discovery.targets.endSession,
		),
		idTokenHint: idToken, postLogoutRedirectURI: configuration.PostLogoutRedirectURI,
		state: state, createdAt: now, valid: true,
	}, nil
}

func (flow *Flow) confirmedLocalLogout(
	bundle *TokenBundle,
	confirmation LocalLogoutConfirmation,
) bool {
	if flow == nil || confirmation == nil || bundle == nil || bundle.state == nil {
		return false
	}
	revokedAt := confirmation.LocalSessionRevokedAt()
	now, ok := flow.currentTime()
	if !ok || !validFlowInstant(revokedAt) || revokedAt.After(now) {
		return false
	}
	transactionID := confirmation.OIDCTransactionID()
	pins := confirmation.OIDCTransactionPins()
	bundle.state.mu.Lock()
	defer bundle.state.mu.Unlock()
	return !bundle.state.destroyed && bundle.state.transactionID != (TransactionID{}) &&
		bundle.state.transactionID == transactionID && bundle.state.pins == pins
}
