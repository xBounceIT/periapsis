package federatedoidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
)

const (
	minimumUserInfoBytes = 256
	maximumUserInfoBytes = 256 * 1024
)

var (
	ErrInvalidUpstreamOptions = errors.New("invalid OIDC upstream options")
	ErrUserInfoRejected       = errors.New("OIDC UserInfo rejected")
	ErrRefreshRejected        = errors.New("OIDC refresh rejected")
	ErrRefreshSafeToRetry     = errors.New("OIDC refresh failed before dispatch")
	ErrRefreshAmbiguous       = errors.New("OIDC refresh outcome is ambiguous")
	ErrRevocationFailed       = errors.New("OIDC revocation failed")
	ErrRevocationSafeToRetry  = errors.New("OIDC revocation failed before dispatch")
	ErrRevocationAmbiguous    = errors.New("OIDC revocation outcome is ambiguous")
)

// UpstreamOptions freezes the concrete credential-bearing transport and
// attacker-controlled UserInfo/refresh response ceilings.
type UpstreamOptions struct {
	HTTP             *federatedhttp.Client
	JSONLimits       Limits
	MaxUserInfoBytes int
	MaxRefreshBytes  int
}

// UpstreamHTTP is the real OIDC token, UserInfo, refresh, and revocation
// adapter. It never invokes oauth2.Config.Exchange or an ambient http.Client.
type UpstreamHTTP struct {
	http             *federatedhttp.Client
	jsonLimits       Limits
	maxUserInfoBytes int
	maxRefreshBytes  int
}

func NewUpstreamHTTP(options UpstreamOptions) (*UpstreamHTTP, error) {
	if options.JSONLimits == (Limits{}) {
		options.JSONLimits = DefaultLimits()
	}
	if options.HTTP == nil || !validLimits(options.JSONLimits) ||
		options.MaxUserInfoBytes < minimumUserInfoBytes || options.MaxUserInfoBytes > maximumUserInfoBytes ||
		options.MaxRefreshBytes < minimumTokenResponseBytes || options.MaxRefreshBytes > maximumTokenResponseBytes {
		return nil, ErrInvalidUpstreamOptions
	}
	return &UpstreamHTTP{
		http: options.HTTP, jsonLimits: options.JSONLimits,
		maxUserInfoBytes: options.MaxUserInfoBytes, maxRefreshBytes: options.MaxRefreshBytes,
	}, nil
}

// Exchange implements TokenEndpointPort with exact client-secret placement.
func (adapter *UpstreamHTTP) Exchange(ctx context.Context, request TokenExchangeRequest) (TokenEndpointResponse, error) {
	defer clear(request.ClientSecret)
	defer clear(request.AuthorizationCode)
	defer clear(request.PKCEVerifier)
	if adapter == nil || adapter.http == nil || !validTokenExchangeRequest(request) {
		return TokenEndpointResponse{}, ErrTokenExchangeFailed
	}
	form := encodeForm([]formField{
		{name: "grant_type", value: []byte(request.GrantType)},
		{name: "code", value: request.AuthorizationCode},
		{name: "redirect_uri", value: []byte(request.RedirectURI)},
		{name: "code_verifier", value: request.PKCEVerifier},
	}, request.ClientAuthentication, request.ClientID, request.ClientSecret)
	defer clear(form.body)
	defer clear(form.authorization)
	result, err := adapter.http.Execute(ctx, federatedhttp.OperationRequest{
		Kind: federatedhttp.OperationOIDCToken, Target: request.Endpoint.Target(),
		Authorization: append([]byte(nil), form.authorization...), Body: append([]byte(nil), form.body...),
		MaxResponseBytes: int64(adapter.maxRefreshBytes),
	})
	defer clear(result.Body)
	if err != nil {
		return TokenEndpointResponse{Category: TokenEndpointUnavailable}, nil
	}
	return tokenEndpointResponse(result), nil
}

// UserInfoDocument retains a duplicate-safe bounded JSON object. It formats
// only a redacted shape summary.
type UserInfoDocument struct {
	subject string
	claims  map[string]json.RawMessage
	valid   bool
}

func (document UserInfoDocument) Subject() string { return document.subject }
func (document UserInfoDocument) String() string {
	return fmt.Sprintf("federatedoidc.UserInfoDocument{claims:%d,material:[REDACTED]}", len(document.claims))
}
func (document UserInfoDocument) GoString() string { return document.String() }

// FetchUserInfo consumes request and validates a bounded duplicate-safe JSON
// object with an exact expected subject.
func (adapter *UpstreamHTTP) FetchUserInfo(
	ctx context.Context,
	request *UserInfoRequest,
	expectedSubject string,
) (UserInfoDocument, error) {
	if request != nil {
		defer request.Destroy()
	}
	if adapter == nil || adapter.http == nil || request == nil || !request.valid ||
		!request.endpoint.validEndpoint(EndpointUserInfo) ||
		!validClaimValue(expectedSubject, maximumSubjectBytes) {
		return UserInfoDocument{}, ErrUserInfoRejected
	}
	token := request.AccessToken()
	defer clear(token)
	authorization := append([]byte("Bearer "), token...)
	result, err := adapter.http.Execute(ctx, federatedhttp.OperationRequest{
		Kind: federatedhttp.OperationOIDCUserInfo, Target: request.endpoint.Target(),
		Authorization: authorization, MaxResponseBytes: int64(adapter.maxUserInfoBytes),
	})
	defer clear(result.Body)
	if err != nil || result.Category != federatedhttp.CategorySuccess || result.StatusCode != 200 ||
		!validJSONMediaType(result.MediaType) ||
		validateBoundedJSONObject(result.Body, adapter.maxUserInfoBytes, adapter.jsonLimits) != nil {
		return UserInfoDocument{}, ErrUserInfoRejected
	}
	object, err := decodeObject(result.Body)
	if err != nil {
		return UserInfoDocument{}, ErrUserInfoRejected
	}
	subject, _, err := decodeStringMember(object, "sub", true, maximumSubjectBytes)
	if err != nil || subject != expectedSubject || !validClaimValue(subject, maximumSubjectBytes) {
		return UserInfoDocument{}, ErrUserInfoRejected
	}
	return UserInfoDocument{subject: subject, claims: cloneRawObject(object), valid: true}, nil
}

// MergeUserInfo adds only configured non-security claims that were absent in
// the ID token result. UserInfo cannot replace subject, assurance, ACR/AMR, or any
// existing profile/group projection.
func (flow *Flow) MergeUserInfo(
	proof VerifiedAuthentication,
	document UserInfoDocument,
	policy ClaimExtractionPolicy,
) (VerifiedAuthentication, error) {
	if flow == nil || !proof.valid || !document.valid || document.subject != proof.subject ||
		policy.ACR != nil || policy.AMR != nil {
		return VerifiedAuthentication{}, ErrUserInfoRejected
	}
	extracted, err := flow.extractClaims(document.claims, policy)
	if err != nil || claimSetsOverlap(proof.claims, extracted) {
		return VerifiedAuthentication{}, ErrUserInfoRejected
	}
	result := proof
	result.audience = append([]string(nil), proof.audience...)
	result.claims = proof.Claims()
	result.claims.scalars = append(result.claims.scalars, extracted.scalars...)
	result.claims.profiles = append(result.claims.profiles, extracted.profiles...)
	result.claims.groups = append(result.claims.groups, extracted.groups...)
	slices.SortFunc(result.claims.scalars, func(left, right NamedScalar) int { return strings.Compare(left.Name, right.Name) })
	slices.SortFunc(result.claims.profiles, func(left, right ProfileValue) int {
		return strings.Compare(string(left.Field), string(right.Field))
	})
	slices.Sort(result.claims.groups)
	return result, nil
}

// RefreshExchangeRequest is a one-use rotation request. Secret and token
// slices are consumed by Refresh and never formatted.
type RefreshExchangeRequest struct {
	Endpoint             PinnedEndpoint
	ClientAuthentication ClientAuthenticationMode
	ClientID             string
	ClientSecret         []byte `json:"-"`
	RefreshToken         []byte `json:"-"`
}

func (request RefreshExchangeRequest) String() string {
	return "federatedoidc.RefreshExchangeRequest{material:[REDACTED]}"
}
func (request RefreshExchangeRequest) GoString() string { return request.String() }

// StoredRefreshExchangeRequest carries one endpoint URL pinned into encrypted
// session provenance. RefreshStored recompiles it through the deployment-owned
// egress policy immediately before dispatch.
type StoredRefreshExchangeRequest struct {
	EndpointURL          string `json:"-"`
	ClientAuthentication ClientAuthenticationMode
	ClientID             string
	ClientSecret         []byte `json:"-"`
	RefreshToken         []byte `json:"-"`
}

func (request StoredRefreshExchangeRequest) String() string {
	return "federatedoidc.StoredRefreshExchangeRequest{material:[REDACTED]}"
}
func (request StoredRefreshExchangeRequest) GoString() string { return request.String() }

// RefreshedTokens owns rotated tokens. Destroy clears all material.
type RefreshedTokens struct {
	accessToken  []byte
	refreshToken []byte
	idToken      []byte
	expiresAt    time.Time
}

func (tokens *RefreshedTokens) AccessToken() []byte {
	if tokens == nil {
		return nil
	}
	return append([]byte(nil), tokens.accessToken...)
}
func (tokens *RefreshedTokens) RefreshToken() []byte {
	if tokens == nil {
		return nil
	}
	return append([]byte(nil), tokens.refreshToken...)
}
func (tokens *RefreshedTokens) IDToken() []byte {
	if tokens == nil {
		return nil
	}
	return append([]byte(nil), tokens.idToken...)
}
func (tokens *RefreshedTokens) ExpiresAt() time.Time {
	if tokens == nil {
		return time.Time{}
	}
	return tokens.expiresAt
}
func (tokens *RefreshedTokens) Destroy() {
	if tokens == nil {
		return
	}
	clear(tokens.accessToken)
	clear(tokens.refreshToken)
	clear(tokens.idToken)
	tokens.accessToken, tokens.refreshToken, tokens.idToken = nil, nil, nil
	tokens.expiresAt = time.Time{}
}
func (tokens RefreshedTokens) String() string {
	return "federatedoidc.RefreshedTokens{material:[REDACTED]}"
}
func (tokens RefreshedTokens) GoString() string { return tokens.String() }

// Refresh performs a mandatory rotating refresh. A response which omits the
// successor token or returns the presented token byte-for-byte is rejected.
func (adapter *UpstreamHTTP) Refresh(
	ctx context.Context,
	request RefreshExchangeRequest,
	now time.Time,
) (*RefreshedTokens, error) {
	defer clear(request.ClientSecret)
	defer clear(request.RefreshToken)
	if adapter == nil || adapter.http == nil || !request.Endpoint.validEndpoint(EndpointToken) ||
		!validClientAuthentication(request.ClientAuthentication) || !validClientID(request.ClientID) ||
		len(request.ClientSecret) == 0 || len(request.ClientSecret) > maximumClientSecretBytes ||
		!validTokenBytes(request.RefreshToken, maximumTokenValueBytes) || !validUpstreamInstant(now) {
		return nil, ErrRefreshRejected
	}
	form := encodeForm([]formField{
		{name: "grant_type", value: []byte("refresh_token")},
		{name: "refresh_token", value: request.RefreshToken},
	}, request.ClientAuthentication, request.ClientID, request.ClientSecret)
	defer clear(form.body)
	defer clear(form.authorization)
	result, err := adapter.http.Execute(ctx, federatedhttp.OperationRequest{
		Kind: federatedhttp.OperationOIDCToken, Target: request.Endpoint.Target(),
		Authorization: append([]byte(nil), form.authorization...), Body: append([]byte(nil), form.body...),
		MaxResponseBytes: int64(adapter.maxRefreshBytes),
	})
	defer clear(result.Body)
	if err != nil || result.Category != federatedhttp.CategorySuccess || result.StatusCode != 200 ||
		!validJSONMediaType(result.MediaType) {
		return nil, refreshExecutionError(result, err)
	}
	tokens, err := adapter.parseRefreshedTokens(result.Body, request.RefreshToken, now)
	if err != nil {
		return nil, errors.Join(ErrRefreshRejected, ErrRefreshAmbiguous)
	}
	return tokens, nil
}

func (adapter *UpstreamHTTP) RefreshStored(
	ctx context.Context,
	request StoredRefreshExchangeRequest,
	now time.Time,
) (*RefreshedTokens, error) {
	defer clear(request.ClientSecret)
	defer clear(request.RefreshToken)
	if adapter == nil || adapter.http == nil || request.EndpointURL == "" {
		return nil, ErrRefreshRejected
	}
	target, err := adapter.http.CompileTarget(federatedhttp.DocumentOIDCDiscovery, request.EndpointURL)
	if err != nil {
		return nil, ErrRefreshRejected
	}
	endpoint := newPinnedEndpoint(EndpointToken, request.EndpointURL, target)
	if !endpoint.validEndpoint(EndpointToken) {
		return nil, ErrRefreshRejected
	}
	return adapter.Refresh(ctx, RefreshExchangeRequest{
		Endpoint: endpoint, ClientAuthentication: request.ClientAuthentication,
		ClientID: request.ClientID, ClientSecret: append([]byte(nil), request.ClientSecret...),
		RefreshToken: append([]byte(nil), request.RefreshToken...),
	}, now)
}

func refreshExecutionError(result federatedhttp.OperationResult, err error) error {
	if credentialRequestSafeToRetry(result, err) {
		return errors.Join(ErrRefreshRejected, ErrRefreshSafeToRetry)
	}
	return errors.Join(ErrRefreshRejected, ErrRefreshAmbiguous)
}

func credentialRequestSafeToRetry(result federatedhttp.OperationResult, err error) bool {
	return errors.Is(err, federatedhttp.ErrBusy) || result.RequestNotDispatched
}

func (adapter *UpstreamHTTP) parseRefreshedTokens(
	document []byte,
	presented []byte,
	now time.Time,
) (*RefreshedTokens, error) {
	if adapter == nil || validateBoundedJSONObject(document, adapter.maxRefreshBytes, adapter.jsonLimits) != nil ||
		!validTokenBytes(presented, maximumTokenValueBytes) || !validUpstreamInstant(now) {
		return nil, ErrRefreshRejected
	}
	object, err := decodeObject(document)
	if err != nil {
		return nil, ErrRefreshRejected
	}
	access, _, accessErr := decodeStringMember(object, "access_token", true, maximumTokenValueBytes)
	refresh, _, refreshErr := decodeStringMember(object, "refresh_token", true, maximumTokenValueBytes)
	tokenType, _, typeErr := decodeStringMember(object, "token_type", true, 32)
	idToken, _, idErr := decodeStringMember(object, "id_token", false, maximumCompactTokenBytes)
	expires, present, expiresErr := decodePositiveIntegerMember(object, "expires_in")
	if accessErr != nil || refreshErr != nil || typeErr != nil || idErr != nil || expiresErr != nil || !present ||
		!strings.EqualFold(tokenType, "Bearer") || !validTokenText(access, maximumTokenValueBytes) ||
		!validTokenText(refresh, maximumTokenValueBytes) || sameStringAndBytes(refresh, presented) ||
		expires > int64((24*time.Hour)/time.Second) || idToken != "" && !validTokenText(idToken, maximumCompactTokenBytes) {
		return nil, ErrRefreshRejected
	}
	return &RefreshedTokens{
		accessToken: []byte(access), refreshToken: []byte(refresh), idToken: []byte(idToken),
		expiresAt: now.UTC().Add(time.Duration(expires) * time.Second),
	}, nil
}

// Revoke consumes one local-logout-gated revocation artifact.
func (adapter *UpstreamHTTP) Revoke(ctx context.Context, request *RevocationRequest) error {
	if request != nil {
		defer request.Destroy()
	}
	if adapter == nil || adapter.http == nil || request == nil || !request.valid ||
		!request.endpoint.validEndpoint(EndpointRevocation) || !validClientAuthentication(request.clientAuthentication) ||
		!validClientID(request.clientID) || !validTokenBytes(request.token, maximumTokenValueBytes) {
		return ErrRevocationFailed
	}
	form := encodeForm([]formField{
		{name: "token", value: request.token},
		{name: "token_type_hint", value: []byte(request.tokenKind)},
	}, request.clientAuthentication, request.clientID, request.clientSecret)
	defer clear(form.body)
	defer clear(form.authorization)
	result, err := adapter.http.Execute(ctx, federatedhttp.OperationRequest{
		Kind: federatedhttp.OperationOIDCRevocation, Target: request.endpoint.Target(),
		Authorization: append([]byte(nil), form.authorization...), Body: append([]byte(nil), form.body...),
		MaxResponseBytes: 4096,
	})
	if err != nil || result.Category != federatedhttp.CategorySuccess ||
		result.StatusCode != 200 && result.StatusCode != 204 {
		return ErrRevocationFailed
	}
	return nil
}

// StoredRevocationMaterial is reconstructed only from a claimed retry job
// whose local session revocation already committed. It is intentionally
// separate from the interactive LocalLogoutConfirmation artifact.
type StoredRevocationMaterial struct {
	EndpointURL          string `json:"-"`
	TokenKind            TokenKind
	Token                []byte `json:"-"`
	ClientAuthentication ClientAuthenticationMode
	ClientID             string
	ClientSecret         []byte `json:"-"`
}

func (material StoredRevocationMaterial) String() string {
	return "federatedoidc.StoredRevocationMaterial{material:[REDACTED]}"
}
func (material StoredRevocationMaterial) GoString() string { return material.String() }

// RevokeStored consumes material opened from one already-claimed bounded
// retry job. The job repository is the proof that local revocation preceded
// this best-effort upstream call.
func (adapter *UpstreamHTTP) RevokeStored(ctx context.Context, material StoredRevocationMaterial) error {
	defer clear(material.Token)
	defer clear(material.ClientSecret)
	if adapter == nil || adapter.http == nil || material.EndpointURL == "" ||
		(material.TokenKind != TokenAccess && material.TokenKind != TokenRefresh) ||
		!validTokenBytes(material.Token, maximumTokenValueBytes) ||
		!validClientAuthentication(material.ClientAuthentication) || !validClientID(material.ClientID) ||
		len(material.ClientSecret) == 0 || len(material.ClientSecret) > maximumClientSecretBytes {
		return ErrRevocationFailed
	}
	target, err := adapter.http.CompileTarget(federatedhttp.DocumentOIDCDiscovery, material.EndpointURL)
	if err != nil {
		return ErrRevocationFailed
	}
	endpoint := newPinnedEndpoint(EndpointRevocation, material.EndpointURL, target)
	if !endpoint.validEndpoint(EndpointRevocation) {
		return ErrRevocationFailed
	}
	form := encodeForm([]formField{
		{name: "token", value: material.Token},
		{name: "token_type_hint", value: []byte(material.TokenKind)},
	}, material.ClientAuthentication, material.ClientID, material.ClientSecret)
	defer clear(form.body)
	defer clear(form.authorization)
	result, err := adapter.http.Execute(ctx, federatedhttp.OperationRequest{
		Kind: federatedhttp.OperationOIDCRevocation, Target: endpoint.Target(),
		Authorization: append([]byte(nil), form.authorization...), Body: append([]byte(nil), form.body...),
		MaxResponseBytes: 4096,
	})
	if err != nil || result.Category != federatedhttp.CategorySuccess ||
		result.StatusCode != 200 && result.StatusCode != 204 {
		if credentialRequestSafeToRetry(result, err) {
			return errors.Join(ErrRevocationFailed, ErrRevocationSafeToRetry)
		}
		return errors.Join(ErrRevocationFailed, ErrRevocationAmbiguous)
	}
	return nil
}

type formField struct {
	name  string
	value []byte
}

type encodedForm struct {
	body          []byte
	authorization []byte
}

func encodeForm(fields []formField, mode ClientAuthenticationMode, clientID string, secret []byte) encodedForm {
	ordered := append([]formField(nil), fields...)
	defer func() { clear(ordered) }()
	if mode == ClientSecretPost {
		ordered = append(ordered,
			formField{name: "client_id", value: []byte(clientID)},
			formField{name: "client_secret", value: secret},
		)
	}
	slices.SortFunc(ordered, func(left, right formField) int { return strings.Compare(left.name, right.name) })
	body := make([]byte, 0, 256)
	for index, field := range ordered {
		if index != 0 {
			body = append(body, '&')
		}
		body = appendFormEscape(body, []byte(field.name))
		body = append(body, '=')
		body = appendFormEscape(body, field.value)
	}
	result := encodedForm{body: body}
	if mode == ClientSecretBasic {
		credential := appendFormEscape(nil, []byte(clientID))
		credential = append(credential, ':')
		credential = appendFormEscape(credential, secret)
		result.authorization = make([]byte, len("Basic ")+base64.StdEncoding.EncodedLen(len(credential)))
		copy(result.authorization, "Basic ")
		base64.StdEncoding.Encode(result.authorization[len("Basic "):], credential)
		clear(credential)
	}
	return result
}

func appendFormEscape(destination, source []byte) []byte {
	const hexadecimal = "0123456789ABCDEF"
	for _, character := range source {
		switch {
		case character >= 'a' && character <= 'z', character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9', character == '-', character == '_', character == '.', character == '~':
			destination = append(destination, character)
		case character == ' ':
			destination = append(destination, '+')
		default:
			destination = append(destination, '%', hexadecimal[character>>4], hexadecimal[character&0x0f])
		}
	}
	return destination
}

func tokenEndpointResponse(result federatedhttp.OperationResult) TokenEndpointResponse {
	response := TokenEndpointResponse{StatusCode: result.StatusCode, MediaType: result.MediaType}
	switch result.Category {
	case federatedhttp.CategorySuccess:
		response.Category = TokenEndpointSuccess
		response.Body = append([]byte(nil), result.Body...)
	case federatedhttp.CategoryHTTPStatusRejected:
		response.Category = TokenEndpointRejected
	case federatedhttp.CategoryLimitExceeded:
		response.Category = TokenEndpointLimited
	case federatedhttp.CategoryCancelled, federatedhttp.CategoryOperationTimeout:
		response.Category = TokenEndpointCancelled
	default:
		response.Category = TokenEndpointUnavailable
	}
	return response
}

func cloneRawObject(source map[string]json.RawMessage) map[string]json.RawMessage {
	result := make(map[string]json.RawMessage, len(source))
	for key, value := range source {
		result[key] = append(json.RawMessage(nil), value...)
	}
	return result
}

func claimSetsOverlap(left, right ClaimSet) bool {
	for _, candidate := range right.scalars {
		if _, found := left.Scalar(candidate.Name); found {
			return true
		}
	}
	for _, candidate := range right.profiles {
		if _, found := left.Profile(candidate.Field); found {
			return true
		}
	}
	return len(left.groups) != 0 && len(right.groups) != 0
}

func sameStringAndBytes(left string, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validUpstreamInstant(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Nanosecond()%1_000 == 0
}
