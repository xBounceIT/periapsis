package federatedoidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
)

var flowTestNow = time.Date(2026, time.August, 25, 10, 35, 0, 0, time.UTC)

func testAuthorizationBegin(markers ...byte) AuthorizationBegin {
	marker := byte(1)
	if len(markers) == 1 && markers[0] != 0 {
		marker = markers[0]
	}
	begin := AuthorizationBegin{}
	begin.OperationRunID[6] = 0x70
	begin.OperationRunID[8] = 0x80
	begin.OperationRunID[15] = marker
	begin.ReceiptDigest[0], begin.ReceiptDigest[31] = 1, marker
	begin.NetworkDigest[0], begin.NetworkDigest[31] = 2, marker
	begin.AccountDigest[0], begin.AccountDigest[31] = 3, marker
	begin.ProviderDigest[0], begin.ProviderDigest[31] = 4, marker
	return begin
}

type deterministicFlowReader struct {
	mu      sync.Mutex
	counter byte
}

func (reader *deterministicFlowReader) Read(destination []byte) (int, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	for index := range destination {
		reader.counter++
		if reader.counter == 0 {
			reader.counter = 1
		}
		destination[index] = reader.counter
	}
	return len(destination), nil
}

type fakeVerifierProtector struct {
	mu        sync.Mutex
	contexts  []TransactionProtectionContext
	sealCount int
	openCount int
	openErr   error
}

func (protector *fakeVerifierProtector) SealPKCE(
	_ context.Context,
	protection TransactionProtectionContext,
	verifier []byte,
) (ProtectedVerifier, error) {
	protector.mu.Lock()
	defer protector.mu.Unlock()
	protector.contexts = append(protector.contexts, protection)
	protector.sealCount++
	ciphertext := make([]byte, 16+len(verifier))
	for index := range ciphertext[:16] {
		ciphertext[index] = 0xa5
	}
	for index, value := range verifier {
		ciphertext[16+index] = value ^ 0x5a
	}
	return ProtectedVerifier{KeyVersion: 7, Ciphertext: ciphertext}, nil
}

func (protector *fakeVerifierProtector) OpenPKCE(
	_ context.Context,
	protection TransactionProtectionContext,
	protected ProtectedVerifier,
) ([]byte, error) {
	protector.mu.Lock()
	defer protector.mu.Unlock()
	protector.contexts = append(protector.contexts, protection)
	protector.openCount++
	if protector.openErr != nil {
		return nil, protector.openErr
	}
	if protected.KeyVersion != 7 || len(protected.Ciphertext) < 16 {
		return nil, errors.New("invalid protected verifier fixture")
	}
	verifier := make([]byte, len(protected.Ciphertext)-16)
	for index, value := range protected.Ciphertext[16:] {
		verifier[index] = value ^ 0x5a
	}
	return verifier, nil
}

type fakeTransactionRepository struct {
	mu                  sync.Mutex
	records             map[TransactionID]ClaimedTransaction
	created             []CreateTransactionRequest
	claims              []TransactionClaim
	failures            []TransactionFailure
	failCalls           []TransactionFailure
	createErr           error
	createCommitThenErr bool
	claimErr            error
	claimCommitThenErr  bool
	failErr             error
	failCommitThenErr   bool
}

func newFakeTransactionRepository() *fakeTransactionRepository {
	return &fakeTransactionRepository{records: make(map[TransactionID]ClaimedTransaction)}
}

func (repository *fakeTransactionRepository) CreateReplacing(
	ctx context.Context,
	request CreateTransactionRequest,
) error {
	if ctx == nil || ctx.Err() != nil {
		return context.Canceled
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.createErr != nil {
		return repository.createErr
	}
	request = cloneCreateRequest(request)
	if request.HasPreviousBrowserBinding {
		for id, record := range repository.records {
			if record.State == TransactionPending &&
				equalDigest(record.BrowserDigest, request.PreviousBrowserDigest) {
				record.State = TransactionExpired
				record.Version++
				repository.records[id] = record
			}
		}
	}
	repository.created = append(repository.created, request)
	repository.records[request.Current.ID] = ClaimedTransaction{
		PendingTransaction: clonePendingTransaction(request.Current),
	}
	if repository.createCommitThenErr {
		repository.createCommitThenErr = false
		return errors.New("create response lost")
	}
	return nil
}

func (repository *fakeTransactionRepository) Claim(
	ctx context.Context,
	claim TransactionClaim,
) (ClaimedTransaction, error) {
	if ctx == nil || ctx.Err() != nil {
		return ClaimedTransaction{}, context.Canceled
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.claimErr != nil {
		return ClaimedTransaction{}, repository.claimErr
	}
	repository.claims = append(repository.claims, claim)
	for id, record := range repository.records {
		if !equalDigest(record.StateDigest, claim.StateDigest) ||
			!equalDigest(record.BrowserDigest, claim.BrowserDigest) {
			continue
		}
		if record.State == TransactionClaimed && record.ClaimAttemptID == claim.AttemptID &&
			record.ClaimedAt.Equal(claim.ClaimedAt) &&
			equalDigest(record.AuthorizationCodeDigest, claim.AuthorizationCodeDigest) {
			return cloneClaimedTransaction(record), nil
		}
		if record.State != TransactionPending {
			continue
		}
		if !claim.ClaimedAt.Before(record.ExpiresAt) {
			record.State = TransactionExpired
			record.Version++
			repository.records[id] = record
			return ClaimedTransaction{}, errors.New("expired")
		}
		record.State = TransactionClaimed
		record.Version++
		record.ClaimAttemptID = claim.AttemptID
		record.AuthorizationCodeDigest = claim.AuthorizationCodeDigest
		record.ClaimedAt = claim.ClaimedAt
		repository.records[id] = record
		if repository.claimCommitThenErr {
			repository.claimCommitThenErr = false
			return ClaimedTransaction{}, errors.New("claim response lost")
		}
		return cloneClaimedTransaction(record), nil
	}
	return ClaimedTransaction{}, errors.New("not claimable")
}

func (repository *fakeTransactionRepository) Fail(
	ctx context.Context,
	failure TransactionFailure,
) error {
	if ctx == nil || ctx.Err() != nil {
		return context.Canceled
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.failCalls = append(repository.failCalls, failure)
	if repository.failErr != nil {
		return repository.failErr
	}
	record, present := repository.records[failure.ID]
	if present && record.Version == failure.ExpectedVersion+1 && record.State == failure.State {
		for _, previous := range repository.failures {
			if previous == failure {
				return nil
			}
		}
	}
	if !present || record.Version != failure.ExpectedVersion || record.State != TransactionClaimed {
		return errors.New("not failable")
	}
	record.State = failure.State
	record.Version++
	repository.records[failure.ID] = record
	repository.failures = append(repository.failures, failure)
	if repository.failCommitThenErr {
		repository.failCommitThenErr = false
		return errors.New("response lost after commit")
	}
	return nil
}

func clonePendingTransaction(source PendingTransaction) PendingTransaction {
	result := source
	result.Verifier = cloneProtectedVerifier(source.Verifier)
	result.Scopes = append([]string(nil), source.Scopes...)
	return result
}

func cloneCreateRequest(source CreateTransactionRequest) CreateTransactionRequest {
	result := source
	result.Current = clonePendingTransaction(source.Current)
	return result
}

type observedTokenExchange struct {
	endpointKind EndpointKind
	endpointURL  string
	authMode     ClientAuthenticationMode
	clientIDSet  bool
	secretHash   [sha256.Size]byte
	codeHash     [sha256.Size]byte
	redirectSet  bool
	verifierHash [sha256.Size]byte
	deadlineSet  bool
}

type fakeTokenEndpoint struct {
	mu       sync.Mutex
	response TokenEndpointResponse
	err      error
	observe  func(context.Context, TokenExchangeRequest) error
	calls    []observedTokenExchange
}

func (endpoint *fakeTokenEndpoint) Exchange(
	ctx context.Context,
	request TokenExchangeRequest,
) (TokenEndpointResponse, error) {
	if endpoint.observe != nil {
		if err := endpoint.observe(ctx, request); err != nil {
			return TokenEndpointResponse{}, err
		}
	}
	_, deadlineSet := ctx.Deadline()
	endpoint.mu.Lock()
	endpoint.calls = append(endpoint.calls, observedTokenExchange{
		endpointKind: request.Endpoint.Kind(), endpointURL: request.Endpoint.URL(),
		authMode: request.ClientAuthentication, clientIDSet: request.ClientID != "",
		secretHash: sha256.Sum256(request.ClientSecret), codeHash: sha256.Sum256(request.AuthorizationCode),
		redirectSet: request.RedirectURI != "", verifierHash: sha256.Sum256(request.PKCEVerifier),
		deadlineSet: deadlineSet,
	})
	response := endpoint.response
	response.Body = append([]byte(nil), endpoint.response.Body...)
	err := endpoint.err
	endpoint.mu.Unlock()
	return response, err
}

type flowTestFixture struct {
	flow          *Flow
	repository    *fakeTransactionRepository
	protector     *fakeVerifierProtector
	tokenEndpoint *fakeTokenEndpoint
	configuration AuthorizationConfiguration
	now           *time.Time
}

func newFlowTestFixture(t *testing.T, mutate func(*AuthorizationConfiguration, *FlowPolicy)) flowTestFixture {
	t.Helper()
	discoveryDocument := validDiscoveryDocument(t)
	edKey := ed25519JWK("key-ed25519-primary")
	edKey["key_ops"] = []string{"verify"}
	jwksDocument := marshalJSON(t, map[string]any{"keys": []any{edKey}})
	trust, _ := newTrustTestClient(t, []federatedhttp.Result{
		successfulResult(federatedhttp.DocumentOIDCDiscovery, discoveryDocument),
		successfulResult(federatedhttp.DocumentOIDCJWKS, jwksDocument),
	}, nil)
	discovery := fetchValidDiscovery(t, trust)
	jwks, err := trust.FetchJWKS(context.Background(), discovery, testJWKSRev)
	if err != nil {
		t.Fatal(err)
	}
	runtimeTrust, err := New(Options{HTTP: newCompiler(t), Limits: DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	entityID := func(value byte) identity.EntityID {
		var id identity.EntityID
		for index := range id {
			id[index] = value
		}
		return id
	}
	configuration := AuthorizationConfiguration{
		Provider: identity.ProviderContext{
			Scope: identity.TenantProviderScope, TenantID: entityID(1), ProviderID: entityID(2),
		},
		BindingID: entityID(3), ProviderRevision: 11, BindingRevision: 12,
		ConfigurationRevision: 13, SecurityRevision: 14, MappingRevision: 15,
		AuthorizationRevision: 16, AssurancePolicyRevision: 17, ClientSecretRevision: 18,
		ClientID: "oidc-client", RedirectURI: "https://app.example/api/v1/auth/federated/oidc/callback",
		PostLogoutRedirectURI: "https://app.example/auth/logout/complete",
		ExtraScopes:           []string{"profile"}, UseUserInfo: true,
		Discovery: discovery, JWKS: jwks,
	}
	deploymentRedirect := configuration.RedirectURI
	deploymentLogoutRedirect := configuration.PostLogoutRedirectURI
	policy := DefaultFlowPolicy()
	if mutate != nil {
		mutate(&configuration, &policy)
	}
	callbackEndpoint := TenantOIDCCallbackEndpoint
	if configuration.Authority == DirectPlatformCeremonyAuthority {
		callbackEndpoint = DirectPlatformOIDCCallbackEndpoint
		configuration.RedirectURI = "https://app.example/api/v1/auth/platform/oidc/callback"
		deploymentRedirect = configuration.RedirectURI
	}
	repository := newFakeTransactionRepository()
	protector := &fakeVerifierProtector{}
	tokenEndpoint := &fakeTokenEndpoint{}
	now := flowTestNow
	flow, err := newFlow(FlowOptions{
		Trust: runtimeTrust, Transactions: repository, VerifierProtector: protector,
		TokenEndpoint: tokenEndpoint, RedirectURI: deploymentRedirect,
		PostLogoutRedirectURI: deploymentLogoutRedirect, CallbackEndpoint: callbackEndpoint, Policy: policy,
	}, &deterministicFlowReader{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return flowTestFixture{
		flow: flow, repository: repository, protector: protector,
		tokenEndpoint: tokenEndpoint, configuration: configuration, now: &now,
	}
}

func (fixture flowTestFixture) startAndClaim(t *testing.T) (AuthorizationStart, *ClaimedAuthorization, url.Values) {
	t.Helper()
	start, err := fixture.flow.StartAuthorization(context.Background(), StartAuthorizationRequest{
		Begin: testAuthorizationBegin(), Configuration: fixture.configuration, ReturnPath: "/incidents?view=mine",
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(start.RedirectURL())
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	callback := url.Values{
		"code":  []string{"authorization-code-canary"},
		"state": []string{query.Get("state")},
		"iss":   []string{testIssuer},
	}
	claimed, err := fixture.flow.claimCallback(context.Background(), callbackRequest{
		Configuration: fixture.configuration, RawQuery: callback.Encode(),
		BrowserHandle: start.BrowserHandle(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return start, claimed, query
}

func validIDTokenClaims(nonce string) map[string]any {
	return map[string]any{
		"iss": testIssuer, "sub": "subject-exact", "aud": "oidc-client",
		"nonce": nonce, "iat": flowTestNow.Unix(), "exp": flowTestNow.Add(10 * time.Minute).Unix(),
		"auth_time":          flowTestNow.Add(-2 * time.Minute).Unix(),
		"preferred_username": "analyst", "email": "analyst@example.test",
		"groups": []string{"blue-team", "incident-command"},
		"acr":    "urn:periapsis:assurance:mfa", "amr": []string{"mfa", "pwd"},
	}
}

func signIDToken(t *testing.T, claims map[string]any, mutateHeader func(*jose.SignerOptions)) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return signRawIDToken(t, payload, mutateHeader)
}

func signRawIDToken(t *testing.T, payload []byte, mutateHeader func(*jose.SignerOptions)) string {
	t.Helper()
	_, privateKey := ed25519Material()
	options := (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "key-ed25519-primary")
	if mutateHeader != nil {
		mutateHeader(options)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: privateKey}, options)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func tokenResponseDocument(t *testing.T, idToken string, refresh bool) []byte {
	t.Helper()
	response := map[string]any{
		"id_token": idToken, "access_token": "access-token-canary", "token_type": "Bearer",
		"expires_in": 600, "scope": "openid profile",
	}
	if refresh {
		response["refresh_token"] = "refresh-token-canary"
		response["scope"] = "offline_access openid profile"
	}
	return marshalJSON(t, response)
}

func setSuccessfulTokenResponse(t *testing.T, fixture flowTestFixture, nonce string, mutate func(map[string]any)) {
	t.Helper()
	claims := validIDTokenClaims(nonce)
	if mutate != nil {
		mutate(claims)
	}
	fixture.tokenEndpoint.response = TokenEndpointResponse{
		Category: TokenEndpointSuccess, StatusCode: 200, MediaType: "application/json; charset=utf-8",
		Body: tokenResponseDocument(t, signIDToken(t, claims, nil), fixture.configuration.AllowRefreshToken),
	}
}

type fakeLogoutConfirmation struct {
	id        TransactionID
	pins      TransactionPins
	revokedAt time.Time
}

func (confirmation fakeLogoutConfirmation) OIDCTransactionID() TransactionID { return confirmation.id }
func (confirmation fakeLogoutConfirmation) OIDCTransactionPins() TransactionPins {
	return confirmation.pins
}
func (confirmation fakeLogoutConfirmation) LocalSessionRevokedAt() time.Time {
	return confirmation.revokedAt
}

func splitCompactToken(t *testing.T, compact string) (header, payload, signature []byte) {
	t.Helper()
	parts := make([][]byte, 0, 3)
	start := 0
	for index := 0; index <= len(compact); index++ {
		if index != len(compact) && compact[index] != '.' {
			continue
		}
		part, err := base64.RawURLEncoding.DecodeString(compact[start:index])
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, part)
		start = index + 1
	}
	if len(parts) != 3 {
		t.Fatalf("compact parts = %d", len(parts))
	}
	return parts[0], parts[1], parts[2]
}
