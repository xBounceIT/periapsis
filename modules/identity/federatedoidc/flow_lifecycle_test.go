package federatedoidc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
	"golang.org/x/oauth2"
)

type mutatingCreateRepository struct {
	attempts []CreateTransactionRequest
}

func (repository *mutatingCreateRepository) CreateReplacing(
	_ context.Context,
	request CreateTransactionRequest,
) error {
	repository.attempts = append(repository.attempts, cloneCreateRequest(request))
	if len(request.Current.Verifier.Ciphertext) != 0 {
		request.Current.Verifier.Ciphertext[0] ^= 0xff
	}
	if len(request.Current.Scopes) != 0 {
		request.Current.Scopes[0] = "mutated"
	}
	if len(repository.attempts) == 1 {
		return errors.New("commit response lost")
	}
	return nil
}

func (*mutatingCreateRepository) Claim(context.Context, TransactionClaim) (ClaimedTransaction, error) {
	return ClaimedTransaction{}, errors.New("not used")
}

func (*mutatingCreateRepository) Fail(context.Context, TransactionFailure) error {
	return errors.New("not used")
}

func TestNewFlowRejectsMissingBoundariesAndInvalidPolicy(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	valid := FlowOptions{
		Trust: fixture.flow.trust, Transactions: fixture.repository,
		VerifierProtector: fixture.protector, TokenEndpoint: fixture.tokenEndpoint,
		RedirectURI: fixture.flow.redirectURI, PostLogoutRedirectURI: fixture.flow.postLogoutRedirectURI,
		Policy: DefaultFlowPolicy(),
	}
	tests := map[string]func(*FlowOptions){
		"trust":      func(value *FlowOptions) { value.Trust = nil },
		"repository": func(value *FlowOptions) { value.Transactions = nil },
		"protector":  func(value *FlowOptions) { value.VerifierProtector = nil },
		"post port":  func(value *FlowOptions) { value.TokenEndpoint = nil },
		"redirect":   func(value *FlowOptions) { value.RedirectURI = "" },
		"redirect query": func(value *FlowOptions) {
			value.RedirectURI += "?tenant=attacker"
		},
		"logout origin": func(value *FlowOptions) {
			value.PostLogoutRedirectURI = "https://other.example/auth/logout/complete"
		},
		"ttl": func(value *FlowOptions) { value.Policy.TransactionTTL = time.Second },
		"ttl precision": func(value *FlowOptions) {
			value.Policy.TransactionTTL = time.Minute + time.Nanosecond
		},
		"timeout":      func(value *FlowOptions) { value.Policy.OperationTimeout = 0 },
		"skew":         func(value *FlowOptions) { value.Policy.ClockSkew = 6 * time.Minute },
		"token age":    func(value *FlowOptions) { value.Policy.MaxTokenAge = 0 },
		"claim bounds": func(value *FlowOptions) { value.Policy.Limits.MaxGroups = 0 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			options := valid
			mutate(&options)
			if _, err := NewFlow(options); !errors.Is(err, ErrInvalidFlowOptions) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestAuthorizationStartPinsCodeFlowPKCEAndOpaqueArtifacts(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	// Use a canonical CSPRNG-sized browser handle rather than arbitrary bytes.
	previous := []byte("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA")
	start, err := fixture.flow.StartAuthorization(context.Background(), StartAuthorizationRequest{
		Begin: testAuthorizationBegin(), Configuration: fixture.configuration, ReturnPath: "/incidents?view=mine",
		PreviousBrowserHandle: previous,
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(start.RedirectURL())
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	wantKeys := []string{
		"client_id", "code_challenge", "code_challenge_method", "max_age", "nonce", "redirect_uri",
		"response_mode", "response_type", "scope", "state",
	}
	gotKeys := make([]string, 0, len(query))
	for key, values := range query {
		if len(values) != 1 {
			t.Fatalf("%s cardinality = %d", key, len(values))
		}
		gotKeys = append(gotKeys, key)
	}
	slices.Sort(gotKeys)
	if parsed.Scheme != "https" || parsed.Host != "provider.example" ||
		parsed.Path != "/tenant/authorize" || !slices.Equal(gotKeys, wantKeys) ||
		query.Get("response_type") != ResponseTypeCode || query.Get("response_mode") != ResponseModeQuery ||
		query.Get("code_challenge_method") != CodeChallengeS256 || query.Get("client_id") != "oidc-client" ||
		query.Get("max_age") != "43200" ||
		query.Get("redirect_uri") != fixture.configuration.RedirectURI || query.Get("scope") != "openid profile" ||
		!validOpaque([]byte(query.Get("state"))) || !validOpaque([]byte(query.Get("nonce"))) ||
		!validOpaque(start.BrowserHandle()) {
		t.Fatalf("unexpected authorization request: %v", query)
	}

	fixture.repository.mu.Lock()
	if len(fixture.repository.created) != 1 {
		fixture.repository.mu.Unlock()
		t.Fatalf("creates = %d", len(fixture.repository.created))
	}
	created := cloneCreateRequest(fixture.repository.created[0])
	fixture.repository.mu.Unlock()
	defer clear(created.Current.Verifier.Ciphertext)
	verifier, err := fixture.protector.OpenPKCE(context.Background(), TransactionProtectionContext{
		TransactionID: created.Current.ID, Provider: created.Current.Pins.Provider,
		BindingID: created.Current.Pins.BindingID,
	}, created.Current.Verifier)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(verifier)
	if query.Get("code_challenge") != oauth2.S256ChallengeFromVerifier(string(verifier)) ||
		created.Begin != testAuthorizationBegin() ||
		bytes.Contains(created.Current.Verifier.Ciphertext, verifier) ||
		created.Current.StateDigest != sha256.Sum256([]byte(query.Get("state"))) ||
		created.Current.NonceDigest != sha256.Sum256([]byte(query.Get("nonce"))) ||
		created.Current.BrowserDigest != sha256.Sum256(start.BrowserHandle()) ||
		created.Current.Pins != transactionPins(fixture.configuration) ||
		created.Current.State != TransactionPending || created.Current.Version != 1 ||
		!created.Current.UseUserInfo || created.Current.AllowRefreshToken ||
		!created.HasPreviousBrowserBinding ||
		created.PreviousBrowserDigest != sha256.Sum256(previous) {
		t.Fatal("start did not persist exact one-time pins and digests")
	}
	copyHandle := start.BrowserHandle()
	copyHandle[0] ^= 0xff
	if bytes.Equal(copyHandle, start.BrowserHandle()) {
		t.Fatal("browser handle accessor did not return a defensive copy")
	}
}

func TestAuthorizationStartReplaysExactCreateAfterLostResponse(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	fixture.repository.createCommitThenErr = true
	start, err := fixture.flow.StartAuthorization(context.Background(), StartAuthorizationRequest{
		Begin: testAuthorizationBegin(), Configuration: fixture.configuration, ReturnPath: "/cases",
	})
	if err != nil || start.TransactionID() == (TransactionID{}) {
		t.Fatalf("StartAuthorization() = %s, %v", start, err)
	}
	fixture.repository.mu.Lock()
	defer fixture.repository.mu.Unlock()
	if len(fixture.repository.created) != 2 {
		t.Fatalf("create replay count = %d", len(fixture.repository.created))
	}
	if !reflect.DeepEqual(fixture.repository.created[0], fixture.repository.created[1]) {
		t.Fatalf("create replay diverged: first=%s second=%s",
			fixture.repository.created[0], fixture.repository.created[1])
	}
}

func TestAuthorizationStartRetryOwnsRepositoryInput(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	repository := &mutatingCreateRepository{}
	fixture.flow.transactions = repository
	start, err := fixture.flow.StartAuthorization(context.Background(), StartAuthorizationRequest{
		Begin: testAuthorizationBegin(), Configuration: fixture.configuration, ReturnPath: "/cases",
	})
	if err != nil || start.TransactionID() == (TransactionID{}) {
		t.Fatalf("StartAuthorization() = %s, %v", start, err)
	}
	if len(repository.attempts) != 2 {
		t.Fatalf("create replay count = %d", len(repository.attempts))
	}
	defer clear(repository.attempts[0].Current.Verifier.Ciphertext)
	defer clear(repository.attempts[1].Current.Verifier.Ciphertext)
	if !reflect.DeepEqual(repository.attempts[0], repository.attempts[1]) {
		t.Fatalf("callee mutation changed retry: first=%s second=%s", repository.attempts[0], repository.attempts[1])
	}
}

func TestCallbackClaimReplaysOnlyTheSameAttemptAfterLostResponse(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	fixture.repository.claimCommitThenErr = true
	_, claimed, _ := fixture.startAndClaim(t)
	if claimed == nil || claimed.record.ClaimAttemptID == (TransactionID{}) {
		t.Fatalf("claimed authorization = %v", claimed)
	}
	fixture.repository.mu.Lock()
	defer fixture.repository.mu.Unlock()
	if len(fixture.repository.claims) != 2 {
		t.Fatalf("claim replay count = %d", len(fixture.repository.claims))
	}
	if !reflect.DeepEqual(fixture.repository.claims[0], fixture.repository.claims[1]) {
		t.Fatalf("claim replay diverged: first=%s second=%s",
			fixture.repository.claims[0], fixture.repository.claims[1])
	}
}

func TestAuthorizationStartRejectsMalformedOrPurposeReusedBeginBeforePersistence(t *testing.T) {
	for name, mutate := range map[string]func(*AuthorizationBegin){
		"missing operation": func(value *AuthorizationBegin) { value.OperationRunID = identity.EntityID{} },
		"non UUIDv7":        func(value *AuthorizationBegin) { value.OperationRunID[6] = 0x40 },
		"wrong variant":     func(value *AuthorizationBegin) { value.OperationRunID[8] = 0x40 },
		"missing receipt":   func(value *AuthorizationBegin) { value.ReceiptDigest = StartReceiptDigest{} },
		"receipt as network": func(value *AuthorizationBegin) {
			value.ReceiptDigest = StartReceiptDigest(value.NetworkDigest)
		},
		"network as account": func(value *AuthorizationBegin) {
			value.AccountDigest = AccountThrottleDigest(value.NetworkDigest)
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newFlowTestFixture(t, nil)
			begin := testAuthorizationBegin()
			mutate(&begin)
			if _, err := fixture.flow.StartAuthorization(context.Background(), StartAuthorizationRequest{
				Begin: begin, Configuration: fixture.configuration, ReturnPath: "/",
			}); !errors.Is(err, ErrAuthorizationRejected) {
				t.Fatalf("StartAuthorization() error = %v", err)
			}
			if len(fixture.repository.created) != 0 || fixture.protector.sealCount != 0 {
				t.Fatalf("malformed begin reached persistence/crypto: creates=%d seals=%d", len(fixture.repository.created), fixture.protector.sealCount)
			}
		})
	}
}

func TestStartReplacingExpiresPreviousBrowserTransaction(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	first, err := fixture.flow.StartAuthorization(context.Background(), StartAuthorizationRequest{
		Begin: testAuthorizationBegin(1), Configuration: fixture.configuration, ReturnPath: "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.flow.StartAuthorization(context.Background(), StartAuthorizationRequest{
		Begin: testAuthorizationBegin(2), Configuration: fixture.configuration, ReturnPath: "/",
		PreviousBrowserHandle: first.BrowserHandle(),
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.repository.mu.Lock()
	firstRecord := fixture.repository.records[first.TransactionID()]
	secondRecord := fixture.repository.records[second.TransactionID()]
	fixture.repository.mu.Unlock()
	if firstRecord.State != TransactionExpired || firstRecord.Version != 2 ||
		secondRecord.State != TransactionPending || first.TransactionID() == second.TransactionID() ||
		bytes.Equal(first.BrowserHandle(), second.BrowserHandle()) {
		t.Fatal("replacement did not atomically retire the previous browser flow")
	}
}

func TestAuthorizationConfigurationRejectsRefreshMismatchAndMutableBoundaries(t *testing.T) {
	tests := map[string]func(*AuthorizationConfiguration){
		"provider revision":      func(value *AuthorizationConfiguration) { value.ProviderRevision = 0 },
		"binding revision":       func(value *AuthorizationConfiguration) { value.BindingRevision = 0 },
		"configuration revision": func(value *AuthorizationConfiguration) { value.ConfigurationRevision = 0 },
		"security revision":      func(value *AuthorizationConfiguration) { value.SecurityRevision = 0 },
		"mapping revision":       func(value *AuthorizationConfiguration) { value.MappingRevision = 0 },
		"authorization revision": func(value *AuthorizationConfiguration) { value.AuthorizationRevision = 0 },
		"assurance revision":     func(value *AuthorizationConfiguration) { value.AssurancePolicyRevision = 0 },
		"revision overflow": func(value *AuthorizationConfiguration) {
			value.ProviderRevision = maximumPersistentRevision + 1
		},
		"discovery overflow":    func(value *AuthorizationConfiguration) { value.Discovery.revision = ^uint64(0) },
		"jwks overflow":         func(value *AuthorizationConfiguration) { value.JWKS.revision = ^uint64(0) },
		"refresh without scope": func(value *AuthorizationConfiguration) { value.AllowRefreshToken = true },
		"scope without refresh": func(value *AuthorizationConfiguration) {
			value.ExtraScopes = append(value.ExtraScopes, "offline_access")
		},
		"forwarded redirect": func(value *AuthorizationConfiguration) {
			value.RedirectURI = "https://evil.example/api/v1/auth/federated/oidc/callback"
		},
		"logout redirect origin":   func(value *AuthorizationConfiguration) { value.PostLogoutRedirectURI = "https://other.example/logout" },
		"wrong discovery revision": func(value *AuthorizationConfiguration) { value.JWKS.discoveryRevision++ },
		"userinfo without endpoint": func(value *AuthorizationConfiguration) {
			value.Discovery.endpoints.UserInfo = ""
			value.Discovery.targets.userinfo = federatedhttp.Target{}
		},
		"platform with binding": func(value *AuthorizationConfiguration) {
			value.Provider.Scope = 2
			value.Provider.TenantID = [16]byte{}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newFlowTestFixture(t, nil)
			mutate(&fixture.configuration)
			if _, err := fixture.flow.StartAuthorization(context.Background(), StartAuthorizationRequest{
				Begin: testAuthorizationBegin(), Configuration: fixture.configuration, ReturnPath: "/",
			}); !errors.Is(err, ErrAuthorizationRejected) {
				t.Fatalf("got %v", err)
			}
			if len(fixture.repository.created) != 0 {
				t.Fatal("invalid configuration reached repository")
			}
		})
	}
}

func TestAuthorizationStartRejectsStaleTrustSnapshots(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	*fixture.now = fixture.configuration.JWKS.Cache().FreshUntil.Add(time.Millisecond)
	if _, err := fixture.flow.StartAuthorization(context.Background(), StartAuthorizationRequest{
		Begin: testAuthorizationBegin(), Configuration: fixture.configuration, ReturnPath: "/",
	}); !errors.Is(err, ErrAuthorizationRejected) {
		t.Fatalf("stale snapshot = %v", err)
	}
	if len(fixture.repository.created) != 0 {
		t.Fatal("stale trust reached repository")
	}

	fixture = newFlowTestFixture(t, nil)
	*fixture.now = fixture.configuration.JWKS.Cache().FreshUntil
	if _, err := fixture.flow.StartAuthorization(context.Background(), StartAuthorizationRequest{
		Begin: testAuthorizationBegin(), Configuration: fixture.configuration, ReturnPath: "/",
	}); err != nil {
		t.Fatalf("exact freshness boundary rejected: %v", err)
	}
}

func TestCallbackValidationRejectsHostileQueriesBeforeClaim(t *testing.T) {
	tests := map[string]func(url.Values, string, []byte) (string, []byte){
		"duplicate state": func(values url.Values, raw string, browser []byte) (string, []byte) {
			return raw + "&state=" + url.QueryEscape(values.Get("state")), browser
		},
		"duplicate code": func(values url.Values, raw string, browser []byte) (string, []byte) {
			return raw + "&code=second", browser
		},
		"code and error": func(values url.Values, raw string, browser []byte) (string, []byte) {
			return raw + "&error=access_denied", browser
		},
		"unknown member": func(values url.Values, raw string, browser []byte) (string, []byte) {
			return raw + "&token=canary", browser
		},
		"wrong issuer": func(values url.Values, raw string, browser []byte) (string, []byte) {
			values.Set("iss", "https://other.example")
			return values.Encode(), browser
		},
		"leading question": func(values url.Values, raw string, browser []byte) (string, []byte) {
			return "?" + raw, browser
		},
		"empty query member": func(values url.Values, raw string, browser []byte) (string, []byte) {
			return raw + "&", browser
		},
		"encoded member name": func(values url.Values, raw string, browser []byte) (string, []byte) {
			return strings.Replace(raw, "code=", "c%6fde=", 1), browser
		},
		"missing browser": func(values url.Values, raw string, _ []byte) (string, []byte) {
			return raw, nil
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newFlowTestFixture(t, nil)
			start, err := fixture.flow.StartAuthorization(context.Background(), StartAuthorizationRequest{
				Begin: testAuthorizationBegin(), Configuration: fixture.configuration, ReturnPath: "/",
			})
			if err != nil {
				t.Fatal(err)
			}
			redirect, _ := url.Parse(start.RedirectURL())
			values := url.Values{
				"code": {"code-canary"}, "state": {redirect.Query().Get("state")}, "iss": {testIssuer},
			}
			raw, browser := mutate(values, values.Encode(), start.BrowserHandle())
			if _, err = fixture.flow.claimCallback(context.Background(), callbackRequest{
				Configuration: fixture.configuration, RawQuery: raw, BrowserHandle: browser,
			}); !errors.Is(err, ErrCallbackRejected) {
				t.Fatalf("got %v", err)
			}
			fixture.repository.mu.Lock()
			state := fixture.repository.records[start.TransactionID()].State
			fixture.repository.mu.Unlock()
			if state != TransactionPending {
				t.Fatalf("hostile callback consumed state: %s", state)
			}
		})
	}
}

func TestCallbackReplayRaceHasExactlyOneWinner(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	start, err := fixture.flow.StartAuthorization(context.Background(), StartAuthorizationRequest{
		Begin: testAuthorizationBegin(), Configuration: fixture.configuration, ReturnPath: "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	redirect, _ := url.Parse(start.RedirectURL())
	raw := url.Values{
		"code": {"code-canary"}, "state": {redirect.Query().Get("state")}, "iss": {testIssuer},
	}.Encode()
	var winners atomic.Int32
	var wait sync.WaitGroup
	for range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, callbackErr := fixture.flow.claimCallback(context.Background(), callbackRequest{
				Configuration: fixture.configuration, RawQuery: raw, BrowserHandle: start.BrowserHandle(),
			}); callbackErr == nil {
				winners.Add(1)
			} else if !errors.Is(callbackErr, ErrCallbackRejected) {
				t.Errorf("unexpected error: %v", callbackErr)
			}
		}()
	}
	wait.Wait()
	if winners.Load() != 1 {
		t.Fatalf("callback winners = %d", winners.Load())
	}
}

func TestCallbackExpiryBoundaryIsTerminalBeforeCodeUse(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	start, err := fixture.flow.StartAuthorization(context.Background(), StartAuthorizationRequest{
		Begin: testAuthorizationBegin(), Configuration: fixture.configuration, ReturnPath: "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	redirect, _ := url.Parse(start.RedirectURL())
	*fixture.now = start.ExpiresAt()
	if _, err = fixture.flow.claimCallback(context.Background(), callbackRequest{
		Configuration: fixture.configuration,
		RawQuery: url.Values{
			"code": {"code-canary"}, "state": {redirect.Query().Get("state")}, "iss": {testIssuer},
		}.Encode(),
		BrowserHandle: start.BrowserHandle(),
	}); !errors.Is(err, ErrCallbackRejected) {
		t.Fatalf("expiry boundary = %v", err)
	}
	fixture.repository.mu.Lock()
	state := fixture.repository.records[start.TransactionID()].State
	fixture.repository.mu.Unlock()
	if state != TransactionExpired {
		t.Fatalf("expired state = %s", state)
	}
}

func TestCallbackClaimsThenTerminatesStaleOrMalformedProjection(t *testing.T) {
	tests := map[string]func(*flowTestFixture, TransactionID){
		"configuration revision": func(fixture *flowTestFixture, _ TransactionID) {
			fixture.configuration.ConfigurationRevision++
		},
		"JWKS rotation": func(fixture *flowTestFixture, _ TransactionID) {
			fixture.configuration.JWKS.revision++
		},
		"userinfo semantic change": func(fixture *flowTestFixture, _ TransactionID) {
			fixture.configuration.UseUserInfo = false
		},
		"missing nonce digest": func(fixture *flowTestFixture, id TransactionID) {
			fixture.repository.mu.Lock()
			record := fixture.repository.records[id]
			record.NonceDigest = [sha256.Size]byte{}
			fixture.repository.records[id] = record
			fixture.repository.mu.Unlock()
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newFlowTestFixture(t, nil)
			start, err := fixture.flow.StartAuthorization(context.Background(), StartAuthorizationRequest{
				Begin: testAuthorizationBegin(), Configuration: fixture.configuration, ReturnPath: "/",
			})
			if err != nil {
				t.Fatal(err)
			}
			redirect, _ := url.Parse(start.RedirectURL())
			mutate(&fixture, start.TransactionID())
			raw := url.Values{
				"code": {"code-canary"}, "state": {redirect.Query().Get("state")}, "iss": {testIssuer},
			}.Encode()
			if _, err = fixture.flow.claimCallback(context.Background(), callbackRequest{
				Configuration: fixture.configuration, RawQuery: raw, BrowserHandle: start.BrowserHandle(),
			}); !errors.Is(err, ErrCallbackRejected) {
				t.Fatalf("got %v", err)
			}
			fixture.repository.mu.Lock()
			failures := append([]TransactionFailure(nil), fixture.repository.failures...)
			fixture.repository.mu.Unlock()
			if len(failures) != 1 || failures[0].Reason != FailureStaleConfiguration ||
				failures[0].State != TransactionFailed {
				t.Fatalf("terminal failure = %v", failures)
			}
		})
	}
}

func TestProviderErrorConsumesTransactionAndStoresOnlySafeReason(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	start, err := fixture.flow.StartAuthorization(context.Background(), StartAuthorizationRequest{
		Begin: testAuthorizationBegin(), Configuration: fixture.configuration, ReturnPath: "/",
	})
	if err != nil {
		t.Fatal(err)
	}
	redirect, _ := url.Parse(start.RedirectURL())
	raw := url.Values{
		"error": {"access_denied"}, "error_description": {testHostileSentinel},
		"state": {redirect.Query().Get("state")}, "iss": {testIssuer},
	}.Encode()
	if _, err = fixture.flow.claimCallback(context.Background(), callbackRequest{
		Configuration: fixture.configuration, RawQuery: raw, BrowserHandle: start.BrowserHandle(),
	}); !errors.Is(err, ErrCallbackRejected) {
		t.Fatalf("got %v", err)
	}
	fixture.repository.mu.Lock()
	defer fixture.repository.mu.Unlock()
	if len(fixture.repository.failures) != 1 ||
		fixture.repository.failures[0].Reason != FailureProviderResponse ||
		strings.Contains(fixture.repository.failures[0].String(), testHostileSentinel) {
		t.Fatalf("unsafe terminal failure: %v", fixture.repository.failures)
	}
}

func TestExchangeUsesOnlyPinnedInjectedPortAndIsOneTime(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	_, claimed, authorizationQuery := fixture.startAndClaim(t)
	setSuccessfulTokenResponse(t, fixture, authorizationQuery.Get("nonce"), nil)
	fixture.tokenEndpoint.observe = func(ctx context.Context, request TokenExchangeRequest) error {
		if request.Endpoint.Kind() != EndpointToken || request.Endpoint.URL() != testToken ||
			request.GrantType != GrantAuthorizationCode ||
			request.ClientAuthentication != ClientSecretBasic || request.ClientID != "oidc-client" ||
			string(request.ClientSecret) != "client-secret-canary" ||
			string(request.AuthorizationCode) != "authorization-code-canary" ||
			request.RedirectURI != fixture.configuration.RedirectURI || !validPKCEVerifier(request.PKCEVerifier) {
			return errors.New("incorrect semantic token request")
		}
		if deadline, ok := ctx.Deadline(); !ok || deadline.IsZero() {
			return errors.New("missing bounded deadline")
		}
		return nil
	}
	bundle, err := fixture.flow.ExchangeCode(context.Background(), claimed, ClientCredential{
		Revision: fixture.configuration.ClientSecretRevision, Secret: []byte("client-secret-canary"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bundle.HasAccessToken() || bundle.HasRefreshToken() ||
		bundle.AccessTokenExpiry() != flowTestNow.Add(10*time.Minute) ||
		!slices.Equal(bundle.Scopes(), []string{"openid", "profile"}) {
		t.Fatalf("unexpected token metadata: %v", bundle)
	}
	if _, err = fixture.flow.ExchangeCode(context.Background(), claimed, ClientCredential{
		Revision: fixture.configuration.ClientSecretRevision, Secret: []byte("client-secret-canary"),
	}); !errors.Is(err, ErrTokenExchangeFailed) {
		t.Fatalf("second exchange = %v", err)
	}
	fixture.tokenEndpoint.mu.Lock()
	defer fixture.tokenEndpoint.mu.Unlock()
	if len(fixture.tokenEndpoint.calls) != 1 || !fixture.tokenEndpoint.calls[0].deadlineSet {
		t.Fatalf("port calls = %v", fixture.tokenEndpoint.calls)
	}
}

func TestTokenResponseHostileCorpusFailsTerminally(t *testing.T) {
	tests := map[string]func(string) TokenEndpointResponse{
		"duplicate member": func(token string) TokenEndpointResponse {
			return successfulTokenHTTP([]byte(`{"id_token":"` + token + `","id_token":"` + token + `","access_token":"a","token_type":"Bearer"}`))
		},
		"error ambiguity": func(token string) TokenEndpointResponse {
			return successfulTokenHTTP([]byte(`{"id_token":"` + token + `","access_token":"a","token_type":"Bearer","error":"none"}`))
		},
		"wrong token type": func(token string) TokenEndpointResponse {
			return successfulTokenHTTP([]byte(`{"id_token":"` + token + `","access_token":"a","token_type":"DPoP"}`))
		},
		"forbidden refresh": func(token string) TokenEndpointResponse {
			return successfulTokenHTTP([]byte(`{"id_token":"` + token + `","access_token":"a","refresh_token":"r","token_type":"Bearer"}`))
		},
		"non ascii bearer token": func(token string) TokenEndpointResponse {
			return successfulTokenHTTP([]byte(`{"id_token":"` + token + `","access_token":"t\u00e9ken","token_type":"Bearer","expires_in":600}`))
		},
		"expanded scopes": func(token string) TokenEndpointResponse {
			return successfulTokenHTTP([]byte(`{"id_token":"` + token + `","access_token":"a","token_type":"Bearer","scope":"openid admin"}`))
		},
		"duration overflow": func(token string) TokenEndpointResponse {
			return successfulTokenHTTP([]byte(`{"id_token":"` + token + `","access_token":"a","token_type":"Bearer","expires_in":9223372036854775807}`))
		},
		"wrong media type": func(token string) TokenEndpointResponse {
			response := successfulTokenHTTP([]byte(`{"id_token":"` + token + `","access_token":"a","token_type":"Bearer"}`))
			response.MediaType = "text/json"
			return response
		},
		"redirect status": func(token string) TokenEndpointResponse {
			response := successfulTokenHTTP([]byte(`{"id_token":"` + token + `","access_token":"a","token_type":"Bearer"}`))
			response.StatusCode = 302
			return response
		},
		"missing expiry": func(token string) TokenEndpointResponse {
			return successfulTokenHTTP([]byte(`{"id_token":"` + token + `","access_token":"a","token_type":"Bearer"}`))
		},
	}
	for name, response := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newFlowTestFixture(t, nil)
			_, claimed, query := fixture.startAndClaim(t)
			token := signIDToken(t, validIDTokenClaims(query.Get("nonce")), nil)
			fixture.tokenEndpoint.response = response(token)
			_, err := fixture.flow.ExchangeCode(context.Background(), claimed, ClientCredential{
				Revision: fixture.configuration.ClientSecretRevision, Secret: []byte("client-secret-canary"),
			})
			if !errors.Is(err, ErrTokenResponseRejected) && !errors.Is(err, ErrTokenExchangeFailed) {
				t.Fatalf("got %v", err)
			}
			if claimed.stage.Load() != claimedStageFailed {
				t.Fatal("invalid response did not make transaction terminal")
			}
		})
	}
}

func TestRefreshOptInRequiresRefreshTokenInResponse(t *testing.T) {
	fixture := newFlowTestFixture(t, func(configuration *AuthorizationConfiguration, _ *FlowPolicy) {
		configuration.AllowRefreshToken = true
		configuration.ExtraScopes = append(configuration.ExtraScopes, "offline_access")
	})
	_, claimed, query := fixture.startAndClaim(t)
	token := signIDToken(t, validIDTokenClaims(query.Get("nonce")), nil)
	fixture.tokenEndpoint.response = successfulTokenHTTP([]byte(`{"id_token":"` + token +
		`","access_token":"a","token_type":"Bearer","expires_in":600,"scope":"offline_access openid profile"}`))
	if _, err := fixture.flow.ExchangeCode(context.Background(), claimed, ClientCredential{
		Revision: fixture.configuration.ClientSecretRevision, Secret: []byte("client-secret-canary"),
	}); !errors.Is(err, ErrTokenResponseRejected) {
		t.Fatalf("missing configured refresh token = %v", err)
	}
}

func successfulTokenHTTP(body []byte) TokenEndpointResponse {
	return TokenEndpointResponse{
		Category: TokenEndpointSuccess, StatusCode: 200,
		MediaType: "application/json", Body: body,
	}
}

func TestExchangeHonorsCancellationWithoutCallingPort(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	_, claimed, _ := fixture.startAndClaim(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := fixture.flow.ExchangeCode(ctx, claimed, ClientCredential{
		Revision: fixture.configuration.ClientSecretRevision, Secret: []byte("client-secret-canary"),
	})
	if !errors.Is(err, ErrTokenExchangeFailed) {
		t.Fatalf("got %v", err)
	}
	fixture.tokenEndpoint.mu.Lock()
	calls := len(fixture.tokenEndpoint.calls)
	fixture.tokenEndpoint.mu.Unlock()
	if calls != 0 || claimed.stage.Load() != claimedStageFailed {
		t.Fatal("cancelled exchange reached port or remained replayable")
	}
}

func TestClaimedCodeExpiresBeforeTokenPort(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	_, claimed, _ := fixture.startAndClaim(t)
	*fixture.now = claimed.record.ExpiresAt
	if _, err := fixture.flow.ExchangeCode(context.Background(), claimed, ClientCredential{
		Revision: fixture.configuration.ClientSecretRevision, Secret: []byte("client-secret-canary"),
	}); !errors.Is(err, ErrTokenExchangeFailed) {
		t.Fatalf("expired exchange = %v", err)
	}
	fixture.tokenEndpoint.mu.Lock()
	calls := len(fixture.tokenEndpoint.calls)
	fixture.tokenEndpoint.mu.Unlock()
	fixture.repository.mu.Lock()
	failures := append([]TransactionFailure(nil), fixture.repository.failures...)
	fixture.repository.mu.Unlock()
	if calls != 0 || len(failures) != 1 || failures[0].Reason != FailureExpired ||
		failures[0].State != TransactionExpired {
		t.Fatalf("expired exchange was not terminal: calls=%d failures=%v", calls, failures)
	}
}

func TestCredentialBoundaryFailuresAreSanitizedAndTerminal(t *testing.T) {
	for name, fail := range map[string]func(*flowTestFixture){
		"protector": func(fixture *flowTestFixture) {
			fixture.protector.openErr = errors.New(testHostileSentinel)
		},
		"token port": func(fixture *flowTestFixture) {
			fixture.tokenEndpoint.err = errors.New(testHostileSentinel)
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newFlowTestFixture(t, nil)
			_, claimed, _ := fixture.startAndClaim(t)
			fail(&fixture)
			_, err := fixture.flow.ExchangeCode(context.Background(), claimed, ClientCredential{
				Revision: fixture.configuration.ClientSecretRevision, Secret: []byte("client-secret-canary"),
			})
			if !errors.Is(err, ErrTokenExchangeFailed) || strings.Contains(err.Error(), testHostileSentinel) ||
				claimed.stage.Load() != claimedStageFailed {
				t.Fatalf("unsafe boundary failure: %v", err)
			}
		})
	}
}

func TestProtocolFailureReplaysExactTerminalMutationAfterLostResponse(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	_, claimed, _ := fixture.startAndClaim(t)
	fixture.repository.failCommitThenErr = true
	fixture.tokenEndpoint.err = errors.New("upstream unavailable")
	_, err := fixture.flow.ExchangeCode(context.Background(), claimed, ClientCredential{
		Revision: fixture.configuration.ClientSecretRevision, Secret: []byte("client-secret-canary"),
	})
	if !errors.Is(err, ErrTokenExchangeFailed) {
		t.Fatalf("ExchangeCode() error = %v", err)
	}
	fixture.repository.mu.Lock()
	defer fixture.repository.mu.Unlock()
	if len(fixture.repository.failCalls) != 2 || fixture.repository.failCalls[0] != fixture.repository.failCalls[1] ||
		len(fixture.repository.failures) != 1 {
		t.Fatalf("failure replay calls=%v commits=%v", fixture.repository.failCalls, fixture.repository.failures)
	}
}
