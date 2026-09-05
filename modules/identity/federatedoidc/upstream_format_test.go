package federatedoidc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func exchangedBundle(t *testing.T, fixture flowTestFixture) (*ClaimedAuthorization, *TokenBundle) {
	t.Helper()
	_, claimed, query := fixture.startAndClaim(t)
	setSuccessfulTokenResponse(t, fixture, query.Get("nonce"), nil)
	bundle, err := fixture.flow.ExchangeCode(context.Background(), claimed, ClientCredential{
		Revision: fixture.configuration.ClientSecretRevision, Secret: []byte("client-secret-canary"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return claimed, bundle
}

func logoutConfirmation(claimed *ClaimedAuthorization, at time.Time) fakeLogoutConfirmation {
	return fakeLogoutConfirmation{id: claimed.record.ID, pins: claimed.record.Pins, revokedAt: at}
}

func TestUserInfoArtifactIsExplicitPinnedDefensiveAndDestroyable(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	_, bundle := exchangedBundle(t, fixture)
	request, err := fixture.flow.BuildUserInfoRequest(fixture.configuration, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if request.Endpoint().Kind() != EndpointUserInfo || request.Endpoint().URL() != testUserInfo ||
		string(request.AccessToken()) != "access-token-canary" {
		t.Fatalf("unexpected UserInfo artifact: %v", request)
	}
	copyToken := request.AccessToken()
	copyToken[0] ^= 0xff
	if string(request.AccessToken()) != "access-token-canary" {
		t.Fatal("UserInfo token accessor exposed mutable storage")
	}
	requestCopy := *request
	request.Destroy()
	if len(request.AccessToken()) != 0 || bytes.Contains(requestCopy.AccessToken(), []byte("access-token-canary")) {
		t.Fatal("UserInfo destroy did not zero aliases")
	}

	fixture.configuration.UseUserInfo = false
	if _, err = fixture.flow.BuildUserInfoRequest(fixture.configuration, bundle); !errors.Is(err, ErrUpstreamArtifactRejected) {
		t.Fatalf("disabled UserInfo = %v", err)
	}
}

func TestRevocationArtifactsRequireCommittedLocalLogoutAndExactToken(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	claimed, bundle := exchangedBundle(t, fixture)
	credential := ClientCredential{
		Revision: fixture.configuration.ClientSecretRevision, Secret: []byte("client-secret-canary"),
	}
	confirmation := logoutConfirmation(claimed, flowTestNow)
	request, err := fixture.flow.BuildRevocationRequest(
		fixture.configuration, bundle, credential, TokenAccess, confirmation,
	)
	if err != nil {
		t.Fatal(err)
	}
	if request.Endpoint().Kind() != EndpointRevocation || request.Endpoint().URL() != testRevocation ||
		request.TokenKind() != TokenAccess || string(request.Token()) != "access-token-canary" ||
		request.ClientAuthentication() != ClientSecretBasic || request.ClientID() != "oidc-client" ||
		string(request.ClientSecret()) != "client-secret-canary" {
		t.Fatalf("unexpected revocation artifact: %v", request)
	}
	copyToken := request.Token()
	copySecret := request.ClientSecret()
	copyToken[0] ^= 0xff
	copySecret[0] ^= 0xff
	if string(request.Token()) != "access-token-canary" || string(request.ClientSecret()) != "client-secret-canary" {
		t.Fatal("revocation getters exposed mutable storage")
	}
	requestCopy := *request
	request.Destroy()
	if len(request.Token()) != 0 || len(request.ClientSecret()) != 0 ||
		bytes.Contains(requestCopy.Token(), []byte("access-token-canary")) ||
		bytes.Contains(requestCopy.ClientSecret(), []byte("client-secret-canary")) {
		t.Fatal("revocation destroy did not zero aliases")
	}

	invalidConfirmations := []LocalLogoutConfirmation{
		nil,
		fakeLogoutConfirmation{id: TransactionID{1}, pins: claimed.record.Pins, revokedAt: flowTestNow},
		fakeLogoutConfirmation{id: claimed.record.ID, pins: TransactionPins{}, revokedAt: flowTestNow},
		fakeLogoutConfirmation{id: claimed.record.ID, pins: claimed.record.Pins, revokedAt: flowTestNow.Add(2 * time.Minute)},
	}
	for _, invalid := range invalidConfirmations {
		if _, err = fixture.flow.BuildRevocationRequest(
			fixture.configuration, bundle, credential, TokenAccess, invalid,
		); !errors.Is(err, ErrUpstreamArtifactRejected) {
			t.Fatalf("invalid local logout accepted: %v", err)
		}
	}
	if _, err = fixture.flow.BuildRevocationRequest(
		fixture.configuration, bundle, credential, TokenRefresh, confirmation,
	); !errors.Is(err, ErrUpstreamArtifactRejected) {
		t.Fatalf("missing refresh token accepted: %v", err)
	}
}

func TestRefreshAndClientSecretPostAreExactOptIn(t *testing.T) {
	fixture := newFlowTestFixture(t, func(configuration *AuthorizationConfiguration, _ *FlowPolicy) {
		configuration.AllowRefreshToken = true
		configuration.ExtraScopes = append(configuration.ExtraScopes, "offline_access")
		configuration.Discovery.clientAuthentication = ClientSecretPost
	})
	_, claimed, query := fixture.startAndClaim(t)
	setSuccessfulTokenResponse(t, fixture, query.Get("nonce"), nil)
	bundle, err := fixture.flow.ExchangeCode(context.Background(), claimed, ClientCredential{
		Revision: fixture.configuration.ClientSecretRevision, Secret: []byte("client-secret-canary"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bundle.HasRefreshToken() || !slices.Equal(bundle.Scopes(), []string{"offline_access", "openid", "profile"}) {
		t.Fatalf("refresh metadata missing: %v", bundle)
	}
	request, err := fixture.flow.BuildRevocationRequest(
		fixture.configuration, bundle,
		ClientCredential{Revision: fixture.configuration.ClientSecretRevision, Secret: []byte("client-secret-canary")},
		TokenRefresh, logoutConfirmation(claimed, flowTestNow),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer request.Destroy()
	if request.ClientAuthentication() != ClientSecretPost || string(request.Token()) != "refresh-token-canary" {
		t.Fatalf("unexpected refresh revocation: %v", request)
	}
}

func TestEndSessionArtifactRequiresLocalLogoutAndCanonicalDeploymentRedirect(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	claimed, bundle := exchangedBundle(t, fixture)
	confirmation := logoutConfirmation(claimed, flowTestNow)
	request, err := fixture.flow.BuildEndSessionRequest(
		fixture.configuration, bundle, confirmation,
	)
	if err != nil {
		t.Fatal(err)
	}
	if request.Endpoint().Kind() != EndpointEndSession || request.Endpoint().URL() != testEndSession ||
		request.PostLogoutRedirectURI() != fixture.configuration.PostLogoutRedirectURI ||
		!validOpaque(request.State()) || len(request.IDTokenHint()) == 0 || request.CreatedAt() != flowTestNow {
		t.Fatalf("unexpected end-session artifact: %v", request)
	}
	state := request.State()
	state[0] ^= 0xff
	if bytes.Equal(state, request.State()) {
		t.Fatal("end-session state accessor exposed mutable storage")
	}
	requestCopy := *request
	request.Destroy()
	if len(request.IDTokenHint()) != 0 || len(request.State()) != 0 ||
		bytes.Contains(requestCopy.IDTokenHint(), []byte("ey")) {
		t.Fatal("end-session destroy did not zero aliases")
	}

	for _, invalid := range []string{
		"http://app.example/auth/logout/complete",
		"https://App.example/auth/logout/complete",
		"https://app.example/auth/logout/complete?next=/admin",
		"https://app.example/auth/../logout",
		"https://app.example/other-registered-path",
	} {
		fixture.configuration.PostLogoutRedirectURI = invalid
		if _, err = fixture.flow.BuildEndSessionRequest(
			fixture.configuration, bundle, confirmation,
		); !errors.Is(err, ErrUpstreamArtifactRejected) {
			t.Fatalf("invalid redirect accepted: %q: %v", invalid, err)
		}
	}
	fixture.configuration.PostLogoutRedirectURI = "https://app.example/auth/logout/complete"
	if _, err = fixture.flow.BuildEndSessionRequest(
		fixture.configuration, bundle, nil,
	); !errors.Is(err, ErrUpstreamArtifactRejected) {
		t.Fatalf("missing local logout accepted: %v", err)
	}
}

func TestTokenBundleCopiesShareDestructionState(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	_, bundle := exchangedBundle(t, fixture)
	copyBundle := *bundle
	bundle.Destroy()
	if bundle.HasAccessToken() || copyBundle.HasAccessToken() || len(copyBundle.Scopes()) != 0 {
		t.Fatal("TokenBundle value copy survived destruction")
	}
}

func TestFlowArtifactFormattingNeverLeaksSecretsClaimsOrURLs(t *testing.T) {
	canary := testHostileSentinel
	digest := sha256.Sum256([]byte(canary))
	transactionID := TransactionID(digest)
	pins := TransactionPins{
		ProviderRevision: 1, ConfigurationRevision: 2, SecurityRevision: 3,
		ClientSecretRevision: 4, DiscoveryRevision: 5, JWKSRevision: 6,
		DiscoveryDigest: digest, JWKSDigest: digest,
	}
	bundle := TokenBundle{state: &tokenBundleState{
		transactionID: transactionID, pins: pins, idToken: []byte(canary),
		accessToken: []byte(canary), refreshToken: []byte(canary), scopes: []string{canary},
	}}
	values := []any{
		TransactionState(canary), TransactionFailureReason(canary), EndpointKind(canary),
		TokenEndpointCategory(canary), TokenKind(canary), ProfileField(canary),
		transactionID, pins,
		ProtectedVerifier{KeyVersion: 1, Ciphertext: []byte(canary)},
		PendingTransaction{ID: transactionID, ClientID: canary, RedirectURI: "https://" + canary,
			ReturnPath: "/" + canary, Scopes: []string{canary}, Verifier: ProtectedVerifier{Ciphertext: []byte(canary)}},
		CreateTransactionRequest{Current: PendingTransaction{ClientID: canary}},
		TransactionClaim{StateDigest: digest, BrowserDigest: digest},
		ClaimedTransaction{PendingTransaction: PendingTransaction{ClientID: canary}},
		TransactionFailure{ID: transactionID, Reason: TransactionFailureReason(canary)},
		TransactionCompletion{ID: transactionID, Pins: pins},
		PinnedEndpoint{kind: EndpointKind(canary), url: "https://" + canary, valid: true},
		TokenExchangeRequest{ClientID: canary, ClientSecret: []byte(canary), AuthorizationCode: []byte(canary),
			RedirectURI: "https://" + canary, PKCEVerifier: []byte(canary)},
		TokenEndpointResponse{Category: TokenEndpointCategory(canary), MediaType: canary, Body: []byte(canary)},
		ClientCredential{Revision: 1, Secret: []byte(canary)},
		FlowOptions{RedirectURI: "https://" + canary, PostLogoutRedirectURI: "https://" + canary},
		AuthorizationConfiguration{ClientID: canary, RedirectURI: "https://" + canary,
			PostLogoutRedirectURI: "https://" + canary, ExtraScopes: []string{canary}},
		AuthorizationStart{redirectURL: "https://" + canary, browserHandle: []byte(canary), valid: true},
		StartAuthorizationRequest{ReturnPath: "/" + canary, PreviousBrowserHandle: []byte(canary)},
		callbackRequest{RawQuery: "code=" + canary, BrowserHandle: []byte(canary)},
		&ClaimedAuthorization{code: []byte(canary)},
		ScalarClaimRule{Claim: canary}, ProfileClaimRule{Claim: canary, Field: ProfileField(canary)},
		StringArrayClaimRule{Claim: canary}, ClaimExtractionPolicy{Scalars: []ScalarClaimRule{{Claim: canary}}},
		NamedScalar{Name: canary, Value: canary}, ProfileValue{Field: ProfileField(canary), Value: canary},
		ClaimSet{groups: []string{canary}},
		VerifiedAuthentication{issuer: "https://" + canary, subject: canary, audience: []string{canary},
			claims: ClaimSet{groups: []string{canary}}, valid: true},
		bundle, &bundle,
		UserInfoRequest{endpoint: PinnedEndpoint{url: "https://" + canary}, accessToken: []byte(canary), valid: true},
		RevocationRequest{endpoint: PinnedEndpoint{url: "https://" + canary}, token: []byte(canary),
			clientID: canary, clientSecret: []byte(canary), valid: true},
		EndSessionRequest{endpoint: PinnedEndpoint{url: "https://" + canary}, idTokenHint: []byte(canary),
			postLogoutRedirectURI: "https://" + canary, state: []byte(canary), valid: true,
			redirectURL: "https://" + canary + "/end?id_token_hint=" + canary},
		StoredEndSessionBuildRequest{EndpointURL: "https://" + canary, IDTokenHint: []byte(canary)},
	}
	userinfo := UserInfoRequest{endpoint: PinnedEndpoint{url: "https://" + canary}, accessToken: []byte(canary), valid: true}
	revocation := RevocationRequest{endpoint: PinnedEndpoint{url: "https://" + canary}, token: []byte(canary),
		clientID: canary, clientSecret: []byte(canary), valid: true}
	endSession := EndSessionRequest{endpoint: PinnedEndpoint{url: "https://" + canary}, idTokenHint: []byte(canary),
		postLogoutRedirectURI: "https://" + canary, state: []byte(canary), valid: true,
		redirectURL: "https://" + canary + "/end?id_token_hint=" + canary}
	values = append(values, &userinfo, &revocation, &endSession)
	encodedCanary := fmt.Sprintf("%x", []byte(canary))
	for _, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			formatted := fmt.Sprintf(format, value)
			if strings.Contains(formatted, canary) || strings.Contains(formatted, encodedCanary) {
				t.Fatalf("%T with %s leaked: %s", value, format, formatted)
			}
		}
	}
	for _, err := range []error{
		ErrInvalidFlowOptions, ErrAuthorizationRejected, ErrTransactionPersistence,
		ErrCallbackRejected, ErrTokenExchangeFailed, ErrTokenResponseRejected,
		ErrIDTokenRejected, ErrJWKSRevisionRestart, ErrClaimExtractionRejected,
		ErrUpstreamArtifactRejected,
	} {
		if strings.Contains(fmt.Sprintf("%#v", err), canary) {
			t.Fatalf("error leaked: %v", err)
		}
	}
}
