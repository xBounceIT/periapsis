package federatedoidc

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
)

func TestTakeSessionMaterialMovesOnlyUsefulTokensAndIsOneShot(t *testing.T) {
	t.Parallel()
	fixture := newFlowTestFixture(t, func(configuration *AuthorizationConfiguration, _ *FlowPolicy) {
		configuration.AllowRefreshToken = true
		configuration.ExtraScopes = append(configuration.ExtraScopes, "offline_access")
	})
	begin := testAuthorizationBegin(31)
	idToken := []byte("id-token-session-canary")
	accessToken := []byte("access-token-must-be-cleared")
	refreshToken := []byte("refresh-token-session-canary")
	bundle := &TokenBundle{state: &tokenBundleState{
		owner: fixture.flow, transactionID: TransactionID{1}, materialID: begin.OperationRunID,
		pins: transactionPins(fixture.configuration), useUserInfo: fixture.configuration.UseUserInfo,
		postLogoutRedirectURI: fixture.configuration.PostLogoutRedirectURI,
		idToken:               idToken, accessToken: accessToken, refreshToken: refreshToken,
		tokenType: "Bearer", scopes: []string{RequiredScopeOpenID, "offline_access"},
		accessExpiry: flowTestNow.Add(time.Hour),
	}}

	material, err := fixture.flow.TakeSessionMaterial(fixture.configuration, bundle)
	if err != nil || material == nil || material.MaterialID() != begin.OperationRunID ||
		!material.HasIDToken() || !material.HasRefreshToken() {
		t.Fatalf("TakeSessionMaterial() = %s, %v", material, err)
	}
	if bundle.HasAccessToken() || bundle.HasRefreshToken() || !allZeroBytes(accessToken) {
		t.Fatal("access token survived session-material transfer")
	}
	tokens, ok := material.TakeTokens()
	if !ok || string(tokens.IDToken) != "id-token-session-canary" ||
		string(tokens.RefreshToken) != "refresh-token-session-canary" ||
		!tokens.AccessExpiresAt.Equal(flowTestNow.Add(time.Hour)) {
		t.Fatalf("TakeTokens() = %s, %t", tokens, ok)
	}
	if material.MaterialID() != ([16]byte{}) || material.HasIDToken() || material.HasRefreshToken() {
		t.Fatal("consumed session material retained ownership metadata")
	}
	if replay, replayed := material.TakeTokens(); replayed || replay != nil {
		t.Fatal("session material could be consumed twice")
	}
	tokens.Destroy()
	if !allZeroBytes(idToken) || !allZeroBytes(refreshToken) || len(tokens.IDToken) != 0 || len(tokens.RefreshToken) != 0 {
		t.Fatal("owned token material was not zeroed")
	}
}

func TestTakeSessionMaterialDropsIDTokenWithoutEndSessionAndNeverTransfersAccessToken(t *testing.T) {
	t.Parallel()
	fixture := newFlowTestFixture(t, func(configuration *AuthorizationConfiguration, _ *FlowPolicy) {
		configuration.Discovery.endpoints.EndSession = ""
		configuration.Discovery.targets.endSession = federatedhttp.Target{}
		configuration.Discovery.targets.count--
	})
	idToken := []byte("unused-id-token")
	accessToken := []byte("never-persist-access-token")
	bundle := &TokenBundle{state: &tokenBundleState{
		owner: fixture.flow, transactionID: TransactionID{2}, materialID: testAuthorizationBegin(32).OperationRunID,
		pins: transactionPins(fixture.configuration), useUserInfo: fixture.configuration.UseUserInfo,
		postLogoutRedirectURI: fixture.configuration.PostLogoutRedirectURI,
		idToken:               idToken, accessToken: accessToken, tokenType: "Bearer",
		scopes: []string{RequiredScopeOpenID}, accessExpiry: flowTestNow.Add(time.Hour),
	}}
	material, err := fixture.flow.TakeSessionMaterial(fixture.configuration, bundle)
	if err != nil || material != nil {
		t.Fatalf("TakeSessionMaterial() = %s, %v", material, err)
	}
	if !allZeroBytes(idToken) || !allZeroBytes(accessToken) || bundle.HasAccessToken() {
		t.Fatal("unused or access token material survived")
	}
}

func TestTakeSessionMaterialRejectsConfigurationDriftWithoutReleasingTokens(t *testing.T) {
	t.Parallel()
	fixture := newFlowTestFixture(t, nil)
	bundle := &TokenBundle{state: &tokenBundleState{
		owner: fixture.flow, transactionID: TransactionID{3}, materialID: testAuthorizationBegin(33).OperationRunID,
		pins: transactionPins(fixture.configuration), useUserInfo: fixture.configuration.UseUserInfo,
		postLogoutRedirectURI: fixture.configuration.PostLogoutRedirectURI,
		idToken:               []byte("id-token-drift-canary"), accessToken: []byte("access-token-drift-canary"),
	}}
	drifted := fixture.configuration
	drifted.ClientSecretRevision++
	if material, err := fixture.flow.TakeSessionMaterial(drifted, bundle); err == nil || material != nil {
		t.Fatalf("configuration drift accepted: %s, %v", material, err)
	}
	if !bundle.HasAccessToken() {
		t.Fatal("rejected transfer mutated the source bundle")
	}
	bundle.Destroy()
}

func TestOIDCSessionMaterialFormattingIsRedacted(t *testing.T) {
	t.Parallel()
	const canary = "oidc-session-owned-canary"
	material := &SessionMaterial{state: &sessionMaterialState{
		materialID: testAuthorizationBegin(34).OperationRunID,
		idToken:    []byte(canary), refreshToken: []byte(canary),
	}}
	tokens := &OwnedSessionTokens{IDToken: []byte(canary), RefreshToken: []byte(canary)}
	for _, value := range []any{material, tokens} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if output := fmt.Sprintf(format, value); strings.Contains(output, canary) {
				t.Fatalf("%T leaked with %s: %s", value, format, output)
			}
		}
	}
	material.Destroy()
	tokens.Destroy()
}

func allZeroBytes(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
