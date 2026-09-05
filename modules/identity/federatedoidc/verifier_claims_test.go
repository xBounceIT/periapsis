package federatedoidc

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func defaultClaimPolicy() ClaimExtractionPolicy {
	return ClaimExtractionPolicy{
		Scalars:  []ScalarClaimRule{{Claim: "preferred_username", Required: true}},
		Profiles: []ProfileClaimRule{{Claim: "email", Field: ProfileEmail, Required: true}},
		Groups:   &StringArrayClaimRule{Claim: "groups", Required: true},
		ACR:      &ScalarClaimRule{Claim: "acr"},
		AMR:      &StringArrayClaimRule{Claim: "amr"},
	}
}

func exchangeSignedClaims(
	t *testing.T,
	fixture flowTestFixture,
	mutate func(map[string]any),
) (*ClaimedAuthorization, *TokenBundle, string) {
	t.Helper()
	_, claimed, query := fixture.startAndClaim(t)
	claims := validIDTokenClaims(query.Get("nonce"))
	if mutate != nil {
		mutate(claims)
	}
	idToken := signIDToken(t, claims, nil)
	fixture.tokenEndpoint.response = successfulTokenHTTP(tokenResponseDocument(t, idToken, false))
	bundle, err := fixture.flow.ExchangeCode(context.Background(), claimed, ClientCredential{
		Revision: fixture.configuration.ClientSecretRevision, Secret: []byte("client-secret-canary"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return claimed, bundle, query.Get("nonce")
}

func TestVerifyIDTokenValidatesProofAndExtractsDefensiveClaims(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	_, claimed, query := fixture.startAndClaim(t)
	claims := validIDTokenClaims(query.Get("nonce"))
	accessHash := sha512.Sum512([]byte("access-token-canary"))
	claims["at_hash"] = base64.RawURLEncoding.EncodeToString(accessHash[:sha512.Size/2])
	idToken := signIDToken(t, claims, nil)
	fixture.tokenEndpoint.response = successfulTokenHTTP(tokenResponseDocument(t, idToken, false))
	bundle, err := fixture.flow.ExchangeCode(context.Background(), claimed, ClientCredential{
		Revision: fixture.configuration.ClientSecretRevision, Secret: []byte("client-secret-canary"),
	})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := fixture.flow.VerifyIDToken(context.Background(), claimed, bundle, defaultClaimPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if proof.Issuer() != testIssuer || proof.Subject() != "subject-exact" ||
		!slices.Equal(proof.Audience(), []string{"oidc-client"}) ||
		proof.IssuedAt() != flowTestNow || proof.ExpiresAt() != flowTestNow.Add(10*time.Minute) ||
		proof.AuthenticatedAt() != flowTestNow.Add(-2*time.Minute) ||
		proof.Completion().ID != claimed.TransactionID() ||
		proof.Completion().ExpectedVersion != 2 || proof.Completion().Pins != transactionPins(fixture.configuration) ||
		proof.Completion().ReturnPath != "/incidents?view=mine" {
		t.Fatalf("unexpected proof: %v", proof)
	}
	extracted := proof.Claims()
	if value, ok := extracted.Scalar("preferred_username"); !ok || value != "analyst" {
		t.Fatalf("scalar = %q, %v", value, ok)
	}
	if value, ok := extracted.Profile(ProfileEmail); !ok || value != "analyst@example.test" {
		t.Fatalf("profile = %q, %v", value, ok)
	}
	if extracted.ACR() != "urn:periapsis:assurance:mfa" ||
		!slices.Equal(extracted.Groups(), []string{"blue-team", "incident-command"}) ||
		!slices.Equal(extracted.AMR(), []string{"mfa", "pwd"}) {
		t.Fatalf("claims = %v", extracted)
	}
	audience := proof.Audience()
	audience[0] = "mutated"
	groups := extracted.Groups()
	groups[0] = "mutated"
	if proof.Audience()[0] != "oidc-client" || proof.Claims().Groups()[0] != "blue-team" {
		t.Fatal("proof accessors exposed mutable storage")
	}
	if _, err = fixture.flow.VerifyIDToken(context.Background(), claimed, bundle, defaultClaimPolicy()); !errors.Is(err, ErrIDTokenRejected) {
		t.Fatalf("second verification = %v", err)
	}
}

func TestIDTokenSecurityClaimCorpusFailsClosedAndDestroysTokens(t *testing.T) {
	tests := map[string]func(map[string]any){
		"issuer":       func(value map[string]any) { value["iss"] = "https://other.example" },
		"audience":     func(value map[string]any) { value["aud"] = "other-client" },
		"multi no azp": func(value map[string]any) { value["aud"] = []string{"oidc-client", "api"} },
		"wrong azp": func(value map[string]any) {
			value["aud"] = []string{"oidc-client", "api"}
			value["azp"] = "api"
		},
		"present azp":   func(value map[string]any) { value["azp"] = "other-client" },
		"nonce":         func(value map[string]any) { value["nonce"] = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA" },
		"subject empty": func(value map[string]any) { value["sub"] = "" },
		"bidi subject":  func(value map[string]any) { value["sub"] = "subject\u202eexact" },
		"expired": func(value map[string]any) {
			value["iat"] = flowTestNow.Add(-20 * time.Minute).Unix()
			value["exp"] = flowTestNow.Add(-2 * time.Minute).Unix()
		},
		"old iat": func(value map[string]any) {
			value["iat"] = flowTestNow.Add(-11 * time.Minute).Unix()
			value["exp"] = flowTestNow.Add(30 * time.Minute).Unix()
		},
		"future iat":          func(value map[string]any) { value["iat"] = flowTestNow.Add(2 * time.Minute).Unix() },
		"future nbf":          func(value map[string]any) { value["nbf"] = flowTestNow.Add(2 * time.Minute).Unix() },
		"old auth":            func(value map[string]any) { value["auth_time"] = flowTestNow.Add(-13 * time.Hour).Unix() },
		"missing auth":        func(value map[string]any) { delete(value, "auth_time") },
		"numeric date string": func(value map[string]any) { value["iat"] = "1787655600" },
		"duplicate audience":  func(value map[string]any) { value["aud"] = []string{"oidc-client", "oidc-client"} },
		"bad access hash":     func(value map[string]any) { value["at_hash"] = "wrong-hash" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newFlowTestFixture(t, nil)
			claimed, bundle, _ := exchangeSignedClaims(t, fixture, mutate)
			if _, err := fixture.flow.VerifyIDToken(context.Background(), claimed, bundle, defaultClaimPolicy()); !errors.Is(err, ErrIDTokenRejected) {
				t.Fatalf("got %v", err)
			}
			if bundle.HasAccessToken() || claimed.stage.Load() != claimedStageFailed {
				t.Fatal("failed token remained usable")
			}
		})
	}
}

func TestIDTokenCompactAndSignatureHostileCorpus(t *testing.T) {
	tests := map[string]func(*testing.T, string) string{
		"unknown kid": func(t *testing.T, token string) string {
			_, payload, _ := splitCompactToken(t, token)
			return signRawIDToken(t, payload, func(options *jose.SignerOptions) {
				options.WithHeader("kid", "unknown-key")
			})
		},
		"invalid signature": func(t *testing.T, token string) string {
			header, payload, signature := splitCompactToken(t, token)
			signature[0] ^= 0x80
			return encodeCompactParts(header, payload, signature)
		},
		"padded header": func(t *testing.T, token string) string {
			header, payload, signature := splitCompactToken(t, token)
			return base64.RawURLEncoding.EncodeToString(header) + "=." +
				base64.RawURLEncoding.EncodeToString(payload) + "." +
				base64.RawURLEncoding.EncodeToString(signature)
		},
		"duplicate header": func(t *testing.T, token string) string {
			_, payload, signature := splitCompactToken(t, token)
			return encodeCompactParts([]byte(`{"alg":"EdDSA","alg":"EdDSA","kid":"key-ed25519-primary","typ":"JWT"}`), payload, signature)
		},
		"forbidden jku": func(t *testing.T, token string) string {
			_, payload, signature := splitCompactToken(t, token)
			return encodeCompactParts([]byte(`{"alg":"EdDSA","kid":"key-ed25519-primary","typ":"JWT","jku":"https://evil.example/jwks"}`), payload, signature)
		},
		"duplicate payload": func(t *testing.T, token string) string {
			_, payload, _ := splitCompactToken(t, token)
			payload = append(payload[:len(payload)-1], []byte(`,"sub":"second-subject"}`)...)
			return signRawIDToken(t, payload, nil)
		},
		"algorithm key mismatch": func(t *testing.T, token string) string {
			_, payload, signature := splitCompactToken(t, token)
			return encodeCompactParts([]byte(`{"alg":"RS256","kid":"key-ed25519-primary","typ":"JWT"}`), payload, signature)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newFlowTestFixture(t, nil)
			_, claimed, query := fixture.startAndClaim(t)
			base := signIDToken(t, validIDTokenClaims(query.Get("nonce")), nil)
			token := mutate(t, base)
			fixture.tokenEndpoint.response = successfulTokenHTTP(tokenResponseDocument(t, token, false))
			bundle, err := fixture.flow.ExchangeCode(context.Background(), claimed, ClientCredential{
				Revision: fixture.configuration.ClientSecretRevision, Secret: []byte("client-secret-canary"),
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = fixture.flow.VerifyIDToken(context.Background(), claimed, bundle, defaultClaimPolicy())
			if name == "unknown kid" {
				if !errors.Is(err, ErrJWKSRevisionRestart) {
					t.Fatalf("got %v", err)
				}
			} else if !errors.Is(err, ErrIDTokenRejected) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func encodeCompactParts(header, payload, signature []byte) string {
	return base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(signature)
}

func TestConfiguredFiveMinuteNBFSkewRemainsLocallyDecisive(t *testing.T) {
	fixture := newFlowTestFixture(t, func(_ *AuthorizationConfiguration, policy *FlowPolicy) {
		policy.ClockSkew = 5 * time.Minute
	})
	claimed, bundle, _ := exchangeSignedClaims(t, fixture, func(value map[string]any) {
		value["nbf"] = flowTestNow.Add(5 * time.Minute).Unix()
		value["exp"] = flowTestNow.Add(15 * time.Minute).Unix()
	})
	if _, err := fixture.flow.VerifyIDToken(context.Background(), claimed, bundle, defaultClaimPolicy()); err != nil {
		t.Fatalf("configured boundary rejected by library clock: %v", err)
	}

	fixture = newFlowTestFixture(t, func(_ *AuthorizationConfiguration, policy *FlowPolicy) {
		policy.ClockSkew = 5 * time.Minute
	})
	claimed, bundle, _ = exchangeSignedClaims(t, fixture, func(value map[string]any) {
		value["nbf"] = flowTestNow.Add(5*time.Minute + time.Second).Unix()
		value["exp"] = flowTestNow.Add(15 * time.Minute).Unix()
	})
	if _, err := fixture.flow.VerifyIDToken(context.Background(), claimed, bundle, defaultClaimPolicy()); !errors.Is(err, ErrIDTokenRejected) {
		t.Fatalf("above configured skew accepted: %v", err)
	}
}

func TestClaimExtractionRejectsWrongTypesDuplicatesAndSecurityRemapping(t *testing.T) {
	tests := map[string]struct {
		mutateClaims func(map[string]any)
		mutatePolicy func(*ClaimExtractionPolicy)
	}{
		"scalar number":    {mutateClaims: func(value map[string]any) { value["preferred_username"] = 7 }},
		"groups scalar":    {mutateClaims: func(value map[string]any) { value["groups"] = "blue-team" }},
		"groups mixed":     {mutateClaims: func(value map[string]any) { value["groups"] = []any{"blue-team", 7} }},
		"groups duplicate": {mutateClaims: func(value map[string]any) { value["groups"] = []string{"blue-team", "blue-team"} }},
		"missing required": {mutateClaims: func(value map[string]any) { delete(value, "email") }},
		"bidi profile":     {mutateClaims: func(value map[string]any) { value["email"] = "analyst\u2066@example.test" }},
		"duplicate policy": {mutatePolicy: func(value *ClaimExtractionPolicy) {
			value.Profiles[0].Claim = "preferred_username"
		}},
		"audience as groups": {mutatePolicy: func(value *ClaimExtractionPolicy) { value.Groups.Claim = "aud" }},
		"amr as scalar":      {mutatePolicy: func(value *ClaimExtractionPolicy) { value.Scalars[0].Claim = "amr" }},
		"acr as scalar":      {mutatePolicy: func(value *ClaimExtractionPolicy) { value.Scalars[0].Claim = "acr" }},
		"subject as acr":     {mutatePolicy: func(value *ClaimExtractionPolicy) { value.ACR.Claim = "sub" }},
		"subject as amr":     {mutatePolicy: func(value *ClaimExtractionPolicy) { value.AMR.Claim = "sub" }},
		"custom claim as amr": {mutatePolicy: func(value *ClaimExtractionPolicy) {
			value.AMR.Claim = "custom_amr"
		}},
		"required acr assurance": {mutatePolicy: func(value *ClaimExtractionPolicy) {
			value.ACR.Required = true
		}},
		"required amr assurance": {mutatePolicy: func(value *ClaimExtractionPolicy) {
			value.AMR.Required = true
		}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newFlowTestFixture(t, nil)
			claimed, bundle, _ := exchangeSignedClaims(t, fixture, test.mutateClaims)
			policy := defaultClaimPolicy()
			if test.mutatePolicy != nil {
				test.mutatePolicy(&policy)
			}
			if _, err := fixture.flow.VerifyIDToken(context.Background(), claimed, bundle, policy); !errors.Is(err, ErrClaimExtractionRejected) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestMalformedOrMissingTrustClaimsYieldPrimaryOnlyProjection(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"duplicate amr": func(value map[string]any) { value["amr"] = []string{"mfa", "mfa"} },
		"scalar amr":    func(value map[string]any) { value["amr"] = "mfa" },
		"empty amr":     func(value map[string]any) { value["amr"] = []string{} },
		"array acr":     func(value map[string]any) { value["acr"] = []string{"trusted"} },
		"bidi acr":      func(value map[string]any) { value["acr"] = "trusted\u202e" },
		"missing both": func(value map[string]any) {
			delete(value, "acr")
			delete(value, "amr")
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newFlowTestFixture(t, nil)
			claimed, bundle, _ := exchangeSignedClaims(t, fixture, mutate)
			proof, err := fixture.flow.VerifyIDToken(
				context.Background(), claimed, bundle, defaultClaimPolicy(),
			)
			if err != nil {
				t.Fatalf("VerifyIDToken() error = %v", err)
			}
			if proof.Claims().ACR() != "" || len(proof.Claims().AMR()) != 0 {
				t.Fatalf("untrusted assurance projected: %+v", proof.Claims())
			}
		})
	}
}

func TestIDTokenVerificationRejectsClaimedConfigurationDrift(t *testing.T) {
	fixture := newFlowTestFixture(t, nil)
	claimed, bundle, _ := exchangeSignedClaims(t, fixture, nil)
	claimed.configuration.UseUserInfo = false
	if _, err := fixture.flow.VerifyIDToken(
		context.Background(), claimed, bundle, defaultClaimPolicy(),
	); !errors.Is(err, ErrIDTokenRejected) {
		t.Fatalf("configuration-drifted proof = %v", err)
	}
}
