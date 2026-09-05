package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/services/api/internal/federatedauth"
	"github.com/periapsis-im/periapsis/services/api/internal/platformoidcauth"
)

func TestFederatedAuthRepositoryRestoresExactDirectOIDCConfiguration(t *testing.T) {
	t.Parallel()
	record := platformOIDCDirectConfigurationWireFixture(t)
	authority := platformOIDCDirectStartAuthorityFixture()
	queries := make([]string, 0, 3)
	repository := &FederatedAuthRepository{
		oidcClient: platformOIDCDirectConfigurationClient(t),
		queryer: federatedAuthQueryerStub{query: func(
			_ context.Context,
			query string,
			arguments ...any,
		) pgx.Row {
			queries = append(queries, query)
			if len(arguments) != 1 {
				t.Fatalf("arguments = %d", len(arguments))
			}
			payload, ok := arguments[0].([]byte)
			if !ok {
				t.Fatalf("payload = %T", arguments[0])
			}
			switch query {
			case beginPlatformOIDCDirectConfigurationSQL:
				if string(payload) != `{"loginKey":"corp"}` {
					t.Fatalf("begin payload = %s", payload)
				}
				return platformOIDCDirectJSONRow(t, record)
			case resolvePlatformOIDCDirectConfigurationSQL:
				var lookup platformOIDCDirectCallbackConfigurationLookupWire
				if err := json.Unmarshal(payload, &lookup); err != nil || lookup.ExpectedVersion != 2 ||
					!validPlatformOIDCDigest(lookup.TransactionID) ||
					!validPlatformOIDCDigest(lookup.BrowserCapabilityDigest) ||
					lookup.Pins.LoginPolicyRevision != record.Pins.LoginPolicyRevision {
					t.Fatalf("callback payload = %s, %v", payload, err)
				}
				return platformOIDCDirectJSONRow(t, platformOIDCDirectCallbackConfigurationWire{
					Pins: record.Pins, ReturnPath: authority.ReturnPath, Configuration: record,
				})
			default:
				t.Fatalf("query = %q", query)
				return nil
			}
		}},
	}

	grant, err := repository.BeginDirectOIDCLogin(context.Background(), authority)
	if err != nil || grant.Authority != authority || grant.Pins.Provider.ProviderID == (identity.EntityID{}) {
		t.Fatalf("BeginDirectOIDCLogin() = %s, %v", grant, err)
	}
	start, err := repository.LoadDirectOIDCStartConfiguration(context.Background(), grant)
	if err != nil || start.Grant != grant ||
		start.Configuration.Authorization.Authority != federatedoidc.DirectPlatformCeremonyAuthority ||
		start.Configuration.Authorization.PlanRevision != grant.Pins.PlanRevision ||
		start.Configuration.Authorization.Discovery.Revision() != grant.Pins.DiscoveryRevision ||
		start.Configuration.Authorization.JWKS.Revision() != grant.Pins.JWKSRevision ||
		start.Configuration.Authorization.JWKS.DiscoveryDigest() != grant.Pins.DiscoveryDigest {
		t.Fatalf("LoadDirectOIDCStartConfiguration() = %s, %v", start, err)
	}

	transactionID := federatedoidc.TransactionID(sha256.Sum256([]byte("direct-callback-transaction")))
	browserCapability := platformoidcauth.DirectBrowserCapabilityDigest(
		sha256.Sum256([]byte("direct-callback-browser-capability")),
	)
	lookup := platformoidcauth.DirectOIDCCallbackConfigurationLookup{
		Transaction: federatedoidc.CallbackConfigurationLookup{
			TransactionID: transactionID, ExpectedVersion: 2,
			Pins:       platformOIDCDirectTransactionPins(grant.Pins),
			ReturnPath: authority.ReturnPath,
		},
		BrowserCapabilityDigest: browserCapability,
	}
	callback, err := repository.ResolveDirectOIDCCallbackConfiguration(context.Background(), lookup)
	if err != nil || callback.Lookup != lookup || callback.Pins != grant.Pins ||
		callback.ReturnPath != authority.ReturnPath ||
		callback.Configuration.Authorization.Discovery.Digest() != grant.Pins.DiscoveryDigest ||
		callback.Configuration.Authorization.JWKS.Digest() != grant.Pins.JWKSDigest {
		t.Fatalf("ResolveDirectOIDCCallbackConfiguration() = %s, %v", callback, err)
	}
	if len(queries) != 3 || queries[0] != beginPlatformOIDCDirectConfigurationSQL ||
		queries[1] != beginPlatformOIDCDirectConfigurationSQL ||
		queries[2] != resolvePlatformOIDCDirectConfigurationSQL {
		t.Fatalf("queries = %#v", queries)
	}
}

func TestDirectOIDCConfigurationWireRejectsAuthorityAndProjectionDrift(t *testing.T) {
	t.Parallel()
	base := platformOIDCDirectConfigurationWireFixture(t)
	repository := &FederatedAuthRepository{oidcClient: platformOIDCDirectConfigurationClient(t)}
	tests := map[string]func(*platformOIDCDirectConfigurationWire){
		"missing plan revision": func(value *platformOIDCDirectConfigurationWire) {
			value.Pins.PlanRevision = 0
		},
		"authorization revision drift": func(value *platformOIDCDirectConfigurationWire) {
			value.Authorization.SecurityRevision++
		},
		"floor drift": func(value *platformOIDCDirectConfigurationWire) {
			value.PlatformFloor.Revision++
		},
		"new account admission": func(value *platformOIDCDirectConfigurationWire) {
			value.RuntimeAdmissionPolicy.AccountMode = "jit"
		},
		"userinfo": func(value *platformOIDCDirectConfigurationWire) {
			value.UserInfoClaims.ACR = &federatedoidc.ScalarClaimRule{Claim: "acr"}
		},
		"discovery digest": func(value *platformOIDCDirectConfigurationWire) {
			value.DiscoveryDigest[0] ^= 0xff
		},
		"jwks document": func(value *platformOIDCDirectConfigurationWire) {
			value.JWKSDocument[0] ^= 0xff
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := clonePlatformOIDCDirectConfigurationWire(base)
			mutate(&candidate)
			defer clearPlatformOIDCDirectConfigurationWire(&candidate)
			if configuration, pins, err := repository.platformOIDCDirectConfigurationFromWire(candidate); err == nil || !reflect.DeepEqual(configuration, platformoidcauth.DirectOIDCConfiguration{}) ||
				pins != (platformoidcauth.DirectOIDCConfigurationPins{}) {
				t.Fatalf("platformOIDCDirectConfigurationFromWire() = %s, %s, %v", configuration, pins, err)
			}
		})
	}
}

func TestDirectOIDCConfigurationWireAllowsOptionalRefresh(t *testing.T) {
	t.Parallel()
	record := platformOIDCDirectConfigurationWireFixture(t)
	record.Authorization.AllowRefreshToken = true
	record.Authorization.ExtraScopes = []string{"offline_access"}
	repository := &FederatedAuthRepository{oidcClient: platformOIDCDirectConfigurationClient(t)}
	configuration, pins, err := repository.platformOIDCDirectConfigurationFromWire(record)
	if err != nil || !configuration.Authorization.AllowRefreshToken ||
		!reflect.DeepEqual(configuration.Authorization.ExtraScopes, []string{"offline_access"}) ||
		configuration.Authorization.Pins() != platformOIDCDirectTransactionPins(pins) {
		t.Fatalf("platformOIDCDirectConfigurationFromWire() = %s, %s, %v", configuration, pins, err)
	}
}

func TestDirectOIDCConfigurationRepositoryFailsClosedBeforeQuery(t *testing.T) {
	t.Parallel()
	called := false
	repository := &FederatedAuthRepository{
		oidcClient: platformOIDCDirectConfigurationClient(t),
		queryer: federatedAuthQueryerStub{query: func(context.Context, string, ...any) pgx.Row {
			called = true
			return platformOIDCDirectJSONRow(t, platformOIDCDirectConfigurationWireFixture(t))
		}},
	}
	authority := platformOIDCDirectStartAuthorityFixture()
	authority.Lookup.LoginKey = "INVALID"
	if grant, err := repository.BeginDirectOIDCLogin(context.Background(), authority); err == nil ||
		grant != (platformoidcauth.DirectOIDCStartGrant{}) || called {
		t.Fatalf("BeginDirectOIDCLogin() = %s, %v, called=%t", grant, err, called)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if grant, err := repository.BeginDirectOIDCLogin(cancelled, platformOIDCDirectStartAuthorityFixture()); err == nil || grant != (platformoidcauth.DirectOIDCStartGrant{}) || called {
		t.Fatalf("cancelled BeginDirectOIDCLogin() = %s, %v, called=%t", grant, err, called)
	}
}

func platformOIDCDirectConfigurationWireFixture(t *testing.T) platformOIDCDirectConfigurationWire {
	t.Helper()
	providerID := uuid.Must(uuid.NewV7())
	floorID := uuid.Must(uuid.NewV7())
	issuer := "https://idp.example.test/direct"
	discovery := platformOIDCDirectJSON(t, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"jwks_uri":                              "https://keys.example.test/direct/jwks",
		"response_types_supported":              []string{federatedoidc.ResponseTypeCode},
		"response_modes_supported":              []string{federatedoidc.ResponseModeQuery},
		"grant_types_supported":                 []string{federatedoidc.GrantAuthorizationCode},
		"code_challenge_methods_supported":      []string{federatedoidc.CodeChallengeS256},
		"token_endpoint_auth_methods_supported": []string{string(federatedoidc.ClientSecretBasic)},
		"subject_types_supported":               []string{"public"},
		"scopes_supported":                      []string{federatedoidc.RequiredScopeOpenID},
		"id_token_signing_alg_values_supported": []string{string(federatedoidc.SigningRS256)},
	})
	modulus := make([]byte, 256)
	modulus[0], modulus[len(modulus)-1] = 0x80, 0x01
	jwks := platformOIDCDirectJSON(t, map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "kid": "direct-key-1", "use": "sig", "key_ops": []string{"verify"},
		"alg": string(federatedoidc.SigningRS256),
		"n":   base64.RawURLEncoding.EncodeToString(modulus), "e": "AQAB",
	}}})
	retrievedAt := time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)
	pins := platformOIDCDirectPinsWire{
		Provider:         federatedProviderBindingWire{Scope: federatedPlatformProviderScopeWire, ProviderID: providerID.String()},
		ProviderRevision: 2, LoginPolicyRevision: 3, ConfigurationRevision: 4,
		SecurityRevision: 5, PlanRevision: 6, AssurancePolicyRevision: 7,
		PlatformFloorPolicyID: floorID.String(), PlatformFloorPolicyRevision: 8,
		ClientSecretRevision: 9, DiscoveryRevision: 10, DiscoveryDigest: sha256Bytes(discovery),
		JWKSRevision: 11, JWKSDigest: sha256Bytes(jwks),
	}
	return platformOIDCDirectConfigurationWire{
		Authorization: platformOIDCDirectAuthorizationWire{
			Provider: pins.Provider, ProviderRevision: pins.ProviderRevision,
			LoginPolicyRevision:   pins.LoginPolicyRevision,
			ConfigurationRevision: pins.ConfigurationRevision, SecurityRevision: pins.SecurityRevision,
			AssurancePolicyRevision:     pins.AssurancePolicyRevision,
			PlatformFloorPolicyID:       pins.PlatformFloorPolicyID,
			PlatformFloorPolicyRevision: pins.PlatformFloorPolicyRevision,
			ClientSecretRevision:        pins.ClientSecretRevision, ClientID: "direct-client",
			RedirectURI: "https://app.example.test/api/v1/auth/platform/oidc/callback",
			ExtraScopes: []string{},
		},
		Issuer: issuer, DiscoveryRevision: pins.DiscoveryRevision,
		DiscoveryDocument: discovery, DiscoveryDigest: append([]byte(nil), pins.DiscoveryDigest...),
		DiscoveryCache: federatedCacheMetadataWire{
			RetrievedAt: retrievedAt, FreshUntil: retrievedAt.Add(time.Hour), Cacheable: true,
		},
		DiscoveryPolicy: oidcTrustPolicyWire{
			ClientAuthentication: string(federatedoidc.ClientSecretBasic),
			SigningAlgorithms:    []string{string(federatedoidc.SigningRS256)},
		},
		JWKSDocument: jwks, JWKSDigest: append([]byte(nil), pins.JWKSDigest...),
		JWKSRevision: pins.JWKSRevision,
		JWKSCache: federatedCacheMetadataWire{
			RetrievedAt: retrievedAt, FreshUntil: retrievedAt.Add(time.Hour), Cacheable: true,
		},
		Pins: pins,
		PlatformFloor: assurancePolicyWire{
			ID: floorID.String(), Revision: int64(pins.PlatformFloorPolicyRevision), Level: "primary",
		},
		RuntimeAdmissionPolicy: platformOIDCDirectAdmissionPolicyWire{
			AccountMode: string(platformoidcauth.AccountModeExistingIdentity),
		},
	}
}

func platformOIDCDirectStartAuthorityFixture() platformoidcauth.DirectOIDCStartAuthority {
	digest := func(value byte) [sha256.Size]byte {
		var result [sha256.Size]byte
		result[0], result[len(result)-1] = value, value^0xff
		return result
	}
	return platformoidcauth.DirectOIDCStartAuthority{
		Lookup: platformoidcauth.DirectOIDCStartLookup{
			OperationRunID: identity.EntityID(uuid.Must(uuid.NewV7())), LoginKey: "corp",
			ReceiptDigest:           platformoidcauth.DirectStartReceiptDigest(digest(1)),
			NetworkDigest:           platformoidcauth.DirectNetworkRateDigest(digest(2)),
			AccountDigest:           platformoidcauth.DirectAccountRateDigest(digest(3)),
			ProviderDigest:          platformoidcauth.DirectProviderRateDigest(digest(4)),
			BrowserCapabilityDigest: platformoidcauth.DirectBrowserCapabilityDigest(digest(5)),
		},
		ReturnPath: "/app",
		Audit: platformoidcauth.DirectAuditContext{
			RequestID:     identity.EntityID(uuid.Must(uuid.NewV7())),
			CorrelationID: identity.EntityID(uuid.Must(uuid.NewV7())),
			RemoteAddress: netip.MustParseAddr("203.0.113.10"), UserAgent: "Periapsis test browser",
		},
	}
}

func platformOIDCDirectTransactionPins(
	value platformoidcauth.DirectOIDCConfigurationPins,
) federatedoidc.TransactionPins {
	return federatedoidc.TransactionPins{
		Authority: federatedoidc.DirectPlatformCeremonyAuthority,
		Provider:  value.Provider, ProviderRevision: value.ProviderRevision,
		PlatformLoginRevision: value.PlatformLoginRevision,
		ConfigurationRevision: value.ConfigurationRevision, SecurityRevision: value.SecurityRevision,
		PlanRevision: value.PlanRevision, AssurancePolicyRevision: value.AssurancePolicyRevision,
		PlatformFloorPolicyID: value.PlatformFloorPolicyID,
		PlatformFloorRevision: value.PlatformFloorPolicyRevision,
		ClientSecretRevision:  value.ClientSecretRevision, DiscoveryRevision: value.DiscoveryRevision,
		DiscoveryDigest: value.DiscoveryDigest, JWKSRevision: value.JWKSRevision, JWKSDigest: value.JWKSDigest,
	}
}

func platformOIDCDirectConfigurationClient(t *testing.T) *federatedoidc.Client {
	t.Helper()
	httpClient, err := federatedauth.NewDeploymentHTTPClient(federatedauth.DeploymentHTTPOptions{
		Resolver: net.DefaultResolver, Dialer: &net.Dialer{}, AllowedHTTPSPorts: []uint16{443},
		RootCAs: x509.NewCertPool(), OperationTimeout: 2 * time.Second, MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatalf("NewDeploymentHTTPClient() error = %v", err)
	}
	client, err := federatedoidc.New(federatedoidc.Options{
		HTTP: httpClient, Limits: federatedoidc.DefaultLimits(),
	})
	if err != nil {
		t.Fatalf("federatedoidc.New() error = %v", err)
	}
	return client
}

func platformOIDCDirectJSONRow(t *testing.T, value any) pgx.Row {
	t.Helper()
	payload := platformOIDCDirectJSON(t, value)
	return federatedAuthRowFunc(func(destinations ...any) error {
		if len(destinations) != 1 {
			t.Fatalf("destinations = %d", len(destinations))
		}
		destination, ok := destinations[0].(*[]byte)
		if !ok {
			t.Fatalf("destination = %T", destinations[0])
		}
		*destination = append([]byte(nil), payload...)
		return nil
	})
}

func platformOIDCDirectJSON(t *testing.T, value any) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return payload
}

func sha256Bytes(value []byte) []byte {
	digest := sha256.Sum256(value)
	return append([]byte(nil), digest[:]...)
}

func clonePlatformOIDCDirectConfigurationWire(
	value platformOIDCDirectConfigurationWire,
) platformOIDCDirectConfigurationWire {
	value.Authorization.ExtraScopes = append([]string(nil), value.Authorization.ExtraScopes...)
	value.DiscoveryDocument = append([]byte(nil), value.DiscoveryDocument...)
	value.DiscoveryDigest = append([]byte(nil), value.DiscoveryDigest...)
	value.DiscoveryPolicy.SigningAlgorithms = append([]string(nil), value.DiscoveryPolicy.SigningAlgorithms...)
	value.JWKSDocument = append([]byte(nil), value.JWKSDocument...)
	value.JWKSDigest = append([]byte(nil), value.JWKSDigest...)
	value.Pins.DiscoveryDigest = append([]byte(nil), value.Pins.DiscoveryDigest...)
	value.Pins.JWKSDigest = append([]byte(nil), value.Pins.JWKSDigest...)
	value.IDTokenClaims = cloneOIDCClaimExtractionPolicy(value.IDTokenClaims)
	value.UserInfoClaims = cloneOIDCClaimExtractionPolicy(value.UserInfoClaims)
	return value
}
