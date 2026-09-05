package federatedauth

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/federatedhttp"
	"github.com/periapsis-im/periapsis/modules/identity/federatedoidc"
	"github.com/periapsis-im/periapsis/modules/identity/federatedsaml"
)

type tenantFederatedConfigurationRecordsFake struct {
	oidc        TenantOIDCConfigurationRecord
	saml        TenantSAMLConfigurationRecord
	oidcBegin   []OIDCStartLookup
	oidcResolve []federatedoidc.CallbackConfigurationLookup
	samlBegin   []SAMLStartLookup
	samlResolve []federatedsaml.CallbackConfigurationLookup
	err         error
	cancel      context.CancelFunc
}

func (records *tenantFederatedConfigurationRecordsFake) BeginTenantOIDCConfigurationRecord(
	_ context.Context,
	lookup OIDCStartLookup,
) (TenantOIDCConfigurationRecord, error) {
	records.oidcBegin = append(records.oidcBegin, lookup)
	if records.cancel != nil {
		records.cancel()
	}
	return records.oidc, records.err
}

func (records *tenantFederatedConfigurationRecordsFake) ResolveTenantOIDCConfigurationRecord(
	_ context.Context,
	lookup federatedoidc.CallbackConfigurationLookup,
) (TenantOIDCConfigurationRecord, error) {
	records.oidcResolve = append(records.oidcResolve, lookup)
	if records.cancel != nil {
		records.cancel()
	}
	return records.oidc, records.err
}

func (records *tenantFederatedConfigurationRecordsFake) BeginTenantSAMLConfigurationRecord(
	_ context.Context,
	lookup SAMLStartLookup,
) (TenantSAMLConfigurationRecord, error) {
	records.samlBegin = append(records.samlBegin, lookup)
	if records.cancel != nil {
		records.cancel()
	}
	return records.saml, records.err
}

func (records *tenantFederatedConfigurationRecordsFake) ResolveTenantSAMLConfigurationRecord(
	_ context.Context,
	lookup federatedsaml.CallbackConfigurationLookup,
) (TenantSAMLConfigurationRecord, error) {
	records.samlResolve = append(records.samlResolve, lookup)
	if records.cancel != nil {
		records.cancel()
	}
	return records.saml, records.err
}

type configurationResolver struct{}

func (configurationResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
}

type configurationDialer struct{}

func (configurationDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("network disabled in configuration test")
}

func TestPinnedTenantConfigurationSourceRestoresExactOIDCPinsWithoutNetwork(t *testing.T) {
	record := tenantOIDCConfigurationRecordFixture(t)
	records := &tenantFederatedConfigurationRecordsFake{oidc: record}
	source := mustPinnedTenantConfigurationSource(t, records)

	beginLookup := validOIDCStartLookupFixture()
	begin, err := source.BeginTenantOIDCLogin(context.Background(), beginLookup)
	if err != nil {
		t.Fatalf("BeginTenantOIDCLogin() error = %v", err)
	}
	pins := oidcPinsFromRecord(record)
	callbackLookup := federatedoidc.CallbackConfigurationLookup{
		TransactionID: federatedoidc.TransactionID{1}, ExpectedVersion: 2, Pins: pins,
	}
	resolved, err := source.ResolveTenantOIDCCallback(context.Background(), callbackLookup)
	if err != nil {
		t.Fatalf("ResolveTenantOIDCCallback() error = %v", err)
	}
	if len(records.oidcBegin) != 1 || records.oidcBegin[0] != beginLookup || len(records.oidcResolve) != 1 ||
		records.oidcResolve[0] != callbackLookup || begin.Authorization.Discovery.Revision() != record.DiscoveryRevision ||
		begin.Authorization.Discovery.Digest() != record.DiscoveryDigest ||
		begin.Authorization.JWKS.Revision() != record.JWKSRevision ||
		begin.Authorization.JWKS.Digest() != record.JWKSDigest ||
		resolved.Authorization.Discovery.Digest() != record.DiscoveryDigest ||
		resolved.Authorization.JWKS.Digest() != record.JWKSDigest {
		t.Fatalf("restored OIDC configuration mismatch: begin=%s resolved=%s", begin, resolved)
	}

	record.DiscoveryDocument[0] ^= 0xff
	record.JWKSDocument[0] ^= 0xff
	if begin.Authorization.Discovery.Issuer() != "https://oidc.example.test/tenant" ||
		begin.Authorization.JWKS.KeyCount() != 1 {
		t.Fatal("compiled configuration retained mutable public documents")
	}
}

func TestPinnedTenantConfigurationSourceRestoresExactSAMLPins(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	record := tenantSAMLConfigurationRecordFixture(t, now)
	records := &tenantFederatedConfigurationRecordsFake{saml: record}
	source := mustPinnedTenantConfigurationSource(t, records)

	beginLookup := validSAMLStartLookupFixture()
	begin, err := source.BeginTenantSAMLLogin(context.Background(), beginLookup)
	if err != nil {
		t.Fatalf("BeginTenantSAMLLogin() error = %v", err)
	}
	pins := samlPinsFromConfiguration(t, begin.Authentication)
	callbackLookup := federatedsaml.CallbackConfigurationLookup{
		TransactionID: federatedsaml.TransactionID{1}, ExpectedVersion: 2, Pins: pins,
	}
	resolved, err := source.ResolveTenantSAMLCallback(context.Background(), callbackLookup)
	if err != nil {
		t.Fatalf("ResolveTenantSAMLCallback() error = %v", err)
	}
	if len(records.samlBegin) != 1 || records.samlBegin[0] != beginLookup || len(records.samlResolve) != 1 ||
		records.samlResolve[0] != callbackLookup || begin.Authentication.Metadata.Revision() != record.MetadataRevision ||
		begin.Authentication.Metadata.Digest() != record.MetadataDigest ||
		resolved.Authentication.Metadata.Digest() != record.MetadataDigest {
		t.Fatalf("restored SAML configuration mismatch: begin=%s resolved=%s", begin, resolved)
	}

	record.MetadataDocument[0] ^= 0xff
	if begin.Authentication.Metadata.EntityID() != record.ExpectedEntityID {
		t.Fatal("compiled SAML configuration retained mutable metadata")
	}
}

func TestPinnedTenantConfigurationSourceRejectsProjectionDriftAndMalformedPersistence(t *testing.T) {
	validOIDC := tenantOIDCConfigurationRecordFixture(t)
	validSAML := tenantSAMLConfigurationRecordFixture(t, time.Now().UTC().Truncate(time.Microsecond))

	for name, mutate := range map[string]func(*TenantOIDCConfigurationRecord){
		"source error":     func(*TenantOIDCConfigurationRecord) {},
		"discovery digest": func(value *TenantOIDCConfigurationRecord) { value.DiscoveryDigest[0] ^= 0xff },
		"jwks digest":      func(value *TenantOIDCConfigurationRecord) { value.JWKSDigest[0] ^= 0xff },
		"issuer drift":     func(value *TenantOIDCConfigurationRecord) { value.Issuer += "/" },
		"snapshot injected": func(value *TenantOIDCConfigurationRecord) {
			value.Authorization = validOIDC.Authorization
			value.Authorization.Discovery = tenantOIDCCompiledFixture(t).Authorization.Discovery
		},
	} {
		t.Run("oidc/"+name, func(t *testing.T) {
			candidate := cloneOIDCConfigurationRecord(validOIDC)
			mutate(&candidate)
			records := &tenantFederatedConfigurationRecordsFake{oidc: candidate}
			if name == "source error" {
				records.err = errors.New("database detail canary")
			}
			source := mustPinnedTenantConfigurationSource(t, records)
			if _, err := source.BeginTenantOIDCLogin(context.Background(), validOIDCStartLookupFixture()); !errors.Is(err, ErrAuthentication) || strings.Contains(err.Error(), "canary") {
				t.Fatalf("BeginTenantOIDCLogin() error = %v", err)
			}
		})
	}

	for name, mutate := range map[string]func(*TenantSAMLConfigurationRecord){
		"metadata digest": func(value *TenantSAMLConfigurationRecord) { value.MetadataDigest[0] ^= 0xff },
		"entity drift":    func(value *TenantSAMLConfigurationRecord) { value.ExpectedEntityID += "/" },
		"snapshot injected": func(value *TenantSAMLConfigurationRecord) {
			value.Authentication.Metadata = samlConfigurationFixture(t, value.MetadataRetrievedAt, false).Authentication.Metadata
		},
	} {
		t.Run("saml/"+name, func(t *testing.T) {
			candidate := cloneSAMLConfigurationRecord(validSAML)
			mutate(&candidate)
			source := mustPinnedTenantConfigurationSource(t, &tenantFederatedConfigurationRecordsFake{saml: candidate})
			if _, err := source.BeginTenantSAMLLogin(context.Background(), validSAMLStartLookupFixture()); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("BeginTenantSAMLLogin() error = %v", err)
			}
		})
	}
}

func TestPinnedTenantConfigurationSourceRejectsCallbackPinDrift(t *testing.T) {
	oidcRecord := tenantOIDCConfigurationRecordFixture(t)
	samlRecord := tenantSAMLConfigurationRecordFixture(t, time.Now().UTC().Truncate(time.Microsecond))
	source := mustPinnedTenantConfigurationSource(t, &tenantFederatedConfigurationRecordsFake{
		oidc: oidcRecord, saml: samlRecord,
	})

	oidcPins := oidcPinsFromRecord(oidcRecord)
	oidcPins.SecurityRevision++
	if _, err := source.ResolveTenantOIDCCallback(context.Background(), federatedoidc.CallbackConfigurationLookup{
		TransactionID: federatedoidc.TransactionID{1}, ExpectedVersion: 2, Pins: oidcPins,
	}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("OIDC drift error = %v", err)
	}

	samlConfiguration, err := compileSAMLRecord(samlRecord, nil)
	if err != nil {
		t.Fatal(err)
	}
	samlPins := samlPinsFromConfiguration(t, samlConfiguration.Authentication)
	samlPins.ConfigurationDigest[0] ^= 0xff
	if _, err := source.ResolveTenantSAMLCallback(context.Background(), federatedsaml.CallbackConfigurationLookup{
		TransactionID: federatedsaml.TransactionID{1}, ExpectedVersion: 2, Pins: samlPins,
	}); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("SAML drift error = %v", err)
	}
}

func TestPinnedTenantConfigurationSourceHonorsCancellationAfterPersistence(t *testing.T) {
	for name, run := range map[string]func(*PinnedTenantConfigurationSource, context.Context) error{
		"OIDC": func(source *PinnedTenantConfigurationSource, ctx context.Context) error {
			_, err := source.BeginTenantOIDCLogin(ctx, validOIDCStartLookupFixture())
			return err
		},
		"SAML": func(source *PinnedTenantConfigurationSource, ctx context.Context) error {
			_, err := source.BeginTenantSAMLLogin(ctx, validSAMLStartLookupFixture())
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			records := &tenantFederatedConfigurationRecordsFake{
				oidc:   tenantOIDCConfigurationRecordFixture(t),
				saml:   tenantSAMLConfigurationRecordFixture(t, time.Now().UTC().Truncate(time.Microsecond)),
				cancel: cancel,
			}
			source := mustPinnedTenantConfigurationSource(t, records)
			if err := run(source, ctx); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("cancelled configuration load error = %v", err)
			}
		})
	}
}

func TestPersistentConfigurationFormattingRedactsDocumentsAndLocations(t *testing.T) {
	const canary = "configuration-document-canary.example/private"
	values := []any{
		TenantOIDCConfigurationRecord{Issuer: "https://" + canary, DiscoveryDocument: []byte(canary), JWKSDocument: []byte(canary)},
		TenantSAMLConfigurationRecord{ExpectedEntityID: "https://" + canary, MetadataDocument: []byte(canary)},
		&PinnedTenantConfigurationSource{},
	}
	for _, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if output := fmtSprint(format, value); strings.Contains(output, canary) ||
				strings.Contains(output, base64.StdEncoding.EncodeToString([]byte(canary))) {
				t.Fatalf("%T leaked with %s: %s", value, format, output)
			}
		}
	}
}

func mustPinnedTenantConfigurationSource(
	t *testing.T,
	records TenantFederatedConfigurationRecords,
) *PinnedTenantConfigurationSource {
	t.Helper()
	oidcClient := newConfigurationOIDCClient(t)
	source, err := NewPinnedTenantConfigurationSource(records, oidcClient)
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func newConfigurationOIDCClient(t *testing.T) *federatedoidc.Client {
	t.Helper()
	policy, err := federatedhttp.NewDeploymentEgressPolicy(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	httpClient, err := federatedhttp.New(federatedhttp.Options{
		Resolver: configurationResolver{}, Dialer: configurationDialer{}, EgressPolicy: policy,
		RootCAs: x509.NewCertPool(), Limits: federatedhttp.DefaultLimits(), MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	oidcClient, err := federatedoidc.New(federatedoidc.Options{HTTP: httpClient, Limits: federatedoidc.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	return oidcClient
}

func tenantOIDCConfigurationRecordFixture(t *testing.T) TenantOIDCConfigurationRecord {
	t.Helper()
	issuer := "https://oidc.example.test/tenant"
	discovery := mustJSON(t, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"jwks_uri":                              "https://keys.example.test/tenant/jwks",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"revocation_endpoint":                   issuer + "/revoke",
		"end_session_endpoint":                  issuer + "/logout",
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
	jwks := mustJSON(t, map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "kid": "key-1", "use": "sig", "key_ops": []string{"verify"},
		"alg": string(federatedoidc.SigningRS256),
		"n":   base64.RawURLEncoding.EncodeToString(modulus), "e": "AQAB",
	}}})
	retrievedAt := time.Date(2026, time.August, 26, 9, 0, 0, 0, time.UTC)
	configuration := tenantOIDCConfigurationFixture().Authorization
	configuration.ProviderRevision = 2
	configuration.BindingRevision = 3
	configuration.ConfigurationRevision = 4
	configuration.SecurityRevision = 5
	configuration.MappingRevision = 6
	configuration.AuthorizationRevision = 7
	configuration.AssurancePolicyRevision = 8
	configuration.ClientSecretRevision = 9
	configuration.ClientID = "client-exact"
	configuration.RedirectURI = "https://app.example.test/api/v1/auth/federated/oidc/callback"
	configuration.PostLogoutRedirectURI = "https://app.example.test/logout/callback"
	return TenantOIDCConfigurationRecord{
		Authorization: configuration, Issuer: issuer, DiscoveryRevision: 10,
		DiscoveryDocument: discovery, DiscoveryDigest: sha256.Sum256(discovery),
		DiscoveryCache: federatedhttp.CacheMetadata{RetrievedAt: retrievedAt, FreshUntil: retrievedAt.Add(time.Hour), Cacheable: true},
		DiscoveryPolicy: federatedoidc.TrustPolicy{
			ClientAuthentication: federatedoidc.ClientSecretBasic,
			SigningAlgorithms:    []federatedoidc.SigningAlgorithm{federatedoidc.SigningRS256},
		},
		JWKSDocument: jwks, JWKSDigest: sha256.Sum256(jwks), JWKSRevision: 11,
		JWKSCache: federatedhttp.CacheMetadata{RetrievedAt: retrievedAt, FreshUntil: retrievedAt.Add(time.Hour), Cacheable: true},
	}
}

func tenantOIDCCompiledFixture(t *testing.T) TenantOIDCConfiguration {
	t.Helper()
	record := tenantOIDCConfigurationRecordFixture(t)
	source := mustPinnedTenantConfigurationSource(t, &tenantFederatedConfigurationRecordsFake{oidc: record})
	configuration, err := source.BeginTenantOIDCLogin(context.Background(), validOIDCStartLookupFixture())
	if err != nil {
		t.Fatal(err)
	}
	return configuration
}

func oidcPinsFromRecord(record TenantOIDCConfigurationRecord) federatedoidc.TransactionPins {
	value := record.Authorization
	return federatedoidc.TransactionPins{
		Provider: value.Provider, BindingID: value.BindingID,
		ProviderRevision: value.ProviderRevision, BindingRevision: value.BindingRevision,
		ConfigurationRevision: value.ConfigurationRevision, SecurityRevision: value.SecurityRevision,
		MappingRevision: value.MappingRevision, AuthorizationRevision: value.AuthorizationRevision,
		AssurancePolicyRevision: value.AssurancePolicyRevision, ClientSecretRevision: value.ClientSecretRevision,
		DiscoveryRevision: record.DiscoveryRevision, DiscoveryDigest: record.DiscoveryDigest,
		JWKSRevision: record.JWKSRevision, JWKSDigest: record.JWKSDigest,
	}
}

func tenantSAMLConfigurationRecordFixture(t *testing.T, now time.Time) TenantSAMLConfigurationRecord {
	t.Helper()
	configuration := samlConfigurationFixture(t, now, true).Authentication
	metadataDocument := samlMetadataDocument(
		configuration.Metadata.EntityID(), configuration.Metadata.SSORedirectURL(),
		configuration.Metadata.SLORedirectURL(), now.Add(24*time.Hour), samlCertificateFixture(t, now),
	)
	metadata, err := federatedsaml.CompileMetadata(federatedsaml.MetadataCompilationRequest{
		Document: metadataDocument, ExpectedEntityID: configuration.Metadata.EntityID(), Revision: 6,
		RetrievedAt: now.Add(-time.Minute), MaximumValidUntil: now.Add(48 * time.Hour),
	}, federatedsaml.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	configuration.Metadata = federatedsaml.MetadataSnapshot{}
	return TenantSAMLConfigurationRecord{
		Authentication: configuration, ExpectedEntityID: metadata.EntityID(), MetadataRevision: metadata.Revision(),
		MetadataDocument: metadataDocument, MetadataDigest: metadata.Digest(), MetadataRetrievedAt: metadata.RetrievedAt(),
		MetadataMaximumValidUntil: now.Add(48 * time.Hour),
	}
}

func samlPinsFromConfiguration(t *testing.T, configuration federatedsaml.Configuration) federatedsaml.TransactionPins {
	t.Helper()
	// Starting the kernel is the public constructor for the private normalized
	// configuration digest. Capturing the repository projection keeps this
	// test on the same code path used by production.
	repository := &samlTestTransactions{}
	kernel, err := federatedsaml.New(federatedsaml.Options{
		Transactions: repository, RedirectSigner: samlTestSigner{}, SignatureVerifier: samlTestVerifier{},
		AssertionDecrypter: samlTestDecrypter{}, SessionProtector: samlTestSessionProtector{},
		TransactionTTL: 5 * time.Minute, OperationTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = kernel.StartAuthentication(context.Background(), federatedsaml.StartRequest{
		Begin: samlAuthenticationBeginFixture(51), Configuration: configuration, ReturnPath: "/",
	})
	if err != nil {
		t.Fatalf("StartAuthentication() error = %v", err)
	}
	return repository.pending.Pins
}

func cloneOIDCConfigurationRecord(value TenantOIDCConfigurationRecord) TenantOIDCConfigurationRecord {
	value.DiscoveryDocument = append([]byte(nil), value.DiscoveryDocument...)
	value.JWKSDocument = append([]byte(nil), value.JWKSDocument...)
	return value
}

func cloneSAMLConfigurationRecord(value TenantSAMLConfigurationRecord) TenantSAMLConfigurationRecord {
	value.MetadataDocument = append([]byte(nil), value.MetadataDocument...)
	return value
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func fmtSprint(format string, value any) string {
	return fmt.Sprintf(format, value)
}
