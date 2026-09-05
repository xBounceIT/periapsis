package config

import (
	"bytes"
	"encoding/base64"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/periapsis-im/periapsis/modules/identity/ldapclient"
)

func TestLoadRequiresDatabaseInProduction(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "production")
	t.Setenv("PERIAPSIS_DATABASE_URL", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load() succeeded without a production database URL")
	}
}

func TestLoadRejectsPrivilegedPort(t *testing.T) {
	t.Setenv("PERIAPSIS_API_ADDR", ":443")

	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted a privileged API port")
	}
}

func TestLoadUsesSafeDevelopmentDefaults(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "development")
	t.Setenv("PERIAPSIS_API_ADDR", "")
	config, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if config.Address != ":8080" {
		t.Fatalf("Address = %q, want :8080", config.Address)
	}
	if config.NotifierInternalURL != "http://localhost:8083" {
		t.Fatalf("NotifierInternalURL = %q", config.NotifierInternalURL)
	}
	if config.WebAuthnEnabled || config.WebAuthnRPID != "" {
		t.Fatalf("development WebAuthn pins = enabled %t RP %q, want disabled", config.WebAuthnEnabled, config.WebAuthnRPID)
	}
	if config.APIRateLimitPolicy.NetworkRequestsPerSecond != 100 ||
		config.APIRateLimitPolicy.CredentialRequestsPerSecond != 60 ||
		config.APIRateLimitPolicy.TenantSubjectRequestsPerSecond != 40 {
		t.Fatalf("API rate-limit defaults = %#v", config.APIRateLimitPolicy)
	}
	if config.FederatedOIDCClockSkew != time.Minute {
		t.Fatalf("FederatedOIDCClockSkew = %s, want documented default 1m", config.FederatedOIDCClockSkew)
	}
}

func TestLoadPinsWebAuthnToExactHTTPSRelyingParty(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "development")
	t.Setenv("PERIAPSIS_PUBLIC_URL", "https://auth.example.test")
	t.Setenv("PERIAPSIS_WEBAUTHN_ENABLED", "true")
	t.Setenv("PERIAPSIS_WEBAUTHN_RP_ID", "example.test")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.WebAuthnEnabled || cfg.WebAuthnRPID != "example.test" {
		t.Fatalf("WebAuthn pins = enabled %t RP %q", cfg.WebAuthnEnabled, cfg.WebAuthnRPID)
	}
}

func TestLoadRejectsUnsafeOrAmbiguousWebAuthnConfiguration(t *testing.T) {
	for _, test := range []struct {
		name, environment, publicURL, enabled, rpID string
	}{
		{name: "HTTP enabled", environment: "development", publicURL: "http://auth.example.test", enabled: "true", rpID: "example.test"},
		{name: "origin outside RP", environment: "development", publicURL: "https://auth.other.test", enabled: "true", rpID: "example.test"},
		{name: "RP while disabled", environment: "development", publicURL: "http://localhost:8081", enabled: "false", rpID: "example.test"},
		{name: "production disabled", environment: "production", publicURL: "https://auth.example.test", enabled: "false", rpID: "example.test"},
		{name: "production implicit RP", environment: "production", publicURL: "https://auth.example.test", enabled: "true"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("PERIAPSIS_ENV", test.environment)
			t.Setenv("PERIAPSIS_PUBLIC_URL", test.publicURL)
			t.Setenv("PERIAPSIS_WEBAUTHN_ENABLED", test.enabled)
			t.Setenv("PERIAPSIS_WEBAUTHN_RP_ID", test.rpID)
			if _, err := Load(); err == nil {
				t.Fatal("Load() accepted unsafe WebAuthn configuration")
			}
		})
	}
}

func TestLoadParsesDevelopmentNotifierPreviewConfiguration(t *testing.T) {
	token := "0123456789abcdef0123456789abcdef"
	t.Setenv("PERIAPSIS_ENV", "development")
	t.Setenv("PERIAPSIS_NOTIFIER_INTERNAL_URL", "http://notifier-preview:8083")
	t.Setenv("PERIAPSIS_NOTIFIER_PREVIEW_TOKEN", token)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.NotifierInternalURL != "http://notifier-preview:8083" || string(cfg.NotifierPreviewToken) != token {
		t.Fatalf("notifier preview configuration = %#v", cfg)
	}
}

func TestLoadKeepsPlaintextSMTPDevelopmentOnly(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "development")
	t.Setenv("PERIAPSIS_SMTP_ALLOW_PLAIN_LOCAL", "true")
	cfg, err := Load()
	if err != nil || !cfg.SMTPAllowPlainLocal {
		t.Fatalf("development plaintext SMTP = %t, %v", cfg.SMTPAllowPlainLocal, err)
	}

	t.Setenv("PERIAPSIS_ENV", "production")
	if _, err := Load(); err == nil {
		t.Fatal("Load() allowed plaintext SMTP in production")
	}
}

func TestLoadKeepsPlaintextWebhookDevelopmentOnly(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "development")
	t.Setenv("PERIAPSIS_WEBHOOK_ALLOW_PLAIN_LOCAL", "true")
	cfg, err := Load()
	if err != nil || !cfg.WebhookAllowPlainLocal {
		t.Fatalf("development plaintext webhook = %t, %v", cfg.WebhookAllowPlainLocal, err)
	}

	t.Setenv("PERIAPSIS_ENV", "production")
	if _, err := Load(); err == nil {
		t.Fatal("Load() allowed plaintext webhook in production")
	}
}

func TestLoadRejectsAmbiguousOrWeakNotifierPreviewToken(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "development")
	t.Setenv("PERIAPSIS_NOTIFIER_PREVIEW_TOKEN", "too-short")
	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted a weak notifier preview token")
	}

	tokenFile := filepath.Join(t.TempDir(), "preview-token")
	if err := os.WriteFile(tokenFile, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PERIAPSIS_NOTIFIER_PREVIEW_TOKEN", "0123456789abcdef0123456789abcdef")
	t.Setenv("PERIAPSIS_NOTIFIER_PREVIEW_TOKEN_FILE", tokenFile)
	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted two notifier preview token sources")
	}
}

func TestLoadDisablesDocumentationByDefaultInProduction(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "production")
	setProductionAuthConfig(t)
	databaseURLFile := filepath.Join(t.TempDir(), "database-url")
	if err := os.WriteFile(databaseURLFile, []byte("postgres://example.invalid/periapsis"), 0o600); err != nil {
		t.Fatalf("write database URL fixture: %v", err)
	}
	t.Setenv("PERIAPSIS_DATABASE_URL_FILE", databaseURLFile)
	t.Setenv("PERIAPSIS_DATABASE_URL", "")
	t.Setenv("PERIAPSIS_DOCS_ENABLED", "")

	config, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if config.DocsEnabled {
		t.Fatal("DocsEnabled = true in production without an explicit opt-in")
	}
}

func TestLoadRejectsInsecureProductionPublicURL(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "production")
	t.Setenv("PERIAPSIS_PUBLIC_URL", "http://periapsis.example")

	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted an insecure production public URL")
	}
}

func TestPublicOriginCanonicalizesHostCaseAndDefaultPort(t *testing.T) {
	for _, raw := range []string{"https://Example.COM:443/", "https://Example.COM:0443/"} {
		origin, err := validatePublicOrigin(raw, "production")
		if err != nil {
			t.Fatalf("validatePublicOrigin(%q) error = %v", raw, err)
		}
		if origin != "https://example.com" {
			t.Fatalf("origin = %q, want canonical browser origin", origin)
		}
	}

	if _, err := validatePublicOrigin("https://example.com:", "production"); err == nil {
		t.Fatal("validatePublicOrigin() accepted an empty port")
	}

	ipv6, err := validatePublicOrigin("https://[0:0:0:0:0:0:0:1]", "production")
	if err != nil || ipv6 != "https://[::1]" {
		t.Fatalf("IPv6 origin = %q, error = %v, want browser-canonical form", ipv6, err)
	}
	for _, raw := range []string{
		"https://127.000.000.001",
		"https://0177.0.0.1",
		"https://0x7f000001",
	} {
		if _, err := validatePublicOrigin(raw, "production"); err == nil {
			t.Fatalf("validatePublicOrigin() accepted ambiguous legacy IPv4 form %q", raw)
		}
	}
}

func TestLoadRejectsDirectProductionMasterKey(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "production")
	setProductionDatabaseConfig(t)
	t.Setenv("PERIAPSIS_PUBLIC_URL", "https://periapsis.example")
	t.Setenv("PERIAPSIS_MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("PERIAPSIS_MASTER_KEY_FILE", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted an environment-only production master key")
	}
}

func TestLoadRequiresFileBackedProductionBootstrapToken(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "production")
	setProductionDatabaseConfig(t)
	setProductionAuthConfig(t)
	t.Setenv("PERIAPSIS_BOOTSTRAP_TOKEN_FILE", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted missing production bootstrap authority")
	}
}

func TestLoadValidatesAuthenticationTimeoutBounds(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "development")
	t.Setenv("PERIAPSIS_SESSION_IDLE_TIMEOUT", "2h")
	t.Setenv("PERIAPSIS_SESSION_ABSOLUTE_TIMEOUT", "1h")

	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted an absolute session timeout below its idle timeout")
	}
}

func TestLoadValidatesRequestTimeoutBounds(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "development")
	t.Setenv("PERIAPSIS_REQUEST_TIMEOUT", "30s")
	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted a request deadline beyond the server write budget")
	}
}

func TestLoadValidatesPasswordVerificationConcurrency(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "development")
	t.Setenv("PERIAPSIS_AUTH_KDF_CONCURRENCY", "0")
	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted an unbounded password-verification configuration")
	}
	t.Setenv("PERIAPSIS_AUTH_KDF_CONCURRENCY", "not-a-number")
	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted a malformed password-verification configuration")
	}
}

func TestLoadValidatesAPIRateLimitPolicy(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "development")
	t.Setenv("PERIAPSIS_API_RATE_LIMIT_NETWORK_RPS", "80")
	t.Setenv("PERIAPSIS_API_RATE_LIMIT_CREDENTIAL_RPS", "50")
	t.Setenv("PERIAPSIS_API_RATE_LIMIT_TENANT_SUBJECT_RPS", "30")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.APIRateLimitPolicy.NetworkRequestsPerSecond != 80 ||
		cfg.APIRateLimitPolicy.CredentialRequestsPerSecond != 50 ||
		cfg.APIRateLimitPolicy.TenantSubjectRequestsPerSecond != 30 {
		t.Fatalf("API rate-limit policy = %#v", cfg.APIRateLimitPolicy)
	}

	for _, test := range []struct{ name, variable, value string }{
		{name: "zero", variable: "PERIAPSIS_API_RATE_LIMIT_NETWORK_RPS", value: "0"},
		{name: "over database maximum", variable: "PERIAPSIS_API_RATE_LIMIT_CREDENTIAL_RPS", value: "101"},
		{name: "malformed", variable: "PERIAPSIS_API_RATE_LIMIT_TENANT_SUBJECT_RPS", value: "many"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("PERIAPSIS_ENV", "development")
			t.Setenv("PERIAPSIS_API_RATE_LIMIT_NETWORK_RPS", "")
			t.Setenv("PERIAPSIS_API_RATE_LIMIT_CREDENTIAL_RPS", "")
			t.Setenv("PERIAPSIS_API_RATE_LIMIT_TENANT_SUBJECT_RPS", "")
			t.Setenv(test.variable, test.value)
			if _, err := Load(); err == nil {
				t.Fatal("Load() accepted an invalid API rate-limit policy")
			}
		})
	}
}

func TestLoadDecodesExactDevelopmentMasterKey(t *testing.T) {
	want := []byte("0123456789abcdef0123456789abcdef")
	t.Setenv("PERIAPSIS_ENV", "development")
	t.Setenv("PERIAPSIS_MASTER_KEY", base64.StdEncoding.EncodeToString(want))

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if string(cfg.MasterKey) != string(want) {
		t.Fatal("MasterKey does not match the decoded secret")
	}
}

func TestLoadParsesDevelopmentCredentialKeyring(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("abcdef0123456789abcdef0123456789"))
	t.Setenv("PERIAPSIS_ENV", "development")
	t.Setenv("PERIAPSIS_API_CREDENTIAL_KEYRING", `{"activeVersion":3,"keys":[{"version":3,"key":"`+key+`"}]}`)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.CredentialKeyring.ActiveVersion() != 3 {
		t.Fatalf("CredentialKeyring.ActiveVersion() = %d", cfg.CredentialKeyring.ActiveVersion())
	}
}

func TestLoadParsesDevelopmentIdentityKeyring(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	t.Setenv("PERIAPSIS_ENV", "development")
	t.Setenv("PERIAPSIS_IDENTITY_KEYRING", `{"activeVersion":3,"keys":[{"version":3,"key":"`+key+`"}]}`)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.IdentityKeyring.ActiveVersion() != 3 {
		t.Fatalf("IdentityKeyring.ActiveVersion() = %d", cfg.IdentityKeyring.ActiveVersion())
	}
}

func TestLoadUsesDocumentedLDAPDeploymentEnvironment(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "development")
	t.Setenv("PERIAPSIS_LDAP_STARTTLS_PORTS", "389,1389")
	t.Setenv("PERIAPSIS_LDAP_LDAPS_PORTS", "636,1636")
	t.Setenv("PERIAPSIS_LDAP_PRIVATE_EGRESS_CIDRS", "10.20.0.0/16,fd12:3456::/48")
	t.Setenv("PERIAPSIS_LDAP_MAX_CONCURRENT", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.LDAPMaxConcurrent != 8 {
		t.Fatalf("LDAPMaxConcurrent = %d, want documented default 8", cfg.LDAPMaxConcurrent)
	}
	if !equalLDAPPorts(cfg.LDAPAllowedStartTLSPorts, []uint16{389, 1389}) ||
		!equalLDAPPorts(cfg.LDAPAllowedLDAPSPorts, []uint16{636, 1636}) {
		t.Fatalf("LDAP ports = StartTLS %v, LDAPS %v", cfg.LDAPAllowedStartTLSPorts, cfg.LDAPAllowedLDAPSPorts)
	}
	wantCIDRs := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("fd12:3456::/48")}
	if len(cfg.LDAPPrivateEgressCIDRs) != len(wantCIDRs) {
		t.Fatalf("private LDAP CIDRs = %v", cfg.LDAPPrivateEgressCIDRs)
	}
	for index := range wantCIDRs {
		if cfg.LDAPPrivateEgressCIDRs[index] != wantCIDRs[index] {
			t.Fatalf("private LDAP CIDR %d = %v, want %v", index, cfg.LDAPPrivateEgressCIDRs[index], wantCIDRs[index])
		}
	}
}

func TestLoadUsesDocumentedFederatedDeploymentEnvironment(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "development")
	t.Setenv("PERIAPSIS_FEDERATED_HTTPS_PORTS", "443,8443")
	t.Setenv("PERIAPSIS_FEDERATED_PRIVATE_EGRESS_CIDRS", "10.30.0.0/16,fd12:9876::/48")
	t.Setenv("PERIAPSIS_FEDERATED_MAX_CONCURRENT", "24")
	t.Setenv("PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW", "2m30s")
	t.Setenv("PERIAPSIS_FEDERATED_OPERATION_TIMEOUT", "12s")
	t.Setenv("PERIAPSIS_FEDERATED_CA_BUNDLE_FILE", "  /run/secrets/federated-ca.pem  ")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.FederatedMaxConcurrent != 24 || cfg.FederatedOIDCClockSkew != 150*time.Second ||
		cfg.FederatedOperationTimeout != 12*time.Second {
		t.Fatalf(
			"federated bounds = concurrency %d, OIDC skew %s, timeout %s",
			cfg.FederatedMaxConcurrent,
			cfg.FederatedOIDCClockSkew,
			cfg.FederatedOperationTimeout,
		)
	}
	if cfg.FederatedCABundleFile != "/run/secrets/federated-ca.pem" {
		t.Fatalf("federated CA bundle file = %q", cfg.FederatedCABundleFile)
	}
	if !equalLDAPPorts(cfg.FederatedAllowedHTTPSPorts, []uint16{443, 8443}) {
		t.Fatalf("federated HTTPS ports = %v", cfg.FederatedAllowedHTTPSPorts)
	}
	wantCIDRs := []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16"), netip.MustParsePrefix("fd12:9876::/48")}
	if len(cfg.FederatedPrivateEgressCIDRs) != len(wantCIDRs) {
		t.Fatalf("private federation CIDRs = %v", cfg.FederatedPrivateEgressCIDRs)
	}
	for index := range wantCIDRs {
		if cfg.FederatedPrivateEgressCIDRs[index] != wantCIDRs[index] {
			t.Fatalf("private federation CIDR %d = %v, want %v", index, cfg.FederatedPrivateEgressCIDRs[index], wantCIDRs[index])
		}
	}
}

func TestLoadRejectsMalformedFederatedDeploymentEnvironment(t *testing.T) {
	tests := []struct{ name, variable, value string }{
		{name: "noncanonical CIDR", variable: "PERIAPSIS_FEDERATED_PRIVATE_EGRESS_CIDRS", value: "10.1.2.3/8"},
		{name: "duplicate CIDR", variable: "PERIAPSIS_FEDERATED_PRIVATE_EGRESS_CIDRS", value: "10.0.0.0/8,10.0.0.0/8"},
		{name: "leading-zero port", variable: "PERIAPSIS_FEDERATED_HTTPS_PORTS", value: "0443"},
		{name: "duplicate port", variable: "PERIAPSIS_FEDERATED_HTTPS_PORTS", value: "443,443"},
		{name: "zero concurrency", variable: "PERIAPSIS_FEDERATED_MAX_CONCURRENT", value: "0"},
		{name: "excessive concurrency", variable: "PERIAPSIS_FEDERATED_MAX_CONCURRENT", value: "257"},
		{name: "negative OIDC clock skew", variable: "PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW", value: "-1us"},
		{name: "excessive OIDC clock skew", variable: "PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW", value: "5m1us"},
		{name: "unaligned OIDC clock skew", variable: "PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW", value: "1s1ns"},
		{name: "short operation timeout", variable: "PERIAPSIS_FEDERATED_OPERATION_TIMEOUT", value: "99ms"},
		{name: "unaligned operation timeout", variable: "PERIAPSIS_FEDERATED_OPERATION_TIMEOUT", value: "100ms1ns"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("PERIAPSIS_ENV", "development")
			t.Setenv(test.variable, test.value)
			if _, err := Load(); err == nil {
				t.Fatalf("Load() accepted %s=%q", test.variable, test.value)
			}
		})
	}
}

func TestLoadAcceptsFederatedOIDCClockSkewBounds(t *testing.T) {
	for _, value := range []string{"0s", "5m"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("PERIAPSIS_ENV", "development")
			t.Setenv("PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW", value)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() rejected PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW=%q: %v", value, err)
			}
			want, err := time.ParseDuration(value)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.FederatedOIDCClockSkew != want {
				t.Fatalf("FederatedOIDCClockSkew = %s, want %s", cfg.FederatedOIDCClockSkew, want)
			}
		})
	}
}

func TestLoadRejectsMalformedLDAPDeploymentEnvironment(t *testing.T) {
	tests := []struct{ name, variable, value string }{
		{name: "noncanonical CIDR", variable: "PERIAPSIS_LDAP_PRIVATE_EGRESS_CIDRS", value: "10.1.2.3/8"},
		{name: "duplicate CIDR", variable: "PERIAPSIS_LDAP_PRIVATE_EGRESS_CIDRS", value: "10.0.0.0/8,10.0.0.0/8"},
		{name: "leading-zero port", variable: "PERIAPSIS_LDAP_STARTTLS_PORTS", value: "0389"},
		{name: "duplicate port", variable: "PERIAPSIS_LDAP_LDAPS_PORTS", value: "636,636"},
		{name: "zero concurrency", variable: "PERIAPSIS_LDAP_MAX_CONCURRENT", value: "0"},
		{name: "excessive concurrency", variable: "PERIAPSIS_LDAP_MAX_CONCURRENT", value: "257"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("PERIAPSIS_ENV", "development")
			t.Setenv(test.variable, test.value)
			if _, err := Load(); err == nil {
				t.Fatalf("Load() accepted %s=%q", test.variable, test.value)
			}
		})
	}
}

func TestLDAPClientRejectsPublicAndMetadataEgressConfiguration(t *testing.T) {
	for _, raw := range []string{"93.184.216.0/24", "169.254.169.254/32"} {
		prefixes, err := parseLDAPPrivateEgressCIDRs(raw)
		if err != nil {
			t.Fatalf("parseLDAPPrivateEgressCIDRs(%q) syntax error = %v", raw, err)
		}
		if _, err := ldapclient.New(ldapclient.Options{
			Resolver: net.DefaultResolver, Dialer: &net.Dialer{}, PrivateEgressCIDRs: prefixes, MaxConcurrent: 8,
		}); err == nil {
			t.Fatalf("ldapclient.New() accepted non-private egress CIDR %q", raw)
		}
	}
}

func TestSecretConfigConsumersClearSourceBuffers(t *testing.T) {
	t.Parallel()

	bootstrapSource := []byte("0123456789abcdef0123456789abcdef")
	bootstrapDigest, err := digestBootstrapToken(bootstrapSource)
	if err != nil {
		t.Fatalf("digestBootstrapToken() error = %v", err)
	}
	if !allZeroBytes(bootstrapSource) || len(bootstrapDigest) != 32 {
		t.Fatalf("bootstrap source cleared = %t, digest bytes = %d", allZeroBytes(bootstrapSource), len(bootstrapDigest))
	}
	clear(bootstrapDigest)

	masterSource := []byte(base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	masterKey, err := decodeMasterKey(masterSource)
	if err != nil {
		t.Fatalf("decodeMasterKey() error = %v", err)
	}
	if !allZeroBytes(masterSource) || len(masterKey) != 32 {
		t.Fatalf("master source cleared = %t, decoded bytes = %d", allZeroBytes(masterSource), len(masterKey))
	}
	clear(masterKey)

	credentialKey := base64.StdEncoding.EncodeToString([]byte("abcdef0123456789abcdef0123456789"))
	keyringSource := []byte(`{"activeVersion":1,"keys":[{"version":1,"key":"` + credentialKey + `"}]}`)
	keyring, err := parseCredentialKeyringDocument(keyringSource)
	if err != nil {
		t.Fatalf("parseCredentialKeyringDocument() error = %v", err)
	}
	if !allZeroBytes(keyringSource) || keyring.ActiveVersion() != 1 {
		t.Fatalf("keyring source cleared = %t, active version = %d", allZeroBytes(keyringSource), keyring.ActiveVersion())
	}

	invalidKeyringSource := []byte(`{"activeVersion":1,"keys":[`)
	if _, err := parseCredentialKeyringDocument(invalidKeyringSource); err == nil {
		t.Fatal("parseCredentialKeyringDocument() unexpectedly accepted invalid JSON")
	}
	if !allZeroBytes(invalidKeyringSource) {
		t.Fatal("invalid keyring source buffer was not cleared")
	}
}

func TestLoadRejectsDirectProductionCredentialKeyring(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "production")
	setProductionDatabaseConfig(t)
	setProductionAuthConfig(t)
	t.Setenv("PERIAPSIS_API_CREDENTIAL_KEYRING_FILE", "")
	key := base64.StdEncoding.EncodeToString([]byte("abcdef0123456789abcdef0123456789"))
	t.Setenv("PERIAPSIS_API_CREDENTIAL_KEYRING", `{"activeVersion":1,"keys":[{"version":1,"key":"`+key+`"}]}`)

	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted an environment-only production credential keyring")
	}
}

func TestLoadRejectsDirectOrMissingProductionIdentityKeyring(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	for _, test := range []struct{ name, direct string }{
		{name: "missing"},
		{name: "direct", direct: `{"activeVersion":1,"keys":[{"version":1,"key":"` + key + `"}]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("PERIAPSIS_ENV", "production")
			setProductionDatabaseConfig(t)
			setProductionAuthConfig(t)
			t.Setenv("PERIAPSIS_IDENTITY_KEYRING_FILE", "")
			t.Setenv("PERIAPSIS_IDENTITY_KEYRING", test.direct)
			if _, err := Load(); err == nil {
				t.Fatalf("Load() accepted %s production identity keyring", test.name)
			}
		})
	}
}

func TestLoadRejectsDirectDatabaseURLInProduction(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "production")
	t.Setenv("PERIAPSIS_DATABASE_URL", "postgres://example.invalid/periapsis")
	t.Setenv("PERIAPSIS_DATABASE_URL_FILE", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted an environment-only production database secret")
	}
}

func TestLoadDefaultsToProductionSafetyWhenEnvironmentIsMissing(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "")
	t.Setenv("PERIAPSIS_DATABASE_URL", "postgres://example.invalid/periapsis")
	t.Setenv("PERIAPSIS_DATABASE_URL_FILE", "")

	if _, err := Load(); err == nil {
		t.Fatal("Load() failed open when PERIAPSIS_ENV was missing")
	}
}

func TestLoadRejectsDirectDatabaseURLAlongsideProductionSecretFile(t *testing.T) {
	databaseURLFile := filepath.Join(t.TempDir(), "database-url")
	if err := os.WriteFile(databaseURLFile, []byte("postgres://file.example.invalid/periapsis"), 0o600); err != nil {
		t.Fatalf("write database URL fixture: %v", err)
	}
	t.Setenv("PERIAPSIS_ENV", "production")
	t.Setenv("PERIAPSIS_DATABASE_URL_FILE", databaseURLFile)
	t.Setenv("PERIAPSIS_DATABASE_URL", "postgres://stale.example.invalid/periapsis")

	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted a direct database secret alongside its production secret file")
	}
}

func TestLoadRejectsNonCanonicalEnvironment(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "Production")

	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted a noncanonical environment")
	}
}

func TestLoadRejectsMalformedDurations(t *testing.T) {
	t.Setenv("PERIAPSIS_READINESS_TIMEOUT", "eventually")

	if _, err := Load(); err == nil {
		t.Fatal("Load() silently replaced a malformed duration")
	}
}

func TestLoadParsesTrustedProxyCIDRs(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "development")
	t.Setenv("PERIAPSIS_TRUSTED_PROXY_CIDRS", "10.20.0.0/16, 2001:db8::/32,10.20.0.0/16")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("2001:db8::/32")}
	if len(cfg.TrustedProxyCIDRs) != len(want) {
		t.Fatalf("TrustedProxyCIDRs = %v, want %v", cfg.TrustedProxyCIDRs, want)
	}
	for index := range want {
		if cfg.TrustedProxyCIDRs[index] != want[index] {
			t.Fatalf("TrustedProxyCIDRs[%d] = %v, want %v", index, cfg.TrustedProxyCIDRs[index], want[index])
		}
	}
}

func TestLoadRejectsMalformedTrustedProxyCIDR(t *testing.T) {
	t.Setenv("PERIAPSIS_ENV", "development")
	t.Setenv("PERIAPSIS_TRUSTED_PROXY_CIDRS", "10.20.0.0/16,not-a-network")

	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted a malformed trusted proxy CIDR")
	}
}

func setProductionAuthConfig(t *testing.T) {
	t.Helper()
	masterKeyFile := filepath.Join(t.TempDir(), "master-key")
	encoded := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	if err := os.WriteFile(masterKeyFile, []byte(encoded), 0o600); err != nil {
		t.Fatalf("write master key fixture: %v", err)
	}
	t.Setenv("PERIAPSIS_MASTER_KEY_FILE", masterKeyFile)
	t.Setenv("PERIAPSIS_MASTER_KEY", "")
	bootstrapTokenFile := filepath.Join(t.TempDir(), "bootstrap-token")
	if err := os.WriteFile(bootstrapTokenFile, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatalf("write bootstrap token fixture: %v", err)
	}
	t.Setenv("PERIAPSIS_BOOTSTRAP_TOKEN_FILE", bootstrapTokenFile)
	t.Setenv("PERIAPSIS_BOOTSTRAP_TOKEN", "")
	credentialKeyringFile := filepath.Join(t.TempDir(), "api-credential-keyring")
	credentialKey := base64.StdEncoding.EncodeToString([]byte("abcdef0123456789abcdef0123456789"))
	credentialKeyring := `{"activeVersion":1,"keys":[{"version":1,"key":"` + credentialKey + `"}]}`
	if err := os.WriteFile(credentialKeyringFile, []byte(credentialKeyring), 0o600); err != nil {
		t.Fatalf("write API credential keyring fixture: %v", err)
	}
	t.Setenv("PERIAPSIS_API_CREDENTIAL_KEYRING_FILE", credentialKeyringFile)
	t.Setenv("PERIAPSIS_API_CREDENTIAL_KEYRING", "")
	identityKeyringFile := filepath.Join(t.TempDir(), "identity-keyring")
	identityKey := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	identityKeyring := `{"activeVersion":1,"keys":[{"version":1,"key":"` + identityKey + `"}]}`
	if err := os.WriteFile(identityKeyringFile, []byte(identityKeyring), 0o600); err != nil {
		t.Fatalf("write identity keyring fixture: %v", err)
	}
	t.Setenv("PERIAPSIS_IDENTITY_KEYRING_FILE", identityKeyringFile)
	t.Setenv("PERIAPSIS_IDENTITY_KEYRING", "")
	notificationKeyringFile := filepath.Join(t.TempDir(), "notification-keyring")
	notificationKey := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	notificationKeyring := `{"activeVersion":1,"keys":[{"version":1,"key":"` + notificationKey + `"}]}`
	if err := os.WriteFile(notificationKeyringFile, []byte(notificationKeyring), 0o600); err != nil {
		t.Fatalf("write notification keyring fixture: %v", err)
	}
	t.Setenv("NOTIFICATION_KEYRING_FILE", notificationKeyringFile)
	t.Setenv("NOTIFICATION_KEYRING", "")
	previewTokenFile := filepath.Join(t.TempDir(), "notifier-preview-token")
	if err := os.WriteFile(previewTokenFile, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatalf("write notifier preview token fixture: %v", err)
	}
	t.Setenv("PERIAPSIS_NOTIFIER_PREVIEW_TOKEN_FILE", previewTokenFile)
	t.Setenv("PERIAPSIS_NOTIFIER_PREVIEW_TOKEN", "")
	t.Setenv("PERIAPSIS_NOTIFIER_INTERNAL_URL", "http://notifier-preview:8083")
	t.Setenv("PERIAPSIS_PUBLIC_URL", "https://periapsis.example")
	t.Setenv("PERIAPSIS_WEBAUTHN_ENABLED", "true")
	t.Setenv("PERIAPSIS_WEBAUTHN_RP_ID", "periapsis.example")
}

func setProductionDatabaseConfig(t *testing.T) {
	t.Helper()
	databaseURLFile := filepath.Join(t.TempDir(), "database-url")
	if err := os.WriteFile(databaseURLFile, []byte("postgres://example.invalid/periapsis"), 0o600); err != nil {
		t.Fatalf("write database URL fixture: %v", err)
	}
	t.Setenv("PERIAPSIS_DATABASE_URL_FILE", databaseURLFile)
	t.Setenv("PERIAPSIS_DATABASE_URL", "")
}

func allZeroBytes(value []byte) bool {
	return bytes.Count(value, []byte{0}) == len(value)
}

func equalLDAPPorts(left, right []uint16) bool {
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
