// Package config loads and validates API runtime configuration.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/modules/identity/webauthn"
	"github.com/periapsis-im/periapsis/services/api/internal/apiratelimit"
	"github.com/periapsis-im/periapsis/services/api/internal/notification"
	"github.com/periapsis-im/periapsis/services/api/internal/origin"
	"github.com/periapsis-im/periapsis/services/api/internal/serviceaccount"
)

const (
	defaultAddress                = ":8080"
	defaultReadinessTimeout       = 2 * time.Second
	defaultRequestTimeout         = 15 * time.Second
	defaultShutdownTimeout        = 10 * time.Second
	defaultBootstrapTimeout       = 10 * time.Minute
	defaultMFAChallengeTTL        = 5 * time.Minute
	defaultSessionIdleTTL         = 30 * time.Minute
	defaultSessionAbsoluteTTL     = 8 * time.Hour
	defaultAuthKDFConcurrency     = 2
	defaultAPINetworkRPS          = 100
	defaultAPICredentialRPS       = 60
	defaultAPITenantSubjectRPS    = 40
	defaultFederatedMaxConcurrent = 16
	defaultFederatedOIDCClockSkew = time.Minute
	defaultFederatedOperationTTL  = 20 * time.Second
	defaultLDAPMaxConcurrent      = 8
	defaultNotifierURL            = "http://localhost:8083"
	minimumNonPrivilegedPort      = 1024
)

// Config contains non-secret API runtime settings and the database connection URL.
type Config struct {
	Address                     string
	APIRateLimitPolicy          apiratelimit.Policy
	AuthKDFConcurrency          int
	BootstrapEnrollmentTimeout  time.Duration
	BootstrapTokenDigest        []byte
	CredentialKeyring           serviceaccount.CredentialKeyring
	DatabaseURL                 string
	DocsEnabled                 bool
	Environment                 string
	FederatedAllowedHTTPSPorts  []uint16
	FederatedCABundleFile       string
	FederatedMaxConcurrent      int
	FederatedOIDCClockSkew      time.Duration
	FederatedOperationTimeout   time.Duration
	FederatedPrivateEgressCIDRs []netip.Prefix
	IdentityKeyring             identity.Keyring
	LDAPAllowedLDAPSPorts       []uint16
	LDAPAllowedStartTLSPorts    []uint16
	LDAPMaxConcurrent           int
	LDAPPrivateEgressCIDRs      []netip.Prefix
	MasterKey                   []byte
	MFAChallengeTimeout         time.Duration
	NotificationKeyring         notification.Keyring
	NotifierInternalURL         string
	NotifierPreviewToken        []byte
	PublicOrigin                string
	ReadinessTimeout            time.Duration
	RequestTimeout              time.Duration
	Release                     string
	SessionAbsoluteTimeout      time.Duration
	SessionIdleTimeout          time.Duration
	ShutdownTimeout             time.Duration
	SMTPAllowPlainLocal         bool
	TrustedProxyCIDRs           []netip.Prefix
	WebhookAllowPlainLocal      bool
	WebAuthnEnabled             bool
	WebAuthnRPID                string
}

// Load reads configuration from environment variables and rejects unsafe production defaults.
func Load() (Config, error) {
	var bootstrapTokenDigest, masterKey, notifierPreviewToken []byte
	retainSecrets := false
	defer func() {
		if !retainSecrets {
			clear(bootstrapTokenDigest)
			clear(masterKey)
			clear(notifierPreviewToken)
		}
	}()

	databaseURL, err := valueOrFile("PERIAPSIS_DATABASE_URL")
	if err != nil {
		return Config{}, err
	}
	environment := valueOrDefault("PERIAPSIS_ENV", "production")
	if err := validateEnvironment(environment); err != nil {
		return Config{}, err
	}
	notifierInternalURL := valueOrDefault("PERIAPSIS_NOTIFIER_INTERNAL_URL", defaultNotifierURL)
	notifierPreviewToken, err = loadNotifierPreviewToken(environment)
	if err != nil {
		return Config{}, err
	}
	docsEnabled, err := boolValue("PERIAPSIS_DOCS_ENABLED", environment != "production")
	if err != nil {
		return Config{}, err
	}
	smtpAllowPlainLocal, err := boolValue("PERIAPSIS_SMTP_ALLOW_PLAIN_LOCAL", false)
	if err != nil {
		return Config{}, err
	}
	if environment == "production" && smtpAllowPlainLocal {
		return Config{}, errors.New("PERIAPSIS_SMTP_ALLOW_PLAIN_LOCAL cannot be enabled in production")
	}
	webhookAllowPlainLocal, err := boolValue("PERIAPSIS_WEBHOOK_ALLOW_PLAIN_LOCAL", false)
	if err != nil {
		return Config{}, err
	}
	if environment == "production" && webhookAllowPlainLocal {
		return Config{}, errors.New("PERIAPSIS_WEBHOOK_ALLOW_PLAIN_LOCAL cannot be enabled in production")
	}
	readinessTimeout, err := durationValue("PERIAPSIS_READINESS_TIMEOUT", defaultReadinessTimeout)
	if err != nil {
		return Config{}, err
	}
	requestTimeout, err := durationValue("PERIAPSIS_REQUEST_TIMEOUT", defaultRequestTimeout)
	if err != nil {
		return Config{}, err
	}
	shutdownTimeout, err := durationValue("PERIAPSIS_SHUTDOWN_TIMEOUT", defaultShutdownTimeout)
	if err != nil {
		return Config{}, err
	}
	bootstrapTimeout, err := durationValue("PERIAPSIS_BOOTSTRAP_ENROLLMENT_TIMEOUT", defaultBootstrapTimeout)
	if err != nil {
		return Config{}, err
	}
	mfaChallengeTimeout, err := durationValue("PERIAPSIS_MFA_CHALLENGE_TIMEOUT", defaultMFAChallengeTTL)
	if err != nil {
		return Config{}, err
	}
	sessionIdleTimeout, err := durationValue("PERIAPSIS_SESSION_IDLE_TIMEOUT", defaultSessionIdleTTL)
	if err != nil {
		return Config{}, err
	}
	sessionAbsoluteTimeout, err := durationValue("PERIAPSIS_SESSION_ABSOLUTE_TIMEOUT", defaultSessionAbsoluteTTL)
	if err != nil {
		return Config{}, err
	}
	publicOrigin, err := validatePublicOrigin(
		valueOrDefault("PERIAPSIS_PUBLIC_URL", "http://localhost:8081"),
		environment,
	)
	if err != nil {
		return Config{}, err
	}
	webAuthnEnabled, err := boolValue("PERIAPSIS_WEBAUTHN_ENABLED", environment == "production")
	if err != nil {
		return Config{}, err
	}
	if environment == "production" && !webAuthnEnabled {
		return Config{}, errors.New("PERIAPSIS_WEBAUTHN_ENABLED cannot be disabled in production")
	}
	webAuthnRPID := strings.TrimSpace(os.Getenv("PERIAPSIS_WEBAUTHN_RP_ID"))
	if webAuthnEnabled {
		if environment == "production" && webAuthnRPID == "" {
			return Config{}, errors.New("PERIAPSIS_WEBAUTHN_RP_ID is required in production")
		}
		if webAuthnRPID == "" {
			parsedOrigin, parseErr := url.Parse(publicOrigin)
			if parseErr != nil {
				return Config{}, errors.New("PERIAPSIS_PUBLIC_URL cannot derive a WebAuthn RP ID")
			}
			webAuthnRPID = parsedOrigin.Hostname()
		}
		if _, compileErr := webauthn.CompileRelyingParty(webAuthnRPID, []string{publicOrigin}, 1); compileErr != nil {
			return Config{}, errors.New("PERIAPSIS_WEBAUTHN_RP_ID and PERIAPSIS_PUBLIC_URL are not a valid relying-party pin")
		}
	} else if webAuthnRPID != "" {
		return Config{}, errors.New("PERIAPSIS_WEBAUTHN_RP_ID requires PERIAPSIS_WEBAUTHN_ENABLED")
	}
	trustedProxyCIDRs, err := parseTrustedProxyCIDRs(os.Getenv("PERIAPSIS_TRUSTED_PROXY_CIDRS"))
	if err != nil {
		return Config{}, err
	}
	authKDFConcurrency, err := intValue("PERIAPSIS_AUTH_KDF_CONCURRENCY", defaultAuthKDFConcurrency)
	if err != nil {
		return Config{}, err
	}
	apiNetworkRPS, err := intValue("PERIAPSIS_API_RATE_LIMIT_NETWORK_RPS", defaultAPINetworkRPS)
	if err != nil {
		return Config{}, err
	}
	apiCredentialRPS, err := intValue("PERIAPSIS_API_RATE_LIMIT_CREDENTIAL_RPS", defaultAPICredentialRPS)
	if err != nil {
		return Config{}, err
	}
	apiTenantSubjectRPS, err := intValue("PERIAPSIS_API_RATE_LIMIT_TENANT_SUBJECT_RPS", defaultAPITenantSubjectRPS)
	if err != nil {
		return Config{}, err
	}
	ldapPrivateEgressCIDRs, err := parseLDAPPrivateEgressCIDRs(os.Getenv("PERIAPSIS_LDAP_PRIVATE_EGRESS_CIDRS"))
	if err != nil {
		return Config{}, err
	}
	ldapStartTLSPorts, err := parseLDAPAllowedPorts("PERIAPSIS_LDAP_STARTTLS_PORTS")
	if err != nil {
		return Config{}, err
	}
	ldapPorts, err := parseLDAPAllowedPorts("PERIAPSIS_LDAP_LDAPS_PORTS")
	if err != nil {
		return Config{}, err
	}
	ldapMaxConcurrent, err := intValue("PERIAPSIS_LDAP_MAX_CONCURRENT", defaultLDAPMaxConcurrent)
	if err != nil {
		return Config{}, err
	}
	federatedPrivateEgressCIDRs, err := parseFederatedPrivateEgressCIDRs(
		os.Getenv("PERIAPSIS_FEDERATED_PRIVATE_EGRESS_CIDRS"),
	)
	if err != nil {
		return Config{}, err
	}
	federatedHTTPSPorts, err := parseLDAPAllowedPorts("PERIAPSIS_FEDERATED_HTTPS_PORTS")
	if err != nil {
		return Config{}, err
	}
	federatedMaxConcurrent, err := intValue("PERIAPSIS_FEDERATED_MAX_CONCURRENT", defaultFederatedMaxConcurrent)
	if err != nil {
		return Config{}, err
	}
	federatedOIDCClockSkew, err := durationValue(
		"PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW",
		defaultFederatedOIDCClockSkew,
	)
	if err != nil {
		return Config{}, err
	}
	federatedOperationTimeout, err := durationValue(
		"PERIAPSIS_FEDERATED_OPERATION_TIMEOUT",
		defaultFederatedOperationTTL,
	)
	if err != nil {
		return Config{}, err
	}
	bootstrapToken, err := secretBytesOrFile("PERIAPSIS_BOOTSTRAP_TOKEN")
	if err != nil {
		return Config{}, err
	}
	bootstrapTokenDigest, err = digestBootstrapToken(bootstrapToken)
	if err != nil {
		return Config{}, err
	}
	masterKeyEncoded, err := secretBytesOrFile("PERIAPSIS_MASTER_KEY")
	if err != nil {
		return Config{}, err
	}
	masterKey, err = decodeMasterKey(masterKeyEncoded)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		Address: valueOrDefault("PERIAPSIS_API_ADDR", defaultAddress),
		APIRateLimitPolicy: apiratelimit.Policy{
			NetworkRequestsPerSecond:       int32(apiNetworkRPS),
			CredentialRequestsPerSecond:    int32(apiCredentialRPS),
			TenantSubjectRequestsPerSecond: int32(apiTenantSubjectRPS),
		},
		AuthKDFConcurrency:          authKDFConcurrency,
		BootstrapEnrollmentTimeout:  bootstrapTimeout,
		BootstrapTokenDigest:        bootstrapTokenDigest,
		DatabaseURL:                 databaseURL,
		DocsEnabled:                 docsEnabled,
		Environment:                 environment,
		FederatedAllowedHTTPSPorts:  federatedHTTPSPorts,
		FederatedCABundleFile:       strings.TrimSpace(os.Getenv("PERIAPSIS_FEDERATED_CA_BUNDLE_FILE")),
		FederatedMaxConcurrent:      federatedMaxConcurrent,
		FederatedOIDCClockSkew:      federatedOIDCClockSkew,
		FederatedOperationTimeout:   federatedOperationTimeout,
		FederatedPrivateEgressCIDRs: federatedPrivateEgressCIDRs,
		LDAPAllowedLDAPSPorts:       ldapPorts,
		LDAPAllowedStartTLSPorts:    ldapStartTLSPorts,
		LDAPMaxConcurrent:           ldapMaxConcurrent,
		LDAPPrivateEgressCIDRs:      ldapPrivateEgressCIDRs,
		MasterKey:                   masterKey,
		MFAChallengeTimeout:         mfaChallengeTimeout,
		NotifierInternalURL:         notifierInternalURL,
		NotifierPreviewToken:        notifierPreviewToken,
		PublicOrigin:                publicOrigin,
		ReadinessTimeout:            readinessTimeout,
		RequestTimeout:              requestTimeout,
		Release:                     valueOrDefault("PERIAPSIS_RELEASE", "development"),
		SessionAbsoluteTimeout:      sessionAbsoluteTimeout,
		SessionIdleTimeout:          sessionIdleTimeout,
		ShutdownTimeout:             shutdownTimeout,
		SMTPAllowPlainLocal:         smtpAllowPlainLocal,
		TrustedProxyCIDRs:           trustedProxyCIDRs,
		WebhookAllowPlainLocal:      webhookAllowPlainLocal,
		WebAuthnEnabled:             webAuthnEnabled,
		WebAuthnRPID:                webAuthnRPID,
	}

	if err := validateAddress(cfg.Address); err != nil {
		return Config{}, err
	}
	if cfg.ReadinessTimeout <= 0 || cfg.ReadinessTimeout > 30*time.Second {
		return Config{}, errors.New("PERIAPSIS_READINESS_TIMEOUT must be between 1ns and 30s")
	}
	if cfg.RequestTimeout < time.Second || cfg.RequestTimeout > 25*time.Second {
		return Config{}, errors.New("PERIAPSIS_REQUEST_TIMEOUT must be between 1s and 25s")
	}
	if cfg.ShutdownTimeout <= 0 || cfg.ShutdownTimeout > time.Minute {
		return Config{}, errors.New("PERIAPSIS_SHUTDOWN_TIMEOUT must be between 1ns and 1m")
	}
	if cfg.BootstrapEnrollmentTimeout < 2*time.Minute || cfg.BootstrapEnrollmentTimeout > 15*time.Minute {
		return Config{}, errors.New("PERIAPSIS_BOOTSTRAP_ENROLLMENT_TIMEOUT must be between 2m and 15m")
	}
	if cfg.MFAChallengeTimeout < time.Minute || cfg.MFAChallengeTimeout > 15*time.Minute {
		return Config{}, errors.New("PERIAPSIS_MFA_CHALLENGE_TIMEOUT must be between 1m and 15m")
	}
	if cfg.SessionIdleTimeout < 5*time.Minute || cfg.SessionIdleTimeout > 24*time.Hour {
		return Config{}, errors.New("PERIAPSIS_SESSION_IDLE_TIMEOUT must be between 5m and 24h")
	}
	if cfg.SessionAbsoluteTimeout < cfg.SessionIdleTimeout || cfg.SessionAbsoluteTimeout > 7*24*time.Hour {
		return Config{}, errors.New("PERIAPSIS_SESSION_ABSOLUTE_TIMEOUT must be at least the idle timeout and at most 168h")
	}
	if cfg.AuthKDFConcurrency < 1 || cfg.AuthKDFConcurrency > 16 {
		return Config{}, errors.New("PERIAPSIS_AUTH_KDF_CONCURRENCY must be between 1 and 16")
	}
	if apiNetworkRPS < 1 || apiNetworkRPS > int(apiratelimit.MaximumRequestsPerSecond) ||
		apiCredentialRPS < 1 || apiCredentialRPS > int(apiratelimit.MaximumRequestsPerSecond) ||
		apiTenantSubjectRPS < 1 || apiTenantSubjectRPS > int(apiratelimit.MaximumRequestsPerSecond) {
		return Config{}, errors.New("PERIAPSIS_API_RATE_LIMIT_*_RPS values must be between 1 and 100")
	}
	if cfg.LDAPMaxConcurrent < 1 || cfg.LDAPMaxConcurrent > 256 {
		return Config{}, errors.New("PERIAPSIS_LDAP_MAX_CONCURRENT must be between 1 and 256")
	}
	if cfg.FederatedMaxConcurrent < 1 || cfg.FederatedMaxConcurrent > 256 {
		return Config{}, errors.New("PERIAPSIS_FEDERATED_MAX_CONCURRENT must be between 1 and 256")
	}
	if cfg.FederatedOIDCClockSkew < 0 || cfg.FederatedOIDCClockSkew > 5*time.Minute ||
		cfg.FederatedOIDCClockSkew%time.Microsecond != 0 {
		return Config{}, errors.New("PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW must be microsecond-aligned and between 0s and 5m")
	}
	if cfg.FederatedOperationTimeout < 100*time.Millisecond || cfg.FederatedOperationTimeout > 2*time.Minute ||
		cfg.FederatedOperationTimeout%time.Microsecond != 0 {
		return Config{}, errors.New("PERIAPSIS_FEDERATED_OPERATION_TIMEOUT must be microsecond-aligned and between 100ms and 2m")
	}
	if cfg.Environment == "production" {
		if strings.TrimSpace(os.Getenv("PERIAPSIS_DATABASE_URL")) != "" {
			return Config{}, errors.New("PERIAPSIS_DATABASE_URL must not be set in production; use PERIAPSIS_DATABASE_URL_FILE")
		}
		if strings.TrimSpace(os.Getenv("PERIAPSIS_DATABASE_URL_FILE")) == "" || cfg.DatabaseURL == "" {
			return Config{}, errors.New("PERIAPSIS_DATABASE_URL_FILE is required in production")
		}
		if strings.TrimSpace(os.Getenv("PERIAPSIS_BOOTSTRAP_TOKEN")) != "" {
			return Config{}, errors.New("PERIAPSIS_BOOTSTRAP_TOKEN must not be set in production; use PERIAPSIS_BOOTSTRAP_TOKEN_FILE")
		}
		if strings.TrimSpace(os.Getenv("PERIAPSIS_BOOTSTRAP_TOKEN_FILE")) == "" || len(cfg.BootstrapTokenDigest) != sha256.Size {
			return Config{}, errors.New("PERIAPSIS_BOOTSTRAP_TOKEN_FILE is required in production")
		}
		if strings.TrimSpace(os.Getenv("PERIAPSIS_MASTER_KEY")) != "" {
			return Config{}, errors.New("PERIAPSIS_MASTER_KEY must not be set in production; use PERIAPSIS_MASTER_KEY_FILE")
		}
		if strings.TrimSpace(os.Getenv("PERIAPSIS_MASTER_KEY_FILE")) == "" || len(cfg.MasterKey) != 32 {
			return Config{}, errors.New("PERIAPSIS_MASTER_KEY_FILE is required in production")
		}
		if strings.TrimSpace(os.Getenv("PERIAPSIS_API_CREDENTIAL_KEYRING")) != "" {
			return Config{}, errors.New("PERIAPSIS_API_CREDENTIAL_KEYRING must not be set in production; use PERIAPSIS_API_CREDENTIAL_KEYRING_FILE")
		}
		if strings.TrimSpace(os.Getenv("PERIAPSIS_API_CREDENTIAL_KEYRING_FILE")) == "" {
			return Config{}, errors.New("PERIAPSIS_API_CREDENTIAL_KEYRING_FILE is required in production")
		}
		if strings.TrimSpace(os.Getenv("PERIAPSIS_IDENTITY_KEYRING")) != "" {
			return Config{}, errors.New("PERIAPSIS_IDENTITY_KEYRING must not be set in production; use PERIAPSIS_IDENTITY_KEYRING_FILE")
		}
		if strings.TrimSpace(os.Getenv("PERIAPSIS_IDENTITY_KEYRING_FILE")) == "" {
			return Config{}, errors.New("PERIAPSIS_IDENTITY_KEYRING_FILE is required in production")
		}
		if strings.TrimSpace(os.Getenv("NOTIFICATION_KEYRING")) != "" {
			return Config{}, errors.New("NOTIFICATION_KEYRING must not be set; use NOTIFICATION_KEYRING_FILE")
		}
		if strings.TrimSpace(os.Getenv("NOTIFICATION_KEYRING_FILE")) == "" {
			return Config{}, errors.New("NOTIFICATION_KEYRING_FILE is required in production")
		}
		if strings.TrimSpace(os.Getenv("PERIAPSIS_NOTIFIER_INTERNAL_URL")) == "" {
			return Config{}, errors.New("PERIAPSIS_NOTIFIER_INTERNAL_URL is required in production")
		}
	}

	credentialKeyringDocument, err := secretBytesOrFile("PERIAPSIS_API_CREDENTIAL_KEYRING")
	if err != nil {
		return Config{}, err
	}
	if len(credentialKeyringDocument) != 0 {
		cfg.CredentialKeyring, err = parseCredentialKeyringDocument(credentialKeyringDocument)
		if err != nil {
			return Config{}, err
		}
	}
	if cfg.Environment == "production" && cfg.CredentialKeyring.ActiveVersion() == 0 {
		return Config{}, errors.New("PERIAPSIS_API_CREDENTIAL_KEYRING_FILE is required in production")
	}
	identityKeyringDocument, err := secretBytesOrFile("PERIAPSIS_IDENTITY_KEYRING")
	if err != nil {
		return Config{}, err
	}
	if len(identityKeyringDocument) != 0 {
		cfg.IdentityKeyring, err = identity.ParseKeyringDocument(identityKeyringDocument)
		if err != nil {
			return Config{}, errors.New("PERIAPSIS_IDENTITY_KEYRING contains an invalid keyring document")
		}
	}
	if cfg.Environment == "production" && cfg.IdentityKeyring.ActiveVersion() == 0 {
		return Config{}, errors.New("PERIAPSIS_IDENTITY_KEYRING_FILE is required in production")
	}
	notificationKeyringDocument, err := exactSecretFile("NOTIFICATION_KEYRING_FILE")
	if err != nil {
		return Config{}, err
	}
	if len(notificationKeyringDocument) != 0 {
		cfg.NotificationKeyring, err = notification.ParseKeyringDocument(notificationKeyringDocument)
		clear(notificationKeyringDocument)
		if err != nil {
			return Config{}, errors.New("NOTIFICATION_KEYRING_FILE contains an invalid keyring document")
		}
	}
	if cfg.Environment == "production" && cfg.NotificationKeyring.ActiveVersion() == 0 {
		return Config{}, errors.New("NOTIFICATION_KEYRING_FILE is required in production")
	}
	retainSecrets = true
	return cfg, nil
}

func parseLDAPPrivateEgressCIDRs(value string) ([]netip.Prefix, error) {
	return parseCanonicalPrivateEgressCIDRs("PERIAPSIS_LDAP_PRIVATE_EGRESS_CIDRS", value)
}

func parseFederatedPrivateEgressCIDRs(value string) ([]netip.Prefix, error) {
	return parseCanonicalPrivateEgressCIDRs("PERIAPSIS_FEDERATED_PRIVATE_EGRESS_CIDRS", value)
}

func parseCanonicalPrivateEgressCIDRs(name, value string) ([]netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	if len(parts) > 64 {
		return nil, fmt.Errorf("%s must contain at most 64 entries", name)
	}
	prefixes := make([]netip.Prefix, 0, len(parts))
	seen := make(map[netip.Prefix]struct{}, len(parts))
	for _, part := range parts {
		canonical := strings.TrimSpace(part)
		prefix, err := netip.ParsePrefix(canonical)
		if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
			return nil, fmt.Errorf("%s must be a comma-separated canonical CIDR list", name)
		}
		if prefix != prefix.Masked() || prefix.String() != canonical {
			return nil, fmt.Errorf("%s must be a comma-separated canonical CIDR list", name)
		}
		if _, duplicate := seen[prefix]; duplicate {
			return nil, fmt.Errorf("%s must not contain duplicates", name)
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func parseLDAPAllowedPorts(name string) ([]uint16, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	if len(parts) > 16 {
		return nil, fmt.Errorf("%s must contain at most 16 ports", name)
	}
	ports := make([]uint16, 0, len(parts))
	seen := make(map[uint16]struct{}, len(parts))
	for _, part := range parts {
		canonical := strings.TrimSpace(part)
		parsed, err := strconv.ParseUint(canonical, 10, 16)
		if err != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != canonical {
			return nil, fmt.Errorf("%s must be a comma-separated canonical port list", name)
		}
		port := uint16(parsed)
		if _, duplicate := seen[port]; duplicate {
			return nil, fmt.Errorf("%s must not contain duplicate ports", name)
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	return ports, nil
}

func parseTrustedProxyCIDRs(value string) ([]netip.Prefix, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	if len(parts) > 32 {
		return nil, errors.New("PERIAPSIS_TRUSTED_PROXY_CIDRS must contain at most 32 entries")
	}
	prefixes := make([]netip.Prefix, 0, len(parts))
	seen := make(map[netip.Prefix]struct{}, len(parts))
	for _, part := range parts {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil {
			return nil, errors.New("PERIAPSIS_TRUSTED_PROXY_CIDRS must be a comma-separated CIDR list")
		}
		prefix = prefix.Masked()
		if _, exists := seen[prefix]; exists {
			continue
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func validatePublicOrigin(rawURL, environment string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", errors.New("PERIAPSIS_PUBLIC_URL must be an absolute origin without credentials, path, query, or fragment")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" && !(environment != "production" && scheme == "http") {
		return "", errors.New("PERIAPSIS_PUBLIC_URL must use HTTPS in production")
	}
	hostname, err := origin.CanonicalHostname(parsed.Hostname())
	if err != nil {
		return "", errors.New("PERIAPSIS_PUBLIC_URL host must be a canonical ASCII hostname or IP address")
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return "", errors.New("PERIAPSIS_PUBLIC_URL contains an empty port")
	}
	port := parsed.Port()
	if port != "" {
		parsedPort, portErr := strconv.Atoi(port)
		if portErr != nil || parsedPort < 1 || parsedPort > 65535 {
			return "", errors.New("PERIAPSIS_PUBLIC_URL contains an invalid port")
		}
		if parsedPort == 443 && scheme == "https" || parsedPort == 80 && scheme == "http" {
			port = ""
		} else {
			port = strconv.Itoa(parsedPort)
		}
	}
	host := hostname
	if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	if port != "" {
		host = net.JoinHostPort(hostname, port)
	}
	return scheme + "://" + host, nil
}

func validateEnvironment(environment string) error {
	switch environment {
	case "development", "test", "production":
		return nil
	default:
		return errors.New("PERIAPSIS_ENV must be development, test, or production")
	}
}

func validateAddress(address string) error {
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("PERIAPSIS_API_ADDR must be host:port: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < minimumNonPrivilegedPort || port > 65535 {
		return errors.New("PERIAPSIS_API_ADDR must use a non-privileged TCP port")
	}
	return nil
}

func valueOrDefault(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func boolValue(name string, fallback bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", name)
	}
	return parsed, nil
}

func durationValue(name string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid duration: %w", name, err)
	}
	return parsed, nil
}

func intValue(name string, fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", name)
	}
	return parsed, nil
}

func valueOrFile(name string) (string, error) {
	fileName := strings.TrimSpace(os.Getenv(name + "_FILE"))
	if fileName == "" {
		return strings.TrimSpace(os.Getenv(name)), nil
	}
	contents, err := os.ReadFile(fileName)
	if err != nil {
		return "", fmt.Errorf("read %s_FILE: %w", name, err)
	}
	value := strings.TrimSpace(string(contents))
	if value == "" {
		return "", fmt.Errorf("%s_FILE contains an empty value", name)
	}
	return value, nil
}

func secretBytesOrFile(name string) ([]byte, error) {
	fileName := strings.TrimSpace(os.Getenv(name + "_FILE"))
	if fileName == "" {
		value := strings.TrimSpace(os.Getenv(name))
		if value == "" {
			return nil, nil
		}
		return []byte(value), nil
	}
	contents, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("read %s_FILE: %w", name, err)
	}
	trimmed := bytes.TrimSpace(contents)
	if len(trimmed) == 0 {
		clear(contents)
		return nil, fmt.Errorf("%s_FILE contains an empty value", name)
	}
	copy(contents, trimmed)
	clear(contents[len(trimmed):])
	return contents[:len(trimmed)], nil
}

func exactSecretFile(name string) ([]byte, error) {
	fileName := strings.TrimSpace(os.Getenv(name))
	if fileName == "" {
		return nil, nil
	}
	contents, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	trimmed := bytes.TrimSpace(contents)
	if len(trimmed) == 0 || len(trimmed) > 64*1024 {
		clear(contents)
		return nil, fmt.Errorf("%s contains an empty or oversized value", name)
	}
	copy(contents, trimmed)
	clear(contents[len(trimmed):])
	return contents[:len(trimmed)], nil
}

func loadNotifierPreviewToken(environment string) ([]byte, error) {
	const name = "PERIAPSIS_NOTIFIER_PREVIEW_TOKEN"
	direct := strings.TrimSpace(os.Getenv(name))
	fileName := strings.TrimSpace(os.Getenv(name + "_FILE"))
	if direct != "" && fileName != "" {
		return nil, errors.New("PERIAPSIS_NOTIFIER_PREVIEW_TOKEN must use exactly one secret source")
	}
	if environment == "production" {
		if direct != "" {
			return nil, errors.New("PERIAPSIS_NOTIFIER_PREVIEW_TOKEN must not be set in production; use PERIAPSIS_NOTIFIER_PREVIEW_TOKEN_FILE")
		}
		if fileName == "" {
			return nil, errors.New("PERIAPSIS_NOTIFIER_PREVIEW_TOKEN_FILE is required in production")
		}
	}
	value, err := secretBytesOrFile(name)
	if err != nil {
		return nil, err
	}
	if len(value) == 0 {
		return nil, nil
	}
	if !validNotifierPreviewToken(value) {
		clear(value)
		return nil, errors.New("PERIAPSIS_NOTIFIER_PREVIEW_TOKEN must contain a strong ASCII bearer token")
	}
	return value, nil
}

func validNotifierPreviewToken(value []byte) bool {
	if len(value) < 32 || len(value) > 512 {
		return false
	}
	for _, character := range value {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._~+/=-", rune(character)) {
			continue
		}
		return false
	}
	return true
}

func digestBootstrapToken(value []byte) ([]byte, error) {
	defer clear(value)
	if len(value) == 0 {
		return nil, nil
	}
	if len(value) < 32 || len(value) > 1024 {
		return nil, errors.New("PERIAPSIS_BOOTSTRAP_TOKEN must contain between 32 and 1024 bytes")
	}
	digest := sha256.Sum256(value)
	result := append([]byte(nil), digest[:]...)
	clear(digest[:])
	return result, nil
}

func decodeMasterKey(encoded []byte) ([]byte, error) {
	defer clear(encoded)
	if len(encoded) == 0 {
		return nil, nil
	}
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	decodedBytes, err := base64.StdEncoding.Strict().Decode(decoded, encoded)
	if err != nil || decodedBytes != 32 {
		clear(decoded)
		return nil, errors.New("PERIAPSIS_MASTER_KEY must be standard padded Base64 for exactly 32 bytes")
	}
	decoded = decoded[:decodedBytes]
	canonical := make([]byte, base64.StdEncoding.EncodedLen(len(decoded)))
	base64.StdEncoding.Encode(canonical, decoded)
	canonicalEncoding := bytes.Equal(canonical, encoded)
	clear(canonical)
	if !canonicalEncoding {
		clear(decoded)
		return nil, errors.New("PERIAPSIS_MASTER_KEY must be standard padded Base64 for exactly 32 bytes")
	}
	return decoded, nil
}

func parseCredentialKeyringDocument(document []byte) (serviceaccount.CredentialKeyring, error) {
	defer clear(document)
	return serviceaccount.ParseCredentialKeyring(document)
}
