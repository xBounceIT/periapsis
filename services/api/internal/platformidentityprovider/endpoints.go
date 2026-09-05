package platformidentityprovider

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/periapsis-im/periapsis/services/api/internal/origin"
)

const (
	platformOIDCCallbackPath   = "/api/v1/auth/platform/oidc/callback"
	tenantOIDCCallbackPath     = "/api/v1/auth/federated/oidc/callback"
	platformOIDCPostLogoutPath = "/signed-out"
	platformSAMLMetadataPrefix = "/api/v1/auth/platform/saml/"
	platformSAMLMetadataSuffix = "/metadata"
	platformSAMLACSPath        = "/api/v1/auth/platform/saml/acs"
)

// canonicalEndpointPolicy owns every browser-facing endpoint recorded in a
// platform provider configuration. Values are derived once from deployment
// configuration and never from a request Host or forwarding header.
type canonicalEndpointPolicy struct {
	oidcRedirectURI           string
	tenantOIDCRedirectURI     string
	oidcPostLogoutRedirectURI string
	samlMetadataBase          string
	samlACSURL                string
}

func newCanonicalEndpointPolicy(publicOrigin string) (canonicalEndpointPolicy, error) {
	canonical, err := validateCanonicalPublicOrigin(publicOrigin)
	if err != nil {
		return canonicalEndpointPolicy{}, err
	}
	return canonicalEndpointPolicy{
		oidcRedirectURI:           canonical + platformOIDCCallbackPath,
		tenantOIDCRedirectURI:     canonical + tenantOIDCCallbackPath,
		oidcPostLogoutRedirectURI: canonical + platformOIDCPostLogoutPath,
		samlMetadataBase:          canonical + platformSAMLMetadataPrefix,
		samlACSURL:                canonical + platformSAMLACSPath,
	}, nil
}

// validateCanonicalPublicOrigin requires TLS even in development because every
// browser-facing provider endpoint is persisted as an immutable trust boundary.
func validateCanonicalPublicOrigin(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.Path != "" || parsed.RawPath != "" || parsed.ForceQuery ||
		parsed.Scheme != "https" {
		return "", errors.New("canonical public origin is required")
	}
	hostname, err := origin.CanonicalHostname(parsed.Hostname())
	if err != nil || strings.HasSuffix(parsed.Host, ":") {
		return "", errors.New("canonical public origin is required")
	}
	port := parsed.Port()
	if port != "" {
		numericPort, portErr := strconv.Atoi(port)
		if portErr != nil || numericPort < 1 || numericPort > 65535 ||
			numericPort == 443 {
			return "", errors.New("canonical public origin is required")
		}
		port = strconv.Itoa(numericPort)
	}
	canonicalHost := hostname
	if strings.Contains(hostname, ":") {
		canonicalHost = "[" + hostname + "]"
	}
	if port != "" {
		canonicalHost = net.JoinHostPort(hostname, port)
	}
	canonical := parsed.Scheme + "://" + canonicalHost
	if canonical != value {
		return "", errors.New("canonical public origin is required")
	}
	return canonical, nil
}

func (policy canonicalEndpointPolicy) valid() bool {
	return policy.oidcRedirectURI != "" && policy.tenantOIDCRedirectURI != "" &&
		policy.oidcPostLogoutRedirectURI != "" &&
		policy.samlMetadataBase != "" && policy.samlACSURL != ""
}

func (policy canonicalEndpointPolicy) acceptsOIDC(configuration OIDCCreateConfiguration) bool {
	return policy.valid() && configuration.RedirectURI == policy.oidcRedirectURI &&
		configuration.TenantRedirectURI == policy.tenantOIDCRedirectURI &&
		configuration.PostLogoutRedirectURI == policy.oidcPostLogoutRedirectURI
}

func (policy canonicalEndpointPolicy) acceptsSAML(
	providerKey string,
	configuration SAMLCreateConfiguration,
) bool {
	return policy.valid() && providerKeyPattern.MatchString(providerKey) &&
		configuration.SPEntityID == policy.samlMetadataBase+providerKey+platformSAMLMetadataSuffix &&
		configuration.ACSURL == policy.samlACSURL
}
