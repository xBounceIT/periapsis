package httpserver

import (
	"errors"
	"math"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	identity "github.com/periapsis-im/periapsis/modules/identity"
	"github.com/periapsis-im/periapsis/services/api/internal/authentication"
	"github.com/periapsis-im/periapsis/services/api/internal/origin"
	"github.com/periapsis-im/periapsis/services/api/internal/platformsamladapter"
)

type federatedProtocol string

const (
	federatedProtocolOIDC         federatedProtocol = "oidc"
	federatedProtocolSAML         federatedProtocol = "saml"
	federatedProtocolPlatformOIDC federatedProtocol = "platform_oidc"
	federatedProtocolPlatformSAML federatedProtocol = "platform_saml"
	federatedProtocolLDAP         federatedProtocol = "ldap"
	federatedProtocolPlatformLDAP federatedProtocol = "platform_ldap"

	developmentOIDCTransactionCookie         = "periapsis_oidc_transaction"
	developmentSAMLTransactionCookie         = "periapsis_saml_transaction"
	developmentPlatformOIDCTransactionCookie = "periapsis_platform_oidc_transaction"
	developmentPlatformSAMLTransactionCookie = platformsamladapter.DirectSAMLDevelopmentTransactionCookie
	productionOIDCTransactionCookie          = "__Host-periapsis_oidc_transaction"
	productionSAMLTransactionCookie          = "__Host-periapsis_saml_transaction"
	productionPlatformOIDCTransactionCookie  = "__Host-periapsis_platform_oidc_transaction"
	productionPlatformSAMLTransactionCookie  = platformsamladapter.DirectSAMLProductionTransactionCookie

	// FederatedContinuationPath is shared with protocol-neutral browser
	// transports that must emit the exact post-primary continuation redirect.
	// The handler keeps the private alias so existing route code cannot drift
	// from the exported composition contract.
	FederatedContinuationPath       = "/?auth=federated-mfa"
	federatedContinuationPath       = FederatedContinuationPath
	maximumFederatedReturnPathBytes = 2 * 1024
	maximumOIDCRedirectBytes        = 16 * 1024
	maximumSAMLRedirectBytes        = 64 * 1024
	maximumFederatedTransactionTTL  = 15 * time.Minute
)

type federatedTransactionCookiePolicy struct {
	name     string
	sameSite http.SameSite
}

func newFederatedTransactionCookiePolicy(
	environment string,
	publicOrigin string,
	protocol federatedProtocol,
) (federatedTransactionCookiePolicy, error) {
	var developmentName, secureName string
	var sameSite http.SameSite
	switch protocol {
	case federatedProtocolOIDC:
		developmentName = developmentOIDCTransactionCookie
		secureName = productionOIDCTransactionCookie
		sameSite = http.SameSiteLaxMode
	case federatedProtocolPlatformOIDC:
		developmentName = developmentPlatformOIDCTransactionCookie
		secureName = productionPlatformOIDCTransactionCookie
		sameSite = http.SameSiteLaxMode
	case federatedProtocolSAML:
		developmentName = developmentSAMLTransactionCookie
		secureName = productionSAMLTransactionCookie
		sameSite = http.SameSiteNoneMode
	case federatedProtocolPlatformSAML:
		developmentName = developmentPlatformSAMLTransactionCookie
		secureName = productionPlatformSAMLTransactionCookie
		sameSite = http.SameSiteNoneMode
	default:
		return federatedTransactionCookiePolicy{}, errors.New("unsupported federated protocol")
	}
	secureOrigin, err := browserOriginUsesSecureCookies(environment, publicOrigin)
	if err != nil {
		return federatedTransactionCookiePolicy{}, err
	}
	name := developmentName
	if secureOrigin {
		name = secureName
	}
	return federatedTransactionCookiePolicy{name: name, sameSite: sameSite}, nil
}

func setFederatedTransactionCookie(
	w http.ResponseWriter,
	policy federatedTransactionCookiePolicy,
	handle []byte,
	expiresAt time.Time,
	now time.Time,
) error {
	if !validFederatedTransactionCookiePolicy(policy) || !validMFABrowserHandle(string(handle)) ||
		!validFederatedExpiry(expiresAt, now) {
		return errFederatedTransportUnavailable
	}
	maxAge := int(math.Ceil(expiresAt.Sub(now).Seconds()))
	if maxAge < 1 {
		return errFederatedTransportUnavailable
	}
	http.SetCookie(w, &http.Cookie{
		Name: policy.name, Value: string(handle), Path: "/", Expires: expiresAt,
		MaxAge: maxAge, HttpOnly: true, Secure: true, SameSite: policy.sameSite,
	})
	return nil
}

func clearFederatedTransactionCookie(w http.ResponseWriter, policy federatedTransactionCookiePolicy) {
	if !validFederatedTransactionCookiePolicy(policy) {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: policy.name, Value: "", Path: "/", Expires: time.Unix(1, 0).UTC(),
		MaxAge: -1, HttpOnly: true, Secure: true, SameSite: policy.sameSite,
	})
}

func federatedTransactionHandle(
	r *http.Request,
	policy federatedTransactionCookiePolicy,
	required bool,
) ([]byte, error) {
	if r == nil || !validFederatedTransactionCookiePolicy(policy) {
		return nil, authentication.ErrInvalidAuthentication
	}
	value := ""
	count := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == policy.name {
			count++
			value = cookie.Value
		}
	}
	if count == 0 && !required {
		return nil, nil
	}
	if count != 1 || !validMFABrowserHandle(value) {
		return nil, authentication.ErrInvalidAuthentication
	}
	return []byte(value), nil
}

func validFederatedTransactionCookiePolicy(policy federatedTransactionCookiePolicy) bool {
	return policy.name != "" &&
		(policy.sameSite == http.SameSiteLaxMode || policy.sameSite == http.SameSiteNoneMode)
}

func validFederatedExpiry(expiresAt, now time.Time) bool {
	if expiresAt.IsZero() || now.IsZero() || expiresAt.Location() != time.UTC || now.Location() != time.UTC {
		return false
	}
	return expiresAt.After(now) && !expiresAt.After(now.Add(maximumFederatedTransactionTTL))
}

func validFederatedEntityID(value identity.EntityID) bool {
	identifier := uuid.UUID(value)
	return identifier != uuid.Nil && identifier.Version() == 7 && identifier.Variant() == uuid.RFC4122
}

func validFederatedIdPRedirect(raw string, maximum int) bool {
	if raw == "" || len(raw) > maximum || !utf8.ValidString(raw) || strings.TrimSpace(raw) != raw ||
		strings.ContainsAny(raw, "\r\n\\") {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.Fragment != "" || parsed.RawPath != "" || parsed.Hostname() == "" || parsed.String() != raw {
		return false
	}
	hostname, err := origin.CanonicalHostname(parsed.Hostname())
	if err != nil || hostname != parsed.Hostname() || strings.HasSuffix(parsed.Host, ".") || strings.Contains(parsed.Host, "%") {
		return false
	}
	if port := parsed.Port(); port != "" {
		value, parseErr := strconv.Atoi(port)
		if parseErr != nil || value < 1 || value > 65535 || strconv.Itoa(value) != port {
			return false
		}
	}
	return true
}

func validFederatedReturnPath(value string) bool {
	if value == "" || len(value) > maximumFederatedReturnPathBytes || !utf8.ValidString(value) ||
		!strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.ContainsRune(value, '\\') {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.Fragment != "" || parsed.RawPath != "" ||
		parsed.Path == "" || strings.Contains(parsed.Path, "//") || path.Clean(parsed.Path) != parsed.Path ||
		parsed.String() != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
