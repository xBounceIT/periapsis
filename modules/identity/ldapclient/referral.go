package ldapclient

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	ldap "github.com/go-ldap/ldap/v3"
)

type directoryEndpointOrigin struct {
	transport Transport
	host      string
	port      uint16
}

func directoryOriginForEndpoint(endpoint Endpoint) directoryEndpointOrigin {
	return directoryEndpointOrigin{
		transport: endpoint.Transport,
		host:      endpoint.Host,
		port:      endpoint.Port,
	}
}

func directoryReferralEndpoint(
	rawURL string,
	allowed map[directoryEndpointOrigin]Endpoint,
) (Endpoint, error) {
	if !validDirectoryReferralURLText(rawURL) || len(allowed) == 0 {
		return Endpoint{}, errDirectoryReferral
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || !parsed.IsAbs() || parsed.Opaque != "" || parsed.User != nil ||
		parsed.Host == "" || parsed.Path != "" || parsed.RawPath != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.RawFragment != "" {
		return Endpoint{}, errDirectoryReferral
	}

	var transport Transport
	var defaultPort uint16
	switch parsed.Scheme {
	case "ldap":
		transport = TransportStartTLS
		defaultPort = 389
	case "ldaps":
		transport = TransportLDAPS
		defaultPort = 636
	default:
		return Endpoint{}, errDirectoryReferral
	}
	host := parsed.Hostname()
	if !validCanonicalNetworkName(host) {
		return Endpoint{}, errDirectoryReferral
	}

	port := defaultPort
	portText := parsed.Port()
	if portText != "" {
		parsedPort, parseErr := strconv.ParseUint(portText, 10, 16)
		if parseErr != nil || parsedPort == 0 || strconv.FormatUint(parsedPort, 10) != portText {
			return Endpoint{}, errDirectoryReferral
		}
		port = uint16(parsedPort)
	}
	canonicalHost := host
	if address, parseErr := netip.ParseAddr(host); parseErr == nil && address.Is6() {
		canonicalHost = "[" + host + "]"
	}
	withPort := parsed.Scheme + "://" + canonicalHost + ":" + strconv.Itoa(int(port))
	withoutPort := parsed.Scheme + "://" + canonicalHost
	if rawURL != withPort && !(portText == "" && port == defaultPort && rawURL == withoutPort) {
		return Endpoint{}, errDirectoryReferral
	}

	endpoint, found := allowed[directoryEndpointOrigin{transport: transport, host: host, port: port}]
	if !found || !endpoint.Enabled || !endpoint.ReferralAllowed {
		return Endpoint{}, errDirectoryReferral
	}
	return endpoint, nil
}

func validDirectoryReferralURLText(value string) bool {
	if value == "" || len(value) > maximumDirectoryReferralURLBytes || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

// directoryLDAPErrorReferrals extracts the bounded URI sequence from an LDAP
// result-code 10 packet. It never uses the diagnostic string carried by the
// upstream error.
func directoryLDAPErrorReferrals(err error) ([]string, bool, error) {
	var ldapError *ldap.Error
	if !errors.As(err, &ldapError) || ldapError.ResultCode != ldap.LDAPResultReferral {
		return nil, false, nil
	}
	if ldapError.Packet == nil || len(ldapError.Packet.Children) < 2 ||
		ldapError.Packet.Children[1] == nil {
		return nil, true, errDirectoryReferral
	}
	response := ldapError.Packet.Children[1]
	if len(response.Children) < 4 {
		return nil, true, errDirectoryReferral
	}
	var referralContainerFound bool
	referrals := make([]string, 0, 1)
	for _, child := range response.Children[3:] {
		// LDAPResult referral is context-specific, constructed tag [3]. A few
		// deployed servers use tag [19], which go-ldap also accepts.
		if child == nil || child.ClassType != 128 || child.TagType != 32 ||
			(child.Tag != 3 && child.Tag != 19) || referralContainerFound {
			return nil, true, errDirectoryReferral
		}
		referralContainerFound = true
		if len(child.Children) == 0 || len(child.Children) > maximumDirectoryReferralsPerResponse {
			return nil, true, errDirectoryReferral
		}
		for _, uri := range child.Children {
			if uri == nil {
				return nil, true, errDirectoryReferral
			}
			value, ok := uri.Value.(string)
			if !ok || !validDirectoryReferralURLText(value) {
				return nil, true, errDirectoryReferral
			}
			referrals = append(referrals, value)
		}
	}
	if !referralContainerFound || len(referrals) == 0 {
		return nil, true, errDirectoryReferral
	}
	return referrals, true, nil
}

type directoryCategorizedError struct {
	category DirectoryCategory
}

func (err directoryCategorizedError) Error() string { return "LDAP directory operation failed" }

func newDirectoryCategorizedError(category DirectoryCategory) error {
	if safeDirectoryCategory(category) == "unknown" || category == DirectoryCategorySuccess {
		return errDirectoryProtocol
	}
	return directoryCategorizedError{category: category}
}
