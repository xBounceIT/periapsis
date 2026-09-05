package federatedhttp

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// CompileTarget validates and freezes one canonical HTTPS document URL under
// the client's deployment-owned port policy.
func (client *Client) CompileTarget(kind DocumentKind, rawURL string) (Target, error) {
	if client == nil {
		return Target{}, ErrInvalidTarget
	}
	return client.compileTarget(kind, rawURL)
}

func (client *Client) compileTarget(kind DocumentKind, rawURL string) (Target, error) {
	if !validDocumentKind(kind) || !validTargetText(rawURL) {
		return Target{}, ErrInvalidTarget
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil ||
		parsed.Host == "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.RawFragment != "" || parsed.RawPath != "" || !validCanonicalPath(parsed.Path) {
		return Target{}, ErrInvalidTarget
	}
	host := parsed.Hostname()
	if !validCanonicalHost(host) {
		return Target{}, ErrInvalidTarget
	}

	port := uint16(443)
	portText := parsed.Port()
	if portText != "" {
		parsedPort, parseErr := strconv.ParseUint(portText, 10, 16)
		if parseErr != nil || parsedPort == 0 || parsedPort == 443 ||
			strconv.FormatUint(parsedPort, 10) != portText {
			return Target{}, ErrInvalidTarget
		}
		port = uint16(parsedPort)
	}
	if _, allowed := client.policy.ports[port]; !allowed {
		return Target{}, ErrInvalidTarget
	}

	authority := host
	if address, parseErr := netip.ParseAddr(host); parseErr == nil && address.Is6() {
		authority = "[" + host + "]"
	}
	if port != 443 {
		authority += ":" + strconv.Itoa(int(port))
	}
	canonical := "https://" + authority + parsed.Path
	if canonical != rawURL || parsed.Host != authority {
		return Target{}, ErrInvalidTarget
	}
	return Target{
		kind: kind, canonicalURL: canonical, host: host, port: port, valid: true,
	}, nil
}

func (client *Client) validatedTarget(target Target) (Target, *url.URL, error) {
	if client == nil || !target.valid {
		return Target{}, nil, ErrInvalidTarget
	}
	validated, err := client.compileTarget(target.kind, target.canonicalURL)
	if err != nil || validated != target {
		return Target{}, nil, ErrInvalidTarget
	}
	parsed, err := url.Parse(validated.canonicalURL)
	if err != nil {
		return Target{}, nil, ErrInvalidTarget
	}
	return validated, parsed, nil
}

func (client *Client) redirectTarget(current Target, location string) (Target, error) {
	if !validTargetText(location) {
		return Target{}, ErrInvalidTarget
	}
	if strings.HasPrefix(location, "/") && !strings.HasPrefix(location, "//") {
		currentURL, err := url.Parse(current.canonicalURL)
		if err != nil {
			return Target{}, ErrInvalidTarget
		}
		return client.compileTarget(current.kind, "https://"+currentURL.Host+location)
	}
	return client.compileTarget(current.kind, location)
}

func validDocumentKind(kind DocumentKind) bool {
	switch kind {
	case DocumentOIDCDiscovery, DocumentOIDCJWKS, DocumentSAMLMetadata:
		return true
	default:
		return false
	}
}

func validTargetText(value string) bool {
	if value == "" || len(value) > maximumTargetBytes || !utf8.ValidString(value) ||
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

func validCanonicalHost(value string) bool {
	if value == "" || len(value) > 253 || strings.ToLower(value) != value ||
		strings.TrimSpace(value) != value {
		return false
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Zone() == "" && !address.Is4In6() && address.String() == value
	}
	if looksLikeAmbiguousAddress(value) || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := range label {
			character := label[index]
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func looksLikeAmbiguousAddress(value string) bool {
	decimalOrDot := true
	for index := range value {
		if value[index] != '.' && (value[index] < '0' || value[index] > '9') {
			decimalOrDot = false
			break
		}
	}
	if decimalOrDot {
		return true
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) <= 2 || !strings.HasPrefix(label, "0x") {
			continue
		}
		hexadecimal := true
		for index := 2; index < len(label); index++ {
			character := label[index]
			if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
				hexadecimal = false
				break
			}
		}
		if hexadecimal {
			return true
		}
	}
	return false
}

func validCanonicalPath(value string) bool {
	if len(value) > maximumPathBytes || !utf8.ValidString(value) {
		return false
	}
	if value == "" {
		return true
	}
	if value[0] != '/' || strings.Contains(value, "//") || strings.ContainsRune(value, '\\') {
		return false
	}
	segments := strings.Split(value[1:], "/")
	for index, segment := range segments {
		if segment == "." || segment == ".." || segment == "" && index != len(segments)-1 {
			return false
		}
	}
	for index := range value {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("/-._~!$&'()*+,;=:@", rune(character)) {
			continue
		}
		return false
	}
	return true
}
